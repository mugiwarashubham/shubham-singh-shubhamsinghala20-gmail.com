import { forbidden, badRequest } from './http.js';

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

const catalogue = (db) => db.prepare('SELECT key FROM permissions ORDER BY key').all().map((r) => r.key);
const membership = (db, orgId, userId) => db.prepare('SELECT role,status FROM memberships WHERE org_id=? AND user_id=?').get(orgId,userId);
const expand = (pattern, keys) => {
  if (pattern === '*') return keys;
  if (pattern.endsWith(':*')) return keys.filter((key) => key.startsWith(pattern.slice(0, -1)));
  return keys.includes(pattern) ? [pattern] : [];
};

function grantsFor(db, userId, orgId, deviceId, at) {
  const scope = deviceId == null ? '' : ' AND (g.device_id IS NULL OR g.device_id = ?)';
  const args = [userId, orgId, at, at];
  if (deviceId != null) args.push(deviceId);
  return db.prepare(`SELECT g.id, g.device_id, g.effect, gp.permission
    FROM grants g JOIN grant_permissions gp ON gp.grant_id=g.id
    WHERE g.user_id=? AND g.org_id=? AND g.revoked_at IS NULL
      AND (g.starts_at IS NULL OR g.starts_at <= ?)
      AND (g.expires_at IS NULL OR g.expires_at > ?)${scope}`).all(...args);
}

function denySet(keys, role, reason) {
  return { role, permissions: Object.fromEntries(keys.map((key) => [key, { effect:'deny', source:null, reason }])) };
}

function resolveCore(db, { userId, orgId, deviceId, now }) {
  const keys = catalogue(db);
  const m = membership(db, orgId, userId);
  if (!m || m.status === 'removed' || m.status === 'invited') return denySet(keys, m?.role ?? null, 'inactive_membership');
  if (m.status === 'suspended') return denySet(keys, m.role, 'suspended');

  const baseline = new Set(db.prepare('SELECT permission FROM role_permissions WHERE role=?').all(m.role).map((r) => r.permission));
  const rows = grantsFor(db, userId, orgId, deviceId, now.toISOString());
  const expanded = rows.map((row) => ({ ...row, permissions: expand(row.permission, keys) }));
  const permissions = {};
  for (const key of keys) {
    const denies = expanded.filter((g) => g.effect === 'deny' && g.permissions.includes(key));
    if (denies.length) {
      permissions[key] = { effect:'deny', source:`grant:${denies[0].id}`, reason:'explicit_deny' };
      continue;
    }
    const allow = expanded.find((g) => g.effect === 'allow' && g.permissions.includes(key));
    if (allow) permissions[key] = { effect:'allow', source:`grant:${allow.id}`, reason:null };
    else if (baseline.has(key)) permissions[key] = { effect:'allow', source:`role:${m.role}`, reason:null };
    else permissions[key] = { effect:'deny', source:null, reason:'implicit' };
  }
  return { role:m.role, permissions };
}

export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  return resolveCore(db, { userId, orgId, deviceId, now });
}

export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const ids = [...new Set(deviceIds)];
  const keys = catalogue(db);
  const m = membership(db, orgId, userId);
  if (!m || m.status === 'removed' || m.status === 'invited') return { role: m?.role ?? null, byDevice: Object.fromEntries(ids.map(id => [id, denyAll(keys,m?.role??null,'inactive_membership').permissions])) };
  if (m.status === 'suspended') return { role:m.role, byDevice:Object.fromEntries(ids.map(id => [id,denyAll(keys,m.role,'suspended').permissions])) };
  const baseline = new Set(db.prepare('SELECT permission FROM role_permissions WHERE role=?').all(m.role).map(r=>r.permission));
  const at=now.toISOString();
  const grants=ids.length?db.prepare(`SELECT g.id,g.device_id,g.effect,gp.permission FROM grants g JOIN grant_permissions gp ON gp.grant_id=g.id
    WHERE g.user_id=? AND g.org_id=? AND g.revoked_at IS NULL
      AND (g.starts_at IS NULL OR g.starts_at<=?) AND (g.expires_at IS NULL OR g.expires_at>?)
      AND (g.device_id IS NULL OR g.device_id IN (${ids.map(()=>'?').join(',')}))`).all(userId,orgId,at,at,...ids):[];
  const allGrants=[...grants];
  const byDevice={};
  for(const id of ids){
    const relevant=allGrants.filter(g=>g.device_id===null||g.device_id===id).map(g=>({...g,permissions:expand(g.permission,keys)}));
    const out={};
    for(const key of keys){const deny=relevant.find(g=>g.effect==='deny'&&g.permissions.includes(key));const allow=relevant.find(g=>g.effect==='allow'&&g.permissions.includes(key));out[key]=deny?{effect:'deny',source:`grant:${deny.id}`,reason:'explicit_deny'}:allow?{effect:'allow',source:`grant:${allow.id}`,reason:null}:baseline.has(key)?{effect:'allow',source:`role:${m.role}`,reason:null}:{effect:'deny',source:null,reason:'implicit'};}
    byDevice[id]=out;
  }
  return { role:m.role, byDevice };
}

export function can(db, ctx, permission, deviceId = null) {
  const result = resolve(db, { userId:ctx.userId, orgId:ctx.orgId, deviceId });
  return result.permissions[permission]?.effect === 'allow';
}

export function assertCan(db, ctx, permission, deviceId = null) {
  const result = resolve(db, { userId:ctx.userId, orgId:ctx.orgId, deviceId });
  const answer = result.permissions[permission];
  if (!answer || answer.effect !== 'allow') {
    throw forbidden(`permission denied: ${permission}`, answer?.reason ?? 'missing_permission');
  }
  return answer;
}

export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  if (!Array.isArray(patterns) || patterns.length === 0) throw badRequest('permissions must be a non-empty array');
  if (patterns.some((p) => typeof p !== 'string' || !p)) throw badRequest('permissions must be non-empty strings');
  const keys = catalogue(db);
  const expanded = [...new Set(patterns.flatMap((p) => expand(p, keys)))];
  if (expanded.length !== patterns.flatMap((p) => expand(p, keys)).length) {
    const unknown = patterns.find((p) => expand(p, keys).length === 0);
    throw badRequest(`unknown permission: ${unknown}`, 'unknown_permission');
  }
  const current = resolve(db, { userId:ctx.userId, orgId:ctx.orgId, deviceId });
  const lacking = expanded.find((p) => current.permissions[p]?.effect !== 'allow');
  if (lacking) throw forbidden(`you cannot grant ${lacking}`, 'missing_permission');
}

export function assertCanStartSession(db, ctx, mode, deviceId) {
  const permissions = resolve(db, { userId:ctx.userId, orgId:ctx.orgId, deviceId }).permissions;
  const start = permissions['session:start'];
  if (!start || start.effect !== 'allow') throw forbidden('session:start is required', 'missing_permission');
  const needed = MODE_PERMISSION[mode];
  const action = permissions[needed];
  if (!action || action.effect !== 'allow') throw forbidden(`${needed} is required`, 'missing_device_permission');
}

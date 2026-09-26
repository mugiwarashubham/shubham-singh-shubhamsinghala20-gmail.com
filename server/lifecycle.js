import { newId, nowIso } from './db.js';
import { badRequest, forbidden, lastOwner } from './http.js';

export function roleRanks(db) {
  return Object.fromEntries(db.prepare('SELECT key,rank FROM roles').all().map((r) => [r.key,r.rank]));
}
export function assertRoleExists(db, role) {
  if (!db.prepare('SELECT 1 FROM roles WHERE key=?').get(role)) throw badRequest(`unknown role: ${role}`, 'unknown_role');
}
export function assertCanModify(db, callerRole, targetRole) {
  if (callerRole === 'owner') return;
  const ranks = roleRanks(db);
  if ((ranks[callerRole] ?? -1) > (ranks[targetRole] ?? Infinity)) return;
  throw forbidden('you cannot modify a user at or above your own role', 'insufficient_rank');
}
export function assertNotLastOwner(db, orgId, userId) {
  const target = db.prepare('SELECT role FROM memberships WHERE org_id=? AND user_id=?').get(orgId,userId);
  if (target?.role !== 'owner') return;
  const n = db.prepare("SELECT count(*) n FROM memberships WHERE org_id=? AND role='owner' AND status='active'").get(orgId).n;
  if (n <= 1) throw lastOwner();
}
export function endActiveSessions(db, { orgId, userId=null, deviceId=null, reason, exceptSessionId=null }) {
  const clauses = ['org_id=?','state=\'active\'']; const args=[orgId];
  if (userId) { clauses.push('user_id=?'); args.push(userId); }
  if (deviceId) { clauses.push('device_id=?'); args.push(deviceId); }
  if (exceptSessionId) { clauses.push('id!=?'); args.push(exceptSessionId); }
  const ids = db.prepare(`SELECT id FROM sessions WHERE ${clauses.join(' AND ')}`).all(...args).map((r)=>r.id);
  const update = db.prepare("UPDATE sessions SET state='ended',ended_at=?,end_reason=? WHERE id=?");
  for (const id of ids) update.run(nowIso(),reason,id);
  return ids;
}
export function snapshotAuthority(db, { userId, orgId, deviceId }) {
  const role = db.prepare('SELECT role FROM memberships WHERE org_id=? AND user_id=?').get(orgId,userId)?.role ?? null;
  const at=nowIso();
  const grantIds=db.prepare(`SELECT id FROM grants WHERE org_id=? AND user_id=? AND revoked_at IS NULL
    AND (starts_at IS NULL OR starts_at<=?) AND (expires_at IS NULL OR expires_at>?)
    AND (device_id IS NULL OR device_id=?)`).all(orgId,userId,at,at,deviceId).map(r=>r.id);
  return JSON.stringify({ role, grantIds, snapshotAt:at });
}
export function sessionExpiry(db, orgId) {
  const minutes=db.prepare('SELECT max_session_minutes m FROM organizations WHERE id=?').get(orgId)?.m ?? 60;
  return new Date(Date.now()+minutes*60000).toISOString();
}
export { newId, nowIso };

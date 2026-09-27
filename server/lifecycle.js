import { newId, nowIso } from './db.js';
import { badRequest, forbidden, lastOwner } from './http.js';

/**
 * Role ranks are used ONLY for modification authority.
 *
 * They must never be used to decide normal permissions because
 * roles such as operator and auditor are not ordered by capability.
 */
export function roleRanks(db) {
  return Object.fromEntries(
    db
      .prepare('SELECT key, rank FROM roles')
      .all()
      .map((row) => [row.key, row.rank])
  );
}

/**
 * Make sure a role exists in the database.
 */
export function assertRoleExists(db, role) {
  if (!db.prepare('SELECT 1 FROM roles WHERE key = ?').get(role)) {
    throw badRequest(
      `unknown role: ${role}`,
      'unknown_role'
    );
  }
}

/**
 * Check whether the caller is allowed to modify a target member.
 *
 * Owners can manage every role.
 *
 * Other roles can only manage users below their own rank.
 * This check is intentionally based on the target role.
 */
export function assertCanModify(
  db,
  callerRole,
  targetRole
) {
  if (callerRole === 'owner') {
    return;
  }

  const ranks = roleRanks(db);

  const callerRank = ranks[callerRole] ?? -1;
  const targetRank = ranks[targetRole] ?? Infinity;

  if (callerRank > targetRank) {
    return;
  }

  throw forbidden(
    'you cannot modify a user at or above your own role',
    'insufficient_rank'
  );
}

/**
 * A non-owner must not be able to assign a role
 * at or above their own role.
 *
 * Example:
 *   admin -> viewer       allowed
 *   admin -> operator     allowed
 *   admin -> admin        denied
 *   admin -> owner        denied
 *
 * Owners can assign any valid role.
 */
export function assertCanAssignRole(
  db,
  callerRole,
  newRole
) {
  if (callerRole === 'owner') {
    return;
  }

  const ranks = roleRanks(db);

  const callerRank = ranks[callerRole] ?? -1;
  const newRoleRank = ranks[newRole] ?? Infinity;

  if (callerRank > newRoleRank) {
    return;
  }

  throw forbidden(
    'you cannot assign a role at or above your own role',
    'insufficient_rank'
  );
}

/**
 * Prevent removal/demotion of the last active owner.
 */
export function assertNotLastOwner(
  db,
  orgId,
  userId
) {
  const target = db
    .prepare(
      `SELECT role
       FROM memberships
       WHERE org_id = ?
         AND user_id = ?`
    )
    .get(orgId, userId);

  if (target?.role !== 'owner') {
    return;
  }

  const result = db
    .prepare(
      `SELECT count(*) AS n
       FROM memberships
       WHERE org_id = ?
         AND role = 'owner'
         AND status = 'active'`
    )
    .get(orgId);

  if (result.n <= 1) {
    throw lastOwner();
  }
}

/**
 * End active sessions for a user, device or organization.
 *
 * Existing sessions are deliberately handled separately from
 * permission changes. This supports the assignment's grandfathering
 * rule: changing someone's permissions does not automatically kill
 * an already-authorized session.
 */
export function endActiveSessions(
  db,
  {
    orgId,
    userId = null,
    deviceId = null,
    reason,
    exceptSessionId = null
  }
) {
  const clauses = [
    'org_id = ?',
    "state = 'active'"
  ];

  const args = [orgId];

  if (userId) {
    clauses.push('user_id = ?');
    args.push(userId);
  }

  if (deviceId) {
    clauses.push('device_id = ?');
    args.push(deviceId);
  }

  if (exceptSessionId) {
    clauses.push('id != ?');
    args.push(exceptSessionId);
  }

  const sessions = db
    .prepare(
      `SELECT id
       FROM sessions
       WHERE ${clauses.join(' AND ')}`
    )
    .all(...args);

  const update = db.prepare(
    `UPDATE sessions
     SET state = 'ended',
         ended_at = ?,
         end_reason = ?
     WHERE id = ?`
  );

  for (const session of sessions) {
    update.run(
      nowIso(),
      reason,
      session.id
    );
  }

  return sessions.map((session) => session.id);
}

/**
 * Store the authorization state that created a session.
 *
 * This snapshot is what allows an already-authorized session
 * to survive a later permission change.
 */
export function snapshotAuthority(
  db,
  {
    userId,
    orgId,
    deviceId
  }
) {
  const membership = db
    .prepare(
      `SELECT role
       FROM memberships
       WHERE org_id = ?
         AND user_id = ?`
    )
    .get(orgId, userId);

  const role = membership?.role ?? null;
  const at = nowIso();

  const grantIds = db
    .prepare(
      `SELECT id
       FROM grants
       WHERE org_id = ?
         AND user_id = ?
         AND revoked_at IS NULL
         AND (starts_at IS NULL OR starts_at <= ?)
         AND (expires_at IS NULL OR expires_at > ?)
         AND (device_id IS NULL OR device_id = ?)`
    )
    .all(
      orgId,
      userId,
      at,
      at,
      deviceId
    )
    .map((row) => row.id);

  return JSON.stringify({
    role,
    grantIds,
    snapshotAt: at
  });
}

/**
 * Calculate the expiration time for a new session.
 */
export function sessionExpiry(
  db,
  orgId
) {
  const row = db
    .prepare(
      `SELECT max_session_minutes AS minutes
       FROM organizations
       WHERE id = ?`
    )
    .get(orgId);

  const minutes = row?.minutes ?? 60;

  return new Date(
    Date.now() + minutes * 60_000
  ).toISOString();
}

export { newId, nowIso };
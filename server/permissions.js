import { forbidden, badRequest } from './http.js';

export const MODE_PERMISSION = {
  view: 'device:view',
  control: 'device:control',
  terminal: 'device:terminal'
};

// Always read permissions from the database.
// Do not hard-code the documented permission matrix.
const catalogue = (db) =>
  db.prepare('SELECT key FROM permissions ORDER BY key').all().map((row) => row.key);

const membership = (db, orgId, userId) =>
  db
    .prepare(
      `SELECT role, status
       FROM memberships
       WHERE org_id = ? AND user_id = ?`
    )
    .get(orgId, userId);

/**
 * Expands permission patterns using the permission catalogue
 * stored in the database.
 *
 * Examples:
 *   device:view -> ["device:view"]
 *   device:*    -> all device:* permissions
 *   *           -> all permissions
 */
const expand = (pattern, keys) => {
  if (pattern === '*') {
    return keys;
  }

  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -1);
    return keys.filter((key) => key.startsWith(prefix));
  }

  return keys.includes(pattern) ? [pattern] : [];
};

/**
 * Return every active grant applicable to a user/org/device.
 *
 * Device-scoped grants only apply to their specific device.
 * Organization-wide grants apply to every device in the organization.
 */
function grantsFor(db, userId, orgId, deviceId, at) {
  const deviceFilter =
    deviceId == null
      ? ''
      : ' AND (g.device_id IS NULL OR g.device_id = ?)';

  const args = [userId, orgId, at, at];

  if (deviceId != null) {
    args.push(deviceId);
  }

  return db
    .prepare(
      `SELECT
         g.id,
         g.device_id,
         g.effect,
         gp.permission
       FROM grants g
       JOIN grant_permissions gp
         ON gp.grant_id = g.id
       WHERE g.user_id = ?
         AND g.org_id = ?
         AND g.revoked_at IS NULL
         AND (g.starts_at IS NULL OR g.starts_at <= ?)
         AND (g.expires_at IS NULL OR g.expires_at > ?)
         ${deviceFilter}`
    )
    .all(...args);
}

/**
 * Build a complete denied permission set.
 */
function denySet(keys, role, reason) {
  return {
    role,
    permissions: Object.fromEntries(
      keys.map((key) => [
        key,
        {
          effect: 'deny',
          source: null,
          reason
        }
      ])
    )
  };
}

/**
 * Resolve permissions for one user/org/device context.
 */
function resolveCore(db, { userId, orgId, deviceId, now }) {
  const keys = catalogue(db);
  const m = membership(db, orgId, userId);

  // No membership at all is different from an inactive membership.
  if (!m) {
    return denySet(keys, null, 'not_a_member');
  }

  // Removed/invited memberships exist but cannot use permissions.
  if (m.status === 'removed' || m.status === 'invited') {
    return denySet(keys, m.role, 'inactive_membership');
  }

  // Suspended users remain members but receive no permissions.
  if (m.status === 'suspended') {
    return denySet(keys, m.role, 'suspended');
  }

  // Role permissions are always loaded from the database.
  const baseline = new Set(
    db
      .prepare('SELECT permission FROM role_permissions WHERE role = ?')
      .all(m.role)
      .map((row) => row.permission)
  );

  const rows = grantsFor(
    db,
    userId,
    orgId,
    deviceId,
    now.toISOString()
  );

  const expanded = rows.map((row) => ({
    ...row,
    permissions: expand(row.permission, keys)
  }));

  const permissions = {};

  for (const key of keys) {
    // Explicit deny always wins.
    const denies = expanded.filter(
      (grant) =>
        grant.effect === 'deny' &&
        grant.permissions.includes(key)
    );

    if (denies.length > 0) {
      permissions[key] = {
        effect: 'deny',
        source: `grant:${denies[0].id}`,
        reason: 'explicit_deny'
      };
      continue;
    }

    // Otherwise an explicit allow grant can provide access.
    const allow = expanded.find(
      (grant) =>
        grant.effect === 'allow' &&
        grant.permissions.includes(key)
    );

    if (allow) {
      permissions[key] = {
        effect: 'allow',
        source: `grant:${allow.id}`,
        reason: null
      };
      continue;
    }

    // Finally fall back to the role baseline.
    if (baseline.has(key)) {
      permissions[key] = {
        effect: 'allow',
        source: `role:${m.role}`,
        reason: null
      };
      continue;
    }

    permissions[key] = {
      effect: 'deny',
      source: null,
      reason: 'implicit'
    };
  }

  return {
    role: m.role,
    permissions
  };
}

/**
 * Resolve permissions for one user.
 */
export function resolve(
  db,
  { userId, orgId, deviceId = null, now = new Date() }
) {
  return resolveCore(db, {
    userId,
    orgId,
    deviceId,
    now
  });
}

/**
 * Resolve permissions for multiple devices in one database query.
 */
export function resolveDevices(
  db,
  { userId, orgId, deviceIds, now = new Date() }
) {
  const ids = [...new Set(deviceIds)];
  const keys = catalogue(db);
  const m = membership(db, orgId, userId);

  // No membership.
  if (!m) {
    const denied = denySet(keys, null, 'not_a_member').permissions;

    return {
      role: null,
      byDevice: Object.fromEntries(
        ids.map((id) => [id, denied])
      )
    };
  }

  // Inactive membership.
  if (m.status === 'removed' || m.status === 'invited') {
    const denied = denySet(
      keys,
      m.role,
      'inactive_membership'
    ).permissions;

    return {
      role: m.role,
      byDevice: Object.fromEntries(
        ids.map((id) => [id, denied])
      )
    };
  }

  // Suspended membership.
  if (m.status === 'suspended') {
    const denied = denySet(
      keys,
      m.role,
      'suspended'
    ).permissions;

    return {
      role: m.role,
      byDevice: Object.fromEntries(
        ids.map((id) => [id, denied])
      )
    };
  }

  const baseline = new Set(
    db
      .prepare('SELECT permission FROM role_permissions WHERE role = ?')
      .all(m.role)
      .map((row) => row.permission)
  );

  const at = now.toISOString();

  let grants = [];

  if (ids.length > 0) {
    const placeholders = ids.map(() => '?').join(',');

    grants = db
      .prepare(
        `SELECT
           g.id,
           g.device_id,
           g.effect,
           gp.permission
         FROM grants g
         JOIN grant_permissions gp
           ON gp.grant_id = g.id
         WHERE g.user_id = ?
           AND g.org_id = ?
           AND g.revoked_at IS NULL
           AND (g.starts_at IS NULL OR g.starts_at <= ?)
           AND (g.expires_at IS NULL OR g.expires_at > ?)
           AND (
             g.device_id IS NULL
             OR g.device_id IN (${placeholders})
           )`
      )
      .all(
        userId,
        orgId,
        at,
        at,
        ...ids
      );
  }

  const expandedGrants = grants.map((grant) => ({
    ...grant,
    permissions: expand(grant.permission, keys)
  }));

  const byDevice = {};

  for (const deviceId of ids) {
    const relevant = expandedGrants.filter(
      (grant) =>
        grant.device_id === null ||
        grant.device_id === deviceId
    );

    const permissions = {};

    for (const key of keys) {
      // Explicit deny wins, including an organization-wide deny.
      const deny = relevant.find(
        (grant) =>
          grant.effect === 'deny' &&
          grant.permissions.includes(key)
      );

      if (deny) {
        permissions[key] = {
          effect: 'deny',
          source: `grant:${deny.id}`,
          reason: 'explicit_deny'
        };
        continue;
      }

      const allow = relevant.find(
        (grant) =>
          grant.effect === 'allow' &&
          grant.permissions.includes(key)
      );

      if (allow) {
        permissions[key] = {
          effect: 'allow',
          source: `grant:${allow.id}`,
          reason: null
        };
        continue;
      }

      if (baseline.has(key)) {
        permissions[key] = {
          effect: 'allow',
          source: `role:${m.role}`,
          reason: null
        };
        continue;
      }

      permissions[key] = {
        effect: 'deny',
        source: null,
        reason: 'implicit'
      };
    }

    byDevice[deviceId] = permissions;
  }

  return {
    role: m.role,
    byDevice
  };
}

/**
 * Check whether a user has a permission.
 */
export function can(
  db,
  ctx,
  permission,
  deviceId = null
) {
  const result = resolve(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    deviceId
  });

  return result.permissions[permission]?.effect === 'allow';
}

/**
 * Require a permission or throw a 403.
 */
export function assertCan(
  db,
  ctx,
  permission,
  deviceId = null
) {
  const result = resolve(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    deviceId
  });

  const answer = result.permissions[permission];

  if (!answer || answer.effect !== 'allow') {
    throw forbidden(
      `permission denied: ${permission}`,
      answer?.reason ?? 'missing_permission'
    );
  }

  return answer;
}

/**
 * Check whether the current user may grant all requested permissions.
 */
export function assertMayGrant(
  db,
  ctx,
  patterns,
  deviceId = null
) {
  if (!Array.isArray(patterns) || patterns.length === 0) {
    throw badRequest(
      'permissions must be a non-empty array'
    );
  }

  if (
    patterns.some(
      (pattern) =>
        typeof pattern !== 'string' ||
        !pattern
    )
  ) {
    throw badRequest(
      'permissions must be non-empty strings'
    );
  }

  const keys = catalogue(db);

  const expanded = [
    ...new Set(
      patterns.flatMap((pattern) =>
        expand(pattern, keys)
      )
    )
  ];

  const requestedExpanded = patterns.flatMap(
    (pattern) => expand(pattern, keys)
  );

  // Every requested pattern must resolve to at least
  // one known permission.
  if (
    expanded.length !== requestedExpanded.length
  ) {
    const unknown = patterns.find(
      (pattern) =>
        expand(pattern, keys).length === 0
    );

    throw badRequest(
      `unknown permission: ${unknown}`,
      'unknown_permission'
    );
  }

  const current = resolve(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    deviceId
  });

  const lacking = expanded.find(
    (permission) =>
      current.permissions[permission]?.effect !== 'allow'
  );

  if (lacking) {
    throw forbidden(
      `you cannot grant ${lacking}`,
      'missing_permission'
    );
  }
}

/**
 * Session start requires both:
 * 1. session:start
 * 2. the device permission matching the requested mode.
 */
export function assertCanStartSession(
  db,
  ctx,
  mode,
  deviceId
) {
  const permissions = resolve(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    deviceId
  }).permissions;

  const start = permissions['session:start'];

  if (!start || start.effect !== 'allow') {
    throw forbidden(
      'session:start is required',
      'missing_permission'
    );
  }

  const needed = MODE_PERMISSION[mode];

  const action = permissions[needed];

  if (!action || action.effect !== 'allow') {
    throw forbidden(
      `${needed} is required`,
      'missing_device_permission'
    );
  }
}
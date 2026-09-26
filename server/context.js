import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, notFound } from './http.js';

export function authenticate(db, secret) {
  return function buildContext(req, params) {
    const header = req.headers.authorization ?? '';
    if (!header.startsWith('Bearer ') || !header.slice(7)) throw unauthenticated('missing bearer token');
    const claims = verifyAccessToken(header.slice(7), secret);
    const membership = db.prepare(`
      SELECT m.*, o.deleted_at AS org_deleted_at
      FROM memberships m JOIN organizations o ON o.id = m.org_id
      WHERE m.org_id = ? AND m.user_id = ?
    `).get(claims.org, claims.sub);
    if (!membership) throw unauthenticated('not a member of this org');
    if (membership.org_deleted_at) throw notFound();
    if (membership.status === 'removed') throw unauthenticated('membership removed');
    if (params.org && params.org !== claims.org) throw notFound();
    if (membership.status !== 'suspended') assertFresh(claims, membership);
    return { userId: claims.sub, orgId: claims.org, role: membership.role, membership, claims };
  };
}

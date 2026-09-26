import { createHmac, timingSafeEqual, randomBytes, scryptSync, randomUUID } from 'node:crypto';
import { unauthenticated, tokenStale } from './http.js';

const ALG = 'HS256';
const ISS = 'remoteops';
const AUD = 'remoteops-api';
export const ACCESS_TTL_SECONDS = 15 * 60;
export const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;
const encode = (value) => Buffer.from(value).toString('base64url');
const decode = (value) => Buffer.from(value, 'base64url');

export function signToken(claims, secret) {
  const h = encode(JSON.stringify({ alg: ALG, typ: 'JWT' }));
  const p = encode(JSON.stringify(claims));
  const sig = createHmac('sha256', secret).update(`${h}.${p}`).digest();
  return `${h}.${p}.${encode(sig)}`;
}

export function issueAccessToken({ userId, orgId, role, permVersion }, secret) {
  const now = Math.floor(Date.now() / 1000);
  return signToken({
    iss: ISS, aud: AUD, sub: userId, org: orgId, role, pv: permVersion,
    jti: randomUUID(), iat: now, exp: now + ACCESS_TTL_SECONDS,
  }, secret);
}

export function verifyAccessToken(token, secret) {
  if (typeof token !== 'string') throw unauthenticated('malformed token');
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) throw unauthenticated('malformed token');
  const [headerPart, payloadPart, signaturePart] = parts;

  let header;
  try {
    header = JSON.parse(decode(headerPart).toString('utf8'));
  } catch {
    throw unauthenticated('malformed token header');
  }
  if (!header || typeof header !== 'object' || header.alg !== ALG || header.typ !== 'JWT') {
    throw unauthenticated('unsupported token algorithm');
  }

  const expected = createHmac('sha256', secret).update(`${headerPart}.${payloadPart}`).digest();
  let actual;
  try { actual = decode(signaturePart); } catch { throw unauthenticated('bad signature'); }
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw unauthenticated('bad signature');

  let claims;
  try { claims = JSON.parse(decode(payloadPart).toString('utf8')); }
  catch { throw unauthenticated('malformed token payload'); }
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)) throw unauthenticated('malformed token payload');

  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp) || claims.exp <= now) throw unauthenticated('token expired');
  if (claims.iss !== ISS || claims.aud !== AUD) throw unauthenticated('bad token issuer or audience');
  if (typeof claims.jti !== 'string' || claims.jti.length === 0) throw unauthenticated('token has no jti');
  return claims;
}

export function assertFresh(claims, membership) {
  if (!membership) throw unauthenticated('not a member of this org');
  if (membership.perm_version !== claims.pv) throw tokenStale();
}

export const newRefreshToken = () => randomBytes(32).toString('base64url');
export const newInviteToken = () => randomBytes(32).toString('base64url');
const HASH_KEY = process.env.APP_HASH_KEY ?? 'dev-only-app-hash-key-change-me';
export const hashRefreshToken = (raw) => createHmac('sha256', `${HASH_KEY}:refresh`).update(raw).digest('hex');
export const hashInviteToken = (raw) => createHmac('sha256', `${HASH_KEY}:invite`).update(raw).digest('hex');

export function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  return `scrypt$${salt}$${scryptSync(password, salt, 64).toString('hex')}`;
}
export function verifyPassword(password, stored) {
  const [scheme, salt, expected] = String(stored ?? '').split('$');
  if (scheme !== 'scrypt' || !salt || !expected) return false;
  const actual = scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(actual, 'hex'); const b = Buffer.from(expected, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

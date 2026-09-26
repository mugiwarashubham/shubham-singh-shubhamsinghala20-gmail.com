import { newId, nowIso } from '../db.js';
import { send, badRequest, unauthenticated, forbidden, notFound } from '../http.js';
import { issueAccessToken, verifyPassword, newRefreshToken, hashRefreshToken, ACCESS_TTL_SECONDS, REFRESH_TTL_SECONDS } from '../auth.js';
import { resolve } from '../permissions.js';
import { audit } from '../audit.js';

const COOKIE='rt';
const cookieValue=(req)=> (req.headers.cookie??'').split(';').map(v=>v.trim()).find(v=>v.startsWith(`${COOKIE}=`))?.slice(COOKIE.length+1) ?? null;
const setCookie=(res,value)=>res.setHeader('set-cookie',`${COOKIE}=${value}; HttpOnly; SameSite=Strict; Path=/v1/auth; Max-Age=${REFRESH_TTL_SECONDS}`);
function activeOrgs(db,userId){
  return db.prepare(`SELECT m.org_id id,o.name,o.theme,m.role,m.perm_version FROM memberships m JOIN organizations o ON o.id=m.org_id
    WHERE m.user_id=? AND m.status='active' AND o.deleted_at IS NULL ORDER BY o.name`).all(userId);
}
function issue(db,secret,user,org){
  const token=issueAccessToken({userId:user.id,orgId:org.id,role:org.role,permVersion:org.perm_version},secret);
  const raw=newRefreshToken();
  db.prepare(`INSERT INTO refresh_tokens(id,user_id,token_hash,family_id,expires_at) VALUES(?,?,?,?,?)`)
    .run(newId('rft'),user.id,hashRefreshToken(raw),newId('fam'),new Date(Date.now()+REFRESH_TTL_SECONDS*1000).toISOString());
  return {token,raw};
}
function response(db,user,orgs,active,token){return {token,expiresIn:ACCESS_TTL_SECONDS,user:{id:user.id,email:user.email,name:user.name},orgId:active.id,role:active.role,orgs:orgs.map(o=>({id:o.id,name:o.name,theme:o.theme,role:o.role}))};}

export function register(router,{db,secret}){
  router.post('/v1/auth/login',(ctx,_p,res)=>{
    const email=typeof ctx.body.email==='string'?ctx.body.email.trim().toLowerCase():null;
    const password=ctx.body.password;
    if(!email||typeof password!=='string') throw badRequest('email and password are required');
    const user=db.prepare('SELECT * FROM users WHERE email=?').get(email);
    if(!user||!verifyPassword(password,user.password_hash)){
      if(user){const m=db.prepare("SELECT org_id FROM memberships WHERE user_id=? AND status='active' LIMIT 1").get(user.id);if(m) audit(db,{orgId:m.org_id,actorId:user.id,action:'auth.login',result:'deny',reasonCode:'bad_credentials',requestId:ctx.requestId});}
      throw unauthenticated('invalid email or password');
    }
    const orgs=activeOrgs(db,user.id); if(!orgs.length) throw forbidden('you are not an active member of any organization');
    const active=ctx.body.orgId?orgs.find(o=>o.id===ctx.body.orgId):orgs[0]; if(!active) throw notFound();
    const issued=issue(db,secret,user,active); setCookie(res,issued.raw);
    audit(db,{orgId:active.id,actorId:user.id,action:'auth.login',result:'allow',requestId:ctx.requestId});
    send(res,200,response(db,user,orgs,active,issued.token));
  });

  router.post('/v1/auth/token',(ctx,_p,res)=>{
    if(typeof ctx.body.orgId!=='string') throw badRequest('orgId is required');
    const org=activeOrgs(db,ctx.userId).find(o=>o.id===ctx.body.orgId); if(!org) throw notFound();
    const user=db.prepare('SELECT id,email,name FROM users WHERE id=?').get(ctx.userId);
    const issued=issue(db,secret,user,org); setCookie(res,issued.raw);
    send(res,200,{token:issued.token,expiresIn:ACCESS_TTL_SECONDS,orgId:org.id,role:org.role,orgs:activeOrgs(db,ctx.userId).map(o=>({id:o.id,name:o.name,theme:o.theme,role:o.role}))});
  });

  router.post('/v1/auth/refresh',(ctx,_p,res)=>{
    const raw=cookieValue(ctx.req); if(!raw) throw unauthenticated('no refresh token');
    const row=db.prepare('SELECT * FROM refresh_tokens WHERE token_hash=?').get(hashRefreshToken(raw));
    if(!row) throw unauthenticated('unknown refresh token');
    if(row.revoked_at){db.prepare('UPDATE refresh_tokens SET revoked_at=? WHERE family_id=? AND revoked_at IS NULL').run(nowIso(),row.family_id);throw unauthenticated('refresh token reuse detected; session family revoked');}
    if(row.expires_at<=nowIso()) throw unauthenticated('refresh token expired');
    const orgs=activeOrgs(db,row.user_id); if(!orgs.length) throw forbidden('you are not an active member of any organization');
    db.prepare('UPDATE refresh_tokens SET revoked_at=? WHERE id=?').run(nowIso(),row.id);
    const next=newRefreshToken(); db.prepare(`INSERT INTO refresh_tokens(id,user_id,token_hash,family_id,expires_at) VALUES(?,?,?,?,?)`).run(newId('rft'),row.user_id,hashRefreshToken(next),row.family_id,new Date(Date.now()+REFRESH_TTL_SECONDS*1000).toISOString());
    setCookie(res,next); const active=orgs[0]; const user=db.prepare('SELECT id,email,name FROM users WHERE id=?').get(row.user_id);
    const token=issueAccessToken({userId:user.id,orgId:active.id,role:active.role,permVersion:active.perm_version},secret);
    send(res,200,response(db,user,orgs,active,token));
  });

  router.get('/v1/auth/me',(ctx,_p,res)=>{
    const user=db.prepare('SELECT id,email,name FROM users WHERE id=?').get(ctx.userId);
    const org=db.prepare('SELECT id,name,theme,max_session_minutes FROM organizations WHERE id=?').get(ctx.orgId);
    send(res,200,{user,org,role:ctx.role,orgs:activeOrgs(db,ctx.userId).map(o=>({id:o.id,name:o.name,theme:o.theme,role:o.role})),permissions:resolve(db,{userId:ctx.userId,orgId:ctx.orgId}).permissions});
  });
}

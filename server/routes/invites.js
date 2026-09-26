import { newId, nowIso } from '../db.js';
import { newInviteToken, hashInviteToken, hashPassword } from '../auth.js';
import { send, badRequest, notFound, gone, conflict } from '../http.js';
import { assertCan } from '../permissions.js';
import { audit } from '../audit.js';
import { assertRoleExists } from '../lifecycle.js';

function inviteRow(db,token){return db.prepare(`SELECT i.*,o.name org_name,r.label role_label FROM invites i JOIN organizations o ON o.id=i.org_id JOIN roles r ON r.key=i.role WHERE i.token_hash=?`).get(hashInviteToken(token));}
export function register(router,{db}){
  router.get('/v1/invites/:token',(ctx,p,res)=>{const i=inviteRow(db,p.token);if(!i)throw notFound();if(i.revoked_at||i.accepted_at)throw gone();if(i.expires_at<=nowIso())throw gone();send(res,200,{id:i.id,orgId:i.org_id,orgName:i.org_name,email:i.email,role:i.role,roleLabel:i.role_label,expiresAt:i.expires_at});});
  router.post('/v1/invites/:token/accept',(ctx,p,res)=>{
    const i=inviteRow(db,p.token);if(!i)throw notFound();if(i.revoked_at||i.accepted_at||i.expires_at<=nowIso())throw gone();
    const email=String(ctx.body.email??i.email).trim().toLowerCase(); if(email!==i.email)throw badRequest('email does not match invite');
    const password=String(ctx.body.password??''); if(password.length<8)throw badRequest('password must be at least 8 characters');
    const existing=db.prepare('SELECT * FROM users WHERE email=?').get(email); const user=existing??{id:newId('usr'),email,name:String(ctx.body.name??email.split('@')[0]),password_hash:hashPassword(password)};
    db.transaction(()=>{if(!existing)db.prepare('INSERT INTO users(id,email,name,password_hash) VALUES(?,?,?,?)').run(user.id,user.email,user.name,user.password_hash);db.prepare(`UPDATE invites SET accepted_at=?,accepted_by=? WHERE id=?`).run(nowIso(),user.id,i.id);db.prepare(`INSERT INTO memberships(id,org_id,user_id,role,status,joined_at) VALUES(?,?,?,?,'active',?)`).run(newId('mem'),i.org_id,user.id,i.role,nowIso());audit(db,{orgId:i.org_id,actorId:user.id,action:'invite.accept',targetType:'invite',targetId:i.id,result:'allow',requestId:ctx.requestId});})();
    send(res,201,{userId:user.id,orgId:i.org_id,role:i.role});
  });
  router.post('/v1/orgs/:org/invites',(ctx,p,res)=>{assertCan(db,ctx,'user:invite');const email=String(ctx.body.email??'').trim().toLowerCase();if(!email||!email.includes('@'))throw badRequest('valid email is required');const role=String(ctx.body.role??'');assertRoleExists(db,role);const expiresAt=ctx.body.expiresAt?new Date(ctx.body.expiresAt):new Date(Date.now()+7*86400000);if(Number.isNaN(expiresAt.getTime())||expiresAt<=new Date())throw badRequest('invalid expiry');const raw=newInviteToken();const id=newId('inv');try{db.prepare(`INSERT INTO invites(id,org_id,email,role,token_hash,invited_by,expires_at) VALUES(?,?,?,?,?,?,?)`).run(id,p.org,email,role,hashInviteToken(raw),ctx.userId,expiresAt.toISOString());}catch(err){if(String(err.code).includes('CONSTRAINT'))throw conflict('an active invite already exists');throw err;}audit(db,{orgId:p.org,actorId:ctx.userId,action:'invite.create',targetType:'invite',targetId:id,result:'allow',requestId:ctx.requestId});send(res,201,{id,email,role,expiresAt:expiresAt.toISOString(),inviteToken:raw});});
  router.get('/v1/orgs/:org/invites',(ctx,p,res)=>{assertCan(db,ctx,'user:invite');send(res,200,{invites:db.prepare(`SELECT id,email,role,expires_at,accepted_at,revoked_at,created_at FROM invites WHERE org_id=? ORDER BY created_at DESC`).all(p.org)});});
  router.delete('/v1/orgs/:org/invites/:id',(ctx,p,res)=>{assertCan(db,ctx,'user:invite');const i=db.prepare('SELECT * FROM invites WHERE id=? AND org_id=? AND revoked_at IS NULL').get(p.id,p.org);if(!i)throw notFound();db.prepare('UPDATE invites SET revoked_at=? WHERE id=?').run(nowIso(),p.id);audit(db,{orgId:p.org,actorId:ctx.userId,action:'invite.revoke',targetType:'invite',targetId:p.id,result:'allow',requestId:ctx.requestId});send(res,204);});
}

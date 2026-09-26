import { newId, nowIso, bumpPermVersion } from '../db.js';
import { send, badRequest, notFound, conflict, selfRoleChange } from '../http.js';
import { assertCan, resolve } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { assertCanModify, assertNotLastOwner, endActiveSessions, assertRoleExists } from '../lifecycle.js';

const THEMES=['cobalt','amber','moss','plum','rust','teal'];
function page(q){const limit=q.get('limit')==null?50:Number(q.get('limit'));const offset=q.get('offset')==null?0:Number(q.get('offset'));if(!Number.isInteger(limit)||limit<1||limit>200||!Number.isInteger(offset)||offset<0)throw badRequest('invalid pagination');return{limit,offset};}
function activeMember(db,org,user){return db.prepare("SELECT * FROM memberships WHERE org_id=? AND user_id=? AND status='active'").get(org,user);}
function visibleDevice(db,org,id){return db.prepare('SELECT * FROM devices WHERE id=? AND org_id=? AND deleted_at IS NULL').get(id,org);}

export function register(router,{db}){
  router.get('/v1/orgs',(ctx,_p,res)=>send(res,200,{orgs:db.prepare(`SELECT o.id,o.name,o.theme,m.role,m.status FROM memberships m JOIN organizations o ON o.id=m.org_id WHERE m.user_id=? AND m.status='active' AND o.deleted_at IS NULL ORDER BY o.name`).all(ctx.userId)}));

  router.post('/v1/orgs',(ctx,_p,res)=>{
    const name=String(ctx.body.name??'').trim(); if(name.length<1||name.length>200)throw badRequest('name must be 1-200 characters');
    const id=newId('org'); const count=db.prepare('SELECT count(*) n FROM organizations').get().n; const theme=THEMES.includes(ctx.body.theme)?ctx.body.theme:THEMES[count%THEMES.length];
    db.transaction(()=>{db.prepare('INSERT INTO organizations(id,name,theme) VALUES(?,?,?)').run(id,name,theme);db.prepare(`INSERT INTO memberships(id,org_id,user_id,role,status,joined_at) VALUES(?,?,?,'owner','active',?)`).run(newId('mem'),id,ctx.userId,nowIso());audit(db,{orgId:id,actorId:ctx.userId,action:'org.create',targetType:'org',targetId:id,result:'allow',requestId:ctx.requestId});})();
    send(res,201,{id,name,theme,role:'owner'});
  });

  router.patch('/v1/orgs/:org',(ctx,p,res)=>{assertCan(db,ctx,'org:update');const name=ctx.body.name===undefined?null:String(ctx.body.name).trim();if(name!==null&&(name.length<1||name.length>200))throw badRequest('name must be 1-200 characters');const org=db.prepare('SELECT * FROM organizations WHERE id=? AND deleted_at IS NULL').get(p.org);if(!org)throw notFound();if(name!==null)db.prepare('UPDATE organizations SET name=? WHERE id=?').run(name,p.org);audit(db,{orgId:p.org,actorId:ctx.userId,action:'org.update',targetType:'org',targetId:p.org,result:'allow',requestId:ctx.requestId});send(res,200,{id:p.org,name:name??org.name,theme:org.theme});});
  router.delete('/v1/orgs/:org',(ctx,p,res)=>{assertCan(db,ctx,'org:delete');const org=db.prepare('SELECT id FROM organizations WHERE id=? AND deleted_at IS NULL').get(p.org);if(!org)throw notFound();db.transaction(()=>{db.prepare('UPDATE organizations SET deleted_at=? WHERE id=?').run(nowIso(),p.org);endActiveSessions(db,{orgId:p.org,reason:'membership_removed'});audit(db,{orgId:p.org,actorId:ctx.userId,action:'org.delete',targetType:'org',targetId:p.org,result:'allow',requestId:ctx.requestId});})();send(res,204);});

  router.get('/v1/orgs/:org/members',(ctx,p,res)=>{assertCan(db,ctx,'user:read');const {limit,offset}=page(ctx.query);const rows=db.prepare(`SELECT m.user_id,u.email,u.name,m.role,m.status,m.joined_at FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.org_id=? ORDER BY u.name LIMIT ? OFFSET ?`).all(p.org,limit,offset);send(res,200,{members:rows});});
  router.get('/v1/orgs/:org/users/:userId/effective',(ctx,p,res)=>{if(p.userId!==ctx.userId)assertCan(db,ctx,'user:read');const m=activeMember(db,p.org,p.userId);if(!m)throw notFound();send(res,200,{userId:p.userId,role:m.role,permissions:resolve(db,{userId:p.userId,orgId:p.org}).permissions});});

  router.patch('/v1/orgs/:org/members/:userId',(ctx,p,res)=>{
    if(p.userId===ctx.userId)throw selfRoleChange(); assertCan(db,ctx,'user:role:update');
    const target=activeMember(db,p.org,p.userId);if(!target)throw notFound();assertCanModify(db,ctx.role,target.role);assertRoleExists(db,ctx.body.role);
    assertNotLastOwner(db,p.org,p.userId);
    db.transaction(()=>{db.prepare('UPDATE memberships SET role=?,perm_version=perm_version+1 WHERE org_id=? AND user_id=?').run(ctx.body.role,p.org,p.userId);audit(db,{orgId:p.org,actorId:ctx.userId,action:'user.role.update',targetType:'user',targetId:p.userId,result:'allow',requestId:ctx.requestId});})();
    send(res,200,{userId:p.userId,role:ctx.body.role});
  });
  router.post('/v1/orgs/:org/members/:userId/suspend',(ctx,p,res)=>{assertCan(db,ctx,'user:remove');if(p.userId===ctx.userId)throw badRequest('you cannot suspend yourself');const target=activeMember(db,p.org,p.userId);if(!target)throw notFound();assertCanModify(db,ctx.role,target.role);assertNotLastOwner(db,p.org,p.userId);db.transaction(()=>{db.prepare("UPDATE memberships SET status='suspended',perm_version=perm_version+1 WHERE org_id=? AND user_id=?").run(p.org,p.userId);endActiveSessions(db,{orgId:p.org,userId:p.userId,reason:'user_suspended'});audit(db,{orgId:p.org,actorId:ctx.userId,action:'user.suspend',targetType:'user',targetId:p.userId,result:'allow',requestId:ctx.requestId});})();send(res,200,{userId:p.userId,status:'suspended'});});
  router.delete('/v1/orgs/:org/members/:userId/suspend',(ctx,p,res)=>{assertCan(db,ctx,'user:remove');const target=db.prepare("SELECT * FROM memberships WHERE org_id=? AND user_id=? AND status='suspended'").get(p.org,p.userId);if(!target)throw notFound();assertCanModify(db,ctx.role,target.role);db.prepare("UPDATE memberships SET status='active',perm_version=perm_version+1 WHERE org_id=? AND user_id=?").run(p.org,p.userId);audit(db,{orgId:p.org,actorId:ctx.userId,action:'user.reinstate',targetType:'user',targetId:p.userId,result:'allow',requestId:ctx.requestId});send(res,200,{userId:p.userId,status:'active'});});
  router.delete('/v1/orgs/:org/members/me',(ctx,p,res)=>{const target=activeMember(db,p.org,ctx.userId);if(!target)throw notFound();assertNotLastOwner(db,p.org,ctx.userId);db.transaction(()=>{db.prepare("UPDATE memberships SET status='removed',perm_version=perm_version+1 WHERE org_id=? AND user_id=?").run(p.org,ctx.userId);endActiveSessions(db,{orgId:p.org,userId:ctx.userId,reason:'membership_removed'});audit(db,{orgId:p.org,actorId:ctx.userId,action:'user.leave',targetType:'user',targetId:ctx.userId,result:'allow',requestId:ctx.requestId});})();send(res,204);});
  router.delete('/v1/orgs/:org/members/:userId',(ctx,p,res)=>{assertCan(db,ctx,'user:remove');if(p.userId===ctx.userId)throw badRequest('use /members/me to leave');const target=activeMember(db,p.org,p.userId);if(!target)throw notFound();assertCanModify(db,ctx.role,target.role);assertNotLastOwner(db,p.org,p.userId);db.transaction(()=>{db.prepare("UPDATE memberships SET status='removed',perm_version=perm_version+1 WHERE org_id=? AND user_id=?").run(p.org,p.userId);endActiveSessions(db,{orgId:p.org,userId:p.userId,reason:'membership_removed'});audit(db,{orgId:p.org,actorId:ctx.userId,action:'user.remove',targetType:'user',targetId:p.userId,result:'allow',requestId:ctx.requestId});})();send(res,204);});

  router.get('/v1/orgs/:org/audit',(ctx,p,res)=>{assertCan(db,ctx,'audit:read');const {limit,offset}=page(ctx.query);send(res,200,{events:db.prepare('SELECT * FROM audit_events WHERE org_id=? ORDER BY at DESC LIMIT ? OFFSET ?').all(p.org,limit,offset)});});
}

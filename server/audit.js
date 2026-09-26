import { newId, nowIso } from './db.js';
export function audit(db, { orgId, actorId=null, action, targetType=null, targetId=null, result, reasonCode=null, requestId=null }) {
  db.prepare(`INSERT INTO audit_events(id,org_id,actor_id,action,target_type,target_id,result,reason_code,request_id,at)
    VALUES(?,?,?,?,?,?,?,?,?,?)`).run(newId('aud'),orgId,actorId,action,targetType,targetId,result,reasonCode,requestId,nowIso());
}
export function auditDenials(db, ctx, meta, work) {
  try { return work(); }
  catch (err) {
    if (err?.code === 'FORBIDDEN') audit(db,{orgId:ctx.orgId,actorId:ctx.userId,result:'deny',reasonCode:err.reason??'missing_permission',requestId:ctx.requestId,...meta});
    throw err;
  }
}

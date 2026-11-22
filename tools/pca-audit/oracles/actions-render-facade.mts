// Oracle: @atlasauth/pca-actions approval-render.ts + facade-spec.ts + provenance.ts. Writes out/ref-actions-render-facade.json.gz.
// PORTING table (confirmed = ReviewOpts.attestationVerified constant; regs are the core registry)
//   renderApproval(def, params, confirmed)                      -> ActionApprovals.renderApproval (= Approval.render)
//   renderDigestForAction(def, params, pcactn, confirmed)       -> ActionApprovals.renderDigestForAction
//   approverRenderCheck(def, params, requested, confirmed)      -> ActionApprovals.approverRenderCheck
//   singleTapAllowed(render)                                    -> ActionApprovals.singleTapAllowed
//   renderersFromDefs(defs, verb, params|null, confirmed)       -> ActionApprovals.renderFromDefs (the returned renderer applied to (verb, '', params))
//   specOfDef(def, reviewed, confirmed) / facadeSpecs(defs, reviewed, confirmed) -> ActionFacade.specOfDef / facadeSpecs
//   provenanceInfoOf(def, confirmed)                            -> ActionProvenance.provenanceInfoOf
//   provenanceActions(defs, confirmed, probeVerbs[])            -> ActionProvenance.provenanceActions(...).apply(verb) for each probe; null = undefined
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import * as DM0 from '../../../packages/pca-actions/src/domain.ts';
import * as AR0 from '../../../packages/pca-actions/src/approval-render.ts';
import * as F0 from '../../../packages/pca-actions/src/facade-spec.ts';
import * as PV0 from '../../../packages/pca-actions/src/provenance.ts';
import * as P0 from '../../../packages/pca/src/index.ts';
import { Oracle, refWrite, clone } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const BI = un(B0), DM = un(DM0), AR = un(AR0), F = un(F0), PV = un(PV0);
const P: any = (P0 as any).paramsDigest ? P0 : (P0 as any).default;
const o = new Oracle('actions-render-facade', 'tools/pca-audit/oracles/actions-render-facade.mts', 'TS-reference oracle for approval-render wrappers, facade specs, provenance facts.');
const ALL: any[] = [...BI.BUILTIN_DEFS, ...DM.DOMAIN_DEFS].map((d: any) => clone(d));
const opt = (c: boolean) => ({ attestationVerified: () => c });
const sample = (d: any): any => {
  const out: any = {};
  for (const [k, p] of Object.entries<any>(d.params)) {
    if (!p.required && p.required !== undefined) continue;
    out[k] = p.role?.startsWith('id.') ? 'abc1234' : p.type === 'integer' ? 7 : p.type === 'boolean' ? true : p.values ? p.values[0] : p.type === 'array' ? ['x'] : p.type === 'set' ? [] : p.type === 'datetime' ? '2030-01-01T00:00:00Z' : 'val';
  }
  return out;
};

for (const d of ALL) {
  const sp = sample(d);
  for (const c of [true, false]) {
    await o.run('renderApproval', `${d.verb} ${c}`, (x: any, p: any, cc: any) => AR.renderApproval(x, p, opt(cc)), [d, sp, c]);
    await o.run('specOfDef', `${d.verb} ${c} reviewed`, (x: any, r: any, cc: any) => F.specOfDef(x, undefined, { ...opt(cc), reviewed: r }), [d, true, c]);
    await o.run('specOfDef', `${d.verb} ${c} plain`, (x: any, r: any, cc: any) => F.specOfDef(x, undefined, { ...opt(cc), reviewed: r }), [d, false, c]);
    await o.run('provenanceInfoOf', `${d.verb} ${c}`, (x: any, cc: any) => PV.provenanceInfoOf(x, undefined, opt(cc)), [d, c]);
  }
  await o.run('renderApproval', `${d.verb} undeclared`, (x: any, p: any, cc: any) => AR.renderApproval(x, p, opt(cc)), [d, { ...sp, zz_extra: 1 }, true]);
  await o.run('renderApproval', `${d.verb} dotted`, (x: any, p: any, cc: any) => AR.renderApproval(x, p, opt(cc)), [d, { ...sp, 'a.b': 1 }, true]);
  await o.run('renderApproval', `${d.verb} float`, (x: any, p: any, cc: any) => AR.renderApproval(x, p, opt(cc)), [d, Object.fromEntries(Object.entries(sp).map(([k, v]) => [k, typeof v === 'number' ? 1.5 : v])), true]);
  await o.run('renderApproval', `${d.verb} empty`, (x: any, p: any, cc: any) => AR.renderApproval(x, p, opt(cc)), [d, {}, true]);
  const rd = (() => { try { return AR.renderApproval(d, sp, opt(true)); } catch { return null; } })();
  if (rd) {
    await o.run('singleTapAllowed', d.verb, AR.singleTapAllowed, [rd]);
    const dg = P.approvalRenderDigest(rd);
    const pcactn = { action: { verb: d.verb, params_digest: P.paramsDigest(sp) } };
    await o.run('renderDigestForAction', `${d.verb} ok`, (x: any, p: any, pc: any, cc: any) => AR.renderDigestForAction(x, p, pc, opt(cc)), [d, sp, pcactn, true]);
    await o.run('renderDigestForAction', `${d.verb} wrong verb`, (x: any, p: any, pc: any, cc: any) => AR.renderDigestForAction(x, p, pc, opt(cc)), [d, sp, { action: { verb: 'x.y', params_digest: pcactn.action.params_digest } }, true]);
    await o.run('renderDigestForAction', `${d.verb} wrong params`, (x: any, p: any, pc: any, cc: any) => AR.renderDigestForAction(x, p, pc, opt(cc)), [d, sp, { action: { verb: d.verb, params_digest: 'x'.repeat(43) } }, true]);
    await o.run('renderDigestForAction', `${d.verb} no digest`, (x: any, p: any, pc: any, cc: any) => AR.renderDigestForAction(x, p, pc, opt(cc)), [d, sp, { action: { verb: d.verb } }, true]);
    await o.run('approverRenderCheck', `${d.verb} ok`, (x: any, p: any, r: any, cc: any) => AR.approverRenderCheck(x, p, r, opt(cc)), [d, sp, dg, true]);
    await o.run('approverRenderCheck', `${d.verb} unconfirmed vs confirmed digest`, (x: any, p: any, r: any, cc: any) => AR.approverRenderCheck(x, p, r, opt(cc)), [d, sp, dg, false]);
    await o.run('approverRenderCheck', `${d.verb} bad`, (x: any, p: any, r: any, cc: any) => AR.approverRenderCheck(x, p, r, opt(cc)), [d, sp, 'x'.repeat(43), true]);
  }
}
await o.run('singleTapAllowed', 'truthy forms', AR.singleTapAllowed, [{ unreviewed: 0 }]);
for (const u of [true, false, 0, 1, '', 'x', null]) await o.run('singleTapAllowed', `unreviewed ${JSON.stringify(u)}`, AR.singleTapAllowed, [{ unreviewed: u }]);
// step-up renderer from defs
const aliased = ALL.filter((d) => (d.aliases ?? []).length > 0).slice(0, 8);
for (const d of aliased) {
  const sp = sample(d);
  for (const v of [d.verb, d.aliases[0], 'nope.verb']) await o.run('renderersFromDefs', `${d.verb} ${v}`, (ds: any, vb: any, p: any, cc: any) => AR.renderersFromDefs(ds, opt(cc))(vb, '', p ?? undefined), [aliased, v, sp, true]);
}
await o.run('renderersFromDefs', 'null params', (ds: any, vb: any, p: any, cc: any) => AR.renderersFromDefs(ds, opt(cc))(vb, '', p ?? undefined), [aliased, aliased[0].verb, null, false]);
// facade packs and provenance resolvers
for (const c of [true, false]) {
  await o.run('facadeSpecs', `all ${c}`, (ds: any, r: any, cc: any) => F.facadeSpecs(ds, undefined, { ...opt(cc), reviewed: r }), [ALL, true, c]);
  await o.run('facadeSpecs', `all plain ${c}`, (ds: any, r: any, cc: any) => F.facadeSpecs(ds, undefined, { ...opt(cc), reviewed: r }), [ALL, false, c]);
  const probes = [...ALL.map((d) => d.verb), ...ALL.flatMap((d) => d.aliases ?? []).slice(0, 20), 'unknown.verb'];
  await o.run('provenanceActions', `all ${c}`, (ds: any, cc: any, pv: any) => { const f = PV.provenanceActions(ds, undefined, opt(cc)); return pv.map((v: string) => f({ verb: v }) ?? null); }, [ALL, c, probes]);
}
const dup = [ALL[0], { ...clone(ALL[1]), aliases: [ALL[0].verb] }];
await o.run('provenanceActions', 'duplicate name', (ds: any, cc: any, pv: any) => { const f = PV.provenanceActions(ds, undefined, opt(cc)); return pv.map((v: string) => f({ verb: v }) ?? null); }, [dup, true, [ALL[0].verb]]);
refWrite(o, 'actions-render-facade');

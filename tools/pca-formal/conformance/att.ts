/**
 * Software-attestation conformance (reference model attestModel vs REAL verifyAttestation) +
 * report_data binding injectivity (exhaustive small-scope: attestationBinding(a) == attestationBinding(b) iff a == b).
 *   tsx att.ts exh   |   tsx att.ts rand <count> <seed>
 */
import { mintGrant, DEFAULT_RISK_POLICY } from '../../../packages/pca/src/index';
import { createDevAttestor, verifyAttestation, attestationBindingB64u, type AttestationDocument } from '../../../packages/pca/src/ext/attestation';
import { attestModel, type AttIn, type AttStage } from './model';
import { keyOf } from './real';
import { NOW, rng } from './spec';

const FAULTS = [
  'grantRef', 'epoch', 'quote', 'docNonce', 'untrusted', 'sigTamper', 'bindHolder', 'bindGrant', 'bindEpoch', 'bindAbsent',
  'notYet', 'expired', 'nonceStale', 'nonceFuture', 'modelBad', 'weightsBad', 'operatorBad', 'promptMissing', 'toolsMissing', 'measBad', 'svnLow',
] as const;
type Fault = typeof FAULTS[number];
const BINDINGS: AttIn['binding'][] = [
  {}, { models: ['m1'] }, { weights: ['w1'] }, { operator: 'op1' }, { minMeasurement: 'meas1' }, { svn: 5 },
  { models: ['m1'], weights: ['w1'], operator: 'op1', minMeasurement: 'meas1', prompts: ['p1'], tools: ['t1'] }, { svn: 5, prompts: ['p1'], tools: ['t1'] },
];
const STAGE_OF: Record<Fault, AttStage> = {
  grantRef: 'pcactn', epoch: 'pcactn', quote: 'pcactn', docNonce: 'nonce', untrusted: 'attestor', sigTamper: 'sig',
  bindHolder: 'binding', bindGrant: 'binding', bindEpoch: 'binding', bindAbsent: 'binding', notYet: 'window', expired: 'window',
  nonceStale: 'nonce_age', nonceFuture: 'nonce_age', modelBad: 'agent_binding', weightsBad: 'agent_binding', operatorBad: 'agent_binding',
  promptMissing: 'agent_binding', toolsMissing: 'agent_binding', measBad: 'agent_binding', svnLow: 'agent_binding',
};
const GOOD = { holder: 'HOLDER', grant: 'GRANT', epoch: 7, nonce: 'NONCE-0123456789abcdef' };

function build(bi: number, faults: Fault[]): { model: AttIn; real: () => Promise<{ ok: boolean; reason?: string }> } {
  const b = BINDINGS[bi]!;
  const has = (f: Fault) => faults.includes(f);
  const doc = {
    model: 'm1', weights: 'w1', measurement: b.svn !== undefined ? '9' : 'meas1', operator: 'op1', prompt: 'p1', tools: 't1',
  };
  if (has('modelBad')) doc.model = 'mX';
  if (has('weightsBad')) doc.weights = 'wX';
  if (has('operatorBad')) doc.operator = 'opX';
  if (has('measBad')) doc.measurement = 'measX';
  if (has('svnLow')) doc.measurement = '3';
  const docNonce = has('docNonce') ? 'NONCE-doc-other' : GOOD.nonce;
  // an honest attestor binds the nonce it signs (the document's own): a relayed quote for another session has both different
  const bind = {
    holder: has('bindHolder') ? 'OTHER' : GOOD.holder, grant: has('bindGrant') ? 'OTHER' : GOOD.grant,
    epoch: has('bindEpoch') ? 8 : GOOD.epoch, nonce: docNonce,
  };
  const issuedAt = has('notYet') ? NOW + 1000 : NOW - 1000;
  const expiresAt = has('expired') ? NOW - 1 : NOW + 1000;
  const expected = { holder: GOOD.holder, grant: GOOD.grant, epoch: GOOD.epoch, nonce: GOOD.nonce, ...(has('nonceStale') ? { nonceIssuedAt: NOW - 300_001 } : has('nonceFuture') ? { nonceIssuedAt: NOW + 1 } : (faults.length % 2 === 0 ? { nonceIssuedAt: NOW - 300_000 } : {})) };
  const model: AttIn = {
    present: true,
    pcactn: { grantRef: has('grantRef') ? 'G2' : GOOD.grant, epoch: has('epoch') ? 9 : GOOD.epoch, quote: has('quote') ? 'Q2' : GOOD.nonce },
    expected,
    doc: {
      nonce: docNonce, attestor: has('untrusted') ? 'untrusted' : 'trusted', sigOk: !has('sigTamper'),
      binding: has('bindAbsent') ? null : bind, issuedAt, expiresAt,
      model: doc.model, weights: doc.weights, measurement: doc.measurement, operator: doc.operator,
      ...(has('promptMissing') ? {} : { prompt: doc.prompt }), ...(has('toolsMissing') ? {} : { tools: doc.tools }),
    },
    trusted: ['trusted'], now: NOW, maxAge: 300_000, binding: b,
  };
  const real = async () => {
    const att = createDevAttestor(keyOf(has('untrusted') ? 'X' : 'B').sk);
    const grant = mintGrant({
      principalSecret: keyOf('P').sk, principalPublic: keyOf('P').pk, holder: keyOf('A').pk, goal: 'g',
      envelope: {
        predicates: [{ verb: 'v1' }], caveats: [], risk_policy: DEFAULT_RISK_POLICY,
        agent_binding: {
          ...(b.models ? { model_allowlist: b.models } : {}), ...(b.weights ? { weights_allowlist: b.weights } : {}),
          ...(b.operator ? { operator: b.operator } : {}),
          ...(b.minMeasurement ? { min_measurement: b.minMeasurement } : {}), ...(b.svn !== undefined ? { min_measurement: { svn: b.svn } } : {}),
          ...(b.prompts ? { system_prompt_allowlist: b.prompts } : {}), ...(b.tools ? { tool_manifest_allowlist: b.tools } : {}),
        },
      },
    }).grant;
    let d: AttestationDocument = att.attest({
      model_id: doc.model, weights_digest: doc.weights, runtime_measurement: doc.measurement, operator: doc.operator,
      ...(has('promptMissing') ? {} : { system_prompt_digest: doc.prompt }), ...(has('toolsMissing') ? {} : { tool_manifest_digest: doc.tools }),
      nonce: docNonce, issued_at: issuedAt, expires_at: expiresAt,
      ...(has('bindAbsent') ? {} : { holder_pub: bind.holder, grant_ref: bind.grant, epoch: bind.epoch }),
    });
    // binding is computed over bind.nonce, but att.attest binds to claims.nonce: patch for the bindNonce / docNonce interplay
    if (!has('bindAbsent')) {
      const att2 = createDevAttestor(keyOf(has('untrusted') ? 'X' : 'B').sk);
      void att2;
    }
    if (has('sigTamper')) d = { ...d, model_id: d.model_id + '!' };
    const ctx = { pcactn: { grant_ref: has('grantRef') ? 'G2' : GOOD.grant, attestation: { epoch: has('epoch') ? 9 : GOOD.epoch, quote_digest: has('quote') ? 'Q2' : GOOD.nonce } }, grant } as never;
    return verifyAttestation({ document: d, ctx, expected: { holderPub: expected.holder, grantRef: expected.grant, epoch: expected.epoch, nonce: expected.nonce, ...(expected.nonceIssuedAt !== undefined ? { nonceIssuedAt: expected.nonceIssuedAt } : {}) }, nowMs: NOW, trustedAttestorKeys: [keyOf('B').pk] });
  };
  return { model, real };
}
const stageOfReason = (r: string | undefined): AttStage => {
  if (!r) return 'ok';
  if (/grant_ref differs|epoch differs|does not bind to this PCActn/.test(r)) return 'pcactn';
  if (/does not match the server-issued nonce/.test(r)) return 'nonce';
  if (/attestor key is not trusted/.test(r)) return 'attestor';
  if (/signature does not verify/.test(r)) return 'sig';
  if (/binding/.test(r) && !/agent_binding/.test(r)) return 'binding';
  if (/validity window|not yet valid|expired\b/.test(r) && !/nonce expired/.test(r)) return 'window';
  if (/nonce/.test(r)) return 'nonce_age';
  return 'agent_binding';
};

async function binding() {
  // injectivity of report_data over a small-scope exhaustive tuple space incl. field-boundary confusions
  const strs = ['', 'a', 'b', 'ab', 'a\u0000b', 'aa'].filter((s) => s !== '');
  const tuples: Array<[string, string, number, string]> = [];
  for (const h of strs) for (const g of strs) for (const e of [0, 1, 256]) for (const n of strs) tuples.push([h, g, e, n]);
  const seen = new Map<string, string>();
  let collisions = 0, distinct = 0;
  for (const t of tuples) {
    const k = attestationBindingB64u({ holderPub: t[0], grantRef: t[1], epoch: t[2], nonce: t[3] });
    const tk = JSON.stringify(t);
    const prev = seen.get(k);
    if (prev !== undefined && prev !== tk) collisions++;
    seen.set(k, tk);
    distinct++;
  }
  return { tuples: tuples.length, collisions, distinct: seen.size };
}

async function main() {
  const [mode, a1, a2] = process.argv.slice(2);
  let n = 0, agree = 0, okCount = 0, stageChecked = 0, stageAgree = 0;
  const examples: unknown[] = [];
  const test = async (bi: number, faults: Fault[]) => {
    const { model, real } = build(bi, faults);
    const m = attestModel(model);
    const r = await real();
    n++;
    if (m.ok) okCount++;
    let ok = m.ok === r.ok;
    if (ok && faults.length === 1) { stageChecked++; const st = stageOfReason(r.reason); if (st === m.stage) stageAgree++; else ok = false; }
    if (ok) agree++; else if (examples.length < 20) examples.push({ bi, faults, model: m, real: r });
  };
  const t0 = Date.now();
  if (mode === 'exh') {
    for (let bi = 0; bi < BINDINGS.length; bi++) {
      await test(bi, []);
      for (const f of FAULTS) await test(bi, [f]);
      for (let i = 0; i < FAULTS.length; i++) for (let j = i + 1; j < FAULTS.length; j++) await test(bi, [FAULTS[i]!, FAULTS[j]!]);
    }
  } else {
    const r = rng(Number(a2 ?? 1));
    for (let c = 0; c < Number(a1 ?? 1000); c++) {
      const fs = FAULTS.filter(() => r.bool(0.12));
      await test(r.int(BINDINGS.length), fs);
    }
  }
  console.log(JSON.stringify({ mode, seconds: (Date.now() - t0) / 1000, cases: n, agree, disagree: n - agree, modelAccepted: okCount, singleFaultStageChecked: stageChecked, stageAgree, bindingInjectivity: await binding(), examples }));
}
main().catch((e) => { console.error(e); process.exit(1); });

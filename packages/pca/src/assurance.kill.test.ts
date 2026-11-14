/**
 * Assurance labels, report and requirement, checked directly on the pure functions: every branch of the label lookup, the
 * multi-root level, the per-check report (attestation / zk / threshold / revocation / signatures), the refresh, and every
 * dimension of `unmetAssurance` with its exact reason.
 */
import { describe, expect, it } from 'vitest';
import {
  type AssuranceReport,
  type AssuranceRequirement,
  assuranceLabelOf,
  assuranceReport,
  isAwaitingAuditScheme,
  multiRootLevel,
  refreshAssurance,
  setAssuranceLabel,
  unmetAssurance,
} from './assurance';
import type { PCActn } from './pcactn';

const labelled = (label: { level: string; vendor?: string; awaiting_audit?: boolean; preview?: boolean; ceremony?: 'single-party' | 'multi-party' }) => setAssuranceLabel({}, label);
const pc = (o: Record<string, unknown>) => o as unknown as PCActn;
const PQ = 'ml-dsa-65';

describe('assuranceLabelOf', () => {
  it('reads labels of objects and functions only; a labelled symbol key is never returned', () => {
    const fn = setAssuranceLabel(() => 0, { level: 'software' });
    expect(assuranceLabelOf(fn)).toEqual({ level: 'software' });
    expect(assuranceLabelOf(labelled({ level: 'hardware', vendor: 'v' }))).toEqual({ level: 'hardware', vendor: 'v' });
    const sym = Symbol('verifier');
    setAssuranceLabel(sym as unknown as object, { level: 'hardware' });
    expect(assuranceLabelOf(sym)).toBeUndefined();
    expect(assuranceLabelOf(null)).toBeUndefined();
    expect(assuranceLabelOf(undefined)).toBeUndefined();
    expect(assuranceLabelOf('hardware')).toBeUndefined();
  });
});

describe('isAwaitingAuditScheme', () => {
  it('frost, frost_dkg and mpc are awaiting audit; multisig, the empty string and unknown are not', () => {
    expect(['frost', 'frost_dkg', 'mpc', 'multisig', '', 'unknown'].map(isAwaitingAuditScheme)).toEqual([true, true, true, false, false, false]);
  });
});

describe('multiRootLevel', () => {
  const hw = () => ({ verifier: labelled({ level: 'hardware' }) });
  const sw = () => ({ verifier: labelled({ level: 'software' }) });
  const un = () => ({ verifier: {} });

  it('two hardware roots in the quorum are multi_root', () => {
    expect(multiRootLevel([hw(), hw()], 2)).toBe('multi_root');
  });
  it('a required root is never counted twice as an optional one', () => {
    expect(multiRootLevel([{ ...hw(), required: true }], 2)).toBe('hardware');
    expect(multiRootLevel([{ ...hw(), required: true }, sw()], 2)).toBe('hardware');
  });
  it('the quorum is filled up to the threshold minus the required roots', () => {
    expect(multiRootLevel([{ ...hw(), required: true }, sw(), hw()], 1)).toBe('hardware');
    expect(multiRootLevel([{ ...hw(), required: true }, sw(), hw()], 2)).toBe('hardware');
    expect(multiRootLevel([{ ...hw(), required: true }, sw(), hw()], 3)).toBe('multi_root');
  });
  it('without hardware the weakest root decides', () => {
    expect(multiRootLevel([sw(), un()], 2)).toBe('unknown');
    expect(multiRootLevel([sw(), sw()], 2)).toBe('software');
    expect(multiRootLevel([sw(), un()], 1)).toBe('unknown');
  });
});

describe('assuranceReport', () => {
  it('an unsupported check names itself in the reason', () => {
    expect(assuranceReport({ checks: { widget: 'unsupported' } })).toStrictEqual({ widget: { outcome: 'unsupported', reason: 'widget is not implemented by this verifier' } });
  });

  it('attestation and zk_compliance passes without any hooks are unknown; threshold and other checks carry no level', () => {
    expect(assuranceReport({ checks: { attestation: 'pass', zk_compliance: 'pass', threshold: 'pass', revocation: 'pass', policy: 'pass' } })).toStrictEqual({
      attestation: { outcome: 'pass', level: 'unknown' },
      zk_compliance: { outcome: 'pass', level: 'unknown' },
      threshold: { outcome: 'pass' },
      revocation: { outcome: 'pass' },
      policy: { outcome: 'pass' },
    });
  });

  it('the hook of each check is the one labelled for it (attestation, zk, threshold, revocation)', () => {
    const hooks = {
      attestation: labelled({ level: 'hardware', vendor: 'tee' }),
      zk: labelled({ level: 'groth16', ceremony: 'multi-party' }),
      threshold: labelled({ level: 'multisig' }),
      revocation: labelled({ level: 'crl', vendor: 'rev' }),
    };
    expect(assuranceReport({ checks: { attestation: 'pass', zk_compliance: 'pass', threshold: 'pass', revocation: 'pass', policy: 'pass' }, hooks })).toStrictEqual({
      attestation: { outcome: 'pass', level: 'hardware', vendor: 'tee' },
      zk_compliance: { outcome: 'pass', level: 'groth16', ceremony: 'multi-party' },
      threshold: { outcome: 'pass', level: 'multisig' },
      revocation: { outcome: 'pass', level: 'crl', vendor: 'rev' },
      policy: { outcome: 'pass' },
    });
  });

  it('a ceremony is reported only for zk_compliance', () => {
    const hooks = { attestation: labelled({ level: 'hardware', ceremony: 'multi-party' }) };
    expect(assuranceReport({ checks: { attestation: 'pass' }, hooks })).toStrictEqual({ attestation: { outcome: 'pass', level: 'hardware' } });
  });

  it('awaiting audit: from the label (either name) or a threshold scheme awaiting audit, never from the scheme name on another check', () => {
    const r = (name: string, label: Parameters<typeof labelled>[0]) => {
      const hooks = { attestation: labelled(label), threshold: labelled(label) };
      return assuranceReport({ checks: { [name]: 'pass' as const }, hooks })[name];
    };
    expect(r('attestation', { level: 'software', awaiting_audit: true })).toStrictEqual({ outcome: 'pass', level: 'software', awaiting_audit: true });
    expect(r('attestation', { level: 'software', preview: true })).toStrictEqual({ outcome: 'pass', level: 'software', awaiting_audit: true });
    expect(r('attestation', { level: 'software' })).toStrictEqual({ outcome: 'pass', level: 'software' });
    expect(r('attestation', { level: 'frost' })).toStrictEqual({ outcome: 'pass', level: 'frost' });
    expect(r('threshold', { level: 'frost' })).toStrictEqual({ outcome: 'pass', level: 'frost', awaiting_audit: true });
    expect(r('threshold', { level: 'multisig' })).toStrictEqual({ outcome: 'pass', level: 'multisig' });
  });

  it('an unlabelled threshold hook is unknown; an unlabelled revocation hook gives no level', () => {
    expect(assuranceReport({ checks: { threshold: 'pass', revocation: 'pass' }, hooks: { threshold: {}, revocation: {} } })).toStrictEqual({
      threshold: { outcome: 'pass', level: 'unknown' },
      revocation: { outcome: 'pass' },
    });
  });

  it('t is reported for threshold only, and only when the hook reported a number', () => {
    const hooks = { attestation: labelled({ level: 'software' }), threshold: labelled({ level: 'multisig' }) };
    expect(assuranceReport({ checks: { attestation: 'pass', threshold: 'pass' }, hooks, thresholdT: 2 })).toStrictEqual({
      attestation: { outcome: 'pass', level: 'software' },
      threshold: { outcome: 'pass', level: 'multisig', t: 2 },
    });
    expect(assuranceReport({ checks: { threshold: 'pass' }, hooks })).toStrictEqual({ threshold: { outcome: 'pass', level: 'multisig' } });
  });

  it('a labelled hook on another check (revocation): level, vendor only when given, awaiting audit from either name', () => {
    const rev = (label: Parameters<typeof labelled>[0]) => assuranceReport({ checks: { revocation: 'pass' }, hooks: { revocation: labelled(label) } }).revocation;
    expect(rev({ level: 'crl' })).toStrictEqual({ outcome: 'pass', level: 'crl' });
    expect(rev({ level: 'crl', vendor: 'v' })).toStrictEqual({ outcome: 'pass', level: 'crl', vendor: 'v' });
    expect(rev({ level: 'crl', awaiting_audit: true })).toStrictEqual({ outcome: 'pass', level: 'crl', awaiting_audit: true });
    expect(rev({ level: 'crl', preview: true })).toStrictEqual({ outcome: 'pass', level: 'crl', awaiting_audit: true });
  });

  it('leaf_signature: Ed25519 stays Ed25519 under allowUnboundPq; a PQ leaf becomes unbound_pq', () => {
    expect(assuranceReport({ checks: { leaf_signature: 'pass' }, pcactn: pc({}), allowUnboundPq: true }).leaf_signature).toStrictEqual({ outcome: 'pass', suites: ['ed25519'], level: 'ed25519' });
    expect(assuranceReport({ checks: { leaf_signature: 'pass' }, pcactn: pc({ alg: 'ed25519' }), allowUnboundPq: true }).leaf_signature).toStrictEqual({ outcome: 'pass', suites: ['ed25519'], level: 'ed25519' });
    expect(assuranceReport({ checks: { leaf_signature: 'pass' }, pcactn: pc({ alg: PQ }), allowUnboundPq: true }).leaf_signature).toStrictEqual({ outcome: 'pass', suites: [PQ], level: 'unbound_pq' });
    expect(assuranceReport({ checks: { leaf_signature: 'pass' }, pcactn: pc({ alg: PQ }) }).leaf_signature).toStrictEqual({ outcome: 'pass', suites: [PQ], level: 'pq' });
  });

  it('cap_chain: the weakest suite, an empty chain is unknown, a missing or null link is Ed25519', () => {
    const chain = (cap_chain: unknown[], allowUnboundPq?: boolean) => assuranceReport({ checks: { cap_chain: 'pass' }, pcactn: pc({ cap_chain }), ...(allowUnboundPq ? { allowUnboundPq } : {}) }).cap_chain;
    expect(chain([{ alg: PQ }, { alg: PQ }])).toStrictEqual({ outcome: 'pass', suites: [PQ, PQ], level: 'pq' });
    expect(chain([])).toStrictEqual({ outcome: 'pass', suites: [], level: 'unknown' });
    expect(chain([null, {}])).toStrictEqual({ outcome: 'pass', suites: ['ed25519', 'ed25519'], level: 'ed25519' });
    expect(chain([{ alg: PQ }, {}], true)).toStrictEqual({ outcome: 'pass', suites: [PQ, 'ed25519'], level: 'unbound_pq' });
    expect(chain([{}, { alg: PQ }], true)).toStrictEqual({ outcome: 'pass', suites: ['ed25519', PQ], level: 'unbound_pq' });
    expect(chain([{ alg: PQ }], true)).toStrictEqual({ outcome: 'pass', suites: [PQ], level: 'unbound_pq' });
    expect(chain([{}, { alg: 'ed25519' }], true)).toStrictEqual({ outcome: 'pass', suites: ['ed25519', 'ed25519'], level: 'ed25519' });
  });

  it('degraded marks only passing checks that exist', () => {
    expect(assuranceReport({ checks: { tighten: 'pass', policy: 'fail' }, degraded: { tighten: 'legacy polarity', policy: 'x', absent: 'y' } })).toStrictEqual({
      tighten: { outcome: 'pass', degraded: true, reason: 'legacy polarity' },
      policy: { outcome: 'fail' },
    });
  });
});

describe('refreshAssurance', () => {
  it('a check that now passes but did not before is reset to a bare pass', () => {
    const report: AssuranceReport = { a: { outcome: 'fail' }, b: { outcome: 'pass', level: 'hardware' } };
    expect(refreshAssurance(report, { a: 'pass', b: 'pass' })).toStrictEqual({ a: { outcome: 'pass' }, b: { outcome: 'pass', level: 'hardware' } });
  });
});

describe('unmetAssurance', () => {
  const unmet = (report: AssuranceReport, req: AssuranceRequirement = {}) => unmetAssurance(report, req);

  it('unsupported without a reason says not implemented', () => {
    expect(unmet({ x: { outcome: 'unsupported' } })).toBe('assurance: unsupported: x (not implemented); a high-assurance policy never accepts it');
  });

  it('a degraded pass is refused with its reason, or "degraded"; a degraded failure is not this refusal', () => {
    expect(unmet({ x: { outcome: 'pass', degraded: true, reason: 'legacy' } })).toBe('assurance: x rests on a degraded compatibility mode (legacy); a high-assurance policy never accepts it');
    expect(unmet({ x: { outcome: 'pass', degraded: true } })).toBe('assurance: x rests on a degraded compatibility mode (degraded); a high-assurance policy never accepts it');
    expect(unmet({ x: { outcome: 'fail', degraded: true } })).toBeUndefined();
    expect(unmet({ x: { outcome: 'pass' } })).toBeUndefined();
  });

  it('attestation: an unlabelled pass is reported as unknown; a level at the requirement passes', () => {
    expect(unmet({ attestation: { outcome: 'pass' } }, { attestation: 'software' })).toBe('assurance: software attestation required but the evidence is unknown');
    expect(unmet({ attestation: { outcome: 'pass', level: 'hardware' } }, { attestation: 'hardware' })).toBeUndefined();
    expect(unmet({ attestation: { outcome: 'pass', level: 'multi_root' } }, { attestation: 'multi_root' })).toBeUndefined();
    expect(unmet({ attestation: { outcome: 'pass', level: 'hardware' } }, { attestation: 'multi_root' })).toBe('assurance: multi_root attestation required but the evidence is hardware');
  });

  it('zk: hardware-bound refuses a pass without a level; ranks decide the rest', () => {
    expect(unmet({ zk_compliance: { outcome: 'pass' } }, { zk: 'attested_vm_hardware' })).toBe('assurance: zk compliance (attested_vm_hardware) required but the prover key is not bound to hardware evidence');
    expect(unmet({ zk_compliance: { outcome: 'pass' } }, { zk: 'proof' })).toBe('assurance: zk compliance (proof) required but the evidence is unknown');
    expect(unmet({ zk_compliance: { outcome: 'pass', level: 'attested_vm' } }, { zk: 'proof' })).toBe('assurance: zk compliance (proof) required but the evidence is attested_vm');
    expect(unmet({ zk_compliance: { outcome: 'pass', level: 'groth16' } }, { zk: 'snark' })).toBeUndefined();
    expect(unmet({ zk_compliance: { outcome: 'pass', level: 'stark' } }, { zk: 'snark' })).toBe('assurance: zk compliance (snark) required but the evidence is stark');
  });

  it('signature pq: pq and hybrid pass; an unlabelled check is unknown', () => {
    expect(unmet({ leaf_signature: { outcome: 'pass', level: 'pq' }, cap_chain: { outcome: 'pass', level: 'pq' } }, { signature: 'pq' })).toBeUndefined();
    expect(unmet({ leaf_signature: { outcome: 'pass', level: 'hybrid' }, cap_chain: { outcome: 'pass', level: 'pq' } }, { signature: 'pq' })).toBeUndefined();
    expect(unmet({ leaf_signature: { outcome: 'pass' }, cap_chain: { outcome: 'pass', level: 'pq' } }, { signature: 'pq' })).toBe('assurance: post-quantum signatures required but leaf_signature is unknown');
  });

  it('threshold: the accepted schemes are listed with " | " in every refusal', () => {
    const req: AssuranceRequirement = { threshold: ['multisig', 'frost'] };
    expect(unmet({}, req)).toBe('assurance: threshold (multisig | frost) required but there is no threshold evidence');
    expect(unmet({ threshold: { outcome: 'pass' } }, req)).toBe('assurance: threshold (multisig | frost) required but no threshold verifier enforced it');
    expect(unmet({ threshold: { outcome: 'pass', level: 'mpc' } }, req)).toBe('assurance: threshold (multisig | frost) required but the scheme is mpc');
  });

  it('awaiting audit: refused unless allowed (either name) or the threshold scheme is listed; failing checks are ignored', () => {
    const aw: AssuranceReport = { attestation: { outcome: 'pass', level: 'software', awaiting_audit: true } };
    expect(unmet(aw)).toBe('assurance: attestation rests on crypto awaiting audit (software); set allowAwaitingAudit or list the scheme to accept it');
    expect(unmet(aw, { allowAwaitingAudit: true })).toBeUndefined();
    expect(unmet(aw, { allowPreview: true })).toBeUndefined();
    expect(unmet({ x: { outcome: 'pass', preview: true } })).toBe('assurance: x rests on crypto awaiting audit (unknown); set allowAwaitingAudit or list the scheme to accept it');
    expect(unmet({ x: { outcome: 'fail', awaiting_audit: true } })).toBeUndefined();
    expect(unmet({ x: { outcome: 'pass', awaiting_audit: true } })).toBe('assurance: x rests on crypto awaiting audit (unknown); set allowAwaitingAudit or list the scheme to accept it');
  });

  it('a listed scheme excuses only the threshold check, not another check with the same level', () => {
    const report: AssuranceReport = { attestation: { outcome: 'pass', level: 'frost', awaiting_audit: true }, threshold: { outcome: 'pass', level: 'frost', awaiting_audit: true } };
    expect(unmet(report, { threshold: ['frost'] })).toBe('assurance: attestation rests on crypto awaiting audit (frost); set allowAwaitingAudit or list the scheme to accept it');
    expect(unmet({ threshold: report.threshold! }, { threshold: ['frost'] })).toBeUndefined();
  });

  it('a threshold entry whose level disappears after the scheme check is matched as the empty string, never as another scheme', () => {
    const marker = ['Stry', 'ker was here!'].join('');
    let reads = 0;
    const report = {} as AssuranceReport;
    // reads 1-3 (the unsupported and degraded scans, the scheme check) see the listed scheme; the awaiting-audit scan sees no level
    Object.defineProperty(report, 'threshold', { enumerable: true, get: () => (++reads <= 3 ? { outcome: 'pass', level: 'frost' } : { outcome: 'pass', awaiting_audit: true }) });
    const req = { threshold: ['frost', marker] } as unknown as AssuranceRequirement;
    expect(unmet(report, req)).toBe('assurance: threshold rests on crypto awaiting audit (unknown); set allowAwaitingAudit or list the scheme to accept it');
    expect(reads).toBe(4);
  });
});


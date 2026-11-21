/**
 * Mutation kills for the 0.5.0 flagship gate survivors in entropy.ts (non-http loopback schemes, the transport message,
 * the key-generation context), facade.ts (connector aliases, catalogs without resolve, alias-less limit lookup),
 * discovery.ts (obligations_supported element types), dlp.ts (ties between equally specific classes), frontier-signals.ts
 * (unknown objective modes), kem.ts (the FIPS 203 modulus check at both coefficient positions, the boundary 3329, the last
 * coefficient, the decapsulation-key length, the per-function error names), hardware-sevsnp.ts (the refusal results of
 * the length and reserved-byte checks), objective-binding.ts (a grant that does not ask for the heuristic) and pcactn.ts
 * (the bond report on a malformed proof, the counter format re-read), plus the witness store paths of mesh.ts.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ml_kem1024, ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { describe, expect, it } from 'vitest';
import { buildCatalog, defineAction, type Catalog } from './catalog';
import { parseDiscoveryDocument } from './discovery';
import { evaluateDlp } from './dlp';
import { EntropyError, generateKeyPairWithEntropy, HttpQrngSource, mixEntropy, type QrngFetch } from './entropy';
import { mintGrant } from './envelope';
import { compilePolicy } from './facade';
import { objectiveSignal } from './frontier-signals';
import { verifyGenuineSevSnpReport } from './hardware-sevsnp';
import { hybridEncapsulate, hybridEncapsulate1024, hybridKem1024Keygen, hybridKemKeygen, mlKemDecapsulationKeyCheck, mlKemEncapsulationKeyCheck, xwingEncapsulateDerand, xwingKeygen } from './kem';
import { encodeKey, generateKeyPair } from './keys';
import { paramsDigest, type PlanNode } from './merkle';
import { MemoryMeshWitnessStore, MeshDomain, MeshWitness, type MeshWitnessState, type MeshWitnessStore } from './mesh';
import { resolveObjectiveRisk } from './objective-binding';
import { buildPCActn, verifyPCActnCore } from './pcactn';
import { DEFAULT_RISK_POLICY } from './risk';

describe('entropy: transport scheme and key-generation context', () => {
  const ok: QrngFetch = async () => ({ ok: true, status: 200, json: async () => ({ data: [1, 2, 3] }), text: async () => '' });
  it('a loopback host over a scheme other than http is refused even with the loopback opt-in', async () => {
    let err: unknown;
    try {
      await new HttpQrngSource({ url: 'ftp://localhost/x', allowInsecureLoopback: true, fetchImpl: ok }).fetch(3);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(EntropyError);
    expect((err as EntropyError).code).toBe('insecure_transport');
    expect((err as Error).message).toBe('QRNG: endpoint must be https (http only for loopback with allowInsecureLoopback)');
  });
  it("generateKeyPairWithEntropy mixes under the 'ed25519-key' context unless the caller names one", async () => {
    const local = () => Uint8Array.from({ length: 32 }, (_, i) => i + 1);
    const none = new Uint8Array(0);
    const k = await generateKeyPairWithEntropy({ randomBytesImpl: () => local() });
    expect(k.secretKey).toEqual(mixEntropy(local(), none, { length: 32, context: 'ed25519-key' }));
    expect(k.secretKey).not.toEqual(mixEntropy(local(), none, { length: 32 }));
    const named = await generateKeyPairWithEntropy({ randomBytesImpl: () => local(), context: 'other' });
    expect(named.secretKey).toEqual(mixEntropy(local(), none, { length: 32, context: 'other' }));
  });
});

describe('facade: catalog aliases and limits', () => {
  const refund = defineAction({ connector: 'stripe', action: 'refund', reversibility: 'reversible', blastRadius: 0.1, description: 'r' });
  const recording = () => {
    const calls: [string, string][] = [];
    const catalog: Catalog = { ...buildCatalog([refund]), resolve: (c, a) => (calls.push([c, a]), refund) };
    return { calls, catalog };
  };
  it('a verb the catalog does not hold resolves through the connector alias', () => {
    const { calls, catalog } = recording();
    const p = compilePolicy({ permissions: { stripe: ['issue_refund'] }, catalog });
    expect(p.actions[0]).toBe(refund);
    expect(calls).toEqual([['stripe', 'issue_refund']]);
  });
  it('a verb with an empty connector is not offered to the alias resolver', () => {
    const { calls, catalog } = recording();
    const p = compilePolicy({ permissions: { '': ['x'] }, catalog });
    expect(p.actions[0]!.description).toBe('(uncatalogued) .x');
    expect(calls).toEqual([]);
  });
  it('a catalog without resolve falls back to the uncatalogued spec', () => {
    const catalog: Catalog = { get: () => undefined, forConnector: () => [], all: () => [] };
    const p = compilePolicy({ permissions: { a: ['b'] }, catalog });
    expect(p.actions[0]).toMatchObject({ verb: 'a.b', reversibility: 'irreversible', description: '(uncatalogued) a.b' });
  });
  it('an action without aliases only takes the limit keyed by its verb or its action name', () => {
    const write = defineAction({ connector: 'notes', action: 'write', reversibility: 'reversible', blastRadius: 0.1, description: 'w' });
    const p = compilePolicy({ permissions: { notes: ['write'] }, catalog: buildCatalog([write]), limits: { 'Stryker was here': '10/hour' } });
    expect(p.limits).toEqual({});
  });
});

describe('discovery: obligations_supported', () => {
  const base = { audience: 'a', pca_versions: [1], signature_suites: ['ed25519'], action_header: 'PCA-Action' };
  it('every element must be a string', () => {
    const m = 'parseDiscoveryDocument: obligations_supported must be a string[]';
    expect(() => parseDiscoveryDocument({ ...base, obligations_supported: [5] })).toThrow(m);
    expect(() => parseDiscoveryDocument({ ...base, obligations_supported: ['a', 5] })).toThrow(m);
    expect(parseDiscoveryDocument({ ...base, obligations_supported: ['a', 'b'] }).obligations_supported).toEqual(['a', 'b']);
  });
});

describe('dlp: equally specific classes', () => {
  const ev = (classes: unknown[]) => evaluateDlp({ classes: classes as never }, { verb: 'v', resource: 'doc:1', taint: 1 });
  it('a class without a ceiling never wins over a sibling that sets one, in either order', () => {
    const open = { name: 'open', resource: 'doc:*' };
    const strict = { name: 'strict', resource: 'doc:*', maxTaintForAuto: 0 };
    for (const classes of [[open, strict], [strict, open]]) {
      expect(ev(classes)).toEqual({ outcome: 'step_up', class: 'strict', reason: "taint 1 > 0 for 'strict' — needs human review" });
    }
  });
  it('a malformed ceiling listed after a lenient one still wins (and denies)', () => {
    const lenient = { name: 'lenient', resource: 'doc:*', maxTaintForAuto: 9 };
    for (const bad of ['x', Number.NaN]) {
      expect(ev([lenient, { name: 'bad', resource: 'doc:*', maxTaintForAuto: bad }])).toEqual({ outcome: 'deny', class: 'bad', reason: 'malformed DLP policy: ceilings must be numbers' });
    }
  });
});

describe('frontier-signals: objectiveSignal', () => {
  it('an unknown mode denies even when the grant falls back to the heuristic', () => {
    expect(objectiveSignal({ mode: 'other', onMismatch: 'heuristic' } as never)).toBe('deny');
    expect(objectiveSignal({ mode: 'mismatch', onMismatch: 'heuristic' } as never)).toBe('ok');
  });
});

describe('kem: FIPS 203 modulus check', () => {
  /** Set 12-bit coefficient j of the t part of an encapsulation key. */
  const setCoeff = (ek: Uint8Array, j: number, v: number) => {
    const t = Math.floor(j / 2) * 3;
    if (j % 2 === 0) {
      ek[t] = v & 0xff;
      ek[t + 1] = (ek[t + 1]! & 0xf0) | (v >> 8);
    } else {
      ek[t + 1] = (ek[t + 1]! & 0x0f) | ((v & 0x0f) << 4);
      ek[t + 2] = v >> 4;
    }
  };
  const with768 = (j: number, v: number) => {
    const ek = ml_kem768.keygen().publicKey.slice();
    setCoeff(ek, j, v);
    return ek;
  };
  it('3328 is reduced and 3329 is not, at an even and at an odd coefficient', () => {
    for (const j of [0, 1]) {
      expect(mlKemEncapsulationKeyCheck(768, with768(j, 3328)), `coefficient ${j}`).toBe(true);
      expect(mlKemEncapsulationKeyCheck(768, with768(j, 3329)), `coefficient ${j}`).toBe(false);
      expect(mlKemEncapsulationKeyCheck(768, with768(j, 4095)), `coefficient ${j}`).toBe(false);
    }
  });
  it('the last coefficient is checked (768 and 1024)', () => {
    expect(mlKemEncapsulationKeyCheck(768, with768(767, 3329))).toBe(false);
    expect(mlKemEncapsulationKeyCheck(768, with768(766, 3329))).toBe(false);
    const ek = ml_kem1024.keygen().publicKey.slice();
    expect(mlKemEncapsulationKeyCheck(1024, ek)).toBe(true);
    setCoeff(ek, 1023, 3329);
    expect(mlKemEncapsulationKeyCheck(1024, ek)).toBe(false);
  });
  it('a decapsulation key one byte too long or short is refused', () => {
    const dk = ml_kem768.keygen().secretKey;
    expect(mlKemDecapsulationKeyCheck(768, dk)).toBe(true);
    const longer = new Uint8Array(dk.length + 1);
    longer.set(dk);
    expect(mlKemDecapsulationKeyCheck(768, longer)).toBe(false);
    expect(mlKemDecapsulationKeyCheck(768, dk.subarray(0, dk.length - 1))).toBe(false);
  });
  it('each encapsulation names itself when the recipient key fails the check', () => {
    const msg = (who: string) => new Error(`${who}: ML-KEM encapsulation key fails the FIPS 203 modulus check`);
    const h = hybridKemKeygen().publicKey.slice();
    setCoeff(h.subarray(32), 0, 3329);
    expect(() => hybridEncapsulate(h)).toThrow(msg('hybridEncapsulate'));
    const x = xwingKeygen().publicKey.slice();
    setCoeff(x.subarray(0, 1184), 0, 3329);
    expect(() => xwingEncapsulateDerand(x, new Uint8Array(64).fill(7))).toThrow(msg('xwingEncapsulateDerand'));
    const h4 = hybridKem1024Keygen().publicKey.slice();
    setCoeff(h4.subarray(32), 0, 3329);
    expect(() => hybridEncapsulate1024(h4)).toThrow(msg('hybridEncapsulate1024'));
  });
});

describe('hardware-sevsnp: the canonical-encoding refusals are not ok', () => {
  const REAL = resolve(__dirname, '..', 'testdata', 'sevsnp-real');
  const report = () => new Uint8Array(readFileSync(resolve(REAL, 'snp_report.bin')));
  const run = (r: Uint8Array) =>
    verifyGenuineSevSnpReport({ report: r, vcekDer: new Uint8Array(readFileSync(resolve(REAL, 'vcek.der'))), askArkPem: readFileSync(resolve(REAL, 'chain.pem'), 'utf8'), nowMs: Date.parse('2026-10-08T12:00:00Z') });
  it('a report one byte too long', async () => {
    const r = new Uint8Array(1185);
    r.set(report());
    expect(await run(r)).toEqual({ ok: false, reason: 'report length 1185 is not the canonical 1184' });
  });
  it('a report with a non-zero reserved signature byte', async () => {
    const r = report();
    r[0x4a0 - 1] = 1;
    expect(await run(r)).toEqual({ ok: false, reason: 'report signature block has non-zero reserved bytes' });
  });
});

describe('objective-binding: only a grant that asks for the heuristic gets it', () => {
  const P = generateKeyPair();
  const H = generateKeyPair();
  const obj = { v: 1, embedder: { scheme: 'native', model_id: 'm', config: {} }, goal: { commit: 'c' }, registry_digest: 'r', graph_digest: 'g', authorized_kinds: [] };
  const resolveWith = (on_mismatch?: string) => {
    const objective_risk = on_mismatch === undefined ? obj : { ...obj, on_mismatch };
    const { grant } = mintGrant({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(H.publicKey), goal: 'x', envelope: { predicates: [], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY, objective_risk } as never });
    return resolveObjectiveRisk({ grant, action: { verb: 'v', resource: 'r', params: {} } as never, instance: { allow_heuristic_fallback: true } as never });
  };
  it('an instance that allows the fallback still denies a grant that did not ask for it', () => {
    expect(resolveWith()).toMatchObject({ mode: 'mismatch', onMismatch: 'deny' });
    expect(resolveWith('deny')).toMatchObject({ mode: 'mismatch', onMismatch: 'deny' });
    expect(resolveWith('heuristic')).toMatchObject({ mode: 'mismatch', onMismatch: 'heuristic' });
  });
});

describe('pcactn: bond report and counter format', () => {
  const principal = generateKeyPair();
  const holder = generateKeyPair();
  const { grant } = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    holder: encodeKey(holder.publicKey),
    goal: 'x',
    envelope: { predicates: [{ verb: 'v', resource: 'r' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  });
  const NOW = Date.UTC(2026, 9, 25, 12);
  const node: PlanNode = { id: 'n', verb: 'v', resource: 'r', params_digest: paramsDigest({}), reversibility_class: 'reversible' };
  const make = () => buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n', params: {}, counter: 1, signerSecret: holder.secretKey, aud: 'rs', now: NOW });
  const opts = { grant, audience: 'rs', nowEpoch: NOW, insecureSkipPlanRootCheck: true };
  it('a proof with a bond_ref that fails as malformed before the bond step gets no bond check', async () => {
    const r = await verifyPCActnCore({ ...make(), bond_ref: 'b' } as never, { grant, audience: 'rs', nowEpoch: NOW, authorizedPlanRoots: {} as never });
    expect(r.allow).toBe(false);
    expect(r.checks.malformed).toBe('fail');
    expect(r.checks.bond).toBeUndefined();
  });
  it('the counter format check reads the counter itself: a value that is no longer an integer fails it', async () => {
    // the wire check reads `counter` twice (the body copy, then the integer check); every later read sees 1.5
    let n = 0;
    const p = { ...make() } as Record<string, unknown>;
    Object.defineProperty(p, 'counter', { enumerable: true, configurable: true, get: () => (n++ < 2 ? 1 : 1.5) });
    const r = await verifyPCActnCore(p as never, opts);
    expect(r.checks.wire).toBe('pass');
    expect(r.checks.counter_format).toBe('fail');
  });
});

describe('mesh: witness stores', () => {
  const kp = () => generateKeyPair();
  it('MemoryMeshWitnessStore is empty until saved, then returns a copy of what was saved', () => {
    const s = new MemoryMeshWitnessStore();
    expect(s.load()).toBeUndefined();
    const st: MeshWitnessState = { seen: [] };
    s.save(st);
    expect(s.load()).toEqual({ seen: [] });
    expect(s.load()).not.toBe(st);
  });
  it('a cosignature persists the new state (head and revocation ids) before it is returned', () => {
    const store = new MemoryMeshWitnessStore();
    const w = new MeshWitness(kp().secretKey, { store });
    const d = new MeshDomain('D', kp().secretKey);
    d.revoke('id1');
    d.publishHead([w], 100);
    const saved = store.load();
    expect(saved).toEqual(w.exportState());
    expect(saved!.seen).toHaveLength(1);
    expect(saved!.seen[0]!.rev_ids).toEqual(['id1']);
    expect(saved!.seen[0]!.head).toEqual(w.lastSeen(d.id));
    expect(saved!.seen[0]!.head.timestamp).toBe(100);
  });
  it('a witness restarted on the same store resumes from it', () => {
    const store = new MemoryMeshWitnessStore();
    const sk = kp().secretKey;
    const d = new MeshDomain('D', kp().secretKey);
    d.publishHead([new MeshWitness(sk, { store })], 100);
    const again = new MeshWitness(sk, { store });
    expect(again.lastSeen(d.id)?.timestamp).toBe(100);
    expect(again.exportState()).toEqual(store.load());
  });
  it('a failed save refuses the cosignature and changes nothing', () => {
    const failing: MeshWitnessStore = {
      load: () => undefined,
      save: () => {
        throw new Error('disk full');
      },
    };
    const w = new MeshWitness(kp().secretKey, { store: failing });
    const d = new MeshDomain('D', kp().secretKey);
    expect(() => d.publishHead([w], 100)).toThrow(new Error('witness: could not persist state; refusing to cosign'));
    expect(w.lastSeen(d.id)).toBeUndefined();
  });
});

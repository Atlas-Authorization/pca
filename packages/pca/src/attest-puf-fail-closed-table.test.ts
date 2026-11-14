/**
 * Fail-closed table for the PUF attestation root: every row is "missing / invalid X => exact result". Fixtures
 * under testdata/puf are a recorded simulated-PUF enrollment with a signed statement and a TPM command-runner
 * transcript, so a change in the wire shape or the extractor shows up as drift. Regenerate deliberately with
 * UPDATE_PUF_FIXTURE=1. The simulated PUF is clonable: this proves the SOFTWARE layer, not real silicon (owner action O-3).
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  type PufAttestationStatement,
  type PufEnrollment,
  type TpmCommandResult,
  TpmEkPufProvider,
  createPufAttestor,
  createPufEnrollmentRegistry,
  createPufVerifier,
  createSimulatedPuf,
  enrollPuf,
  fuzzyEnroll,
  fuzzyReproduce,
} from './attest-puf';
import { assuranceLabelOf, multiRootLevel, setAssuranceLabel } from './assurance';
import {
  type ExpectedAttestationBinding,
  type HardwareAttestationVerifier,
  attestationRegistry,
  createAttestationVerifier,
  createDevAttestor,
  memoryNonceStore,
} from './attestation';
import { mintGrant } from './envelope';
import { b64u } from './hash';
import { encodeKey, generateKeyPair, publicKeyOf } from './keys';
import { buildPCActn, type VerifyContext } from './pcactn';
import { DEFAULT_RISK_POLICY } from './risk';

const DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'puf');
const T = 1_000_000;
const NONCE = 'q3Vx8mZ0aT7bLk2RwYp9Hs';
const REP = 7;
const MSG = 4;
const N = REP * MSG;
const CHALLENGE = new Uint8Array([0xca, 0xfe, 0x01]);
const SEED = new Uint8Array(32).fill(0x11);
const MEAS = 'puf-workload-measurement';
const P = generateKeyPair();
const A = { secretKey: new Uint8Array(32).fill(7), publicKey: publicKeyOf(new Uint8Array(32).fill(7)) }; // fixed so the recorded binding is stable
const HOLDER = encodeKey(A.publicKey);
const EXPECTED: ExpectedAttestationBinding = { holderPub: HOLDER, grantRef: 'grant-puf-1', epoch: 1, nonce: NONCE, nonceIssuedAt: T - 1000 };
const claimsFor = (e: ExpectedAttestationBinding, measurement = MEAS) => ({ measurement, holder_pub: e.holderPub, grant_ref: e.grantRef, epoch: e.epoch, nonce: e.nonce });
const detRng = (n: number): Uint8Array => Uint8Array.from({ length: n }, (_, i) => (i * 7 + 1) & 0xff);

const provider = (seed = SEED, flip: number[] = []) => createSimulatedPuf({ id: 'node-1', seed, length: N, flip });
const enroll = (alg: 'ed25519' | 'ml-dsa-65' = 'ed25519', extra: Partial<PufEnrollment> = {}): PufEnrollment => ({
  ...enrollPuf(provider(), CHALLENGE, { rep: REP, messageBits: MSG, alg, randomBytes: detRng }),
  ...extra,
});
const attest = (enr: PufEnrollment, p = provider(), e = EXPECTED, m = MEAS): PufAttestationStatement => createPufAttestor(p, enr).attest(claimsFor(e, m));

// ---- recorded fixture: drift guard ---------------------------------------------------------------
describe('recorded PUF fixture', () => {
  const file = join(DIR, 'enrollment.json');
  it('the enrollment and the signed statement reproduce byte for byte', () => {
    const enr = enroll();
    const fixture = { note: 'simulated (clonable) PUF; ed25519; rep 7 x 4 bits', seedHex: Buffer.from(SEED).toString('hex'), enrollment: enr, statement: attest(enr) };
    if (process.env.UPDATE_PUF_FIXTURE === '1') writeFileSync(file, `${JSON.stringify(fixture, null, 2)}\n`);
    expect(existsSync(file)).toBe(true);
    // Ed25519 signing here is hedged, so the signature differs per run: compare everything else, then verify it (next test).
    const strip = (x: { statement: PufAttestationStatement }) => ({ ...x, statement: { ...x.statement, sig: '' } });
    expect(strip(JSON.parse(readFileSync(file, 'utf8')))).toEqual(strip(JSON.parse(JSON.stringify(fixture))));
  });
  it('the recorded statement verifies under the recorded enrollment', async () => {
    const rec = JSON.parse(readFileSync(file, 'utf8')) as { enrollment: PufEnrollment; statement: PufAttestationStatement };
    const v = createPufVerifier({ resolveEnrollment: () => rec.enrollment, policy: { measurements: [MEAS] }, resolveEvidence: () => rec.statement });
    const r = await v.verify({ document: {} as never, ctx: {} as never, nowMs: T, expected: EXPECTED });
    expect(r, JSON.stringify(r)).toMatchObject({ ok: true, bound: true });
  });
});

// ---- extractor ------------------------------------------------------------------------------------
describe('fuzzy extractor: missing or invalid X => exact outcome', () => {
  const { helper, key } = fuzzyEnroll(provider().response(CHALLENGE), { rep: REP, messageBits: MSG }, detRng);
  const read = provider().response(CHALLENGE);
  it('reproduces within the bound and diverges beyond it', () => {
    // 3 flips in every block (the bound for rep 7) still reproduces
    const noisy = Uint8Array.from(read);
    for (let b = 0; b < MSG; b++) for (let j = 0; j < 3; j++) noisy[b * REP + j] ^= 1;
    expect(Buffer.from(fuzzyReproduce(noisy, helper)).equals(Buffer.from(key))).toBe(true);
    // 4 flips in one block does not
    const over = Uint8Array.from(read);
    for (let j = 0; j < 4; j++) over[j] ^= 1;
    expect(Buffer.from(fuzzyReproduce(over, helper)).equals(Buffer.from(key))).toBe(false);
  });
  const rows: [string, () => unknown, string][] = [
    ['helper missing the sketch', () => fuzzyReproduce(read, { ...helper, sketch: undefined as never }), 'fuzzyReproduce: helper data missing sketch or salt'],
    ['helper missing the salt', () => fuzzyReproduce(read, { ...helper, salt: undefined as never }), 'fuzzyReproduce: helper data missing sketch or salt'],
    ['sketch not canonical base64url', () => fuzzyReproduce(read, { ...helper, sketch: helper.sketch.slice(0, 2) }), 'fuzzyReproduce: helper sketch or salt is not canonical base64url'],
    ['truncated sketch', () => fuzzyReproduce(read, { ...helper, sketch: helper.sketch.slice(0, 4) }), 'fuzzyReproduce: helper sketch has the wrong length'],
    ['short salt', () => fuzzyReproduce(read, { ...helper, salt: helper.salt.slice(0, 40) }), 'fuzzyReproduce: helper salt has the wrong length'],
    ['no helper at all', () => fuzzyReproduce(read, undefined as never), 'fuzzyReproduce: malformed helper params'],
    ['even repetition factor', () => fuzzyReproduce(read, { ...helper, rep: 6, n: 6 * MSG }), 'fuzzyReproduce: malformed helper params'],
    ['helper n inconsistent', () => fuzzyReproduce(read, { ...helper, n: N + 1 }), 'fuzzyReproduce: helper.n inconsistent with rep*messageBits'],
    ['response of the wrong length', () => fuzzyReproduce(read.slice(1), helper), `fuzzyReproduce: response length ${N - 1} != ${N}`],
    ['response that is not bits', () => fuzzyReproduce(Uint8Array.from(read, () => 2), helper), 'fuzzyReproduce: response must be a 0/1 bit array'],
    ['enroll with even rep', () => fuzzyEnroll(read, { rep: 6, messageBits: MSG }, detRng), 'fuzzyEnroll: rep must be an odd positive integer'],
  ];
  it.each(rows)('%s', (_n, f, msg) => {
    expect(f).toThrow(msg);
  });
});

// ---- verifier -------------------------------------------------------------------------------------
describe('PUF verifier: missing or invalid X => exact denial', () => {
  const enr = enroll();
  const good = attest(enr);
  const NONE = Symbol('none');
  const verifier = (over: Partial<Parameters<typeof createPufVerifier>[0]> = {}, e: PufEnrollment | typeof NONE = enr, st: PufAttestationStatement | typeof NONE = good) =>
    createPufVerifier({ resolveEnrollment: () => (e === NONE ? undefined : e), policy: { measurements: [MEAS] }, resolveEvidence: () => (st === NONE ? undefined : st), ...over });
  const run = (v: HardwareAttestationVerifier, expected: ExpectedAttestationBinding | null = EXPECTED) => v.verify({ document: {} as never, ctx: {} as never, nowMs: T, expected: (expected ?? undefined) as never });
  const SIGFAIL = 'PUF statement signature does not verify under the enrolled public key (wrong/cloned device or excessive noise)';
  const rows: [string, () => Promise<unknown>, string | null][] = [
    ['the baseline', () => run(verifier()), null],
    ['no evidence resolver', () => run(verifier({ resolveEvidence: undefined })), 'no PUF evidence resolver configured (fail closed)'],
    ['resolver returns nothing', () => run(verifier({}, enr, NONE)), 'no PUF attestation statement for this action'],
    ['unknown enrollment', () => run(verifier({}, NONE)), "no PUF enrollment registered for provider 'node-1'"],
    ['revoked enrollment', () => run(verifier({ isRevoked: () => true })), "PUF enrollment for provider 'node-1' is revoked"],
    ['enrollment expired exactly now', () => run(verifier({}, enroll('ed25519', { notAfter: T }))), 'PUF enrollment has expired'],
    ['enrollment valid one ms longer', () => run(verifier({}, enroll('ed25519', { notAfter: T + 1 }))), null],
    ['helper tampered after commitment', () => run(verifier({}, { ...enr, helper: { ...enr.helper, rep: 5, n: 5 * MSG } })), 'PUF enrollment helper commitment mismatch (helper tampered)'],
    ['no helper commitment', () => run(verifier({}, { ...enr, helperCommitment: undefined as never })), 'PUF enrollment helper commitment mismatch (helper tampered)'],
    ['wrong suite', () => run(verifier({}, enr, { ...good, alg: 'ml-dsa-65' })), "PUF statement suite 'ml-dsa-65' does not match the enrolled suite 'ed25519'"],
    ['PQ required, classical key', () => run(verifier({ requirePq: true })), "PQ required: PUF-derived suite 'ed25519' is classical"],
    ['another device (cloned attempt)', () => run(verifier({}, enr, attest(enr, provider(new Uint8Array(32).fill(0x22))))), SIGFAIL],
    ['wrong challenge', () => run(verifier({}, enr, attest({ ...enr, challenge: b64u(new Uint8Array([9])) }))), SIGFAIL],
    ['too many bit flips in one block', () => run(verifier({}, enr, attest(enr, provider(SEED, [0, 1, 2, 3])))), SIGFAIL],
    ['measurement changed after signing', () => run(verifier({}, enr, { ...good, measurement: 'evil' })), SIGFAIL],
    ['binding for another nonce', () => run(verifier(), { ...EXPECTED, nonce: 'another-nonce-0123456789' }), 'PUF statement binding mismatch (holder/grant/epoch/nonce)'],
    ['no expected binding', () => run(verifier(), null), 'no expected attestation binding supplied'],
    ['measurement not allowlisted', () => run(verifier({ policy: { measurements: ['other'] } })), 'measurement not in policy allowlist'],
    ['weights digest not allowlisted', () => run(verifier({ policy: { measurements: [MEAS], weightsMeasurements: ['w1'] } })), 'measured weights digest not in policy allowlist'],
    ['resolver throws', () => run(verifier({ resolveEvidence: () => { throw new Error('store down'); } })), 'puf verification error (fail closed): store down'],
  ];
  it.each(rows)('%s', async (_n, f, reason) => {
    const r = (await f()) as { ok: boolean; reason?: string };
    if (reason === null) expect(r).toMatchObject({ ok: true, bound: true });
    else expect(r).toEqual({ ok: false, reason });
  });
  it('a malformed statement is denied, never thrown', async () => {
    for (const bad of [{ ...good, sig: 5 as never }, { ...good, sig: '' }, { ...good, alg: 5 as never }, 'x' as never, null as never]) {
      const r = (await run(verifier({}, enr, bad))) as { ok: boolean; reason?: string };
      expect(r.ok).toBe(false);
      expect(typeof r.reason).toBe('string');
    }
  });
  it('an empty or missing measurement allowlist is refused at construction (no accept-all)', () => {
    expect(() => createPufVerifier({ resolveEnrollment: () => enr, policy: { measurements: [] } })).toThrow('NON-EMPTY');
    expect(() => createPufVerifier({ resolveEnrollment: undefined as never, policy: { measurements: [MEAS] } })).toThrow('resolveEnrollment is required');
  });
  it('a caller who empties the allowlist after construction does not open the gate', async () => {
    const policy = { measurements: [MEAS] };
    const v = createPufVerifier({ resolveEnrollment: () => enr, policy, resolveEvidence: () => good });
    policy.measurements.length = 0;
    expect(await run(v)).toMatchObject({ ok: true });
  });
  it('the registry revokes for good: re-registering does not un-revoke', () => {
    const reg = createPufEnrollmentRegistry([enr]);
    expect(reg.lookup('node-1')).toBe(enr);
    reg.revoke('node-1');
    reg.register(enr);
    expect([reg.lookup('node-1'), reg.isRevoked('node-1')]).toEqual([undefined, true]);
  });
});

// ---- TPM provider (recorded command-runner transcript) -------------------------------------------
describe('TPM EK provider: recorded transcript', () => {
  const EK_A = Uint8Array.from({ length: 96 }, (_, i) => (i * 13 + 5) & 0xff);
  const EK_B = Uint8Array.from({ length: 96 }, (_, i) => (i * 17 + 9) & 0xff);
  const file = join(DIR, 'tpm-ek-transcript.json');
  type Row = { name: string; command: string; args: string[]; result: { status: number | null; stdoutB64: string; stderr?: string; error?: string } };
  const rec = (name: string, result: Row['result']): Row => ({ name, command: 'tpm2_readpublic', args: ['-c', '0x81010001', '-f', 'der', '-o', '/dev/stdout', '-Q'], result });
  const transcript: Row[] = [
    rec('ok-ek-a', { status: 0, stdoutB64: Buffer.from(EK_A).toString('base64') }),
    rec('ok-ek-b', { status: 0, stdoutB64: Buffer.from(EK_B).toString('base64') }),
    rec('tool-missing', { status: null, stdoutB64: '', error: 'tpm2_readpublic: ENOENT' }),
    rec('nonzero-exit', { status: 1, stdoutB64: '', stderr: 'ERROR: handle not found\n' }),
    rec('short-output', { status: 0, stdoutB64: Buffer.from(EK_A.slice(0, 10)).toString('base64') }),
    rec('empty-output', { status: 0, stdoutB64: '' }),
  ];
  it('the transcript fixture is recorded', () => {
    if (process.env.UPDATE_PUF_FIXTURE === '1') writeFileSync(file, `${JSON.stringify(transcript, null, 2)}\n`);
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(transcript);
  });
  const play = (name: string) => (command: string, args: readonly string[]): TpmCommandResult => {
    const row = transcript.find((r) => r.name === name)!;
    expect([command, [...args]]).toEqual([row.command, row.args]);
    return { status: row.result.status, stdout: Uint8Array.from(Buffer.from(row.result.stdoutB64, 'base64')), ...(row.result.stderr ? { stderr: row.result.stderr } : {}), ...(row.result.error ? { error: row.result.error } : {}) };
  };
  const tpm = (name: string) => new TpmEkPufProvider({ id: 'tpm-1', length: N, run: play(name) });
  const rows: [string, TpmEkPufProvider, string][] = [
    ['tool missing', tpm('tool-missing'), 'TpmEkPufProvider: tpm2-tools unavailable (fail closed): tpm2_readpublic: ENOENT'],
    ['non-zero exit', tpm('nonzero-exit'), "TpmEkPufProvider: 'tpm2_readpublic' exited with status 1 (fail closed): ERROR: handle not found"],
    ['short output', tpm('short-output'), 'TpmEkPufProvider: EK public too short (10 < 64 bytes) — TPM unavailable or wrong handle (fail closed)'],
    ['empty output', tpm('empty-output'), 'TpmEkPufProvider: EK public too short (0 < 64 bytes) — TPM unavailable or wrong handle (fail closed)'],
    ['runner throws', new TpmEkPufProvider({ id: 't', length: N, run: () => { throw new Error('boom'); } }), 'TpmEkPufProvider: tpm2-tools invocation threw (fail closed): boom'],
    ['runner returns nothing', new TpmEkPufProvider({ id: 't', length: N, run: () => undefined as never }), 'TpmEkPufProvider: command runner returned no result (fail closed)'],
  ];
  it.each(rows)('%s throws', (_n, p, msg) => {
    expect(() => p.response(CHALLENGE)).toThrow(msg);
  });
  it('enrolls and attests end to end; a different TPM is refused', async () => {
    const a = tpm('ok-ek-a');
    const enr = enrollPuf(a, CHALLENGE, { rep: REP, messageBits: MSG, alg: 'ed25519', randomBytes: detRng });
    const mk = (p: TpmEkPufProvider) => createPufVerifier({ resolveEnrollment: () => enr, policy: { measurements: [MEAS] }, resolveEvidence: () => createPufAttestor(p, enr).attest(claimsFor(EXPECTED)) });
    const run = (v: HardwareAttestationVerifier) => v.verify({ document: {} as never, ctx: {} as never, nowMs: T, expected: EXPECTED });
    expect(await run(mk(a))).toMatchObject({ ok: true });
    expect(await run(mk(tpm('ok-ek-b')))).toMatchObject({ ok: false });
  });
  it('rejects bad construction', () => {
    expect(() => new TpmEkPufProvider({ id: '', length: N })).toThrow('id must be a non-empty string');
    expect(() => new TpmEkPufProvider({ id: 'x', length: 0 })).toThrow('length must be a positive integer');
  });
});

// ---- the attestation gate (consumer) --------------------------------------------------------------
describe('PUF verifier behind the attestation gate', () => {
  const devAttestor = createDevAttestor(generateKeyPair().secretKey);
  const { grant } = mintGrant({
    principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: HOLDER, goal: 'g',
    envelope: { predicates: [{ verb: 'read', resource: '/a/*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  });
  const pcactn = buildPCActn({
    aud: 'x', grant, chain: [grant], plan: [{ id: 'n1', verb: 'read', resource: '/a/1', reversibility_class: 'reversible' }], nodeId: 'n1', counter: 1, signerSecret: A.secretKey,
    attestation: { quote_digest: NONCE, epoch: 1, model_id: 'm', measurement: 'x', operator: 'o' },
  });
  const ctx = { pcactn, grant } as VerifyContext;
  const binding: ExpectedAttestationBinding = { holderPub: HOLDER, grantRef: pcactn.grant_ref, epoch: 1, nonce: NONCE, nonceIssuedAt: T - 1000 };
  const doc = devAttestor.attest({ model_id: 'm', weights_digest: 'w', runtime_measurement: 'x', operator: 'o', nonce: NONCE, issued_at: T - 1000, expires_at: T + 60_000, holder_pub: HOLDER, grant_ref: pcactn.grant_ref, epoch: 1 });
  const enr = enroll();
  const reg = createPufEnrollmentRegistry([enr]);
  const pufV = createPufVerifier({ resolveEnrollment: (id) => reg.lookup(id), isRevoked: (id) => reg.isRevoked(id), policy: { measurements: [MEAS] }, resolveEvidence: () => attest(enr, provider(), binding) });
  const gate = (hardwareVerifier: HardwareAttestationVerifier, nonceStore?: ReturnType<typeof memoryNonceStore>) =>
    createAttestationVerifier({ trustedAttestorKeys: [devAttestor.publicKey], resolveDocument: attestationRegistry([doc]), expectedBinding: () => binding, now: () => T, hardwareVerifier, ...(nonceStore ? { nonceStore } : {}) });
  const settle = async (h: ReturnType<typeof gate>) => {
    const r = (await h(ctx)) as { ok?: boolean; bound?: boolean; reason?: string };
    return { ok: r.ok, bound: r.bound, reason: r.reason };
  };

  it('a registered, unrevoked device passes the gate; the nonce is single use', async () => {
    const store = memoryNonceStore();
    const h = gate(pufV, store);
    expect(await settle(h)).toEqual({ ok: true, bound: true, reason: undefined });
    expect(await settle(h)).toEqual({ ok: false, bound: false, reason: 'attestation nonce already consumed (replay)' });
  });
  it('a statement from another device is refused by the gate with the verifier reason', async () => {
    const other = createPufVerifier({ resolveEnrollment: () => enr, policy: { measurements: [MEAS] }, resolveEvidence: () => attest(enr, provider(new Uint8Array(32).fill(0x22)), binding) });
    expect(await settle(gate(other))).toEqual({
      ok: false, bound: false,
      reason: 'hardware attestation rejected: PUF statement signature does not verify under the enrolled public key (wrong/cloned device or excessive noise)',
    });
  });
  it('a revoked device is refused at the gate', async () => {
    const r2 = createPufEnrollmentRegistry([enr]);
    r2.revoke('node-1');
    const v = createPufVerifier({ resolveEnrollment: (id) => r2.lookup(id), isRevoked: (id) => r2.isRevoked(id), policy: { measurements: [MEAS] }, resolveEvidence: () => attest(enr, provider(), binding) });
    expect(await settle(gate(v))).toMatchObject({ ok: false, reason: "hardware attestation rejected: PUF enrollment for provider 'node-1' is revoked" });
  });
  it('a PUF root is never hardware assurance: verifier, gate and multi-root all report software', () => {
    expect(assuranceLabelOf(pufV)).toEqual({ level: 'software', vendor: 'puf' });
    expect(assuranceLabelOf(gate(pufV))).toEqual({ level: 'software', vendor: 'puf' });
    expect(multiRootLevel([{ verifier: pufV, required: true }, { verifier: pufV }], 2)).toBe('software');
    const hw = setAssuranceLabel({ verify: () => ({ ok: false }) }, { level: 'hardware' });
    // one real hardware root plus a PUF root is `hardware`, never `multi_root`
    expect(multiRootLevel([{ verifier: hw, required: true }, { verifier: pufV, required: true }], 2)).toBe('hardware');
  });
});

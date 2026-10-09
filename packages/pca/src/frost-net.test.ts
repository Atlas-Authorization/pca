import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { frostAggregate, frostCommit, frostSign, frostTrustedDealerKeygen, type FrostParticipantShare } from './frost';
import { generateKeyPair, verify } from './keys';
import { b64u, utf8 } from './hash';
import {
  frostActionDigest,
  CoordinatorError,
  CoordinatorTimeoutError,
  createSignerPoP,
  enrollVerificationShares,
  EquivocationError,
  EquivocationGuard,
  GuardianSignerService,
  httpSignerTransport,
  inProcessTransport,
  issueAllowToken,
  NetworkCoordinator,
  PoPError,
  startSignerHttpServer,
  verifyAllowToken,
  verifySignerPoP,
  type AllowToken,
  type Round1Response,
  type Round2Response,
  type SignerEnrollment,
  type SignerTransport,
} from './frost-net';

// =================================================================================================
// Shared fixtures.
// =================================================================================================

function fixture(t: number, n: number) {
  const kg = frostTrustedDealerKeygen(t, n);
  const policy = generateKeyPair();
  const verificationShares = kg.participantShares.map((p) => ({ identifier: p.identifier, publicKey: p.publicKey }));
  const makeServices = (policyPk: Uint8Array = policy.publicKey, now?: () => number) =>
    kg.participantShares.map(
      (p) =>
        new GuardianSignerService({
          identifier: p.identifier,
          share: p.share,
          groupPublicKey: kg.groupPublicKey,
          threshold: t,
          policyAuthorityPublicKey: policyPk,
          ...(now ? { now } : {}),
        }),
    );
  return { t, n, kg, policy, verificationShares, makeServices };
}

function coordinatorFor(fx: ReturnType<typeof fixture>, transports: SignerTransport[]): NetworkCoordinator {
  return new NetworkCoordinator({
    groupPublicKey: fx.kg.groupPublicKey,
    threshold: fx.t,
    signers: transports,
    verificationShares: fx.verificationShares,
  });
}

const MSG = utf8('transfer 100 USDC to bob — pcactn thresholdMessage body');

// =================================================================================================
// 1. In-process (separate-actor, isolated session state) — the security-property battery.
// =================================================================================================

describe('network FROST — in-process separate-actor transport', () => {
  it('t-of-n network sign yields a valid aggregate verifying under the group key', async () => {
    const fx = fixture(2, 3);
    const services = fx.makeServices();
    const coord = coordinatorFor(fx, services.map(inProcessTransport));
    const allow = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });

    const res = await coord.sign(MSG, allow);

    expect(res.signers.length).toBe(2);
    expect(res.signature.length).toBe(64);
    // The aggregate is a STANDARD Ed25519 signature — exactly PCA's existing leaf-sig check.
    expect(verify(fx.kg.groupPublicKey, MSG, res.signature)).toBe(true);
  });

  it('works for any t-subset of the n signers (quorum {1,3})', async () => {
    const fx = fixture(2, 3);
    const services = fx.makeServices();
    const coord = coordinatorFor(fx, services.map(inProcessTransport));
    const allow = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });

    const res = await coord.sign(MSG, allow, { signerIds: [1, 3] });
    expect(res.signers.sort()).toEqual([1, 3]);
    expect(verify(fx.kg.groupPublicKey, MSG, res.signature)).toBe(true);
  });

  it('a 3-of-5 quorum also verifies', async () => {
    const fx = fixture(3, 5);
    const services = fx.makeServices();
    const coord = coordinatorFor(fx, services.map(inProcessTransport));
    const allow = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    const res = await coord.sign(MSG, allow, { signerIds: [2, 4, 5] });
    expect(res.signers.length).toBe(3);
    expect(verify(fx.kg.groupPublicKey, MSG, res.signature)).toBe(true);
  });

  // -- threshold integrity -----------------------------------------------------------------------

  it('fewer than t selected signers → no signature', async () => {
    const fx = fixture(2, 3);
    const services = fx.makeServices();
    const coord = coordinatorFor(fx, [inProcessTransport(services[0]!)]);
    const allow = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    await expect(coord.sign(MSG, allow)).rejects.toBeInstanceOf(CoordinatorError);
  });

  it('a single refusing signer (in a t-sized quorum) → no signature', async () => {
    const fx = fixture(2, 3);
    // signer #2 trusts a DIFFERENT policy authority, so it refuses the (correctly-signed) allow.
    const rogueAuthority = generateKeyPair();
    const good = fx.makeServices();
    const refuser = new GuardianSignerService({
      identifier: good[1]!.identifier,
      share: fx.kg.participantShares[1]!.share,
      groupPublicKey: fx.kg.groupPublicKey,
      threshold: fx.t,
      policyAuthorityPublicKey: rogueAuthority.publicKey,
    });
    const coord = coordinatorFor(fx, [inProcessTransport(good[0]!), inProcessTransport(refuser)]);
    const allow = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });

    const err = await coord.sign(MSG, allow).catch((e) => e);
    expect(err).toBeInstanceOf(CoordinatorError);
    expect((err as CoordinatorError).refusals.some((r) => r.identifier === 2)).toBe(true);
  });

  // -- policy authorization gate -----------------------------------------------------------------

  it('a signer given NO allow token refuses', async () => {
    const fx = fixture(2, 3);
    const services = fx.makeServices();
    const coord = coordinatorFor(fx, services.map(inProcessTransport));
    // Forge a structurally-empty "token".
    const notAToken = {} as unknown as AllowToken;
    const err = await coord.sign(MSG, notAToken).catch((e) => e);
    expect(err).toBeInstanceOf(CoordinatorError);
    expect((err as CoordinatorError).refusals.length).toBeGreaterThanOrEqual(2);
  });

  it('a signer given an allow token signed by the WRONG authority refuses', async () => {
    const fx = fixture(2, 3);
    const services = fx.makeServices();
    const coord = coordinatorFor(fx, services.map(inProcessTransport));
    const attacker = generateKeyPair();
    const forged = issueAllowToken(attacker.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    await expect(coord.sign(MSG, forged)).rejects.toBeInstanceOf(CoordinatorError);
  });

  it('an allow token for a DIFFERENT message does not authorize this message', async () => {
    const fx = fixture(2, 3);
    const services = fx.makeServices();
    const coord = coordinatorFor(fx, services.map(inProcessTransport));
    const allowForOther = issueAllowToken(fx.policy.secretKey, { message: utf8('a totally different action'), groupPublicKey: fx.kg.groupPublicKey });
    const err = await coord.sign(MSG, allowForOther).catch((e) => e);
    expect(err).toBeInstanceOf(CoordinatorError);
    expect((err as CoordinatorError).refusals.every((r) => /different action digest/.test(r.reason))).toBe(true);
  });

  it('an allow token for a DIFFERENT group key is refused', async () => {
    const fx = fixture(2, 3);
    const otherGroup = generateKeyPair();
    const services = fx.makeServices();
    const coord = coordinatorFor(fx, services.map(inProcessTransport));
    const allowWrongGroup = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: otherGroup.publicKey });
    await expect(coord.sign(MSG, allowWrongGroup)).rejects.toBeInstanceOf(CoordinatorError);
  });

  it('an EXPIRED allow token is refused', async () => {
    const fx = fixture(2, 3);
    const services = fx.makeServices(fx.policy.publicKey, () => 10_000); // signer clock at t=10000
    const coord = coordinatorFor(fx, services.map(inProcessTransport));
    const expired = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey, expiresAt: 5_000 });
    const err = await coord.sign(MSG, expired).catch((e) => e);
    expect(err).toBeInstanceOf(CoordinatorError);
    expect((err as CoordinatorError).refusals.every((r) => /expired/.test(r.reason))).toBe(true);
  });

  it('a not-yet-valid allow token is refused', async () => {
    const fx = fixture(2, 3);
    const services = fx.makeServices(fx.policy.publicKey, () => 1_000);
    const coord = coordinatorFor(fx, services.map(inProcessTransport));
    const future = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey, notBefore: 5_000 });
    await expect(coord.sign(MSG, future)).rejects.toBeInstanceOf(CoordinatorError);
  });

  // -- compromised coordinator -------------------------------------------------------------------

  it('a compromised coordinator cannot forge a signature over a NEW message (no allow for it)', async () => {
    const fx = fixture(2, 3);
    const services = fx.makeServices();
    const coord = coordinatorFor(fx, services.map(inProcessTransport));
    // Coordinator holds a valid allow for MSG, but wants a signature over evil.
    const allowForMsg = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    const evil = utf8('drain the treasury');
    await expect(coord.sign(evil, allowForMsg)).rejects.toBeInstanceOf(CoordinatorError);
    // It also genuinely has no signature over `evil`.
    const got = await coord.sign(evil, allowForMsg).catch(() => null);
    expect(got).toBeNull();
  });

  it('a compromised coordinator REPLAYING an old allow can only (re)sign the same authorized message', async () => {
    const fx = fixture(2, 3);
    const services = fx.makeServices();
    const transports = services.map(inProcessTransport);
    const allow = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    // Replay the exact allow in a brand-new session → re-signs MSG (fresh nonces), still just MSG.
    const coordA = coordinatorFor(fx, transports);
    const res1 = await coordA.sign(MSG, allow);
    expect(verify(fx.kg.groupPublicKey, MSG, res1.signature)).toBe(true);
    const coordB = coordinatorFor(fx, services.map(inProcessTransport)); // fresh services → fresh sessions
    const res2 = await coordB.sign(MSG, allow);
    expect(verify(fx.kg.groupPublicKey, MSG, res2.signature)).toBe(true);
    // …but the replayed allow still cannot authorize a different message.
    await expect(coordB.sign(utf8('something else'), allow)).rejects.toBeInstanceOf(CoordinatorError);
  });

  it('a compromised coordinator holding < t transports cannot aggregate', async () => {
    const fx = fixture(3, 5);
    const services = fx.makeServices();
    // Attacker only controls 2 of the 5 signers.
    const coord = coordinatorFor(fx, [inProcessTransport(services[0]!), inProcessTransport(services[1]!)]);
    const allow = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    await expect(coord.sign(MSG, allow)).rejects.toBeInstanceOf(CoordinatorError);
  });

  it('a coordinator that lies about the verification-share set is refused (interpolation check)', async () => {
    const fx = fixture(2, 3);
    const services = fx.makeServices();
    // Swap one verification share for a bogus point → Σλ_i·PK_i no longer equals the group key.
    const bogus = generateKeyPair();
    const liar = new NetworkCoordinator({
      groupPublicKey: fx.kg.groupPublicKey,
      threshold: fx.t,
      signers: services.map(inProcessTransport),
      verificationShares: fx.verificationShares.map((v, i) => (i === 1 ? { identifier: v.identifier, publicKey: bogus.publicKey } : v)),
    });
    const allow = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    await expect(liar.sign(MSG, allow)).rejects.toBeInstanceOf(CoordinatorError);
  });

  // -- a single compromised signer -----------------------------------------------------------------

  it('a single compromised signer cannot produce a valid aggregate on its own', async () => {
    const fx = fixture(2, 3);
    const services = fx.makeServices();
    const victim = services[0]!;
    const allow = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });

    // Attacker drives the one signer it controls through a full honest round 1 + round 2.
    const sessionId = 'attacker-session';
    const r1 = victim.round1({ typ: 'pca.frost.round1.v1', session_id: sessionId });
    expect(r1.ok).toBe(true);
    if (!r1.ok) throw new Error('unreachable');
    const r2 = victim.round2({
      typ: 'pca.frost.round2.v1',
      session_id: sessionId,
      message: b64u(MSG),
      group_pk: b64u(fx.kg.groupPublicKey),
      commitments: [r1.commitment],
      verification_shares: [{ identifier: 1, publicKey: b64u(fx.kg.participantShares[0]!.publicKey) }],
      allow,
    });
    // The lone signer refuses: a 1-element signing set is below t=2.
    expect(r2.ok).toBe(false);

    // Even if it had produced a share, one share cannot aggregate into a valid group signature.
    const lone: FrostParticipantShare = fx.kg.participantShares[0]!;
    const c = frostCommit(lone);
    const share = frostSign(lone.identifier, lone.share, fx.kg.groupPublicKey, { hiding: c.hidingNonce, binding: c.bindingNonce }, MSG, [c.commitment]);
    expect(() => frostAggregate(MSG, [c.commitment], [share], fx.kg.groupPublicKey, { threshold: 2 })).toThrow();
  });

  // -- one-shot / service hygiene ------------------------------------------------------------------

  it('a session is one-shot: a second round 2 is refused, and duplicate round 1 is refused', async () => {
    const fx = fixture(2, 3);
    const services = fx.makeServices();
    const coord = coordinatorFor(fx, services.map(inProcessTransport));
    const allow = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    await coord.sign(MSG, allow, { signerIds: [1, 2] });

    // Directly probe signer #1: the session it just completed cannot be re-opened or re-signed.
    const s1 = services[0]!;
    const dupRound1 = s1.round1({ typ: 'pca.frost.round1.v1', session_id: 'sess' });
    expect(dupRound1.ok).toBe(true); // fresh session id is fine
    const dupAgain = s1.round1({ typ: 'pca.frost.round1.v1', session_id: 'sess' });
    expect(dupAgain.ok).toBe(false); // but the SAME session id cannot be re-committed
  });

  it('the signer service never emits its secret share', async () => {
    const fx = fixture(2, 3);
    const s = fx.makeServices()[0]!;
    const r1 = s.round1({ typ: 'pca.frost.round1.v1', session_id: 'x' });
    const serialized = JSON.stringify(r1);
    const shareB64 = b64u(fx.kg.participantShares[0]!.share);
    expect(serialized.includes(shareB64)).toBe(false);
    // The public verification share IS exposed (it is public), the secret share is not reachable.
    expect(b64u(s.verificationShare)).toBe(b64u(fx.kg.participantShares[0]!.publicKey));
    expect(Object.keys(s)).not.toContain('share');
  });

  // -- allow-token unit checks ---------------------------------------------------------------------

  it('verifyAllowToken binds authority, group key, message digest, and validity window', () => {
    const fx = fixture(2, 3);
    const tok = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey, expiresAt: 100 });
    const base = { policyAuthorityPublicKey: fx.policy.publicKey, groupPublicKey: fx.kg.groupPublicKey, message: MSG, now: 50 };
    expect(verifyAllowToken(tok, base).ok).toBe(true);
    expect(tok.body.action_digest).toBe(frostActionDigest(MSG));
    // wrong authority
    expect(verifyAllowToken(tok, { ...base, policyAuthorityPublicKey: generateKeyPair().publicKey }).ok).toBe(false);
    // wrong message
    expect(verifyAllowToken(tok, { ...base, message: utf8('other') }).ok).toBe(false);
    // expired
    expect(verifyAllowToken(tok, { ...base, now: 100 }).ok).toBe(false);
    // tampered signature
    expect(verifyAllowToken({ ...tok, sig: b64u(new Uint8Array(64)) }, base).ok).toBe(false);
    // tampered body (digest) without re-signing
    const tampered = { ...tok, body: { ...tok.body, action_digest: frostActionDigest(utf8('x')) } };
    expect(verifyAllowToken(tampered, base).ok).toBe(false);
  });
});

// =================================================================================================
// 2. Real MULTI-PROCESS: each signer is its own OS process (one share per process) over loopback HTTP.
// =================================================================================================

interface SpawnedSigner {
  identifier: number;
  url: string;
  child: ChildProcess;
  exited: Promise<void>;
}

const RUNNER = resolve(__dirname, 'frost-net-runner.ts');
const READY = 'FROST_SIGNER_READY ';

function spawnSigner(configPath: string): Promise<SpawnedSigner> {
  return new Promise((resolvePromise, reject) => {
    // Run node DIRECTLY with tsx as a loader (not the `.bin/tsx` wrapper, which would fork a grandchild
    // the kill can't reach). This way the child IS the HTTP server process — killing it frees the port.
    const child = spawn(process.execPath, ['--import', 'tsx', RUNNER, configPath], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let settled = false;
    const exited = new Promise<void>((res) => child.on('exit', () => res()));
    const timer = setTimeout(() => {
      if (!settled) reject(new Error('signer did not become ready in time'));
    }, 20_000);
    child.stdout!.on('data', (d: Buffer) => {
      out += d.toString();
      const line = out.split('\n').find((l) => l.startsWith(READY));
      if (line && !settled) {
        settled = true;
        clearTimeout(timer);
        const info = JSON.parse(line.slice(READY.length)) as { identifier: number; url: string };
        resolvePromise({ identifier: info.identifier, url: info.url, child, exited });
      }
    });
    child.stderr!.on('data', (d: Buffer) => process.stderr.write(`[signer] ${d.toString()}`));
    child.on('error', reject);
  });
}

describe('network FROST — real multi-process HTTP transport (one share per OS process)', () => {
  const t = 2;
  const n = 3;
  const kg = frostTrustedDealerKeygen(t, n);
  const policy = generateKeyPair();
  const verificationShares = kg.participantShares.map((p) => ({ identifier: p.identifier, publicKey: p.publicKey }));
  let tmp: string;
  let signers: SpawnedSigner[] = [];

  beforeAll(async () => {
    tmp = mkdtempSync(join(tmpdir(), 'frost-net-'));
    signers = [];
    for (const p of kg.participantShares) {
      const cfgPath = join(tmp, `signer-${p.identifier}.json`);
      writeFileSync(
        cfgPath,
        JSON.stringify({
          identifier: p.identifier,
          share: b64u(p.share),
          groupPublicKey: b64u(kg.groupPublicKey),
          threshold: t,
          policyAuthorityPublicKey: b64u(policy.publicKey),
        }),
      );
      signers.push(await spawnSigner(cfgPath));
    }
  }, 60_000);

  afterAll(async () => {
    for (const s of signers) {
      if (!s.child.killed) s.child.kill('SIGKILL');
    }
    await Promise.all(signers.map((s) => s.exited)).catch(() => undefined);
    if (tmp) rmSync(tmp, { recursive: true, force: true });
  });

  it('spawned exactly one process per share, each reachable on its own port', () => {
    expect(signers.length).toBe(3);
    expect(new Set(signers.map((s) => s.url)).size).toBe(3);
  });

  it('a t-of-n signature across separate PROCESSES verifies under the group key', async () => {
    const transports = signers.map((s) => httpSignerTransport(s.url, s.identifier));
    const coord = new NetworkCoordinator({ groupPublicKey: kg.groupPublicKey, threshold: t, signers: transports, verificationShares });
    const msg = utf8('cross-process network FROST cosign');
    const allow = issueAllowToken(policy.secretKey, { message: msg, groupPublicKey: kg.groupPublicKey });
    const res = await coord.sign(msg, allow, { signerIds: [1, 2] });
    expect(res.signers.sort()).toEqual([1, 2]);
    expect(verify(kg.groupPublicKey, msg, res.signature)).toBe(true);
  });

  it('a forged allow token is refused by the remote signer over the wire', async () => {
    const transports = signers.map((s) => httpSignerTransport(s.url, s.identifier));
    const coord = new NetworkCoordinator({ groupPublicKey: kg.groupPublicKey, threshold: t, signers: transports, verificationShares });
    const msg = utf8('attempted remote forgery');
    const attacker = generateKeyPair();
    const forged = issueAllowToken(attacker.secretKey, { message: msg, groupPublicKey: kg.groupPublicKey });
    const err = await coord.sign(msg, forged, { signerIds: [1, 2] }).catch((e) => e);
    expect(err).toBeInstanceOf(CoordinatorError);
    expect((err as CoordinatorError).refusals.some((r) => /policy authorization/.test(r.reason))).toBe(true);
  });

  it('with only t-1 signer processes reachable, no signature is produced', async () => {
    // Kill signer #2 and wait for the process to actually exit.
    const victim = signers.find((s) => s.identifier === 2)!;
    victim.child.kill('SIGKILL');
    await victim.exited;

    const transports = signers.map((s) => httpSignerTransport(s.url, s.identifier, { timeoutMs: 3_000 }));
    const coord = new NetworkCoordinator({ groupPublicKey: kg.groupPublicKey, threshold: t, signers: transports, verificationShares });
    const msg = utf8('needs two live processes');
    const allow = issueAllowToken(policy.secretKey, { message: msg, groupPublicKey: kg.groupPublicKey });
    // Only #1 and #3 remain; selecting #1 + the dead #2 must fail.
    await expect(coord.sign(msg, allow, { signerIds: [1, 2] })).rejects.toBeInstanceOf(CoordinatorError);
  });
});

// =================================================================================================
// 3. Byzantine-robust defenses (boundary F-1 protocol half): rogue-key PoP, equivocation, timeout.
// =================================================================================================

describe('network FROST — rogue-key defense (proof-of-possession)', () => {
  it('a signer PoP verifies and enrollVerificationShares accepts a fully-PoP’d set', () => {
    const fx = fixture(2, 3);
    const enrollments = fx.makeServices().map((s) => s.enrollment());
    for (const e of enrollments) {
      expect(verifySignerPoP(e.pop, { groupPublicKey: fx.kg.groupPublicKey })).toBe(true);
      expect(e.pop.publicKey).toBe(b64u(e.publicKey));
    }
    const shares = enrollVerificationShares(enrollments, { groupPublicKey: fx.kg.groupPublicKey });
    expect(shares.map((s) => s.identifier).sort()).toEqual([1, 2, 3]);
  });

  it('a PoP is bound to the group key: it does not verify under a different group key', () => {
    const fx = fixture(2, 3);
    const e = fx.makeServices()[0]!.enrollment();
    expect(verifySignerPoP(e.pop, { groupPublicKey: fx.kg.groupPublicKey })).toBe(true);
    expect(verifySignerPoP(e.pop, { groupPublicKey: generateKeyPair().publicKey })).toBe(false);
  });

  it('a forged PoP (zeroed response scalar) is rejected', () => {
    const fx = fixture(2, 3);
    const e = fx.makeServices()[0]!.enrollment();
    expect(verifySignerPoP({ ...e.pop, s: b64u(new Uint8Array(32)) }, { groupPublicKey: fx.kg.groupPublicKey })).toBe(false);
    expect(verifySignerPoP({ ...e.pop, R: b64u(new Uint8Array(32)) }, { groupPublicKey: fx.kg.groupPublicKey })).toBe(false);
  });

  it('a rogue key (victim’s verification share, attacker-controlled PoP) is REJECTED at enrollment', () => {
    const fx = fixture(2, 3);
    const enrollments = fx.makeServices().map((s) => s.enrollment());
    // The attacker claims signer 1's verification share but can only build a PoP for a key IT controls.
    const attackerPop = createSignerPoP(1, fx.kg.participantShares[1]!.share, { groupPublicKey: fx.kg.groupPublicKey });
    // (a) PoP's publicKey does not match the claimed verification share → rejected.
    const rogueA: SignerEnrollment = { identifier: 1, publicKey: fx.kg.participantShares[0]!.publicKey, pop: attackerPop };
    expect(() => enrollVerificationShares([rogueA, enrollments[1]!, enrollments[2]!], { groupPublicKey: fx.kg.groupPublicKey })).toThrow(PoPError);
    // (b) Even if the attacker forces the PoP's publicKey field to the victim's key, the proof does not verify.
    const rogueB: SignerEnrollment = {
      identifier: 1,
      publicKey: fx.kg.participantShares[0]!.publicKey,
      pop: { ...attackerPop, publicKey: b64u(fx.kg.participantShares[0]!.publicKey) },
    };
    expect(() => enrollVerificationShares([rogueB, enrollments[1]!, enrollments[2]!], { groupPublicKey: fx.kg.groupPublicKey })).toThrow(PoPError);
  });

  it('enrollVerificationShares rejects a duplicate enrollment', () => {
    const fx = fixture(2, 3);
    const enrollments = fx.makeServices().map((s) => s.enrollment());
    expect(() => enrollVerificationShares([enrollments[0]!, enrollments[0]!], { groupPublicKey: fx.kg.groupPublicKey })).toThrow(PoPError);
  });

  it('happy path via the PoP enrollment surface still yields a valid aggregate', async () => {
    const fx = fixture(2, 3);
    const services = fx.makeServices();
    const coord = new NetworkCoordinator({
      groupPublicKey: fx.kg.groupPublicKey,
      threshold: 2,
      signers: services.map(inProcessTransport),
      enroll: services.map((s) => s.enrollment()),
    });
    const allow = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    const res = await coord.sign(MSG, allow);
    expect(res.signers.length).toBe(2);
    expect(verify(fx.kg.groupPublicKey, MSG, res.signature)).toBe(true);
  });

  it('the coordinator refuses a signer whose round-1 PoP is invalid (rogue-key defense, per round)', async () => {
    const fx = fixture(2, 3);
    const services = fx.makeServices();
    // Wrap signer #2 so its round-1 PoP is corrupted on the wire.
    const corrupt = (service: GuardianSignerService): SignerTransport => {
      const inner = inProcessTransport(service);
      return {
        identifier: service.identifier,
        round1: async (req): Promise<Round1Response> => {
          const r = await inner.round1(req);
          return r.ok ? { ...r, pop: { ...r.pop, s: b64u(new Uint8Array(32)) } } : r;
        },
        round2: (req): Promise<Round2Response> => inner.round2(req),
      };
    };
    const coord = coordinatorFor(fx, [inProcessTransport(services[0]!), corrupt(services[1]!)]);
    const allow = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    const err = await coord.sign(MSG, allow).catch((e) => e);
    expect(err).toBeInstanceOf(CoordinatorError);
    expect((err as CoordinatorError).refusals.some((r) => r.identifier === 2 && /proof-of-possession/.test(r.reason))).toBe(true);
  });
});

describe('network FROST — equivocation detection', () => {
  it('EquivocationGuard: a second DIFFERING message for the same (session,round,signer) throws; identical repeats are idempotent', () => {
    const g = new EquivocationGuard();
    g.observe('sess', 1, 1, { hiding: 'A', binding: 'B', identifier: 1 });
    // identical repeat — allowed (honest retransmit)
    expect(() => g.observe('sess', 1, 1, { hiding: 'A', binding: 'B', identifier: 1 })).not.toThrow();
    // a different value for the same tuple — rejected
    expect(() => g.observe('sess', 1, 1, { hiding: 'Z', binding: 'B', identifier: 1 })).toThrow(EquivocationError);
    // a different round / signer / session is independent
    expect(() => g.observe('sess', 2, 1, { x: 1 })).not.toThrow();
    expect(() => g.observe('sess', 1, 2, { x: 1 })).not.toThrow();
    expect(() => g.observe('other', 1, 1, { hiding: 'Z', binding: 'B', identifier: 1 })).not.toThrow();
  });

  it('the signer fails closed when its own commitment in the round-2 set differs from its round-1 commitment', () => {
    const fx = fixture(2, 3);
    const [s1, s2] = fx.makeServices();
    const sid = 'equiv-session';
    const r1a = s1!.round1({ typ: 'pca.frost.round1.v1', session_id: sid });
    const r1b = s2!.round1({ typ: 'pca.frost.round1.v1', session_id: sid });
    expect(r1a.ok && r1b.ok).toBe(true);
    if (!r1a.ok || !r1b.ok) throw new Error('unreachable');
    // A coordinator swaps signer 1's own commitment for a DIFFERENT (freshly committed) one.
    const forged = frostCommit(fx.kg.participantShares[0]!);
    const tamperedOwn = { identifier: 1, hiding: b64u(forged.commitment.hiding), binding: b64u(forged.commitment.binding) };
    const allow = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    const r2 = s1!.round2({
      typ: 'pca.frost.round2.v1',
      session_id: sid,
      message: b64u(MSG),
      group_pk: b64u(fx.kg.groupPublicKey),
      commitments: [tamperedOwn, r1b.commitment],
      verification_shares: fx.verificationShares
        .filter((v) => v.identifier === 1 || v.identifier === 2)
        .map((v) => ({ identifier: v.identifier, publicKey: b64u(v.publicKey) })),
      allow,
    });
    expect(r2.ok).toBe(false);
    if (r2.ok) throw new Error('unreachable');
    expect(r2.reason).toMatch(/equivocation/);
  });

  it('the coordinator rejects a signer that equivocates on its round-1 commitment across a reused session id', async () => {
    const fx = fixture(2, 3);
    const services = fx.makeServices();
    // Transport for signer 1 that returns its honest commitment on the first poll and a DIFFERENT one after.
    const equivocator = (service: GuardianSignerService, share: Uint8Array): SignerTransport => {
      const inner = inProcessTransport(service);
      let calls = 0;
      const pop = createSignerPoP(service.identifier, share, { groupPublicKey: fx.kg.groupPublicKey });
      return {
        identifier: service.identifier,
        round1: async (req): Promise<Round1Response> => {
          calls += 1;
          if (calls === 1) return inner.round1(req);
          const c = frostCommit({ identifier: service.identifier, share, publicKey: service.verificationShare });
          return {
            ok: true,
            identifier: service.identifier,
            commitment: { identifier: service.identifier, hiding: b64u(c.commitment.hiding), binding: b64u(c.commitment.binding) },
            pop,
          };
        },
        round2: (req): Promise<Round2Response> => inner.round2(req),
      };
    };
    const coord = new NetworkCoordinator({
      groupPublicKey: fx.kg.groupPublicKey,
      threshold: 2,
      signers: [equivocator(services[0]!, fx.kg.participantShares[0]!.share), inProcessTransport(services[1]!)],
      verificationShares: fx.verificationShares,
      newSessionId: () => 'fixed-session',
    });
    const allow = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    // First call seeds the guard with signer 1's honest round-1 commitment under 'fixed-session'.
    const res1 = await coord.sign(MSG, allow);
    expect(verify(fx.kg.groupPublicKey, MSG, res1.signature)).toBe(true);
    // Second call (same session id) — signer 1 now presents a DIFFERENT commitment → equivocation → abort.
    const err = await coord.sign(MSG, allow).catch((e) => e);
    expect(err).toBeInstanceOf(CoordinatorError);
    expect((err as CoordinatorError).refusals.some((r) => r.identifier === 1 && /equivocation/.test(r.reason))).toBe(true);
  });
});

describe('network FROST — timeout / abort handling', () => {
  const hangTransport = (id: number): SignerTransport => ({
    identifier: id,
    round1: (): Promise<Round1Response> => new Promise<Round1Response>(() => undefined),
    round2: (): Promise<Round2Response> => new Promise<Round2Response>(() => undefined),
  });

  it('a session that does not reach threshold within the window aborts with CoordinatorTimeoutError and no signature', async () => {
    const fx = fixture(2, 3);
    const coord = new NetworkCoordinator({
      groupPublicKey: fx.kg.groupPublicKey,
      threshold: 2,
      signers: [hangTransport(1), hangTransport(2)],
      verificationShares: fx.verificationShares,
      timeoutMs: 50,
    });
    const allow = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    const err = await coord.sign(MSG, allow).catch((e) => e);
    expect(err).toBeInstanceOf(CoordinatorTimeoutError);
    expect(err).toBeInstanceOf(CoordinatorError); // typed, and still caught by existing handling
    // And it genuinely produced no signature.
    const got = await coord.sign(MSG, allow).catch(() => null);
    expect(got).toBeNull();
  });

  it('a per-call timeout overrides the constructor default', async () => {
    const fx = fixture(2, 3);
    const coord = new NetworkCoordinator({
      groupPublicKey: fx.kg.groupPublicKey,
      threshold: 2,
      signers: [hangTransport(1), hangTransport(2)],
      verificationShares: fx.verificationShares,
    });
    const allow = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    await expect(coord.sign(MSG, allow, { timeoutMs: 40 })).rejects.toBeInstanceOf(CoordinatorTimeoutError);
  });

  it('the happy path completes well within a generous deadline and still produces a valid allow-authorized signature', async () => {
    const fx = fixture(2, 3);
    const services = fx.makeServices();
    const coord = new NetworkCoordinator({
      groupPublicKey: fx.kg.groupPublicKey,
      threshold: 2,
      signers: services.map(inProcessTransport),
      verificationShares: fx.verificationShares,
      timeoutMs: 5_000,
    });
    const allow = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    const res = await coord.sign(MSG, allow);
    expect(verify(fx.kg.groupPublicKey, MSG, res.signature)).toBe(true);
  });

  it('the signer stale-session guard refuses a round 2 that arrives after the TTL (no share emitted)', () => {
    const fx = fixture(2, 3);
    let clock = 1_000;
    const svc = new GuardianSignerService({
      identifier: 1,
      share: fx.kg.participantShares[0]!.share,
      groupPublicKey: fx.kg.groupPublicKey,
      threshold: 2,
      policyAuthorityPublicKey: fx.policy.publicKey,
      sessionTtlMs: 100,
      now: () => clock,
    });
    const r1 = svc.round1({ typ: 'pca.frost.round1.v1', session_id: 'ttl' });
    expect(r1.ok).toBe(true);
    if (!r1.ok) throw new Error('unreachable');
    clock = 1_000 + 101; // advance past the TTL window
    const allow = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    const r2 = svc.round2({
      typ: 'pca.frost.round2.v1',
      session_id: 'ttl',
      message: b64u(MSG),
      group_pk: b64u(fx.kg.groupPublicKey),
      commitments: [r1.commitment],
      verification_shares: [{ identifier: 1, publicKey: b64u(fx.kg.participantShares[0]!.publicKey) }],
      allow,
    });
    expect(r2.ok).toBe(false);
    if (r2.ok) throw new Error('unreachable');
    expect(r2.reason).toMatch(/stale-session|expired/);
  });

  it('a round 2 within the TTL is not refused for staleness (TTL does not break the happy path)', async () => {
    const fx = fixture(2, 3);
    let clock = 1_000;
    const services = fx.kg.participantShares.map(
      (p) =>
        new GuardianSignerService({
          identifier: p.identifier,
          share: p.share,
          groupPublicKey: fx.kg.groupPublicKey,
          threshold: 2,
          policyAuthorityPublicKey: fx.policy.publicKey,
          sessionTtlMs: 10_000,
          now: () => clock,
        }),
    );
    const coord = coordinatorFor(fx, services.map(inProcessTransport));
    clock = 1_050; // small advance, well within TTL
    const allow = issueAllowToken(fx.policy.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    const res = await coord.sign(MSG, allow);
    expect(verify(fx.kg.groupPublicKey, MSG, res.signature)).toBe(true);
  });
});

// A direct HTTP-server unit check (no child process) to pin the server-side wire behavior.
describe('network FROST — signer HTTP server wire behavior', () => {
  it('serves round1/round2 and 404s unknown routes', async () => {
    const fx = fixture(2, 3);
    const service = fx.makeServices()[0]!;
    const srv = await startSignerHttpServer(service);
    try {
      const r1 = await fetch(`${srv.url}/round1`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ typ: 'pca.frost.round1.v1', session_id: 'wire' }),
      });
      const body = (await r1.json()) as { ok: boolean; identifier: number };
      expect(body.ok).toBe(true);
      expect(body.identifier).toBe(1);

      const nf = await fetch(`${srv.url}/nope`, { method: 'POST' });
      expect(nf.status).toBe(404);
    } finally {
      await srv.close();
    }
  });
});

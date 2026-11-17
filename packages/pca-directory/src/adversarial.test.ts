import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair } from '@atlasauth/pca';
import { cosignTreeHead } from '@atlasauth/pca/ext/ledger';
import {
  DirectoryLog,
  Monitor,
  Witness,
  MemoryWitnessState,
  checkAgent,
  decodeBundle,
  encodeBundle,
  memoryLogClient,
  signRevocation,
  stapleBundle,
  type CheckOptions,
  type LogClient,
  type StapledBundle,
} from './index';
import { HOUR, T0, makeAgent, makeWorld, register, type World } from './test-util';

const opts = (w: World, o: Partial<CheckOptions['policy']> = {}, witnesses = { threshold: 2 }): CheckOptions => ({
  logs: w.trusted(),
  witnesses: { keys: w.witnessKeys, threshold: witnesses.threshold },
  policy: { trustedIssuers: [b64u(w.issuer.publicKey)], minLogs: 2, now: w.clock.now(), online: 'off', ...o },
});

/** An agent listed in the first `n` logs, cosigned, and stapled. */
async function listed(w: World, n = 3) {
  const agent = makeAgent(w.issuer);
  for (const l of w.logs.slice(0, n)) expect((await register(l, agent)).ok).toBe(true);
  await w.round();
  const bundle = await stapleBundle(agent.sp, w.logs.map((l, i) => ({ id: l.id, client: w.clients[i]! })));
  return { agent, bundle };
}

describe('checkAgent: the good path', () => {
  it('trusts a stapled passport offline when 2 of 3 logs prove it with 2 witnesses each', async () => {
    const w = makeWorld();
    const { bundle } = await listed(w);
    const r = await checkAgent(bundle, opts(w));
    expect(r.decision).toBe('trusted');
    expect(r.logs.filter((l) => l.state === 'proved')).toHaveLength(3);
  });

  it('survives the header round trip', async () => {
    const w = makeWorld();
    const { bundle } = await listed(w);
    const r = await checkAgent(encodeBundle(bundle), opts(w));
    expect(r.decision).toBe('trusted');
  });

  it('trusts a hashed-mode entry without the log ever holding or serving the passport', async () => {
    const w = makeWorld(2);
    const agent = makeAgent(w.issuer);
    for (const l of w.logs) expect((await register(l, agent, 'hashed')).ok).toBe(true);
    await w.round();
    for (const l of w.logs) {
      const rows = await l.entries(0, 10);
      expect(rows[0]!.body).toBeUndefined();
      const wire = JSON.stringify(rows[0]!.entry);
      expect(wire).not.toContain(agent.sp.sub);
      expect(wire).not.toContain(agent.sp.iss);
      expect(wire).not.toContain('acme');
    }
    const bundle = await stapleBundle(agent.sp, w.logs.map((l, i) => ({ id: l.id, client: w.clients[i]! })));
    expect((await checkAgent(bundle, opts(w))).decision).toBe('trusted');
    expect((await checkAgent(bundle, opts(w, { modes: ['public'] }))).decision).toBe('untrusted');
  });
});

describe('checkAgent: quorum, witnesses, freshness', () => {
  it('is unknown when fewer than N independent logs prove the passport', async () => {
    const w = makeWorld();
    const { bundle } = await listed(w, 1);
    const r = await checkAgent(bundle, opts(w));
    expect(r.decision).toBe('unknown');
    expect(r.reasons[0]).toBe('quorum:1/2');
  });

  it('counts a log listed twice once', async () => {
    const w = makeWorld(2);
    const { bundle } = await listed(w, 1);
    const o = opts(w);
    o.logs = [...o.logs, o.logs[0]!];
    expect((await checkAgent(bundle, o)).decision).toBe('unknown');
  });

  it('is unknown when a witness quorum is short, and the stapled head alone cannot pass', async () => {
    const w = makeWorld();
    const agent = makeAgent(w.issuer);
    for (const l of w.logs) await register(l, agent);
    await w.round([0]); // one witness only
    const bundle = await stapleBundle(agent.sp, w.logs.map((l, i) => ({ id: l.id, client: w.clients[i]! })));
    const r = await checkAgent(bundle, opts(w));
    expect(r.decision).toBe('unknown');
    expect(r.logs.every((l) => l.state === 'witness_shortfall')).toBe(true);
  });

  it('does not count cosignatures from witnesses it does not trust', async () => {
    const w = makeWorld();
    const { bundle } = await listed(w);
    const stranger = generateKeyPair();
    const forged: StapledBundle = JSON.parse(JSON.stringify(bundle));
    for (const p of forged.proofs) p.sth.witnesses = [cosignTreeHead(p.sth, stranger.secretKey), cosignTreeHead(p.sth, stranger.secretKey)];
    expect((await checkAgent(forged, opts(w))).decision).toBe('unknown');
  });

  it('refuses a policy that demands no witnesses unless explicitly allowed', async () => {
    const w = makeWorld();
    const { bundle } = await listed(w);
    expect((await checkAgent(bundle, opts(w, {}, { threshold: 0 }))).decision).toBe('unknown');
    expect((await checkAgent(bundle, opts(w, { allowUnwitnessed: true }, { threshold: 0 }))).decision).toBe('trusted');
  });

  it('is unknown on a stale tree head (offline), and the head age is the bound on revocation lag', async () => {
    const w = makeWorld();
    const { bundle } = await listed(w);
    w.clock.advance(2 * HOUR);
    const r = await checkAgent(bundle, opts(w, { maxSthAgeMs: HOUR, now: w.clock.now() }));
    expect(r.decision).toBe('unknown');
    expect(r.logs.every((l) => l.state === 'stale')).toBe(true);
  });

  it('refuses a head dated in the future', async () => {
    const w = makeWorld();
    const { bundle } = await listed(w);
    const r = await checkAgent(bundle, opts(w, { now: T0 - 10 * HOUR }));
    expect(r.decision).not.toBe('trusted');
  });

  it('refuses an expired passport and an untrusted issuer', async () => {
    const w = makeWorld();
    const { bundle } = await listed(w);
    expect((await checkAgent(bundle, opts(w, { now: T0 + 2000 * HOUR, maxSthAgeMs: 5000 * HOUR }))).reasons[0]).toBe('passport:expired');
    expect((await checkAgent(bundle, opts(w, { trustedIssuers: [b64u(generateKeyPair().publicKey)] }))).reasons[0]).toBe('passport:unknown_issuer');
  });
});

describe('checkAgent: forged and malformed evidence', () => {
  it('rejects a forged inclusion proof', async () => {
    const w = makeWorld();
    for (const l of w.logs) await register(l, makeAgent(w.issuer)); // a tree with more than one leaf has a path to forge
    const { bundle } = await listed(w);
    const forged: StapledBundle = JSON.parse(JSON.stringify(bundle));
    const step = forged.proofs[0]!.proof.path[0]!;
    step.hash = step.hash.slice(0, -2) + (step.hash.endsWith('AA') ? 'BB' : 'AA');
    const r = await checkAgent(forged, opts(w));
    expect(r.decision).toBe('untrusted');
    expect(r.logs[0]!.state).toBe('invalid');
  });

  it('rejects an entry that belongs to a different passport, even with a valid proof', async () => {
    const w = makeWorld();
    const { bundle } = await listed(w);
    const other = (await listed(w)).bundle; // a second, genuinely listed agent
    const swapped: StapledBundle = { ...bundle, proofs: other.proofs };
    expect((await checkAgent(swapped, opts(w))).decision).toBe('untrusted');
  });

  it('rejects a head that is not signed by the pinned log key', async () => {
    const w = makeWorld();
    const { bundle } = await listed(w);
    const fake = new DirectoryLog({ id: 'log-0', secret: generateKeyPair().secretKey, now: w.clock.now, flood: false });
    const agent = makeAgent(w.issuer);
    await register(fake, agent);
    const evil = await stapleBundle(agent.sp, [{ id: 'log-0', client: memoryLogClient(fake) }]);
    const mixed: StapledBundle = { ...bundle, passport: agent.sp, proofs: evil.proofs };
    expect((await checkAgent(mixed, opts(w))).decision).toBe('untrusted');
  });

  it('rejects a proof copied from another log', async () => {
    const w = makeWorld();
    const { bundle } = await listed(w);
    const moved: StapledBundle = JSON.parse(JSON.stringify(bundle));
    moved.proofs[0]!.log = 'log-1';
    moved.proofs[1]!.log = 'log-0';
    expect((await checkAgent(moved, opts(w))).decision).toBe('untrusted');
  });

  it('never throws and never trusts on junk', async () => {
    const w = makeWorld();
    const junk: unknown[] = [null, undefined, 0, 'x', '', [], {}, { typ: 'atlas-pca/passport' }, { typ: 'atlas-pca/directory-bundle', ver: 1 }, { capabilities: { extensions: 5 } }, 'AAAA', 'a'.repeat(400_000)];
    for (const j of junk) expect((await checkAgent(j, opts(w))).decision).not.toBe('trusted');
  });

  it('refuses malformed bundles at the decoder', async () => {
    const w = makeWorld();
    const { bundle } = await listed(w);
    const good = encodeBundle(bundle);
    expect(() => decodeBundle(good + '=')).toThrow();
    expect(() => decodeBundle('')).toThrow();
    expect(() => decodeBundle('!!!!')).toThrow();
    expect(() => decodeBundle(b64u(new TextEncoder().encode('{"typ":"nope"}')))).toThrow();
    const many = { ...bundle, proofs: Array.from({ length: 40 }, () => bundle.proofs[0]!) };
    expect(() => decodeBundle(encodeBundle(many as StapledBundle))).toThrow();
    const lopsided: StapledBundle = JSON.parse(JSON.stringify(bundle));
    lopsided.proofs[0]!.proof.path = Array.from({ length: 200 }, () => ({ side: 'L' as const, hash: 'AAAA' }));
    expect((await checkAgent(lopsided, opts(w))).decision).toBe('untrusted');
    const wrongSize: StapledBundle = JSON.parse(JSON.stringify(bundle));
    wrongSize.proofs[0]!.proof.size += 1;
    expect((await checkAgent(wrongSize, opts(w))).decision).toBe('untrusted');
    const nullHead: StapledBundle = JSON.parse(JSON.stringify(bundle));
    (nullHead.proofs[0] as unknown as { sth: unknown }).sth = null;
    expect((await checkAgent(nullHead, opts(w))).decision).not.toBe('trusted');
  });
});

describe('revocation', () => {
  it('a revoked-but-stapled passport passes offline only until the head ages out, and is refused the moment a live log is asked', async () => {
    const w = makeWorld();
    const { agent, bundle } = await listed(w);
    for (const l of w.logs) {
      const r = await l.submit({ revocation: signRevocation(w.issuer.secretKey, agent.sp, { iat: w.clock.now(), reason: 'compromised' }) }, 'issuer');
      expect(r.ok).toBe(true);
    }
    await w.round();
    // offline: the stapled proof is genuine; only its age bounds the damage
    expect((await checkAgent(bundle, opts(w))).decision).toBe('trusted');
    w.clock.advance(30 * HOUR);
    expect((await checkAgent(bundle, opts(w, { now: w.clock.now() }))).decision).toBe('unknown');
    // online: any log that has seen the revocation is enough
    const r = await checkAgent(bundle, { ...opts(w, { online: 'prefer', now: w.clock.now() }), logs: w.trusted(true) });
    expect(r.decision).toBe('untrusted');
    expect(r.logs.some((l) => l.state === 'revoked')).toBe(true);
  });

  it('one honest log is enough to convict even if the others hide the revocation', async () => {
    const w = makeWorld();
    const { agent, bundle } = await listed(w);
    await w.logs[2]!.submit({ revocation: signRevocation(w.issuer.secretKey, agent.sp, { iat: w.clock.now() }) }, 'issuer');
    const r = await checkAgent(bundle, { ...opts(w, { online: 'prefer' }), logs: w.trusted(true) });
    expect(r.decision).toBe('untrusted');
  });

  it('the subject key can revoke itself; nobody else can', async () => {
    const w = makeWorld(1);
    const { agent } = await listed(w, 1);
    const log = w.logs[0]!;
    const stranger = generateKeyPair();
    expect(await log.submit({ revocation: signRevocation(stranger.secretKey, agent.sp, { iat: T0 }) }, 'x')).toMatchObject({ ok: false, reason: 'bad_revocation' });
    const forgedSigner = { ...signRevocation(stranger.secretKey, agent.sp, { iat: T0 }), signer: agent.sp.iss };
    expect(await log.submit({ revocation: forgedSigner }, 'x')).toMatchObject({ ok: false, reason: 'bad_revocation' });
    expect((await log.submit({ revocation: signRevocation(agent.kp.secretKey, agent.sp, { iat: T0 }) }, 'x')).ok).toBe(true);
    // listing a revoked passport again is refused
    expect(await register(log, agent)).toMatchObject({ ok: false, reason: 'revoked' });
  });

  it('a newer passport from the same issuer supersedes the old one', async () => {
    const w = makeWorld(2);
    const { agent, bundle } = await listed(w, 2);
    // same subject key, fresh passport
    const { issuePassport, signPassport } = await import('@atlasauth/pca/ext/attestation');
    const next = signPassport(issuePassport({ model_id: 'model-y', operator: 'acme', hardware_rooted: false, issued_at: T0 }), { issuerSecret: w.issuer.secretKey, subject: agent.sp.sub, exp: T0 + 24 * HOUR });
    const { signPop } = await import('./entry');
    for (const l of w.logs) expect((await l.submit({ passport: next, pop: signPop(agent.kp.secretKey, l.id, next) }, 'x')).ok).toBe(true);
    await w.round();
    const r = await checkAgent(bundle, { ...opts(w, { online: 'prefer' }), logs: w.trusted(true) });
    expect(r.decision).toBe('untrusted');
    expect(r.logs.some((l) => l.state === 'superseded')).toBe(true);
    expect((await checkAgent(bundle, { ...opts(w, { online: 'prefer', rejectSuperseded: false }), logs: w.trusted(true) })).decision).toBe('trusted');
  });
});

describe('split view, rollback, equivocation', () => {
  it('flags a log that serves a different tree of the same size than the one stapled', async () => {
    const w = makeWorld(2);
    const { bundle } = await listed(w, 2);
    // the same signing key, a different history of the same length
    const forkClients: LogClient[] = [];
    for (const [i, l] of w.logs.entries()) {
      const fork = new DirectoryLog({ id: l.id, secret: w.logs[i]!['o'].secret, now: w.clock.now, flood: false, witnessKeys: w.witnessKeys });
      await register(fork, makeAgent(w.issuer));
      forkClients.push(memoryLogClient(fork));
    }
    const o = opts(w, { online: 'prefer' });
    o.logs = w.logs.map((l, i) => ({ id: l.id, guardian: l.publicKey, client: forkClients[i]! }));
    const r = await checkAgent(bundle, o);
    expect(r.decision).toBe('untrusted');
    expect(r.logs.some((l) => l.state === 'equivocation')).toBe(true);
  });

  it('flags a log whose live head is behind the stapled one (rollback)', async () => {
    const w = makeWorld(2);
    const { bundle } = await listed(w, 2);
    const young = new DirectoryLog({ id: 'log-0', secret: w.logs[0]!['o'].secret, now: w.clock.now, flood: false });
    const o = opts(w, { online: 'prefer' });
    o.logs = [{ id: 'log-0', guardian: w.logs[0]!.publicKey, client: memoryLogClient(young) }, w.trusted()[1]!];
    const r = await checkAgent(bundle, o);
    expect(r.decision).toBe('untrusted');
    expect(r.logs[0]!.state).toBe('rollback');
  });

  it('flags a live head that does not extend the stapled head', async () => {
    const w = makeWorld(2);
    const { bundle } = await listed(w, 2);
    const other = new DirectoryLog({ id: 'log-0', secret: w.logs[0]!['o'].secret, now: w.clock.now, flood: false });
    for (let i = 0; i < 3; i++) await register(other, makeAgent(w.issuer));
    const o = opts(w, { online: 'prefer' });
    o.logs = [{ id: 'log-0', guardian: w.logs[0]!.publicKey, client: memoryLogClient(other) }, w.trusted()[1]!];
    const r = await checkAgent(bundle, o);
    expect(r.decision).toBe('untrusted');
    expect(r.logs[0]!.state).toBe('inconsistent');
  });

  it('online: require does not accept a log that cannot be reached', async () => {
    const w = makeWorld(2);
    const { bundle } = await listed(w, 2);
    const dead: LogClient = { ...w.clients[0]!, sth: async () => { throw new Error('down'); } };
    const o = opts(w, { online: 'require' });
    o.logs = [{ id: 'log-0', guardian: w.logs[0]!.publicKey, client: dead }, { id: 'log-1', guardian: w.logs[1]!.publicKey, client: w.clients[1]! }];
    const r = await checkAgent(bundle, o);
    expect(r.decision).toBe('unknown');
    expect(r.logs[0]!.state).toBe('unreachable');
  });
});

describe('witness', () => {
  async function fixture() {
    const w = makeWorld(1, 1);
    const log = w.logs[0]!;
    const wit = w.witnesses[0]!;
    return { w, log, wit };
  }

  it('cosigns growth with a consistency proof, refuses growth without one', async () => {
    const { w, log, wit } = await fixture();
    await register(log, makeAgent(w.issuer));
    const s1 = await log.sth();
    expect((await wit.cosign(s1)).ok).toBe(true);
    await register(log, makeAgent(w.issuer));
    await register(log, makeAgent(w.issuer));
    const s3 = await log.sth();
    expect(await wit.cosign(s3)).toMatchObject({ ok: false, reason: 'proof_required' });
    expect((await wit.cosign(s3, (await log.consistency(1, 3))!)).ok).toBe(true);
  });

  it('refuses a rollback, a forged head and an unknown log', async () => {
    const { w, log, wit } = await fixture();
    await register(log, makeAgent(w.issuer));
    const a = await log.sth();
    await register(log, makeAgent(w.issuer));
    const b = await log.sth();
    expect((await wit.cosign(b)).ok).toBe(true);
    expect(await wit.cosign(a)).toMatchObject({ ok: false, reason: 'rollback' });
    expect(await wit.cosign({ ...b, root: b.root.slice(0, -2) + 'AA' })).toMatchObject({ ok: false, reason: 'bad_head' });
    const stranger = new Witness(generateKeyPair().secretKey, [{ guardian: b64u(generateKeyPair().publicKey) }]);
    expect(await stranger.cosign(a)).toMatchObject({ ok: false, reason: 'unknown_log' });
  });

  it('refuses a consistency proof that does not connect the heads', async () => {
    const { w, log, wit } = await fixture();
    await register(log, makeAgent(w.issuer));
    expect((await wit.cosign(await log.sth())).ok).toBe(true);
    await register(log, makeAgent(w.issuer));
    await register(log, makeAgent(w.issuer));
    const s3 = await log.sth();
    const good = (await log.consistency(1, 3))!;
    expect(await wit.cosign(s3, { ...good, path: good.path.map((p) => p.slice(0, -2) + 'AA') })).toMatchObject({ ok: false, reason: 'bad_proof' });
    expect(await wit.cosign(s3, { ...good, oldSize: 2 })).toMatchObject({ ok: false, reason: 'proof_required' });
  });

  it('catches a log signing two roots of one size, and halts that log', async () => {
    const { w, log, wit } = await fixture();
    await register(log, makeAgent(w.issuer));
    const a = await log.sth();
    const fork = new DirectoryLog({ id: log.id, secret: log['o'].secret, now: w.clock.now, flood: false });
    await register(fork, makeAgent(w.issuer));
    const b = await fork.sth();
    expect((await wit.cosign(a)).ok).toBe(true);
    expect(await wit.cosign(b)).toMatchObject({ ok: false, reason: 'equivocation' });
    // even the honest head is now refused until an operator clears the halt
    await register(log, makeAgent(w.issuer));
    expect(await wit.cosign(await log.sth(), (await log.consistency(1, 2))!)).toMatchObject({ ok: false, reason: 'halted' });
  });

  it('survives a restart with its state (the log cannot roll it back)', async () => {
    const { w, log } = await fixture();
    const state = new MemoryWitnessState();
    const key = generateKeyPair();
    await register(log, makeAgent(w.issuer));
    const s1 = await log.sth();
    await register(log, makeAgent(w.issuer));
    const s2 = await log.sth();
    await new Witness(key.secretKey, [{ guardian: log.publicKey }], state).cosign(s2);
    const again = new Witness(key.secretKey, [{ guardian: log.publicKey }], state);
    expect(await again.cosign(s1)).toMatchObject({ ok: false, reason: 'rollback' });
  });

  it('the log only accepts cosignatures from configured witnesses, for heads it has, that verify', async () => {
    const { w, log } = await fixture();
    await register(log, makeAgent(w.issuer));
    const s = await log.sth();
    const stranger = generateKeyPair();
    expect(await log.addCosignature(s.size, s.root, cosignTreeHead(s, stranger.secretKey))).toBe(false);
    const key = generateKeyPair();
    const open = new DirectoryLog({ id: 'x', secret: generateKeyPair().secretKey, witnessKeys: [b64u(key.publicKey)], now: w.clock.now });
    await register(open, makeAgent(w.issuer));
    const h = await open.sth();
    expect(await open.addCosignature(h.size, h.root, cosignTreeHead(h, key.secretKey))).toBe(true);
    expect(await open.addCosignature(h.size, 'bogus', cosignTreeHead(h, key.secretKey))).toBe(false);
    expect(await open.addCosignature(h.size + 5, h.root, cosignTreeHead(h, key.secretKey))).toBe(false);
    const other = await (async () => { await register(open, makeAgent(w.issuer)); return open.sth(); })();
    expect(await open.addCosignature(h.size, h.root, cosignTreeHead(other, key.secretKey))).toBe(false); // bound to another head
  });
});

describe('log: who gets in, and how fast', () => {
  it('rate limits a flooding submitter and recovers after the window', async () => {
    const w = makeWorld(1, 1, { flood: { max: 3, windowMs: HOUR } });
    const log = w.logs[0]!;
    for (let i = 0; i < 3; i++) expect((await register(log, makeAgent(w.issuer), 'public', 'spammer')).ok).toBe(true);
    expect(await register(log, makeAgent(w.issuer), 'public', 'spammer')).toMatchObject({ ok: false, reason: 'rate_limited' });
    expect((await register(log, makeAgent(w.issuer), 'public', 'someone-else')).ok).toBe(true);
    expect((await log.head()).size).toBe(4);
    w.clock.advance(HOUR + 1);
    expect((await register(log, makeAgent(w.issuer, { now: w.clock.now() }), 'public', 'spammer')).ok).toBe(true);
  });

  it('counts invalid submissions against the flood limit too', async () => {
    const w = makeWorld(1, 1, { flood: { max: 2, windowMs: HOUR } });
    const log = w.logs[0]!;
    for (let i = 0; i < 2; i++) expect((await log.submit({} as never, 'x')).ok).toBe(false);
    expect(await log.submit({} as never, 'x')).toMatchObject({ reason: 'rate_limited' });
  });

  it('caps the entries one subject can hold and the log size', async () => {
    const w = makeWorld(1, 1, { maxEntriesPerSubject: 2, maxEntries: 3 });
    const log = w.logs[0]!;
    const a = makeAgent(w.issuer);
    const { issuePassport, signPassport } = await import('@atlasauth/pca/ext/attestation');
    const { signPop } = await import('./entry');
    const again = (m: string) => signPassport(issuePassport({ model_id: m, operator: 'acme', hardware_rooted: false, issued_at: T0 }), { issuerSecret: w.issuer.secretKey, subject: a.sp.sub, exp: T0 + HOUR });
    expect((await register(log, a)).ok).toBe(true);
    const p2 = again('m2');
    expect((await log.submit({ passport: p2, pop: signPop(a.kp.secretKey, log.id, p2) }, 'x')).ok).toBe(true);
    const p3 = again('m3');
    expect(await log.submit({ passport: p3, pop: signPop(a.kp.secretKey, log.id, p3) }, 'x')).toMatchObject({ reason: 'too_many_entries' });
    expect((await register(log, makeAgent(w.issuer))).ok).toBe(true);
    expect(await register(log, makeAgent(w.issuer))).toMatchObject({ reason: 'log_full' });
  });

  it('refuses listing a key you do not hold, an expired passport, another issuer, and hardware claims without a verifier', async () => {
    const w = makeWorld(1, 1, { issuers: [] });
    const log = w.logs[0]!;
    const a = makeAgent(w.issuer);
    expect(await register(log, a)).toMatchObject({ reason: 'issuer_not_allowed' });
    const open = new DirectoryLog({ id: 'open', secret: generateKeyPair().secretKey, now: w.clock.now, flood: false });
    const { signPop } = await import('./entry');
    expect(await open.submit({ passport: a.sp, pop: signPop(generateKeyPair().secretKey, 'open', a.sp) }, 'x')).toMatchObject({ reason: 'bad_pop' });
    expect(await open.submit({ passport: a.sp, pop: signPop(a.kp.secretKey, 'another-log', a.sp) }, 'x')).toMatchObject({ reason: 'bad_pop' });
    const old = makeAgent(w.issuer, { now: T0 - 48 * HOUR, exp: T0 - HOUR });
    expect(await register(open, old)).toMatchObject({ reason: 'passport_invalid' });
    const { issuePassport, signPassport } = await import('@atlasauth/pca/ext/attestation');
    const hw = signPassport(issuePassport({ model_id: 'm', operator: 'o', hardware_rooted: true, issued_at: T0 }), {
      issuerSecret: w.issuer.secretKey,
      subject: a.sp.sub,
      exp: T0 + HOUR,
      evidence: { document: { nonce: 'n' } as never },
    });
    expect(await open.submit({ passport: hw, pop: signPop(a.kp.secretKey, 'open', hw) }, 'x')).toMatchObject({ reason: 'passport_invalid' });
  });

  it('is idempotent and tamper-evident: a replayed submission adds nothing, and a modified passport is refused', async () => {
    const w = makeWorld(1, 1);
    const log = w.logs[0]!;
    const a = makeAgent(w.issuer);
    const first = await register(log, a);
    const second = await register(log, a);
    expect(first).toMatchObject({ ok: true, created: true });
    expect(second).toMatchObject({ ok: true, created: false, index: 0 });
    const tampered = { ...a.sp, passport: { ...a.sp.passport, operator: 'evil' } };
    expect((await log.submit({ passport: tampered as never, pop: 'x' }, 'x')).ok).toBe(false);
  });

  it('keeps the tree append-only under concurrent writers', async () => {
    const w = makeWorld(1, 1);
    const log = w.logs[0]!;
    const rs = await Promise.all(Array.from({ length: 12 }, () => register(log, makeAgent(w.issuer))));
    expect(rs.every((r) => r.ok)).toBe(true);
    expect(new Set(rs.map((r) => (r.ok ? r.index : -1))).size).toBe(12);
    const sth = await log.sth();
    const proof = (await log.consistency(5, 12))!;
    expect(proof).toBeTruthy();
    expect(sth.size).toBe(12);
  });
});

describe('monitor', () => {
  it('follows a log, verifies every entry, and reports watch hits', async () => {
    const w = makeWorld(1, 3);
    const log = w.logs[0]!;
    const m = new Monitor({ log: { id: log.id, guardian: log.publicKey }, client: w.clients[0]!, witnesses: { witnessKeys: w.witnessKeys, threshold: 2 }, watch: (e) => e.entry.mode === 'public' && e.entry.kind === 'register', now: w.clock.now });
    await register(log, makeAgent(w.issuer));
    await w.round();
    const r1 = await m.poll();
    expect(r1).toMatchObject({ ok: true, newEntries: 1 });
    expect(r1.alerts.map((a) => a.type)).toEqual(['watch_hit']);
    await register(log, makeAgent(w.issuer));
    await w.round();
    expect(await m.poll()).toMatchObject({ ok: true, newEntries: 1 });
    // state survives a restart
    const m2 = new Monitor({ log: { id: log.id, guardian: log.publicKey }, client: w.clients[0]!, witnesses: { witnessKeys: w.witnessKeys, threshold: 2 }, now: w.clock.now }, m.state());
    expect(await m2.poll()).toMatchObject({ ok: true, newEntries: 0 });
  });

  it('detects a rollback, a split view (via gossip) and an unwitnessed head', async () => {
    const w = makeWorld(1, 3);
    const log = w.logs[0]!;
    const base = { log: { id: log.id, guardian: log.publicKey }, witnesses: { witnessKeys: w.witnessKeys, threshold: 2 }, now: w.clock.now };
    await register(log, makeAgent(w.issuer));
    await register(log, makeAgent(w.issuer));
    await w.round();
    const m = new Monitor({ ...base, client: w.clients[0]! });
    expect((await m.poll()).ok).toBe(true);

    const fork = new DirectoryLog({ id: log.id, secret: log['o'].secret, now: w.clock.now, flood: false });
    await register(fork, makeAgent(w.issuer));
    await register(fork, makeAgent(w.issuer));
    const forkHead = await fork.sth();
    expect(m.gossip(forkHead)?.type).toBe('equivocation');
    expect(m.gossip(forkHead)?.evidence).toBeTruthy();

    const young = new DirectoryLog({ id: log.id, secret: log['o'].secret, now: w.clock.now, flood: false });
    await register(young, makeAgent(w.issuer));
    const mr = new Monitor({ ...base, client: memoryLogClient(young) }, m.state());
    expect((await mr.poll()).alerts[0]!.type).toBe('witness_shortfall'); // no witnesses on the young head
    const mr2 = new Monitor({ log: base.log, now: base.now, client: memoryLogClient(young) }, m.state());
    expect((await mr2.poll()).alerts[0]!.type).toBe('rollback');
  });

  it('detects a feed that lies about its entries', async () => {
    const w = makeWorld(1, 3);
    const log = w.logs[0]!;
    await register(log, makeAgent(w.issuer));
    await register(log, makeAgent(w.issuer));
    await w.round();
    const real = w.clients[0]!;
    const liar: LogClient = {
      ...real,
      entries: async (from, limit) => {
        const rows = await real.entries(from, limit);
        return rows.map((r) => (r.index === 1 ? { ...r, entry: { ...r.entry, iat: r.entry.iat + 1 } } : r));
      },
    };
    const m = new Monitor({ log: { id: log.id, guardian: log.publicKey }, client: liar, now: w.clock.now });
    expect((await m.poll()).alerts[0]!.type).toBe('feed_mismatch');
    const short: LogClient = { ...real, entries: async (from, limit) => (from >= 1 ? [] : await real.entries(from, limit)) };
    const m2 = new Monitor({ log: { id: log.id, guardian: log.publicKey }, client: short, now: w.clock.now, pageSize: 1 });
    expect((await m2.poll()).alerts[0]!.type).toBe('feed_mismatch');
  });
});

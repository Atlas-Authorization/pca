import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair } from '@atlasauth/pca';
import {
  DirectoryLog,
  Monitor,
  checkAgent,
  cosignTransition,
  memoryLogClient,
  resolveLogKey,
  retiredAtSize,
  signKeyTransition,
  stapleBundle,
  verifyKeyTransition,
  type CheckOptions,
  type SignedKeyTransition,
} from './index';
import { makeAgent, makeWorld, register, type World } from './test-util';

const WP = (w: World, threshold = 2) => ({ witnessKeys: w.witnessKeys, threshold });

/** Rotate log `i` of the world onto a new key with the witnesses the test names (by index). */
async function rotate(w: World, i: number, cosigners: number[] = [0, 1, 2], newSecret = generateKeyPair().secretKey) {
  const log = w.logs[i]!;
  const { transition, finalHead } = await log.proposeRotation(newSecret);
  for (const wi of cosigners) {
    // a witness cosigns the final head (it may already have) and then the transition
    const proof = undefined;
    await w.witnesses[wi]!.cosign(finalHead, proof);
    const r = await w.witnesses[wi]!.cosignTransition(transition);
    if (r.ok) await log.rotationCosign(r.cosignature);
  }
  return { transition: log.pendingTransition()!, newSecret };
}

const policy = (w: World, o: Partial<CheckOptions['policy']> = {}) => ({ trustedIssuers: [b64u(w.issuer.publicKey)], minLogs: 2, now: w.clock.now(), online: 'off' as const, ...o });
const opts = (w: World, logs = w.trusted(), p: Partial<CheckOptions['policy']> = {}): CheckOptions => ({ logs, witnesses: { keys: w.witnessKeys, threshold: 2 }, policy: policy(w, p) });

async function listedInAll(w: World) {
  const agent = makeAgent(w.issuer);
  for (const l of w.logs) await register(l, agent);
  await w.round();
  return agent;
}

describe('log key rotation', () => {
  it('a witnessed rotation switches the key; relying parties pinned to the old key follow the chain', async () => {
    const w = makeWorld(2, 3, { rotationThreshold: 2 });
    const agent = await listedInAll(w);
    const pin = w.trusted(); // what the relying party pinned: the keys before the rotation
    const oldKey = w.logs[0]!.publicKey;
    const before = await stapleBundle(agent.sp, w.logs.map((l, i) => ({ id: l.id, client: w.clients[i]! })));

    const { transition } = await rotate(w, 0);
    expect(transition.witnesses).toHaveLength(3);
    const done = await w.logs[0]!.completeRotation();
    expect(done.from).toBe(oldKey);
    expect(w.logs[0]!.publicKey).toBe(done.to);
    expect(await w.logs[0]!.transitions()).toHaveLength(1);

    // new entries, new head under the new key, witnessed by the same witnesses (they learned the new key from the transition)
    await register(w.logs[0]!, makeAgent(w.issuer));
    await w.round();
    const after = await stapleBundle(agent.sp, w.logs.map((l, i) => ({ id: l.id, client: w.clients[i]! })));
    expect(after.proofs[0]!.sth.guardian).toBe(done.to);
    expect(after.proofs[0]!.transitions).toHaveLength(1);

    // pinned to the OLD key: the chain is accepted
    expect((await checkAgent(after, opts(w, pin))).decision).toBe('trusted');
    // a bundle made before the rotation (head by the old key, up to the handover) still checks
    expect((await checkAgent(before, opts(w, pin))).decision).toBe('trusted');
    // without the transition the new key is a stranger
    const stripped = JSON.parse(JSON.stringify(after));
    for (const p of stripped.proofs) delete p.transitions;
    const r = await checkAgent(stripped, opts(w, pin));
    expect(r.decision).toBe('untrusted');
    expect(r.logs[0]!.state).toBe('invalid');
    // a relying party that already holds the transition does not need it in the bundle
    const held = pin.map((t, i) => (i === 0 ? { ...t, transitions: [done] } : t));
    expect((await checkAgent(stripped, opts(w, held))).decision).toBe('trusted');
  });

  it('online checks stay continuous across the rotation (consistency from an old-key head to a new-key head)', async () => {
    const w = makeWorld(2, 3, { rotationThreshold: 2 });
    const agent = await listedInAll(w);
    const bundle = await stapleBundle(agent.sp, w.logs.map((l, i) => ({ id: l.id, client: w.clients[i]! })));
    const pin = w.trusted(true);
    await rotate(w, 0);
    await w.logs[0]!.completeRotation();
    await register(w.logs[0]!, makeAgent(w.issuer));
    await w.round();
    const r = await checkAgent(bundle, opts(w, pin, { online: 'prefer' }));
    expect(r.decision).toBe('trusted');
  });

  it('a rotation that skips the witness quorum does not complete, and the old key stays', async () => {
    const w = makeWorld(1, 3, { rotationThreshold: 2 });
    await listedInAll(w);
    const log = w.logs[0]!;
    const oldKey = log.publicKey;
    await rotate(w, 0, [0]); // one cosignature of two
    await expect(log.completeRotation()).rejects.toThrow(/needs 2 witness/);
    expect(log.publicKey).toBe(oldKey);
    expect(await log.transitions()).toHaveLength(0);
    // an unknown witness does not help
    const stranger = generateKeyPair();
    expect(await log.rotationCosign(cosignTransition(log.pendingTransition()!, stranger.secretKey))).toBe(false);
    await expect(log.completeRotation()).rejects.toThrow();
    // and the log accepts nothing while it waits, then resumes when the rotation is abandoned
    expect(await register(log, makeAgent(w.issuer))).toMatchObject({ ok: false, reason: 'conflict' });
    log.abortRotation();
    expect((await register(log, makeAgent(w.issuer))).ok).toBe(true);
  });

  it('a transition with no witnesses is never valid, whatever the policy', async () => {
    const w = makeWorld(1, 3);
    const a = generateKeyPair();
    const b = generateKeyPair();
    const t = signKeyTransition({ log: 'l', instanceId: 'i', principal: 'p', seq: 1, oldSecret: a.secretKey, newSecret: b.secretKey, atSize: 1, atRoot: 'R', iat: 1 });
    expect(verifyKeyTransition(t, WP(w, 0))).toBe(false);
    expect(verifyKeyTransition(t, WP(w, 1))).toBe(false);
    const wit = { ...t, witnesses: [cosignTransition(t, w.witnessSecrets[0]!)] };
    expect(verifyKeyTransition(wit, WP(w, 1))).toBe(true);
    expect(verifyKeyTransition(wit, WP(w, 2))).toBe(false);
  });

  it('forged transitions are ignored: bad signatures, another log, a stranger as the old key, a replayed witness cosignature', async () => {
    const w = makeWorld(1, 3);
    const real = generateKeyPair();
    const attacker = generateKeyPair();
    const scope = { instanceId: 'i', principal: 'p' };
    const mk = (oldSecret: Uint8Array, newSecret: Uint8Array, o: Partial<SignedKeyTransition> = {}) => {
      const t = signKeyTransition({ log: 'l', instanceId: 'i', principal: 'p', seq: 1, oldSecret, newSecret, atSize: 2, atRoot: 'R', iat: 1 });
      const wt = { ...t, ...o };
      return { ...wt, witnesses: [0, 1].map((i) => cosignTransition(t, w.witnessSecrets[i]!)) } as SignedKeyTransition;
    };
    const pinned = b64u(real.publicKey);
    const toKey = (t: SignedKeyTransition) => t.to;

    // the attacker signs a handover FROM their own key: it does not start at the pinned key
    const fromAttacker = mk(attacker.secretKey, generateKeyPair().secretKey);
    expect(resolveLogKey(pinned, toKey(fromAttacker), [fromAttacker], WP(w), scope).ok).toBe(false);

    // the attacker claims to be the real key: the old-key signature does not verify
    const next = generateKeyPair();
    const forged = mk(attacker.secretKey, next.secretKey, { from: pinned });
    expect(verifyKeyTransition(forged, WP(w))).toBe(false);
    expect(resolveLogKey(pinned, b64u(next.publicKey), [forged], WP(w), scope).ok).toBe(false);

    // a genuine transition, tampered after witnessing (the cosignatures name the original statement)
    const good = mk(real.secretKey, next.secretKey);
    expect(resolveLogKey(pinned, b64u(next.publicKey), [good], WP(w), scope).ok).toBe(true);
    expect(verifyKeyTransition({ ...good, at_size: 99 }, WP(w))).toBe(false);
    expect(verifyKeyTransition({ ...good, to: b64u(attacker.publicKey) }, WP(w))).toBe(false);
    // witnesses of another statement replayed onto this one
    const other = mk(real.secretKey, generateKeyPair().secretKey);
    expect(verifyKeyTransition({ ...good, witnesses: other.witnesses }, WP(w))).toBe(false);
    // a different log's transition does not apply
    expect(resolveLogKey(pinned, b64u(next.publicKey), [good], WP(w), { instanceId: 'elsewhere' }).ok).toBe(false);
    // the retired key may not sign past its handover
    expect(retiredAtSize(pinned, [good], WP(w), scope)).toBe(2);
    expect(retiredAtSize(pinned, [forged], WP(w), scope)).toBeUndefined();
  });

  it('chains of rotations resolve in order, out-of-sequence and looping ones do not', async () => {
    const w = makeWorld(1, 3);
    const k = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
    const wit = (t: SignedKeyTransition): SignedKeyTransition => ({ ...t, witnesses: [0, 1].map((i) => cosignTransition(t, w.witnessSecrets[i]!)) });
    const t1 = wit(signKeyTransition({ log: 'l', instanceId: 'i', principal: 'p', seq: 1, oldSecret: k[0]!.secretKey, newSecret: k[1]!.secretKey, atSize: 1, atRoot: 'R1', iat: 1 }));
    const t2 = wit(signKeyTransition({ log: 'l', instanceId: 'i', principal: 'p', seq: 2, oldSecret: k[1]!.secretKey, newSecret: k[2]!.secretKey, atSize: 2, atRoot: 'R2', iat: 2 }));
    const t2bad = wit(signKeyTransition({ log: 'l', instanceId: 'i', principal: 'p', seq: 5, oldSecret: k[1]!.secretKey, newSecret: k[2]!.secretKey, atSize: 2, atRoot: 'R2', iat: 2 }));
    const loop = wit(signKeyTransition({ log: 'l', instanceId: 'i', principal: 'p', seq: 3, oldSecret: k[2]!.secretKey, newSecret: k[0]!.secretKey, atSize: 3, atRoot: 'R3', iat: 3 }));
    const [a, , c] = k.map((x) => b64u(x.publicKey)) as [string, string, string];
    const r = resolveLogKey(a, c, [t2, t1], WP(w), {});
    expect(r.ok && r.chain.map((t) => t.seq)).toEqual([1, 2]);
    expect(resolveLogKey(a, c, [t1, t2bad], WP(w), {}).ok).toBe(false);
    expect(resolveLogKey(a, 'nobody', [t1, t2, loop], WP(w), {}).ok).toBe(false);
  });

  it('refuses a head signed by the retired key beyond the handover (a stolen old key)', async () => {
    const w = makeWorld(2, 3, { rotationThreshold: 2 });
    const agent = await listedInAll(w);
    const oldSecret = (w.logs[0] as unknown as { secret: Uint8Array }).secret;
    const pin = w.trusted();
    await rotate(w, 0);
    const done = await w.logs[0]!.completeRotation();
    // someone holding the OLD key runs a log that has grown past the handover
    const rogue = new DirectoryLog({ id: w.logs[0]!.id, secret: oldSecret, now: w.clock.now, flood: false });
    await register(rogue, agent);
    for (let i = 0; i < 4; i++) await register(rogue, makeAgent(w.issuer));
    const sth = await rogue.sth();
    expect(sth.size).toBeGreaterThan(done.at_size);
    const p = (await memoryLogClient(rogue).inclusion((await import('./entry')).passportDigest(agent.sp)))!;
    const bundle = await stapleBundle(agent.sp, [{ id: w.logs[1]!.id, client: w.clients[1]! }]);
    bundle.proofs.push({ log: w.logs[0]!.id, index: p.entry.index, entry: p.entry.entry, proof: p.proof, sth: p.sth, transitions: [done] });
    const r = await checkAgent(bundle, opts(w, pin));
    expect(r.decision).toBe('untrusted');
    expect(r.logs.find((l) => l.log === w.logs[0]!.id)!.state).toBe('invalid');
  });
});

describe('witnesses and rotation', () => {
  it('a witness cosigns a transition only for the exact head it last cosigned, and then retires the old key', async () => {
    const w = makeWorld(1, 3, { rotationThreshold: 1 });
    const log = w.logs[0]!;
    await register(log, makeAgent(w.issuer));
    const { transition, finalHead } = await log.proposeRotation(generateKeyPair().secretKey);
    // witness 0 never cosigned the final head: it refuses
    expect(await w.witnesses[0]!.cosignTransition(transition)).toMatchObject({ ok: false, reason: 'stale_state' });
    expect((await w.witnesses[0]!.cosign(finalHead)).ok).toBe(true);
    expect((await w.witnesses[0]!.cosignTransition(transition)).ok).toBe(true);
    // the old key may not sign anything larger any more (the witness, not just the relying party, enforces it)
    const rogue = new DirectoryLog({ id: log.id, secret: (log as unknown as { secret: Uint8Array }).secret, now: w.clock.now, flood: false });
    await register(rogue, makeAgent(w.issuer));
    await register(rogue, makeAgent(w.issuer));
    expect(await w.witnesses[0]!.cosign(await rogue.sth(), (await rogue.consistency(1, 2)) ?? undefined)).toMatchObject({ ok: false, reason: 'retired' });
  });

  it('a witness refuses a transition that is badly signed or names a different head', async () => {
    const w = makeWorld(1, 3);
    const log = w.logs[0]!;
    await register(log, makeAgent(w.issuer));
    const { transition, finalHead } = await log.proposeRotation(generateKeyPair().secretKey);
    await w.witnesses[1]!.cosign(finalHead);
    expect(await w.witnesses[1]!.cosignTransition({ ...transition, sig_old: transition.sig_new })).toMatchObject({ ok: false, reason: 'bad_transition' });
    expect(await w.witnesses[1]!.cosignTransition({ ...transition, at_root: 'other' })).toMatchObject({ ok: false });
    expect((await w.witnesses[1]!.cosignTransition({ ...transition, from: b64u(generateKeyPair().publicKey) })).ok).toBe(false);
  });

  it('a log may not take a principal that could be mistaken for a transition', () => {
    expect(() => new DirectoryLog({ id: 'x', secret: generateKeyPair().secretKey, principal: 'directory-key-transition:evil' })).toThrow();
  });
});

describe('the monitor across a rotation', () => {
  it('follows the log through the rotation and keeps verifying the whole history', async () => {
    const w = makeWorld(1, 3, { rotationThreshold: 2 });
    const log = w.logs[0]!;
    const m = new Monitor({ log: { id: log.id, guardian: log.publicKey }, client: w.clients[0]!, witnesses: WP(w), now: w.clock.now });
    await register(log, makeAgent(w.issuer));
    await w.round();
    expect((await m.poll()).ok).toBe(true);
    await rotate(w, 0);
    await log.completeRotation();
    await register(log, makeAgent(w.issuer));
    await w.round();
    const r = await m.poll();
    expect(r).toMatchObject({ ok: true, newEntries: 1 });
    expect(r.head!.guardian).toBe(log.publicKey);
    // a monitor restarted from saved state keeps going
    const m2 = new Monitor({ log: { id: log.id, guardian: (await log.transitions())[0]!.from }, client: w.clients[0]!, witnesses: WP(w), now: w.clock.now }, m.state());
    expect((await m2.poll()).ok).toBe(true);
  });

  it('rejects a head from a rotated key when no witnessed transition leads to it', async () => {
    const w = makeWorld(1, 3);
    const log = w.logs[0]!;
    await register(log, makeAgent(w.issuer));
    await w.round();
    const impostor = new DirectoryLog({ id: log.id, secret: generateKeyPair().secretKey, now: w.clock.now, flood: false });
    await register(impostor, makeAgent(w.issuer));
    const m = new Monitor({ log: { id: log.id, guardian: log.publicKey }, client: memoryLogClient(impostor), witnesses: WP(w), now: w.clock.now });
    expect((await m.poll()).alerts[0]!.type).toBe('bad_head');
  });

  it("catches a witnessed transition that hands over a history that is not the log's", async () => {
    const w = makeWorld(1, 3);
    const log = w.logs[0]!;
    const oldSecret = (log as unknown as { secret: Uint8Array }).secret;
    const oldKey = log.publicKey;
    await register(log, makeAgent(w.issuer));
    await register(log, makeAgent(w.issuer));
    await w.round();
    // a handover at the wrong root, validly signed by both keys and cosigned by (colluding) witnesses
    const next = generateKeyPair();
    const t = signKeyTransition({ log: log.id, instanceId: log.id, principal: log.id, seq: 1, oldSecret, newSecret: next.secretKey, atSize: 2, atRoot: 'not-the-root', iat: 1 });
    const witnessed: SignedKeyTransition = { ...t, witnesses: [0, 1].map((i) => cosignTransition(t, w.witnessSecrets[i]!)) };
    // the real history, signed by the new key (same rows, same stored cosignatures)
    const successor = new DirectoryLog({ id: log.id, secret: next.secretKey, now: w.clock.now, flood: false, store: log.store });
    const client = { ...memoryLogClient(successor, { minCosigs: 1 }), transitions: async () => [witnessed] };
    const m = new Monitor({ log: { id: log.id, guardian: oldKey }, client, witnesses: WP(w), now: w.clock.now });
    const r = await m.poll();
    expect(r.ok).toBe(false);
    expect(r.alerts[0]!.type).toBe('inconsistent');
  });
});

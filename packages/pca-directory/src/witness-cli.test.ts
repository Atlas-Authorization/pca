import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair } from '@atlasauth/pca';
import { DirectoryLog, MemoryWitnessState, cosignTransition, type SignedKeyTransition } from './index';
import { cancelRetirementCommand, followCommand, readTransitions } from './witness-cli';
import { makeAgent, makeWorld, register, type World } from './test-util';

const dir = mkdtempSync(join(tmpdir(), 'witness-cli-'));
const file = (name: string, body: unknown) => {
  const p = join(dir, name);
  writeFileSync(p, typeof body === 'string' ? body : JSON.stringify(body));
  return p;
};
/** A fetch over an in-process log's routes: just consistency, which is all `follow` asks the log for. */
const fetchFor = (log: DirectoryLog) => async (url: string) => {
  const u = new URL(url);
  if (u.pathname.endsWith('/consistency')) {
    const proof = await log.consistency(Number(u.searchParams.get('from')), Number(u.searchParams.get('to')));
    return { ok: !!proof, status: proof ? 200 : 400, json: async () => ({ consistency_proof: proof }) };
  }
  return { ok: false, status: 404, json: async () => ({}) };
};

/** A world where log 0 has rotated while witness 2 was down (it never saw the head, nor the transition). */
async function rotatedWhileDown() {
  const w: World = makeWorld(1, 3, { rotationThreshold: 2 });
  const log = w.logs[0]!;
  await register(log, makeAgent(w.issuer));
  await w.round([0, 1, 2]); // everyone has seen size 1
  const oldKey = log.publicKey;
  await register(log, makeAgent(w.issuer));
  await w.round([0, 1]); // witness 2 is down from here on
  const { transition, finalHead } = await log.proposeRotation(generateKeyPair().secretKey);
  for (const i of [0, 1]) {
    await w.witnesses[i]!.cosign(finalHead);
    const r = await w.witnesses[i]!.cosignTransition(transition);
    if (r.ok) await log.rotationCosign(r.cosignature);
  }
  const done = await log.completeRotation();
  return { w, log, oldKey, done };
}

describe('pca-directory-witness follow', () => {
  it('lets a witness that was down adopt the witnessed chain, after checking its own history is part of it', async () => {
    const { w, log, oldKey, done } = await rotatedWhileDown();
    const state = w.witnessStates[2]!; // it last cosigned size 1
    expect((await state.get(oldKey))!.size).toBe(1);
    const lines = await followCommand({
      key: file('w2.key', b64u(w.witnessSecrets[2]!)),
      state: 'unused',
      stateImpl: state,
      from: oldKey,
      log: { url: 'https://log.example/v1/pca/directory', guardian: done.to },
      transition: file('t.json', { object: 'list', data: [done] }),
      witnesses: w.witnessKeys,
      threshold: 2,
      fetch: fetchFor(log),
    });
    expect(lines[0]).toContain(done.to);
    // it now follows the new key from the handover, and the old key is retired
    expect(await state.get(done.to)).toMatchObject({ size: done.at_size, root: done.at_root });
    expect((await state.get(oldKey))!.retiredTo).toBe(done.to);
    await register(log, makeAgent(w.issuer));
    const head = await log.sth();
    const proof = (await log.consistency(done.at_size, head.size))!;
    expect((await w.witnesses[2]!.cosign(head, proof)).ok).toBe(true);
  });

  it('refuses without a witness quorum, with a forged transition, or for a different quorum than it trusts', async () => {
    const { w, log, oldKey, done } = await rotatedWhileDown();
    const base = {
      key: file('w2b.key', b64u(w.witnessSecrets[2]!)),
      state: 'unused',
      from: oldKey,
      log: { url: 'https://log.example/v1/pca/directory', guardian: done.to },
      witnesses: w.witnessKeys,
      threshold: 2,
      fetch: fetchFor(log),
    };
    const fresh = () => new MemoryWitnessState();
    const seeded = async () => {
      const s = new MemoryWitnessState();
      const prev = (await w.witnessStates[2]!.get(oldKey))!;
      await s.set(oldKey, { size: prev.size, root: prev.root });
      return s;
    };
    const one: SignedKeyTransition = { ...done, witnesses: done.witnesses!.slice(0, 1) };
    await expect(followCommand({ ...base, stateImpl: await seeded(), transition: file('one.json', [one]) })).rejects.toThrow(/no_chain/);
    const forged = { ...done, sig_old: done.sig_new };
    await expect(followCommand({ ...base, stateImpl: await seeded(), transition: file('forged.json', [forged]) })).rejects.toThrow(/no_chain/);
    const stranger = generateKeyPair();
    const strangers = { ...done, witnesses: [cosignTransition(done, stranger.secretKey), cosignTransition(done, generateKeyPair().secretKey)] };
    await expect(followCommand({ ...base, stateImpl: await seeded(), transition: file('strangers.json', [strangers]) })).rejects.toThrow(/no_chain/);
    await expect(followCommand({ ...base, stateImpl: await seeded(), transition: file('ok.json', [done]), witnesses: [], threshold: 0 })).rejects.toThrow(/witness quorum/);
    // a witness that has never heard of the old key does not adopt anything
    await expect(followCommand({ ...base, stateImpl: fresh(), from: b64u(generateKeyPair().publicKey), transition: file('ok2.json', [done]) })).rejects.toThrow(/no_chain/);
  });

  it('refuses a witness that cosigned past the handover, one whose history does not match, and one that cannot get a proof', async () => {
    const { w, log, oldKey, done } = await rotatedWhileDown();
    const cfg = { key: file('w2c.key', b64u(w.witnessSecrets[2]!)), state: 'unused', from: oldKey, log: { url: 'https://log.example/v1/pca/directory', guardian: done.to }, transition: file('t2.json', [done]), witnesses: w.witnessKeys, threshold: 2, fetch: fetchFor(log) };
    const ahead = new MemoryWitnessState();
    await ahead.set(oldKey, { size: done.at_size + 3, root: 'whatever' });
    await expect(followCommand({ ...cfg, stateImpl: ahead })).rejects.toThrow(/ahead/);
    const sameSizeOtherRoot = new MemoryWitnessState();
    await sameSizeOtherRoot.set(oldKey, { size: done.at_size, root: 'a-different-root' });
    await expect(followCommand({ ...cfg, stateImpl: sameSizeOtherRoot })).rejects.toThrow(/root_mismatch/);
    const behindWrongRoot = new MemoryWitnessState();
    await behindWrongRoot.set(oldKey, { size: 1, root: 'not-the-root-of-size-1' });
    await expect(followCommand({ ...cfg, stateImpl: behindWrongRoot })).rejects.toThrow(/bad_proof/);
    const behind = new MemoryWitnessState();
    const prev = (await w.witnessStates[2]!.get(oldKey))!;
    await behind.set(oldKey, { size: prev.size, root: prev.root });
    await expect(followCommand({ ...cfg, stateImpl: behind, fetch: async () => ({ ok: false, status: 503, json: async () => ({}) }) })).rejects.toThrow(/proof_required/);
  });

  it('reads transitions from a file in any of the published shapes, or from a URL', async () => {
    const { done } = await rotatedWhileDown();
    expect(await readTransitions(file('a.json', [done]))).toHaveLength(1);
    expect(await readTransitions(file('b.json', { data: [done] }))).toHaveLength(1);
    expect(await readTransitions(file('c.json', { transition: done }))).toHaveLength(1);
    expect(await readTransitions(file('d.json', done))).toHaveLength(1);
    expect(await readTransitions('https://log.example/key-transitions', async () => ({ ok: true, status: 200, json: async () => ({ data: [done] }) }))).toHaveLength(1);
    await expect(readTransitions('https://log.example/key-transitions', async () => ({ ok: false, status: 500, json: async () => ({}) }))).rejects.toThrow(/500/);
    await expect(readTransitions(file('bad.json', 'not json'))).rejects.toThrow();
  });
});

describe('pca-directory-witness cancel-retirement', () => {
  it('lets the old key sign again after the log abandoned its rotation', async () => {
    const w = makeWorld(1, 3, { rotationThreshold: 2 });
    const log = w.logs[0]!;
    await register(log, makeAgent(w.issuer));
    await w.round([0, 1, 2]);
    const oldKey = log.publicKey;
    const { transition, finalHead } = await log.proposeRotation(generateKeyPair().secretKey);
    await w.witnesses[0]!.cosign(finalHead);
    expect((await w.witnesses[0]!.cosignTransition(transition)).ok).toBe(true);
    log.abortRotation(); // the log gave up; witness 0 has retired its key anyway
    await register(log, makeAgent(w.issuer));
    const head = await log.sth();
    const proof = (await log.consistency(1, 2))!;
    expect(await w.witnesses[0]!.cosign(head, proof)).toMatchObject({ ok: false, reason: 'retired' });
    const state = w.witnessStates[0]!;
    const lines = await cancelRetirementCommand({ key: file('w0.key', b64u(w.witnessSecrets[0]!)), state: 'unused', guardian: oldKey, stateImpl: state });
    expect(lines[0]).toContain('may sign again');
    expect((await w.witnesses[0]!.cosign(head, proof)).ok).toBe(true);
    // a second run, a key that is not retired and an unknown key are all reported plainly
    expect((await cancelRetirementCommand({ key: file('w0.key', b64u(w.witnessSecrets[0]!)), state: 'unused', guardian: oldKey, stateImpl: state }))[0]).toContain('not retired');
    await expect(cancelRetirementCommand({ key: file('w0.key', b64u(w.witnessSecrets[0]!)), state: 'unused', guardian: 'nobody', stateImpl: state })).rejects.toThrow(/no state/);
  });
});


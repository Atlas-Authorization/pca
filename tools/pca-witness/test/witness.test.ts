import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { b64u, encodeKey, generateKeyPair } from '@atlasauth/pca';
import { createMemoryDurableKv, openDurableState, type DurableKv } from '@atlasauth/pca/durable-state';
import { type SignedTreeHead, TransparencyLedger, signTreeHead, verifyCheckpointChain, verifyHeadConsistency, verifyTreeHead, detectTreeHeadEquivocation } from '@atlasauth/pca/ext/ledger';
import { Witness } from '../src/witness';
import { createWitnessServer, MAX_BODY_BYTES } from '../src/server';

const G = generateKeyPair();
const OTHER = generateKeyPair();
const W = generateKeyPair();
const W2 = generateKeyPair();
const gpk = encodeKey(G.publicKey);
const wpk = encodeKey(W.publicKey);
const LOG = { instance_id: 'inst-1', principal: 'grant-1', guardian_public: gpk };
const leaf = (i: number) => b64u(new TextEncoder().encode(`leaf-${i}-padding-padding-padding`)).slice(0, 43);
const chain = new TransparencyLedger('grant-1');
for (let i = 0; i < 40; i++) chain.appendCommitment(leaf(i));
const sth = (size: number, prevSize?: number, o: { root?: string; secret?: Uint8Array; principal?: string } = {}): SignedTreeHead =>
  signTreeHead(o.secret ?? G.secretKey, { instance_id: 'inst-1', principal: o.principal ?? 'grant-1', size, root: o.root ?? chain.rootAt(size), prev_root: prevSize === undefined ? '' : chain.rootAt(prevSize), timestamp: 1_800_000_000_000 + size });
const proof = (m: number, n: number) => chain.consistencyProof(m, n);
const witness = (kv: DurableKv = createMemoryDurableKv(), secret = W.secretKey) => new Witness({ kv, witnessSecret: secret, logs: [LOG] });

describe('Witness.cosign', () => {
  it('first sight: cosigns a genuine head (trust on first use) and the cosignature satisfies a 1-of-1 witness policy', async () => {
    const w = witness();
    const h = sth(8, 7);
    const r = await w.cosign({ sth: h });
    expect(r.status).toBe(200);
    if (r.status !== 200) return;
    expect(r.body).toMatchObject({ witness: wpk, head: { size: 8, root: chain.rootAt(8) }, first_sight: true });
    expect(verifyTreeHead({ ...h, witnesses: [r.body.cosignature] }, gpk, { witnessKeys: [wpk], threshold: 1 })).toBe(true);
    expect(verifyTreeHead({ ...h, witnesses: [r.body.cosignature] }, gpk, { witnessKeys: [encodeKey(W2.publicKey)], threshold: 1 })).toBe(false);
  });

  it('cosigns an extension only with a proof that connects it to the last cosigned head', async () => {
    const w = witness();
    await w.cosign({ sth: sth(8, 7) });
    expect(await w.cosign({ sth: sth(12, 11) })).toEqual({ status: 409, body: { error: 'proof_required', detail: 'a consistency proof from size 8 is required' } });
    const bad = { ...proof(8, 12), path: proof(8, 12).path.map((h, i) => (i === 0 ? h.replace(/^./, (x) => (x === 'A' ? 'B' : 'A')) : h)) };
    expect(await w.cosign({ sth: sth(12, 11), proof: bad })).toEqual({ status: 409, body: { error: 'inconsistent', detail: 'the head is not an extension of the last cosigned head (size 8)' } });
    expect(await w.cosign({ sth: sth(12, 11), proof: proof(7, 12) })).toMatchObject({ status: 409, body: { error: 'inconsistent' } });
    const ok = await w.cosign({ sth: sth(12, 11), proof: proof(8, 12) });
    expect(ok).toMatchObject({ status: 200, body: { head: { size: 12 }, first_sight: false } });
    expect((await w.state('inst-1', 'grant-1'))!.latest.size).toBe(12);
  });

  it('refuses a rollback and a split view; the equivocating pair is stored as evidence anyone can verify', async () => {
    const w = witness();
    await w.cosign({ sth: sth(8, 7) });
    expect(await w.cosign({ sth: sth(5, 4) })).toEqual({ status: 409, body: { error: 'rollback', detail: 'the last cosigned head has size 8' } });
    const forked = new TransparencyLedger('grant-1');
    for (let i = 0; i < 7; i++) forked.appendCommitment(leaf(i));
    forked.appendCommitment(leaf(999));
    const rival = sth(8, 7, { root: forked.head().root });
    const r = await w.cosign({ sth: rival });
    expect(r.status).toBe(409);
    expect(r.body).toMatchObject({ error: 'equivocation' });
    const ev = (r.body as { evidence: { a: SignedTreeHead; b: SignedTreeHead } }).evidence;
    expect(detectTreeHeadEquivocation(ev.a, ev.b, gpk)).toBe(true);
    const st = await w.state('inst-1', 'grant-1');
    expect(st!.latest.root).toBe(chain.rootAt(8)); // the first head still stands
    expect(st!.evidence).toHaveLength(1);
    expect(detectTreeHeadEquivocation(st!.evidence[0]!.a, st!.evidence[0]!.b, gpk)).toBe(true);
    await w.cosign({ sth: rival }); // the same rival again does not pile up evidence
    expect((await w.state('inst-1', 'grant-1'))!.evidence).toHaveLength(1);
  });

  it('the same head again is cosigned again and nothing changes (retry safe)', async () => {
    const w = witness();
    const h = sth(8, 7);
    const a = await w.cosign({ sth: h });
    const b = await w.cosign({ sth: h });
    expect(b).toMatchObject({ status: 200, body: { first_sight: false } });
    expect((a as { body: { cosignature: unknown } }).body.cosignature).toEqual((b as { body: { cosignature: unknown } }).body.cosignature); // ed25519 is deterministic
    expect((await w.state('inst-1', 'grant-1'))!.latest).toEqual(h);
  });

  it('every refusal is exact and writes nothing', async () => {
    const kv = createMemoryDurableKv();
    const w = witness(kv);
    const h = sth(8, 7);
    expect(await w.cosign(null)).toEqual({ status: 400, body: { error: 'malformed_request', detail: 'expected { sth, proof? }' } });
    expect(await w.cosign({})).toEqual({ status: 400, body: { error: 'malformed_request', detail: 'expected { sth, proof? }' } });
    expect(await w.cosign({ sth: [] })).toMatchObject({ status: 400 });
    expect(await w.cosign({ sth: { size: 1 } })).toEqual({ status: 400, body: { error: 'malformed_request', detail: 'sth lacks instance_id / principal' } });
    expect(await w.cosign({ sth: sth(8, 7, { principal: 'grant-2' }) })).toEqual({ status: 404, body: { error: 'unknown_log' } });
    expect(await w.cosign({ sth: sth(8, 7, { secret: OTHER.secretKey }) })).toEqual({ status: 403, body: { error: 'bad_signature' } });
    expect(await w.cosign({ sth: { ...h, size: 9 } })).toEqual({ status: 403, body: { error: 'bad_signature' } });
    expect(await w.cosign({ sth: { ...h, sig: h.sig.replace(/^./, (x) => (x === 'A' ? 'B' : 'A')) } })).toEqual({ status: 403, body: { error: 'bad_signature' } });
    expect(await kv.keys()).toEqual([]);
  });

  it('cosigns only the head: cosignatures other witnesses attached are stripped before storing', async () => {
    const w = witness();
    const h = sth(8, 7);
    await w.cosign({ sth: { ...h, witnesses: [{ key: 'x', sig: 'y' }] } });
    expect((await w.state('inst-1', 'grant-1'))!.latest).toEqual(h);
  });

  it('survives a restart: the head on disk is the head it checks the next one against', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pca-witness-'));
    try {
      await witness(await openDurableState({ dir })).cosign({ sth: sth(8, 7) });
      const back = witness(await openDurableState({ dir }));
      expect(await back.cosign({ sth: sth(5, 4) })).toMatchObject({ status: 409, body: { error: 'rollback' } });
      expect(await back.cosign({ sth: sth(12, 11), proof: proof(8, 12) })).toMatchObject({ status: 200 });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('racing requests cannot both advance from one state', async () => {
    const kv = createMemoryDurableKv();
    const a = witness(kv);
    const b = witness(kv);
    await a.cosign({ sth: sth(8, 7) });
    const forked = new TransparencyLedger('grant-1');
    for (let i = 0; i < 8; i++) forked.appendCommitment(leaf(i));
    for (let i = 8; i < 12; i++) forked.appendCommitment(leaf(500 + i));
    const rivalHead = signTreeHead(G.secretKey, { instance_id: 'inst-1', principal: 'grant-1', size: 12, root: forked.head().root, prev_root: chain.rootAt(11), timestamp: 5 });
    const r = await Promise.all([a.cosign({ sth: sth(12, 11), proof: proof(8, 12) }), b.cosign({ sth: rivalHead, proof: forked.consistencyProof(8, 12) }), a.cosign({ sth: sth(12, 11), proof: proof(8, 12) }), b.cosign({ sth: rivalHead, proof: forked.consistencyProof(8, 12) })]);
    const root = (await a.state('inst-1', 'grant-1'))!.latest.root;
    // whichever head won, the other fork is refused: never two cosigned roots at size 12
    for (const [i, x] of r.entries()) {
      const mine = i % 2 === 0 ? chain.rootAt(12) : forked.head().root;
      expect(x.status === 200, `request ${i}`).toBe(mine === root);
    }
  });

  it('a log of heads cosigned in sequence forms a chain a client verifies end to end, with the witness threshold', async () => {
    const w = witness();
    const cps = [];
    let prev: number | undefined;
    for (const size of [1, 4, 9, 20, 40]) {
      const h = sth(size, size - 1);
      const r = await w.cosign({ sth: h, ...(prev === undefined ? {} : { proof: proof(prev, size) }) });
      if (r.status !== 200) throw new Error(`size ${size}: ${JSON.stringify(r.body)}`);
      cps.push({ sth: { ...h, witnesses: [r.body.cosignature] }, ...(prev === undefined ? {} : { proof: proof(prev, size) }) });
      prev = size;
    }
    expect(verifyCheckpointChain(cps, gpk, { witnessKeys: [wpk], threshold: 1 })).toMatchObject({ ok: true });
    expect(verifyHeadConsistency(cps[3]!.sth, cps[4]!.sth, cps[4]!.proof!, gpk, { witnessKeys: [wpk], threshold: 1 })).toBe(true);
  });

  it('refuses to be built wrongly', () => {
    const base = { kv: createMemoryDurableKv(), witnessSecret: W.secretKey, logs: [LOG] };
    expect(() => new Witness({ ...base, kv: undefined as never })).toThrow(TypeError);
    expect(() => new Witness({ ...base, witnessSecret: new Uint8Array(31) })).toThrow(TypeError);
    expect(() => new Witness({ ...base, witnessSecret: 'k' as never })).toThrow(TypeError);
    expect(() => new Witness({ ...base, logs: [] })).toThrow(TypeError);
    expect(() => new Witness({ ...base, logs: [{ ...LOG, guardian_public: '' }] })).toThrow(TypeError);
    expect(() => new Witness({ ...base, logs: [{ instance_id: 1 } as never] })).toThrow(TypeError);
  });

  it('a store that fails or holds junk is a 500, never a cosignature', async () => {
    const kv = createMemoryDurableKv();
    const down: DurableKv = { get: kv.get, set: kv.set, keys: kv.keys, update: () => Promise.reject(new Error('down')) };
    expect(await witness(down).cosign({ sth: sth(8, 7) })).toEqual({ status: 500, body: { error: 'state_unavailable' } });
    await kv.set(`witness/v1/${JSON.stringify(['inst-1', 'grant-1'])}`, { v: 1, latest: 'x' });
    expect(await witness(kv).cosign({ sth: sth(8, 7) })).toEqual({ status: 500, body: { error: 'state_unavailable' } });
  });
});

describe('the HTTP server', () => {
  const servers: Array<{ close(): void }> = [];
  afterEach(() => {
    while (servers.length) servers.pop()!.close();
  });
  const start = async (w = witness()) => {
    const lines: string[] = [];
    const srv = createWitnessServer(w, (l) => lines.push(l));
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    servers.push(srv);
    return { base: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, lines };
  };
  const post = (base: string, body: string, headers: Record<string, string> = { 'content-type': 'application/json' }) => fetch(`${base}/v1/cosign`, { method: 'POST', headers, body });

  it('serves health, the key and the configured logs, then a cosign round trip and the state', async () => {
    const { base, lines } = await start();
    expect(await (await fetch(`${base}/healthz`)).json()).toEqual({ ok: true });
    expect(await (await fetch(`${base}/v1/key`)).json()).toEqual({ witness: wpk, logs: [LOG] });
    expect((await fetch(`${base}/v1/state/inst-1/grant-1`)).status).toBe(404);
    const h = sth(8, 7);
    const r = await post(base, JSON.stringify({ sth: h }));
    expect(r.status).toBe(200);
    const body = (await r.json()) as { cosignature: unknown; witness: string };
    expect(verifyTreeHead({ ...h, witnesses: [body.cosignature as never] }, gpk, { witnessKeys: [wpk], threshold: 1 })).toBe(true);
    const st = (await (await fetch(`${base}/v1/state/inst-1/grant-1`)).json()) as { latest: { size: number } };
    expect(st.latest.size).toBe(8);
    expect(lines).toEqual(['cosign status=200 size=8']);
  });

  it('refuses a wrong method, a wrong path, a wrong content type, bad JSON and an oversized body', async () => {
    const { base } = await start();
    expect((await fetch(`${base}/v1/cosign`)).status).toBe(405);
    expect((await fetch(`${base}/nope`)).status).toBe(404);
    expect((await post(base, '{}', { 'content-type': 'text/plain' })).status).toBe(415);
    expect(await (await post(base, '{not json')).json()).toEqual({ error: 'malformed_request', detail: 'body is not JSON' });
    const big = await post(base, JSON.stringify({ sth: { pad: 'x'.repeat(MAX_BODY_BYTES) } })).catch(() => ({ status: 413 }));
    expect(big.status).toBe(413);
    expect((await post(base, JSON.stringify({ sth: sth(8, 7, { secret: OTHER.secretKey }) }))).status).toBe(403);
  });

  it('never puts the witness secret in a response or a log line', async () => {
    const { base, lines } = await start();
    const texts = [await (await fetch(`${base}/v1/key`)).text(), await (await post(base, JSON.stringify({ sth: sth(8, 7) }))).text(), await (await post(base, 'junk')).text(), ...lines];
    for (const t of texts) {
      expect(t).not.toContain(b64u(W.secretKey));
      expect(t).not.toContain(Buffer.from(W.secretKey).toString('hex'));
    }
  });
});

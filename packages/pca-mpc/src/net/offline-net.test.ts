/**
 * Limit 5b: the dealer-free offline phase over the mutual-TLS network. Real OS processes, one per party and NO
 * dealer process: the parties derive the MAC keys, the sacrificed triples and the authenticated inputs from
 * oblivious transfer between every ordered pair, then run the same online protocol.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { T } from './test-timing';
import { composeClear } from '../compose';
import type { DecisionVector } from '../party';
import { launchLocal, type LaunchOptions, type NodeOutput } from './launch-local';

let buildDir = '';
let mainJs = '';

beforeAll(() => {
  buildDir = mkdtempSync(join(resolve(__dirname, '../..'), '.nettest-build-'));
  const tsc = require.resolve('typescript/bin/tsc');
  execFileSync(process.execPath, [tsc, '-p', resolve(__dirname, '../../tsconfig.build.json'), '--outDir', buildDir], { stdio: 'pipe' });
  mainJs = join(buildDir, 'net', 'party-main.js');
}, T(180_000));

afterAll(() => {
  if (buildDir) rmSync(buildDir, { recursive: true, force: true });
});

const V3: DecisionVector[] = [
  { allow: 1, t: 1, rQuant: 2 },
  { allow: 1, t: 2, rQuant: 5 },
  { allow: 1, t: 1, rQuant: 3 },
];
const Q = 6;
const run = (o: Partial<LaunchOptions>) =>
  launchLocal({ n: 3, vectors: V3, mainJs, Q, offline: 'no-dealer', recvTimeoutMs: 120_000, killAfterMs: 600_000, ...o });
const parties = (outs: NodeOutput[]) => outs.filter((o) => o.role === 'party');

describe('(5b) no trusted dealer: the OT-based offline phase runs over mutual TLS', () => {
  it('3 processes, no dealer process: the composed decision equals the cleartext one and every transcript agrees', async () => {
    const r = await run({});
    expect(r.outputs).toHaveLength(3); // no dealer node exists
    const ps = parties(r.outputs);
    for (const p of ps) expect(p.json?.ok, `party ${p.id}: ${p.stderr} ${JSON.stringify(p.json?.error)}`).toBe(true);
    for (const p of ps) {
      expect(p.json.result.composed).toEqual(composeClear(V3, Q));
      expect(p.json.result.offlineMode).toBe('no-dealer');
      expect(p.json.result.identifiableAbort).toBe(true);
      expect(p.json.result.macKeys).toBe(2);
    }
    expect(new Set(ps.map((p) => p.json.result.transcriptDigest)).size).toBe(1);
  }, T(450_000));

  it('n = 2 and n = 4 work too, and random vectors match the cleartext composition', async () => {
    for (const n of [2, 4]) {
      const vs = V3.concat([{ allow: 1, t: 3, rQuant: 1 }]).slice(0, n);
      const r = await run({ vectors: vs, n });
      for (const p of parties(r.outputs)) {
        expect(p.json?.ok, `n=${n} party ${p.id}: ${p.stderr} ${JSON.stringify(p.json?.error)}`).toBe(true);
        expect(p.json.result.composed).toEqual(composeClear(vs, Q));
      }
    }
    const denied = V3.map((v, i) => (i === 1 ? { ...v, allow: 0 as const } : v));
    const r = await run({ vectors: denied });
    for (const p of parties(r.outputs)) expect(p.json.result.composed.allow).toBe(0);
  }, T(450_000));
});

/** Every honest party aborted with no output; returns the direct (first-hand) reports. */
function honestAborts(outs: NodeOutput[], culprit: number): NodeOutput[] {
  const honest = parties(outs).filter((p) => p.id !== culprit);
  for (const p of honest) {
    expect(p.json, `party ${p.id}: ${p.stderr}`).not.toBeNull();
    expect(p.json.ok, `party ${p.id} must not output a result`).toBe(false);
    expect(p.json.result).toBeUndefined();
  }
  const direct = honest.filter((p) => p.json.error.kind !== 'peer-abort');
  if (direct.length > 0) return direct;
  // The culprit may abort (and send its abort frame) before an honest party reaches its own check. A peer-abort whose
  // authenticated sender is the culprit is then the only report: blamed = sender = culprit, a first-hand fact about the sender.
  for (const p of honest) expect(p.json.error.blamed, `party ${p.id}: ${p.json.error.message}`).toBe(culprit);
  return [];
}

describe('(5b) a cheating party in the dealer-free protocol never causes a wrong answer', () => {
  const fast = { recvTimeoutMs: 60_000 };

  it('each party in turn lies about an opened value (3 parties): no output, and the pairwise tags (also generated from OT) NAME it', async () => {
    for (const culprit of [0, 1, 2]) {
      const r = await run({ ...fast, overrides: { [culprit]: { behavior: { kind: 'open-lie', round: 'mul0' } } } });
      const direct = honestAborts(r.outputs, culprit);
        for (const p of direct) {
        expect(p.json.error.kind).toBe('mac-check');
        expect(p.json.error.blamed).toBe(culprit);
      }
    }
  }, T(300_000));

  it('each party in turn forges its MAC share or its MAC residual: the blame round names it', async () => {
    for (const [culprit, beh] of [
      [0, { kind: 'mac-lie', round: 'mul1' }],
      [2, { kind: 'sigma-lie' }],
    ] as const) {
      const r = await run({ ...fast, overrides: { [culprit]: { behavior: beh } } });
      const direct = honestAborts(r.outputs, culprit);
        for (const p of direct) {
        expect(p.json.error.kind).toBe('mac-check');
        expect(p.json.error.blamed).toBe(culprit);
      }
    }
  }, T(900_000));

  it('two parties: the only possible culprit is the peer, and it is named', async () => {
    const r = await run({ ...fast, n: 2, vectors: V3.slice(0, 2), overrides: { 0: { behavior: { kind: 'open-lie', round: 'mul0' } } } });
    const direct = honestAborts(r.outputs, 0);
    for (const d of direct) {
      expect(d.json.error.kind).toBe('mac-check');
      expect(d.json.error.blamed).toBe(0);
    }
  }, T(200_000));

  it('feeds a wrong operand into the OT multiplication of a triple product: the sacrifice catches it and the transcript audit names the cheater', async () => {
    const r = await run({ ...fast, overrides: { 2: { behavior: { kind: 'offline-lie' } } } });
    const direct = honestAborts(r.outputs, 2);
    for (const p of direct) {
      expect(p.json.error.kind).toBe('mac-check');
      expect(p.json.error.message).toMatch(/sacrifice FAILED/);
      expect(p.json.error.blamed).toBe(2); // attributed by the post-abort audit of the discarded triple's OT transcript
      expect(p.json.error.message).toMatch(/OT transcript audit names party 2/);
    }
  }, T(200_000));

  it('sends an inconsistent OT-extension u matrix: the KOS check aborts and NAMES the cheater', async () => {
    const r = await run({ ...fast, overrides: { 2: { behavior: { kind: 'ot-u-lie' } } } });
    const direct = honestAborts(r.outputs, 2);
    for (const p of direct) {
      expect(p.json.error.kind).toBe('ot-check');
      expect(p.json.error.blamed).toBe(2);
    }
  }, T(200_000));

  it('sends a base-OT proof of knowledge that does not verify: the receivers abort and name the cheater', async () => {
    const r = await run({ ...fast, overrides: { 0: { behavior: { kind: 'ot-proof-lie' } } } });
    const direct = honestAborts(r.outputs, 0);
    for (const p of direct) {
      expect(p.json.error.kind).toBe('ot-check');
      expect(p.json.error.blamed).toBe(0);
    }
  }, T(200_000));

  it('vanishes in the middle of the offline phase: attributable disconnect/timeout, no output', async () => {
    const r = await run({ recvTimeoutMs: 30_000, overrides: { 1: { behavior: { kind: 'crash', round: 'ox1.0.u' } } } });
    const direct = honestAborts(r.outputs, 1);
    for (const p of direct) {
      expect(['disconnect', 'timeout']).toContain(p.json.error.kind);
      expect(p.json.error.blamed).toBe(1);
    }
  }, T(200_000));
});

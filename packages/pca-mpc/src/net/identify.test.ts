/**
 * Audit residual limit 6 (identifiable abort) and limit 5a over the real network: real OS processes, one per
 * party plus a trusted dealer, talking only over mutual TLS.
 *
 *  - in trusted-dealer mode every opened share carries a pairwise information-theoretic MAC (`pa.ts`), so a
 *    party that lies about a share, a tag, a MAC share or a residual is NAMED by the honest verifiers. Each of
 *    the three parties is made the cheater in turn, for each kind of lie.
 *  - a dealer that deals a wrong triple (c != a*b) is caught by the parties' sacrifice and named as the dealer;
 *    a dealer that deals a MAC that does not match its value is named by the blame round.
 *  - in no-dealer mode (see offline-net.test.ts) there are no pairwise tags: that is the documented residual.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { T } from './test-timing';
import { composeClear } from '../compose';
import type { DecisionVector } from '../party';
import { launchLocal, type LaunchOptions, type NodeOutput } from './launch-local';
import type { Behavior } from './protocol';

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
  { allow: 1, t: 1, rQuant: 12 },
  { allow: 1, t: 2, rQuant: 55 },
  { allow: 1, t: 1, rQuant: 30 },
];
const run = (o: Partial<LaunchOptions>) => launchLocal({ n: 3, vectors: V3, mainJs, Q: 64, ...o });
const parties = (outs: NodeOutput[]) => outs.filter((o) => o.role === 'party');

/** Every honest party aborts with no output; at least one names `culprit` first-hand; none names anyone else. */
function expectIdentified(outs: NodeOutput[], culprit: number, kind = 'mac-check'): void {
  const honest = parties(outs).filter((p) => p.id !== culprit);
  expect(honest.length).toBeGreaterThan(0);
  let direct = 0;
  for (const p of honest) {
    expect(p.json, `party ${p.id}: ${p.stderr}`).not.toBeNull();
    expect(p.json.ok, `party ${p.id} must not output a result`).toBe(false);
    expect(p.json.result).toBeUndefined();
    const e = p.json.error;
    if (e.kind === 'peer-abort') {
      // second-hand: only a claim, and the claim (when it names anyone) names the culprit
      if (e.claimedBlame !== undefined && e.claimedBlame !== null) expect(e.claimedBlame, `party ${p.id}: ${e.message}`).toBe(culprit);
    } else {
      expect(e.kind, `party ${p.id}: ${e.message}`).toBe(kind);
      expect(e.blamed, `party ${p.id} must name the cheater: ${e.message}`).toBe(culprit);
      direct++;
    }
  }
  expect(direct, 'at least one honest party identified the cheater first-hand').toBeGreaterThan(0);
}

describe('honest dealer-mode runs report their security parameters', () => {
  it('2 MAC keys, sacrificed triples, identifiable aborts, labelled trusted-dealer; equals composeClear', async () => {
    const r = await run({ Q: 64 });
    for (const p of parties(r.outputs)) {
      expect(p.json?.ok, p.stderr).toBe(true);
      const res = p.json.result;
      expect(res.composed).toEqual(composeClear(V3, 64));
      expect(res.offlineMode).toBe('trusted-dealer');
      expect(res.macKeys).toBe(2);
      expect(res.sacrificePartners).toBe(2);
      expect(res.sacrificedTriples).toBe(2 * (4 + 64));
      expect(res.identifiableAbort).toBe(true);
    }
  }, T(60_000));
});

describe('(6) each party in turn is the cheater and is named', () => {
  const lies: { name: string; beh: Behavior }[] = [
    { name: 'lies about an opened value in a multiplication round', beh: { kind: 'open-lie', round: 'mul0' } },
    { name: 'lies about an opened value in the output round', beh: { kind: 'open-lie', round: 'out' } },
    { name: 'lies about an opened value during the triple sacrifice', beh: { kind: 'open-lie', round: 'sac-rho' } },
    { name: 'sends a wrong pairwise tag', beh: { kind: 'bad-tag', round: 'mul1' } },
    { name: 'equivocates (a different share to one peer)', beh: { kind: 'equivocate', round: 'mul0' } },
    { name: 'forges its MAC share (found by the blame round)', beh: { kind: 'mac-lie', round: 'mul1' } },
    { name: 'commits to and opens a wrong MAC residual (found by the blame round)', beh: { kind: 'sigma-lie' } },
  ];
  for (const culprit of [0, 1, 2]) {
    for (const l of lies) {
      it(`party ${culprit} ${l.name}`, async () => {
        const r = await run({ overrides: { [culprit]: { behavior: l.beh } } });
        expectIdentified(r.outputs, culprit);
      }, T(60_000));
    }
  }

  it('two-party run: the cheater is named too', async () => {
    const r = await launchLocal({
      n: 2,
      vectors: V3.slice(0, 2),
      mainJs,
      Q: 64,
      overrides: { 0: { behavior: { kind: 'open-lie', round: 'mul0' } } },
    });
    expectIdentified(r.outputs, 0);
  }, T(60_000));

  it('commitment-level lies stay attributable as before (coin seed, MAC residual opening)', async () => {
    for (const culprit of [0, 2]) {
      const r = await run({ overrides: { [culprit]: { behavior: { kind: 'bad-sigma-open' } } } });
      expectIdentified(r.outputs, culprit, 'commitment');
    }
  }, T(120_000));
});

describe('(5a) a lying trusted dealer is detected over the network', () => {
  it('a dealer that deals c = a*b + 1: every party aborts and names the DEALER', async () => {
    const r = await run({ overrides: { 3: { dealerFault: { keepCDelta: '1' } } } });
    for (const p of parties(r.outputs)) {
      expect(p.json?.ok, `party ${p.id}`).toBe(false);
      expect(p.json.result).toBeUndefined();
    }
    const direct = parties(r.outputs).filter((p) => p.json.error.kind !== 'peer-abort');
    expect(direct.length).toBeGreaterThan(0);
    for (const p of direct) {
      expect(p.json.error.kind).toBe('dealer');
      expect(p.json.error.blamed).toBe(3);
      expect(p.json.error.message).toMatch(/sacrifice FAILED/);
    }
  }, T(60_000));

  it('a lie in only ONE sacrifice partner is caught too', async () => {
    const r = await run({ overrides: { 3: { dealerFault: { partnerCDelta: [null, '9'] } } } });
    const direct = parties(r.outputs).filter((p) => p.json?.error?.kind !== 'peer-abort');
    expect(direct.length).toBeGreaterThan(0);
    for (const p of direct) expect(p.json.error.kind).toBe('dealer');
  }, T(60_000));

  it('a dealer that deals a MAC that does not match its value: the blame round names the DEALER', async () => {
    const r = await run({ overrides: { 3: { dealerFault: { macFaultAtInput: 0 } } } });
    for (const p of parties(r.outputs)) expect(p.json?.ok, `party ${p.id}`).toBe(false);
    const direct = parties(r.outputs).filter((p) => p.json.error.kind !== 'peer-abort');
    expect(direct.length).toBeGreaterThan(0);
    for (const p of direct) {
      expect(p.json.error.kind).toBe('dealer');
      expect(p.json.error.blamed).toBe(3);
    }
  }, T(60_000));
});

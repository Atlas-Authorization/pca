/**
 * Networked MPC: real OS processes (one per party + a dealer) talking only over mutual-TLS sockets on
 * localhost. Honest runs must equal the in-process run; every injected network or protocol fault must end
 * in an ABORT with no output, within the timeout, and (where the evidence allows) naming the culprit.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import * as tls from 'node:tls';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { T, until, waitListening, reservePorts } from './test-timing';
import { composeClear } from '../compose';
import type { DecisionVector } from '../party';
import { composeSecureMalicious } from '../spdz-runner';
import { generateIdentity, readPem } from './certs';
import type { FrameFault } from './faults';
import { launchLocal, launchOtLocal, type LaunchOptions, type NodeOutput } from './launch-local';
import { Mesh } from './mesh';
import type { Behavior } from './protocol';
import { FrameSplitter, MAX_FRAME_BYTES, WIRE_VERSION, encodeFrame, hx, parseFrame, unhx, unhxArray } from './wire';

let buildDir = '';
let mainJs = '';

beforeAll(() => {
  // inside the package so `@atlasauth/pca-mpc-wasm` resolves through packages/pca-mpc/node_modules (deterministic)
  buildDir = mkdtempSync(join(resolve(__dirname, '../..'), '.nettest-build-'));
  const tsc = require.resolve('typescript/bin/tsc');
  execFileSync(process.execPath, [tsc, '-p', resolve(__dirname, '../../tsconfig.build.json'), '--outDir', buildDir], {
    stdio: 'pipe',
  });
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

const run = (o: Partial<LaunchOptions> & { vectors?: DecisionVector[] }) =>
  launchLocal({ n: (o.vectors ?? V3).length, vectors: V3, mainJs, ...o });

const parties = (outs: NodeOutput[]) => outs.filter((o) => o.role === 'party');

function lcg(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 0x100000000;
  };
}

describe('wire codec', () => {
  it('rejects non-canonical field elements and wrong shapes', () => {
    expect(unhx('0')).toBe(0n);
    expect(unhx(hx(2n ** 61n - 2n))).toBe(2n ** 61n - 2n);
    expect(unhx(hx(2n ** 61n - 1n))).toBeNull(); // == p
    expect(unhx('01')).toBeNull(); // leading zero
    expect(unhx('AB')).toBeNull(); // uppercase
    expect(unhx('1'.repeat(17))).toBeNull();
    expect(unhx(5)).toBeNull();
    expect(unhxArray(['1', '2'], 3)).toBeNull();
  });
  it('splits frames incrementally and refuses a hostile length prefix', () => {
    const f = encodeFrame({ v: WIRE_VERSION, ty: 'msg', sid: 's', seq: 0, rd: 'r', d: [1] });
    const sp = new FrameSplitter();
    expect(sp.push(f.subarray(0, 3))).toHaveLength(0);
    expect(sp.push(f.subarray(3, 10))).toHaveLength(0);
    const out = sp.push(f.subarray(10));
    expect(out).toHaveLength(1);
    expect(parseFrame(out[0]!)?.rd).toBe('r');
    const h = Buffer.alloc(4);
    h.writeUInt32BE(MAX_FRAME_BYTES + 1, 0);
    expect(() => new FrameSplitter().push(h)).toThrow('oversize');
  });
  it('parseFrame is strict', () => {
    const ok = { v: WIRE_VERSION, ty: 'msg', sid: 's', seq: 0, rd: 'r', d: null };
    const b = (o: unknown) => Buffer.from(JSON.stringify(o));
    expect(parseFrame(b(ok))).not.toBeNull();
    expect(parseFrame(b({ ...ok, x: 1 }))).toBeNull();
    expect(parseFrame(b({ ...ok, ty: 'nope' }))).toBeNull();
    expect(parseFrame(b({ ...ok, seq: -1 }))).toBeNull();
    expect(parseFrame(b({ ...ok, seq: 1.5 }))).toBeNull();
    expect(parseFrame(Buffer.from('not json'))).toBeNull();
    expect(parseFrame(b([1, 2]))).toBeNull();
  });
});

describe('TLS identity (pinned self-signed certs)', () => {
  it('rejects a client whose certificate is not pinned, and a server impersonator', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pca-mpc-id-'));
    try {
      const a = generateIdentity(join(dir, 'a'), 'a');
      const b = generateIdentity(join(dir, 'b'), 'b');
      const evil = generateIdentity(join(dir, 'evil'), 'evil');
      const [pa, pb] = (await reservePorts(2)) as [number, number];
      const nodes = [
        { id: 0, host: '127.0.0.1', port: pa, certPem: readPem(a.certPath) },
        { id: 1, host: '127.0.0.1', port: pb, certPem: readPem(b.certPath) },
      ];
      const m0 = new Mesh({ selfId: 0, nodes, keyPem: readPem(a.keyPath), certPem: readPem(a.certPath), sessionId: 's', listenHost: '127.0.0.1', connectTimeoutMs: 2500 });
      const wait0 = m0.connect().catch((e) => e);
      await waitListening(pa);
      // (1) impostor client with an unpinned cert: handshake must fail.
      const failed = await new Promise<boolean>((res) => {
        const s = tls.connect({ host: '127.0.0.1', port: pa, key: readPem(evil.keyPath), cert: readPem(evil.certPath), rejectUnauthorized: false });
        s.on('secureConnect', () => void until(() => s.destroyed, 'the unpinned client to be dropped', 5000).then(() => res(true), () => res(false)));
        s.on('error', () => res(true));
        s.on('close', () => res(true));
      });
      expect(failed).toBe(true);
      expect(m0.events.some((e) => e.includes('tlsClientError') || e.includes('rejected incoming'))).toBe(true);
      // (2) node 1 dials an impostor server squatting on node 0's address: must never authenticate.
      const imp = tls.createServer({ key: readPem(evil.keyPath), cert: readPem(evil.certPath) }, (s) => s.on('error', () => undefined));
      const [pimp] = (await reservePorts(1)) as [number];
      await new Promise<void>((r) => imp.listen(pimp, '127.0.0.1', () => r()));
      const m1 = new Mesh({
        selfId: 1,
        nodes: [{ ...nodes[0]!, port: pimp }, nodes[1]!],
        keyPem: readPem(b.keyPath),
        certPem: readPem(b.certPath),
        sessionId: 's',
        listenHost: '127.0.0.1',
        connectTimeoutMs: 1500,
      });
      const r1 = await m1.connect().catch((e) => e);
      expect(r1).toBeInstanceOf(Error);
      expect((r1 as Error).message).toMatch(/timeout|identity/);
      imp.close();
      await wait0;
      m0.fail(m0.failed ?? (r1 as never));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, T(240_000));
});

describe('honest multi-process runs == in-process runs', () => {
  it('3 parties, Q=100: composed decision equals composeSecureMalicious and composeClear; transcripts agree', async () => {
    const r = await run({ Q: 100 });
    const ps = parties(r.outputs);
    expect(ps.every((p) => p.json?.ok === true && p.exitCode === 0)).toBe(true);
    const inproc = composeSecureMalicious(V3, { Q: 100 });
    for (const p of ps) {
      expect(p.json.result.composed).toEqual(inproc.composed);
      expect(p.json.result.composed).toEqual(composeClear(V3));
      expect(p.json.result.multiplications).toBe(inproc.multiplications);
    }
    expect(new Set(ps.map((p) => p.json.result.transcriptDigest)).size).toBe(1);
    expect(inproc.composed).toEqual({ allow: 1, t: 2, rQuant: 55 });
  }, T(240_000));

  it('a denying party flips allow to 0 (all four processes agree)', async () => {
    const vs: DecisionVector[] = [V3[0]!, V3[1]!, { allow: 0, t: 3, rQuant: 99 }, { allow: 1, t: 1, rQuant: 1 }];
    const r = await run({ vectors: vs, Q: 100 });
    for (const p of parties(r.outputs)) expect(p.json.result.composed).toEqual({ allow: 0, t: 3, rQuant: 99 });
  }, T(240_000));

  it('single party (n=1) works', async () => {
    const r = await run({ vectors: [{ allow: 1, t: 3, rQuant: 7 }], Q: 16 });
    expect(parties(r.outputs)[0]!.json.result.composed).toEqual({ allow: 1, t: 3, rQuant: 7 });
  }, T(240_000));

  it('random vectors, n in 2..4, match composeClear', async () => {
    const rnd = lcg(0xfeed);
    const Q = 16;
    for (let iter = 0; iter < 6; iter++) {
      const n = 2 + (iter % 3);
      const vs: DecisionVector[] = Array.from({ length: n }, () => ({
        allow: rnd() < 0.7 ? 1 : 0,
        t: (1 + Math.floor(rnd() * 3)) as 1 | 2 | 3,
        rQuant: Math.floor(rnd() * (Q + 1)),
      }));
      const r = await run({ vectors: vs, Q });
      const want = composeClear(vs);
      for (const p of parties(r.outputs)) {
        expect(p.json?.ok).toBe(true);
        expect(p.json.result.composed).toEqual(want);
      }
    }
  }, T(300_000));
});

/** All honest parties aborted without output; returns their error records. */
function assertAborted(outs: NodeOutput[], culprit: number | null, kinds: string[]): void {
  const honest = parties(outs).filter((p) => p.id !== culprit);
  for (const p of honest) {
    expect(p.json, `party ${p.id} produced no JSON: ${p.stderr}`).not.toBeNull();
    expect(p.json.ok, `party ${p.id} must not output a result`).toBe(false);
    expect(p.json.result).toBeUndefined();
    expect(p.exitCode).toBe(3);
    const e = p.json.error;
    const direct = kinds.includes(e.kind);
    const viaPeer = e.kind === 'peer-abort' && (e.claimedKind === undefined || kinds.includes(e.claimedKind));
    expect(direct || viaPeer, `party ${p.id}: unexpected abort kind ${e.kind}/${e.claimedKind}`).toBe(true);
    if (culprit !== null) {
      if (viaPeer) {
        // A peer-abort is only a claim, kept apart from attribution. When the frame came from the culprit itself
        // (e.blamed === culprit) or was relayed second-hand by an honest peer (e.blamed === null: it carries whatever
        // the culprit claimed), its accusation is unconstrained: a malicious party's own abort frame bypasses its
        // tamper fault and may name anyone (e.g. its own mul0.t timeout names an honest peer). Only a first-hand
        // abort from an honest peer (e.blamed is that peer) must accuse the culprit.
        if (e.blamed !== null && e.blamed !== culprit && e.claimedBlame !== undefined && e.claimedBlame !== null) {
          expect(e.claimedBlame).toBe(culprit);
        }
      } else {
        expect(e.blamed, `party ${p.id} must blame the culprit (${e.message})`).toBe(culprit);
      }
    }
  }
}

describe('malicious sender at the framing layer (party 1 attacks round mul0)', () => {
  const cases: { fault: FrameFault['kind']; kinds: string[] }[] = [
    { fault: 'duplicate', kinds: ['duplicate'] },
    { fault: 'reorder', kinds: ['out-of-order'] },
    { fault: 'skip-seq', kinds: ['out-of-order'] },
    { fault: 'garbage', kinds: ['malformed'] },
    { fault: 'wrong-round', kinds: ['wrong-round'] },
    { fault: 'wrong-session', kinds: ['wrong-session'] },
    { fault: 'oversize', kinds: ['oversize'] },
    { fault: 'extra-field', kinds: ['malformed'] },
    { fault: 'truncate', kinds: ['timeout', 'malformed', 'out-of-order', 'oversize', 'disconnect'] },
    { fault: 'drop', kinds: ['timeout', 'out-of-order'] },
    { fault: 'silent-from', kinds: ['timeout'] },
  ];
  for (const c of cases) {
    it(`${c.fault}: honest parties abort, blame party 1, no output`, async () => {
      const r = await run({
        Q: 64,
        recvTimeoutMs: 30_000,
        overrides: { 1: { frameFault: { kind: c.fault, round: 'mul0', to: undefined } } },
      });
      assertAborted(r.outputs, 1, c.kinds);
    }, T(240_000));
  }

  it('silent-from: the culprit aborting first with its own (false) accusation of an honest peer is still only a claim', async () => {
    // Party 1 is silent from mul0, so it never gets the honest parties' mul0.t and times out on them; with a shorter
    // deadline than the honest parties' its abort frame (not subject to the tamper fault) reaches them first and
    // accuses an honest party. Deterministic stand-in for the CPU-starved CI ordering that flaked the old assertion.
    const r = await run({
      Q: 64,
      recvTimeoutMs: 30_000,
      overrides: { 1: { recvTimeoutMs: T(6_000), frameFault: { kind: 'silent-from', round: 'mul0', to: undefined } } },
    });
    assertAborted(r.outputs, 1, ['timeout']);
  }, T(240_000));

  it('bitflip inside a payload never yields a silently wrong answer', async () => {
    const r = await run({ Q: 64, recvTimeoutMs: 30_000, overrides: { 1: { frameFault: { kind: 'bitflip', round: 'mul0' } } } });
    for (const p of parties(r.outputs).filter((x) => x.id !== 1)) {
      expect(p.json.ok).toBe(false);
      expect(['malformed', 'mac-check', 'equivocation', 'peer-abort']).toContain(p.json.error.kind);
    }
  }, T(240_000));
});

describe('a forged abort frame is only a claim (party 1 accuses an honest party)', () => {
  for (const accuse of [0, 2]) {
    it(`party 1 accuses honest party ${accuse}: every honest node blames the reporter (1), never the accused`, async () => {
      const r = await run({
        Q: 64,
        recvTimeoutMs: 30_000,
        overrides: { 1: { frameFault: { kind: 'false-accuse', round: 'mul0', accuse } } },
      });
      const honest = parties(r.outputs).filter((p) => p.id !== 1);
      expect(honest.length).toBe(2);
      for (const p of honest) {
        expect(p.json?.ok, `party ${p.id}: ${p.stderr}`).toBe(false);
        const e = p.json.error;
        // the accused is never blamed; the accusation is only kept apart as a claim
        expect(e.blamed, `party ${p.id}: ${e.message}`).not.toBe(accuse);
        expect([1, null]).toContain(e.blamed); // 1 = it got the frame from party 1 itself; null = second-hand relay
        if (e.kind === 'peer-abort') expect(e.claimedBlame).toBe(accuse);
      }
      // whoever received the forged frame first-hand blames its sender, party 1
      expect(honest.some((p) => p.json.error.blamed === 1)).toBe(true);
    }, T(240_000));
  }

  it('test hooks cannot be enabled from a plain production config', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pca-mpc-hooks-'));
    try {
      const id = generateIdentity(join(dir, 'n0'), 'n0');
      const cfg = {
        role: 'party', id: 0, n: 1, sessionId: 's', input: { allow: 1, t: 1, rQuant: 1 },
        nodes: [{ id: 0, host: '127.0.0.1', port: (await reservePorts(1))[0]!, certPath: id.certPath }],
        keyPath: id.keyPath, certPath: id.certPath, behavior: { kind: 'crash', round: 'prep' },
      };
      const p = join(dir, 'cfg.json');
      writeFileSync(p, JSON.stringify(cfg));
      for (const extra of [{}, { unsafeTestHooks: true }]) {
        writeFileSync(p, JSON.stringify({ ...cfg, ...extra }));
        const r = spawnSync(process.execPath, [mainJs, p], { encoding: 'utf8', env: { ...process.env, PCA_MPC_UNSAFE_TEST_HOOKS: undefined } });
        expect(r.status).toBe(3);
        expect(JSON.parse(r.stdout.trim()).error.message).toMatch(/test hooks .* not enabled/);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, T(240_000));
});

describe('malicious party deviating inside the protocol (party 1)', () => {
  const beh = (b: Behavior): Partial<LaunchOptions> => ({ Q: 64, recvTimeoutMs: 30_000, overrides: { 1: { behavior: b } } });

  it('lies about an opened value: every honest party aborts and the pairwise MAC NAMES the cheater (trusted-dealer mode)', async () => {
    const r = await run(beh({ kind: 'open-lie', round: 'mul0' }));
    assertAborted(r.outputs, 1, ['mac-check']);
    expect(parties(r.outputs).some((p) => p.id !== 1 && p.json.error.blamed === 1)).toBe(true);
  }, T(240_000));

  it('lies about an opened value in the OUTPUT round: MAC-check aborts', async () => {
    const r = await run(beh({ kind: 'open-lie', round: 'out' }));
    for (const p of parties(r.outputs)) expect(p.json.ok).toBe(false);
    for (const p of parties(r.outputs).filter((x) => x.id !== 1)) expect(['mac-check', 'peer-abort']).toContain(p.json.error.kind);
  }, T(240_000));

  it('forges a MAC share: MAC-check aborts', async () => {
    const r = await run(beh({ kind: 'mac-lie', round: 'mul1' }));
    for (const p of parties(r.outputs)) expect(p.json.ok).toBe(false);
    for (const p of parties(r.outputs).filter((x) => x.id !== 1)) expect(['mac-check', 'peer-abort']).toContain(p.json.error.kind);
  }, T(240_000));

  it('equivocates (different shares to different peers): aborts, never a divergent output', async () => {
    const r = await run(beh({ kind: 'equivocate', round: 'mul0' }));
    for (const p of parties(r.outputs)) expect(p.json.ok).toBe(false);
  }, T(240_000));

  it('opens a coin seed that does not match its commitment: attributable', async () => {
    const r = await run(beh({ kind: 'bad-coin-open' }));
    assertAborted(r.outputs, 1, ['commitment']);
  }, T(240_000));

  it('opens a MAC residual that does not match its commitment: attributable', async () => {
    const r = await run(beh({ kind: 'bad-sigma-open' }));
    assertAborted(r.outputs, 1, ['commitment']);
  }, T(240_000));

  it('sends a wrong-length array: malformed, attributable', async () => {
    const r = await run(beh({ kind: 'short-array', round: 'mul0' }));
    assertAborted(r.outputs, 1, ['malformed']);
  }, T(240_000));

  it('sends a non-canonical field element: malformed, attributable', async () => {
    const r = await run(beh({ kind: 'noncanonical', round: 'out' }));
    assertAborted(r.outputs, 1, ['malformed']);
  }, T(240_000));

  it('crashes mid-protocol: disconnect, attributable', async () => {
    const r = await run(beh({ kind: 'crash', round: 'mul1' }));
    assertAborted(r.outputs, 1, ['disconnect', 'timeout']);
  }, T(240_000));

  it('connects then vanishes before its first message (no-show): attributable', async () => {
    const r = await run(beh({ kind: 'crash', round: 'prep' }));
    assertAborted(r.outputs, 1, ['disconnect', 'timeout']);
  }, T(240_000));
});

describe('network adversary on the wire (TCP proxy on the link party2 -> party0)', () => {
  const wire = (kind: 'drop' | 'delay' | 'truncate' | 'bitflip' | 'duplicate' | 'reorder', dir: 'c2s' | 's2c', ms?: number, recvTimeoutMs = 30_000) =>
    run({ Q: 64, recvTimeoutMs, wireFault: { dialer: 2, target: 0, fault: { kind, dir, afterBytes: 4000, ms } } });

  for (const kind of ['bitflip', 'truncate', 'duplicate', 'reorder'] as const) {
    for (const dir of ['c2s', 's2c'] as const) {
      it(`${kind} ${dir}: TLS rejects it; all parties abort with no output; blame falls on that link`, async () => {
        const r = await wire(kind, dir);
        for (const p of parties(r.outputs)) {
          expect(p.json.ok, `party ${p.id}`).toBe(false);
          expect(p.json.result).toBeUndefined();
        }
        const reporters = parties(r.outputs).filter((p) => p.json.error.kind !== 'peer-abort');
        expect(reporters.length).toBeGreaterThan(0);
        for (const p of reporters) {
          expect(['disconnect', 'timeout', 'malformed']).toContain(p.json.error.kind);
          expect([0, 2]).toContain(p.json.error.blamed); // the two endpoints of the faulty link
        }
        expect(r.proxyLog.length).toBeGreaterThan(0);
      }, T(240_000));
    }
  }

  it('drop (black hole): timeout, all abort', async () => {
    const r = await wire('drop', 'c2s');
    for (const p of parties(r.outputs)) expect(p.json.ok).toBe(false);
    expect(parties(r.outputs).some((p) => p.json.error.kind === 'timeout')).toBe(true);
  }, T(240_000));

  it('delay below the timeout is tolerated: correct result', async () => {
    const r = await wire('delay', 'c2s', 300, 120_000); // a delay 400x smaller than the timeout: tolerated however loaded the box is
    for (const p of parties(r.outputs)) {
      expect(p.json.ok).toBe(true);
      expect(p.json.result.composed).toEqual(composeClear(V3));
    }
  }, T(240_000));

  it('delay above the timeout aborts', async () => {
    const r = await run({ Q: 64, recvTimeoutMs: 3000, wireFault: { dialer: 2, target: 0, fault: { kind: 'delay', dir: 'c2s', afterBytes: 4000, ms: 600_000 } } });
    for (const p of parties(r.outputs)) expect(p.json.ok).toBe(false);
  }, T(240_000));
});

describe('pairwise base OT over the network (WASM-backed primitives, two processes)', () => {
  for (const kind of ['ec', 'lwe'] as const) {
    it(`${kind}: receiver's pads equal the sender's pads at the receiver's choices`, async () => {
      const r = await launchOtLocal({ kind, count: 32, mainJs });
      for (const o of r.outputs) {
        expect(o.json?.ok, o.stderr + JSON.stringify(o.json?.error)).toBe(true);
        expect(o.json.result.matched).toBe(true);
      }
      if (kind === 'ec') expect(r.outputs[0]!.json.result.wasmCurveActive).toBe(true);
    }, T(90_000));
  }
});

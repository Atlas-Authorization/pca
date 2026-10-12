/**
 * Mutation-kill tests for pq.ts (part 3): the lazily-loaded FN-DSA and LESS backends — candidate resolution,
 * fail-closed behaviour, reason strings, caching, and the arguments handed to the binding. `node:module`'s
 * createRequire is mocked per fresh module instance, so no real wasm is needed (or trusted) here.
 */
import { dirname, join, resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { b64u } from './hash';

type PqMod = typeof import('./pq');
type Req = (spec: string) => unknown;

async function freshPq(req: Req | 'throws', created?: { count: number }): Promise<PqMod> {
  vi.resetModules();
  vi.doMock('node:module', () => ({
    createRequire: () => {
      if (created) created.count++;
      if (req === 'throws') throw new Error('createRequire exploded');
      return req;
    },
  }));
  return import('./pq');
}
afterEach(() => {
  vi.doUnmock('node:module');
  vi.resetModules();
});
function thrown(fn: () => unknown): Error {
  try {
    fn();
  } catch (e) {
    return e as Error;
  }
  throw new Error('expected a throw');
}

const FN_SPEC = '@atlasauth/pca-fndsa-wasm';
const LESS_SPEC = '@atlasauth/pca-less-wasm';
const MSG = new Uint8Array([1, 2, 3]);
const notFound = (spec: string): never => {
  throw new Error(`Cannot find module '${spec}'`);
};

// ---- FN-DSA backend ------------------------------------------------------------------------------
function fnBinding(log: unknown[][] = [], ...rest: unknown[]) {
  const verifyRet = rest.length > 0 ? rest[0] : true;
  return {
    verify: (...a: unknown[]) => {
      log.push(['verify', ...a]);
      return verifyRet;
    },
    sign: (...a: unknown[]) => {
      log.push(['sign', ...a]);
      return new Uint8Array([9, 9]);
    },
    keygen: (...a: unknown[]) => {
      log.push(['keygen', ...a]);
      return { verifyingKey: new Uint8Array([7]), signingKey: new Uint8Array([8]) };
    },
  };
}

describe('FN-DSA backend resolution', () => {
  it('tries the package first, then the sibling dist path; stops at the first usable one', async () => {
    const specs: string[] = [];
    const good = fnBinding();
    const P = await freshPq((s) => {
      specs.push(s);
      return good;
    });
    expect(P.isFnDsaBackendActive()).toBe(true);
    expect(specs).toEqual([FN_SPEC]);
  });
  it('falls through a throwing first candidate to the sibling dist path (exact path)', async () => {
    const specs: string[] = [];
    const good = fnBinding();
    const P = await freshPq((s) => {
      specs.push(s);
      if (s === FN_SPEC) throw new Error('boom');
      return good;
    });
    expect(P.isFnDsaBackendActive()).toBe(true);
    expect(specs.length).toBe(2);
    expect(specs[0]).toBe(FN_SPEC);
    expect(resolve(specs[1]!)).toBe(resolve(dirname(__filename), '..', '..', 'pca-fndsa-wasm', 'dist', 'index.js'));
    expect(specs[1]!.endsWith(join('pca-fndsa-wasm', 'dist', 'index.js'))).toBe(true);
  });
  it('falls through an unusable first module (incomplete surface) to the second', async () => {
    const good = fnBinding();
    const incompletes = [{ verify() {}, sign() {} }, { verify() {}, keygen() {} }, { sign() {}, keygen() {} }, { verify: 1, sign() {}, keygen() {} }, {}, null, 'str', 5, undefined];
    for (const bad of incompletes) {
      const P = await freshPq((s) => (s === FN_SPEC ? bad : good));
      expect(P.isFnDsaBackendActive(), String(bad)).toBe(true);
      const log: unknown[][] = [];
      const P2 = await freshPq((s) => (s === FN_SPEC ? bad : fnBinding(log)));
      P2.fnDsa512Keygen(new Uint8Array(32));
      expect(log.length, String(bad)).toBe(1);
    }
  });
  it('a function-typed module (even one carrying all three ops) is refused', async () => {
    const fnMod = Object.assign(() => 0, fnBinding());
    const P = await freshPq(() => fnMod);
    expect(P.isFnDsaBackendActive()).toBe(false);
  });
  it('no candidate usable => inactive; verify fails closed; keygen/sign THROW with the exact messages', async () => {
    const P = await freshPq(() => {
      throw new Error('nope');
    });
    expect(P.isFnDsaBackendActive()).toBe(false);
    expect(P.fnDsa512Verify(new Uint8Array(897), MSG, new Uint8Array(666))).toBe(false);
    expect(P.fnDsa1024Verify(new Uint8Array(1793), MSG, new Uint8Array(1280))).toBe(false);
    expect(thrown(() => P.fnDsa512Keygen(new Uint8Array(32))).message).toBe('fnDsa512Keygen: FN-DSA wasm backend unavailable');
    expect(thrown(() => P.fnDsa1024Keygen(new Uint8Array(32))).message).toBe('fnDsa1024Keygen: FN-DSA wasm backend unavailable');
    expect(thrown(() => P.fnDsa512Sign(new Uint8Array(1), MSG, new Uint8Array(32))).message).toBe('fnDsa512Sign: FN-DSA wasm backend unavailable');
    expect(thrown(() => P.fnDsa1024Sign(new Uint8Array(1), MSG, new Uint8Array(32))).message).toBe('fnDsa1024Sign: FN-DSA wasm backend unavailable');
  });
  it('createRequire itself failing pins the backend unavailable (fail closed), without throwing', async () => {
    const P = await freshPq('throws');
    expect(P.isFnDsaBackendActive()).toBe(false);
    expect(P.fnDsa512Verify(new Uint8Array(897), MSG, new Uint8Array(666))).toBe(false);
  });
  it('the probe result is cached (one createRequire, one load per candidate, however many calls)', async () => {
    const specs: string[] = [];
    const created = { count: 0 };
    const P = await freshPq((s) => {
      specs.push(s);
      throw new Error('nope');
    }, created);
    for (let i = 0; i < 4; i++) {
      P.isFnDsaBackendActive();
      P.fnDsa512Verify(new Uint8Array(897), MSG, new Uint8Array(666));
    }
    expect(created.count).toBe(1);
    expect(specs.length).toBe(2);
    // and a successful probe is cached too
    const specs2: string[] = [];
    const good = fnBinding();
    const P2 = await freshPq((s) => (specs2.push(s), good));
    P2.isFnDsaBackendActive();
    P2.isFnDsaBackendActive();
    P2.fnDsa512Keygen(new Uint8Array(32));
    expect(specs2).toEqual([FN_SPEC]);
  });
});

describe('FN-DSA wasm call contract', () => {
  it('verify: variant + (pk, msg, sig) forwarded; only literal `true` is acceptance', async () => {
    for (const [ret, want] of [[true, true], [1, false], ['true', false], [{}, false], [undefined, false], [false, false]] as const) {
      const log: unknown[][] = [];
      const P = await freshPq(() => fnBinding(log, ret));
      const pk5 = new Uint8Array(897).fill(1);
      const sg5 = new Uint8Array(666).fill(2);
      expect(P.fnDsa512Verify(pk5, MSG, sg5), String(ret)).toBe(want);
      expect(log).toEqual([['verify', 'fn-dsa-512', pk5, MSG, sg5]]);
      const log2: unknown[][] = [];
      const P2 = await freshPq(() => fnBinding(log2, ret));
      const pk10 = new Uint8Array(1793).fill(1);
      const sg10 = new Uint8Array(1280).fill(2);
      expect(P2.fnDsa1024Verify(pk10, MSG, sg10), String(ret)).toBe(want);
      expect(log2).toEqual([['verify', 'fn-dsa-1024', pk10, MSG, sg10]]);
    }
  });
  it('verify: lengths are checked BEFORE the wasm is called; non-Uint8Array refused; a throwing wasm => false', async () => {
    const log: unknown[][] = [];
    const P = await freshPq(() => fnBinding(log));
    expect(P.fnDsa512Verify(new Uint8Array(896), MSG, new Uint8Array(666))).toBe(false);
    expect(P.fnDsa512Verify(new Uint8Array(898), MSG, new Uint8Array(666))).toBe(false);
    expect(P.fnDsa512Verify(new Uint8Array(897), MSG, new Uint8Array(665))).toBe(false);
    expect(P.fnDsa512Verify(new Uint8Array(897), MSG, new Uint8Array(667))).toBe(false);
    expect(P.fnDsa512Verify(Array(897).fill(0) as never, MSG, new Uint8Array(666))).toBe(false);
    expect(P.fnDsa512Verify(new Uint8Array(897), MSG, Array(666).fill(0) as never)).toBe(false);
    expect(P.fnDsa1024Verify(new Uint8Array(897), MSG, new Uint8Array(1280))).toBe(false); // 512-sized key under the 1024 verifier
    expect(P.fnDsa1024Verify(new Uint8Array(1793), MSG, new Uint8Array(666))).toBe(false);
    expect(P.fnDsa1024Verify(new Uint8Array(1792), MSG, new Uint8Array(1280))).toBe(false);
    expect(P.fnDsa1024Verify(new Uint8Array(1794), MSG, new Uint8Array(1280))).toBe(false);
    expect(P.fnDsa1024Verify(new Uint8Array(1793), MSG, new Uint8Array(1279))).toBe(false);
    expect(P.fnDsa1024Verify(new Uint8Array(1793), MSG, new Uint8Array(1281))).toBe(false);
    expect(log).toEqual([]);
    const throwing = { ...fnBinding(), verify: () => { throw new Error('wasm trap'); } };
    const P2 = await freshPq(() => throwing);
    expect(P2.fnDsa512Verify(new Uint8Array(897), MSG, new Uint8Array(666))).toBe(false);
  });
  it('the b64u verifiers decode strictly with the exact lengths, then delegate', async () => {
    const log: unknown[][] = [];
    const P = await freshPq(() => fnBinding(log));
    const pk = b64u(new Uint8Array(897).fill(3));
    const sg = b64u(new Uint8Array(666).fill(4));
    expect(P.fnDsa512VerifyB64u(pk, MSG, sg)).toBe(true);
    expect(P.fnDsa512VerifyB64u(pk, MSG, b64u(new Uint8Array(665)))).toBe(false);
    expect(P.fnDsa512VerifyB64u(b64u(new Uint8Array(896)), MSG, sg)).toBe(false);
    expect(P.fnDsa512VerifyB64u(pk, MSG, '!')).toBe(false);
    expect(P.fnDsa512VerifyB64u(undefined, MSG, sg)).toBe(false);
    expect(log.length).toBe(1);
    const pk10 = b64u(new Uint8Array(1793).fill(3));
    const sg10 = b64u(new Uint8Array(1280).fill(4));
    expect(P.fnDsa1024VerifyB64u(pk10, MSG, sg10)).toBe(true);
    expect(P.fnDsa1024VerifyB64u(pk10, MSG, sg)).toBe(false);
    expect(P.fnDsa1024VerifyB64u(pk, MSG, sg10)).toBe(false);
    expect(P.fnDsa1024VerifyB64u(pk10, MSG, undefined)).toBe(false);
    expect(log.length).toBe(2);
  });
  it('keygen / sign forward the variant and arguments and return the binding result as is', async () => {
    const log: unknown[][] = [];
    const P = await freshPq(() => fnBinding(log));
    const seed = new Uint8Array(32).fill(5);
    const sk = new Uint8Array([1]);
    const r5 = P.fnDsa512Keygen(seed);
    const r10 = P.fnDsa1024Keygen(seed);
    expect(Array.from(r5.verifyingKey)).toEqual([7]);
    expect(Array.from(r10.signingKey)).toEqual([8]);
    expect(Array.from(P.fnDsa512Sign(sk, MSG, seed))).toEqual([9, 9]);
    expect(Array.from(P.fnDsa1024Sign(sk, MSG, seed))).toEqual([9, 9]);
    expect(log).toEqual([
      ['keygen', 'fn-dsa-512', seed],
      ['keygen', 'fn-dsa-1024', seed],
      ['sign', 'fn-dsa-512', sk, MSG, seed],
      ['sign', 'fn-dsa-1024', sk, MSG, seed],
    ]);
  });
});

// ---- LESS backend --------------------------------------------------------------------------------
function lessBinding(over: Record<string, unknown> = {}, log: unknown[][] = []) {
  return {
    keygen: () => (log.push(['keygen']), { publicKey: new Uint8Array(97484), secretKey: new Uint8Array(32) }),
    seedWith: (s: unknown) => void log.push(['seedWith', s]),
    signDetached: (...a: unknown[]) => (log.push(['signDetached', ...a]), new Uint8Array(1329)),
    verify: (...a: unknown[]) => (log.push(['verify', ...a]), true),
    ...over,
  };
}
const PK = new Uint8Array(97484);
const sigN = (n: number): Uint8Array => new Uint8Array(n);

describe('LESS backend probing and reasons', () => {
  it('override loader: a usable binding is probed once with (zero pk, empty msg, min-length sig) and cached', async () => {
    const P = await import('./pq');
    const log: unknown[][] = [];
    let loads = 0;
    P.setLessBackendLoaderForTests(() => (loads++, lessBinding({}, log)));
    expect(P.isLessBackendActive()).toBe(true);
    expect(P.lessBackendStatus()).toStrictEqual({ available: true });
    expect(P.isLessBackendActive()).toBe(true);
    expect(loads).toBe(1);
    expect(log.length).toBe(1);
    const [name, pk, msg, sig] = log[0] as [string, Uint8Array, Uint8Array, Uint8Array];
    expect(name).toBe('verify');
    expect([pk.length, msg.length, sig.length]).toEqual([97484, 0, 1153]);
    expect(Array.from(pk).every((x) => x === 0)).toBe(true);
    P.setLessBackendLoaderForTests(undefined);
  });
  it('re-installing a loader clears the cached probe (state is reset, not stale)', async () => {
    const P = await import('./pq');
    P.setLessBackendLoaderForTests(() => lessBinding());
    expect(P.isLessBackendActive()).toBe(true);
    P.setLessBackendLoaderForTests(() => null);
    expect(P.isLessBackendActive()).toBe(false);
    expect(P.lessBackendStatus()).toStrictEqual({ available: false, reason: 'LESS backend loader returned an unusable module' });
    P.setLessBackendLoaderForTests(() => lessBinding());
    expect(P.lessBackendStatus()).toStrictEqual({ available: true });
    P.setLessBackendLoaderForTests(undefined);
  });
  it('override loader returning an unusable module => exact reason', async () => {
    const P = await import('./pq');
    for (const bad of [null, undefined, 'x', 5, {}, { keygen() {}, seedWith() {}, signDetached() {} }, { keygen() {}, seedWith() {}, verify() {} }, { keygen() {}, signDetached() {}, verify() {} }, { seedWith() {}, signDetached() {}, verify() {} }, Object.assign(() => 0, lessBinding())]) {
      P.setLessBackendLoaderForTests(() => bad);
      expect(P.lessBackendStatus(), String(bad)).toStrictEqual({ available: false, reason: 'LESS backend loader returned an unusable module' });
    }
    P.setLessBackendLoaderForTests(undefined);
  });
  it('override loader that throws => `LESS backend failed to load: <message>` (truncated to 160 chars)', async () => {
    const P = await import('./pq');
    P.setLessBackendLoaderForTests(() => {
      throw new Error('boom');
    });
    expect(P.lessBackendStatus()).toStrictEqual({ available: false, reason: 'LESS backend failed to load: boom' });
    const long = 'x'.repeat(300);
    P.setLessBackendLoaderForTests(() => {
      throw new Error(long);
    });
    expect(P.lessBackendStatus().reason).toBe(`LESS backend failed to load: ${'x'.repeat(160)}`);
    P.setLessBackendLoaderForTests(() => {
      throw undefined;
    });
    expect(P.lessBackendStatus().reason).toBe('LESS backend failed to load: undefined');
    P.setLessBackendLoaderForTests(undefined);
  });
  it('a binding whose wasm cannot instantiate (probe throws) => exact reason, inactive', async () => {
    const P = await import('./pq');
    P.setLessBackendLoaderForTests(() => lessBinding({ verify: () => { throw new Error('no wasm'); } }));
    expect(P.isLessBackendActive()).toBe(false);
    expect(P.lessBackendStatus()).toStrictEqual({ available: false, reason: 'LESS wasm could not be instantiated: no wasm' });
    P.setLessBackendLoaderForTests(() => lessBinding({ verify: () => { throw new Error('y'.repeat(400)); } }));
    expect(P.lessBackendStatus().reason).toBe(`LESS wasm could not be instantiated: ${'y'.repeat(160)}`);
    P.setLessBackendLoaderForTests(undefined);
  });
  it('a probe returning false/garbage is NOT an instantiation failure (only a throw is)', async () => {
    const P = await import('./pq');
    P.setLessBackendLoaderForTests(() => lessBinding({ verify: () => false }));
    expect(P.lessBackendStatus()).toStrictEqual({ available: true });
    P.setLessBackendLoaderForTests(undefined);
  });
  it('real-path resolution: not installed => default reason; candidates in order (package, sibling dist)', async () => {
    const specs: string[] = [];
    const P = await freshPq((s) => (specs.push(s), notFound(s)));
    expect(P.lessBackendStatus()).toStrictEqual({ available: false, reason: 'optional package @atlasauth/pca-less-wasm is not installed' });
    expect(specs.length).toBe(2);
    expect(specs[0]).toBe(LESS_SPEC);
    expect(resolve(specs[1]!)).toBe(resolve(dirname(__filename), '..', '..', 'pca-less-wasm', 'dist', 'index.js'));
  });
  it('real-path resolution: a non-"Cannot find module" error becomes the reason; "Cannot find module" does not overwrite it', async () => {
    const P = await freshPq((s) => {
      if (s === LESS_SPEC) throw new Error('syntax error in wasm glue');
      return notFound(s);
    });
    expect(P.lessBackendStatus()).toStrictEqual({ available: false, reason: '@atlasauth/pca-less-wasm failed to load: syntax error in wasm glue' });
    const P2 = await freshPq((s) => {
      if (s === LESS_SPEC) throw new Error('z'.repeat(300));
      return notFound(s);
    });
    expect(P2.lessBackendStatus().reason).toBe(`@atlasauth/pca-less-wasm failed to load: ${'z'.repeat(160)}`);
    const P3 = await freshPq((s) => {
      if (s === LESS_SPEC) return notFound(s);
      throw new Error('late failure');
    });
    expect(P3.lessBackendStatus().reason).toBe('@atlasauth/pca-less-wasm failed to load: late failure');
    const P4 = await freshPq(() => {
      throw undefined;
    });
    expect(P4.lessBackendStatus().reason).toBe('@atlasauth/pca-less-wasm failed to load: undefined');
  });
  it('real-path resolution: a module without the API => "loaded but does not expose" reason (sticky over a later not-found)', async () => {
    const P = await freshPq((s) => (s === LESS_SPEC ? { keygen() {} } : notFound(s)));
    expect(P.lessBackendStatus()).toStrictEqual({ available: false, reason: '@atlasauth/pca-less-wasm loaded but does not expose the expected API' });
  });
  it('real-path resolution: first usable candidate wins and the second is not touched; a later one rescues an earlier failure', async () => {
    const specs: string[] = [];
    const P = await freshPq((s) => (specs.push(s), lessBinding()));
    expect(P.isLessBackendActive()).toBe(true);
    expect(P.lessBackendStatus()).toStrictEqual({ available: true });
    expect(specs).toEqual([LESS_SPEC]);
    const P2 = await freshPq((s) => (s === LESS_SPEC ? notFound(s) : lessBinding()));
    expect(P2.lessBackendStatus()).toStrictEqual({ available: true });
    const P3 = await freshPq((s) => (s === LESS_SPEC ? { nope: 1 } : lessBinding()));
    expect(P3.lessBackendStatus()).toStrictEqual({ available: true });
  });
  it('real-path resolution: createRequire itself failing => `LESS backend failed to load: <msg>`', async () => {
    const P = await freshPq('throws');
    expect(P.lessBackendStatus()).toStrictEqual({ available: false, reason: 'LESS backend failed to load: createRequire exploded' });
  });
  it('real-path resolution is not used while a loader override is installed', async () => {
    const created = { count: 0 };
    const P = await freshPq(() => notFound('x'), created);
    P.setLessBackendLoaderForTests(() => lessBinding());
    expect(P.isLessBackendActive()).toBe(true);
    expect(created.count).toBe(0);
  });
});

describe('LESS wrappers', () => {
  it('keygen: validates the seed first (RangeError, exact message), then seeds then generates', async () => {
    const P = await import('./pq');
    const log: unknown[][] = [];
    P.setLessBackendLoaderForTests(() => lessBinding({}, log));
    P.isLessBackendActive();
    log.length = 0;
    for (const bad of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0), 'x' as never, null as never, Array(32).fill(0) as never]) {
      const e = thrown(() => P.lessCat1Keygen(bad));
      expect(e).toBeInstanceOf(RangeError);
      expect(e.message).toBe('lessCat1Keygen: seed must be 32 bytes');
    }
    expect(log).toEqual([]);
    const seed = new Uint8Array(32).fill(3);
    const r = P.lessCat1Keygen(seed);
    expect(log).toEqual([['seedWith', seed], ['keygen']]);
    expect(r.publicKey.length).toBe(97484);
    expect(r.secretKey.length).toBe(32);
    P.setLessBackendLoaderForTests(undefined);
  });
  it('sign: validates the seed first (RangeError, exact message), then seeds then signs', async () => {
    const P = await import('./pq');
    const log: unknown[][] = [];
    P.setLessBackendLoaderForTests(() => lessBinding({}, log));
    P.isLessBackendActive();
    log.length = 0;
    const sk = new Uint8Array(32).fill(1);
    for (const bad of [new Uint8Array(31), new Uint8Array(33), 'x' as never, undefined as never]) {
      const e = thrown(() => P.lessCat1Sign(sk, MSG, bad));
      expect(e).toBeInstanceOf(RangeError);
      expect(e.message).toBe('lessCat1Sign: seed must be 32 bytes');
    }
    expect(log).toEqual([]);
    const seed = new Uint8Array(32).fill(4);
    const s = P.lessCat1Sign(sk, MSG, seed);
    expect(log).toEqual([['seedWith', seed], ['signDetached', sk, MSG]]);
    expect(s.length).toBe(1329);
    P.setLessBackendLoaderForTests(undefined);
  });
  it('unavailable backend: keygen / sign throw `<op>: LESS suites are unsupported — <reason>`; bad seed still wins', async () => {
    const P = await import('./pq');
    P.setLessBackendLoaderForTests(() => null);
    const seed = new Uint8Array(32);
    expect(thrown(() => P.lessCat1Keygen(seed)).message).toBe('lessCat1Keygen: LESS suites are unsupported — LESS backend loader returned an unusable module');
    expect(thrown(() => P.lessCat1Sign(seed, MSG, seed)).message).toBe('lessCat1Sign: LESS suites are unsupported — LESS backend loader returned an unusable module');
    expect(thrown(() => P.lessCat1Keygen(new Uint8Array(1))).message).toBe('lessCat1Keygen: seed must be 32 bytes');
    P.setLessBackendLoaderForTests(undefined);
  });
  it('verify: forwards (pk, msg, sig); only literal true accepts; lengths gate BEFORE the binding', async () => {
    const P = await import('./pq');
    for (const [ret, want] of [[true, true], [1, false], ['yes', false], [undefined, false], [false, false]] as const) {
      const log: unknown[][] = [];
      P.setLessBackendLoaderForTests(() => lessBinding({ verify: (...a: unknown[]) => (log.push(['verify', ...a]), ret) }));
      expect(P.lessCat1Verify(PK, MSG, sigN(1329)), String(ret)).toBe(want);
      expect(log.length, String(ret)).toBe(2); // probe + the real call
      expect(log[1]![1]).toBe(PK);
      expect(log[1]![2]).toBe(MSG);
      expect((log[1]![3] as Uint8Array).length).toBe(1329);
    }
    const log: unknown[][] = [];
    P.setLessBackendLoaderForTests(() => lessBinding({}, log));
    P.isLessBackendActive();
    log.length = 0;
    // valid grid lengths: 1153 + 16k
    for (const n of [1153, 1169, 1217, 1313, 1329]) expect(P.lessCat1Verify(PK, MSG, sigN(n)), String(n)).toBe(true);
    expect(log.length).toBe(5);
    log.length = 0;
    for (const n of [0, 1, 1137, 1152, 1154, 1168, 1328, 1330, 1345, 1361, 2000]) expect(P.lessCat1Verify(PK, MSG, sigN(n)), String(n)).toBe(false);
    expect(P.lessCat1Verify(new Uint8Array(97483), MSG, sigN(1329))).toBe(false);
    expect(P.lessCat1Verify(new Uint8Array(97485), MSG, sigN(1329))).toBe(false);
    expect(P.lessCat1Verify(Array(97484).fill(0) as never, MSG, sigN(1329))).toBe(false);
    expect(P.lessCat1Verify(PK, MSG, Array(1329).fill(0) as never)).toBe(false);
    expect(log).toEqual([]);
    P.setLessBackendLoaderForTests(undefined);
  });
  it('verify: unavailable backend => false; throwing binding => false', async () => {
    const P = await import('./pq');
    P.setLessBackendLoaderForTests(() => null);
    expect(P.lessCat1Verify(PK, MSG, sigN(1329))).toBe(false);
    P.setLessBackendLoaderForTests(undefined);
    let calls = 0;
    P.setLessBackendLoaderForTests(() => lessBinding({ verify: () => { if (calls++ > 0) throw new Error('trap'); return true; } }));
    expect(P.lessCat1Verify(PK, MSG, sigN(1329))).toBe(false);
    P.setLessBackendLoaderForTests(undefined);
  });
  it('b64u verify: sig length checked on the decoded bytes against the LESS grid; both halves validated', async () => {
    const P = await import('./pq');
    const log: unknown[][] = [];
    P.setLessBackendLoaderForTests(() => lessBinding({}, log));
    P.isLessBackendActive();
    log.length = 0;
    const pk = b64u(PK);
    for (const n of [1153, 1169, 1329]) expect(P.lessCat1VerifyB64u(pk, MSG, b64u(sigN(n))), String(n)).toBe(true);
    expect(log.length).toBe(3);
    log.length = 0;
    for (const n of [1152, 1154, 1330, 1345, 0, 1137]) expect(P.lessCat1VerifyB64u(pk, MSG, b64u(sigN(n))), String(n)).toBe(false);
    expect(P.lessCat1VerifyB64u(b64u(new Uint8Array(97483)), MSG, b64u(sigN(1329)))).toBe(false);
    expect(P.lessCat1VerifyB64u(pk, MSG, '!')).toBe(false);
    expect(P.lessCat1VerifyB64u(pk, MSG, undefined)).toBe(false);
    expect(P.lessCat1VerifyB64u(pk, MSG, '')).toBe(false);
    expect(P.lessCat1VerifyB64u(undefined, MSG, b64u(sigN(1329)))).toBe(false);
    expect(P.lessCat1VerifyB64u('', MSG, b64u(sigN(1329)))).toBe(false);
    expect(P.lessCat1VerifyB64u(pk, MSG, b64u(sigN(1329)) + '=')).toBe(false);
    expect(log).toEqual([]);
    P.setLessBackendLoaderForTests(undefined);
  });
});

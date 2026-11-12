/** Drives the portable loader and the C-ABI wrappers against a scripted stand-in for the wasm instance. */
import { afterEach, describe, expect, it, vi } from 'vitest';

const MEM = 400_000;
const SEED = 16;
const PK = 8;
const SK = 4;
const SIG_MAX = 2 * 32 + 34 * 32 + 11 * SEED + 1; // 1329

interface OpenStep {
  rc: number;
  msg?: Uint8Array;
}
interface Opts {
  bigSizes?: boolean;
  signatureMax?: number;
  autoseedRc?: number;
  keypairRc?: number;
  signRc?: number;
  /** malloc call indexes (0-based, counted per fake) that return 0 */
  mallocFail?: number[];
  initialize?: boolean;
  streaming?: boolean;
  openScript?: OpenStep[];
  instantiateReturnsInstance?: boolean;
}

function makeFake(o: Opts = {}) {
  const buffer = new ArrayBuffer(MEM);
  const u8 = new Uint8Array(buffer);
  const dv = new DataView(buffer);
  const st = {
    mallocs: [] as { n: number; ptr: number }[],
    frees: [] as number[],
    mallocCalls: 0,
    next: 1024,
    autoseed: 0,
    initialize: 0,
    sizeCalls: 0,
    seeded: [] as { len: number; bytes: number[] }[],
    signs: [] as { smlenPtr: number; mlen: unknown; sk: number[]; msg: number[]; ptrs: number[] }[],
    opens: [] as { smlen: unknown; bytes: number[]; zeroTail: boolean; markAfter: boolean; ptrs: number[] }[],
    imports: undefined as undefined | Record<string, Record<string, (...a: number[]) => number>>,
    earlyRandom: -1,
    instantiated: [] as unknown[],
    streamed: 0,
    script: [...(o.openScript ?? [])],
  };
  const big = (n: number): number | bigint => (o.bigSizes === false ? n : BigInt(n));
  const exports: Record<string, unknown> = {
    memory: { buffer },
    malloc(n: number): number {
      const i = st.mallocCalls++;
      if (o.mallocFail?.includes(i)) return 0;
      const ptr = st.next;
      st.next += Math.max(8, Math.ceil(Math.max(n, 1) / 8) * 8);
      st.mallocs.push({ n, ptr });
      return ptr;
    },
    free(p: number) {
      st.frees.push(p);
    },
    less_public_key_bytes: () => (st.sizeCalls++, big(PK)),
    less_secret_key_bytes: () => big(SK),
    less_signature_max_bytes: () => big(o.signatureMax ?? SIG_MAX),
    less_seed_bytes: () => big(SEED),
    less_autoseed: () => (st.autoseed++, o.autoseedRc ?? 0),
    less_seed(p: number, len: number) {
      st.seeded.push({ len, bytes: [...u8.slice(p, p + len)] });
    },
    less_keypair(pk: number, sk: number) {
      u8.fill(0x11, pk, pk + PK);
      u8.fill(0x22, sk, sk + SK);
      return o.keypairRc ?? 0;
    },
    less_sign(sm: number, smlenPtr: number, m: number, mlen: unknown, sk: number) {
      const n = Number(mlen);
      st.signs.push({ smlenPtr, mlen, sk: [...u8.slice(sk, sk + SK)], msg: [...u8.slice(m, m + n)], ptrs: [sm, smlenPtr, m, sk] });
      u8.set(u8.slice(m, m + n), sm);
      u8.fill(0xee, sm + n, sm + n + 3);
      dv.setBigUint64(smlenPtr, BigInt(n + 3), true);
      return o.signRc ?? 0;
    },
    less_open(out: number, mlenPtr: number, sm: number, smlen: unknown, pk: number) {
      const n = Number(smlen);
      let zeroTail = true;
      for (let i = sm + n; i < sm + n + SIG_MAX; i++) if (u8[i] !== 0) zeroTail = false;
      st.opens.push({ smlen, bytes: [...u8.slice(sm, sm + n)], zeroTail, markAfter: u8[sm + n + SIG_MAX] === 0xaa, ptrs: [out, mlenPtr, sm, pk] });
      const step = st.script.shift() ?? { rc: 1 };
      if (step.rc === 0) {
        const msg = step.msg ?? new Uint8Array(0);
        u8.set(msg, out);
        dv.setBigUint64(mlenPtr, BigInt(msg.length), true);
      }
      return step.rc;
    },
  };
  if (o.initialize) exports._initialize = () => void st.initialize++;
  function Instance(this: unknown, _m: unknown, imports: Record<string, Record<string, (...a: number[]) => number>>) {
    st.imports = imports;
    st.earlyRandom = imports.wasi_snapshot_preview1!.random_get!(0, 8);
    return { exports };
  }
  const WA: Record<string, unknown> = {
    Module: function Module() {},
    Instance,
    async instantiate(bytes: unknown, imports: Record<string, Record<string, (...a: number[]) => number>>) {
      st.instantiated.push(bytes);
      st.imports = imports;
      const inst = { exports };
      return o.instantiateReturnsInstance ? inst : { instance: inst, module: {} };
    },
  };
  if (o.streaming) {
    WA.instantiateStreaming = async (_r: unknown, imports: Record<string, Record<string, (...a: number[]) => number>>) => {
      st.streamed++;
      st.imports = imports;
      return { instance: { exports }, module: {} };
    };
  }
  return { WA, st, u8, dv };
}

type Core = typeof import('./core');
async function load(o: Opts = {}): Promise<{ core: Core; fake: ReturnType<typeof makeFake> }> {
  vi.resetModules();
  const fake = makeFake(o);
  vi.stubGlobal('WebAssembly', fake.WA);
  const core = await import('./core');
  return { core, fake };
}
afterEach(() => vi.unstubAllGlobals());

/** An attached signed message of the pinned layout: message || (digest, salt, W rows, `leaves` seeds, count byte). */
function shaped(msgLen: number, leaves: number, patch: (sm: Uint8Array, cf: number) => void = () => {}): Uint8Array {
  const sigLen = SIG_MAX - (11 - leaves) * SEED;
  const sm = new Uint8Array(msgLen + sigLen);
  sm[sm.length - 1] = leaves;
  patch(sm, msgLen + 64);
  return sm;
}
const PKEY = new Uint8Array(PK);

describe('the WASI random_get import', () => {
  it('answers EFAULT while the instance memory is not yet known, then serves the instance memory', async () => {
    const { core, fake } = await load();
    core.initLessSync(new Uint8Array(1));
    expect(fake.st.earlyRandom).toBe(21);
    const calls: number[][] = [];
    vi.stubGlobal('crypto', { getRandomValues: (a: Uint8Array) => (calls.push([a.byteOffset, a.length]), a) });
    const rg = fake.st.imports!.wasi_snapshot_preview1!.random_get!;
    expect(rg(0, 4)).toBe(0);
    expect(calls).toEqual([[0, 4]]);
  });
  it('checks the range against the memory size at every boundary', async () => {
    const { core, fake } = await load();
    core.initLessSync(new Uint8Array(1));
    vi.stubGlobal('crypto', { getRandomValues: (a: Uint8Array) => a });
    const rg = fake.st.imports!.wasi_snapshot_preview1!.random_get!;
    expect(rg(-1, 4)).toBe(21);
    expect(rg(0, -1)).toBe(21);
    expect(rg(MEM - 4, 4)).toBe(0);
    expect(rg(MEM - 3, 4)).toBe(21);
    expect(rg(10, MEM)).toBe(21);
    expect(rg(0, 0)).toBe(0);
    expect(rg(MEM, 0)).toBe(0);
    expect(rg(1, 0)).toBe(0);
  });
  it('fills in chunks of at most 65536 bytes at the right offsets and never calls for zero bytes', async () => {
    const { core, fake } = await load();
    core.initLessSync(new Uint8Array(1));
    const calls: number[][] = [];
    vi.stubGlobal('crypto', { getRandomValues: (a: Uint8Array) => (calls.push([a.byteOffset, a.length]), a) });
    const rg = fake.st.imports!.wasi_snapshot_preview1!.random_get!;
    expect(rg(100, 0)).toBe(0);
    expect(calls).toEqual([]);
    expect(rg(100, 131_072)).toBe(0);
    expect(calls).toEqual([[100, 65_536], [65_636, 65_536]]);
    calls.length = 0;
    expect(rg(100, 131_082)).toBe(0);
    expect(calls).toEqual([[100, 65_536], [65_636, 65_536], [131_172, 10]]);
  });
  it('fails closed (EIO) without Web Crypto, without getRandomValues, or when it throws', async () => {
    const { core, fake } = await load();
    core.initLessSync(new Uint8Array(1));
    const rg = fake.st.imports!.wasi_snapshot_preview1!.random_get!;
    vi.stubGlobal('crypto', undefined);
    expect(rg(0, 4)).toBe(29);
    vi.stubGlobal('crypto', {});
    expect(rg(0, 4)).toBe(29);
    vi.stubGlobal('crypto', { getRandomValues: () => { throw new Error('quota'); } });
    expect(rg(0, 4)).toBe(29);
  });
});

describe('loading', () => {
  it('reports initialisation and runs the reactor initialiser only when exported', async () => {
    const a = await load({ initialize: true });
    expect(a.core.isInitialized()).toBe(false);
    a.core.initLessSync(new Uint8Array(1));
    expect(a.core.isInitialized()).toBe(true);
    expect(a.fake.st.initialize).toBe(1);
    const b = await load();
    expect(() => b.core.initLessSync(new Uint8Array(1))).not.toThrow();
  });
  it('without a loader the API refuses with the exact instruction; a failing loader names the package', async () => {
    const { core } = await load();
    const msg = 'LESS wasm is not initialised. In browsers/workers/edge call `await initLess(urlOrBytes)` (or import "@atlasauth/pca-less-wasm/embedded" and call `await initLessEmbedded()`) before using the API.';
    expect(() => core.sizes()).toThrow(msg);
    try {
      core.sizes();
    } catch (e) {
      expect(e).toBeInstanceOf(core.LessError);
      expect((e as Error).name).toBe('LessError');
    }
    core.setSyncWasmLoader(() => { throw new Error('enoent'); });
    expect(() => core.sizes()).toThrow('LESS wasm could not be read from the package. Reinstall @atlasauth/pca-less-wasm, or call initLess(bytes|url).');
  });
  it('a working loader initialises on first use', async () => {
    const { core, fake } = await load();
    core.setSyncWasmLoader(() => new Uint8Array(3));
    expect(core.sizes()).toEqual({ publicKey: PK, secretKey: SK, signatureMax: SIG_MAX, seed: SEED });
    expect(core.isInitialized()).toBe(true);
    expect(fake.st.sizeCalls).toBe(1);
  });
  it('sizes() are numbers even when the wasm returns i64, and are read once', async () => {
    const { core, fake } = await load({ bigSizes: true });
    core.initLessSync(new Uint8Array(1));
    const s = core.sizes();
    expect(typeof s.publicKey).toBe('number');
    expect(s).toEqual({ publicKey: PK, secretKey: SK, signatureMax: SIG_MAX, seed: SEED });
    core.sizes();
    expect(fake.st.sizeCalls).toBe(1);
    const n = await load({ bigSizes: false });
    n.core.initLessSync(new Uint8Array(1));
    expect(n.core.sizes().publicKey).toBe(PK);
  });

  const okResp = (headers: Record<string, string>, bytes = new Uint8Array([1, 2, 3])) =>
    ({ ok: true, status: 200, headers: { get: (k: string) => headers[k] ?? null }, arrayBuffer: async () => bytes.buffer }) as unknown as Response;

  it('initLess from bytes, an ArrayBuffer, a promised response; the instantiate result may be an instance or a pair', async () => {
    for (const ret of [false, true]) {
      const { core, fake } = await load({ instantiateReturnsInstance: ret });
      await core.initLess(new Uint8Array([9]));
      expect(core.isInitialized()).toBe(true);
      expect(fake.st.instantiated).toEqual([new Uint8Array([9])]);
      await core.initLess(new Uint8Array([7]).buffer);
      expect(fake.st.instantiated[1]).toEqual(new Uint8Array([7]));
      await core.initLess(Promise.resolve(okResp({})));
      expect(fake.st.instantiated[2]).toEqual(new Uint8Array([1, 2, 3]));
      expect(fake.st.imports!.wasi_snapshot_preview1!.random_get!(0, 0)).toBe(0);
    }
  });
  it('initLess fetches a URL or string, and refuses without fetch or on a bad status, with exact messages', async () => {
    const { core, fake } = await load();
    const seen: unknown[] = [];
    vi.stubGlobal('fetch', async (u: unknown) => (seen.push(u), okResp({})));
    await core.initLess('https://x.example/less.wasm');
    await core.initLess(new URL('https://y.example/less.wasm'));
    expect(seen).toEqual(['https://x.example/less.wasm', new URL('https://y.example/less.wasm')]);
    expect(fake.st.instantiated).toHaveLength(2);
    vi.stubGlobal('fetch', undefined);
    const e1 = await core.initLess('https://x.example/less.wasm').catch((e: unknown) => e);
    expect(e1).toBeInstanceOf(core.LessError);
    expect((e1 as Error).message).toBe('initLess: fetch is unavailable; pass the wasm bytes instead');
    vi.stubGlobal('fetch', async () => ({ ok: false, status: 404, headers: { get: () => null } }));
    const e2 = await core.initLess('https://x.example/less.wasm').catch((e: unknown) => e);
    expect(e2).toBeInstanceOf(core.LessError);
    expect((e2 as Error).message).toBe('initLess: fetching wasm failed (HTTP 404)');
  });
  it('streams only application/wasm responses when instantiateStreaming exists', async () => {
    const s = await load({ streaming: true });
    await s.core.initLess(okResp({ 'content-type': 'application/wasm' }));
    await s.core.initLess(okResp({ 'content-type': 'application/wasm; charset=binary' }));
    expect(s.fake.st.streamed).toBe(2);
    expect(s.fake.st.instantiated).toHaveLength(0);
    await s.core.initLess(okResp({ 'content-type': 'x-application/wasm' }));
    await s.core.initLess(okResp({ 'content-type': 'application/octet-stream' }));
    await s.core.initLess(okResp({}));
    expect(s.fake.st.streamed).toBe(2);
    expect(s.fake.st.instantiated).toHaveLength(3);
    const n = await load();
    await n.core.initLess(okResp({ 'content-type': 'application/wasm' }));
    expect(n.fake.st.instantiated).toHaveLength(1);
  });
});

describe('seeding', () => {
  it('seedFromEntropy seeds once; a refusing getentropy is an error', async () => {
    const { core, fake } = await load();
    core.initLessSync(new Uint8Array(1));
    core.seedFromEntropy();
    core.keygen();
    expect(fake.st.autoseed).toBe(1);
    const bad = await load({ autoseedRc: -1 });
    bad.core.initLessSync(new Uint8Array(1));
    expect(() => bad.core.seedFromEntropy()).toThrow('less_autoseed: WASI getentropy failed');
    expect(() => bad.core.keygen()).toThrow('less_autoseed: WASI getentropy failed');
    expect(() => bad.core.sign(new Uint8Array(SK), new Uint8Array(1))).toThrow('less_autoseed: WASI getentropy failed');
  });
  it('seedWith copies the seed in, frees its buffer and counts as seeded; a failed malloc is an error', async () => {
    const { core, fake } = await load();
    core.initLessSync(new Uint8Array(1));
    core.seedWith(new Uint8Array([5, 6, 7]));
    expect(fake.st.seeded).toEqual([{ len: 3, bytes: [5, 6, 7] }]);
    expect(fake.st.frees).toEqual([fake.st.mallocs[0]!.ptr]);
    core.keygen();
    expect(fake.st.autoseed).toBe(0);
    const bad = await load({ mallocFail: [0] });
    bad.core.initLessSync(new Uint8Array(1));
    expect(() => bad.core.seedWith(new Uint8Array(3))).toThrow('seedWith: wasm malloc failed');
    expect(bad.fake.st.seeded).toEqual([]);
  });
  it('sign auto-seeds on first use', async () => {
    const { core, fake } = await load();
    core.initLessSync(new Uint8Array(1));
    core.sign(new Uint8Array(SK), new Uint8Array(2));
    core.sign(new Uint8Array(SK), new Uint8Array(2));
    expect(fake.st.autoseed).toBe(1);
  });
});

describe('keygen', () => {
  it('returns the written key bytes and frees both buffers', async () => {
    const { core, fake } = await load();
    core.initLessSync(new Uint8Array(1));
    const k = core.keygen();
    expect(k.publicKey).toEqual(new Uint8Array(PK).fill(0x11));
    expect(k.secretKey).toEqual(new Uint8Array(SK).fill(0x22));
    expect(fake.st.mallocs.map((m) => m.n)).toEqual([PK, SK]);
    expect(fake.st.frees).toEqual(fake.st.mallocs.map((m) => m.ptr));
  });
  it('refuses when either allocation fails, with the exact message', async () => {
    for (const idx of [0, 1]) {
      const { core } = await load({ mallocFail: [idx] });
      core.initLessSync(new Uint8Array(1));
      expect(() => core.keygen()).toThrow('keygen: wasm malloc failed');
    }
  });
  it('a failing keypair is an error and still frees both buffers', async () => {
    const { core, fake } = await load({ keypairRc: 3 });
    core.initLessSync(new Uint8Array(1));
    expect(() => core.keygen()).toThrow('keygen: wasm keypair failed');
    expect(fake.st.frees).toEqual(fake.st.mallocs.map((m) => m.ptr));
  });
});

describe('sign', () => {
  it('checks the secret-key length with the exact message', async () => {
    const { core } = await load();
    core.initLessSync(new Uint8Array(1));
    expect(() => core.sign(new Uint8Array(3), new Uint8Array(1))).toThrow('sign: secretKey must be 4 bytes, got 3');
  });
  it('hands the key and message to the wasm, returns the written signed message and frees four buffers', async () => {
    const { core, fake } = await load();
    core.initLessSync(new Uint8Array(1));
    const out = core.sign(new Uint8Array([1, 2, 3, 4]), new Uint8Array([9, 8]));
    expect(out).toEqual(new Uint8Array([9, 8, 0xee, 0xee, 0xee]));
    expect(fake.st.mallocs.map((m) => m.n)).toEqual([SK, 2, 2 + SIG_MAX, 8]);
    const call = fake.st.signs[0]!;
    expect(call.sk).toEqual([1, 2, 3, 4]);
    expect(call.msg).toEqual([9, 8]);
    expect(call.mlen).toBe(2n);
    expect(fake.st.frees).toEqual(fake.st.mallocs.map((m) => m.ptr));
    core.sign(new Uint8Array(SK), new Uint8Array(0));
    expect(fake.st.mallocs.slice(4).map((m) => m.n)).toEqual([SK, 1, SIG_MAX, 8]);
  });
  it('refuses when any one of the four allocations fails', async () => {
    for (const idx of [0, 1, 2, 3]) {
      const { core } = await load({ mallocFail: [idx] });
      core.initLessSync(new Uint8Array(1));
      expect(() => core.sign(new Uint8Array(SK), new Uint8Array(2))).toThrow('sign: wasm malloc failed');
    }
  });
  it('a failing sign is an error and still frees all four buffers', async () => {
    const { core, fake } = await load({ signRc: 2 });
    core.initLessSync(new Uint8Array(1));
    expect(() => core.sign(new Uint8Array(SK), new Uint8Array(2))).toThrow('sign: wasm sign failed');
    expect(fake.st.frees).toEqual(fake.st.mallocs.map((m) => m.ptr));
    expect(fake.st.frees).toHaveLength(4);
  });
  it('signDetached strips the message prefix', async () => {
    const { core } = await load();
    core.initLessSync(new Uint8Array(1));
    expect(core.signDetached(new Uint8Array(SK), new Uint8Array([9, 8]))).toEqual(new Uint8Array([0xee, 0xee, 0xee]));
  });
});

describe('open: the layout and shape guards run before the wasm sees the input', () => {
  const rejected = { ok: false, message: new Uint8Array(0) };
  const run = async (sm: Uint8Array, script: OpenStep[] = []) => {
    const { core, fake } = await load({ openScript: script });
    core.initLessSync(new Uint8Array(1));
    const r = core.open(PKEY, sm);
    return { r, fake };
  };
  it('a wasm whose parameter set differs from the pinned layout fails loudly', async () => {
    const { core } = await load({ signatureMax: SIG_MAX + 1 });
    core.initLessSync(new Uint8Array(1));
    expect(() => core.open(PKEY, shaped(0, 0))).toThrow('wasm parameter set does not match the pinned less-252-45 layout');
  });
  it('refuses a wrong-sized public key with the exact message', async () => {
    const { core } = await load();
    core.initLessSync(new Uint8Array(1));
    expect(() => core.open(new Uint8Array(3), shaped(0, 0))).toThrow('open: publicKey must be 8 bytes, got 3');
  });
  it('empty input, a seed count above 11, and a message shorter than its own signature never reach the wasm', async () => {
    for (const sm of [new Uint8Array(0), new Uint8Array(1345).fill(0).map((_, i) => (i === 1344 ? 12 : 0)), new Uint8Array(1500).fill(0).map((_, i) => (i === 1499 ? 255 : 0)), shaped(0, 1).slice(1)]) {
      const { r, fake } = await run(sm);
      expect(r).toEqual(rejected);
      expect(fake.st.opens).toHaveLength(0);
    }
  });
  it('accepts the boundary shapes: count 11 at its exact length, count 1 at its exact length', async () => {
    for (const leaves of [0, 1, 11]) {
      const { fake } = await run(shaped(0, leaves));
      expect(fake.st.opens.length).toBeGreaterThanOrEqual(1);
    }
  });
  it('rejects a set padding bit in any signed row, at any message offset, but only in the high nibble', async () => {
    for (const w of [0, 1, 33]) {
      for (const bit of [0x10, 0x20, 0x40, 0x80]) {
        const { r, fake } = await run(shaped(40, 3, (sm, cf) => { sm[cf + w * 32 + 31] = bit; }));
        expect(r).toEqual(rejected);
        expect(fake.st.opens).toHaveLength(0);
      }
    }
    const lowOnly = await run(shaped(40, 3, (sm, cf) => { for (let w = 0; w < 34; w++) sm[cf + w * 32 + 31] = 0x0f; }));
    expect(lowOnly.fake.st.opens.length).toBeGreaterThanOrEqual(1);
    // the byte right after the last row belongs to the seeds and is not padding
    const afterRows = await run(shaped(40, 3, (sm, cf) => { sm[cf + 34 * 32 + 31] = 0xff; }));
    expect(afterRows.fake.st.opens.length).toBeGreaterThanOrEqual(1);
  });
});

describe('open: calling the wasm', () => {
  const msg = new Uint8Array([7, 7, 7]);
  it('allocates, zero-fills the over-read slack, calls less_open, reads the message back and frees in order', async () => {
    const { core, fake } = await load({ openScript: [{ rc: 0, msg }] });
    core.initLessSync(new Uint8Array(1));
    fake.u8.fill(0xaa, 1024, 60_000); // stale memory the zero-fill must overwrite
    const sm = shaped(3, 0, (b) => b.set(msg, 0));
    const r = core.open(new Uint8Array(PK).fill(5), sm);
    expect(r.ok).toBe(true);
    expect(r.message).toEqual(msg);
    expect(fake.st.mallocs.map((m) => m.n)).toEqual([PK, sm.length + SIG_MAX, sm.length, 8]);
    const call = fake.st.opens[0]!;
    expect(call.smlen).toBe(BigInt(sm.length));
    expect(call.bytes).toEqual([...sm]);
    expect(call.zeroTail).toBe(true);
    expect(call.markAfter).toBe(true);
    expect(fake.st.opens).toHaveLength(1);
    const [pPk, pSm, pOut, pMlen] = fake.st.mallocs.map((m) => m.ptr);
    expect(call.ptrs).toEqual([pOut, pMlen, pSm, pPk]);
    expect(fake.st.frees).toEqual([pPk, pSm, pOut, pMlen]);
  });
  it('a refusing wasm gives {ok:false} with an empty message and still frees', async () => {
    const { core, fake } = await load({ openScript: [{ rc: 1 }] });
    core.initLessSync(new Uint8Array(1));
    expect(core.open(PKEY, shaped(0, 0))).toEqual({ ok: false, message: new Uint8Array(0) });
    expect(fake.st.frees).toHaveLength(4);
  });
  it('refuses when any one of the four allocations fails', async () => {
    for (const idx of [0, 1, 2, 3]) {
      const { core } = await load({ mallocFail: [idx] });
      core.initLessSync(new Uint8Array(1));
      expect(() => core.open(PKEY, shaped(0, 0))).toThrow('open: wasm malloc failed');
    }
  });
  it('a signature with a seed count above zero is checked again with its last seed dropped and the count lowered', async () => {
    const sm = shaped(2, 2, (b, cf) => b.fill(0x33, cf + 34 * 32, b.length - 1));
    const canonical = await load({ openScript: [{ rc: 0, msg: new Uint8Array([1, 2]) }, { rc: 1 }] });
    canonical.core.initLessSync(new Uint8Array(1));
    expect(canonical.core.open(PKEY, sm)).toEqual({ ok: true, message: new Uint8Array([1, 2]) });
    expect(canonical.fake.st.opens).toHaveLength(2);
    const second = canonical.fake.st.opens[1]!;
    expect(second.smlen).toBe(BigInt(sm.length - SEED));
    const want = [...sm.subarray(0, sm.length - 1 - SEED), 1];
    expect(second.bytes).toEqual(want);
    const malleated = await load({ openScript: [{ rc: 0, msg: new Uint8Array([1, 2]) }, { rc: 0 }] });
    malleated.core.initLessSync(new Uint8Array(1));
    expect(malleated.core.open(PKEY, sm)).toEqual({ ok: false, message: new Uint8Array(0) });
  });
  it('a signature with a zero seed count is opened exactly once', async () => {
    const { core, fake } = await load({ openScript: [{ rc: 0, msg: new Uint8Array(0) }, { rc: 0 }] });
    core.initLessSync(new Uint8Array(1));
    expect(core.open(PKEY, shaped(0, 0)).ok).toBe(true);
    expect(fake.st.opens).toHaveLength(1);
  });
  it('a failed first open returns without the canonical re-check', async () => {
    const { core, fake } = await load({ openScript: [{ rc: 1 }, { rc: 0 }] });
    core.initLessSync(new Uint8Array(1));
    expect(core.open(PKEY, shaped(0, 3)).ok).toBe(false);
    expect(fake.st.opens).toHaveLength(1);
  });
});

describe('verify (detached)', () => {
  const sig = shaped(0, 0);
  const run = async (m: Uint8Array, returned: Uint8Array | null, pk = PKEY) => {
    const { core } = await load({ openScript: returned ? [{ rc: 0, msg: returned }] : [{ rc: 1 }] });
    core.initLessSync(new Uint8Array(1));
    return core.verify(pk, m, sig);
  };
  it('true only when the opened payload equals the message byte for byte', async () => {
    const m = new Uint8Array([1, 2, 3]);
    expect(await run(m, new Uint8Array([1, 2, 3]))).toBe(true);
    expect(await run(m, new Uint8Array([1, 2, 4]))).toBe(false);
    expect(await run(m, new Uint8Array([9, 2, 3]))).toBe(false);
    expect(await run(m, new Uint8Array([1, 2, 3, 4]))).toBe(false);
    expect(await run(m, new Uint8Array([1, 2]))).toBe(false);
    expect(await run(m, null)).toBe(false);
    expect(await run(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });
  it('a wrong-sized public key is a plain false, not an exception', async () => {
    expect(await run(new Uint8Array(1), new Uint8Array(1), new Uint8Array(3))).toBe(false);
  });
});

describe('embedded entry', () => {
  it('initLessEmbeddedSync and initLessEmbedded initialise the real wasm', async () => {
    vi.resetModules();
    const core = await import('./core');
    const emb = await import('./embedded');
    expect(core.isInitialized()).toBe(false);
    emb.initLessEmbeddedSync();
    expect(core.isInitialized()).toBe(true);
    vi.resetModules();
    const core2 = await import('./core');
    const emb2 = await import('./embedded');
    await emb2.initLessEmbedded();
    expect(core2.isInitialized()).toBe(true);
    expect(emb2.embeddedWasmBytes()).toHaveLength(Buffer.from(emb2.WASM_BASE64, 'base64').length);
  });
});

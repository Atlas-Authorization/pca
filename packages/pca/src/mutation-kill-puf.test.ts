/**
 * Mutation-kill suite for attest-puf.ts. Independent reference implementations (HKDF, counter-mode PRG, repetition
 * code) are re-derived here so every field, boundary, error string and ordering of checks is pinned to the spec.
 */
import { describe, expect, it } from 'vitest';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { b64u, canonicalBytes, hashCanonical, unb64u, utf8 } from './hash';
import {
  PUF_ATTEST_DOMAIN,
  PUF_EXTRACT_INFO,
  PUF_KEY_BYTES,
  TPM_EK_PUF_DOMAIN,
  TpmEkPufProvider,
  createPufAttestor,
  createPufEnrollmentRegistry,
  createPufVerifier,
  createSimulatedPuf,
  defaultTpmCommandRunner,
  enrollPuf,
  fuzzyEnroll,
  fuzzyReproduce,
  type FuzzyExtractorHelper,
  type PufAttestationStatement,
  type PufEnrollment,
  type TpmCommandResult,
  type TpmCommandRunner,
} from './attest-puf';
import { type ExpectedAttestationBinding, attestationBindingB64u } from './attestation';
import { encodeKey, generateKeyPair } from './keys';
import { verifyWithSuite } from './pq';

const A = generateKeyPair();
const T = 1_000_000;
const EXPECTED: ExpectedAttestationBinding = { holderPub: encodeKey(A.publicKey), grantRef: 'g-1', epoch: 3, nonce: 'n-1', nonceIssuedAt: T - 1000 };
const CLAIMS = { measurement: 'm-1', holder_pub: EXPECTED.holderPub, grant_ref: 'g-1', epoch: 3, nonce: 'n-1' };
const CH = new Uint8Array([1, 2, 3]);
const seq = (n: number, k = 7, o = 1): Uint8Array => Uint8Array.from({ length: n }, (_, i) => (i * k + o) & 0xff);

const refPrg = (secretOrSeedParts: (ctr: Uint8Array) => Uint8Array, length: number): Uint8Array => {
  const need = Math.ceil(length / 8);
  const nblocks = Math.max(1, Math.ceil(need / 32));
  const stream = new Uint8Array(nblocks * 32);
  for (let blk = 0; blk < nblocks; blk++) {
    const ctr = new Uint8Array(4);
    new DataView(ctr.buffer).setUint32(0, blk, false);
    stream.set(sha256(secretOrSeedParts(ctr)), blk * 32);
  }
  const bits = new Uint8Array(length);
  for (let i = 0; i < length; i++) bits[i] = (stream[i >> 3]! >> (i & 7)) & 1;
  return bits;
};
const cat = (...p: Uint8Array[]): Uint8Array => {
  const o = new Uint8Array(p.reduce((a, b) => a + b.length, 0));
  let k = 0;
  for (const x of p) {
    o.set(x, k);
    k += x.length;
  }
  return o;
};
const pack = (bits: Uint8Array): Uint8Array => {
  const out = new Uint8Array(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i++) if (bits[i]) out[i >> 3]! |= 1 << (i & 7);
  return out;
};

describe('puf constants', () => {
  it('exact domain strings and key size', () => {
    expect(PUF_EXTRACT_INFO).toBe('atlas-pca/puf-extract/v1');
    expect(PUF_ATTEST_DOMAIN).toBe('atlas-pca/attest-puf/v1\0');
    expect(PUF_KEY_BYTES).toBe(32);
    expect(TPM_EK_PUF_DOMAIN).toBe('atlas-pca/puf-tpm-ek/v1');
  });
});

describe('fuzzyEnroll', () => {
  const W = Uint8Array.from([1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0]); // rep 3 x 4
  it('helper fields, sketch, salt and key equal the reference construction', () => {
    const calls: number[] = [];
    const rb = (n: number) => {
      calls.push(n);
      return n === 4 ? Uint8Array.from([0xff, 0x02, 0x03, 0x00]) : seq(n, 5, 9);
    };
    const { key, helper } = fuzzyEnroll(W, { rep: 3, messageBits: 4 }, rb);
    expect(calls).toEqual([4, 32]);
    const m = [1, 0, 1, 0];
    const code = Uint8Array.from(m.flatMap((b) => [b, b, b]));
    const sketch = Uint8Array.from(code.map((c, i) => c ^ W[i]!));
    expect(helper).toEqual({ sketch: b64u(pack(sketch)), salt: b64u(seq(32, 5, 9)), rep: 3, messageBits: 4, n: 12 });
    expect(key).toEqual(hkdf(sha256, pack(W), seq(32, 5, 9), utf8('atlas-pca/puf-extract/v1'), 32));
    expect(key.length).toBe(32);
  });
  it('rep: odd positive integer only (message exact)', () => {
    const rb = (n: number) => new Uint8Array(n);
    const W3 = new Uint8Array(3);
    for (const rep of [0, -1, 2, 4, 1.5, NaN]) {
      expect(() => fuzzyEnroll(new Uint8Array(4), { rep, messageBits: 1 }, rb), String(rep)).toThrow(new RangeError('fuzzyEnroll: rep must be an odd positive integer'));
    }
    expect(() => fuzzyEnroll(new Uint8Array(1), { rep: 1, messageBits: 1 }, rb)).not.toThrow();
    expect(() => fuzzyEnroll(W3, { rep: 3, messageBits: 1 }, rb)).not.toThrow();
  });
  it('messageBits: positive integer only (message exact)', () => {
    const rb = (n: number) => new Uint8Array(n);
    for (const messageBits of [0, -1, 1.5, NaN]) {
      expect(() => fuzzyEnroll(new Uint8Array(3), { rep: 3, messageBits }, rb), String(messageBits)).toThrow(new RangeError('fuzzyEnroll: messageBits must be a positive integer'));
    }
    expect(() => fuzzyEnroll(new Uint8Array(3), { rep: 3, messageBits: 1 }, rb)).not.toThrow();
  });
  it('response length and bit-ness are checked, with exact messages', () => {
    const rb = (n: number) => new Uint8Array(n);
    expect(() => fuzzyEnroll(new Uint8Array(5), { rep: 3, messageBits: 2 }, rb)).toThrow(new RangeError('fuzzyEnroll: response length 5 != rep*messageBits 6'));
    expect(() => fuzzyEnroll(Uint8Array.from([0, 1, 0, 1, 0, 2]), { rep: 3, messageBits: 2 }, rb)).toThrow(new RangeError('fuzzyEnroll: response must be a 0/1 bit array'));
    expect(() => fuzzyEnroll(Uint8Array.from([2, 1, 0, 1, 0, 1]), { rep: 3, messageBits: 2 }, rb)).toThrow('fuzzyEnroll: response must be a 0/1 bit array');
    expect(() => fuzzyEnroll(Uint8Array.from([1, 1, 1, 1, 1, 1]), { rep: 3, messageBits: 2 }, rb)).not.toThrow();
  });
});

describe('fuzzyReproduce', () => {
  const W = Uint8Array.from([1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0]);
  const { key, helper } = fuzzyEnroll(W, { rep: 3, messageBits: 4 }, (n) => seq(n, 3, 2));
  const bad = (h: unknown, w: Uint8Array = W) => () => fuzzyReproduce(w, h as FuzzyExtractorHelper);
  it('reproduces within the bound and diverges beyond it', () => {
    expect(fuzzyReproduce(W, helper)).toEqual(key);
    const one = Uint8Array.from(W);
    one[0]! ^= 1;
    one[3]! ^= 1;
    one[6]! ^= 1;
    one[9]! ^= 1; // one flip per block
    expect(fuzzyReproduce(one, helper)).toEqual(key);
    const two = Uint8Array.from(W);
    two[0]! ^= 1;
    two[1]! ^= 1;
    expect(fuzzyReproduce(two, helper)).not.toEqual(key);
  });
  it('malformed helper params are refused with the exact message', () => {
    const msg = new RangeError('fuzzyReproduce: malformed helper params');
    expect(bad(null)).toThrow(msg);
    expect(bad(undefined)).toThrow(msg);
    expect(bad({ ...helper, rep: 1.5, n: 6 })).toThrow(msg);
    expect(bad({ ...helper, messageBits: 1.5 })).toThrow(msg);
    expect(bad({ ...helper, rep: 'x' })).toThrow(msg);
    expect(bad({ ...helper, messageBits: 'x' })).toThrow(msg);
    expect(bad({ ...helper, rep: 0, n: 0 }, new Uint8Array(0))).toThrow(msg);
    expect(bad({ ...helper, rep: -1, n: -4 }, new Uint8Array(0))).toThrow(msg);
    expect(bad({ ...helper, rep: 4, n: 16 }, new Uint8Array(16))).toThrow(msg);
    expect(bad({ ...helper, rep: 2, messageBits: 4, n: 8 }, new Uint8Array(8))).toThrow(msg);
  });
  it('rep 1 is a legal helper', () => {
    const w = Uint8Array.from([1, 0, 1]);
    const e = fuzzyEnroll(w, { rep: 1, messageBits: 3 }, (n) => seq(n));
    expect(fuzzyReproduce(w, e.helper)).toEqual(e.key);
  });
  it('n and response length consistency, exact messages; bit check labelled', () => {
    expect(bad({ ...helper, n: 11 })).toThrow(new RangeError('fuzzyReproduce: helper.n inconsistent with rep*messageBits'));
    expect(bad(helper, new Uint8Array(11))).toThrow(new RangeError('fuzzyReproduce: response length 11 != 12'));
    const w2 = Uint8Array.from(W);
    w2[11] = 2;
    expect(bad(helper, w2)).toThrow(new RangeError('fuzzyReproduce: response must be a 0/1 bit array'));
    const w3 = Uint8Array.from(W);
    w3[0] = 3;
    expect(bad(helper, w3)).toThrow('fuzzyReproduce: response must be a 0/1 bit array');
  });
});

describe('createSimulatedPuf', () => {
  it('matches the reference counter-mode PRG (multi-block) and flips exactly the listed in-range bits', () => {
    const seed = seq(32, 3, 5);
    for (const len of [28, 256, 257, 300, 520]) {
      const want = refPrg((ctr) => cat(seed, CH, ctr), len);
      expect(createSimulatedPuf({ id: 'x', seed, length: len }).response(CH)).toEqual(want);
    }
    const base = createSimulatedPuf({ id: 'x', seed, length: 40 }).response(CH);
    const fl = createSimulatedPuf({ id: 'x', seed, length: 40, flip: [0, 5, 39] }).response(CH);
    const exp = Uint8Array.from(base);
    for (const p of [0, 5, 39]) exp[p]! ^= 1;
    expect(fl).toEqual(exp);
    expect(createSimulatedPuf({ id: 'x', seed, length: 40, flip: [5, 5] }).response(CH)[5]).toBe(base[5]! ^ 1);
    expect(createSimulatedPuf({ id: 'x', seed, length: 40, flip: [-1, 40, 41] }).response(CH)).toEqual(base);
    expect(createSimulatedPuf({ id: 'q', seed, length: 40 }).id).toBe('q');
  });
});

describe('TpmEkPufProvider construction and defaults', () => {
  const ok: TpmCommandResult = { status: 0, stdout: seq(64) };
  const capture = () => {
    const seen: { c: string; a: readonly string[] }[] = [];
    const run: TpmCommandRunner = (c, a) => {
      seen.push({ c, a });
      return ok;
    };
    return { seen, run };
  };
  it('id / length / minEkBytes validation with exact messages', () => {
    expect(() => new TpmEkPufProvider(null as never)).toThrow(new TypeError('TpmEkPufProvider: id must be a non-empty string'));
    expect(() => new TpmEkPufProvider(undefined as never)).toThrow(new TypeError('TpmEkPufProvider: id must be a non-empty string'));
    expect(() => new TpmEkPufProvider({ id: 5 as never, length: 8 })).toThrow(new TypeError('TpmEkPufProvider: id must be a non-empty string'));
    expect(() => new TpmEkPufProvider({ id: '', length: 8 })).toThrow(new TypeError('TpmEkPufProvider: id must be a non-empty string'));
    const lenMsg = new RangeError('TpmEkPufProvider: length must be a positive integer (= enrolled rep*messageBits)');
    for (const length of [0, -1, 1.5, NaN]) expect(() => new TpmEkPufProvider({ id: 'x', length })).toThrow(lenMsg);
    expect(() => new TpmEkPufProvider({ id: 'x', length: 1 })).not.toThrow();
    const mMsg = new RangeError('TpmEkPufProvider: minEkBytes must be a positive integer');
    for (const minEkBytes of [0, -1, 1.5, NaN]) expect(() => new TpmEkPufProvider({ id: 'x', length: 8, minEkBytes })).toThrow(mMsg);
    expect(() => new TpmEkPufProvider({ id: 'x', length: 8, minEkBytes: 1 })).not.toThrow();
    expect(new TpmEkPufProvider({ id: 'dev', length: 8 }).id).toBe('dev');
  });
  it('default tool and argv, custom tool / handle / args, empty strings fall back', () => {
    const d = capture();
    new TpmEkPufProvider({ id: 'x', length: 8, run: d.run }).readEkPublic();
    expect(d.seen).toEqual([{ c: 'tpm2_readpublic', a: ['-c', '0x81010001', '-f', 'der', '-o', '/dev/stdout', '-Q'] }]);
    const c = capture();
    new TpmEkPufProvider({ id: 'x', length: 8, run: c.run, tool: 'my-tool', ekHandle: '0x1234' }).readEkPublic();
    expect(c.seen).toEqual([{ c: 'my-tool', a: ['-c', '0x1234', '-f', 'der', '-o', '/dev/stdout', '-Q'] }]);
    const e = capture();
    new TpmEkPufProvider({ id: 'x', length: 8, run: e.run, tool: '', ekHandle: '' }).readEkPublic();
    expect(e.seen[0]).toEqual({ c: 'tpm2_readpublic', a: ['-c', '0x81010001', '-f', 'der', '-o', '/dev/stdout', '-Q'] });
    const n = capture();
    new TpmEkPufProvider({ id: 'x', length: 8, run: n.run, tool: 5 as never, ekHandle: 7 as never }).readEkPublic();
    expect(n.seen[0]!.c).toBe('tpm2_readpublic');
    expect(n.seen[0]!.a[1]).toBe('0x81010001');
    const a = capture();
    new TpmEkPufProvider({ id: 'x', length: 8, run: a.run, ekHandle: 'ignored', args: ['--x', '1'] }).readEkPublic();
    expect(a.seen[0]!.a).toEqual(['--x', '1']);
  });
});

describe('TpmEkPufProvider.readEkPublic fail-closed paths', () => {
  const mk = (run: TpmCommandRunner, extra: Partial<ConstructorParameters<typeof TpmEkPufProvider>[0]> = {}) => new TpmEkPufProvider({ id: 'x', length: 8, run, ...extra });
  it('a throwing runner is wrapped (Error and non-Error)', () => {
    expect(() =>
      mk(() => {
        throw new Error('boom');
      }).readEkPublic(),
    ).toThrow(new Error('TpmEkPufProvider: tpm2-tools invocation threw (fail closed): boom'));
    expect(() =>
      mk(() => {
        throw 'str';
      }).readEkPublic(),
    ).toThrow(new Error('TpmEkPufProvider: tpm2-tools invocation threw (fail closed): unknown'));
  });
  it('non-object results', () => {
    const m = new Error('TpmEkPufProvider: command runner returned no result (fail closed)');
    expect(() => mk(() => null as never).readEkPublic()).toThrow(m);
    expect(() => mk(() => undefined as never).readEkPublic()).toThrow(m);
    expect(() => mk(() => 'x' as never).readEkPublic()).toThrow(m);
    expect(() => mk(() => 0 as never).readEkPublic()).toThrow(m);
  });
  it('spawn error text, non-zero status text (trimmed stderr), null status', () => {
    expect(() => mk(() => ({ status: null, stdout: new Uint8Array(0), error: 'tpm2_readpublic: ENOENT' })).readEkPublic()).toThrow(
      new Error('TpmEkPufProvider: tpm2-tools unavailable (fail closed): tpm2_readpublic: ENOENT'),
    );
    expect(() => mk(() => ({ status: 1, stdout: new Uint8Array(0), stderr: '  ERROR: no TPM \n' }), { tool: 'tt' }).readEkPublic()).toThrow(
      new Error("TpmEkPufProvider: 'tt' exited with status 1 (fail closed): ERROR: no TPM"),
    );
    expect(() => mk(() => ({ status: 2, stdout: new Uint8Array(0) })).readEkPublic()).toThrow(
      new Error("TpmEkPufProvider: 'tpm2_readpublic' exited with status 2 (fail closed)"),
    );
    expect(() => mk(() => ({ status: 2, stdout: new Uint8Array(0), stderr: '' })).readEkPublic()).toThrow(
      new Error("TpmEkPufProvider: 'tpm2_readpublic' exited with status 2 (fail closed)"),
    );
    expect(() => mk(() => ({ status: null, stdout: new Uint8Array(0) })).readEkPublic()).toThrow(
      new Error("TpmEkPufProvider: 'tpm2_readpublic' exited with status null (fail closed)"),
    );
  });
  it('an empty-string error field is ignored (status decides)', () => {
    const ek = seq(64);
    expect(mk(() => ({ status: 0, stdout: ek, error: '' })).readEkPublic()).toEqual(ek);
    expect(() => mk(() => ({ status: 3, stdout: ek, error: '' })).readEkPublic()).toThrow(/exited with status 3/);
  });
  it('EK length boundary: exactly minEkBytes is accepted, one less refused; non-bytes counts as 0', () => {
    expect(mk(() => ({ status: 0, stdout: seq(64) })).readEkPublic().length).toBe(64);
    expect(() => mk(() => ({ status: 0, stdout: seq(63) })).readEkPublic()).toThrow(
      new Error('TpmEkPufProvider: EK public too short (63 < 64 bytes) — TPM unavailable or wrong handle (fail closed)'),
    );
    expect(mk(() => ({ status: 0, stdout: seq(10) }), { minEkBytes: 10 }).readEkPublic().length).toBe(10);
    expect(() => mk(() => ({ status: 0, stdout: seq(9) }), { minEkBytes: 10 }).readEkPublic()).toThrow('(9 < 10 bytes)');
    expect(mk(() => ({ status: 0, stdout: seq(1) }), { minEkBytes: 1 }).readEkPublic().length).toBe(1);
    expect(() => mk(() => ({ status: 0, stdout: 'abc' as never })).readEkPublic()).toThrow('(0 < 64 bytes)');
  });
  it('response derives HKDF(ek, domain, challenge) bits via the counter-mode PRG (multi-block)', () => {
    const ek = seq(100, 11, 3);
    for (const length of [28, 256, 257, 300, 600]) {
      const p = mk(() => ({ status: 0, stdout: ek }), { length });
      const secret = hkdf(sha256, ek, utf8('atlas-pca/puf-tpm-ek/v1'), CH, 32);
      expect(p.response(CH)).toEqual(refPrg((ctr) => cat(secret, ctr), length));
    }
  });
});

describe('defaultTpmCommandRunner (stubbed process.getBuiltinModule)', () => {
  const withProcess = <T>(fake: unknown, fn: () => T): T => {
    const d = Object.getOwnPropertyDescriptor(globalThis, 'process')!;
    Object.defineProperty(globalThis, 'process', { value: fake, configurable: true, writable: true });
    try {
      return fn();
    } finally {
      Object.defineProperty(globalThis, 'process', d);
    }
  };
  const catchErr = (f: () => unknown): Error => {
    try {
      f();
    } catch (e) {
      return e as Error;
    }
    throw new Error('did not throw');
  };
  it('throws when there is no Node runtime', () => {
    const msg = 'TpmEkPufProvider: no Node runtime (process.getBuiltinModule, Node >= 22.3) to spawn tpm2-tools; inject opts.run (fail closed)';
    for (const fake of [undefined, null, {}, { getBuiltinModule: 'x' }]) {
      const e = withProcess(fake, () => catchErr(() => defaultTpmCommandRunner('t', [])));
      expect(e.message).toBe(msg);
    }
  });
  it('throws when child_process.execFileSync is unavailable', () => {
    const msg = 'TpmEkPufProvider: node:child_process.execFileSync unavailable (fail closed)';
    const asked: string[] = [];
    for (const mod of [undefined, null, {}, { execFileSync: 1 }]) {
      const e = withProcess({ getBuiltinModule: (id: string) => (asked.push(id), mod) }, () => catchErr(() => defaultTpmCommandRunner('t', [])));
      expect(e.message).toBe(msg);
    }
    expect(new Set(asked)).toEqual(new Set(['node:child_process']));
  });
  it('success: exact execFileSync options, result copied into a plain Uint8Array', () => {
    const calls: unknown[][] = [];
    const out = Buffer.from([1, 2, 3]);
    const r = withProcess({ getBuiltinModule: () => ({ execFileSync: (...a: unknown[]) => (calls.push(a), out) }) }, () => defaultTpmCommandRunner('cmd', ['a', 'b']));
    expect(calls).toEqual([['cmd', ['a', 'b'], { timeout: 15_000, maxBuffer: 1 << 20, stdio: ['ignore', 'pipe', 'pipe'] }]]);
    expect(r.status).toBe(0);
    expect(Object.keys(r).sort()).toEqual(['status', 'stdout']);
    expect(Array.from(r.stdout)).toEqual([1, 2, 3]);
    expect(r.stdout.constructor).toBe(Uint8Array);
    expect(r.stdout).not.toBe(out);
  });
  const failing = (err: unknown) => withProcess({ getBuiltinModule: () => ({ execFileSync: () => { throw err; } }) }, () => defaultTpmCommandRunner('cmd', []));
  it('non-zero exit: status, copied stdout, decoded stderr', () => {
    const r = failing({ status: 4, stdout: Buffer.from([9, 8]), stderr: Buffer.from('bad tpm'), message: 'msg' });
    expect(r.status).toBe(4);
    expect(r.stderr).toBe('bad tpm');
    expect(Array.from(r.stdout)).toEqual([9, 8]);
    expect(r.stdout.constructor).toBe(Uint8Array);
    expect('error' in r).toBe(false);
    const r2 = failing({ status: 0, message: 'boo' });
    expect(r2.status).toBe(0);
    expect('error' in r2).toBe(false);
  });
  it('stderr falls back to the error message (string only), stdout to empty', () => {
    expect(failing({ status: 1, message: 'm' }).stderr).toBe('m');
    expect(failing({ status: 1, message: 5 }).stderr).toBeUndefined();
    expect(failing({ status: 1 }).stderr).toBeUndefined();
    expect(failing({ status: 1, stdout: 'notbytes' }).stdout).toEqual(new Uint8Array(0));
    expect(failing({ status: 1 }).stdout.length).toBe(0);
  });
  it('spawn failure: null status, code in error (or "spawn failed")', () => {
    const r = failing({ code: 'ENOENT', message: 'spawn cmd ENOENT' });
    expect(r.status).toBeNull();
    expect(r.error).toBe('cmd: ENOENT');
    expect(r.stderr).toBe('spawn cmd ENOENT');
    expect(r.stdout.length).toBe(0);
    expect(failing({ code: 5 }).error).toBe('cmd: spawn failed');
    expect(failing({}).error).toBe('cmd: spawn failed');
    const s = failing({ status: '1', code: 'EACCES' });
    expect(s.status).toBeNull();
    expect(s.error).toBe('cmd: EACCES');
  });
  it('real child process: success, exit code, ENOENT', () => {
    const ok = defaultTpmCommandRunner(process.execPath, ['-e', 'process.stdout.write("hi")']);
    expect(ok.status).toBe(0);
    expect(Buffer.from(ok.stdout).toString()).toBe('hi');
    const bad = defaultTpmCommandRunner(process.execPath, ['-e', 'process.stderr.write("oops");process.exit(3)']);
    expect(bad.status).toBe(3);
    expect(bad.stderr).toBe('oops');
    const none = defaultTpmCommandRunner('/nonexistent/definitely-not-here', []);
    expect(none.status).toBeNull();
    expect(none.error).toBe('/nonexistent/definitely-not-here: ENOENT');
  });
});

// ------------------------------------------------------------------ enrollment / attestor / registry / verifier
const W_LEN = 21; // rep 3 x 7
const mkPuf = (id = 'dev-1', seed = new Uint8Array(32).fill(4)) => createSimulatedPuf({ id, seed, length: W_LEN });
const enrollAlg = (alg: 'ed25519' | 'ml-dsa-65' | 'ml-dsa-87', puf = mkPuf()) => enrollPuf(puf, CH, { rep: 3, messageBits: 7, alg, randomBytes: (n) => seq(n, 5, 3) });

describe('enrollPuf / createPufAttestor', () => {
  it('default alg is ml-dsa-65; supplied randomBytes feed the sketch and salt; commitment = hashCanonical(helper)', () => {
    const e = enrollPuf(mkPuf(), CH, { rep: 3, messageBits: 7, randomBytes: (n) => seq(n, 5, 3) });
    expect(e.alg).toBe('ml-dsa-65');
    expect(e.providerId).toBe('dev-1');
    expect(e.challenge).toBe(b64u(CH));
    expect(e.helper.salt).toBe(b64u(seq(32, 5, 3)));
    expect(e.helperCommitment).toBe(hashCanonical(e.helper));
    expect(e.helperCommitment.length).toBeGreaterThan(10);
    expect(e.helper).toMatchObject({ rep: 3, messageBits: 7, n: 21 });
  });
  it('rejects an unsupported suite everywhere', () => {
    const m = new RangeError("PUF root: unsupported derived suite 'rsa' (use ed25519, ml-dsa-65 or ml-dsa-87)");
    expect(() => enrollPuf(mkPuf(), CH, { rep: 3, messageBits: 7, alg: 'rsa' as never, randomBytes: (n) => seq(n) })).toThrow(m);
    const e = enrollAlg('ed25519');
    expect(() => createPufAttestor(mkPuf(), { ...e, alg: 'rsa' as never })).toThrow(m);
    expect(() => createPufAttestor(mkPuf(), { ...e, alg: 'ml-dsa-44' as never })).toThrow("unsupported derived suite 'ml-dsa-44'");
  });
  it('default randomness: uses WebCrypto (two enrolments differ), 32-byte salt', () => {
    const a = enrollPuf(mkPuf(), CH, { rep: 3, messageBits: 7, alg: 'ed25519' });
    const b = enrollPuf(mkPuf(), CH, { rep: 3, messageBits: 7, alg: 'ed25519' });
    expect(unb64u(a.helper.salt).length).toBe(32);
    expect(a.helper.salt).not.toBe(b.helper.salt);
  });
  it('defaultRandomBytes: returns the filled buffer; fails closed without a secure RNG', () => {
    const d = Object.getOwnPropertyDescriptor(globalThis, 'crypto')!;
    const set = (v: unknown) => Object.defineProperty(globalThis, 'crypto', { value: v, configurable: true, writable: true });
    const run = (v: unknown): { e?: Error; salt?: string; sketch?: string } => {
      set(v);
      try {
        const r = enrollPuf(mkPuf(), CH, { rep: 3, messageBits: 7, alg: 'ed25519' });
        return { salt: r.helper.salt, sketch: r.helper.sketch };
      } catch (e) {
        return { e: e as Error };
      } finally {
        Object.defineProperty(globalThis, 'crypto', d);
      }
    };
    const filled = run({ getRandomValues: (a: Uint8Array) => (a.fill(7), a) });
    expect(filled.salt).toBe(b64u(new Uint8Array(32).fill(7)));
    const msg = 'enrollPuf: no secure RNG available; pass opts.randomBytes';
    for (const v of [undefined, null, {}, { getRandomValues: 5 }]) expect(run(v).e?.message).toBe(msg);
  });
  it('statement fields: body, binding, weights_digest only when given, no pq_sig key for pure suites', () => {
    for (const alg of ['ed25519', 'ml-dsa-65', 'ml-dsa-87'] as const) {
      const puf = mkPuf();
      const enr = enrollAlg(alg, puf);
      const att = createPufAttestor(puf, enr);
      const st = att.attest(CLAIMS);
      expect(Object.keys(st).sort()).toEqual(['alg', 'binding', 'measurement', 'provider_id', 'sig']);
      expect(st.alg).toBe(alg);
      expect(st.provider_id).toBe('dev-1');
      expect(st.measurement).toBe('m-1');
      expect(st.binding).toBe(attestationBindingB64u({ holderPub: EXPECTED.holderPub, grantRef: 'g-1', epoch: 3, nonce: 'n-1' }));
      const w = att.attest({ ...CLAIMS, weights_digest: 'wd' });
      expect(w.weights_digest).toBe('wd');
      expect(Object.keys(w).sort()).toEqual(['alg', 'binding', 'measurement', 'provider_id', 'sig', 'weights_digest']);
    }
  });
  it('the signature covers PUF_ATTEST_DOMAIN || canonical(body) under the enrolled key', () => {
    const puf = mkPuf();
    const enr = enrollAlg('ed25519', puf);
    const st = createPufAttestor(puf, enr).attest({ ...CLAIMS, weights_digest: 'wd' });
    const { sig, ...body } = st;
    const dom = utf8('atlas-pca/attest-puf/v1\0');
    const msg = cat(dom, canonicalBytes(body));
    const verify = (m: Uint8Array) => verifyWithSuite('ed25519', { edPub: enr.publicKey } as never, m, { sig } as never);
    expect(verify(msg)).toBe(true);
    expect(verify(canonicalBytes(body))).toBe(false);
    expect(verify(cat(dom, canonicalBytes({ ...body, measurement: 'zz' })))).toBe(false);
    expect(verify(cat(utf8('atlas-pca/attest-puf/v1'), canonicalBytes(body)))).toBe(false);
  });
});

describe('createPufEnrollmentRegistry', () => {
  const e1 = enrollAlg('ed25519', mkPuf('a'));
  const e2 = enrollAlg('ed25519', mkPuf('b'));
  it('constructor seeds, register adds/overwrites, lookup misses are undefined', () => {
    const r = createPufEnrollmentRegistry([e1]);
    expect(r.lookup('a')).toBe(e1);
    expect(r.lookup('b')).toBeUndefined();
    r.register(e2);
    expect(r.lookup('b')).toBe(e2);
    const dup = { ...e1, publicKey: 'other' };
    r.register(dup);
    expect(r.lookup('a')).toBe(dup);
    expect(createPufEnrollmentRegistry([e1, dup]).lookup('a')).toBe(dup);
    expect(createPufEnrollmentRegistry().lookup('a')).toBeUndefined();
    expect(createPufEnrollmentRegistry(undefined).lookup('a')).toBeUndefined();
  });
  it('junk entries are ignored without throwing', () => {
    const junk = [null, undefined, 5, { providerId: 5 }, {}, { providerId: undefined }] as never[];
    const r = createPufEnrollmentRegistry(junk);
    for (const k of ['5', 5, 'undefined', undefined, 'null']) expect(r.lookup(k as never)).toBeUndefined();
    for (const j of junk) expect(() => r.register(j)).not.toThrow();
    for (const k of ['5', 5, 'undefined', undefined, 'null']) expect(r.lookup(k as never)).toBeUndefined();
    expect(createPufEnrollmentRegistry('abc' as never).lookup('a')).toBeUndefined();
  });
});

describe('createPufVerifier', () => {
  const puf = mkPuf();
  const enr = enrollAlg('ml-dsa-65', puf);
  const att = createPufAttestor(puf, enr);
  const input = (...a: unknown[]) => ({ expected: (a.length ? a[0] : EXPECTED) as never, document: {} as never, ctx: {} as never, nowMs: T });
  const verifier = (over: Record<string, unknown> = {}, policy: Record<string, unknown> = {}) =>
    createPufVerifier({
      resolveEnrollment: () => enr,
      policy: { measurements: ['m-1'], ...policy } as never,
      resolveEvidence: () => att.attest(CLAIMS),
      ...over,
    } as never);
  const deny = async (v: ReturnType<typeof verifier>, ...rest: unknown[]) => {
    const r = await v.verify(input(...rest));
    expect(r.ok).toBe(false);
    return r.reason;
  };

  it('construction guards with exact messages', () => {
    const m = new TypeError('createPufVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)');
    expect(() => createPufVerifier(undefined as never)).toThrow(m);
    expect(() => createPufVerifier(null as never)).toThrow(m);
    expect(() => createPufVerifier({ resolveEnrollment: () => enr } as never)).toThrow(m);
    expect(() => createPufVerifier({ resolveEnrollment: () => enr, policy: {} } as never)).toThrow(m);
    expect(() => createPufVerifier({ resolveEnrollment: () => enr, policy: { measurements: 'x' } } as never)).toThrow(m);
    expect(() => createPufVerifier({ resolveEnrollment: () => enr, policy: { measurements: [] } } as never)).toThrow(m);
    const m2 = new TypeError('createPufVerifier: resolveEnrollment is required');
    expect(() => createPufVerifier({ policy: { measurements: ['a'] } } as never)).toThrow(m2);
    expect(() => createPufVerifier({ resolveEnrollment: 5, policy: { measurements: ['a'] } } as never)).toThrow(m2);
  });
  it('accepts a good statement: exact result fields', async () => {
    const r = await verifier().verify(input());
    expect(r).toEqual({
      ok: true,
      bound: true,
      measured: { model_id: '', weights_digest: '', weights_measured: false, runtime_measurement: 'm-1', operator: '' },
      hostAsserted: { provider_id: 'dev-1', suite: 'ml-dsa-65' },
    });
  });
  it('weights digest is carried into the identity; deriveIdentity override receives (statement, enrollment)', async () => {
    const st = att.attest({ ...CLAIMS, weights_digest: 'wd-1' });
    const r = await verifier({ resolveEvidence: () => st }).verify(input());
    expect(r.measured).toEqual({ model_id: '', weights_digest: 'wd-1', weights_measured: false, runtime_measurement: 'm-1', operator: '' });
    const seen: unknown[][] = [];
    const custom = { model_id: 'M', weights_digest: 'x', weights_measured: true, runtime_measurement: 'y', operator: 'o' };
    const r2 = await verifier({}, { deriveIdentity: (...a: unknown[]) => (seen.push(a), custom) }).verify(input());
    expect(r2.measured).toBe(custom);
    expect(seen.length).toBe(1);
    expect((seen[0]![0] as PufAttestationStatement).provider_id).toBe('dev-1');
    expect(seen[0]![1]).toBe(enr);
  });
  it('async resolvers are awaited and receive (document, ctx) / (providerId, document, ctx)', async () => {
    const doc = { d: 1 } as never;
    const ctx = { c: 1 } as never;
    const log: unknown[][] = [];
    const v = createPufVerifier({
      resolveEnrollment: async (...a: unknown[]) => (log.push(a), enr),
      policy: { measurements: ['m-1'] },
      resolveEvidence: async (...a: unknown[]) => (log.push(a), att.attest(CLAIMS)),
    } as never);
    expect((await v.verify({ document: doc, ctx, nowMs: T, expected: EXPECTED } as never)).ok).toBe(true);
    expect(log).toEqual([
      [doc, ctx],
      ['dev-1', doc, ctx],
    ]);
  });
  it('evidence seam failures', async () => {
    expect(await deny(createPufVerifier({ resolveEnrollment: () => enr, policy: { measurements: ['m-1'] } } as never))).toBe('no PUF evidence resolver configured (fail closed)');
    const st = att.attest(CLAIMS);
    const bad: unknown[] = [undefined, null, 'str', 5, { ...st, provider_id: 5 }, { ...st, provider_id: undefined }, { ...st, alg: 5 }, { ...st, alg: undefined }];
    for (const b of bad) expect(await deny(verifier({ resolveEvidence: () => b })), String(JSON.stringify(b))).toBe('no PUF attestation statement for this action');
  });
  it('unknown enrollment', async () => {
    expect(await deny(verifier({ resolveEnrollment: () => undefined }))).toBe("no PUF enrollment registered for provider 'dev-1'");
  });
  it('helper commitment mismatch precedes the suite checks', async () => {
    const tampered = { ...enr, helper: { ...enr.helper, rep: 5, n: 35 }, alg: 'ed25519' as const };
    expect(await deny(verifier({ resolveEnrollment: () => tampered }))).toBe('PUF enrollment helper commitment mismatch (helper tampered)');
    expect(await deny(verifier({ resolveEnrollment: () => ({ ...enr, helperCommitment: undefined }) }))).toBe('PUF enrollment helper commitment mismatch (helper tampered)');
  });
  it('suite agreement and unknown suites', async () => {
    const edEnr = enrollAlg('ed25519');
    const r = await deny(verifier({ resolveEnrollment: () => edEnr }));
    expect(r).toBe("PUF statement suite 'ml-dsa-65' does not match the enrolled suite 'ed25519'");
    const weird = { ...enr, alg: 'bogus' };
    const st = { ...att.attest(CLAIMS), alg: 'bogus' };
    expect(await deny(verifier({ resolveEnrollment: () => weird, resolveEvidence: () => st }))).toBe("PUF statement declares an unknown signature alg 'bogus'");
  });
  it('requirePq: classical refused, every PQ PUF suite accepted', async () => {
    const edPuf = mkPuf();
    const edEnr = enrollAlg('ed25519', edPuf);
    const edSt = createPufAttestor(edPuf, edEnr).attest(CLAIMS);
    expect(await deny(verifier({ resolveEnrollment: () => edEnr, resolveEvidence: () => edSt, requirePq: true }))).toBe("PQ required: PUF-derived suite 'ed25519' is classical");
    expect((await verifier({ resolveEnrollment: () => edEnr, resolveEvidence: () => edSt }).verify(input())).ok).toBe(true);
    expect((await verifier({ resolveEnrollment: () => edEnr, resolveEvidence: () => edSt, requirePq: false }).verify(input())).ok).toBe(true);
    expect((await verifier({ requirePq: true }).verify(input())).ok).toBe(true);
    const p87 = mkPuf();
    const e87 = enrollAlg('ml-dsa-87', p87);
    const s87 = createPufAttestor(p87, e87).attest(CLAIMS);
    const r87 = await verifier({ resolveEnrollment: () => e87, resolveEvidence: () => s87, requirePq: true }).verify(input());
    expect(r87.ok).toBe(true);
    expect(r87.hostAsserted).toEqual({ provider_id: 'dev-1', suite: 'ml-dsa-87' });
    expect(e87.publicKey).not.toBe(enr.publicKey);
    expect((await verifier({ resolveEnrollment: () => e87, resolveEvidence: () => s87 }).verify(input())).ok).toBe(true);
  });
  it('signature checked under the enrolled key; tampered fields denied', async () => {
    const st = att.attest(CLAIMS);
    const sigMsg = 'PUF statement signature does not verify under the enrolled public key (wrong/cloned device or excessive noise)';
    expect(await deny(verifier({ resolveEvidence: () => ({ ...st, measurement: 'm-2' }) }, { measurements: ['m-1', 'm-2'] }))).toBe(sigMsg);
    expect(await deny(verifier({ resolveEvidence: () => ({ ...st, weights_digest: 'zz' }) }))).toBe(sigMsg);
    expect(await deny(verifier({ resolveEvidence: () => ({ ...st, sig: b64u(new Uint8Array(64)) }) }))).toBe(sigMsg);
  });
  it('binding: missing expected, unconstructible expected, mismatch', async () => {
    expect(await deny(verifier(), undefined)).toBe('no expected attestation binding supplied');
    expect(await deny(verifier(), null)).toBe('no expected attestation binding supplied');
    expect(await deny(verifier(), { ...EXPECTED, epoch: -1 })).toBe('binding not constructible: binding: epoch must be a non-negative safe integer');
    expect(await deny(verifier(), { ...EXPECTED, nonce: '' })).toBe('binding not constructible: binding: nonce required');
    expect(await deny(verifier(), { ...EXPECTED, nonce: 'other' })).toBe('PUF statement binding mismatch (holder/grant/epoch/nonce)');
    expect(await deny(verifier(), { ...EXPECTED, epoch: 4 })).toBe('PUF statement binding mismatch (holder/grant/epoch/nonce)');
  });
  it('measurement allowlist', async () => {
    expect(await deny(verifier({}, { measurements: ['zzz'] }))).toBe('measurement not in policy allowlist');
    expect((await verifier({}, { measurements: ['zzz', 'm-1'] }).verify(input())).ok).toBe(true);
  });
  it('weights allowlist: gating, missing digest, empty list ungated', async () => {
    const withW = att.attest({ ...CLAIMS, weights_digest: 'wd-1' });
    const wm = 'measured weights digest not in policy allowlist';
    expect(await deny(verifier({}, { weightsMeasurements: ['wd-1'] }))).toBe(wm); // statement has no weights digest
    expect(await deny(verifier({ resolveEvidence: () => withW }, { weightsMeasurements: ['wd-2'] }))).toBe(wm);
    expect((await verifier({ resolveEvidence: () => withW }, { weightsMeasurements: ['wd-2', 'wd-1'] }).verify(input())).ok).toBe(true);
    expect((await verifier({}, { weightsMeasurements: [] }).verify(input())).ok).toBe(true);
    expect((await verifier({ resolveEvidence: () => withW }, { weightsMeasurements: [] }).verify(input())).ok).toBe(true);
    expect((await verifier({}, {}).verify(input())).ok).toBe(true);
  });
  it('thrown errors are converted to fail-closed reasons', async () => {
    const thrower = (x: unknown) => verifier({ resolveEvidence: () => { throw x; } });
    expect(await deny(thrower(new Error('kaput')))).toBe('puf verification error (fail closed): kaput');
    expect(await deny(thrower('nope'))).toBe('puf verification error (fail closed): unknown');
    expect(await deny(verifier({ resolveEvidence: () => null as never, resolveEnrollment: () => { throw new Error('x'); } }))).toBe('no PUF attestation statement for this action');
  });
  it('enrollment of a different device / noise beyond the bound fails; within the bound passes', async () => {
    const noisyOk = createSimulatedPuf({ id: 'dev-1', seed: new Uint8Array(32).fill(4), length: W_LEN, flip: [0, 3, 6, 9, 12, 15, 18] });
    expect((await verifier({ resolveEvidence: () => createPufAttestor(noisyOk, enr).attest(CLAIMS) }).verify(input())).ok).toBe(true);
    const noisyBad = createSimulatedPuf({ id: 'dev-1', seed: new Uint8Array(32).fill(4), length: W_LEN, flip: [0, 1] });
    const r = await deny(verifier({ resolveEvidence: () => createPufAttestor(noisyBad, enr).attest(CLAIMS) }));
    expect(r).toMatch(/does not verify under the enrolled public key/);
    const other = enrollAlg('ml-dsa-65', mkPuf('dev-1', new Uint8Array(32).fill(9)));
    expect(other.publicKey).not.toBe(enr.publicKey);
  });
});

describe('PufEnrollment helper is bound by hashCanonical', () => {
  it('a swapped helper with a recomputed-but-different commitment is detected', async () => {
    const e: PufEnrollment = enrollAlg('ed25519');
    const other = enrollAlg('ed25519', mkPuf('dev-1', new Uint8Array(32).fill(8)));
    const swapped = { ...e, helper: other.helper };
    const v = createPufVerifier({ resolveEnrollment: () => swapped, policy: { measurements: ['m-1'] }, resolveEvidence: () => createPufAttestor(mkPuf(), e).attest(CLAIMS) });
    const r = await v.verify({ document: {} as never, ctx: {} as never, nowMs: T, expected: EXPECTED });
    expect(r.reason).toBe('PUF enrollment helper commitment mismatch (helper tampered)');
  });
});

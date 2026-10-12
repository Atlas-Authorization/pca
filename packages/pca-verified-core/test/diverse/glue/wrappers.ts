// Wrappers that sit at MODULE BOUNDARIES of the production glue (installed by vi.mock in the test files) and re-compute each
// boolean / digest the glue hands to the Dafny core with the independent models in reference.ts.
import { createHash } from 'node:crypto';
import { Monitor } from './monitor';
import { b64uStrictRef, canonRef, edVerifyRefBytes, edVerifyRef, hashRef, suiteRef, tap } from './reference';

const hx = (u: Uint8Array | undefined) => (u instanceof Uint8Array ? Buffer.from(u).toString('hex') : String(u));
const short = (s: string) => (s.length > 200 ? s.slice(0, 100) + '...' + s.slice(-60) : s);

type AnyFn = (...a: any[]) => any;

/** keys.ts: verify (bytes) and verifyB64u (strings). */
export function wrapKeys<M extends Record<string, any>>(real: M, mon: Monitor): M {
  const verify = (pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean => {
    const got = (real.verify as AnyFn)(pk, msg, sig);
    const ref = pk instanceof Uint8Array && sig instanceof Uint8Array && msg instanceof Uint8Array ? edVerifyRefBytes(pk, msg, sig) : false;
    mon.note('G.ed25519.verify');
    if (pk instanceof Uint8Array && sig instanceof Uint8Array && pk.length === 32 && sig.length === 64) mon.dump('EV', hx(pk), hx(msg), hx(sig));
    if (got !== ref) mon.violate('P-ED25519-STRICT', { glue: got, ref, pk: hx(pk), msg: short(hx(msg)), sig: hx(sig) });
    return got;
  };
  const verifyB64u = (pkB: string, msg: Uint8Array, sigB: string): boolean => {
    const got = (real.verifyB64u as AnyFn)(pkB, msg, sigB);
    mon.note('G.ed25519.verifyB64u');
    const ref = msg instanceof Uint8Array ? edVerifyRef(pkB, msg, sigB) : false;
    const pk = b64uStrictRef(pkB, 32), sg = b64uStrictRef(sigB, 64);
    if (pk && sg) mon.dump('EV', hx(pk), hx(msg), hx(sg));
    if (got !== ref) mon.violate('P-ED25519-STRICT/b64u', { glue: got, ref, pk: String(pkB), msg: short(hx(msg)), sig: String(sigB) });
    return got;
  };
  return { ...real, verify, verifyB64u };
}

/** pq.ts: verifyWithSuite + verifyLeafSuite. `isPinned` is the production PQ-key choke-point predicate (a precondition, not recomputed). */
export function wrapPq<M extends Record<string, any>>(real: M, mon: Monitor): M {
  const OPS: Record<string, [string, string]> = { 'ml-dsa-65': ['MV', '65'], 'ml-dsa-87': ['MV', '87'], 'slh-dsa-sha2-128f': ['SV', 'sha2-128f'], 'slh-dsa-sha2-256s': ['SV', 'sha2-256s'] };
  tap.pq = (kind, pk, msg, sg) => { const o = OPS[kind]; if (o) mon.dump(o[0], o[1], hx(pk), hx(msg), hx(sg)); };
  const isPinned = (x: unknown) => (real.isPinnedPqKey as AnyFn)(x);
  const check = (id: string, alg: unknown, keys: any, msg: Uint8Array, s: any, got: boolean) => {
    mon.note(id);
    let ref: boolean | undefined;
    try { ref = suiteRef(alg, keys, msg, s, isPinned); } catch (e) { mon.violate(id + '/ref-crash', { alg: String(alg), err: String(e) }); return; }
    if (ref === undefined) { mon.note(id + '.unchecked-suite'); return; }
    mon.note(id + '.alg=' + (alg === undefined ? 'ed25519' : String(alg)));
    if (got !== ref) mon.violate(id, { alg: String(alg), glue: got, ref, edPub: String(keys?.edPub), pq: String(keys?.pq?.b64u).slice(0, 40), msg: short(hx(msg)), sig: String(s?.sig).slice(0, 120), pq_sig: String(s?.pq_sig).slice(0, 80) });
  };
  const verifyWithSuite = (alg: unknown, keys: any, msg: Uint8Array, s: any): boolean => {
    const got = (real.verifyWithSuite as AnyFn)(alg, keys, msg, s);
    check('G-SUITE', alg, keys, msg, s, got);
    return got;
  };
  const verifyLeafSuite = (i: any): boolean => {
    const got = (real.verifyLeafSuite as AnyFn)(i);
    check('G-LEAF-SIG', i?.alg, { edPub: i?.holder, ...(i?.pq !== undefined ? { pq: i.pq } : {}) }, i?.message, { sig: i?.sig, pq_sig: i?.pqSig }, got);
    return got;
  };
  return { ...real, verifyWithSuite, verifyLeafSuite };
}

/** hash.ts: hashCanonical / canonicalizeStrict / decodeB64uStrict. */
export function wrapHash<M extends Record<string, any>>(real: M, mon: Monitor): M {
  const hashCanonical = (value: unknown, suite: 'sha256' | 'sha384' = 'sha256'): string => {
    let got: string | undefined, gotErr: unknown;
    try { got = (real.hashCanonical as AnyFn)(value, suite); } catch (e) { gotErr = e; }
    mon.note('G-CANON.hashCanonical');
    let refStr: string | undefined, refErr = false;
    try { refStr = canonRef(value); } catch { refErr = true; }
    if (gotErr !== undefined || refErr) {
      if ((gotErr !== undefined) !== refErr) mon.violate('G-CANON/profile', { glueThrew: gotErr !== undefined, refThrew: refErr, value: short(safeJson(value)) });
      if (gotErr !== undefined) throw gotErr;
      return got as string;
    }
    const refHash = hashRef(Buffer.from(refStr!, 'utf8'), suite === 'sha384' ? 'sha384' : 'sha256');
    if (got !== refHash) mon.violate('G-CANON', { glue: got, ref: refHash, canon: short(refStr!) });
    return got!;
  };
  const canonicalizeStrict = (value: unknown): string => {
    let got: string | undefined, gotErr: unknown;
    try { got = (real.canonicalizeStrict as AnyFn)(value); } catch (e) { gotErr = e; }
    mon.note('G-CANON.canonicalizeStrict');
    let refStr: string | undefined, refErr = false;
    try { refStr = canonRef(value); } catch { refErr = true; }
    if ((gotErr !== undefined) !== refErr) mon.violate('G-CANON/profile', { glueThrew: gotErr !== undefined, refThrew: refErr, value: short(safeJson(value)) });
    else if (!refErr && got !== refStr) mon.violate('G-CANON/bytes', { glue: short(String(got)), ref: short(refStr!) });
    if (gotErr !== undefined) throw gotErr;
    return got as string;
  };
  const decodeB64uStrict = (s: unknown, len?: number): Uint8Array | null => {
    const got = (real.decodeB64uStrict as AnyFn)(s, len);
    mon.note('G-B64U');
    const ref = b64uStrictRef(s, len);
    if ((got === null) !== (ref === null) || (got !== null && ref !== null && Buffer.compare(Buffer.from(got), Buffer.from(ref)) !== 0)) mon.violate('G-B64U', { s: short(String(s)), len, glue: got === null ? null : hx(got), ref: ref === null ? null : hx(ref) });
    return got;
  };
  const shaWrap = (name: 'sha256' | 'sha384') => (bytes: Uint8Array): Uint8Array => {
    const out: Uint8Array = (real[name] as AnyFn)(bytes);
    mon.note('G-' + name.toUpperCase());
    const ref = createHash(name).update(bytes).digest();
    if (Buffer.compare(Buffer.from(out), ref) !== 0) mon.violate('P-' + name.toUpperCase(), { len: bytes.length, glue: hx(out).slice(0, 32), ref: ref.toString('hex').slice(0, 32) });
    return out;
  };
  const hashWithSuite = (bytes: Uint8Array, suite: 'sha256' | 'sha384' = 'sha256'): Uint8Array => {
    const out: Uint8Array = (real.hashWithSuite as AnyFn)(bytes, suite);
    mon.note('G-HASHSUITE');
    const ref = createHash(suite === 'sha384' ? 'sha384' : 'sha256').update(bytes).digest();
    if (Buffer.compare(Buffer.from(out), ref) !== 0) mon.violate('P-HASHSUITE', { suite, len: bytes.length });
    return out;
  };
  return { ...real, hashCanonical, canonicalizeStrict, decodeB64uStrict, sha256: shaWrap('sha256'), sha384: shaWrap('sha384'), hashWithSuite };
}

/** A noble hash function object replaced by one that cross-checks every call against node:crypto (OpenSSL). */
export function wrapShaModule(real: Record<string, any>, mon: Monitor, names: Record<string, string>): Record<string, any> {
  const out: Record<string, any> = { ...real };
  for (const [exp, algo] of Object.entries(names)) {
    const orig = real[exp] as AnyFn;
    if (typeof orig !== 'function') continue;
    const w: any = (data: Uint8Array | string, opts?: unknown) => {
      const res: Uint8Array = orig(data, opts);
      if (opts === undefined) {
        mon.note('P-' + algo.toUpperCase());
        const bytes = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
        const ref = createHash(algo).update(bytes).digest();
        if (Buffer.compare(Buffer.from(res), ref) !== 0) mon.violate('P-' + algo.toUpperCase(), { len: bytes.length, glue: hx(res).slice(0, 32), ref: ref.toString('hex').slice(0, 32) });
      }
      return res;
    };
    Object.assign(w, orig);
    out[exp] = w;
  }
  return out;
}

function safeJson(v: unknown): string { try { return JSON.stringify(v) ?? String(v); } catch { return String(v); } }

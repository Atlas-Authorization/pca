// Shared support for the frost-net and frost-dkg oracles (not a generator itself): seed-label arguments, the scripted randomness
// source, the dealer-share descriptors core-frost-swift already uses, and the typed error / open-reason capture.
//
// RANDOMNESS. The reference draws fresh randomness only through ed25519.utils.randomPrivateKey (nonces, PoP nonces, DKG polynomials,
// DKG PoP nonces, session ids). The generator replaces that one function with a scripted queue per OWNER (a signer, a DKG party), so
// every transcript is byte-stable. A case that consumes randomness carries it as the LAST argument {"$rng":[<32-byte value>, ...]},
// in the exact order the reference drew it. A native harness strips that argument and feeds the values, in order, to the lane's
// random-bytes seam for that call. A draw outside the script, or a script not fully consumed, aborts the generator.
import { createRequire } from 'node:module';
import { seed, reparse, jsonOut } from './lib.mjs';

// frost.ts is loaded as CommonJS by tsx, so the instance of noble it uses is the CJS one: patch THAT one.
const req = createRequire(new URL('../../../packages/pca/src/frost.ts', import.meta.url));
export const ed: any = req('@noble/curves/ed25519').ed25519;

export const PFX = 'ref-frost-net/';
export const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64url');
export const fromB64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
export const B = (u: Uint8Array) => ({ $bytes: b64(u) });
/** A label-derived 32-byte value in corpus form: {"$bytes":{"$seed":label}} = sha256("atlas-pca-conformance/" + label). */
export const S = (label: string) => ({ $bytes: { $seed: PFX + label } });
export const sdb = (label: string): Uint8Array => seed(PFX + label);
export const hex = (u: Uint8Array) => Buffer.from(u).toString('hex');
export const hexB = (h: string) => B(Uint8Array.from(Buffer.from(h, 'hex')));

// ---- scripted randomness (per owner) ------------------------------------------------------------------------------
const QUEUES = new Map<string, { vals: Uint8Array[]; pos: number }>();
let OWNER: string | null = null;
export let UNSCRIPTED = false;
ed.utils.randomPrivateKey = () => {
  const q = OWNER === null ? undefined : QUEUES.get(OWNER);
  if (!q || q.pos >= q.vals.length) {
    UNSCRIPTED = true;
    throw new Error(`unscripted randomness draw (owner ${OWNER})`);
  }
  return q.vals[q.pos++]!.slice();
};
export const setQueue = (owner: string, labels: string[]) => QUEUES.set(owner, { vals: labels.map(sdb), pos: 0 });
export const setQueueBytes = (owner: string, vals: Uint8Array[]) => QUEUES.set(owner, { vals, pos: 0 });
export const clearQueues = () => QUEUES.clear();
export const queueLeft = () => [...QUEUES].filter(([, q]) => q.pos !== q.vals.length).map(([k, q]) => `${k}: ${q.pos}/${q.vals.length}`);
/** Run `f` with the randomness owner set (synchronous section only: draws happen inside `f`). */
export function as<T>(owner: string, f: () => T): T {
  const prev = OWNER;
  OWNER = owner;
  try {
    return f();
  } finally {
    OWNER = prev;
  }
}

// ---- corpus-form value resolution ---------------------------------------------------------------------------------
let F: any;
export const bindFrost = (frost: any) => (F = frost);
const SHARE_CACHE = new Map<string, Uint8Array>();
export function resolveShare(d: any): Uint8Array {
  const key = JSON.stringify(d);
  let s = SHARE_CACHE.get(key);
  if (!s) {
    const kg = F.frostTrustedDealerKeygen(d.t, d.n, { secret: d.secret ? un(d.secret) : undefined, coefficients: d.coefficients ? un(d.coefficients) : undefined, identifiers: d.identifiers ?? undefined });
    s = kg.participantShares.find((p: any) => p.identifier === d.id).share as Uint8Array;
    SHARE_CACHE.set(key, s);
  }
  return s;
}
/** Corpus form -> reference value: {$bytes:str}, {$bytes:{$seed}}, {$share:{...}} (dealer share), {$num:'NaN'|...}. */
export const un = (v: any): any => {
  if (Array.isArray(v)) return v.map(un);
  if (v !== null && typeof v === 'object') {
    const ks = Object.keys(v);
    if (ks.length === 1 && ks[0] === '$bytes') {
      const x = v.$bytes;
      if (typeof x === 'string') return fromB64(x);
      if (x && typeof x.$seed === 'string') return seed(x.$seed);
    }
    if (ks.length === 1 && ks[0] === '$share') return resolveShare(v.$share);
    if (ks.length === 1 && ks[0] === '$num') return Number(v.$num === '-Infinity' ? -Infinity : v.$num === 'Infinity' ? Infinity : NaN);
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, un(x)]));
  }
  return v;
};
export const J = (x: any) => JSON.parse(JSON.stringify(x));
export const flipB = (v: any, i = 0) => { const u = un(v); u[i] ^= 1; return B(u); };
/** Flip one bit of the first byte of a canonical base64url STRING (stays canonical when the bytes are 32/64 long). */
export const flipStr = (s: string, i = 0) => { const u = fromB64(s); u[i] ^= 1; return b64(u); };

// ---- dealer descriptors ---------------------------------------------------------------------------------------------
export interface Dealer { t: number; n: number; secret: any; coefficients: any[]; identifiers?: number[] }
export const dealerOf = (label: string, t: number, n: number, identifiers?: number[]): Dealer => ({
  t, n, secret: S(label + '/s'), coefficients: Array.from({ length: t - 1 }, (_, i) => S(label + '/c' + i)), ...(identifiers ? { identifiers } : {}),
});
export const kgOf = (d: Dealer) => F.frostTrustedDealerKeygen(d.t, d.n, { secret: un(d.secret), coefficients: un(d.coefficients), identifiers: d.identifiers });
/** {"$share": {t, n, secret, coefficients, identifiers, id}}: the dealer share of participant `id` (the native runs ITS keygen on these seeds). */
export const shareOf = (d: Dealer, id: number) => ({ $share: { t: d.t, n: d.n, secret: d.secret, coefficients: d.coefficients, identifiers: d.identifiers ?? null, id } });

// ---- capture ----------------------------------------------------------------------------------------------------------
const TYPED = new Set(['PoPError', 'EquivocationError', 'CoordinatorError', 'CoordinatorTimeoutError', 'DkgChannelError']);
export function errOut(e: any): any {
  const o: any = { $throws: e instanceof Error ? e.message : String(e) };
  if (e && typeof e.code === 'string') o.code = e.code;
  if (e && TYPED.has(e.name)) {
    o.class = e.name;
    if (e.name === 'PoPError' && e.identifier !== undefined) o.identifier = e.identifier;
    if (e.name === 'EquivocationError') Object.assign(o, { session_id: e.session_id, round: e.round, identifier: e.identifier, previousDigest: e.previousDigest, offendingDigest: e.offendingDigest });
    if (e.name === 'CoordinatorError' || e.name === 'CoordinatorTimeoutError') o.refusals = jsonOut(e.refusals);
    if (e.name === 'CoordinatorTimeoutError') o.timeoutMs = e.timeoutMs;
    if (e.name === 'DkgChannelError') o.peer = e.peer ?? null;
  }
  return o;
}
export async function cap(f: (...a: any[]) => any, args: any[]): Promise<any> {
  try {
    return jsonOut(await f(...args));
  } catch (e: any) {
    if (UNSCRIPTED) throw e;
    return errOut(e);
  }
}

// ---- open reasons ------------------------------------------------------------------------------------------------------
// A refusal reason that comes from one of the module's own fixed branches must be reproduced exactly; a reason that wraps an
// inner library / primitive error message (the reference's catch-all `e.message`) is lane-specific text. The generator marks the
// latter with "reasonOpen": true: a native must refuse in the same place but need not match the text. Everything else is exact.
const FIXED = [
  /^malformed round-[12] request$/, /^session already signed( \(one-shot\))?$/, /^duplicate round-1 for session$/, /^no round-1 state for this session$/,
  /^session expired \(stale-session guard: round-1 older than \d+ms\)$/, /^message not canonical base64url$/, /^request names a different group key$/,
  /^policy authorization failed: allow token (missing or malformed|has no body|missing signature|signature not canonical base64url|not signed by the trusted policy authority|authorizes a different group key|authorizes a different action digest|not yet valid|expired)$/,
  /^policy authorization failed: invalid verification time$/,
  /^signing set below threshold t=\d+$/, /^our commitment is not in the signing set$/, /^equivocation detected: our commitment in the signing set differs from our round-1 commitment$/,
  /^bad commitment( identifier| point encoding)?$/, /^commitments (must be a list|list exceeds the maximum signing set)$/, /^verification_shares (must be a list|list exceeds the maximum signing set)$/,
  /^bad verification( share|-share identifier|-share key encoding)$/,
  /^session expired/, /^no verification share on record for this signer$/, /^invalid or missing proof-of-possession \(rogue-key defense\)$/,
  /^equivocation: signer \d+ sent two different messages for session '.*' round \d+$/, /^malformed signature share$/, /^unreachable$/,
  /^allow token (missing or malformed|has no body|missing signature|signature not canonical base64url|not signed by the trusted policy authority|authorizes a different group key|authorizes a different action digest|not yet valid|expired)$/,
  /^invalid verification time$/,
  /^equivocation check failed$/, /^(canned refusal|busy|nope|store down)$/,
];
export const isFixedReason = (r: string) => FIXED.some((re) => re.test(r));
/** Add "reasonOpen": true next to every non-fixed `reason` string of an object that is a refusal. */
export function markOpen(v: any): any {
  if (Array.isArray(v)) return v.map(markOpen);
  if (v !== null && typeof v === 'object') {
    const o: any = Object.fromEntries(Object.entries(v).map(([k, x]) => [k, markOpen(x)]));
    if (typeof o.reason === 'string' && (o.ok === false || o.refused === true || 'identifier' in o) && !isFixedReason(o.reason)) o.reasonOpen = true;
    return o;
  }
  return v;
}

/** The case runner: args in corpus form; `rng` (labels) is appended as the last argument and consumed by the reference in order. */
export function runner(o: any, opts: { open?: boolean; loose?: boolean } = {}) {
  return async (fn: string, name: string, f: (...a: any[]) => any, jargs: any[], rng?: string[], post?: (out: any) => any) => {
    const args = rng ? [...jargs, { $rng: rng.map(S) }] : jargs;
    const a = reparse(args);
    clearQueues();
    if (rng) setQueue('main', rng);
    UNSCRIPTED = false;
    OWNER = 'main';
    let out = await cap(f, un(rng ? a.slice(0, -1) : a));
    OWNER = null;
    // async work must not draw randomness outside `as`: any unscripted draw has already thrown
    const left = opts.loose ? [] : queueLeft();
    if (left.length) throw new Error(`case ${fn}/${name}: randomness script not fully consumed (${left.join(', ')})`);
    if (post) out = post(out);
    if (opts.open) out = markOpen(out);
    return o.add(fn, name, a, out);
  };
}

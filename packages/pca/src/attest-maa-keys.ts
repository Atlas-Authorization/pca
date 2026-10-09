/**
 * Rotation-safe key trust store for Azure MAA token-signing keys.
 *
 * PROBLEM: `createAzureMaaVerifier` needs `trustAnchors` (SPKI pins). MAA instance signing certs ROTATE, so a
 * hard-coded pin silently breaks (or, worse, gets "fixed" by pinning whatever the service returns). This module
 * derives `{ rootSpkiSha256: string[] }` from a freshly fetched `<issuer>/certs` JWKS under an explicit
 * rotation policy, persists the accepted set, and fails closed when policy is violated.
 *
 * WHAT IS GUARANTEED
 *   - Network I/O happens ONLY when the caller invokes `getTrustAnchors` / `fetchMaaCerts` (never automatic),
 *     only for HTTPS issuers pinned in `policy.trustedIssuers`, with `redirect: 'error'`, a response-URL check,
 *     a hard timeout and a hard body-size limit. `fetch` is injected, never taken from a global.
 *   - Every cert that contributes an anchor is validated: self-signed instance certs must have a subject that is
 *     EXACTLY `CN=<issuer URL>` (no wildcard, no extra RDNs), be genuinely self-signed, inside their validity
 *     window (+skew), no older than `maxKeyAgeMs` (self-signed only), and use RSA >= 2048 bits or EC P-256/384/521.
 *     Microsoft-chained keys are used only through a pinned chain root (`chainRootSpkiSha256`, default: built-in)
 *     and, when pinned, a pinned intermediate (`chainIntermediateSpkiSha256`).
 *   - The accepted anchor set may only change by ROTATION: at most `maxNewKeysPerFetch` unseen keys per fetch and
 *     (by default) at least one key in common with the previous unexpired set. A total replacement is rejected
 *     unless the new keys are approved by an operator-signed manifest (`maa-signing-spki` entries whose label is
 *     the issuer URL, verified with `verifyAllowlistManifest`). A `revoked` tombstone in that manifest strips
 *     the key from the result even though the JWKS still serves it.
 *   - Cache: results are reused for `ttlMs`. If a refresh fails at the TRANSPORT level the last accepted set is
 *     served for at most `maxStaleMs` after it was fetched, then the call fails closed. Policy violations
 *     (bad cert, rotation breach) never fall back to stale data.
 *   - The persisted state (caller's get/set) is validated on load; `fetchedAtMs` is monotone and a clock that
 *     moves backwards past the stored fetch time fails closed.
 *
 * WHAT IS NOT GUARANTEED
 *   - THE FIRST ACCEPTED SET IS NO LONGER TRUST-ON-FIRST-USE by default, but the offline root is NOT Microsoft for
 *     the self-signed instance keys (Microsoft publishes no root for them). By default (`builtinPins`) the baseline
 *     is the pin set shipped in this package (attest-maa-pins): a manifest signed by the RELEASE SIGNING KEY
 *     (hybrid Ed25519 + ML-DSA-65, public half embedded), whose signed corroboration record states that >= 3
 *     independent network vantage points (local, Google Cloud, Azure) saw identical key material. Trust therefore
 *     rests on (release key) AND (vantage independence at signing time); a compromised release key, or an
 *     attacker who controlled every vantage that day, defeats it. The pins expire (fail closed with
 *     `builtin-pins-invalid`); ship a new release or supply your own `initialPins` / `builtinPins` source.
 *   - An issuer the release did not pin has NO built-in baseline: it still needs `initialPins`, a signed re-pin,
 *     persisted state, or the explicit `allowTrustOnFirstUse: true` opt-in (TOFU over TLS + issuer pin). Use
 *     `corroborateMaaKeySets(observations, k)` to make that first use k-vantage-corroborated instead of blind.
 *   - Microsoft-CHAINED keys DO have an offline Microsoft root: the built-in pins fix the root (Microsoft Root
 *     Certificate Authority 2011) AND the `Microsoft Azure Attestation PCA 2019` intermediate; the chain must verify
 *     link-by-link to that root and pass through that intermediate, and the anchor handed to the verifier is the
 *     intermediate. No CRL/OCSP or Microsoft revocation is consulted; cert validity windows are.
 *   - A self-signed instance cert proves nothing about identity beyond "served from this TLS origin"; the CN
 *     check blocks copy-paste of another instance's cert, not a compromised origin (observed: the SPKIs are
 *     identical ACROSS instances, so a pin proves "a MAA-service key", not "this instance's key").
 *   - A slow, in-policy rotation chain (one new key per fetch, always overlapping) is accepted by design.
 *   - Rollback of the persisted key state is only prevented if the store is durable (`durableMaaKeyStateStore` over
 *     `openDurableState`: crash-safe, hash-chained, monotone in `fetchedAtMs`); wiping the whole state directory
 *     returns the store to the built-in-pin baseline, which is itself rollback-bounded by the shipped version floor.
 */
import { createHash, X509Certificate } from 'node:crypto';
import { verifyAllowlistManifest, projectAllowlist, type VerifyAllowlistOptions } from './attest-allowlist';
import type { AzureMaaTrustAnchors, MaaJwk, MaaJwks } from './attest-azure-maa';
import type { DurableKv } from './durable-state';
import { loadBuiltinMaaPins, BUILTIN_CHAIN_LEAF_CN, type BuiltinMaaPinsSource } from './attest-maa-pins';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const ISSUER_URL = /^https:\/\/[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$/;
const HEX64 = /^[0-9a-f]{64}$/;
const MAX_JWKS_KEYS = 32;
const MAX_X5C = 8;
const MAX_X5C_B64 = 131_072;
const EC_CURVES = new Set(['prime256v1', 'secp384r1', 'secp521r1']);

export interface MaaKeyPolicy {
  /** Pinned MAA instance issuer URLs (exact match, https, no path / trailing slash). */
  trustedIssuers: string[];
  /** Reuse a fetched set for this long (default 1 h). */
  ttlMs?: number;
  /** Serve the last accepted set on transport failure for at most this long after its fetch (default 24 h). */
  maxStaleMs?: number;
  /** Max keys not in the previous set per fetch (default 2). */
  maxNewKeysPerFetch?: number;
  /** Max keys in the very first (TOFU / re-pinned) set (default 8). */
  maxInitialKeys?: number;
  /** Reject certs whose notBefore is older than this (default 400 days). */
  maxKeyAgeMs?: number;
  /** Require >= 1 key in common with the previous unexpired set (default true). */
  requireOverlap?: boolean;
  /** EXPLICIT opt-in to trust-on-first-use when there is no built-in pin, no initialPins, no state (default false). */
  allowTrustOnFirstUse?: boolean;
  /** Out-of-band SPKI SHA-256 pins per issuer, used as the baseline when no state is stored. */
  initialPins?: Record<string, string[]>;
  /** SPKI SHA-256 of pinned roots under which Microsoft-chained JWKS keys are accepted. Default: none (chained keys ignored). */
  chainRootSpkiSha256?: string[];
  /**
   * SPKI SHA-256 of an INTERMEDIATE CA every accepted chained key must pass through (e.g. `Microsoft Azure
   * Attestation PCA 2019`). When set, the anchor handed to the verifier is this intermediate (narrower than
   * the shared Microsoft root) and the chain must still end in a pinned root.
   */
  chainIntermediateSpkiSha256?: string[];
  /**
   * Built-in signed pin set shipped with this package (see attest-maa-pins). DEFAULT (`undefined`/`true`):
   * ON - the first accepted key set is anchored on the release-signed pins, no trust-on-first-use. `false`
   * disables it. An object substitutes another signed source (tests / forks with their own release key).
   * Explicit `initialPins` / `chainRootSpkiSha256` / `chainIntermediateSpkiSha256` / `chainLeafCn` always win.
   */
  builtinPins?: boolean | BuiltinMaaPinsSource;
  /** If set, a chained leaf's subject CN must be one of these (e.g. `Microsoft Azure Attestation 2020`). */
  chainLeafCn?: string[];
  /** Clock skew tolerance for cert validity (default 60 s). */
  clockSkewMs?: number;
  /** Fetch timeout (default 10 s). */
  fetchTimeoutMs?: number;
  /** Max response bytes (default 1 MiB; real MAA certs carry ~40 KB of endorsements). */
  maxBodyBytes?: number;
}

export interface MaaAnchorRecord {
  spki: string;
  kind: 'self-signed' | 'chained-root' | 'chained-intermediate';
  notBeforeMs: number;
  notAfterMs: number;
  firstSeenMs: number;
}

export interface MaaKeyState {
  v: 1;
  issuer: string;
  fetchedAtMs: number;
  anchors: MaaAnchorRecord[];
}

/** Caller-supplied persistence. */
export interface MaaKeyStateStore {
  get(issuer: string): Promise<MaaKeyState | undefined> | MaaKeyState | undefined;
  set(issuer: string, state: MaaKeyState): Promise<void> | void;
}

/** Simple in-memory store (tests / single-process). Production callers should persist durably. */
export function createMemoryMaaKeyStateStore(): MaaKeyStateStore & { snapshot(): Map<string, MaaKeyState> } {
  const m = new Map<string, MaaKeyState>();
  return {
    get: (i) => m.get(i),
    set: (i, s) => void m.set(i, JSON.parse(JSON.stringify(s)) as MaaKeyState),
    snapshot: () => new Map(m),
  };
}

/**
 * Persist the accepted key sets in durable state (`openDurableState` or the in-memory `createMemoryDurableKv`).
 * Writes are atomic read-modify-write and MONOTONE in `fetchedAtMs`: a stale writer can never move the stored
 * state backwards. A corrupt stored record is returned as-is so `getTrustAnchors` fails closed (`corrupt-state`).
 */
export function durableMaaKeyStateStore(kv: DurableKv): MaaKeyStateStore {
  const k = (issuer: string): string => `maa-keys/${issuer}`;
  return {
    get: async (issuer) => (await kv.get(k(issuer))) as MaaKeyState | undefined,
    set: async (issuer, state) => {
      await kv.update(k(issuer), (prev) => {
        const p = prev === undefined ? undefined : parseState(prev, issuer);
        return p && p.fetchedAtMs > state.fetchedAtMs ? undefined : state;
      });
    },
  };
}

export type MaaKeyErrorCode =
  | 'untrusted-issuer'
  | 'corrupt-state'
  | 'clock-regression'
  | 'fetch-failed'
  | 'stale-exceeded'
  | 'no-valid-keys'
  | 'no-baseline'
  | 'too-many-new-keys'
  | 'no-overlap'
  | 'repin-invalid'
  | 'builtin-pins-invalid';

export interface MaaTrustOk {
  ok: true;
  /** Ready for `createAzureMaaVerifier({ trustAnchors })`. */
  trustAnchors: AzureMaaTrustAnchors & { rootSpkiSha256: string[] };
  source: 'cache' | 'fetched' | 'stale-cache';
  anchors: MaaAnchorRecord[];
  /** Keys in this result not in the previous set. */
  newKeys: string[];
  /** Keys in the previous set absent now. */
  removedKeys: string[];
  /** JWKS entries that were not accepted, with the reason. */
  rejected: Array<{ kid: string; reason: string }>;
}
export type MaaTrustResult = MaaTrustOk | { ok: false; code: MaaKeyErrorCode; reason: string };

// ───────────────────────────── guarded fetch ─────────────────────────────

export interface FetchMaaCertsOptions {
  fetch: typeof fetch;
  timeoutMs?: number;
  maxBytes?: number;
}

/** Fetch `<issuer>/certs` with HTTPS-only, no redirects, a timeout and a size limit. THROWS on any problem. */
export async function fetchMaaCerts(issuer: string, opts: FetchMaaCertsOptions): Promise<MaaJwks> {
  if (typeof opts?.fetch !== 'function') throw new TypeError('fetchMaaCerts: a fetch implementation must be injected');
  if (!ISSUER_URL.test(issuer)) throw new TypeError('fetchMaaCerts: issuer must be an https origin URL (no path, no trailing slash)');
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const maxBytes = opts.maxBytes ?? 1_048_576;
  const url = `${issuer}/certs`;
  const ac = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, rej) => {
    timer = setTimeout(() => {
      ac.abort();
      rej(new Error(`MAA certs fetch timed out after ${timeoutMs} ms`));
    }, timeoutMs);
  });
  try {
    const work = (async () => {
      const res = await opts.fetch(url, { redirect: 'error', signal: ac.signal, headers: { accept: 'application/json' } });
      if (!res.ok) throw new Error(`MAA certs fetch failed: HTTP ${res.status}`);
      if (res.url && res.url !== url) throw new Error('MAA certs fetch: response URL differs from the request (redirect)');
      const declared = Number(res.headers?.get?.('content-length') ?? '0');
      if (Number.isFinite(declared) && declared > maxBytes) throw new Error('MAA certs response exceeds the size limit');
      const bytes = await readLimited(res, maxBytes);
      let parsed: unknown;
      try {
        parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      } catch {
        throw new Error('MAA certs response is not valid UTF-8 JSON');
      }
      return parseJwks(parsed);
    })();
    return await Promise.race([work, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

async function readLimited(res: Response, maxBytes: number): Promise<Uint8Array> {
  const body = res.body;
  if (body && typeof body.getReader === 'function') {
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new Error('MAA certs response exceeds the size limit');
      }
      chunks.push(value);
    }
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      out.set(c, off);
      off += c.byteLength;
    }
    return out;
  }
  const buf = new Uint8Array(await res.arrayBuffer());
  if (buf.byteLength > maxBytes) throw new Error('MAA certs response exceeds the size limit');
  return buf;
}

function parseJwks(x: unknown): MaaJwks {
  if (typeof x !== 'object' || x === null || !Array.isArray((x as { keys?: unknown }).keys)) throw new Error('MAA certs: response has no keys array');
  const raw = (x as { keys: unknown[] }).keys;
  if (raw.length > MAX_JWKS_KEYS) throw new Error('MAA certs: too many keys');
  const keys: MaaJwk[] = [];
  for (const k of raw) {
    if (typeof k !== 'object' || k === null) throw new Error('MAA certs: malformed key entry');
    const r = k as Record<string, unknown>;
    const x5c = r['x5c'];
    if (!Array.isArray(x5c) || x5c.length === 0 || x5c.length > MAX_X5C || x5c.some((c) => typeof c !== 'string' || c.length === 0 || c.length > MAX_X5C_B64)) {
      throw new Error('MAA certs: key without a well-formed x5c');
    }
    keys.push({
      ...(typeof r['kid'] === 'string' ? { kid: r['kid'] } : {}),
      ...(typeof r['kty'] === 'string' ? { kty: r['kty'] } : {}),
      ...(typeof r['alg'] === 'string' ? { alg: r['alg'] } : {}),
      x5c: x5c as string[],
    });
  }
  return { keys };
}

// ───────────────────────────── JWKS evaluation ─────────────────────────────

const spkiOf = (c: X509Certificate): string => createHash('sha256').update(new Uint8Array(c.publicKey.export({ type: 'spki', format: 'der' }))).digest('hex');

function parseCert(b64: string): X509Certificate {
  return new X509Certificate(Buffer.from(b64, 'base64'));
}
function validity(c: X509Certificate): { from: number; to: number } {
  return { from: Date.parse(c.validFrom), to: Date.parse(c.validTo) };
}
/** Subject CN when the subject is exactly one CN RDN; otherwise undefined. */
function soleCn(subject: string): string | undefined {
  const lines = subject.split('\n').filter((l) => l.length > 0);
  if (lines.length !== 1) return undefined;
  const m = /^CN=(.*)$/.exec(lines[0]!);
  return m ? m[1] : undefined;
}
function leafCn(subject: string): string | undefined {
  for (const l of subject.split('\n')) if (l.startsWith('CN=')) return l.slice(3);
  return undefined;
}
function keyStrengthError(c: X509Certificate): string | null {
  const pk = c.publicKey;
  if (pk.asymmetricKeyType === 'rsa') {
    const bits = pk.asymmetricKeyDetails?.modulusLength ?? 0;
    return bits >= 2048 && bits <= 8192 ? null : `RSA key size ${bits} outside 2048..8192`;
  }
  if (pk.asymmetricKeyType === 'ec') {
    const curve = pk.asymmetricKeyDetails?.namedCurve ?? '';
    return EC_CURVES.has(curve) ? null : `EC curve '${curve}' not allowed`;
  }
  return `key type '${String(pk.asymmetricKeyType)}' not allowed`;
}
function safeVerify(c: X509Certificate, k: X509Certificate['publicKey']): boolean {
  try {
    return c.verify(k);
  } catch {
    return false;
  }
}

export interface MaaJwksEvaluation {
  accepted: Array<Omit<MaaAnchorRecord, 'firstSeenMs'>>;
  rejected: Array<{ kid: string; reason: string }>;
}

/** Pure validation of every key in a JWKS against the policy at `nowMs`. Never throws. */
export function evaluateMaaJwks(jwks: MaaJwks, issuer: string, policy: MaaKeyPolicy, nowMs: number): MaaJwksEvaluation {
  const skew = policy.clockSkewMs ?? 60_000;
  const maxAge = policy.maxKeyAgeMs ?? 400 * DAY;
  const roots = new Set((policy.chainRootSpkiSha256 ?? []).map((s) => s.toLowerCase()));
  const inters = new Set((policy.chainIntermediateSpkiSha256 ?? []).map((s) => s.toLowerCase()));
  const accepted = new Map<string, Omit<MaaAnchorRecord, 'firstSeenMs'>>();
  const rejected: Array<{ kid: string; reason: string }> = [];
  for (const [i, key] of (jwks?.keys ?? []).entries()) {
    const kid = key.kid ?? `#${i}`;
    const no = (reason: string) => void rejected.push({ kid, reason });
    try {
      const x5c = key.x5c;
      if (!Array.isArray(x5c) || x5c.length === 0) {
        no('no x5c');
        continue;
      }
      const certs = x5c.map(parseCert);
      const leaf = certs[0]!;
      for (const [j, c] of certs.entries()) {
        const v = validity(c);
        if (!Number.isFinite(v.from) || !Number.isFinite(v.to)) throw new Error(`cert ${j}: unparsable validity`);
        if (nowMs + skew < v.from) throw new Error(`cert ${j}: not yet valid`);
        if (nowMs - skew > v.to) throw new Error(`cert ${j}: expired`);
      }
      const lv = validity(leaf);
      const strength = keyStrengthError(leaf);
      if (strength) throw new Error(strength);
      if (certs.length === 1) {
        if (nowMs - lv.from > maxAge) throw new Error('key older than maxKeyAgeMs');
        const cn = soleCn(leaf.subject);
        if (cn === undefined) throw new Error('subject is not a single CN');
        if (cn.includes('*')) throw new Error('wildcard CN rejected');
        if (cn !== issuer) throw new Error('subject CN does not equal the issuer URL');
        if (leaf.issuer !== leaf.subject || !safeVerify(leaf, leaf.publicKey)) throw new Error('not a genuine self-signed cert');
        const spki = spkiOf(leaf);
        accepted.set(spki, { spki, kind: 'self-signed', notBeforeMs: lv.from, notAfterMs: lv.to });
        continue;
      }
      // Chained key: only under an explicitly pinned root (and, when configured, a pinned intermediate).
      if (roots.size === 0) throw new Error('chained key ignored (no chainRootSpkiSha256 configured)');
      for (let j = 0; j < certs.length - 1; j++) if (!safeVerify(certs[j]!, certs[j + 1]!.publicKey)) throw new Error(`chain link ${j} is not signed by the next cert`);
      const top = certs[certs.length - 1]!;
      if (top.issuer !== top.subject || !safeVerify(top, top.publicKey)) throw new Error('chain does not end in a self-signed root');
      const rootSpki = spkiOf(top);
      if (!roots.has(rootSpki)) throw new Error('chain root is not pinned');
      if (policy.chainLeafCn && !policy.chainLeafCn.includes(leafCn(leaf.subject) ?? '\u0000')) throw new Error('chained leaf CN not allowed');
      const top2 = validity(top);
      let anchorSpki = rootSpki;
      let anchorKind: MaaAnchorRecord['kind'] = 'chained-root';
      let anchorFrom = top2.from;
      let anchorTo = top2.to;
      if (inters.size > 0) {
        // The pinned intermediate must sit strictly between leaf and root; it (not the shared root) becomes the anchor.
        const mid = certs.slice(1, -1).find((c) => inters.has(spkiOf(c)));
        if (!mid) throw new Error('chain does not pass through a pinned intermediate');
        const mv = validity(mid);
        anchorSpki = spkiOf(mid);
        anchorKind = 'chained-intermediate';
        anchorFrom = mv.from;
        anchorTo = mv.to;
      }
      const prev = accepted.get(anchorSpki);
      accepted.set(anchorSpki, {
        spki: anchorSpki,
        kind: anchorKind,
        notBeforeMs: prev ? Math.min(prev.notBeforeMs, anchorFrom) : anchorFrom,
        notAfterMs: Math.min(anchorTo, Math.max(prev?.notAfterMs ?? 0, lv.to)),
      });
    } catch (e) {
      no(e instanceof Error ? e.message : 'invalid key');
    }
  }
  return { accepted: [...accepted.values()], rejected };
}

// ───────────────────────────── trust store ─────────────────────────────

export interface MaaRepin {
  /** Operator-signed manifest (attest-allowlist) carrying `maa-signing-spki` entries labelled with the issuer URL. */
  manifest: unknown;
  /** Verification options for the manifest (issuerKeys, minVersion, lastSeenVersion, ...); `nowMs` is supplied here. */
  verify: Omit<VerifyAllowlistOptions, 'nowMs'>;
}

export interface MaaKeyTrustOptions {
  policy: MaaKeyPolicy;
  store: MaaKeyStateStore;
  fetch: typeof fetch;
}

export interface MaaKeyTrust {
  getTrustAnchors(issuer: string, opts: { nowMs: number; repin?: MaaRepin }): Promise<MaaTrustResult>;
}

function parseState(x: unknown, issuer: string): MaaKeyState | null {
  if (typeof x !== 'object' || x === null) return null;
  const s = x as Record<string, unknown>;
  if (s['v'] !== 1 || s['issuer'] !== issuer || !Number.isSafeInteger(s['fetchedAtMs']) || !Array.isArray(s['anchors'])) return null;
  const anchors: MaaAnchorRecord[] = [];
  for (const a of s['anchors'] as unknown[]) {
    if (typeof a !== 'object' || a === null) return null;
    const r = a as Record<string, unknown>;
    if (typeof r['spki'] !== 'string' || !HEX64.test(r['spki'])) return null;
    if (r['kind'] !== 'self-signed' && r['kind'] !== 'chained-root' && r['kind'] !== 'chained-intermediate') return null;
    if (![r['notBeforeMs'], r['notAfterMs'], r['firstSeenMs']].every((n) => Number.isSafeInteger(n))) return null;
    anchors.push({ spki: r['spki'], kind: r['kind'], notBeforeMs: r['notBeforeMs'] as number, notAfterMs: r['notAfterMs'] as number, firstSeenMs: r['firstSeenMs'] as number });
  }
  return { v: 1, issuer, fetchedAtMs: s['fetchedAtMs'] as number, anchors };
}

export function createMaaKeyTrust(opts: MaaKeyTrustOptions): MaaKeyTrust {
  const { policy, store } = opts;
  if (typeof opts.fetch !== 'function') throw new TypeError('createMaaKeyTrust: fetch must be injected');
  if (!Array.isArray(policy?.trustedIssuers) || policy.trustedIssuers.length === 0 || policy.trustedIssuers.some((i) => !ISSUER_URL.test(i))) {
    throw new TypeError('createMaaKeyTrust: policy.trustedIssuers must be a non-empty list of https origin URLs');
  }
  const trusted = new Set(policy.trustedIssuers);
  const ttl = policy.ttlMs ?? HOUR;
  const maxStale = policy.maxStaleMs ?? DAY;
  const maxNew = policy.maxNewKeysPerFetch ?? 2;
  const maxInitial = policy.maxInitialKeys ?? 8;
  const skew = policy.clockSkewMs ?? 60_000;
  const requireOverlap = policy.requireOverlap ?? true;
  const fail = (code: MaaKeyErrorCode, reason: string): MaaTrustResult => ({ ok: false, code, reason });

  const live = (a: MaaAnchorRecord[], nowMs: number) => a.filter((r) => nowMs - skew <= r.notAfterMs && nowMs + skew >= r.notBeforeMs);
  const build = (
    source: MaaTrustOk['source'],
    anchors: MaaAnchorRecord[],
    newKeys: string[],
    removedKeys: string[],
    rejected: MaaTrustOk['rejected'],
  ): MaaTrustResult => {
    const spkis = [...new Set(anchors.map((a) => a.spki))].sort();
    if (spkis.length === 0) return fail('no-valid-keys', 'no unexpired, un-revoked signing keys remain');
    return { ok: true, trustAnchors: { rootSpkiSha256: spkis }, source, anchors, newKeys, removedKeys, rejected };
  };

  return {
    async getTrustAnchors(issuer, { nowMs, repin }) {
      try {
        if (!trusted.has(issuer)) return fail('untrusted-issuer', 'issuer is not in policy.trustedIssuers');
        if (!Number.isSafeInteger(nowMs)) return fail('clock-regression', 'nowMs must be an integer');

        // Operator approvals / revocations (re-pin manifest).
        let approved = new Set<string>();
        let denied = new Set<string>();
        if (repin) {
          const v = verifyAllowlistManifest(repin.manifest, { ...repin.verify, nowMs });
          if (!v.ok) return fail('repin-invalid', `${v.code}: ${v.reason}`);
          const p = projectAllowlist(v, { nowMs });
          approved = new Set(p.maaSigningSpkis[issuer] ?? []);
          denied = new Set(p.revoked.filter((r) => r.kind === 'maa-signing-spki' && r.label === issuer).map((r) => r.value));
        }
        // Built-in release-signed pins (default on): the offline root of the first accepted set.
        let effPolicy: MaaKeyPolicy = policy;
        let builtinBaseline: string[] = [];
        let builtinReason: string | undefined;
        if (policy.builtinPins !== false) {
          const b = loadBuiltinMaaPins({ nowMs, ...(typeof policy.builtinPins === 'object' ? { source: policy.builtinPins } : {}) });
          if (b.ok) {
            builtinBaseline = b.maaSigningSpkis[issuer] ?? [];
            for (const r of b.revokedSigningSpkis[issuer] ?? []) denied.add(r);
            effPolicy = {
              ...policy,
              chainRootSpkiSha256: policy.chainRootSpkiSha256 ?? b.maaChainRootSpkis,
              chainIntermediateSpkiSha256: policy.chainIntermediateSpkiSha256 ?? b.maaChainIntermediateSpkis,
              chainLeafCn: policy.chainLeafCn ?? [...BUILTIN_CHAIN_LEAF_CN],
            };
            // The pinned Microsoft intermediate only counts for issuers the release actually pinned (no leak to others).
            if (builtinBaseline.length > 0) builtinBaseline = [...builtinBaseline, ...b.maaChainIntermediateSpkis];
          } else builtinReason = b.reason;
        }
        const allow = (a: MaaAnchorRecord[]) => a.filter((r) => !denied.has(r.spki));

        const rawState = await store.get(issuer);
        let state: MaaKeyState | undefined;
        if (rawState !== undefined) {
          const parsed = parseState(rawState, issuer);
          if (!parsed) return fail('corrupt-state', 'persisted MAA key state failed validation');
          state = parsed;
          if (nowMs < state.fetchedAtMs - skew) return fail('clock-regression', 'clock is behind the last persisted fetch time');
        }

        // 1. Fresh cache.
        if (state && nowMs - state.fetchedAtMs < ttl && nowMs >= state.fetchedAtMs) {
          const a = allow(live(state.anchors, nowMs));
          if (a.length > 0) return build('cache', a, [], [], []);
        }

        // 2. Refresh.
        let jwks: MaaJwks;
        try {
          jwks = await fetchMaaCerts(issuer, { fetch: opts.fetch, ...(policy.fetchTimeoutMs !== undefined ? { timeoutMs: policy.fetchTimeoutMs } : {}), ...(policy.maxBodyBytes !== undefined ? { maxBytes: policy.maxBodyBytes } : {}) });
        } catch (e) {
          const why = e instanceof Error ? e.message : 'fetch error';
          if (!state) return fail('fetch-failed', `${why}; no cached key set`);
          if (nowMs - state.fetchedAtMs > maxStale) return fail('stale-exceeded', `${why}; cached set is older than maxStaleMs`);
          const a = allow(live(state.anchors, nowMs));
          if (a.length === 0) return fail('stale-exceeded', `${why}; every cached key has expired or been revoked`);
          return build('stale-cache', a, [], [], []);
        }

        const ev = evaluateMaaJwks(jwks, issuer, effPolicy, nowMs);
        const accepted = ev.accepted.filter((r) => !denied.has(r.spki));
        if (accepted.length === 0) return fail('no-valid-keys', `no JWKS key passed validation (${ev.rejected.map((r) => `${r.kid}: ${r.reason}`).join('; ') || 'empty JWKS'})`);

        // 3. Rotation policy.
        const prevAnchors = state ? live(state.anchors, nowMs) : [];
        const baseline = new Set<string>(prevAnchors.map((a) => a.spki));
        if (!state) {
          for (const p of policy.initialPins?.[issuer] ?? []) baseline.add(p.toLowerCase());
          for (const p of builtinBaseline) baseline.add(p);
        }
        for (const p of builtinBaseline) approved.add(p);
        const acceptedSet = new Set(accepted.map((a) => a.spki));
        const approvedHere = [...acceptedSet].filter((s) => approved.has(s));
        const unapprovedNew = [...acceptedSet].filter((s) => !baseline.has(s) && !approved.has(s));
        if (baseline.size === 0) {
          if (approvedHere.length === 0 && !policy.allowTrustOnFirstUse) {
            if (builtinReason !== undefined) return fail('builtin-pins-invalid', `built-in pins unusable (${builtinReason}); no persisted state, no initialPins, no signed re-pin; refusing trust-on-first-use`);
            return fail('no-baseline', 'no persisted state, no built-in pin for this issuer, no initialPins and no signed re-pin: refusing trust-on-first-use');
          }
          if (acceptedSet.size > maxInitial && approvedHere.length < acceptedSet.size) return fail('too-many-new-keys', `initial set of ${acceptedSet.size} keys exceeds maxInitialKeys`);
        } else {
          if (unapprovedNew.length > maxNew) return fail('too-many-new-keys', `${unapprovedNew.length} new keys exceed maxNewKeysPerFetch=${maxNew}`);
          const overlap = [...acceptedSet].some((s) => baseline.has(s)) || approvedHere.length > 0;
          if (requireOverlap && !overlap) return fail('no-overlap', 'the new key set shares no key with the previous set and is not covered by a signed re-pin');
        }

        // 4. Persist (monotone fetchedAtMs) and return.
        const firstSeen = new Map((state?.anchors ?? []).map((a) => [a.spki, a.firstSeenMs] as const));
        const records: MaaAnchorRecord[] = accepted.map((a) => ({ ...a, firstSeenMs: firstSeen.get(a.spki) ?? nowMs }));
        const fetchedAtMs = state ? Math.max(state.fetchedAtMs, nowMs) : nowMs;
        await store.set(issuer, { v: 1, issuer, fetchedAtMs, anchors: records });
        const newKeys = records.filter((r) => !baseline.has(r.spki)).map((r) => r.spki);
        const removedKeys = [...baseline].filter((s) => !acceptedSet.has(s));
        return build('fetched', records, newKeys, removedKeys, ev.rejected);
      } catch (e) {
        return fail('fetch-failed', e instanceof Error ? e.message : 'unexpected error');
      }
    },
  };
}

// ───────────────────────────── multi-vantage corroboration ─────────────────────────────

/** One independent observation of `<issuer>/certs` from a named network vantage point. */
export interface MaaVantageObservation {
  /** Stable label of the vantage (e.g. `gcp-cloudbuild-us-west1`, `azure-aci-eastus`). Counted once per distinct label. */
  vantage: string;
  issuer: string;
  jwks: MaaJwks;
}

export type MaaCorroborationResult =
  | { ok: true; issuer: string; spkis: string[]; vantages: string[]; k: number }
  | { ok: false; code: 'malformed' | 'insufficient-vantages' | 'vantage-disagreement' | 'no-valid-keys'; reason: string };

/**
 * Accept a FIRST-USE key set only if at least `k` (>= 2) DISTINCT vantage points observed the same issuer and
 * ALL supplied observations validate (per `evaluateMaaJwks`) to the IDENTICAL SPKI set. Any disagreement - even
 * from a single vantage beyond the k - fails closed (a divergent view is evidence of a path attack or an
 * in-flight rotation; re-run once it settles). The result is directly usable as `initialPins[issuer]`.
 *
 * GUARANTEES only what the vantage labels honestly are: independence is the caller's claim, not proven here.
 * It defeats an attacker who controls ONE network path to the issuer, not one who controls k of them.
 */
export function corroborateMaaKeySets(
  sets: readonly MaaVantageObservation[],
  k: number,
  opts: { issuer: string; nowMs: number; policy?: Partial<MaaKeyPolicy> },
): MaaCorroborationResult {
  const bad = (code: 'malformed' | 'insufficient-vantages' | 'vantage-disagreement' | 'no-valid-keys', reason: string): MaaCorroborationResult => ({ ok: false, code, reason });
  try {
    if (!Number.isSafeInteger(k) || k < 2) return bad('malformed', 'k must be an integer >= 2');
    if (!ISSUER_URL.test(opts?.issuer) || !Number.isSafeInteger(opts.nowMs)) return bad('malformed', 'issuer/nowMs invalid');
    if (!Array.isArray(sets)) return bad('malformed', 'sets must be an array');
    const policy: MaaKeyPolicy = { trustedIssuers: [opts.issuer], ...opts.policy };
    const byVantage = new Map<string, string>();
    for (const o of sets) {
      if (typeof o?.vantage !== 'string' || o.vantage.length === 0 || o.vantage.length > 100) return bad('malformed', 'vantage label must be a non-empty string');
      if (o.issuer !== opts.issuer) return bad('malformed', `observation from '${o.vantage}' is for a different issuer`);
      const ev = evaluateMaaJwks(o.jwks, opts.issuer, policy, opts.nowMs);
      if (ev.accepted.length === 0) return bad('no-valid-keys', `vantage '${o.vantage}' observed no valid key (${ev.rejected.map((r) => r.reason).join('; ') || 'empty'})`);
      const fp = ev.accepted.map((a) => a.spki).sort().join(',');
      const prior = byVantage.get(o.vantage);
      if (prior !== undefined && prior !== fp) return bad('vantage-disagreement', `vantage '${o.vantage}' supplied two different key sets`);
      byVantage.set(o.vantage, fp);
    }
    if (byVantage.size < k) return bad('insufficient-vantages', `${byVantage.size} distinct vantage(s) < k=${k}`);
    const distinct = new Set(byVantage.values());
    if (distinct.size !== 1) {
      return bad('vantage-disagreement', `vantages disagree: ${[...byVantage.entries()].map(([v, f]) => `${v}=${f.split(',').map((x) => x.slice(0, 8)).join('+')}`).join(' | ')}`);
    }
    const spkis = [...distinct][0]!.split(',');
    return { ok: true, issuer: opts.issuer, spkis, vantages: [...byVantage.keys()].sort(), k };
  } catch (e) {
    return bad('malformed', e instanceof Error ? e.message : 'corroboration error');
  }
}

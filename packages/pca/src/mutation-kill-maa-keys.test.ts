/**
 * Mutation-kill suite for attest-maa-keys.ts: the guarded fetch, JWKS evaluation (real MAA certs plus minted ones), the trust state machine
 * (cache / refresh / rotation / re-pin / built-in pins) and multi-vantage corroboration.
 */
import * as crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import type { MaaKeyPolicy, MaaKeyState, MaaKeyStateStore, MaaRepin, MaaTrustResult } from './attest-maa-keys';
import { signAllowlistManifest, type AllowlistEntry, type AllowlistIssuerKey } from './attest-allowlist';
import { parseMaaJwt, type MaaJwks } from './attest-azure-maa';
import { createMemoryDurableKv } from './durable-state';
import { b64u } from './hash';
import { generateKeyPair } from './keys';


// The module under test is loaded lazily from INSIDE the tests so that Stryker attributes its load-time (static) coverage to the first
// test below, which exercises every module-level constant.
type Keys = typeof import('./attest-maa-keys');
const mod = (): Promise<Keys> => import('./attest-maa-keys');
const corroborateMaaKeySets: Keys['corroborateMaaKeySets'] = (...a) => loaded!.corroborateMaaKeySets(...a);
let loaded: Keys | undefined;
const createMaaKeyTrust: Keys['createMaaKeyTrust'] = (...a) => loaded!.createMaaKeyTrust(...a);
const createMemoryMaaKeyStateStore: Keys['createMemoryMaaKeyStateStore'] = (...a) => loaded!.createMemoryMaaKeyStateStore(...a);
const durableMaaKeyStateStore: Keys['durableMaaKeyStateStore'] = (...a) => loaded!.durableMaaKeyStateStore(...a);
const evaluateMaaJwks: Keys['evaluateMaaJwks'] = (...a) => loaded!.evaluateMaaJwks(...a);
const fetchMaaCerts: Keys['fetchMaaCerts'] = (...a) => loaded!.fetchMaaCerts(...a);

// ── real fixtures ─────────────────────────────────────────────────────────────────────────────────
const FIX = (f: string) => resolve(__dirname, '..', 'fixtures', 'real-azure-maa', f);
const JWKS = JSON.parse(readFileSync(FIX('maa-signing-certs.json'), 'utf8')) as MaaJwks;
const TOKEN = readFileSync(FIX('pcabound-tdxvm-token.jwt'), 'utf8').trim();
const ISSUER = 'https://sharedwus.wus.attest.azure.net';
const NOW = ((parseMaaJwt(TOKEN).payload as Record<string, unknown>)['iat'] as number) * 1000 + 3_600_000;
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const spkiOfCert = (c: crypto.X509Certificate) => crypto.createHash('sha256').update(new Uint8Array(c.publicKey.export({ type: 'spki', format: 'der' }))).digest('hex');
const certAt = (k: number, i = 0) => new crypto.X509Certificate(Buffer.from(JWKS.keys[k]!.x5c![i]!, 'base64'));
const SPKI_A = spkiOfCert(certAt(0));
const SPKI_B = spkiOfCert(certAt(3));
const MS_ROOT_SPKI = spkiOfCert(certAt(1, 2));
const MS_MID_SPKI = spkiOfCert(certAt(1, 1));
const JWKS_A: MaaJwks = { keys: [JWKS.keys[0]!] };
const JWKS_B: MaaJwks = { keys: [JWKS.keys[3]!] };
const JWKS_AB: MaaJwks = { keys: [JWKS.keys[0]!, JWKS.keys[3]!] };

// ── DER minter with real signatures (any key type) ───────────────────────────────────────────────
const cat = (...a: Uint8Array[]) => {
  const out = new Uint8Array(a.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of a) {
    out.set(x, o);
    o += x.length;
  }
  return out;
};
const derLen = (n: number) => {
  if (n < 0x80) return Uint8Array.from([n]);
  const b: number[] = [];
  for (let x = n; x > 0; x = Math.floor(x / 256)) b.unshift(x & 0xff);
  return Uint8Array.from([0x80 | b.length, ...b]);
};
const tlv = (tag: number, c: Uint8Array) => cat(Uint8Array.from([tag]), derLen(c.length), c);
const seq = (...i: Uint8Array[]) => tlv(0x30, cat(...i));
const set = (...i: Uint8Array[]) => tlv(0x31, cat(...i));
const int = (v: number) => tlv(0x02, Uint8Array.from([v]));
const oidOf = (d: string) => {
  const a = d.split('.').map(Number);
  const body: number[] = [a[0]! * 40 + a[1]!];
  for (const x of a.slice(2)) {
    const st = [x & 0x7f];
    for (let v = Math.floor(x / 128); v > 0; v = Math.floor(v / 128)) st.unshift((v & 0x7f) | 0x80);
    body.push(...st);
  }
  return tlv(0x06, Uint8Array.from(body));
};
const utc = (ms: number) => {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, '0');
  return tlv(0x17, new Uint8Array(Buffer.from(`${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`, 'ascii')));
};
const OID_CN = '2.5.4.3';
const OID_O = '2.5.4.10';
type Rdn = readonly [string, string];
const name = (rdns: readonly Rdn[]) => seq(...rdns.map(([o, v]) => set(seq(oidOf(o), tlv(0x0c, new Uint8Array(Buffer.from(v)))))));
interface Signer {
  priv: crypto.KeyObject;
}
const sigAlgOf = (priv: crypto.KeyObject): Uint8Array => {
  const t = priv.asymmetricKeyType;
  if (t === 'rsa') return seq(oidOf('1.2.840.113549.1.1.11'), Uint8Array.from([5, 0]));
  if (t === 'ed25519') return seq(oidOf('1.3.101.112'));
  return seq(oidOf('1.2.840.10045.4.3.2'));
};
interface CertSpec {
  subject: readonly Rdn[];
  issuer: readonly Rdn[];
  spki: Uint8Array;
  signer: Signer;
  notBefore: number;
  notAfter: number;
}
const mkCert = (s: CertSpec): Uint8Array => {
  const alg = sigAlgOf(s.signer.priv);
  const tbs = seq(tlv(0xa0, int(2)), int(0x2a), alg, name(s.issuer), seq(utc(s.notBefore), utc(s.notAfter)), name(s.subject), s.spki);
  const sig = s.signer.priv.asymmetricKeyType === 'ed25519' ? crypto.sign(null, Buffer.from(tbs), s.signer.priv) : crypto.sign('sha256', Buffer.from(tbs), s.signer.priv);
  return seq(tbs, alg, tlv(0x03, cat(Uint8Array.from([0]), new Uint8Array(sig))));
};
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
interface KP {
  pub: crypto.KeyObject;
  priv: crypto.KeyObject;
  spki: Uint8Array;
  spkiSha: string;
}
const wrapKp = (pub: crypto.KeyObject, priv: crypto.KeyObject): KP => {
  const spki = new Uint8Array(pub.export({ type: 'spki', format: 'der' }));
  return { pub, priv, spki, spkiSha: crypto.createHash('sha256').update(Buffer.from(spki)).digest('hex') };
};
const ecKp = (curve = 'P-256') => {
  const k = crypto.generateKeyPairSync('ec', { namedCurve: curve });
  return wrapKp(k.publicKey, k.privateKey);
};
const rsaKp = (bits = 2048) => {
  const k = crypto.generateKeyPairSync('rsa', { modulusLength: bits });
  return wrapKp(k.publicKey, k.privateKey);
};
const edKp = () => {
  const k = crypto.generateKeyPairSync('ed25519');
  return wrapKp(k.publicKey, k.privateKey);
};
/** A self-signed instance certificate for `issuer` (CN = issuer), valid around NOW. */
const selfSigned = (kp: KP, o: { cn?: string; extraRdn?: Rdn[]; notBefore?: number; notAfter?: number } = {}) => {
  const subj: Rdn[] = [...(o.cn === undefined ? [[OID_CN, ISSUER] as Rdn] : [[OID_CN, o.cn] as Rdn]), ...(o.extraRdn ?? [])];
  return mkCert({ subject: subj, issuer: subj, spki: kp.spki, signer: kp, notBefore: o.notBefore ?? NOW - 30 * DAY, notAfter: o.notAfter ?? NOW + 300 * DAY });
};
const jwk = (certs: Uint8Array[], kid?: string) => ({ ...(kid ? { kid } : {}), kty: 'RSA', x5c: certs.map(b64) });
const fabricatedRsaSpki = (bits: number): Uint8Array => {
  const bytes = Math.ceil(bits / 8);
  const n = new Uint8Array(bytes);
  n.fill(0xab);
  n[0] = bits % 8 === 0 ? 0x80 : 1 << ((bits % 8) - 1);
  n[bytes - 1] = 0xab;
  const modulus = tlv(0x02, cat(Uint8Array.from([0]), n));
  const rsaKey = seq(modulus, int(3)).slice();
  const inner = seq(modulus, tlv(0x02, Uint8Array.from([1, 0, 1])));
  void rsaKey;
  return seq(seq(oidOf('1.2.840.113549.1.1.1'), Uint8Array.from([5, 0])), tlv(0x03, cat(Uint8Array.from([0]), inner)));
};

// ── policy / fetch helpers ───────────────────────────────────────────────────────────────────────
const respond = (j: unknown, init: ResponseInit = { status: 200 }) => new Response(typeof j === 'string' ? j : JSON.stringify(j), init);
type Step = MaaJwks | Error | (() => Response) | Record<string, unknown>;
function fetchOf(seqSteps: Step[]) {
  let i = 0;
  const calls: { url: string; init: RequestInit | undefined }[] = [];
  const f = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init });
    const step = seqSteps[Math.min(i++, seqSteps.length - 1)]!;
    if (step instanceof Error) throw step;
    if (typeof step === 'function') return step();
    return respond(step);
  }) as typeof fetch;
  return { f, calls };
}
const basePolicy = (over: Partial<MaaKeyPolicy> = {}): MaaKeyPolicy => ({ trustedIssuers: [ISSUER], allowTrustOnFirstUse: true, builtinPins: false, ...over });
function trust(steps: Step[], over: Partial<MaaKeyPolicy> = {}, store: MaaKeyStateStore & { snapshot?: () => Map<string, MaaKeyState> } = createMemoryMaaKeyStateStore()) {
  const { f, calls } = fetchOf(steps);
  return { t: createMaaKeyTrust({ policy: basePolicy(over), store, fetch: f }), store: store as ReturnType<typeof createMemoryMaaKeyStateStore>, calls };
}
const code = (r: MaaTrustResult) => (r.ok ? 'ok' : r.code);
const spkis = (r: MaaTrustResult) => (r.ok ? r.trustAnchors.rootSpkiSha256 : `${r.code}: ${r.reason}`);
const reasonOf = (r: MaaTrustResult) => (r.ok ? 'ok' : r.reason);


beforeEach(async () => {
  loaded ??= await mod();
});

describe('module-level tables and defaults (first test: owns the load-time coverage)', () => {
  it('limits, patterns, curve allowlist, hex pattern and the hour/day defaults', async () => {
    loaded = await mod();
    // MAX_JWKS_KEYS = 32, MAX_X5C = 8, MAX_X5C_B64 = 131072
    const tiny = 'QQ==';
    const run = (j: unknown) => fetchMaaCerts(ISSUER, { fetch: fetchOf([() => respond(j)]).f });
    await expect(run({ keys: Array.from({ length: 33 }, () => ({ x5c: [tiny] })) })).rejects.toThrow('MAA certs: too many keys');
    expect((await run({ keys: Array.from({ length: 32 }, () => ({ x5c: [tiny] })) })).keys.length).toBe(32);
    await expect(run({ keys: [{ x5c: Array.from({ length: 9 }, () => tiny) }] })).rejects.toThrow('MAA certs: key without a well-formed x5c');
    expect((await run({ keys: [{ x5c: Array.from({ length: 8 }, () => tiny) }] })).keys[0]!.x5c!.length).toBe(8);
    await expect(run({ keys: [{ x5c: ['a'.repeat(131_073)] }] })).rejects.toThrow('MAA certs: key without a well-formed x5c');
    expect((await run({ keys: [{ x5c: ['a'.repeat(131_072)] }] })).keys.length).toBe(1);
    // ISSUER_URL
    for (const bad of ['http://a.example', 'https://a.example/', 'https://A.example', 'https://a.example:123456', 'https://.a.example', 'https://a.example-', 'https://', 'xhttps://a.example', ' https://a.example']) await expect(fetchMaaCerts(bad, { fetch: fetchOf([JWKS]).f }), bad).rejects.toThrow(/issuer must be an https origin URL/);
    for (const ok of ['https://a', 'https://a-b.example:8443', 'https://a1.b2:1']) expect((await fetchMaaCerts(ok, { fetch: fetchOf([JWKS]).f })).keys.length, ok).toBe(4);
    // EC_CURVES
    for (const curve of ['P-256', 'P-384', 'P-521']) expect(evaluateMaaJwks({ keys: [jwk([selfSigned(ecKp(curve))])] }, ISSUER, basePolicy(), NOW).accepted.length, curve).toBe(1);
    expect(evaluateMaaJwks({ keys: [jwk([selfSigned(ecKp('secp256k1'))], 'k')] }, ISSUER, basePolicy(), NOW).rejected[0]!.reason).toBe("EC curve 'secp256k1' not allowed");
    // HEX64 (persisted-state validation)
    const { t, store } = trust([JWKS_A]);
    await store.set(ISSUER, { v: 1, issuer: ISSUER, fetchedAtMs: NOW, anchors: [{ spki: SPKI_A.toUpperCase(), kind: 'self-signed', notBeforeMs: 1, notAfterMs: 2, firstSeenMs: 3 }] });
    expect(code(await t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('corrupt-state');
    for (const spki of [`zz${SPKI_A}`, `${SPKI_A}zz`, `\n${SPKI_A}`]) {
      await store.set(ISSUER, { v: 1, issuer: ISSUER, fetchedAtMs: NOW, anchors: [{ spki, kind: 'self-signed', notBeforeMs: 1, notAfterMs: 2, firstSeenMs: 3 }] });
      expect(code(await t.getTrustAnchors(ISSUER, { nowMs: NOW })), spki).toBe('corrupt-state');
    }
    // HOUR / DAY defaults: one-hour cache, 24-hour staleness, 400-day key age
    const d = trust([JWKS_A, new Error('down')]);
    await d.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect((await d.t.getTrustAnchors(ISSUER, { nowMs: NOW + HOUR - 1 })).ok && d.calls.length).toBe(1);
    expect((await d.t.getTrustAnchors(ISSUER, { nowMs: NOW + DAY })).ok).toBe(true);
    expect(code(await d.t.getTrustAnchors(ISSUER, { nowMs: NOW + DAY + 1 }))).toBe('stale-exceeded');
    const nb = Math.floor(NOW / 1000) * 1000 - 400 * DAY;
    const old = jwk([selfSigned(ecKp(), { notBefore: nb, notAfter: NOW + 100 * DAY })], 'old');
    expect(evaluateMaaJwks({ keys: [old] }, ISSUER, basePolicy(), NOW).accepted.length).toBe(1);
    expect(evaluateMaaJwks({ keys: [old] }, ISSUER, basePolicy(), NOW + 1000).accepted.length).toBe(0);
    // the 1 MiB default body limit
    const big = (n: number) => () => ({ ok: true, status: 200, url: '', headers: new Headers(), body: null, arrayBuffer: async () => new Uint8Array(n).buffer }) as unknown as Response;
    await expect(fetchMaaCerts(ISSUER, { fetch: fetchOf([big(1_048_577)]).f })).rejects.toThrow(/exceeds the size limit/);
  });
});

// ═════════════════════════════════════════ fetchMaaCerts ═════════════════════════════════════════
describe('fetchMaaCerts', () => {
  const j1 = (certB64: string) => ({ keys: [{ kid: 'k', kty: 'RSA', alg: 'RS256', x5c: [certB64] }] });
  it('input guards and the request it makes', async () => {
    await expect(fetchMaaCerts(ISSUER, { fetch: undefined as never })).rejects.toThrow(new TypeError('fetchMaaCerts: a fetch implementation must be injected'));
    await expect(fetchMaaCerts(ISSUER, undefined as never)).rejects.toThrow(new TypeError('fetchMaaCerts: a fetch implementation must be injected'));
    const bad = new TypeError('fetchMaaCerts: issuer must be an https origin URL (no path, no trailing slash)');
    for (const iss of ['http://a.example', 'https://a.example/', 'https://a.example/x', 'https://', 'a.example', 'https://A.example', 'https://a.example:123456', 'https://.a.example', 'https://a.example-']) {
      await expect(fetchMaaCerts(iss, { fetch: fetchOf([JWKS]).f }), iss).rejects.toThrow(bad);
    }
    const { f, calls } = fetchOf([JWKS]);
    await fetchMaaCerts('https://a-b.example:8443', { fetch: f });
    expect(calls.length).toBe(1);
    expect(calls[0]!.url).toBe('https://a-b.example:8443/certs');
    expect(calls[0]!.init).toMatchObject({ redirect: 'error', headers: { accept: 'application/json' } });
    expect(calls[0]!.init!.signal).toBeInstanceOf(AbortSignal);
  });
  it('HTTP status, redirects, declared and streamed size', async () => {
    await expect(fetchMaaCerts(ISSUER, { fetch: fetchOf([() => new Response('x', { status: 503 })]).f })).rejects.toThrow(new Error('MAA certs fetch failed: HTTP 503'));
    const redirected = (url: string) => () => {
      const r = respond(JWKS);
      Object.defineProperty(r, 'url', { value: url });
      return r;
    };
    await expect(fetchMaaCerts(ISSUER, { fetch: fetchOf([redirected('https://evil.example/certs')]).f })).rejects.toThrow(new Error('MAA certs fetch: response URL differs from the request (redirect)'));
    expect((await fetchMaaCerts(ISSUER, { fetch: fetchOf([redirected(`${ISSUER}/certs`)]).f })).keys.length).toBe(4);
    expect((await fetchMaaCerts(ISSUER, { fetch: fetchOf([redirected('')]).f })).keys.length).toBe(4); // an empty url is "unknown", not a redirect
    const body = JSON.stringify(JWKS);
    const exact = Buffer.byteLength(body);
    const lim = new Error('MAA certs response exceeds the size limit');
    await expect(fetchMaaCerts(ISSUER, { fetch: fetchOf([() => respond(body)]).f, maxBytes: exact - 1 })).rejects.toThrow(lim);
    expect((await fetchMaaCerts(ISSUER, { fetch: fetchOf([() => respond(body)]).f, maxBytes: exact })).keys.length).toBe(4);
    // declared content-length is trusted only as an upper bound
    const declared = (n: string) => () => respond(body, { status: 200, headers: { 'content-length': n } });
    await expect(fetchMaaCerts(ISSUER, { fetch: fetchOf([declared(String(exact + 1))]).f, maxBytes: exact })).rejects.toThrow(lim);
    expect((await fetchMaaCerts(ISSUER, { fetch: fetchOf([declared(String(exact))]).f, maxBytes: exact })).keys.length).toBe(4);
    expect((await fetchMaaCerts(ISSUER, { fetch: fetchOf([declared('abc')]).f })).keys.length).toBe(4);
    // body streamed beyond the limit with no declared length: the reader is cancelled
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new Uint8Array(60));
        c.enqueue(new Uint8Array(60));
      },
      cancel() {
        cancelled = true;
      },
    });
    await expect(fetchMaaCerts(ISSUER, { fetch: fetchOf([() => new Response(stream)]).f, maxBytes: 100 })).rejects.toThrow(lim);
    expect(cancelled).toBe(true);
    // exactly at the limit is fine for the streaming reader
    const okStream = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new TextEncoder().encode(body.slice(0, 50)));
        c.enqueue(new TextEncoder().encode(body.slice(50)));
        c.close();
      },
    });
    expect((await fetchMaaCerts(ISSUER, { fetch: fetchOf([() => new Response(okStream)]).f, maxBytes: exact })).keys.length).toBe(4);
    // no stream at all: the buffered path enforces the limit too
    const buffered = (n: number) => () => ({ ok: true, status: 200, url: '', headers: new Headers(), body: null, arrayBuffer: async () => new Uint8Array(n).buffer }) as unknown as Response;
    await expect(fetchMaaCerts(ISSUER, { fetch: fetchOf([buffered(11)]).f, maxBytes: 10 })).rejects.toThrow(lim);
    await expect(fetchMaaCerts(ISSUER, { fetch: fetchOf([buffered(10)]).f, maxBytes: 10 })).rejects.toThrow(/valid UTF-8 JSON/);
  });
  it('responses without headers / without a stream reader are handled; invalid UTF-8 is refused even inside a JSON string', async () => {
    const body = JSON.stringify(JWKS);
    const bare = (extra: Record<string, unknown>) => () => ({ ok: true, status: 200, url: '', arrayBuffer: async () => new TextEncoder().encode(body).buffer, ...extra }) as unknown as Response;
    expect((await fetchMaaCerts(ISSUER, { fetch: fetchOf([bare({})]).f })).keys.length).toBe(4); // no headers object at all
    expect((await fetchMaaCerts(ISSUER, { fetch: fetchOf([bare({ headers: {} })]).f })).keys.length).toBe(4); // headers without get()
    expect((await fetchMaaCerts(ISSUER, { fetch: fetchOf([bare({ headers: new Headers(), body: {} })]).f })).keys.length).toBe(4); // a body without getReader
    const lenient = new Uint8Array([...new TextEncoder().encode('{"keys":[],"note":"'), 0xff, ...new TextEncoder().encode('"}')]);
    await expect(fetchMaaCerts(ISSUER, { fetch: fetchOf([() => new Response(lenient)]).f })).rejects.toThrow(new Error('MAA certs response is not valid UTF-8 JSON'));
    const ok = new TextEncoder().encode('{"keys":[],"note":"é"}');
    expect((await fetchMaaCerts(ISSUER, { fetch: fetchOf([() => new Response(ok)]).f })).keys).toEqual([]);
  });
  it('the timeout timer is cancelled once the fetch settles', async () => {
    let signal: AbortSignal | undefined;
    const quick = (async (_u: string, init?: RequestInit) => {
      signal = init?.signal as AbortSignal;
      return respond(JWKS);
    }) as unknown as typeof fetch;
    await fetchMaaCerts(ISSUER, { fetch: quick, timeoutMs: 40 });
    await new Promise((r) => setTimeout(r, 120));
    expect(signal!.aborted).toBe(false);
    const failing = (async (_u: string, init?: RequestInit) => {
      signal = init?.signal as AbortSignal;
      return new Response('x', { status: 500 });
    }) as unknown as typeof fetch;
    await expect(fetchMaaCerts(ISSUER, { fetch: failing, timeoutMs: 40 })).rejects.toThrow(/HTTP 500/);
    await new Promise((r) => setTimeout(r, 120));
    expect(signal!.aborted).toBe(false);
  });
  it('the default size limit is 1 MiB', async () => {
    const mk = (n: number) => () => ({ ok: true, status: 200, url: '', headers: new Headers(), body: null, arrayBuffer: async () => new Uint8Array(n).buffer }) as unknown as Response;
    await expect(fetchMaaCerts(ISSUER, { fetch: fetchOf([mk(1_048_577)]).f })).rejects.toThrow(/exceeds the size limit/);
    await expect(fetchMaaCerts(ISSUER, { fetch: fetchOf([mk(1_048_576)]).f })).rejects.toThrow(/valid UTF-8 JSON/);
  });
  it('UTF-8 / JSON strictness', async () => {
    const m = new Error('MAA certs response is not valid UTF-8 JSON');
    await expect(fetchMaaCerts(ISSUER, { fetch: fetchOf([() => new Response('not json')]).f })).rejects.toThrow(m);
    await expect(fetchMaaCerts(ISSUER, { fetch: fetchOf([() => new Response(new Uint8Array([0xff, 0xfe, 0x7b]))]).f })).rejects.toThrow(m);
  });
  it('timeout aborts the request', async () => {
    let signal: AbortSignal | undefined;
    const never = (async (_u: string, init?: RequestInit) => {
      signal = init?.signal as AbortSignal;
      return new Promise<Response>(() => undefined);
    }) as unknown as typeof fetch;
    await expect(fetchMaaCerts(ISSUER, { fetch: never, timeoutMs: 20 })).rejects.toThrow(new Error('MAA certs fetch timed out after 20 ms'));
    expect(signal!.aborted).toBe(true);
  });
  it('JWKS shape rules', async () => {
    const run = (j: unknown) => fetchMaaCerts(ISSUER, { fetch: fetchOf([() => respond(j)]).f });
    const real = JWKS.keys[0]!.x5c![0]!;
    await expect(run(null)).rejects.toThrow(new Error('MAA certs: response has no keys array'));
    await expect(run({ keys: 'x' })).rejects.toThrow(new Error('MAA certs: response has no keys array'));
    await expect(run({})).rejects.toThrow(new Error('MAA certs: response has no keys array'));
    await expect(run('"str"')).rejects.toThrow(new Error('MAA certs: response has no keys array'));
    const tiny = 'QQ==';
    await expect(run({ keys: Array.from({ length: 33 }, () => ({ x5c: [tiny] })) })).rejects.toThrow(new Error('MAA certs: too many keys'));
    expect((await run({ keys: Array.from({ length: 32 }, () => ({ x5c: [tiny] })) })).keys.length).toBe(32);
    for (const k of [null, 5, 'x']) await expect(run({ keys: [k] })).rejects.toThrow(new Error('MAA certs: malformed key entry'));
    const bad = new Error('MAA certs: key without a well-formed x5c');
    for (const x5c of [undefined, [], 'x', Array.from({ length: 9 }, () => tiny), [5], [''], ['a'.repeat(131_073)], [tiny, '']]) await expect(run({ keys: [{ kid: 'a', x5c }] }), JSON.stringify(x5c)?.slice(0, 40)).rejects.toThrow(bad);
    expect((await run({ keys: [{ x5c: Array.from({ length: 8 }, () => tiny) }] })).keys[0]!.x5c!.length).toBe(8);
    expect((await run({ keys: [{ x5c: ['a'.repeat(131_072)] }] })).keys.length).toBe(1);
    expect(await run(j1(real))).toStrictEqual({ keys: [{ kid: 'k', kty: 'RSA', alg: 'RS256', x5c: [real] }] });
    expect(await run({ keys: [{ kid: 5, kty: 5, alg: 5, x5c: [real], extra: 1 }] })).toStrictEqual({ keys: [{ x5c: [real] }] });
  });
});

// ═════════════════════════════════════════ stores ═════════════════════════════════════════
describe('state stores', () => {
  const st = (fetchedAtMs: number, issuer = ISSUER): MaaKeyState => ({ v: 1, issuer, fetchedAtMs, anchors: [{ spki: 'a'.repeat(64), kind: 'self-signed', notBeforeMs: 1, notAfterMs: 2, firstSeenMs: 3 }] });
  it('the memory store copies on write and snapshots', async () => {
    const s = createMemoryMaaKeyStateStore();
    expect(await s.get(ISSUER)).toBeUndefined();
    const original = st(5);
    await s.set(ISSUER, original);
    original.anchors[0]!.spki = 'mutated';
    expect((await s.get(ISSUER))!.anchors[0]!.spki).toBe('a'.repeat(64));
    expect([...s.snapshot().keys()]).toEqual([ISSUER]);
    s.snapshot().delete(ISSUER);
    expect(await s.get(ISSUER)).toBeDefined();
  });
  it('the durable store keys by issuer and never moves fetchedAtMs backwards', async () => {
    const kv = createMemoryDurableKv();
    const s = durableMaaKeyStateStore(kv);
    expect(await s.get(ISSUER)).toBeUndefined();
    await s.set(ISSUER, st(100));
    expect(await kv.get(`maa-keys/${ISSUER}`)).toEqual(st(100));
    expect(await s.get(ISSUER)).toEqual(st(100));
    await s.set(ISSUER, st(50)); // older: ignored
    expect(((await s.get(ISSUER)) as MaaKeyState).fetchedAtMs).toBe(100);
    const sameTimeOther: MaaKeyState = { ...st(100), anchors: [{ spki: 'b'.repeat(64), kind: 'chained-root', notBeforeMs: 5, notAfterMs: 6, firstSeenMs: 7 }] };
    await s.set(ISSUER, sameTimeOther); // equal fetchedAtMs: the newer write wins
    expect(await s.get(ISSUER)).toEqual(sameTimeOther);
    await s.set(ISSUER, st(200));
    expect(((await s.get(ISSUER)) as MaaKeyState).fetchedAtMs).toBe(200);
    // a corrupt previous record is replaced; one for another issuer does not count
    await kv.set(`maa-keys/${ISSUER}`, { junk: true });
    await s.set(ISSUER, st(10));
    expect(((await s.get(ISSUER)) as MaaKeyState).fetchedAtMs).toBe(10);
    await kv.set(`maa-keys/${ISSUER}`, st(999, 'https://other.example'));
    await s.set(ISSUER, st(1));
    expect(((await s.get(ISSUER)) as MaaKeyState).fetchedAtMs).toBe(1);
  });
});

// ═════════════════════════════════════════ evaluateMaaJwks ═════════════════════════════════════════
describe('evaluateMaaJwks: self-signed instance certificates', () => {
  const ev = (keys: unknown[], over: Partial<MaaKeyPolicy> = {}, now = NOW, issuer = ISSUER) => evaluateMaaJwks({ keys } as never, issuer, basePolicy(over), now);
  const rejectedWith = (keys: unknown[], over: Partial<MaaKeyPolicy> = {}, now = NOW) => ev(keys, over, now).rejected.map((r) => `${r.kid}: ${r.reason}`);
  it('accepts a good cert and reports its validity window', () => {
    const kp = ecKp();
    const c = selfSigned(kp);
    const r = ev([jwk([c], 'k1')]);
    expect(r.rejected).toEqual([]);
    expect(r.accepted).toEqual([{ spki: kp.spkiSha, kind: 'self-signed', notBeforeMs: NOW - 30 * DAY, notAfterMs: NOW + 300 * DAY }]);
    const x = new crypto.X509Certificate(Buffer.from(c));
    expect(r.accepted[0]!.notBeforeMs).toBe(Date.parse(x.validFrom));
    expect(r.accepted[0]!.notAfterMs).toBe(Date.parse(x.validTo));
  });
  it('real instance certs; a missing/empty jwks; duplicate certs collapse', () => {
    expect(evaluateMaaJwks(JWKS, ISSUER, basePolicy(), NOW).accepted.map((a) => a.spki).sort()).toEqual([SPKI_A, SPKI_B].sort());
    expect(evaluateMaaJwks(undefined as never, ISSUER, basePolicy(), NOW)).toEqual({ accepted: [], rejected: [] });
    expect(evaluateMaaJwks({} as never, ISSUER, basePolicy(), NOW)).toEqual({ accepted: [], rejected: [] });
    expect(evaluateMaaJwks({ keys: [] }, ISSUER, basePolicy(), NOW)).toEqual({ accepted: [], rejected: [] });
    const kp = ecKp();
    const c = selfSigned(kp);
    expect(ev([jwk([c]), jwk([c])]).accepted.length).toBe(1);
  });
  it('kid labels: the kid, or #<index>', () => {
    const r = ev([{ x5c: [] }, { kid: 'named', x5c: [] }, { kid: 'k', x5c: 'x' }]);
    expect(r.rejected).toEqual([
      { kid: '#0', reason: 'no x5c' },
      { kid: 'named', reason: 'no x5c' },
      { kid: 'k', reason: 'no x5c' },
    ]);
    expect(rejectedWith([{ kid: 'z' }])).toEqual(['z: no x5c']);
  });
  it('unparseable certificates carry the parser message; non-Error throws become "invalid key"', () => {
    const r = ev([{ kid: 'bad', x5c: ['bm90IGEgY2VydA=='] }]);
    expect(r.rejected.length).toBe(1);
    expect(r.rejected[0]!.kid).toBe('bad');
    expect(r.rejected[0]!.reason.length).toBeGreaterThan(3);
    expect(r.rejected[0]!.reason).not.toBe('invalid key');
  });
  it('validity: both ends, with the default 60 s skew and a custom skew', () => {
    const kp = ecKp();
    const nb = Math.floor(NOW / 1000) * 1000 - 30 * DAY;
    const na = nb + 100 * DAY;
    const c = selfSigned(kp, { notBefore: nb, notAfter: na });
    const k = [jwk([c], 'v')];
    expect(ev(k, {}, nb).accepted.length).toBe(1);
    expect(ev(k, {}, nb - 60_000).accepted.length).toBe(1); // within the default skew
    expect(rejectedWith(k, {}, nb - 60_001)).toEqual(['v: cert 0: not yet valid']);
    expect(ev(k, {}, na).accepted.length).toBe(1);
    expect(ev(k, {}, na + 60_000).accepted.length).toBe(1);
    expect(rejectedWith(k, {}, na + 60_001)).toEqual(['v: cert 0: expired']);
    expect(ev(k, { clockSkewMs: 0 }, nb - 1).accepted.length).toBe(0);
    expect(ev(k, { clockSkewMs: 0 }, nb).accepted.length).toBe(1);
    expect(ev(k, { clockSkewMs: 0 }, na + 1).accepted.length).toBe(0);
    expect(ev(k, { clockSkewMs: 5000 }, nb - 5000).accepted.length).toBe(1);
    expect(ev(k, { clockSkewMs: 5000 }, nb - 5001).accepted.length).toBe(0);
    expect(ev(k, { clockSkewMs: 5000 }, na + 5000).accepted.length).toBe(1);
    expect(ev(k, { clockSkewMs: 5000 }, na + 5001).accepted.length).toBe(0);
  });
  it('maximum key age', () => {
    const kp = ecKp();
    const nb = Math.floor(NOW / 1000) * 1000 - 400 * DAY;
    const c = selfSigned(kp, { notBefore: nb, notAfter: NOW + 100 * DAY });
    const k = [jwk([c], 'old')];
    expect(ev(k).accepted.length).toBe(1); // exactly 400 days
    expect(rejectedWith(k, {}, NOW + 1000)).toEqual(['old: key older than maxKeyAgeMs']);
    expect(ev(k, { maxKeyAgeMs: 400 * DAY }, NOW).accepted.length).toBe(1);
    expect(ev(k, { maxKeyAgeMs: 400 * DAY - 1 }, NOW).accepted.length).toBe(0);
    expect(ev(k, { maxKeyAgeMs: 401 * DAY }, NOW + 1000).accepted.length).toBe(1);
  });
  it('subject rules: single CN equal to the issuer, no wildcards, genuinely self-signed', () => {
    const kp = ecKp();
    const bad = (c: Uint8Array, why: string) => expect(rejectedWith([jwk([c], 'x')])).toEqual([`x: ${why}`]);
    bad(selfSigned(kp, { extraRdn: [[OID_O, 'Org']] }), 'subject is not a single CN');
    bad(mkCert({ subject: [[OID_O, 'only-org']], issuer: [[OID_O, 'only-org']], spki: kp.spki, signer: kp, notBefore: NOW - DAY, notAfter: NOW + DAY }), 'subject is not a single CN');
    bad(selfSigned(kp, { cn: '*.attest.azure.net' }), 'wildcard CN rejected');
    bad(selfSigned(kp, { cn: 'https://sharedeus.eus.attest.azure.net' }), 'subject CN does not equal the issuer URL');
    bad(selfSigned(kp, { cn: `${ISSUER}/` }), 'subject CN does not equal the issuer URL');
    // issuer differs from subject
    const other = ecKp();
    bad(mkCert({ subject: [[OID_CN, ISSUER]], issuer: [[OID_CN, 'someone else']], spki: kp.spki, signer: kp, notBefore: NOW - DAY, notAfter: NOW + DAY }), 'not a genuine self-signed cert');
    // right names, wrong signing key
    bad(mkCert({ subject: [[OID_CN, ISSUER]], issuer: [[OID_CN, ISSUER]], spki: kp.spki, signer: other, notBefore: NOW - DAY, notAfter: NOW + DAY }), 'not a genuine self-signed cert');
    expect(ev([jwk([selfSigned(kp)])]).accepted.length).toBe(1);
    // a single RDN whose VALUE merely looks like "CN=<issuer>" is not a CN
    const ou = mkCert({ subject: [['2.5.4.11', `CN=${ISSUER}`]], issuer: [['2.5.4.11', `CN=${ISSUER}`]], spki: kp.spki, signer: kp, notBefore: NOW - DAY, notAfter: NOW + DAY });
    bad(ou, 'subject is not a single CN');
    // a CN that merely contains '=' or newlines is not a single CN
    bad(selfSigned(kp, { cn: `${ISSUER}\nO=x` }), 'subject CN does not equal the issuer URL');
  });
  it('key strength: RSA 2048..8192 inclusive, EC P-256/P-384/P-521 only, nothing else', () => {
    const strength = (spki: Uint8Array, signer: KP = ecKp()) => {
      const c = mkCert({ subject: [[OID_CN, ISSUER]], issuer: [[OID_CN, ISSUER]], spki, signer, notBefore: NOW - DAY, notAfter: NOW + DAY });
      return rejectedWith([jwk([c], 's')])[0];
    };
    const sizeMsg = (b: number) => `s: RSA key size ${b} outside 2048..8192`;
    expect(strength(fabricatedRsaSpki(2047))).toBe(sizeMsg(2047));
    expect(strength(fabricatedRsaSpki(2048))).toBe('s: not a genuine self-signed cert');
    expect(strength(fabricatedRsaSpki(2056))).toBe('s: not a genuine self-signed cert');
    expect(strength(fabricatedRsaSpki(8192))).toBe('s: not a genuine self-signed cert');
    expect(strength(fabricatedRsaSpki(8193))).toBe(sizeMsg(8193));
    expect(strength(fabricatedRsaSpki(1024))).toBe(sizeMsg(1024));
    const rsa2048 = rsaKp(2048);
    expect(ev([jwk([selfSigned(rsa2048)])]).accepted.length).toBe(1);
    const rsa1024 = rsaKp(1024);
    expect(rejectedWith([jwk([selfSigned(rsa1024)], 'r')])).toEqual(['r: RSA key size 1024 outside 2048..8192']);
    for (const curve of ['P-256', 'P-384', 'P-521']) expect(ev([jwk([selfSigned(ecKp(curve))])]).accepted.length, curve).toBe(1);
    expect(rejectedWith([jwk([selfSigned(ecKp('secp256k1'))], 'k')])).toEqual(["k: EC curve 'secp256k1' not allowed"]);
    expect(rejectedWith([jwk([selfSigned(edKp())], 'e')])).toEqual(["e: key type 'ed25519' not allowed"]);
  });
});

describe('evaluateMaaJwks: chained keys', () => {
  const root = ecKp();
  const mid = ecKp();
  const leaf = ecKp();
  const CN_LEAF = 'Microsoft Azure Attestation 2020';
  const mkChain = (o: { leafCn?: string; leafTo?: number; midTo?: number; rootTo?: number; leafFrom?: number; midFrom?: number; rootFrom?: number; rootSigner?: KP; midSigner?: KP; leafSigner?: KP } = {}) => {
    const rootC = mkCert({ subject: [[OID_CN, 'Root']], issuer: [[OID_CN, 'Root']], spki: root.spki, signer: o.rootSigner ?? root, notBefore: o.rootFrom ?? NOW - 3000 * DAY, notAfter: o.rootTo ?? NOW + 3000 * DAY });
    const midC = mkCert({ subject: [[OID_CN, 'Mid']], issuer: [[OID_CN, 'Root']], spki: mid.spki, signer: o.midSigner ?? root, notBefore: o.midFrom ?? NOW - 2000 * DAY, notAfter: o.midTo ?? NOW + 2000 * DAY });
    const leafC = mkCert({ subject: [[OID_CN, o.leafCn ?? CN_LEAF]], issuer: [[OID_CN, 'Mid']], spki: leaf.spki, signer: o.leafSigner ?? mid, notBefore: o.leafFrom ?? NOW - 100 * DAY, notAfter: o.leafTo ?? NOW + 200 * DAY });
    return { rootC, midC, leafC };
  };
  const evc = (keys: unknown[], over: Partial<MaaKeyPolicy> = {}, now = NOW) => evaluateMaaJwks({ keys } as never, ISSUER, basePolicy(over), now);
  const why = (keys: unknown[], over: Partial<MaaKeyPolicy> = {}) => evc(keys, over).rejected.map((r) => `${r.kid}: ${r.reason}`);
  const full = mkChain();
  const key = (c = full, kid = 'c') => jwk([c.leafC, c.midC, c.rootC], kid);
  it('ignored without a pinned root; anchored on the root otherwise', () => {
    expect(why([key()])).toEqual(['c: chained key ignored (no chainRootSpkiSha256 configured)']);
    expect(why([key()], { chainRootSpkiSha256: [] })).toEqual(['c: chained key ignored (no chainRootSpkiSha256 configured)']);
    const r = evc([key()], { chainRootSpkiSha256: [root.spkiSha.toUpperCase()] });
    expect(r.rejected).toEqual([]);
    expect(r.accepted).toEqual([{ spki: root.spkiSha, kind: 'chained-root', notBeforeMs: NOW - 3000 * DAY, notAfterMs: Math.min(NOW + 3000 * DAY, NOW + 200 * DAY) }]);
  });
  it('chain structure: links, self-signed root, pinned root', () => {
    const pin = { chainRootSpkiSha256: [root.spkiSha] };
    const other = ecKp();
    expect(why([key(mkChain({ leafSigner: other }))], pin)).toEqual(['c: chain link 0 is not signed by the next cert']);
    expect(why([key(mkChain({ midSigner: other }))], pin)).toEqual(['c: chain link 1 is not signed by the next cert']);
    expect(why([jwk([full.leafC, full.midC], 'c')], pin)).toEqual(['c: chain does not end in a self-signed root']);
    expect(why([jwk([full.leafC, full.midC, mkCert({ subject: [[OID_CN, 'Root']], issuer: [[OID_CN, 'Root']], spki: root.spki, signer: other, notBefore: NOW - 3000 * DAY, notAfter: NOW + 3000 * DAY })], 'c')], pin)[0]).toMatch(/chain (link 1 is not signed|does not end in a self-signed root)/);
    expect(why([key()], { chainRootSpkiSha256: ['00'.repeat(32)] })).toEqual(['c: chain root is not pinned']);
  });
  it('leaf CN allowlist', () => {
    const pin = { chainRootSpkiSha256: [root.spkiSha] };
    expect(evc([key()], { ...pin, chainLeafCn: [CN_LEAF] }).accepted.length).toBe(1);
    expect(evc([key()], { ...pin, chainLeafCn: ['other', CN_LEAF] }).accepted.length).toBe(1);
    expect(why([key()], { ...pin, chainLeafCn: ['other'] })).toEqual(['c: chained leaf CN not allowed']);
    expect(why([key()], { ...pin, chainLeafCn: [] })).toEqual(['c: chained leaf CN not allowed']);
    expect(evc([key()], { ...pin }).accepted.length).toBe(1); // undefined = no CN gate
    // a leaf without any CN never matches
    const noCn = mkChain();
    const leafNoCn = mkCert({ subject: [[OID_O, 'x']], issuer: [[OID_CN, 'Mid']], spki: leaf.spki, signer: mid, notBefore: NOW - DAY, notAfter: NOW + DAY });
    expect(why([jwk([leafNoCn, noCn.midC, noCn.rootC], 'n')], { ...pin, chainLeafCn: ['x'] })).toEqual(['n: chained leaf CN not allowed']);
    expect(why([jwk([leafNoCn, noCn.midC, noCn.rootC], 'n')], { ...pin, chainLeafCn: [''] })).toEqual(['n: chained leaf CN not allowed']);
    // the CN is read from the CN= line wherever it sits in a multi-RDN subject
    const multi = mkCert({ subject: [[OID_O, 'Org'], [OID_CN, CN_LEAF]], issuer: [[OID_CN, 'Mid']], spki: leaf.spki, signer: mid, notBefore: NOW - DAY, notAfter: NOW + DAY });
    expect(evc([jwk([multi, noCn.midC, noCn.rootC], 'm')], { ...pin, chainLeafCn: [CN_LEAF] }).accepted.length).toBe(1);
  });
  it('a root that is signed by its own key but names a different issuer is not self-signed', () => {
    const pin = { chainRootSpkiSha256: [root.spkiSha] };
    const fakeRoot = mkCert({ subject: [[OID_CN, 'Root']], issuer: [[OID_CN, 'Someone Else']], spki: root.spki, signer: root, notBefore: NOW - 3000 * DAY, notAfter: NOW + 3000 * DAY });
    const midC = mkCert({ subject: [[OID_CN, 'Mid']], issuer: [[OID_CN, 'Root']], spki: mid.spki, signer: root, notBefore: NOW - DAY, notAfter: NOW + DAY });
    const leafC = mkCert({ subject: [[OID_CN, CN_LEAF]], issuer: [[OID_CN, 'Mid']], spki: leaf.spki, signer: mid, notBefore: NOW - DAY, notAfter: NOW + DAY });
    expect(why([jwk([leafC, midC, fakeRoot], 'c')], pin)).toEqual(['c: chain does not end in a self-signed root']);
  });
  it('a pinned intermediate becomes the anchor; it must sit strictly between leaf and root', () => {
    const pin = { chainRootSpkiSha256: [root.spkiSha], chainIntermediateSpkiSha256: [mid.spkiSha.toUpperCase()] };
    const r = evc([key()], pin);
    expect(r.rejected).toEqual([]);
    expect(r.accepted).toEqual([{ spki: mid.spkiSha, kind: 'chained-intermediate', notBeforeMs: NOW - 2000 * DAY, notAfterMs: Math.min(NOW + 2000 * DAY, NOW + 200 * DAY) }]);
    expect(why([key()], { chainRootSpkiSha256: [root.spkiSha], chainIntermediateSpkiSha256: ['00'.repeat(32)] })).toEqual(['c: chain does not pass through a pinned intermediate']);
    // pinning the root's key as "intermediate" does not count (the root is not strictly between)
    expect(why([key()], { chainRootSpkiSha256: [root.spkiSha], chainIntermediateSpkiSha256: [root.spkiSha] })).toEqual(['c: chain does not pass through a pinned intermediate']);
    // nor does the leaf
    expect(why([key()], { chainRootSpkiSha256: [root.spkiSha], chainIntermediateSpkiSha256: [leaf.spkiSha] })).toEqual(['c: chain does not pass through a pinned intermediate']);
    // a two-certificate chain (leaf + root) has no intermediate at all
    const two = jwk([mkCert({ subject: [[OID_CN, CN_LEAF]], issuer: [[OID_CN, 'Root']], spki: leaf.spki, signer: root, notBefore: NOW - DAY, notAfter: NOW + DAY }), full.rootC], 't');
    expect(why([two], pin)).toEqual(['t: chain does not pass through a pinned intermediate']);
    expect(evc([two], { chainRootSpkiSha256: [root.spkiSha] }).accepted.length).toBe(1);
  });
  it('every certificate of a chain must be valid now; windows follow the anchor', () => {
    const pin = { chainRootSpkiSha256: [root.spkiSha] };
    expect(why([key(mkChain({ rootTo: NOW - 3 * HOUR }))], pin)).toEqual(['c: cert 2: expired']);
    expect(why([key(mkChain({ midFrom: NOW + 3 * HOUR }))], pin)).toEqual(['c: cert 1: not yet valid']);
    expect(why([key(mkChain({ leafTo: NOW - 3 * HOUR }))], pin)).toEqual(['c: cert 0: expired']);
    // two leaves under the same anchor: the window widens to the earliest notBefore and the latest leaf expiry (capped by the anchor)
    const a = mkChain({ leafFrom: NOW - 50 * DAY, leafTo: NOW + 100 * DAY, rootFrom: NOW - 90 * DAY, rootTo: NOW + 400 * DAY });
    const b = mkChain({ leafFrom: NOW - 40 * DAY, leafTo: NOW + 300 * DAY, rootFrom: NOW - 90 * DAY, rootTo: NOW + 400 * DAY });
    const merged = evc([key(a, 'a'), key(b, 'b')], pin);
    expect(merged.accepted).toEqual([{ spki: root.spkiSha, kind: 'chained-root', notBeforeMs: NOW - 90 * DAY, notAfterMs: NOW + 300 * DAY }]);
    const capped = mkChain({ leafFrom: NOW - 40 * DAY, leafTo: NOW + 500 * DAY, rootFrom: NOW - 90 * DAY, rootTo: NOW + 400 * DAY, midTo: NOW + 600 * DAY });
    expect(evc([key(a, 'a'), key(capped, 'c')], pin).accepted[0]!.notAfterMs).toBe(NOW + 400 * DAY);
    expect(evc([key(capped, 'c'), key(a, 'a')], pin).accepted[0]!.notAfterMs).toBe(NOW + 400 * DAY);
    const early = mkChain({ rootFrom: NOW - 200 * DAY, rootTo: NOW + 400 * DAY });
    const m2 = evc([key(a, 'a'), key(early, 'e')], pin);
    expect(m2.accepted[0]!.notBeforeMs).toBe(NOW - 200 * DAY);
    const m3 = evc([key(early, 'e'), key(a, 'a')], pin);
    expect(m3.accepted[0]!.notBeforeMs).toBe(NOW - 200 * DAY);
  });
  it('a chain of the real fixture (via the pinned Microsoft root) works end to end', () => {
    const r = evaluateMaaJwks(JWKS, ISSUER, basePolicy({ chainRootSpkiSha256: [MS_ROOT_SPKI], chainLeafCn: ['Microsoft Azure Attestation 2020'] }), NOW);
    expect(r.accepted.map((a) => a.spki).sort()).toEqual([SPKI_A, SPKI_B, MS_ROOT_SPKI].sort());
    const r2 = evaluateMaaJwks(JWKS, ISSUER, basePolicy({ chainRootSpkiSha256: [MS_ROOT_SPKI], chainIntermediateSpkiSha256: [MS_MID_SPKI] }), NOW);
    expect(r2.accepted.map((a) => [a.spki, a.kind]).sort()).toEqual([[SPKI_A, 'self-signed'], [SPKI_B, 'self-signed'], [MS_MID_SPKI, 'chained-intermediate']].sort());
  });
});

// ═════════════════════════════════════════ createMaaKeyTrust ═════════════════════════════════════════
describe('createMaaKeyTrust: configuration', () => {
  const { f } = fetchOf([JWKS]);
  it('validation messages', () => {
    const store = createMemoryMaaKeyStateStore();
    const m = (policy: unknown, ...rest: unknown[]) => {
      const fetchFn = rest.length ? rest[0] : f;
      try {
        createMaaKeyTrust({ policy: policy as never, store, fetch: fetchFn as never });
      } catch (e) {
        return (e as Error).message;
      }
      return 'NO THROW';
    };
    expect(m({ trustedIssuers: [ISSUER] }, undefined)).toBe('createMaaKeyTrust: fetch must be injected');
    const list = 'createMaaKeyTrust: policy.trustedIssuers must be a non-empty list of https origin URLs';
    for (const p of [undefined, {}, { trustedIssuers: 'x' }, { trustedIssuers: [] }, { trustedIssuers: ['http://a.example'] }, { trustedIssuers: [ISSUER, 'https://a.example/x'] }]) expect(m(p)).toBe(list);
    expect(m({ trustedIssuers: [ISSUER, 'https://b.example:8443'] })).toBe('NO THROW');
  });
});

describe('createMaaKeyTrust: gatekeeping and the result', () => {
  it('issuer and clock', async () => {
    const { t } = trust([JWKS_A]);
    expect(await t.getTrustAnchors('https://other.attest.azure.net', { nowMs: NOW })).toEqual({ ok: false, code: 'untrusted-issuer', reason: 'issuer is not in policy.trustedIssuers' });
    for (const nowMs of [NOW + 0.5, NaN, Infinity, '5' as never]) expect(await t.getTrustAnchors(ISSUER, { nowMs })).toEqual({ ok: false, code: 'clock-regression', reason: 'nowMs must be an integer' });
  });
  it('the first fetch: fields, sorting, persistence', async () => {
    const { t, store, calls } = trust([JWKS_AB]);
    const r = await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.source).toBe('fetched');
    expect(r.trustAnchors).toEqual({ rootSpkiSha256: [SPKI_A, SPKI_B].sort() });
    expect(r.newKeys.sort()).toEqual([SPKI_A, SPKI_B].sort());
    expect(r.removedKeys).toEqual([]);
    expect(r.rejected).toEqual([]);
    expect(r.anchors.every((a) => a.firstSeenMs === NOW && a.kind === 'self-signed')).toBe(true);
    expect(store.snapshot().get(ISSUER)).toMatchObject({ v: 1, issuer: ISSUER, fetchedAtMs: NOW });
    expect(calls.length).toBe(1);
  });
  it('duplicate anchors are de-duplicated in the SPKI list', async () => {
    const { t } = trust([{ keys: [JWKS.keys[0]!, JWKS.keys[0]!] }]);
    expect(spkis(await t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toEqual([SPKI_A]);
  });
  it('no valid keys, with the per-key reasons', async () => {
    const empty = trust([{ keys: [{ x5c: ['bm90IGEgY2VydA=='] }] }]);
    const r = await empty.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(code(r)).toBe('no-valid-keys');
    expect(reasonOf(r)).toMatch(/^no JWKS key passed validation \(#0: .+\)$/);
    const none = trust([{ keys: [] }]);
    expect(reasonOf(await none.t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('no JWKS key passed validation (empty JWKS)');
    const two = trust([{ keys: [{ kid: 'a', x5c: ['bm90IGEgY2VydA=='] }, { kid: 'b', x5c: ['bm90IGEgY2VydA=='] }] }]);
    expect(reasonOf(await two.t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toMatch(/^no JWKS key passed validation \(a: .+; b: .+\)$/);
  });
  it('rejected keys are reported alongside accepted ones', async () => {
    const { t } = trust([JWKS]);
    const r = await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(r.ok && r.rejected.length).toBe(2);
    expect(r.ok && r.rejected[0]!.reason).toMatch(/chained key ignored/);
  });
});

describe('createMaaKeyTrust: persisted state, cache, staleness', () => {
  it('corrupt state is refused for every field shape', async () => {
    const good = (): MaaKeyState => ({ v: 1, issuer: ISSUER, fetchedAtMs: NOW, anchors: [{ spki: SPKI_A, kind: 'self-signed', notBeforeMs: NOW - DAY, notAfterMs: NOW + DAY, firstSeenMs: NOW }] });
    const variants: unknown[] = [
      null,
      5,
      'x',
      { ...good(), v: 2 },
      { ...good(), issuer: 'https://other.example' },
      { ...good(), fetchedAtMs: 1.5 },
      { ...good(), fetchedAtMs: 'x' },
      { ...good(), anchors: 'x' },
      { ...good(), anchors: [null] },
      { ...good(), anchors: [5] },
      { ...good(), anchors: [{ ...good().anchors[0], spki: 'zz' }] },
      { ...good(), anchors: [{ ...good().anchors[0], spki: 5 }] },
      { ...good(), anchors: [{ ...good().anchors[0], spki: SPKI_A.toUpperCase() }] },
      { ...good(), anchors: [{ ...good().anchors[0], spki: `${SPKI_A}0` }] },
      { ...good(), anchors: [{ ...good().anchors[0], kind: 'other' }] },
      { ...good(), anchors: [{ ...good().anchors[0], notBeforeMs: 1.5 }] },
      { ...good(), anchors: [{ ...good().anchors[0], notAfterMs: 'x' }] },
      { ...good(), anchors: [{ ...good().anchors[0], firstSeenMs: undefined }] },
    ];
    for (const v of variants) {
      const { t, store } = trust([JWKS_A]);
      await store.set(ISSUER, v as MaaKeyState);
      const r = await t.getTrustAnchors(ISSUER, { nowMs: NOW });
      expect(r, JSON.stringify(v)?.slice(0, 80)).toEqual({ ok: false, code: 'corrupt-state', reason: 'persisted MAA key state failed validation' });
    }
    for (const kind of ['self-signed', 'chained-root', 'chained-intermediate'] as const) {
      const { t, store } = trust([JWKS_A]);
      await store.set(ISSUER, { ...good(), anchors: [{ ...good().anchors[0]!, kind }] });
      expect((await t.getTrustAnchors(ISSUER, { nowMs: NOW })).ok, kind).toBe(true);
    }
    const { t, store } = trust([JWKS_A]);
    await store.set(ISSUER, { ...good(), anchors: [] });
    expect(code(await t.getTrustAnchors(ISSUER, { nowMs: NOW }))).not.toBe('corrupt-state');
  });
  it('clock regression boundary uses the skew', async () => {
    const { t } = trust([JWKS_A, JWKS_A]);
    await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    const e = { ok: false, code: 'clock-regression', reason: 'clock is behind the last persisted fetch time' };
    expect(await t.getTrustAnchors(ISSUER, { nowMs: NOW - 60_001 })).toEqual(e);
    expect((await t.getTrustAnchors(ISSUER, { nowMs: NOW - 60_000 })).ok).toBe(true); // exactly at the skew: not a regression
    expect(code(await t.getTrustAnchors(ISSUER, { nowMs: NOW - 60_000 }))).not.toBe('clock-regression');
    const wide = trust([JWKS_A], { clockSkewMs: 0 });
    await wide.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(code(await wide.t.getTrustAnchors(ISSUER, { nowMs: NOW - 1 }))).toBe('clock-regression');
    expect(code(await wide.t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('ok');
  });
  it('fresh cache: ttl boundaries, expired anchors, revoked anchors', async () => {
    const { t, calls } = trust([JWKS_A, JWKS_A, JWKS_A], { ttlMs: HOUR });
    await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    const c1 = await t.getTrustAnchors(ISSUER, { nowMs: NOW + HOUR - 1 });
    expect(c1.ok && c1.source).toBe('cache');
    expect(c1.ok && [c1.newKeys, c1.removedKeys, c1.rejected]).toEqual([[], [], []]);
    expect(calls.length).toBe(1);
    const c2 = await t.getTrustAnchors(ISSUER, { nowMs: NOW + HOUR });
    expect(c2.ok && c2.source).toBe('fetched');
    expect(calls.length).toBe(2);
    // within the ttl, but every anchor expired -> refresh
    const exp = trust([JWKS_A, JWKS_A], { ttlMs: 1000 * DAY });
    await exp.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    const r = await exp.t.getTrustAnchors(ISSUER, { nowMs: NOW + 400 * DAY });
    expect(exp.calls.length).toBe(2);
    expect(code(r)).toBe('no-valid-keys');
    // a nowMs equal to fetchedAt is "fresh"; the default ttl is one hour
    const d = trust([JWKS_A, JWKS_A]);
    await d.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect((await d.t.getTrustAnchors(ISSUER, { nowMs: NOW })).ok && d.calls.length).toBe(1);
    await d.t.getTrustAnchors(ISSUER, { nowMs: NOW + HOUR });
    expect(d.calls.length).toBe(2);
    // cache within the ttl but nowMs slightly before fetchedAt (inside the skew) -> refresh instead of serving
    const s = trust([JWKS_A, JWKS_A]);
    await s.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    await s.t.getTrustAnchors(ISSUER, { nowMs: NOW - 1000 });
    expect(s.calls.length).toBe(2);
  });
  it('anchor liveness window uses the skew on both ends', async () => {
    const kp = ecKp();
    const nb = Math.floor(NOW / 1000) * 1000;
    const c = selfSigned(kp, { notBefore: nb, notAfter: nb + 10 * DAY });
    const { t } = trust([{ keys: [jwk([c], 'k')] }], { ttlMs: 1000 * DAY });
    await t.getTrustAnchors(ISSUER, { nowMs: nb });
    const at = (ms: number) => t.getTrustAnchors(ISSUER, { nowMs: ms });
    expect((await at(nb + 10 * DAY)).ok && (await at(nb + 10 * DAY)).ok).toBe(true);
    expect(code(await at(nb + 10 * DAY + 60_000))).toBe('ok');
    const after = await at(nb + 10 * DAY + 60_001);
    expect(after.ok && after.source).not.toBe('cache'); // the cache no longer serves it
  });
  it('fetch failure: stale cache within maxStaleMs, then fail-closed; messages carry the cause', async () => {
    const { t } = trust([JWKS_A, new Error('network down')], { ttlMs: HOUR, maxStaleMs: 6 * HOUR });
    await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    const stale = await t.getTrustAnchors(ISSUER, { nowMs: NOW + 6 * HOUR });
    expect(stale.ok && stale.source).toBe('stale-cache');
    expect(stale.ok && [stale.newKeys, stale.removedKeys, stale.rejected]).toEqual([[], [], []]);
    expect(await t.getTrustAnchors(ISSUER, { nowMs: NOW + 6 * HOUR + 1 })).toEqual({ ok: false, code: 'stale-exceeded', reason: 'network down; cached set is older than maxStaleMs' });
    const none = trust([new Error('down')]);
    expect(await none.t.getTrustAnchors(ISSUER, { nowMs: NOW })).toEqual({ ok: false, code: 'fetch-failed', reason: 'down; no cached key set' });
    const weird = trust([() => { throw 'str'; }]);
    expect(reasonOf(await weird.t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('fetch error; no cached key set');
    const exp = trust([JWKS_A, new Error('down')], { ttlMs: HOUR, maxStaleMs: 1000 * DAY });
    await exp.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(await exp.t.getTrustAnchors(ISSUER, { nowMs: NOW + 500 * DAY })).toEqual({ ok: false, code: 'stale-exceeded', reason: 'down; every cached key has expired or been revoked' });
    // the default staleness bound is 24 h
    const d = trust([JWKS_A, new Error('down')]);
    await d.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect((await d.t.getTrustAnchors(ISSUER, { nowMs: NOW + DAY })).ok).toBe(true);
    expect(code(await d.t.getTrustAnchors(ISSUER, { nowMs: NOW + DAY + 1 }))).toBe('stale-exceeded');
  });
  it('fetch tuning knobs reach the fetcher (timeout, max body)', async () => {
    const { t } = trust([() => respond({ keys: [] }, { status: 200, headers: { 'content-length': '5000' } })], { maxBodyBytes: 100 });
    expect(reasonOf(await t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('MAA certs response exceeds the size limit; no cached key set');
    const slow = createMaaKeyTrust({ policy: basePolicy({ fetchTimeoutMs: 15 }), store: createMemoryMaaKeyStateStore(), fetch: (async () => new Promise<Response>(() => undefined)) as unknown as typeof fetch });
    expect(reasonOf(await slow.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('MAA certs fetch timed out after 15 ms; no cached key set');
  });
});

describe('createMaaKeyTrust: rotation policy', () => {
  it('baseline sources: persisted state, initialPins (case-insensitive), nothing', async () => {
    const m = 'no persisted state, no built-in pin for this issuer, no initialPins and no signed re-pin: refusing trust-on-first-use';
    const none = trust([JWKS_A], { allowTrustOnFirstUse: false });
    expect(await none.t.getTrustAnchors(ISSUER, { nowMs: NOW })).toEqual({ ok: false, code: 'no-baseline', reason: m });
    const pins = trust([JWKS_A], { allowTrustOnFirstUse: false, initialPins: { [ISSUER]: [SPKI_A.toUpperCase()] } });
    expect(spkis(await pins.t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toEqual([SPKI_A]);
    const otherIssuer = trust([JWKS_A], { allowTrustOnFirstUse: false, initialPins: { 'https://other.example': [SPKI_A] } });
    expect(code(await otherIssuer.t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('no-baseline');
    const wrongPin = trust([JWKS_A], { allowTrustOnFirstUse: false, initialPins: { [ISSUER]: [SPKI_B] } });
    expect(code(await wrongPin.t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('no-overlap');
    const emptyPins = trust([JWKS_A], { allowTrustOnFirstUse: false, initialPins: { [ISSUER]: [] } });
    expect(code(await emptyPins.t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('no-baseline');
    // initialPins are only a baseline when there is no persisted state
    const withState = trust([JWKS_B], { initialPins: { [ISSUER]: [SPKI_B] } });
    await withState.store.set(ISSUER, { v: 1, issuer: ISSUER, fetchedAtMs: NOW - 2 * HOUR, anchors: [{ spki: SPKI_A, kind: 'self-signed', notBeforeMs: NOW - 30 * DAY, notAfterMs: NOW + 300 * DAY, firstSeenMs: NOW - 2 * HOUR }] });
    expect(code(await withState.t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('no-overlap');
  });
  it('initial set size: maxInitialKeys boundary (default 8, custom)', async () => {
    const m = (n: number) => `initial set of ${n} keys exceeds maxInitialKeys`;
    const keys = Array.from({ length: 3 }, () => jwk([selfSigned(ecKp())]));
    const three = trust([{ keys }], { maxInitialKeys: 3 });
    expect((await three.t.getTrustAnchors(ISSUER, { nowMs: NOW })).ok).toBe(true);
    const tooMany = trust([{ keys }], { maxInitialKeys: 2 });
    expect(await tooMany.t.getTrustAnchors(ISSUER, { nowMs: NOW })).toEqual({ ok: false, code: 'too-many-new-keys', reason: m(3) });
    const nine = Array.from({ length: 9 }, () => jwk([selfSigned(ecKp())]));
    expect(await trust([{ keys: nine }]).t.getTrustAnchors(ISSUER, { nowMs: NOW })).toEqual({ ok: false, code: 'too-many-new-keys', reason: m(9) });
    expect((await trust([{ keys: nine.slice(0, 8) }]).t.getTrustAnchors(ISSUER, { nowMs: NOW })).ok).toBe(true);
  });
  it('rotation: new keys per fetch and overlap', async () => {
    const mkSet = (n: number) => Array.from({ length: n }, () => jwk([selfSigned(ecKp())]));
    const base = mkSet(1);
    const add = (k: number) => [...base, ...mkSet(k)];
    const rot = async (k: number, over: Partial<MaaKeyPolicy> = {}) => {
      const { t } = trust([{ keys: base }, { keys: add(k) }], over);
      await t.getTrustAnchors(ISSUER, { nowMs: NOW });
      return t.getTrustAnchors(ISSUER, { nowMs: NOW + 2 * HOUR });
    };
    expect((await rot(2)).ok).toBe(true); // default maxNewKeysPerFetch = 2
    expect(await rot(3)).toEqual({ ok: false, code: 'too-many-new-keys', reason: '3 new keys exceed maxNewKeysPerFetch=2' });
    expect((await rot(3, { maxNewKeysPerFetch: 3 })).ok).toBe(true);
    expect(code(await rot(1, { maxNewKeysPerFetch: 0 }))).toBe('too-many-new-keys');
    // no overlap
    const a = mkSet(1);
    const b = mkSet(1);
    const { t } = trust([{ keys: a }, { keys: b }, { keys: b }]);
    await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(await t.getTrustAnchors(ISSUER, { nowMs: NOW + 2 * HOUR })).toEqual({ ok: false, code: 'no-overlap', reason: 'the new key set shares no key with the previous set and is not covered by a signed re-pin' });
    const free = trust([{ keys: a }, { keys: b }], { requireOverlap: false });
    await free.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect((await free.t.getTrustAnchors(ISSUER, { nowMs: NOW + 2 * HOUR })).ok).toBe(true);
  });
  it('persistence: firstSeen is kept, fetchedAt never decreases, new/removed keys are reported', async () => {
    const { t, store } = trust([JWKS_A, JWKS_AB, JWKS_B], { clockSkewMs: 1000 * DAY });
    await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    const r2 = await t.getTrustAnchors(ISSUER, { nowMs: NOW + 2 * HOUR });
    expect(r2.ok && r2.newKeys).toEqual([SPKI_B]);
    expect(r2.ok && r2.removedKeys).toEqual([]);
    const snap = store.snapshot().get(ISSUER)!;
    expect(snap.fetchedAtMs).toBe(NOW + 2 * HOUR);
    expect(snap.anchors.find((a) => a.spki === SPKI_A)!.firstSeenMs).toBe(NOW);
    expect(snap.anchors.find((a) => a.spki === SPKI_B)!.firstSeenMs).toBe(NOW + 2 * HOUR);
    const r3 = await t.getTrustAnchors(ISSUER, { nowMs: NOW + 4 * HOUR });
    expect(r3.ok && r3.removedKeys).toEqual([SPKI_A]);
    expect(r3.ok && r3.newKeys).toEqual([]);
    // a refetch at an earlier (but skew-tolerated) time keeps the later fetchedAt
    const back = trust([JWKS_A, JWKS_A], { ttlMs: 1000, clockSkewMs: 1000 * DAY });
    await back.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    await back.t.getTrustAnchors(ISSUER, { nowMs: NOW - 10 * HOUR });
    expect(back.store.snapshot().get(ISSUER)!.fetchedAtMs).toBe(NOW);
  });
  it('the store is untouched when the rotation policy refuses', async () => {
    const { t, store } = trust([JWKS_A, JWKS_B]);
    await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    const before = JSON.stringify(store.snapshot().get(ISSUER));
    expect(code(await t.getTrustAnchors(ISSUER, { nowMs: NOW + 2 * HOUR }))).toBe('no-overlap');
    expect(JSON.stringify(store.snapshot().get(ISSUER))).toBe(before);
  });
  it('unexpected exceptions are fail-closed', async () => {
    const store: MaaKeyStateStore = {
      get: () => {
        throw new Error('store exploded');
      },
      set: () => undefined,
    };
    const t = createMaaKeyTrust({ policy: basePolicy(), store, fetch: fetchOf([JWKS_A]).f });
    expect(await t.getTrustAnchors(ISSUER, { nowMs: NOW })).toEqual({ ok: false, code: 'fetch-failed', reason: 'store exploded' });
    const t2 = createMaaKeyTrust({
      policy: basePolicy(),
      store: {
        get: () => {
          throw 'str';
        },
        set: () => undefined,
      },
      fetch: fetchOf([JWKS_A]).f,
    });
    expect(reasonOf(await t2.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('unexpected error');
  });
});


describe('createMaaKeyTrust: additional boundaries', () => {
  const anchorOf = (over: Partial<MaaKeyState['anchors'][0]> = {}) => ({ spki: SPKI_A, kind: 'self-signed' as const, notBeforeMs: NOW - 30 * DAY, notAfterMs: NOW + 30 * DAY, firstSeenMs: NOW - DAY, ...over });
  const seeded = async (a: ReturnType<typeof anchorOf>, over: Partial<MaaKeyPolicy> = {}) => {
    const x = trust([JWKS_A], { ttlMs: 1000 * DAY, ...over });
    await x.store.set(ISSUER, { v: 1, issuer: ISSUER, fetchedAtMs: NOW - 1000, anchors: [a] });
    return x;
  };
  it('cached anchors keep their kind; liveness is inclusive on both ends with the skew', async () => {
    const live = await seeded(anchorOf({ kind: 'chained-root' }));
    const r = await live.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(r.ok && r.source).toBe('cache');
    expect(r.ok && r.anchors.map((a) => a.kind)).toEqual(['chained-root']);
    const atEnd = await seeded(anchorOf({ notAfterMs: NOW - 60_000 }));
    expect((await atEnd.t.getTrustAnchors(ISSUER, { nowMs: NOW })).ok && atEnd.calls.length).toBe(0);
    const pastEnd = await seeded(anchorOf({ notAfterMs: NOW - 60_001 }));
    await pastEnd.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(pastEnd.calls.length).toBe(1);
    const atStart = await seeded(anchorOf({ notBeforeMs: NOW + 60_000 }));
    const rs = await atStart.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(rs.ok && rs.source).toBe('cache');
    const beforeStart = await seeded(anchorOf({ notBeforeMs: NOW + 60_001 }));
    await beforeStart.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(beforeStart.calls.length).toBe(1);
    const wide = await seeded(anchorOf({ notAfterMs: NOW - 5000 }), { clockSkewMs: 5000 });
    expect((await wide.t.getTrustAnchors(ISSUER, { nowMs: NOW })).ok && wide.calls.length).toBe(0);
  });
  it('array-valued spki fields are corrupt even if they stringify to a valid pin', async () => {
    const x = trust([JWKS_A]);
    await x.store.set(ISSUER, { v: 1, issuer: ISSUER, fetchedAtMs: NOW, anchors: [anchorOf({ spki: [SPKI_A] as never })] });
    expect(code(await x.t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('corrupt-state');
  });
  it('re-pin approvals expire at the manifest-evaluated time and only maa-signing-spki tombstones for this issuer deny', async () => {
    const op = generateKeyPair();
    const issuerKeys: Record<string, AllowlistIssuerKey> = { ops: { alg: 'ed25519', keys: { edPub: b64u(op.publicKey) } } };
    const repinOf = (entries: AllowlistEntry[]): MaaRepin => ({
      manifest: signAllowlistManifest({ version: 1, issuedAt: NOW, notBefore: NOW - DAY, expiresAt: NOW + 30 * DAY, entries }, { issuer: 'ops', alg: 'ed25519', secrets: { edSecret: op.secretKey } }),
      verify: { issuerKeys },
    });
    const a = trust([JWKS_A, JWKS_B]);
    await a.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    const expired = repinOf([{ kind: 'maa-signing-spki', value: SPKI_B, label: ISSUER, notAfter: NOW + HOUR }]);
    expect(code(await a.t.getTrustAnchors(ISSUER, { nowMs: NOW + 2 * HOUR, repin: expired }))).toBe('no-overlap');
    const b = trust([JWKS_A, JWKS_B]);
    await b.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    const valid = repinOf([{ kind: 'maa-signing-spki', value: SPKI_B, label: ISSUER, notAfter: NOW + 3 * HOUR }]);
    expect(spkis(await b.t.getTrustAnchors(ISSUER, { nowMs: NOW + 2 * HOUR, repin: valid }))).toEqual([SPKI_B]);
    const c = trust([JWKS_AB]);
    const otherKind = repinOf([{ kind: 'maa-chain-root-spki', value: SPKI_A, label: ISSUER, revoked: true }]);
    expect(spkis(await c.t.getTrustAnchors(ISSUER, { nowMs: NOW, repin: otherKind }))).toEqual([SPKI_A, SPKI_B].sort());
  });
  it('shipped pins stay approved when a persisted state lacks them (they license a replacement)', async () => {
    const { f } = fetchOf([JWKS_AB]);
    const store = createMemoryMaaKeyStateStore();
    const t = createMaaKeyTrust({ policy: { trustedIssuers: [ISSUER], maxNewKeysPerFetch: 0 }, store, fetch: f });
    await store.set(ISSUER, { v: 1, issuer: ISSUER, fetchedAtMs: NOW - 2 * HOUR, anchors: [anchorOf({ spki: 'c'.repeat(64) })] });
    const r = await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(r.ok).toBe(true);
    expect(r.ok && r.trustAnchors.rootSpkiSha256).toEqual([SPKI_A, SPKI_B].sort());
    // the same refetch without the shipped pins is refused (new keys over budget, no overlap)
    const t2 = createMaaKeyTrust({ policy: { trustedIssuers: [ISSUER], maxNewKeysPerFetch: 0, builtinPins: false }, store: (() => { const s = createMemoryMaaKeyStateStore(); void s.set(ISSUER, { v: 1, issuer: ISSUER, fetchedAtMs: NOW - 2 * HOUR, anchors: [anchorOf({ spki: 'c'.repeat(64) })] }); return s; })(), fetch: fetchOf([JWKS_AB]).f });
    expect(code(await t2.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('too-many-new-keys');
  });
});

describe('createMaaKeyTrust: signed re-pin manifests', () => {
  const op = generateKeyPair();
  const issuerKeys: Record<string, AllowlistIssuerKey> = { ops: { alg: 'ed25519', keys: { edPub: b64u(op.publicKey) } } };
  const repinOf = (entries: AllowlistEntry[], over: Partial<MaaRepin['verify']> = {}, version = 1): MaaRepin => ({
    manifest: signAllowlistManifest({ version, issuedAt: NOW, notBefore: NOW - DAY, expiresAt: NOW + 30 * DAY, entries }, { issuer: 'ops', alg: 'ed25519', secrets: { edSecret: op.secretKey } }),
    verify: { issuerKeys, ...over },
  });
  const spkiEntry = (value: string, label = ISSUER, revoked = false): AllowlistEntry => ({ kind: 'maa-signing-spki', value, label, ...(revoked ? { revoked: true } : {}) });
  it('invalid manifests fail closed with code and reason', async () => {
    const { t } = trust([JWKS_A]);
    const bad = await t.getTrustAnchors(ISSUER, { nowMs: NOW, repin: repinOf([spkiEntry(SPKI_A)], { issuerKeys: {} }) });
    expect(bad).toEqual({ ok: false, code: 'repin-invalid', reason: "unknown-issuer: issuer 'ops' is not registered" });
    const late = await t.getTrustAnchors(ISSUER, { nowMs: NOW + 40 * DAY, repin: repinOf([spkiEntry(SPKI_A)]) });
    expect(late).toEqual({ ok: false, code: 'repin-invalid', reason: 'expired: manifest has expired' });
  });
  it('an approval for this issuer licenses a total replacement; for another issuer it does not', async () => {
    const a = trust([JWKS_A, JWKS_B]);
    await a.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    const ok = await a.t.getTrustAnchors(ISSUER, { nowMs: NOW + 2 * HOUR, repin: repinOf([spkiEntry(SPKI_B)]) });
    expect(spkis(ok)).toEqual([SPKI_B]);
    expect(ok.ok && ok.removedKeys).toEqual([SPKI_A]);
    const b = trust([JWKS_A, JWKS_B]);
    await b.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(code(await b.t.getTrustAnchors(ISSUER, { nowMs: NOW + 2 * HOUR, repin: repinOf([spkiEntry(SPKI_B, 'https://other.example')]) }))).toBe('no-overlap');
    // an approval alone also bootstraps a first contact without TOFU
    const c = trust([JWKS_A], { allowTrustOnFirstUse: false });
    expect(spkis(await c.t.getTrustAnchors(ISSUER, { nowMs: NOW, repin: repinOf([spkiEntry(SPKI_A)]) }))).toEqual([SPKI_A]);
    const d = trust([JWKS_A], { allowTrustOnFirstUse: false });
    expect(code(await d.t.getTrustAnchors(ISSUER, { nowMs: NOW, repin: repinOf([spkiEntry(SPKI_B)]) }))).toBe('no-baseline');
  });
  it('approved keys do not count against the new-key budget; unapproved ones do', async () => {
    const mk = (n: number) => Array.from({ length: n }, () => ecKp());
    const kps = mk(4);
    const keys = (xs: KP[]) => xs.map((k) => jwk([selfSigned(k)]));
    const { t } = trust([{ keys: keys(kps.slice(0, 1)) }, { keys: keys(kps) }], { maxNewKeysPerFetch: 1 });
    await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    const approveAll = repinOf(kps.slice(1).map((k) => spkiEntry(k.spkiSha)));
    expect((await t.getTrustAnchors(ISSUER, { nowMs: NOW + 2 * HOUR, repin: approveAll })).ok).toBe(true);
    const u = trust([{ keys: keys(kps.slice(0, 1)) }, { keys: keys(kps) }], { maxNewKeysPerFetch: 1 });
    await u.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(code(await u.t.getTrustAnchors(ISSUER, { nowMs: NOW + 2 * HOUR, repin: repinOf([spkiEntry(kps[1]!.spkiSha)]) }))).toBe('too-many-new-keys');
    // initial set larger than maxInitialKeys is fine when every key is approved, not otherwise
    const init = trust([{ keys: keys(kps) }], { maxInitialKeys: 2, allowTrustOnFirstUse: false });
    expect((await init.t.getTrustAnchors(ISSUER, { nowMs: NOW, repin: repinOf(kps.map((k) => spkiEntry(k.spkiSha))) })).ok).toBe(true);
    const init2 = trust([{ keys: keys(kps) }], { maxInitialKeys: 2, allowTrustOnFirstUse: false });
    expect(code(await init2.t.getTrustAnchors(ISSUER, { nowMs: NOW, repin: repinOf(kps.slice(0, 3).map((k) => spkiEntry(k.spkiSha))) }))).toBe('too-many-new-keys');
    const init3 = trust([{ keys: keys(kps) }], { maxInitialKeys: 2 });
    expect(code(await init3.t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('too-many-new-keys');
  });
  it('tombstones (for this issuer only) strip keys everywhere: fresh fetch, cache and stale cache', async () => {
    const strip = repinOf([spkiEntry(SPKI_A, ISSUER, true)], {}, 2);
    const r = await trust([JWKS_AB]).t.getTrustAnchors(ISSUER, { nowMs: NOW, repin: strip });
    expect(spkis(r)).toEqual([SPKI_B]);
    expect(code(await trust([JWKS_A]).t.getTrustAnchors(ISSUER, { nowMs: NOW, repin: strip }))).toBe('no-valid-keys');
    const otherLabel = repinOf([spkiEntry(SPKI_A, 'https://other.example', true)], {}, 2);
    expect(spkis(await trust([JWKS_AB]).t.getTrustAnchors(ISSUER, { nowMs: NOW, repin: otherLabel }))).toEqual([SPKI_A, SPKI_B].sort());
    // cache serving honours a later revocation
    const c = trust([JWKS_AB, JWKS_AB]);
    await c.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    const cached = await c.t.getTrustAnchors(ISSUER, { nowMs: NOW + 5 * 60_000, repin: strip });
    expect(cached.ok && cached.source).toBe('cache');
    expect(spkis(cached)).toEqual([SPKI_B]);
    // stale-cache serving honours it too
    const s = trust([JWKS_AB, new Error('down')], { ttlMs: HOUR });
    await s.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    const stale = await s.t.getTrustAnchors(ISSUER, { nowMs: NOW + 2 * HOUR, repin: strip });
    expect(stale.ok && stale.source).toBe('stale-cache');
    expect(spkis(stale)).toEqual([SPKI_B]);
    // a fresh cache whose keys are ALL revoked refreshes instead
    const all = trust([JWKS_A, JWKS_B]);
    await all.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    const refreshed = await all.t.getTrustAnchors(ISSUER, { nowMs: NOW + 60_000, repin: strip });
    expect(all.calls.length).toBe(2);
    expect(code(refreshed)).not.toBe('cache');
  });
});

describe('createMaaKeyTrust: built-in release-signed pins', () => {
  const BUILTIN = { builtinPins: undefined } as Partial<MaaKeyPolicy>;
  const dflt = (steps: Step[], over: Partial<MaaKeyPolicy> = {}) => {
    const { f, calls } = fetchOf(steps);
    const store = createMemoryMaaKeyStateStore();
    const { builtinPins: _b, allowTrustOnFirstUse: _t, ...rest } = basePolicy(over);
    void _b;
    void _t;
    return { t: createMaaKeyTrust({ policy: { ...rest, ...over, ...(over.builtinPins === undefined ? {} : { builtinPins: over.builtinPins }) }, store, fetch: f }), store, calls };
  };
  it('default: the first accepted set is anchored on the shipped pins (including the Microsoft intermediate), no TOFU', async () => {
    const { t, store } = dflt([JWKS]);
    const r = await t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.trustAnchors.rootSpkiSha256).toEqual([SPKI_A, SPKI_B, MS_MID_SPKI].sort());
    expect(r.anchors.map((a) => a.kind).sort()).toEqual(['chained-intermediate', 'self-signed', 'self-signed']);
    expect(r.newKeys).toEqual([]);
    expect(r.removedKeys).toEqual([]);
    expect(store.snapshot().get(ISSUER)!.anchors.length).toBe(3);
    const explicitTrue = dflt([JWKS], { builtinPins: true });
    expect((await explicitTrue.t.getTrustAnchors(ISSUER, { nowMs: NOW })).ok).toBe(true);
  });
  it('an issuer the release did not pin has no baseline (and the pinned Microsoft intermediate does not leak to it)', async () => {
    const other = 'https://sharedneu.neu.attest.azure.net';
    const { f } = fetchOf([JWKS_A]);
    const t = createMaaKeyTrust({ policy: { trustedIssuers: [other] }, store: createMemoryMaaKeyStateStore(), fetch: f });
    // the fixture certs name ISSUER, not `other`, so nothing validates; use a minted cert for `other`
    const kp = ecKp();
    const t2 = createMaaKeyTrust({ policy: { trustedIssuers: [other] }, store: createMemoryMaaKeyStateStore(), fetch: fetchOf([{ keys: [jwk([selfSigned(kp, { cn: other })])] }]).f });
    const r = await t2.getTrustAnchors(other, { nowMs: NOW });
    expect(r).toEqual({ ok: false, code: 'no-baseline', reason: 'no persisted state, no built-in pin for this issuer, no initialPins and no signed re-pin: refusing trust-on-first-use' });
    expect(code(await t.getTrustAnchors(other, { nowMs: NOW }))).toBe('no-valid-keys');
  });
  it('disabled: no baseline without TOFU / initialPins', async () => {
    const t = createMaaKeyTrust({ policy: { trustedIssuers: [ISSUER], builtinPins: false }, store: createMemoryMaaKeyStateStore(), fetch: fetchOf([JWKS]).f });
    expect(code(await t.getTrustAnchors(ISSUER, { nowMs: NOW }))).toBe('no-baseline');
  });
  it('explicit policy always wins over the shipped pins', async () => {
    const noChains = dflt([JWKS], { chainRootSpkiSha256: [] });
    const r = await noChains.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(r.ok && r.trustAnchors.rootSpkiSha256).toEqual([SPKI_A, SPKI_B].sort());
    const leafCn = dflt([JWKS], { chainLeafCn: ['nope'] });
    const r2 = await leafCn.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(r2.ok && r2.trustAnchors.rootSpkiSha256).toEqual([SPKI_A, SPKI_B].sort());
    const customInter = dflt([JWKS], { chainIntermediateSpkiSha256: ['00'.repeat(32)] });
    const r3 = await customInter.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(r3.ok && r3.trustAnchors.rootSpkiSha256).toEqual([SPKI_A, SPKI_B].sort());
    const customRoot = dflt([JWKS], { chainRootSpkiSha256: [MS_ROOT_SPKI], chainIntermediateSpkiSha256: [] });
    const r4 = await customRoot.t.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(r4.ok && r4.trustAnchors.rootSpkiSha256).toEqual([SPKI_A, SPKI_B, MS_ROOT_SPKI].sort());
  });
  it('a substitute signed pin source, and unusable pins', async () => {
    const op = generateKeyPair();
    const keys: Record<string, AllowlistIssuerKey> = { rel: { alg: 'ed25519', keys: { edPub: b64u(op.publicKey) } } };
    const sign = (entries: AllowlistEntry[]) => signAllowlistManifest({ version: 1, issuedAt: NOW, notBefore: NOW - DAY, expiresAt: NOW + 100 * DAY, entries }, { issuer: 'rel', alg: 'ed25519', secrets: { edSecret: op.secretKey } });
    const custom = 'https://custom.attest.azure.net';
    const kp = ecKp();
    const kp2 = ecKp();
    const corr: AllowlistEntry = { kind: 'attest-corroboration', value: 'ab'.repeat(32), label: 'vantages=3;method=test' };
    const entries: AllowlistEntry[] = [
      { kind: 'maa-signing-spki', value: kp.spkiSha, label: custom },
      { kind: 'maa-signing-spki', value: kp2.spkiSha, label: custom, revoked: true },
      { kind: 'maa-chain-root-spki', value: 'aa'.repeat(32), label: 'r' },
      { kind: 'maa-chain-intermediate-spki', value: 'bb'.repeat(32), label: 'i' },
      corr,
    ];
    const source = { manifest: sign(entries), issuerKeys: keys };
    const mk = (jwks: unknown[], builtinPins: MaaKeyPolicy['builtinPins']) => createMaaKeyTrust({ policy: { trustedIssuers: [custom], builtinPins }, store: createMemoryMaaKeyStateStore(), fetch: fetchOf([{ keys: jwks }]).f });
    const both = [jwk([selfSigned(kp, { cn: custom })]), jwk([selfSigned(kp2, { cn: custom })])];
    const r = await mk(both, source).getTrustAnchors(custom, { nowMs: NOW });
    expect(spkis(r)).toEqual([kp.spkiSha]); // the pinned key; the release-revoked one is stripped
    // unusable pins: the failure reason is surfaced only when there is nothing else to anchor on
    const broken = { manifest: { not: 'a manifest' }, issuerKeys: keys };
    const rb = await mk(both, broken).getTrustAnchors(custom, { nowMs: NOW });
    expect(code(rb)).toBe('builtin-pins-invalid');
    expect(reasonOf(rb)).toBe('built-in pins unusable (malformed: manifest has an unexpected shape); no persisted state, no initialPins, no signed re-pin; refusing trust-on-first-use');
    // TOFU explicitly allowed overrides the unusable-pin refusal
    const tofu = createMaaKeyTrust({ policy: { trustedIssuers: [custom], builtinPins: broken, allowTrustOnFirstUse: true }, store: createMemoryMaaKeyStateStore(), fetch: fetchOf([{ keys: both }]).f });
    expect((await tofu.getTrustAnchors(custom, { nowMs: NOW })).ok).toBe(true);
    // a source for another issuer: no baseline for this one
    const wrongIssuer = { manifest: sign([{ kind: 'maa-signing-spki', value: kp.spkiSha, label: 'https://elsewhere.example' }, ...entries.slice(2)]), issuerKeys: keys };
    expect(code(await mk(both, wrongIssuer).getTrustAnchors(custom, { nowMs: NOW }))).toBe('no-baseline');
    expect(BUILTIN).toBeDefined();
  });
});

// ═════════════════════════════════════════ corroboration ═════════════════════════════════════════
describe('corroborateMaaKeySets', () => {
  const obs = (vantage: string, jwks: MaaJwks, issuer = ISSUER) => ({ vantage, issuer, jwks });
  const co = (sets: unknown, k: unknown, over: Record<string, unknown> = {}) => corroborateMaaKeySets(sets as never, k as number, { issuer: ISSUER, nowMs: NOW, ...over } as never);
  it('agreement of k distinct vantages', () => {
    const r = co([obs('b', JWKS_AB), obs('a', JWKS_AB), obs('c', { keys: [JWKS.keys[3]!, JWKS.keys[0]!] })], 3);
    expect(r).toEqual({ ok: true, issuer: ISSUER, spkis: [SPKI_A, SPKI_B].sort(), vantages: ['a', 'b', 'c'], k: 3 });
    expect(co([obs('a', JWKS_A), obs('b', JWKS_A)], 2)).toMatchObject({ ok: true, k: 2, spkis: [SPKI_A] });
  });
  it('argument validation', () => {
    const m = (code_: string, reason: string) => ({ ok: false, code: code_, reason });
    for (const k of [1, 0, -1, 2.5, NaN, '2']) expect(co([], k)).toEqual(m('malformed', 'k must be an integer >= 2'));
    expect(corroborateMaaKeySets([], 2, undefined as never)).toEqual(m('malformed', 'issuer/nowMs invalid'));
    expect(co([], 2, { issuer: 'http://x' })).toEqual(m('malformed', 'issuer/nowMs invalid'));
    expect(co([], 2, { issuer: undefined })).toEqual(m('malformed', 'issuer/nowMs invalid'));
    expect(co([], 2, { nowMs: 1.5 })).toEqual(m('malformed', 'issuer/nowMs invalid'));
    expect(co('x', 2)).toEqual(m('malformed', 'sets must be an array'));
    expect(co(undefined, 2)).toEqual(m('malformed', 'sets must be an array'));
    const lab = m('malformed', 'vantage label must be a non-empty string');
    expect(co([obs('', JWKS_A)], 2)).toEqual(lab);
    expect(co([obs('x'.repeat(101), JWKS_A)], 2)).toEqual(lab);
    expect(co([{ ...obs('a', JWKS_A), vantage: 5 }], 2)).toEqual(lab);
    expect(co([null], 2)).toEqual(lab);
    expect(co([obs('x'.repeat(100), JWKS_A), obs('y', JWKS_A)], 2).ok).toBe(true);
    expect(co([obs('a', JWKS_A, 'https://other.example')], 2)).toEqual(m('malformed', "observation from 'a' is for a different issuer"));
  });
  it('per-vantage validity, consistency and quorum', () => {
    const noKeys = co([obs('a', { keys: [] })], 2);
    expect(noKeys).toEqual({ ok: false, code: 'no-valid-keys', reason: "vantage 'a' observed no valid key (empty)" });
    const bad = co([obs('a', { keys: [{ x5c: ['bm90IGEgY2VydA=='] }] })], 2);
    expect(bad.ok).toBe(false);
    expect(!bad.ok && bad.code).toBe('no-valid-keys');
    expect(!bad.ok && bad.reason).toMatch(/^vantage 'a' observed no valid key \(.+\)$/);
    const two = co([{ vantage: 'a', issuer: ISSUER, jwks: { keys: [{ x5c: ['bm90IGEgY2VydA=='] }, { x5c: ['bm90IGEgY2VydA=='] }] } }], 2);
    expect(!two.ok && two.reason).toMatch(/^vantage 'a' observed no valid key \(.+; .+\)$/);
    expect(co([obs('a', JWKS_A), obs('a', JWKS_B)], 2)).toEqual({ ok: false, code: 'vantage-disagreement', reason: "vantage 'a' supplied two different key sets" });
    expect(co([obs('a', JWKS_A), obs('a', JWKS_A)], 2)).toEqual({ ok: false, code: 'insufficient-vantages', reason: '1 distinct vantage(s) < k=2' });
    expect(co([obs('a', JWKS_A), obs('b', JWKS_A)], 3)).toEqual({ ok: false, code: 'insufficient-vantages', reason: '2 distinct vantage(s) < k=3' });
    const dis = co([obs('a', JWKS_A), obs('b', JWKS_B)], 2);
    expect(dis.ok).toBe(false);
    expect(!dis.ok && dis.code).toBe('vantage-disagreement');
    expect(!dis.ok && dis.reason).toBe(`vantages disagree: a=${SPKI_A.slice(0, 8)} | b=${SPKI_B.slice(0, 8)}`);
    const dis2 = co([obs('a', JWKS_AB), obs('b', JWKS_A)], 2);
    expect(!dis2.ok && dis2.reason).toMatch(/^vantages disagree: a=[0-9a-f]{8}\+[0-9a-f]{8} \| b=[0-9a-f]{8}$/);
  });
  it('the evaluation policy (issuer, clock, extra policy) applies', () => {
    expect(co([obs('a', JWKS_A), obs('b', JWKS_A)], 2, { nowMs: Date.parse('2027-12-01T00:00:00Z') }).ok).toBe(false);
    expect(co([obs('a', JWKS_A), obs('b', JWKS_A)], 2, { policy: { maxKeyAgeMs: 1 } }).ok).toBe(false);
    const chained = co([obs('a', JWKS), obs('b', JWKS)], 2, { policy: { chainRootSpkiSha256: [MS_ROOT_SPKI] } });
    expect(chained).toMatchObject({ ok: true });
    expect(chained.ok && chained.spkis.sort()).toEqual([SPKI_A, SPKI_B, MS_ROOT_SPKI].sort());
    const plain = co([obs('a', JWKS), obs('b', JWKS)], 2);
    expect(plain.ok && plain.spkis.sort()).toEqual([SPKI_A, SPKI_B].sort());
  });
  it('unexpected exceptions become "malformed"', () => {
    const boom = { get vantage(): string { throw new Error('getter exploded'); }, issuer: ISSUER, jwks: JWKS_A };
    expect(co([boom], 2)).toEqual({ ok: false, code: 'malformed', reason: 'getter exploded' });
    const weird = { get vantage(): string { throw 'str'; }, issuer: ISSUER, jwks: JWKS_A };
    expect(co([weird], 2)).toEqual({ ok: false, code: 'malformed', reason: 'corroboration error' });
  });
});

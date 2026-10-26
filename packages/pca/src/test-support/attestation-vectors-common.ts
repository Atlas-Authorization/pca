// Shared plumbing of the attestation-evidence conformance vector builders (TEST/TOOLING ONLY).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { attestationBinding } from '../attestation';
import { b64, runAttestationVector, type JsonObject, type Vendor, type WireBinding, type WireResult } from './attestation-wire';

export type Intent = 'accept' | 'reject';

export interface VectorIn {
  id: string;
  vendor: Vendor;
  /** Feature tags a native may use to scope its port (for example `strictness`, `collateral:rim`, `real`). */
  tags?: string[];
  intent: Intent;
  /** One sentence: what the row proves. */
  description: string;
  config: JsonObject;
  /** Verifier clock, epoch ms. */
  now: number;
  binding: WireBinding;
  /** The evidence wire object, or null for "the resolver has no evidence for this action". */
  evidence: JsonObject | null;
}

export interface Vector extends Omit<VectorIn, 'binding' | 'tags'> {
  tags: string[];
  expected_binding: WireBinding;
  expect: WireResult & { reason_match?: 'exact' | 'prefix'; reason_prefix?: string };
}

/**
 * Reasons that end in the message of an exception raised INSIDE node:crypto / OpenSSL (certificate parsing). Its wording is
 * not portable, so a native compares only the stable prefix (`reason_match: "prefix"`).
 */
const PASSTHROUGH = [
  'AMD chain verification error: ',
  'amd-snp verification error (fail closed): ',
  'intel-dcap verification error (fail closed): ',
  'azure-maa verification error (fail closed): ',
  'gcp-confidential-space verification error (fail closed): ',
  'nvidia-spdm verification error (fail closed): ',
  'x5c chain verification error (fail closed): ',
  'PCK chain X.509 verification error (fail closed): ',
  'device chain unparseable: ',
  'JWKS key is not a usable public key: ',
];
const NODE_TEXT = /error:[0-9A-Fa-f]{6,8}|ERR_OSSL|ERR_CRYPTO|OSSL_|asn1 |ASN1|DECODER|PEM routines|bad decrypt|X509 /;

export class Collector {
  readonly vectors: Vector[] = [];
  private readonly ids = new Set<string>();
  /** Reasons that look like OpenSSL text but were not recognised as pass-through (a generator bug to fix). */
  readonly suspicious: string[] = [];
  /** Rows whose recorded outcome is not what their `intent` says: the generator must fail on any. */
  readonly mismatches: string[] = [];

  async add(v: VectorIn): Promise<WireResult> {
    if (this.ids.has(v.id)) throw new Error(`duplicate vector id ${v.id}`);
    this.ids.add(v.id);
    // what is run is exactly what is stored: round-trip through JSON first (drops undefined members)
    v = { ...v, config: clone(v.config), evidence: v.evidence === null ? null : clone(v.evidence), binding: clone(v.binding) };
    const expect = (await runAttestationVector({ vendor: v.vendor, config: v.config, evidence: v.evidence, now: v.now, expected_binding: v.binding })) as Vector['expect'];
    const accepted = 'ok' in expect && expect.ok === true;
    if (v.intent === 'accept' ? !accepted : accepted) this.mismatches.push(`${v.id}: intent ${v.intent} but the reference answered ${JSON.stringify(expect).slice(0, 300)}`);
    const text = 'reason' in expect ? expect.reason : 'construct_error' in expect ? expect.construct_error : undefined;
    if (typeof text === 'string' && 'reason' in expect) {
      const p = PASSTHROUGH.find((x) => text.includes(x) && NODE_TEXT.test(text.slice(text.indexOf(x) + x.length)));
      if (p) {
        expect.reason_match = 'prefix';
        expect.reason_prefix = text.slice(0, text.indexOf(p) + p.length);
      } else if (NODE_TEXT.test(text)) this.suspicious.push(`${v.id}: ${text}`);
    }
    const { binding, tags, ...rest } = v;
    this.vectors.push({ ...rest, tags: tags ?? [], expected_binding: binding, expect });
    return expect;
  }
}

// ───────────────────────────────────────────────────────────── fixtures
const FIXTURES = join(__dirname, '..', '..', 'fixtures');
export const fxBytes = (...p: string[]): Uint8Array => new Uint8Array(readFileSync(join(FIXTURES, ...p)));
export const fxText = (...p: string[]): string => readFileSync(join(FIXTURES, ...p), 'utf8');

// ───────────────────────────────────────────────────────────── byte edits (all return fresh arrays)
export const flip = (u: Uint8Array, at: number, mask = 0x01): Uint8Array => {
  const c = new Uint8Array(u);
  c[at] = c[at]! ^ mask;
  return c;
};
export const setByte = (u: Uint8Array, at: number, v: number): Uint8Array => {
  const c = new Uint8Array(u);
  c[at] = v;
  return c;
};
export const append = (u: Uint8Array, ...bytes: number[]): Uint8Array => Uint8Array.from([...u, ...bytes]);
export const cut = (u: Uint8Array, n: number): Uint8Array => u.slice(0, n);
export const bytesB64 = b64;
export const textBytes = (s: string): Uint8Array => new TextEncoder().encode(s);

// ───────────────────────────────────────────────────────────── the binding the synthetic evidence is minted for
export const SYN_BINDING: WireBinding = { holderPub: 'conf-holder-ed25519-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', grantRef: 'grant_conf_attestation_0001', epoch: 3, nonce: 'srv-nonce-conf-0123456789abcdef' };
export const bindingBytes = (b: WireBinding): Uint8Array => attestationBinding(b);
/** The four single-field relays of a binding (each must be refused by a bound quote). */
export const relays = (b: WireBinding): Array<[string, WireBinding]> => [
  ['holder', { ...b, holderPub: `${b.holderPub}x` }],
  ['grant', { ...b, grantRef: `${b.grantRef}x` }],
  ['epoch', { ...b, epoch: b.epoch + 1 }],
  ['nonce', { ...b, nonce: `${b.nonce}x` }],
];
/** Bindings `attestationBinding` itself refuses (each verifier reports "binding not constructible" or its own wrapper). */
export const badBindings = (b: WireBinding): Array<[string, WireBinding]> => [
  ['empty-holder', { ...b, holderPub: '' }],
  ['empty-grant', { ...b, grantRef: '' }],
  ['empty-nonce', { ...b, nonce: '' }],
  ['negative-epoch', { ...b, epoch: -1 }],
  ['fractional-epoch', { ...b, epoch: 1.5 }],
];

export const hexOf = (u: Uint8Array): string => Buffer.from(u).toString('hex');
export function clone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x)) as T;
}

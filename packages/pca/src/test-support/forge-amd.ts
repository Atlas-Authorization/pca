/**
 * TEST-ONLY forger for AMD-style SEV-SNP certificate chains, in the REAL wire format of AMD's KDS chain:
 *   ARK  — RSA-4096 (RSASSA-PSS / SHA-384 / MGF1-SHA-384 / salt 48, explicit default trailerField), self-signed, CA:TRUE pathLen 2
 *   ASK  — RSA-4096 (same PSS profile), signed by the ARK, CA:TRUE pathLen 0, keyUsage keyCertSign
 *   VCEK — EC P-384 key, signed by the ASK with RSASSA-PSS, carries ONLY the AMD extensions (hwID + SPLs), no BasicConstraints
 * Every knob a negative test needs (extensions, validity, signer) is overridable. The chain is verified by the production
 * code against a TEST ARK pin (`arkPin`), never a real AMD root. NEVER import this from production code.
 */
import { constants, createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { bitString, boolean, cat, derTime, dn, ext, extension, forgeKey, integer, nul, octets, oid, pemOf, seq, tlv, ctx, type ForgeKey } from './forge-x509';

const rsaCache = new Map<string, { priv: KeyObject; pub: KeyObject; spki: Uint8Array }>();
/** A cached RSA-4096 RSASSA-PSS key (SHA-384 / MGF1-SHA-384 / salt 48) for `label`. */
export function rsaPssKey(label: string): { priv: KeyObject; pub: KeyObject; spki: Uint8Array } {
  let k = rsaCache.get(label);
  if (!k) {
    const { privateKey, publicKey } = generateKeyPairSync('rsa-pss', { modulusLength: 4096 });
    k = { priv: privateKey, pub: publicKey, spki: new Uint8Array(publicKey.export({ type: 'spki', format: 'der' })) };
    rsaCache.set(label, k);
  }
  return k;
}

const sha384Alg = (): Uint8Array => seq(oid('2.16.840.1.101.3.4.2.2'), nul());
/** AMD's RSASSA-PSS AlgorithmIdentifier; `trailer` adds the explicit default trailerField [3] 1. */
function pssAlgId(trailer: boolean): Uint8Array {
  return seq(
    oid('1.2.840.113549.1.1.10'),
    seq(ctx(0, sha384Alg()), ctx(1, seq(oid('1.2.840.113549.1.1.8'), sha384Alg())), ctx(2, integer(48)), ...(trailer ? [ctx(3, integer(1))] : [])),
  );
}

export const AMD_OID = {
  hwid: '1.3.6.1.4.1.3704.1.4',
  bl: '1.3.6.1.4.1.3704.1.3.1',
  tee: '1.3.6.1.4.1.3704.1.3.2',
  snp: '1.3.6.1.4.1.3704.1.3.3',
  ucode: '1.3.6.1.4.1.3704.1.3.8',
} as const;

export interface VcekSpl {
  chip: Uint8Array;
  bl: number;
  tee: number;
  snp: number;
  ucode: number;
}
/** The AMD VCEK extensions exactly as AMD encodes them (non-critical; SPL = DER INTEGER; hwID = 64 raw bytes). */
export function amdVcekExtensions(v: VcekSpl): Uint8Array[] {
  return [
    extension(AMD_OID.bl, false, integer(v.bl)),
    extension(AMD_OID.tee, false, integer(v.tee)),
    extension(AMD_OID.snp, false, integer(v.snp)),
    extension(AMD_OID.ucode, false, integer(v.ucode)),
    extension(AMD_OID.hwid, false, v.chip),
  ];
}

interface CertSpec {
  subject: string;
  issuer: string;
  spki: Uint8Array;
  signer: KeyObject;
  serial: number;
  notBefore: Date;
  notAfter: Date;
  extensions: readonly Uint8Array[];
  trailer: boolean;
  /** Replaces the whole `[3]` block bytes (to craft structural malformations). */
  rawExtensionsBlock?: Uint8Array;
}
function buildCert(c: CertSpec): Uint8Array {
  const alg = pssAlgId(c.trailer);
  const block = c.rawExtensionsBlock ?? (c.extensions.length > 0 ? ctx(3, seq(...c.extensions)) : new Uint8Array(0));
  const tbs = seq(ctx(0, integer(2)), integer(c.serial), alg, dn([['CN', c.issuer]]), seq(derTime(c.notBefore), derTime(c.notAfter)), dn([['CN', c.subject]]), c.spki, block);
  const sig = sign('sha384', tbs, { key: c.signer, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 });
  return seq(tbs, alg, bitString(new Uint8Array(sig)));
}

export interface CertKnobs {
  notBefore?: Date;
  notAfter?: Date;
  /** Replace the default extension list entirely. */
  extensions?: readonly Uint8Array[];
  /** Replace the whole [3] block with these exact bytes. */
  rawExtensionsBlock?: Uint8Array;
}
export interface AmdChainOptions {
  family?: string;
  ark?: CertKnobs;
  ask?: CertKnobs;
  vcek?: CertKnobs & { spl?: Partial<VcekSpl> };
  /** Sign the ASK with this label's key instead of the ARK's (an ASK not issued by the ARK). */
  askSignedBy?: string;
  /** Sign the VCEK with this label's key instead of the ASK's. */
  vcekSignedBy?: string;
  /** Distinguishes independent chains (their ARK pins differ). */
  label?: string;
}
export interface ForgedAmdChain {
  arkDer: Uint8Array;
  askDer: Uint8Array;
  vcekDer: Uint8Array;
  /** The VCEK's EC P-384 key (sign reports with `vcekKey.priv`). */
  vcekKey: ForgeKey;
  /** `ASK` then `ARK`, as AMD KDS serves them. */
  askArkPem: string;
  /** SPKI SHA-384 hex of the forged ARK — pass as `trustAnchorArkSpkiSha384`. */
  arkPin: string;
}

export const FORGE_NB = new Date('2022-01-01T00:00:00Z');
export const FORGE_NA = new Date('2040-01-01T00:00:00Z');
export const FORGE_CHIP = new Uint8Array(64).map((_, i) => (i * 7 + 3) & 0xff);

export function forgeAmdChain(o: AmdChainOptions = {}): ForgedAmdChain {
  const label = o.label ?? 'amd-test';
  const fam = o.family ?? 'Genoa';
  const ark = rsaPssKey(`${label}/ark`);
  const ask = rsaPssKey(`${label}/ask`);
  const vcekKey = forgeKey(`${label}/vcek`, 'P-384');
  const spl: VcekSpl = { chip: FORGE_CHIP, bl: 7, tee: 0, snp: 3, ucode: 0, ...o.vcek?.spl };
  const arkDer = buildCert({
    subject: `ARK-${fam}`,
    issuer: `ARK-${fam}`,
    spki: ark.spki,
    signer: ark.priv,
    serial: 1,
    notBefore: o.ark?.notBefore ?? FORGE_NB,
    notAfter: o.ark?.notAfter ?? FORGE_NA,
    extensions: o.ark?.extensions ?? [ext.basicConstraints(true, 2), ext.keyUsage(['keyCertSign', 'cRLSign'])],
    trailer: true,
    ...(o.ark?.rawExtensionsBlock ? { rawExtensionsBlock: o.ark.rawExtensionsBlock } : {}),
  });
  const askDer = buildCert({
    subject: `SEV-${fam}`,
    issuer: `ARK-${fam}`,
    spki: ask.spki,
    signer: o.askSignedBy ? rsaPssKey(`${o.askSignedBy}/ark`).priv : ark.priv,
    serial: 2,
    notBefore: o.ask?.notBefore ?? FORGE_NB,
    notAfter: o.ask?.notAfter ?? FORGE_NA,
    extensions: o.ask?.extensions ?? [ext.basicConstraints(true, 0), ext.keyUsage(['keyCertSign'])],
    trailer: true,
    ...(o.ask?.rawExtensionsBlock ? { rawExtensionsBlock: o.ask.rawExtensionsBlock } : {}),
  });
  const vcekDer = buildCert({
    subject: 'SEV-VCEK',
    issuer: `SEV-${fam}`,
    spki: vcekKey.spki,
    signer: o.vcekSignedBy ? rsaPssKey(`${o.vcekSignedBy}/ask`).priv : ask.priv,
    serial: 3,
    notBefore: o.vcek?.notBefore ?? FORGE_NB,
    notAfter: o.vcek?.notAfter ?? FORGE_NA,
    extensions: o.vcek?.extensions ?? amdVcekExtensions(spl),
    trailer: false,
    ...(o.vcek?.rawExtensionsBlock ? { rawExtensionsBlock: o.vcek.rawExtensionsBlock } : {}),
  });
  return {
    arkDer,
    askDer,
    vcekDer,
    vcekKey,
    askArkPem: pemOf(askDer) + pemOf(arkDer),
    arkPin: createHash('sha384').update(ark.spki).digest('hex'),
  };
}

// Re-exported for tests that craft raw extension bytes.
export { boolean, cat, extension, integer, octets, oid, seq, tlv, ctx, ext, pemOf };

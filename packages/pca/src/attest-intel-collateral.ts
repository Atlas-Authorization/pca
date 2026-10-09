/**
 * Intel PCS COLLATERAL verification for the genuine DCAP TDX quote path (the "online remainder" that
 * `attest-intel-tdx.ts` documents). Entirely OFFLINE given collateral bytes the caller fetched from Intel PCS:
 *   - TDX TCB info (`/tdx/certification/v4/tcb`) and TD-QE identity (`/tdx/certification/v4/qe/identity`):
 *     the signed JSON object (ECDSA-P256/SHA-256 over the EXACT bytes of the `tcbInfo` / `enclaveIdentity`
 *     value, signature hex r||s) is verified under the TCB Signing certificate, whose issuer chain must end at
 *     the PINNED Intel SGX Root CA (never taken from the supplied chain);
 *   - the PCK CRL (signed by the PCK CA found in the quote's own verified chain) and the Intel Root CA CRL
 *     (signed by the pinned root);
 *   - the platform TCB status (PCK-cert SGX components + PCESVN, TD-report TEE_TCB_SVN, TDX-module identity),
 *     the QE identity check, and a status policy.
 * Fails CLOSED on missing, stale, malformed, unsigned or revoked collateral. Uses only node:crypto
 * (OpenSSL) X509Certificate / verify. The evaluated status is whatever the genuine data says.
 */
import { X509Certificate, verify, type KeyObject } from 'node:crypto';
import { extractPckFmspcAndTcb, parseDcapQuote, toHex, verifyGenuineTdxQuote, verifyIntelPckChainX509 } from './attest-intel-tdx';

export type TcbStatus =
  | 'UpToDate'
  | 'SWHardeningNeeded'
  | 'ConfigurationNeeded'
  | 'ConfigurationAndSWHardeningNeeded'
  | 'OutOfDateConfigurationNeeded'
  | 'OutOfDate'
  | 'Revoked';

/** Severity order (index = badness); a merged status is the worst of its parts. */
const STATUS_ORDER: readonly TcbStatus[] = [
  'UpToDate',
  'SWHardeningNeeded',
  'ConfigurationNeeded',
  'ConfigurationAndSWHardeningNeeded',
  'OutOfDateConfigurationNeeded',
  'OutOfDate',
  'Revoked',
];

export const DEFAULT_ACCEPTED_STATUSES: readonly TcbStatus[] = ['UpToDate', 'SWHardeningNeeded'];

/** The collateral bytes as fetched from Intel PCS. Issuer chains are PEM (URL-decoded header values). */
export interface IntelTdxCollateral {
  tcbInfoJson: string | Uint8Array;
  tcbInfoIssuerChainPem: string;
  qeIdentityJson: string | Uint8Array;
  qeIdentityIssuerChainPem: string;
  /** PCK CRL (DER) for the CA that issued the quote's PCK (platform or processor). */
  pckCrlDer: Uint8Array;
  /** Intel SGX Root CA CRL (DER). */
  rootCrlDer: Uint8Array;
}

export interface IntelCollateralPolicy {
  /** Statuses to accept. Default UpToDate + SWHardeningNeeded. */
  acceptStatuses?: readonly TcbStatus[];
  /** Minimum tcbEvaluationDataNumber for both TCB info and QE identity. */
  minTcbEvaluationDataNumber?: number;
}

export interface IntelCollateralResult {
  /** True iff the collateral verified AND the evaluated status is accepted by policy. */
  ok: boolean;
  reason?: string;
  /** Final evaluated status (worst of platform TCB, TDX module, QE identity); set whenever evaluation completed. */
  status?: TcbStatus;
  platformStatus?: TcbStatus;
  tdxModuleStatus?: TcbStatus;
  qeStatus?: TcbStatus;
  advisoryIds?: string[];
  tcbEvaluationDataNumber?: number;
  fmspc?: string;
}

// ───────────────────────────── DER helpers (CRL parsing) ─────────────────────────────
interface Tlv {
  tag: number;
  start: number;
  end: number;
  next: number;
}
function tlv(b: Uint8Array, off: number, limit = b.length): Tlv {
  if (off + 2 > limit) throw new RangeError('DER truncated');
  const tag = b[off]!;
  let len = b[off + 1]!;
  let p = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || p + n > limit) throw new RangeError('DER bad length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[p + i]!;
    p += n;
  }
  if (p + len > limit) throw new RangeError('DER overrun');
  return { tag, start: p, end: p + len, next: p + len };
}
function derTime(b: Uint8Array, t: Tlv): number {
  const s = Buffer.from(b.subarray(t.start, t.end)).toString('ascii');
  let m: RegExpMatchArray | null;
  if (t.tag === 0x17) {
    m = s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
    if (!m) throw new RangeError('bad UTCTime');
    const yy = Number(m[1]);
    return Date.UTC(yy >= 50 ? 1900 + yy : 2000 + yy, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
  }
  if (t.tag === 0x18) {
    m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
    if (!m) throw new RangeError('bad GeneralizedTime');
    return Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
  }
  throw new RangeError('not a DER time');
}
function normSerial(hexOrBytes: string): string {
  return hexOrBytes.toLowerCase().replace(/^0+/, '');
}

interface ParsedCrl {
  tbs: Uint8Array;
  thisUpdate: number;
  nextUpdate: number;
  revoked: Set<string>;
  sigDer: Uint8Array;
}
function parseCrl(der: Uint8Array): ParsedCrl {
  const outer = tlv(der, 0);
  if (outer.tag !== 0x30 || outer.next !== der.length) throw new RangeError('CRL: bad outer SEQUENCE');
  const tbsT = tlv(der, outer.start, outer.end);
  if (tbsT.tag !== 0x30) throw new RangeError('CRL: bad TBSCertList');
  const tbs = der.slice(outer.start, tbsT.next);
  const algT = tlv(der, tbsT.next, outer.end);
  const sigT = tlv(der, algT.next, outer.end);
  if (sigT.tag !== 0x03 || sigT.next !== outer.end) throw new RangeError('CRL: bad signature');
  const sigDer = der.slice(sigT.start + 1, sigT.end); // skip unused-bits byte

  let p = tbsT.start;
  let t = tlv(der, p, tbsT.end);
  if (t.tag === 0x02) {
    p = t.next; // version
    t = tlv(der, p, tbsT.end);
  }
  p = t.next; // signature AlgorithmIdentifier
  const iss = tlv(der, p, tbsT.end);
  if (iss.tag !== 0x30) throw new RangeError('CRL: bad issuer');
  const tu = tlv(der, iss.next, tbsT.end);
  const thisUpdate = derTime(der, tu);
  let q = tu.next;
  let nextUpdate = Number.NaN;
  const revoked = new Set<string>();
  if (q < tbsT.end) {
    let n = tlv(der, q, tbsT.end);
    if (n.tag === 0x17 || n.tag === 0x18) {
      nextUpdate = derTime(der, n);
      q = n.next;
    }
    if (q < tbsT.end) {
      n = tlv(der, q, tbsT.end);
      if (n.tag === 0x30) {
        let e = n.start;
        while (e < n.end) {
          const ent = tlv(der, e, n.end);
          const ser = tlv(der, ent.start, ent.end);
          if (ser.tag !== 0x02) throw new RangeError('CRL: bad revoked entry');
          revoked.add(normSerial(Buffer.from(der.subarray(ser.start, ser.end)).toString('hex')));
          e = ent.next;
        }
      }
    }
  }
  if (!Number.isFinite(nextUpdate)) throw new RangeError('CRL: missing nextUpdate');
  return { tbs, thisUpdate, nextUpdate, revoked, sigDer };
}

/** Verify a CRL (DER) under `issuerKey` at `now`; returns the revoked serials (lowercase hex, no leading zeros). */
export function verifyCrl(crlDer: Uint8Array, issuerKey: KeyObject, now: Date): { ok: true; revoked: ReadonlySet<string> } | { ok: false; reason: string } {
  let crl: ParsedCrl;
  try {
    crl = parseCrl(crlDer);
  } catch (e) {
    return { ok: false, reason: `CRL parse failed: ${e instanceof Error ? e.message : 'unknown'}` };
  }
  if (!verify('sha256', crl.tbs, issuerKey, Buffer.from(crl.sigDer))) return { ok: false, reason: 'CRL signature does not verify under the issuer' };
  if (now.getTime() < crl.thisUpdate) return { ok: false, reason: 'CRL thisUpdate is in the future' };
  if (now.getTime() > crl.nextUpdate) return { ok: false, reason: 'CRL is stale (nextUpdate passed)' };
  return { ok: true, revoked: crl.revoked };
}
export function serialIsRevoked(revoked: ReadonlySet<string>, serialHex: string): boolean {
  return revoked.has(normSerial(serialHex));
}

// ───────────────────────────── certificates ─────────────────────────────
function pemBlocks(pem: string): string[] {
  return pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
}
function certValidAt(c: X509Certificate, now: Date): boolean {
  return now.getTime() >= Date.parse(c.validFrom) && now.getTime() <= Date.parse(c.validTo);
}
function toBytes(x: string | Uint8Array): Uint8Array {
  return typeof x === 'string' ? new TextEncoder().encode(x) : x;
}

/** Verify an issuer chain (leaf first) to the pinned root, validity at `now`, and that no cert is on the root CRL. */
async function signerKeyFromChain(
  chainPem: string,
  pin: string | undefined,
  now: Date,
  rootRevoked: ReadonlySet<string>,
): Promise<{ key: KeyObject } | { error: string }> {
  const chain = await verifyIntelPckChainX509({ pckChainPem: chainPem, trustAnchorRootCaSpkiSha256: pin, nowMs: now.getTime() });
  if (chain.failure === 'validity') return { error: 'issuer chain certificate outside its validity period' };
  if (!chain.ok || !chain.leafDer) return { error: `issuer chain invalid: ${chain.reason ?? 'unknown'}` };
  for (const b of pemBlocks(chainPem)) {
    const c = new X509Certificate(b);
    if (!certValidAt(c, now)) return { error: 'issuer chain certificate outside its validity period' };
    if (serialIsRevoked(rootRevoked, c.serialNumber)) return { error: 'issuer chain certificate is revoked by the Intel Root CA CRL' };
  }
  return { key: new X509Certificate(Buffer.from(chain.leafDer)).publicKey };
}

/** Extract the exact source bytes of the JSON value following `"<name>":` (string-aware brace matching). */
function rawJsonObject(text: string, name: string): string | null {
  const m = new RegExp(`^\\s*\\{\\s*"${name}"\\s*:\\s*`).exec(text);
  if (!m) return null;
  const s = m[0].length;
  if (text[s] !== '{') return null;
  let depth = 0;
  let inStr = false;
  for (let i = s; i < text.length; i++) {
    const ch = text[i]!;
    if (inStr) {
      if (ch === '\\') i++;
      else if (ch === '"') inStr = false;
    } else if (ch === '"') inStr = true;
    else if (ch === '{') depth++;
    else if (ch === '}' && --depth === 0) return text.slice(s, i + 1);
  }
  return null;
}

interface SignedDoc<T> {
  body: T;
}
function verifySignedJson(text: string, name: string, key: KeyObject): SignedDoc<Record<string, unknown>> | { error: string } {
  const raw = rawJsonObject(text, name);
  if (raw === null) return { error: `${name} not found / malformed` };
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return { error: `${name} document is not valid JSON` };
  }
  const sig = (doc as { signature?: unknown }).signature;
  if (typeof sig !== 'string' || !/^[0-9a-fA-F]{128}$/.test(sig)) return { error: `${name} signature missing or malformed` };
  const ok = verify('sha256', Buffer.from(raw, 'utf8'), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig, 'hex'));
  if (!ok) return { error: `${name} signature does not verify under the TCB Signing certificate` };
  const body = (doc as Record<string, unknown>)[name];
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return { error: `${name} is not an object` };
  return { body: body as Record<string, unknown> };
}

function checkFresh(body: Record<string, unknown>, what: string, now: Date): string | null {
  const issue = typeof body.issueDate === 'string' ? Date.parse(body.issueDate) : Number.NaN;
  const next = typeof body.nextUpdate === 'string' ? Date.parse(body.nextUpdate) : Number.NaN;
  if (!Number.isFinite(issue) || !Number.isFinite(next)) return `${what}: issueDate/nextUpdate missing`;
  if (now.getTime() < issue) return `${what}: issueDate is in the future`;
  if (now.getTime() > next) return `${what}: stale (nextUpdate passed)`;
  return null;
}

// ───────────────────────────── status evaluation ─────────────────────────────
function asStatus(s: unknown): TcbStatus | null {
  return typeof s === 'string' && (STATUS_ORDER as readonly string[]).includes(s) ? (s as TcbStatus) : null;
}
function worst(a: TcbStatus, b: TcbStatus): TcbStatus {
  return STATUS_ORDER.indexOf(a) >= STATUS_ORDER.indexOf(b) ? a : b;
}
function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}
function svns(comps: unknown): number[] | null {
  if (!Array.isArray(comps) || comps.length !== 16) return null;
  const out: number[] = [];
  for (const c of comps) {
    if (!isRecord(c) || typeof c.svn !== 'number') return null;
    out.push(c.svn);
  }
  return out;
}
function hexBytes(s: unknown, len: number): Uint8Array | null {
  if (typeof s !== 'string' || s.length !== len * 2 || !/^[0-9a-fA-F]+$/.test(s)) return null;
  return new Uint8Array(Buffer.from(s, 'hex'));
}
function advisories(level: Record<string, unknown>): string[] {
  return Array.isArray(level.advisoryIDs) ? level.advisoryIDs.filter((x): x is string => typeof x === 'string') : [];
}
function maskedEq(value: Uint8Array, mask: Uint8Array, expected: Uint8Array): boolean {
  for (let i = 0; i < value.length; i++) if (((value[i]! & mask[i]!) ^ (expected[i]! & mask[i]!)) !== 0) return false;
  return true;
}

interface TdFields {
  teeTcbSvn: Uint8Array;
  mrSignerSeam: Uint8Array;
  seamAttributes: Uint8Array;
}

function evaluateTcb(
  info: Record<string, unknown>,
  pck: { sgx: Uint8Array; pcesvn: number },
  td: TdFields,
): { error: string } | { platform: TcbStatus; module: TcbStatus; advisories: string[] } {
  const levels = info.tcbLevels;
  if (!Array.isArray(levels) || levels.length === 0) return { error: 'TCB info has no tcbLevels' };
  const minor = td.teeTcbSvn[1]!;

  // TDX module identity (minor version > 0) or the base tdxModule (minor == 0).
  let moduleStatus: TcbStatus = 'UpToDate';
  const adv = new Set<string>();
  let modMrSigner: unknown;
  let modAttr: unknown;
  let modMask: unknown;
  if (minor > 0) {
    const id = `TDX_${minor.toString(16).toUpperCase().padStart(2, '0')}`;
    const ids = info.tdxModuleIdentities;
    const ident = Array.isArray(ids) ? ids.find((x): x is Record<string, unknown> => isRecord(x) && x.id === id) : undefined;
    if (!ident) return { error: `TDX module identity ${id} not present in TCB info` };
    modMrSigner = ident.mrsigner;
    modAttr = ident.attributes;
    modMask = ident.attributesMask;
    const lv = Array.isArray(ident.tcbLevels) ? ident.tcbLevels : [];
    const hit = lv.find((l): l is Record<string, unknown> => isRecord(l) && isRecord(l.tcb) && typeof l.tcb.isvsvn === 'number' && l.tcb.isvsvn <= td.teeTcbSvn[0]!);
    if (!hit) return { error: `TDX module ${id} SVN ${td.teeTcbSvn[0]} is below every known level` };
    const st = asStatus(hit.tcbStatus);
    if (!st) return { error: 'TDX module level has an unknown tcbStatus' };
    moduleStatus = st;
    for (const a of advisories(hit)) adv.add(a);
  } else {
    const m = info.tdxModule;
    if (!isRecord(m)) return { error: 'TCB info missing tdxModule' };
    modMrSigner = m.mrsigner;
    modAttr = m.attributes;
    modMask = m.attributesMask;
  }
  const exMr = hexBytes(modMrSigner, 48);
  const exAttr = hexBytes(modAttr, 8);
  const mask = hexBytes(modMask, 8);
  if (!exMr || !exAttr || !mask) return { error: 'TDX module identity fields malformed' };
  if (Buffer.compare(Buffer.from(exMr), Buffer.from(td.mrSignerSeam)) !== 0) return { error: 'TD report MRSIGNERSEAM does not match the TDX module identity' };
  if (!maskedEq(td.seamAttributes, mask, exAttr)) return { error: 'TD report SEAM attributes do not match the TDX module identity' };

  const from = minor > 0 ? 2 : 0; // identity covers the module SVN/version components
  for (const l of levels) {
    if (!isRecord(l) || !isRecord(l.tcb)) return { error: 'malformed TCB level' };
    const sgx = svns(l.tcb.sgxtcbcomponents);
    const tdx = svns(l.tcb.tdxtcbcomponents);
    if (!sgx || !tdx || typeof l.tcb.pcesvn !== 'number') return { error: 'malformed TCB level components' };
    const st = asStatus(l.tcbStatus);
    if (!st) return { error: 'TCB level has an unknown tcbStatus' };
    let match = pck.pcesvn >= l.tcb.pcesvn;
    for (let i = 0; match && i < 16; i++) if (pck.sgx[i]! < sgx[i]!) match = false;
    for (let i = from; match && i < 16; i++) if (td.teeTcbSvn[i]! < tdx[i]!) match = false;
    if (!match) continue;
    for (const a of advisories(l)) adv.add(a);
    return { platform: st, module: moduleStatus, advisories: [...adv].sort() };
  }
  return { error: 'platform TCB is below every level in the TCB info' };
}

function evaluateQe(
  ident: Record<string, unknown>,
  qe: Uint8Array,
): { error: string } | { status: TcbStatus; advisories: string[] } {
  if (ident.id !== 'TD_QE') return { error: 'QE identity id is not TD_QE' };
  if (ident.version !== 2) return { error: 'unsupported QE identity version' };
  const miscsel = hexBytes(ident.miscselect, 4);
  const miscMask = hexBytes(ident.miscselectMask, 4);
  const attr = hexBytes(ident.attributes, 16);
  const attrMask = hexBytes(ident.attributesMask, 16);
  const mrsigner = hexBytes(ident.mrsigner, 32);
  if (!miscsel || !miscMask || !attr || !attrMask || !mrsigner || typeof ident.isvprodid !== 'number') return { error: 'QE identity fields malformed' };
  if (qe.length !== 384) return { error: 'QE report has wrong length' };
  if (!maskedEq(qe.subarray(16, 20), miscMask, miscsel)) return { error: 'QE MISCSELECT does not match the QE identity' };
  if (!maskedEq(qe.subarray(48, 64), attrMask, attr)) return { error: 'QE ATTRIBUTES do not match the QE identity' };
  if (Buffer.compare(Buffer.from(qe.subarray(128, 160)), Buffer.from(mrsigner)) !== 0) return { error: 'QE MRSIGNER does not match the QE identity' };
  const prod = qe[256]! | (qe[257]! << 8);
  const isvsvn = qe[258]! | (qe[259]! << 8);
  if (prod !== ident.isvprodid) return { error: 'QE ISVPRODID does not match the QE identity' };
  const lv = Array.isArray(ident.tcbLevels) ? ident.tcbLevels : [];
  const hit = lv.find((l): l is Record<string, unknown> => isRecord(l) && isRecord(l.tcb) && typeof l.tcb.isvsvn === 'number' && l.tcb.isvsvn <= isvsvn);
  if (!hit) return { error: 'QE ISVSVN is below every known level' };
  const st = asStatus(hit.tcbStatus);
  if (!st) return { error: 'QE level has an unknown tcbStatus' };
  return { status: st, advisories: advisories(hit) };
}

// ───────────────────────────── entry point ─────────────────────────────
/**
 * Verify a genuine Intel DCAP TDX quote (via {@link verifyGenuineTdxQuote}) and then its Intel PCS
 * collateral at time `now`, returning the evaluated TCB status and the policy decision. Fail closed.
 */
export async function verifyIntelTdxCollateral(opts: {
  quote: Uint8Array;
  collateral: IntelTdxCollateral;
  now: Date;
  policy?: IntelCollateralPolicy;
  trustAnchorRootCaSpkiSha256?: string;
  /** INSECURE opt-in, forwarded to the quote check: accept a TD with TD_ATTRIBUTES.DEBUG set. Default false. */
  allowDebug?: boolean;
}): Promise<IntelCollateralResult> {
  const fail = (reason: string): IntelCollateralResult => ({ ok: false, reason });
  try {
    const c = opts.collateral;
    if (!c || !c.tcbInfoJson || !c.qeIdentityJson || !c.pckCrlDer?.length || !c.rootCrlDer?.length || !c.tcbInfoIssuerChainPem || !c.qeIdentityIssuerChainPem) {
      return fail('collateral incomplete (fail closed)');
    }
    const pin = opts.trustAnchorRootCaSpkiSha256;
    const base = await verifyGenuineTdxQuote({ quote: opts.quote, trustAnchorRootCaSpkiSha256: pin, nowMs: opts.now.getTime(), ...(opts.allowDebug === true ? { policy: { allowDebug: true } } : {}) });
    if (!base.ok || !base.pckTcb || !base.fmspc) return fail(`quote invalid: ${base.reason ?? 'unknown'}`);
    const q = parseDcapQuote(opts.quote);

    // quote's PCK chain: validity at `now`
    const quoteCerts = pemBlocks(q.pckChainPem).map((b) => new X509Certificate(b));
    for (const x of quoteCerts) if (!certValidAt(x, opts.now)) return fail('PCK chain certificate outside its validity period');
    const leaf = quoteCerts.find((x) => !quoteCerts.some((y) => y.issuer === x.subject));
    if (!leaf) return fail('PCK leaf not found');
    const ca = quoteCerts.find((x) => x.subject === leaf.issuer);
    if (!ca) return fail('PCK CA not found in the quote chain');
    const root = quoteCerts.find((x) => x.subject === x.issuer);
    if (!root) return fail('Intel root not found in the quote chain');

    // root CRL: signed by the pinned root (the quote chain's root was already pin-verified); PCK CRL by the PCK CA
    const rootCrl = verifyCrl(c.rootCrlDer, root.publicKey, opts.now);
    if (!rootCrl.ok) return fail(`Intel Root CA CRL: ${rootCrl.reason}`);
    const pckCrl = verifyCrl(c.pckCrlDer, ca.publicKey, opts.now);
    if (!pckCrl.ok) return fail(`PCK CRL: ${pckCrl.reason}`);
    if (serialIsRevoked(rootCrl.revoked, ca.serialNumber)) return fail('PCK CA certificate is revoked by the Intel Root CA CRL');
    if (serialIsRevoked(pckCrl.revoked, leaf.serialNumber)) return fail('PCK leaf certificate is revoked by the PCK CRL');

    // TCB info
    const tcbKey = await signerKeyFromChain(c.tcbInfoIssuerChainPem, pin, opts.now, rootCrl.revoked);
    if ('error' in tcbKey) return fail(`TCB info: ${tcbKey.error}`);
    const tcbDoc = verifySignedJson(Buffer.from(toBytes(c.tcbInfoJson)).toString('utf8'), 'tcbInfo', tcbKey.key);
    if ('error' in tcbDoc) return fail(`TCB info: ${tcbDoc.error}`);
    const info = tcbDoc.body;
    const stale = checkFresh(info, 'TCB info', opts.now);
    if (stale) return fail(stale);
    if (info.id !== 'TDX' || info.version !== 3) return fail('TCB info is not a TDX v3 document');
    if (typeof info.fmspc !== 'string' || info.fmspc.toLowerCase() !== base.fmspc) return fail('TCB info FMSPC does not match the quote PCK');

    // QE identity
    const qeKey = await signerKeyFromChain(c.qeIdentityIssuerChainPem, pin, opts.now, rootCrl.revoked);
    if ('error' in qeKey) return fail(`QE identity: ${qeKey.error}`);
    const qeDoc = verifySignedJson(Buffer.from(toBytes(c.qeIdentityJson)).toString('utf8'), 'enclaveIdentity', qeKey.key);
    if ('error' in qeDoc) return fail(`QE identity: ${qeDoc.error}`);
    const staleQe = checkFresh(qeDoc.body, 'QE identity', opts.now);
    if (staleQe) return fail(staleQe);

    const minEval = opts.policy?.minTcbEvaluationDataNumber;
    const infoNum = typeof info.tcbEvaluationDataNumber === 'number' ? info.tcbEvaluationDataNumber : -1;
    const qeNum = typeof qeDoc.body.tcbEvaluationDataNumber === 'number' ? qeDoc.body.tcbEvaluationDataNumber : -1;
    if (infoNum < 0 || qeNum < 0) return fail('tcbEvaluationDataNumber missing');
    if (minEval !== undefined && (infoNum < minEval || qeNum < minEval)) return fail('tcbEvaluationDataNumber below policy minimum');

    // evaluation
    const body = q.tdReportBody;
    const td: TdFields = { teeTcbSvn: body.slice(0, 16), mrSignerSeam: body.slice(64, 112), seamAttributes: body.slice(112, 120) };
    const pck = extractPckFmspcAndTcb(new Uint8Array(leaf.raw));
    const tcb = evaluateTcb(info, { sgx: pck.sgxTcbComponents, pcesvn: pck.pcesvn }, td);
    if ('error' in tcb) return fail(`TCB evaluation: ${tcb.error}`);
    const qe = evaluateQe(qeDoc.body, q.qeReportBody);
    if ('error' in qe) return fail(`QE identity: ${qe.error}`);

    const status = worst(worst(tcb.platform, tcb.module), qe.status);
    const advisoryIds = [...new Set([...tcb.advisories, ...qe.advisories])].sort();
    const result: IntelCollateralResult = {
      ok: false,
      status,
      platformStatus: tcb.platform,
      tdxModuleStatus: tcb.module,
      qeStatus: qe.status,
      advisoryIds,
      tcbEvaluationDataNumber: Math.min(infoNum, qeNum),
      fmspc: toHex(pck.fmspc),
    };
    const accepted = opts.policy?.acceptStatuses ?? DEFAULT_ACCEPTED_STATUSES;
    if (!accepted.includes(status)) return { ...result, reason: `TCB status ${status} is not accepted by policy` };
    return { ...result, ok: true };
  } catch (e) {
    return fail(`collateral verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
  }
}

/** Decode a PCS issuer-chain HTTP header value (URL-encoded PEM) to PEM. */
export function decodeIssuerChainHeader(value: string): string {
  return decodeURIComponent(value);
}

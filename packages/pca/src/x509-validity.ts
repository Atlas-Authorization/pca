/**
 * Validity window of a Node `X509Certificate`, in epoch milliseconds, parsed WITHOUT `Date.parse`.
 *
 * Node renders a certificate's notBefore / notAfter through OpenSSL as e.g. "Jan  1 00:00:00 2030 GMT". Two cases break
 * the obvious `Date.parse(cert.validTo)`:
 *   - a GeneralizedTime year below 1000 is printed unpadded ("Jan  1 00:00:00 49 GMT"), and `Date.parse` reads a
 *     two-digit year as 19xx/20xx: a certificate that expired in year 49 looked valid until 2049;
 *   - an out-of-range field (second 60, month 13, Feb 30, ...) is printed as "Bad time value", which parses to NaN, and
 *     a check written as `now < from || now > to` then accepts at ANY time.
 * Worse, what Node renders (and `validFromDate` / `validToDate`, Node >= 22.10) depends on the OpenSSL it links: some builds
 * accept a seconds field of 60 and roll it over, others render "Bad time value". The verdict must not depend on the box.
 *
 * So the instants are read from the certificate's OWN DER (`cert.raw`, the TBSCertificate `validity` field), with the
 * RFC 5280 profile applied strictly ({@link parseDerTime}): UTCTime YYMMDDHHMMSSZ or GeneralizedTime YYYYMMDDHHMMSSZ, every
 * field in range, no roll-over, no fractions, no offsets. Only an object WITHOUT `raw` (a hand-made shim) falls back to
 * `validFromDate` / `validToDate`, then to the strictly parsed rendering (four-digit year only). Anything unparseable is NaN,
 * and {@link x509ValidAt} is false for NaN (fail closed).
 */
export interface X509ValidityLike {
  readonly validFrom: string;
  readonly validTo: string;
  readonly validFromDate?: Date;
  readonly validToDate?: Date;
  /** DER of the whole certificate (Node's `X509Certificate.raw`). When present it is the ONLY source of the instants. */
  readonly raw?: Uint8Array;
}

/** One DER TLV at `off`: tag, content start, content end. Throws on anything not a well-formed definite length. */
function tlvAt(der: Uint8Array, off: number): { tag: number; start: number; end: number } {
  if (off + 2 > der.length) throw new RangeError('truncated');
  const tag = der[off]!;
  let len = der[off + 1]!;
  let start = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || start + n > der.length) throw new RangeError('bad length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + der[start + i]!;
    start += n;
  }
  const end = start + len;
  if (end > der.length) throw new RangeError('truncated');
  return { tag, start, end };
}

const DIGITS = /^\d+$/;

/**
 * Strict RFC 5280 Time (section 4.1.2.5): tag 0x17 UTCTime "YYMMDDHHMMSSZ" (YY >= 50 => 19YY, else 20YY) or tag 0x18
 * GeneralizedTime "YYYYMMDDHHMMSSZ". Month 1-12, day valid for that month and year, hour <= 23, minute <= 59, second <= 59.
 * NaN for anything else (fail closed).
 */
export function parseDerTime(tag: number, text: string): number {
  let y: number;
  let rest: string;
  if (tag === 0x17 && text.length === 13) {
    const yy = Number(text.slice(0, 2));
    y = yy >= 50 ? 1900 + yy : 2000 + yy;
    rest = text.slice(2);
  } else if (tag === 0x18 && text.length === 15) {
    y = Number(text.slice(0, 4));
    rest = text.slice(4);
  } else return NaN;
  if (rest[10] !== 'Z' || !DIGITS.test(text.slice(0, text.length - 1))) return NaN;
  const mon = Number(rest.slice(0, 2)), day = Number(rest.slice(2, 4)), h = Number(rest.slice(4, 6)), mi = Number(rest.slice(6, 8)), sec = Number(rest.slice(8, 10));
  if (mon < 1 || mon > 12 || day < 1 || h > 23 || mi > 59 || sec > 59) return NaN;
  const d = new Date(0);
  d.setUTCFullYear(y, mon - 1, day);
  d.setUTCHours(h, mi, sec, 0);
  if (d.getUTCMonth() !== mon - 1 || d.getUTCDate() !== day) return NaN; // Feb 30, Apr 31, ...
  return d.getTime();
}

/** The `validity` instants of a DER certificate (Certificate -> tbsCertificate -> validity); NaN members when malformed. */
export function derValidityMs(der: Uint8Array): { from: number; to: number } {
  try {
    const cert = tlvAt(der, 0);
    if (cert.tag !== 0x30) throw new RangeError('not a SEQUENCE');
    const tbs = tlvAt(der, cert.start);
    if (tbs.tag !== 0x30) throw new RangeError('not a SEQUENCE');
    let off = tbs.start;
    let el = tlvAt(der, off);
    if (el.tag === 0xa0) el = tlvAt(der, (off = el.end)); // optional [0] version
    // serialNumber INTEGER, signature AlgorithmIdentifier, issuer Name, then validity
    if (el.tag !== 0x02) throw new RangeError('serial');
    el = tlvAt(der, (off = el.end));
    if (el.tag !== 0x30) throw new RangeError('signature');
    el = tlvAt(der, (off = el.end));
    if (el.tag !== 0x30) throw new RangeError('issuer');
    const validity = tlvAt(der, el.end);
    if (validity.tag !== 0x30 || validity.end > tbs.end) throw new RangeError('validity');
    const nb = tlvAt(der, validity.start);
    const na = tlvAt(der, nb.end);
    if (na.end !== validity.end) throw new RangeError('validity has extra fields');
    const text = (t: { start: number; end: number }) => String.fromCharCode(...der.subarray(t.start, t.end));
    return { from: parseDerTime(nb.tag, text(nb)), to: parseDerTime(na.tag, text(na)) };
  } catch {
    return { from: NaN, to: NaN };
  }
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const RENDERED = /^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(\.\d+)? (\d{4}) GMT$/;

/** Strict parse of OpenSSL's rendered ASN1_TIME ("Mon DD HH:MM:SS[.fff] YYYY GMT"); NaN for anything else. */
export function parseOpenSslTime(s: unknown): number {
  if (typeof s !== 'string') return NaN;
  const m = RENDERED.exec(s);
  if (!m) return NaN;
  const mon = MONTHS.indexOf(m[1]!);
  const day = Number(m[2]), h = Number(m[3]), mi = Number(m[4]), sec = Number(m[5]), y = Number(m[7]);
  if (mon < 0 || day < 1 || day > 31 || h > 23 || mi > 59 || sec > 59) return NaN;
  const ms = m[6] ? Math.floor(Number('0' + m[6]) * 1000) : 0;
  const d = new Date(0);
  d.setUTCFullYear(y, mon, day);
  d.setUTCHours(h, mi, sec, ms);
  // reject roll-over (Feb 30 -> Mar 2)
  if (d.getUTCMonth() !== mon || d.getUTCDate() !== day) return NaN;
  return d.getTime();
}

function instant(date: Date | undefined, rendered: string): number {
  if (date instanceof Date) {
    const t = date.getTime();
    return Number.isFinite(t) ? t : NaN;
  }
  return parseOpenSslTime(rendered);
}

/** The certificate's validity window in epoch ms; NaN members when a bound is unparseable. */
export function x509ValidityMs(cert: X509ValidityLike): { from: number; to: number } {
  if (cert.raw instanceof Uint8Array) return derValidityMs(cert.raw);
  return { from: instant(cert.validFromDate, cert.validFrom), to: instant(cert.validToDate, cert.validTo) };
}

/** True iff both bounds parse and `from - skew <= nowMs <= to + skew`. False (fail closed) for any unparseable bound. */
export function x509ValidAt(cert: X509ValidityLike, nowMs: number, skewMs = 0): boolean {
  const { from, to } = x509ValidityMs(cert);
  if (!Number.isFinite(from) || !Number.isFinite(to) || !Number.isFinite(nowMs) || !Number.isFinite(skewMs)) return false;
  return nowMs + skewMs >= from && nowMs - skewMs <= to;
}

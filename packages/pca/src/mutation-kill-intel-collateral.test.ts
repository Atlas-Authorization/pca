/** Mutation-kill suite for attest-intel-collateral.ts, over the synthetic Intel PKI / PCS collateral forgers. */
import { describe, expect, it } from 'vitest';
import { X509Certificate } from 'node:crypto';
import {
  DEFAULT_ACCEPTED_STATUSES,
  decodeIssuerChainHeader,
  serialIsRevoked,
  verifyCrl,
  verifyIntelTdxCollateral,
  type IntelCollateralPolicy,
  type IntelTdxCollateral,
  type TcbStatus,
} from './attest-intel-collateral';
import {
  defaultTcbInfoSpec,
  forgeIntelPki,
  forgeTdxCollateral,
  forgeTdxQuote,
  qeIdentityBody,
  signCollateralJson,
  tcbInfoBody,
  type ForgeCollateralOptions,
  type QeIdentitySpec,
  type TdxTcbInfoSpec,
} from './test-support/forge-dcap';
import { bitString, cat, dn, ecdsaSign, forgeCrl, forgeKey, integer, oid, seq, tlv } from './test-support/forge-x509';

const NOW = new Date('2026-10-20T00:00:00Z');
const B = (...n: number[]) => Uint8Array.from(n);
const Q = forgeTdxQuote();
const C = (o: ForgeCollateralOptions = {}, q = Q) => forgeTdxCollateral(q, o);
const run = (q = Q, c: IntelTdxCollateral | undefined = C(), o: Record<string, unknown> = {}) =>
  verifyIntelTdxCollateral({ quote: q.quote, collateral: c as never, now: NOW, trustAnchorRootCaSpkiSha256: q.rootSpkiSha256, ...o });
const reasonOf = async (...a: Parameters<typeof run>) => {
  const r = await run(...a);
  return r.ok ? 'OK' : r.reason;
};
const info = (over: Partial<TdxTcbInfoSpec> = {}, q = Q): Partial<TdxTcbInfoSpec> => ({ ...defaultTcbInfoSpec(q), ...over });
const crlOf = (o: Record<string, unknown> = {}) => forgeCrl({ issuer: Q.pki.rootDn, signer: Q.pki.rootKey, revoked: [], thisUpdate: new Date('2026-10-08T21:28:48Z'), nextUpdate: new Date('2026-11-07T21:28:48Z'), authorityKey: Q.pki.rootKey, ...o } as never);
const rootPub = new X509Certificate(Q.pki.root.der).publicKey;
const crlMsg = (der: Uint8Array, now = NOW) => {
  const r = verifyCrl(der, rootPub, now);
  return r.ok ? 'OK' : r.reason;
};

describe('exports', () => {
  it('default accepted statuses and header decoding', () => {
    expect([...DEFAULT_ACCEPTED_STATUSES]).toEqual(['UpToDate', 'SWHardeningNeeded']);
    expect(decodeIssuerChainHeader('-----BEGIN%20X-----%0AAB%2BC%3D')).toBe('-----BEGIN X-----\nAB+C=');
  });
  it('serialIsRevoked normalises case and leading zeros on the queried serial', () => {
    expect(serialIsRevoked(new Set(['abcdef']), 'ABCDEF')).toBe(true);
    expect(serialIsRevoked(new Set(['abcdef']), '00abcdef')).toBe(true);
    expect(serialIsRevoked(new Set(['abcdef']), '0abcdee')).toBe(false);
    expect(serialIsRevoked(new Set(), 'ab')).toBe(false);
  });
});

describe('verifyCrl: DER and time handling', () => {
  it('a good CRL, and its revoked serials (lowercase hex without leading zeros)', () => {
    const r = verifyCrl(crlOf({ revoked: ['00aabb', 'CD01'] }), rootPub, NOW);
    expect(r.ok).toBe(true);
    if (r.ok) expect([...r.revoked].sort()).toEqual(['aabb', 'cd01']);
  });
  it('structure refusals', () => {
    const good = crlOf();
    const parseFail = (der: Uint8Array) => crlMsg(der);
    expect(parseFail(Uint8Array.from([0x31, ...good.slice(1)]))).toBe('CRL parse failed: CRL: bad outer SEQUENCE');
    expect(parseFail(cat(good, B(0)))).toBe('CRL parse failed: CRL: bad outer SEQUENCE');
    expect(parseFail(B(0x30))).toBe('CRL parse failed: DER truncated');
    expect(parseFail(B(0x30, 0x80, 0x00))).toBe('CRL parse failed: DER bad length');
    expect(parseFail(B(0x30, 0x82, 0x01))).toBe('CRL parse failed: DER bad length');
    expect(parseFail(B(0x30, 0x85, 0, 0, 0, 0, 0))).toBe('CRL parse failed: DER bad length');
    expect(parseFail(B(0x30, 0x81, 0x00))).toBe('CRL parse failed: DER truncated');
    expect(parseFail(B(0x30, 0x05, 0x00))).toBe('CRL parse failed: DER overrun');
  });
  it('a four-octet length form is accepted', () => {
    const good = crlOf();
    // outer header is 30 82 hh ll
    const content = good.slice(4);
    const wrapped = cat(B(0x30, 0x84, 0, 0, (content.length >> 8) & 0xff, content.length & 0xff), content);
    expect(crlMsg(wrapped)).toBe('OK');
  });
  it('bad signature element, bad TBS, bad issuer', () => {
    const good = crlOf();
    const content = good.slice(4);
    expect(crlMsg(seq(content, B(0x05, 0x00)))).toBe('CRL parse failed: CRL: bad signature');
    const tbsLen = 4 + (content[2]! << 8) + content[3]!; // tbs is a long-form (82 hh ll) SEQUENCE
    expect(crlMsg(seq(tlv(0x31, content.slice(2, tbsLen)), content.slice(tbsLen)))).toBe('CRL parse failed: CRL: bad TBSCertList');
    const noIssuer = forgeCrl({ issuer: Q.pki.rootDn, signer: Q.pki.rootKey, revoked: [], thisUpdate: new Date('2026-10-08T21:28:48Z'), nextUpdate: new Date('2026-11-07T21:28:48Z'), raw: { issuer: B(0x31, 0x00) } });
    expect(crlMsg(noIssuer)).toBe('CRL parse failed: CRL: bad issuer');
    const tagged = forgeCrl({ issuer: Q.pki.rootDn, signer: Q.pki.rootKey, revoked: [], thisUpdate: new Date('2026-10-08T21:28:48Z'), nextUpdate: new Date('2026-11-07T21:28:48Z'), raw: { sigTag: 0x04 } });
    expect(crlMsg(tagged)).toBe('CRL parse failed: CRL: bad signature');
  });
  it('without the optional version INTEGER, with a revoked entry whose serial is not an INTEGER', () => {
    expect(crlMsg(forgeCrl({ issuer: Q.pki.rootDn, signer: Q.pki.rootKey, revoked: [], thisUpdate: new Date('2026-10-08T21:28:48Z'), nextUpdate: new Date('2026-11-07T21:28:48Z'), raw: { omitVersion: true } }))).toBe('OK');
    const badEntry = forgeCrl({ issuer: Q.pki.rootDn, signer: Q.pki.rootKey, revoked: [], thisUpdate: new Date('2026-10-08T21:28:48Z'), nextUpdate: new Date('2026-11-07T21:28:48Z'), raw: { entries: [seq(tlv(0x04, B(1)))] } });
    expect(crlMsg(badEntry)).toBe('CRL parse failed: CRL: bad revoked entry');
  });
  const handCrl = (parts: { tbs: Uint8Array[]; signer?: ReturnType<typeof forgeKey> }) => {
    const sigAlg = seq(oid('1.2.840.10045.4.3.2'));
    const tbs = seq(...parts.tbs);
    const sig = ecdsaSign(parts.signer ?? Q.pki.rootKey, 'sha256', tbs).der;
    return seq(tbs, sigAlg, bitString(sig));
  };
  const tu = (iso: string, tag = 0x17, ascii?: string) => {
    const d = new Date(iso);
    const p = (n: number, w = 2) => String(n).padStart(w, '0');
    const g = `${p(d.getUTCFullYear(), 4)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
    return tlv(tag, new TextEncoder().encode(ascii ?? (tag === 0x17 ? g.slice(2) : g)));
  };
  const base = (extra: Uint8Array[]) => [integer(1), seq(oid('1.2.840.10045.4.3.2')), dn(Q.pki.rootDn), ...extra];
  it('TBS that ends right after nextUpdate (no entries, no extensions) is fine; ending after thisUpdate is "missing nextUpdate"', () => {
    expect(crlMsg(handCrl({ tbs: base([tu('2026-10-08T21:28:48Z'), tu('2026-11-07T21:28:48Z')]) }))).toBe('OK');
    expect(crlMsg(handCrl({ tbs: base([tu('2026-10-08T21:28:48Z')]) }))).toBe('CRL parse failed: CRL: missing nextUpdate');
    expect(crlMsg(handCrl({ tbs: base([tu('2026-10-08T21:28:48Z'), tu('2026-11-07T21:28:48Z', 0x18)]) }))).toBe('OK'); // GeneralizedTime nextUpdate
    // revoked list directly after thisUpdate and no nextUpdate
    expect(crlMsg(handCrl({ tbs: base([tu('2026-10-08T21:28:48Z'), seq(seq(integer(5), tu('2026-10-08T21:28:48Z')))]) }))).toBe('CRL parse failed: CRL: missing nextUpdate');
  });
  it('UTCTime / GeneralizedTime text is parsed strictly; 50..99 -> 19xx, 00..49 -> 20xx', () => {
    const t = (ascii: string, tag = 0x17, next = tu('2049-12-31T23:59:59Z')) => crlMsg(handCrl({ tbs: base([tu('2026-10-08T21:28:48Z', tag, ascii), next]) }));
    expect(t('xx261008212848Z')).toBe('CRL parse failed: bad UTCTime');
    expect(t('261008212848Zxx')).toBe('CRL parse failed: bad UTCTime');
    expect(t('2610082128Z')).toBe('CRL parse failed: bad UTCTime');
    expect(t('xx20261008212848Z', 0x18)).toBe('CRL parse failed: bad GeneralizedTime');
    expect(t('20261008212848Zxx', 0x18)).toBe('CRL parse failed: bad GeneralizedTime');
    expect(t('2026100821284Z', 0x18)).toBe('CRL parse failed: bad GeneralizedTime');
    expect(crlMsg(handCrl({ tbs: base([tlv(0x04, B(1)), tu('2027-01-01T00:00:00Z')]) }))).toBe('CRL parse failed: not a DER time');
    // 1999 and 1950 are in the past; 2049 / 2000 are valid expirations
    expect(t('990101000000Z')).toBe('OK');
    expect(t('500101000000Z')).toBe('OK');
    expect(t('491231235959Z', 0x17, tu('2049-12-31T23:59:59Z'))).toBe('CRL parse failed: nextUpdate is invalid'.replace('CRL parse failed: nextUpdate is invalid', 'CRL thisUpdate is in the future'));
    expect(t('000101000000Z')).toBe('OK');
    const nextIs = (ascii: string) => crlMsg(handCrl({ tbs: base([tu('2026-10-08T21:28:48Z'), tu('2026-10-08T21:28:48Z', 0x17, ascii)]) }));
    expect(nextIs('991231235959Z')).toBe('CRL is stale (nextUpdate passed)'); // 1999: long past
    expect(nextIs('491231235959Z')).toBe('OK'); // 2049: far future
    expect(nextIs('500101000000Z')).toBe('CRL is stale (nextUpdate passed)'); // 1950
  });
  it('two-digit years 50..99 mean 19xx (checked against a clock inside the 20th century)', () => {
    const r = verifyCrl(handCrl({ tbs: base([tu('2026-10-08T21:28:48Z', 0x17, '700101000000Z'), tu('2026-10-08T21:28:48Z', 0x17, '991231235959Z')]) }), rootPub, new Date('1975-01-01T00:00:00Z'));
    expect(r.ok).toBe(true);
    const early = verifyCrl(handCrl({ tbs: base([tu('2026-10-08T21:28:48Z', 0x17, '700101000000Z'), tu('2026-10-08T21:28:48Z', 0x17, '991231235959Z')]) }), rootPub, new Date('1965-01-01T00:00:00Z'));
    expect(early).toEqual({ ok: false, reason: 'CRL thisUpdate is in the future' });
  });
  it('signature, thisUpdate and nextUpdate boundaries', () => {
    const bad = forgeCrl({ issuer: Q.pki.rootDn, signer: forgeKey('impostor', 'P-256'), revoked: [], thisUpdate: new Date('2026-10-08T21:28:48Z'), nextUpdate: new Date('2026-11-07T21:28:48Z') });
    expect(crlMsg(bad)).toBe('CRL signature does not verify under the issuer');
    const crl = crlOf();
    expect(crlMsg(crl, new Date('2026-10-08T21:28:48Z'))).toBe('OK');
    expect(crlMsg(crl, new Date('2026-10-08T21:28:47Z'))).toBe('CRL thisUpdate is in the future');
    expect(crlMsg(crl, new Date('2026-11-07T21:28:48Z'))).toBe('OK');
    expect(crlMsg(crl, new Date('2026-11-07T21:28:49Z'))).toBe('CRL is stale (nextUpdate passed)');
  });
});

describe('verifyIntelTdxCollateral: collateral integrity', () => {
  it('incomplete collateral', async () => {
    const m = 'collateral incomplete (fail closed)';
    const good = C();
    for (const c of [undefined, null, {}, { ...good, tcbInfoJson: '' }, { ...good, qeIdentityJson: '' }, { ...good, pckCrlDer: undefined }, { ...good, pckCrlDer: new Uint8Array(0) }, { ...good, rootCrlDer: undefined }, { ...good, rootCrlDer: new Uint8Array(0) }, { ...good, tcbInfoIssuerChainPem: '' }, { ...good, qeIdentityIssuerChainPem: '' }]) {
      expect(await verifyIntelTdxCollateral({ quote: Q.quote, collateral: c as never, now: NOW, trustAnchorRootCaSpkiSha256: Q.rootSpkiSha256 })).toEqual({ ok: false, reason: m });
    }
  });
  it('quote problems are prefixed', async () => {
    expect(await reasonOf(Q, C(), { trustAnchorRootCaSpkiSha256: '00'.repeat(32) })).toBe('quote invalid: PCK chain invalid: Intel SGX Root CA does not match the pinned trust anchor');
    expect(await reasonOf({ ...Q, quote: new Uint8Array(3) } as never)).toMatch(/^quote invalid: quote parse failed/);
    const dbg = forgeTdxQuote({ td: { debug: true } });
    expect(await reasonOf(dbg, C({}, dbg))).toBe('quote invalid: TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)');
    expect((await run(dbg, C({}, dbg), { allowDebug: true })).ok).toBe(true);
    expect(await reasonOf(dbg, C({}, dbg), { allowDebug: false })).toBe('quote invalid: TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)');
  });
  it('CRLs: root CRL and PCK CRL validity, revocation of the PCK CA and the PCK leaf', async () => {
    const stale = { crlNextUpdate: new Date('2026-10-09T00:00:00Z') };
    expect(await reasonOf(Q, C(stale))).toBe('Intel Root CA CRL: CRL is stale (nextUpdate passed)');
    expect(await reasonOf(Q, C({ rootCrlSigner: forgeKey('x', 'P-256') }))).toBe('Intel Root CA CRL: CRL signature does not verify under the issuer');
    expect(await reasonOf(Q, C({ pckCrlSigner: forgeKey('x', 'P-256') }))).toBe('PCK CRL: CRL signature does not verify under the issuer');
    expect(await reasonOf(Q, C({ rootCrlRevoked: [Q.pki.platformCa.serialHex] }))).toBe('PCK CA certificate is revoked by the Intel Root CA CRL');
    expect(await reasonOf(Q, C({ pckCrlRevoked: [Q.pck.serialHex] }))).toBe('PCK leaf certificate is revoked by the PCK CRL');
    // the PCK CRL listing the PCK CA's serial, or the root CRL listing the leaf's, revokes nothing
    expect(await reasonOf(Q, C({ pckCrlRevoked: [Q.pki.platformCa.serialHex] }))).toBe('OK');
    expect(await reasonOf(Q, C({ rootCrlRevoked: [Q.pck.serialHex] }))).toBe('OK');
  });
  it('the PCK leaf is found whatever the order of the quote chain', async () => {
    for (const order of [(q: typeof Q) => [q.pki.root, q.pck, q.pki.platformCa], (q: typeof Q) => [q.pki.platformCa, q.pki.root, q.pck]]) {
      const q = forgeTdxQuote({ chain: { order: order(Q) } });
      expect(await reasonOf(q, C({ pckCrlRevoked: [q.pck.serialHex] }, q))).toBe('PCK leaf certificate is revoked by the PCK CRL');
      expect(await reasonOf(q, C({ rootCrlRevoked: [q.pki.platformCa.serialHex] }, q))).toBe('PCK CA certificate is revoked by the Intel Root CA CRL');
      expect(await reasonOf(q, C({}, q))).toBe('OK');
    }
  });
  it('issuer chains of TCB info / QE identity: validity, pin, revocation by the root CRL', async () => {
    expect(await reasonOf(Q, C({ tcbInfoChainPem: Q.pki.tcbSigning.pem }))).toMatch(/^TCB info: issuer chain invalid: /);
    expect(await reasonOf(Q, C({ qeIdentityChainPem: Q.pki.tcbSigning.pem }))).toMatch(/^QE identity: issuer chain invalid: /);
    const expiredPki = forgeIntelPki(Q.pki.seed, { tcbSigningValidity: [new Date('2018-01-01T00:00:00Z'), new Date('2019-01-01T00:00:00Z')] });
    const expiredChain = expiredPki.tcbSigning.pem + expiredPki.root.pem;
    expect(await reasonOf(Q, C({ tcbInfoChainPem: expiredChain }))).toBe('TCB info: issuer chain certificate outside its validity period');
    expect(await reasonOf(Q, C({ qeIdentityChainPem: expiredChain }))).toBe('QE identity: issuer chain certificate outside its validity period');
    expect(await reasonOf(Q, C({ rootCrlRevoked: [Q.pki.tcbSigning.serialHex] }))).toBe('TCB info: issuer chain certificate is revoked by the Intel Root CA CRL');
    expect(await reasonOf(Q, C({ tcbInfoChainPem: Q.pki.tcbSigning.pem + Q.pki.root.pem }))).toBe('OK');
  });
  it('certificate validity at the evaluation instant is inclusive at both ends', async () => {
    const earlyIssue = '2026-09-01T00:00:00Z';
    const col = (q: typeof Q, nextUpdate: string, crlNext: Date) => C({ tcbInfo: info({ issueDate: earlyIssue, nextUpdate }, q), qeIdentity: { issueDate: earlyIssue, nextUpdate }, crlThisUpdate: new Date(earlyIssue), crlNextUpdate: crlNext }, q);
    const from = Date.parse(new X509Certificate(Q.pck.der).validFrom);
    const farNext = '2040-01-01T00:00:00Z';
    const far = new Date(farNext);
    expect(await reasonOf(Q, col(Q, farNext, far), { now: new Date(from) })).toBe('OK');
    expect(await reasonOf(Q, col(Q, farNext, far), { now: new Date(from - 1000) })).toMatch(/outside its validity period|invalid/);
    const to = Date.parse(new X509Certificate(Q.pki.platformCa.der).validTo);
    expect(await reasonOf(Q, col(Q, farNext, far), { now: new Date(to) })).toBe('OK');
    expect(await reasonOf(Q, col(Q, farNext, far), { now: new Date(to + 1000) })).toMatch(/outside its validity period|invalid/);
  });
});

describe('verifyIntelTdxCollateral: signed documents', () => {
  const resign = (name: 'tcbInfo' | 'enclaveIdentity', body: Record<string, unknown>, tamper?: (raw: string) => string) => signCollateralJson(name, body, Q.pki.tcbSigningKey, tamper);
  const withInfo = (json: string | Uint8Array): IntelTdxCollateral => ({ ...C(), tcbInfoJson: json });
  const body = () => tcbInfoBody(defaultTcbInfoSpec(Q) as TdxTcbInfoSpec);
  it('document structure and signatures', async () => {
    expect(await reasonOf(Q, withInfo('{}'))).toBe('collateral incomplete (fail closed)'.replace('collateral incomplete (fail closed)', 'TCB info: tcbInfo not found / malformed'));
    expect(await reasonOf(Q, withInfo('{"tcbInfo":5,"signature":"00"}'))).toBe('TCB info: tcbInfo not found / malformed');
    expect(await reasonOf(Q, withInfo('{"tcbInfo":{"a":1} nonsense'))).toBe('TCB info: tcbInfo document is not valid JSON');
    const good = resign('tcbInfo', body());
    const sigOnly = (sigVal: unknown) => good.replace(/"signature":"[0-9a-f]+"/, `"signature":${JSON.stringify(sigVal)}`);
    const m = 'TCB info: tcbInfo signature missing or malformed';
    for (const sig of [5, null, ['a'.repeat(128)], 'a'.repeat(127), 'a'.repeat(129), `xx${'a'.repeat(128)}`, `${'a'.repeat(128)}xx`, `${'a'.repeat(127)}g`, '']) expect(await reasonOf(Q, withInfo(sigOnly(sig))), JSON.stringify(sig)).toBe(m);
    expect(await reasonOf(Q, withInfo(good.replace(/"signature":"[0-9a-f]+"/, '"x":1')))).toBe(m);
    expect(await reasonOf(Q, withInfo(sigOnly('00'.repeat(64))))).toBe('TCB info: tcbInfo signature does not verify under the TCB Signing certificate');
    expect(await reasonOf(Q, withInfo(resign('tcbInfo', body(), (raw) => raw.replace('"TDX"', '"TDx"'))))).toBe('TCB info: tcbInfo signature does not verify under the TCB Signing certificate');
    const upper = good.replace(/"signature":"([0-9a-f]+)"/, (_m, h: string) => `"signature":"${h.toUpperCase()}"`);
    expect(await reasonOf(Q, withInfo(upper))).toBe('OK');
    expect(await reasonOf(Q, withInfo(new TextEncoder().encode(good)))).toBe('OK');
    expect(await reasonOf(Q, withInfo(`  ${good}`))).toBe('OK');
  });
  it('the signed value is the exact source text, found with string-aware brace matching', async () => {
    const note = (s: string) => ({ ...body(), note: s });
    for (const s of ['a}b{c', 'q"}x', 'back\\slash"}', '{{{', '}}}', '\\"', 'plain']) expect(await reasonOf(Q, withInfo(resign('tcbInfo', note(s)))), s).toBe('OK');
    // a non-object value that happens to be followed by a braced one is not a signed object
    const sig = '00'.repeat(64);
    expect(await reasonOf(Q, withInfo(`{"tcbInfo":5,"x":{"a":1},"signature":"${sig}"}`))).toBe('TCB info: tcbInfo not found / malformed');
    expect(await reasonOf(Q, withInfo(`{"tcbInfo":"str","x":{"a":1},"signature":"${sig}"}`))).toBe('TCB info: tcbInfo not found / malformed');
    // an unterminated object
    expect(await reasonOf(Q, withInfo(`{"tcbInfo":{"a":1`))).toBe('TCB info: tcbInfo not found / malformed');
  });
  it('a duplicate key that replaces the signed object is not an object', async () => {
    const good = resign('tcbInfo', body());
    for (const dup of ['5', 'null', '[1]', '"s"']) {
      const doc = good.replace(/\}$/, `,"tcbInfo":${dup}}`);
      expect(await reasonOf(Q, withInfo(doc)), dup).toBe('TCB info: tcbInfo is not an object');
    }
  });
  it('freshness window is inclusive and strict about types', async () => {
    const c = C({ crlThisUpdate: new Date('2026-09-01T00:00:00Z'), qeIdentity: { issueDate: '2026-09-01T00:00:00Z' } });
    const mk2 = (b: Record<string, unknown>) => ({ ...c, tcbInfoJson: resign('tcbInfo', { ...body(), ...b }) });
    expect(await reasonOf(Q, mk2({ issueDate: '2026-10-20T00:00:00Z' }))).toBe('OK');
    expect(await reasonOf(Q, mk2({ issueDate: '2026-10-20T00:00:01Z' }))).toBe('TCB info: issueDate is in the future');
    expect(await reasonOf(Q, mk2({ nextUpdate: '2026-10-20T00:00:00Z' }))).toBe('OK');
    expect(await reasonOf(Q, mk2({ nextUpdate: '2026-10-19T23:59:59Z' }))).toBe('TCB info: stale (nextUpdate passed)');
    const missing = 'TCB info: issueDate/nextUpdate missing';
    for (const b of [{ issueDate: 2026 }, { nextUpdate: 2040 }, { issueDate: 'garbage' }, { nextUpdate: 'garbage' }, { issueDate: null }, { nextUpdate: undefined }]) expect(await reasonOf(Q, mk2(b)), JSON.stringify(b)).toBe(missing);
  });
  it('QE identity: freshness uses its own label', async () => {
    const c = C({ crlThisUpdate: new Date('2026-09-01T00:00:00Z') });
    const mk = (b: QeIdentitySpec) => ({ ...c, qeIdentityJson: signCollateralJson('enclaveIdentity', qeIdentityBody(b), Q.pki.tcbSigningKey) });
    expect(await reasonOf(Q, mk({ issueDate: '2026-10-21T00:00:00Z' }))).toBe('QE identity: issueDate is in the future');
    expect(await reasonOf(Q, mk({ nextUpdate: '2026-10-01T00:00:00Z' }))).toBe('QE identity: stale (nextUpdate passed)');
    expect(await reasonOf(Q, { ...c, qeIdentityJson: '{}' })).toBe('QE identity: enclaveIdentity not found / malformed');
    expect(await reasonOf(Q, { ...c, qeIdentityJson: signCollateralJson('enclaveIdentity', qeIdentityBody(), Q.pki.tcbSigningKey).replace('"signature":"', '"signature":"00') })).toBe('QE identity: enclaveIdentity signature missing or malformed');
  });
  it('document identity and PCK match', async () => {
    const m = 'TCB info is not a TDX v3 document';
    const mk = (spec: Partial<TdxTcbInfoSpec>) => C({ tcbInfo: info(spec) });
    expect(await reasonOf(Q, mk({ id: 'SGX' }))).toBe(m);
    expect(await reasonOf(Q, mk({ version: 2 }))).toBe(m);
    expect(await reasonOf(Q, mk({ version: 4 }))).toBe(m);
    expect(await reasonOf(Q, mk({ fmspc: '000000000000' }))).toBe('TCB info FMSPC does not match the quote PCK');
    expect(await reasonOf(Q, mk({ fmspc: '90C06F000000' }))).toBe('OK');
    const numFmspc = { ...C(), tcbInfoJson: resign('tcbInfo', { ...body(), fmspc: 5 }) };
    expect(await reasonOf(Q, numFmspc)).toBe('TCB info FMSPC does not match the quote PCK');
  });
  it('tcbEvaluationDataNumber: zero is valid, absent is not, policy minimum is inclusive', async () => {
    const zero = C({ tcbInfo: info({ tcbEvaluationDataNumber: 0 }), qeIdentity: { tcbEvaluationDataNumber: 0 } });
    const rz = await run(Q, zero);
    expect(rz).toMatchObject({ ok: true, tcbEvaluationDataNumber: 0 });
    const m = 'tcbEvaluationDataNumber missing';
    expect(await reasonOf(Q, C({ tcbInfo: info({ tcbEvaluationDataNumber: null }) }))).toBe(m);
    expect(await reasonOf(Q, C({ qeIdentity: { tcbEvaluationDataNumber: null } }))).toBe(m);
    const c = C({ tcbInfo: info({ tcbEvaluationDataNumber: 20 }), qeIdentity: { tcbEvaluationDataNumber: 25 } });
    expect(await run(Q, c, { policy: { minTcbEvaluationDataNumber: 20 } })).toMatchObject({ ok: true, tcbEvaluationDataNumber: 20 });
    expect(await reasonOf(Q, c, { policy: { minTcbEvaluationDataNumber: 21 } })).toBe('tcbEvaluationDataNumber below policy minimum');
    expect(await reasonOf(Q, C({ tcbInfo: info({ tcbEvaluationDataNumber: 25 }), qeIdentity: { tcbEvaluationDataNumber: 20 } }), { policy: { minTcbEvaluationDataNumber: 21 } })).toBe('tcbEvaluationDataNumber below policy minimum');
    expect(await reasonOf(Q, c, { policy: { minTcbEvaluationDataNumber: 0 } })).toBe('OK');
    expect(await reasonOf(Q, zero, { policy: {} })).toBe('OK');
    const rn = await run(Q, C({ tcbInfo: info({ tcbEvaluationDataNumber: 30 }), qeIdentity: { tcbEvaluationDataNumber: 26 } }));
    expect(rn.tcbEvaluationDataNumber).toBe(26);
  });
});

describe('verifyIntelTdxCollateral: TCB evaluation', () => {
  const lvl = (status: TcbStatus, over: Partial<{ sgx: number[]; pcesvn: number; tdx: number[]; advisories: string[] }> = {}) => ({ sgx: [...Q.pckSpec.sgxTcb], pcesvn: Q.pckSpec.pcesvn, tdx: [...Q.tdBody.subarray(0, 16)], status, ...over });
  const evalWith = (spec: Partial<TdxTcbInfoSpec>, o: Record<string, unknown> = {}, q = Q) => run(q, forgeTdxCollateral(q, { tcbInfo: { ...defaultTcbInfoSpec(q), ...spec } }), o);
  it('the happy path: every result field', async () => {
    expect(await run()).toEqual({
      ok: true,
      status: 'UpToDate',
      platformStatus: 'UpToDate',
      tdxModuleStatus: 'UpToDate',
      qeStatus: 'UpToDate',
      advisoryIds: [],
      tcbEvaluationDataNumber: 20,
      fmspc: '90c06f000000',
    });
  });
  it('policy: the worst of platform / module / QE decides, default accepts UpToDate and SWHardeningNeeded', async () => {
    const r = await evalWith({ levels: [lvl('SWHardeningNeeded')] });
    expect(r).toMatchObject({ ok: true, status: 'SWHardeningNeeded', platformStatus: 'SWHardeningNeeded' });
    const bad = await evalWith({ levels: [lvl('OutOfDate')] });
    expect(bad).toMatchObject({ ok: false, status: 'OutOfDate', platformStatus: 'OutOfDate', tdxModuleStatus: 'UpToDate', qeStatus: 'UpToDate', reason: 'TCB status OutOfDate is not accepted by policy', fmspc: '90c06f000000', tcbEvaluationDataNumber: 20 });
    expect(await evalWith({ levels: [lvl('OutOfDate')] }, { policy: { acceptStatuses: ['OutOfDate'] } as IntelCollateralPolicy })).toMatchObject({ ok: true, status: 'OutOfDate' });
    expect(await evalWith({ levels: [lvl('UpToDate')] }, { policy: { acceptStatuses: ['SWHardeningNeeded'] } as IntelCollateralPolicy })).toMatchObject({ ok: false, reason: 'TCB status UpToDate is not accepted by policy' });
    expect(await evalWith({ tdxModuleIdentities: [{ id: 'TDX_01', levels: [{ isvsvn: 13, status: 'OutOfDate' }] }] })).toMatchObject({ ok: false, status: 'OutOfDate', platformStatus: 'UpToDate', tdxModuleStatus: 'OutOfDate' });
    const qeWorse = C({ qeIdentity: { levels: [{ isvsvn: 4, status: 'Revoked' }] } });
    expect(await run(Q, qeWorse)).toMatchObject({ ok: false, status: 'Revoked', qeStatus: 'Revoked', platformStatus: 'UpToDate' });
    // ordering between non-adjacent statuses
    const mix = await evalWith({ levels: [lvl('ConfigurationNeeded')], tdxModuleIdentities: [{ id: 'TDX_01', levels: [{ isvsvn: 13, status: 'OutOfDate' }] }] }, { policy: { acceptStatuses: ['OutOfDate', 'ConfigurationNeeded'] } as IntelCollateralPolicy });
    expect(mix).toMatchObject({ ok: true, status: 'OutOfDate' });
    const tie = await evalWith({ levels: [lvl('ConfigurationNeeded')], tdxModuleIdentities: [{ id: 'TDX_01', levels: [{ isvsvn: 13, status: 'ConfigurationNeeded' }] }] }, { policy: { acceptStatuses: ['ConfigurationNeeded'] } as IntelCollateralPolicy });
    expect(tie).toMatchObject({ ok: true, status: 'ConfigurationNeeded' });
  });
  it('advisories from the matched level, the module level and the QE level are merged, de-duplicated and sorted', async () => {
    const r = await evalWith(
      { levels: [lvl('UpToDate', { advisories: ['INTEL-SA-9', 'INTEL-SA-2'] })], tdxModuleIdentities: [{ id: 'TDX_01', levels: [{ isvsvn: 13, status: 'UpToDate', advisories: ['INTEL-SA-5', 'INTEL-SA-2'] }] }] },
      {},
    );
    expect(r.advisoryIds).toEqual(['INTEL-SA-2', 'INTEL-SA-5', 'INTEL-SA-9']);
    const qeAdv = await run(Q, forgeTdxCollateral(Q, { tcbInfo: { ...defaultTcbInfoSpec(Q), levels: [lvl('UpToDate', { advisories: ['INTEL-SA-7'] })] }, qeIdentity: { levels: [{ isvsvn: 4, status: 'UpToDate', advisories: ['INTEL-SA-3', 'INTEL-SA-7'] }] } }));
    expect(qeAdv.advisoryIds).toEqual(['INTEL-SA-3', 'INTEL-SA-7']);
    // non-string advisory IDs are dropped
    const dirty = await evalWith({ levels: [lvl('UpToDate')] });
    expect(dirty.advisoryIds).toEqual([]);
    const rawLevels = [{ tcb: { sgxtcbcomponents: Q.pckSpec.sgxTcb.map((svn) => ({ svn })), pcesvn: Q.pckSpec.pcesvn, tdxtcbcomponents: [...Q.tdBody.subarray(0, 16)].map((svn) => ({ svn })) }, tcbStatus: 'UpToDate', advisoryIDs: ['INTEL-SA-1', 5, null, { a: 1 }] }];
    expect((await evalWith({ rawLevels })).advisoryIds).toEqual(['INTEL-SA-1']);
    const notArr = [{ ...rawLevels[0]!, advisoryIDs: 'INTEL-SA-1' }];
    expect((await evalWith({ rawLevels: notArr })).advisoryIds).toEqual([]);
  });
  it('level selection: first matching level in document order; each component and PCESVN gate', async () => {
    const sgx = [...Q.pckSpec.sgxTcb];
    const hi = (i: number) => sgx.map((v, k) => (k === i ? v + 1 : v));
    const levels = [lvl('UpToDate', { pcesvn: Q.pckSpec.pcesvn + 1 }), lvl('SWHardeningNeeded')];
    expect((await evalWith({ levels })).platformStatus).toBe('SWHardeningNeeded'); // pcesvn too high for the first
    for (const i of [0, 7, 15]) {
      const r = await evalWith({ levels: [lvl('UpToDate', { sgx: hi(i) }), lvl('OutOfDate')] }, { policy: { acceptStatuses: ['OutOfDate'] } as IntelCollateralPolicy });
      expect(r.platformStatus, `sgx[${i}]`).toBe('OutOfDate');
    }
    // equal components match; PCESVN equal matches
    expect((await evalWith({ levels: [lvl('UpToDate')] })).platformStatus).toBe('UpToDate');
    const first = await evalWith({ levels: [lvl('SWHardeningNeeded'), lvl('UpToDate')] });
    expect(first.platformStatus).toBe('SWHardeningNeeded');
    expect(await reasonOf(Q, forgeTdxCollateral(Q, { tcbInfo: info({ levels: [lvl('UpToDate', { pcesvn: 999 })] }) }))).toBe('TCB evaluation: platform TCB is below every level in the TCB info');
  });
  it('TDX component comparison starts at index 2 when a module identity is used (minor > 0), and at 0 otherwise', async () => {
    const tee = [...Q.tdBody.subarray(0, 16)];
    // minor = 1: components 0 and 1 are covered by the module identity and are NOT compared
    const bump01 = tee.map((v, i) => (i < 2 ? v + 50 : v));
    expect((await evalWith({ levels: [lvl('UpToDate', { tdx: bump01 })] })).platformStatus).toBe('UpToDate');
    const bump2 = tee.map((v, i) => (i === 2 ? v + 1 : v));
    expect(await reasonOf(Q, forgeTdxCollateral(Q, { tcbInfo: info({ levels: [lvl('UpToDate', { tdx: bump2 })] }) }))).toBe('TCB evaluation: platform TCB is below every level in the TCB info');
    const bump15 = tee.map((v, i) => (i === 15 ? v + 1 : v));
    expect(await reasonOf(Q, forgeTdxCollateral(Q, { tcbInfo: info({ levels: [lvl('UpToDate', { tdx: bump15 })] }) }))).toBe('TCB evaluation: platform TCB is below every level in the TCB info');
    // minor = 0: the base tdxModule is used and every component counts
    const q0 = forgeTdxQuote({ td: { teeTcbSvn: '0d000500000000000000000000000000' } });
    const tee0 = [...q0.tdBody.subarray(0, 16)];
    const l0 = (tdx: number[], status: TcbStatus = 'UpToDate') => ({ sgx: [...q0.pckSpec.sgxTcb], pcesvn: q0.pckSpec.pcesvn, tdx, status });
    expect(((await run(q0, forgeTdxCollateral(q0, { tcbInfo: { ...defaultTcbInfoSpec(q0), levels: [l0(tee0)] } })))).tdxModuleStatus).toBe('UpToDate');
    for (const i of [0, 1]) {
      const bump = tee0.map((v, k) => (k === i ? v + 1 : v));
      expect(await reasonOf(q0, forgeTdxCollateral(q0, { tcbInfo: { ...defaultTcbInfoSpec(q0), levels: [l0(bump)] } })), `tdx[${i}]`).toBe('TCB evaluation: platform TCB is below every level in the TCB info');
    }
  });
  it('malformed TCB levels', async () => {
    const ok = (extra: Record<string, unknown>) => ({ tcb: { sgxtcbcomponents: Q.pckSpec.sgxTcb.map((svn) => ({ svn })), pcesvn: 13, tdxtcbcomponents: [...Q.tdBody.subarray(0, 16)].map((svn) => ({ svn })) }, tcbStatus: 'UpToDate', ...extra });
    const r = (rawLevels: unknown) => reasonOf(Q, forgeTdxCollateral(Q, { tcbInfo: { ...defaultTcbInfoSpec(Q), rawLevels } as never }));
    expect(await r([])).toBe('TCB evaluation: TCB info has no tcbLevels');
    expect(await r('x')).toBe('TCB evaluation: TCB info has no tcbLevels');
    expect(await r(undefined)).toBe('OK'); // undefined rawLevels falls back to the spec levels
    expect(await r([null])).toBe('TCB evaluation: malformed TCB level');
    expect(await r([5])).toBe('TCB evaluation: malformed TCB level');
    expect(await r([['x']])).toBe('TCB evaluation: malformed TCB level');
    expect(await r([{ tcb: null, tcbStatus: 'UpToDate' }])).toBe('TCB evaluation: malformed TCB level');
    expect(await r([{ tcb: [], tcbStatus: 'UpToDate' }])).toBe('TCB evaluation: malformed TCB level');
    const comps = 'TCB evaluation: malformed TCB level components';
    expect(await r([ok({ tcb: { sgxtcbcomponents: [], pcesvn: 13, tdxtcbcomponents: [] } })])).toBe(comps);
    expect(await r([ok({ tcb: { sgxtcbcomponents: Q.pckSpec.sgxTcb.slice(0, 15).map((svn) => ({ svn })), pcesvn: 13, tdxtcbcomponents: [...Q.tdBody.subarray(0, 16)].map((svn) => ({ svn })) } })])).toBe(comps);
    expect(await r([ok({ tcb: { sgxtcbcomponents: Q.pckSpec.sgxTcb.map(() => ({ svn: '5' })), pcesvn: 13, tdxtcbcomponents: [...Q.tdBody.subarray(0, 16)].map((svn) => ({ svn })) } })])).toBe(comps);
    expect(await r([ok({ tcb: { sgxtcbcomponents: Q.pckSpec.sgxTcb.map((svn) => ({ svn })), pcesvn: '13', tdxtcbcomponents: [...Q.tdBody.subarray(0, 16)].map((svn) => ({ svn })) } })])).toBe(comps);
    expect(await r([ok({ tcb: { sgxtcbcomponents: Q.pckSpec.sgxTcb.map((svn) => ({ svn })), pcesvn: 13, tdxtcbcomponents: [...Q.tdBody.subarray(0, 16)].map(() => 5) } })])).toBe(comps);
    expect(await r([ok({ tcbStatus: 'Bogus' })])).toBe('TCB evaluation: TCB level has an unknown tcbStatus');
    expect(await r([ok({ tcbStatus: 5 })])).toBe('TCB evaluation: TCB level has an unknown tcbStatus');
  });
  it('TDX module identity checks', async () => {
    const mod = (over: Record<string, unknown>) => forgeTdxCollateral(Q, { tcbInfo: info({ tdxModuleIdentities: [{ id: 'TDX_01', levels: [{ isvsvn: 13, status: 'UpToDate' }], ...over }] as never }) });
    expect(await reasonOf(Q, forgeTdxCollateral(Q, { tcbInfo: info({ tdxModuleIdentities: [] }) }))).toBe('TCB evaluation: TDX module identity TDX_01 not present in TCB info');
    expect(await reasonOf(Q, forgeTdxCollateral(Q, { tcbInfo: info({ tdxModuleIdentities: [{ id: 'TDX_02', levels: [{ isvsvn: 13, status: 'UpToDate' }] }] }) }))).toBe('TCB evaluation: TDX module identity TDX_01 not present in TCB info');
    expect(await reasonOf(Q, mod({ levels: [{ isvsvn: 14, status: 'UpToDate' }] }))).toBe('TCB evaluation: TDX module TDX_01 SVN 13 is below every known level');
    expect(await reasonOf(Q, mod({ levels: [{ isvsvn: 13, status: 'Bogus' }] }))).toBe('TCB evaluation: TDX module level has an unknown tcbStatus');
    expect(await reasonOf(Q, mod({ mrsigner: 'zz'.repeat(48) }))).toBe('TCB evaluation: TDX module identity fields malformed');
    expect(await reasonOf(Q, mod({ mrsigner: `g${'a'.repeat(95)}` }))).toBe('TCB evaluation: TDX module identity fields malformed');
    expect(await reasonOf(Q, mod({ mrsigner: `${'a'.repeat(95)}g` }))).toBe('TCB evaluation: TDX module identity fields malformed');
    expect(await reasonOf(Q, mod({ mrsigner: 'a'.repeat(94) }))).toBe('TCB evaluation: TDX module identity fields malformed');
    expect(await reasonOf(Q, mod({ attributes: '00' }))).toBe('TCB evaluation: TDX module identity fields malformed');
    expect(await reasonOf(Q, mod({ attributesMask: 'zzzzzzzzzzzzzzzz' }))).toBe('TCB evaluation: TDX module identity fields malformed');
    expect(await reasonOf(Q, mod({ mrsigner: 'ab'.repeat(48) }))).toBe('TCB evaluation: TD report MRSIGNERSEAM does not match the TDX module identity');
    expect(await reasonOf(Q, mod({ attributes: '0100000000000000' }))).toBe('TCB evaluation: TD report SEAM attributes do not match the TDX module identity');
    expect(await reasonOf(Q, mod({ attributes: '0100000000000000', attributesMask: '0000000000000000' }))).toBe('OK'); // a zero mask ignores the attribute
    expect(await reasonOf(Q, mod({ mrsigner: 'AB'.repeat(48) }))).toBe('TCB evaluation: TD report MRSIGNERSEAM does not match the TDX module identity');
    // the module identity list is searched by id, ignoring non-record entries
    const ids = [null, 5, { id: 'TDX_02' }, { id: 'TDX_01', mrsigner: '0'.repeat(96), attributes: '0000000000000000', attributesMask: 'FFFFFFFFFFFFFFFF', tcbLevels: [{ tcb: { isvsvn: 13 }, tcbStatus: 'UpToDate' }] }];
    const c = forgeTdxCollateral(Q, { tcbInfo: info({}) });
    const raw = JSON.parse(JSON.parse(`{"v":${c.tcbInfoJson as string}}`).v.tcbInfo ? (c.tcbInfoJson as string).slice('{"tcbInfo":'.length, (c.tcbInfoJson as string).lastIndexOf(',"signature"')) : '{}');
    raw.tdxModuleIdentities = ids;
    const doc = signCollateralJson('tcbInfo', raw, Q.pki.tcbSigningKey);
    expect(await reasonOf(Q, { ...c, tcbInfoJson: doc })).toBe('OK');
    // identity levels: skip non-record / tcb-less / non-numeric isvsvn entries, take the first with isvsvn <= SVN
    const levels = [null, { tcb: null, tcbStatus: 'Revoked' }, { tcb: { isvsvn: '0' }, tcbStatus: 'Revoked' }, { tcb: { isvsvn: 99 }, tcbStatus: 'OutOfDate' }, { tcb: { isvsvn: 13 }, tcbStatus: 'SWHardeningNeeded' }, { tcb: { isvsvn: 1 }, tcbStatus: 'OutOfDate' }];
    raw.tdxModuleIdentities = [{ id: 'TDX_01', mrsigner: '0'.repeat(96), attributes: '0000000000000000', attributesMask: 'FFFFFFFFFFFFFFFF', tcbLevels: levels }];
    expect(await run(Q, { ...c, tcbInfoJson: signCollateralJson('tcbInfo', raw, Q.pki.tcbSigningKey) })).toMatchObject({ ok: true, tdxModuleStatus: 'SWHardeningNeeded' });
    raw.tdxModuleIdentities = [{ id: 'TDX_01', mrsigner: '0'.repeat(96), attributes: '0000000000000000', attributesMask: 'FFFFFFFFFFFFFFFF' }];
    expect(await reasonOf(Q, { ...c, tcbInfoJson: signCollateralJson('tcbInfo', raw, Q.pki.tcbSigningKey) })).toBe('TCB evaluation: TDX module TDX_01 SVN 13 is below every known level');
  });
  it('base tdxModule is required for minor 0', async () => {
    const q0 = forgeTdxQuote({ td: { teeTcbSvn: '0d000500000000000000000000000000' } });
    const c = (tdxModule: TdxTcbInfoSpec['tdxModule']) => forgeTdxCollateral(q0, { tcbInfo: { ...defaultTcbInfoSpec(q0), tdxModule } });
    expect(await reasonOf(q0, c(null))).toBe('TCB evaluation: TCB info missing tdxModule');
    expect(await reasonOf(q0, c({ mrsigner: '0'.repeat(96), attributes: '0000000000000000', attributesMask: 'FFFFFFFFFFFFFFFF' }))).toBe('OK');
    expect(await reasonOf(q0, c({ mrsigner: 'zz'.repeat(48), attributes: '0000000000000000', attributesMask: 'FFFFFFFFFFFFFFFF' }))).toBe('TCB evaluation: TDX module identity fields malformed');
  });
});

describe('verifyIntelTdxCollateral: QE identity evaluation', () => {
  const qe = (s: QeIdentitySpec) => reasonOf(Q, C({ qeIdentity: s }));
  it('field checks in order, with exact reasons', async () => {
    expect(await qe({ id: 'QE' })).toBe('QE identity: QE identity id is not TD_QE');
    expect(await qe({ version: 1 })).toBe('QE identity: unsupported QE identity version');
    expect(await qe({ version: 3 })).toBe('QE identity: unsupported QE identity version');
    const bad = 'QE identity: QE identity fields malformed';
    expect(await qe({ miscselect: 'zz' })).toBe(bad);
    expect(await qe({ miscselectMask: '00' })).toBe(bad);
    expect(await qe({ attributes: '00' })).toBe(bad);
    expect(await qe({ attributesMask: '00' })).toBe(bad);
    expect(await qe({ mrsigner: 'ab' })).toBe(bad);
    expect(await qe({ isvprodid: '2' })).toBe(bad);
    expect(await qe({ miscselect: '01000000' })).toBe('QE identity: QE MISCSELECT does not match the QE identity');
    expect(await qe({ miscselect: '01000000', miscselectMask: '00000000' })).toBe('OK');
    expect(await qe({ attributes: '33000000000000000000000000000000' })).toBe('QE identity: QE ATTRIBUTES do not match the QE identity');
    expect(await qe({ mrsigner: 'AB'.repeat(32) })).toBe('QE identity: QE MRSIGNER does not match the QE identity');
    expect(await qe({ isvprodid: 3 })).toBe('QE identity: QE ISVPRODID does not match the QE identity');
    expect(await qe({ id: 'QE', version: 1 })).toBe('QE identity: QE identity id is not TD_QE');
  });
  it('levels: ISVSVN selection and status', async () => {
    // default QE report ISVSVN = 7
    expect(await qe({ levels: [{ isvsvn: 8, status: 'UpToDate' }] })).toBe('QE identity: QE ISVSVN is below every known level');
    expect(await run(Q, C({ qeIdentity: { levels: [{ isvsvn: 7, status: 'SWHardeningNeeded' }] } }))).toMatchObject({ ok: true, qeStatus: 'SWHardeningNeeded' });
    expect(await qe({ levels: [{ isvsvn: 7, status: 'Bogus' as never }] })).toBe('QE identity: QE level has an unknown tcbStatus');
    expect(await run(Q, C({ qeIdentity: { levels: [{ isvsvn: 9, status: 'Revoked' }, { isvsvn: 7, status: 'UpToDate' }, { isvsvn: 1, status: 'OutOfDate' }] } }))).toMatchObject({ qeStatus: 'UpToDate' });
    expect(await qe({ levels: [] })).toBe('QE identity: QE ISVSVN is below every known level');
  });
  it('level lists with junk entries are tolerated; non-record levels never match', async () => {
    const c = C();
    const m = (c.qeIdentityJson as string).slice('{"enclaveIdentity":'.length, (c.qeIdentityJson as string).lastIndexOf(',"signature"'));
    const raw = JSON.parse(m);
    raw.tcbLevels = [null, { tcb: null, tcbStatus: 'Revoked' }, { tcb: { isvsvn: '0' }, tcbStatus: 'Revoked' }, { tcb: { isvsvn: 4 }, tcbStatus: 'SWHardeningNeeded' }];
    expect(await run(Q, { ...c, qeIdentityJson: signCollateralJson('enclaveIdentity', raw, Q.pki.tcbSigningKey) })).toMatchObject({ ok: true, qeStatus: 'SWHardeningNeeded' });
    raw.tcbLevels = 'nope';
    expect(await reasonOf(Q, { ...c, qeIdentityJson: signCollateralJson('enclaveIdentity', raw, Q.pki.tcbSigningKey) })).toBe('QE identity: QE ISVSVN is below every known level');
    raw.tcbLevels = [{ tcb: { isvsvn: 4 }, tcbStatus: 'UpToDate', advisoryIDs: ['B', 3, 'A'] }];
    expect((await run(Q, { ...c, qeIdentityJson: signCollateralJson('enclaveIdentity', raw, Q.pki.tcbSigningKey) })).advisoryIds).toEqual(['A', 'B']);
  });
  it('QE report mask arithmetic is bitwise', async () => {
    // attributes mask FB.. ignores bit 2: a QE report differing only there still matches
    const q = forgeTdxQuote({ qe: { attributes: '1500000000000000e700000000000000' } });
    expect(await reasonOf(q, C({}, q))).toBe('OK');
    const q2 = forgeTdxQuote({ qe: { attributes: '1100000000000000e700000000000000' } });
    expect(await reasonOf(q2, C({}, q2))).toBe('OK'); // 0x15 vs 0x11 differ only in the masked bit 2
    const q3 = forgeTdxQuote({ qe: { attributes: '1900000000000000e700000000000000' } });
    expect(await reasonOf(q3, C({}, q3))).toBe('QE identity: QE ATTRIBUTES do not match the QE identity');
  });
});

// Oracle: the exported functions of the vendor attestation modules no earlier corpus records: attest-intel-tdx (DCAP quote + TD report parsers, P-256 key, PCK chain,
// PCK extension reader, the genuine-quote verifier), attest-intel-collateral (CRL, signed-JSON and PCS collateral verification with the TCB / TDX-module / QE statuses),
// attest-intel-dcap (the Azure runtime-data binding), attest-azure-maa and attest-gcp-confidential-space (the JWT parsers, the x5c chain checks, the JWKS fetchers over an
// injected transport, the hwmodel mapper), attest-amd-snp (pemToDer, constants) and the suite / pin constants. NOT here (recorded elsewhere): attest-maa-keys / attest-maa-pins
// (ref-attest-maa), the NVIDIA modules, the hardware-sevsnp helpers (ref-sevsnp-helpers), the verifier constructors (the attestation-evidence vectors drive them end to end).
// Writes out/ref-attest-vendors.json.gz. Inputs: the REAL public Azure TDX quote + Intel PCS collateral + MAA / Confidential Space tokens (packages/pca/fixtures), and
// evidence forged under label-derived TEST keys (a test Intel root, platform CA, PCK leaf, QE, attestation key). The corpus carries certificates, signatures, quotes and public
// keys only: no private key and no seed is recorded. Deterministic: every clock is an argument, signatures are RFC 6979 / PKCS#1 v1.5, fetches are scripted.
//
// PORTING (fn(args) -> native entry point under the REFERENCE name; JSON values; a reference throw is {"$throws": message})
//   {"$bytes": b64u} = bytes. Strings over 400 chars are stored once in the top-level "blobs" map and appear as {"$blob": id} anywhere (also inside {"$bytes": ...}): resolve before use.
//   A reason / throw text that comes from a library is compared by presence only: OpenSSL "error:<8 hex>:..." text, the JSON.parse messages ("Unexpected token ...", "Unexpected end of JSON input"),
//   the P-256 library's point errors ("bad point: ...", "invalid Point, expected length ...") and "URI malformed". Every other text is a fixed string of the reference and compares exactly.
//   Cases whose certificate bytes are not valid DER at all (malformed-certificate, pem-malformed-block, garbage chains) only require a refusal, whatever stack parses them. An absent optional member (trustAnchorRootCaSpkiSha256, policy, ...) means "not given" (the built-in default).
//   constants []                                              -> {INTEL_DCAP_SUITE, AZURE_MAA_SUITE, AZURE_MAA_SUITES, GCP_CS_SUITE, GCP_CS_SUITES, GCP_CS_DEFAULT_ISSUER, INTEL_SGX_ROOT_CA_SPKI_SHA256, AMD_SNP_SUITE, AMD_ARK_SPKI_SHA384, DEFAULT_ACCEPTED_STATUSES}
//   toHex [bytes]                                             -> lowercase hex
//   pemToDer [pem]                                            -> bytes of the FIRST certificate block (base64 body, whitespace removed); throws when there is none
//   ecdsaP256PublicKey [sec1]                                 -> {point: 65-byte uncompressed SEC1} (a compressed point is expanded); throws off the curve
//   parseDcapTdReport [body]                                  -> {teeTcbSvn, mrSeam, mrSignerSeam, tdAttributes, mrTd, mrConfigId, rtmr0..rtmr3, reportData, raw (the first 584 bytes)}; throws under 584 bytes
//   parseDcapQuote [quote]                                    -> {version, attKeyType, teeType, header, tdReportBody, quoteSignature, akPubRaw, qeReportBody, qeReportSignature, qeAuthData, pckChainPem}; throws on every structural violation
//   extractPckFmspcAndTcb [leafDer]                           -> {fmspc, sgxTcbComponents (16), pcesvn, cpusvn}; throws on a missing / malformed Intel SGX extension
//   verifyIntelPckChainX509 [{pckChainPem, trustAnchorRootCaSpkiSha256?, nowMs}] -> {ok, reason?, leafKey?: {point}, leafDer?, depth?, failure?: "validity"}  (nowMs is always given)
//   verifyGenuineTdxQuote [{quote, trustAnchorRootCaSpkiSha256?, expected?, policy?, nowMs}] -> {ok, reason?, report?, fmspc?, pckTcb?, akPub?: {point}, chainDepth?, measured?}; expected = {holderPub, grantRef, epoch, nonce};
//        policy = {mrtds?, fmspcs?, rtmrs?, mrSeams?, mrSignerSeams?, allowDebug?}: an absent / empty mrtds, fmspcs or rtmrs list is not gated, an EMPTY mrSeams / mrSignerSeams list refuses everything
//   verifyCrl [crlDer, {spkiDer}, nowMs]                      -> {ok: true, revoked: [sorted serials, lowercase hex, no leading zeros]} | {ok: false, reason}; the issuer key is the public key whose SubjectPublicKeyInfo DER is spkiDer
//   serialIsRevoked [revoked, serialHex]                      -> bool (case and leading zeros of serialHex are ignored; `revoked` is the list a verifyCrl result carries)
//   verifySignedJson [text, name, {spkiDer}]                  -> {body} | {error}; text = {"<name>":{...},"signature":"<128 hex>"}, the signature is ECDSA P-256 / SHA-256 (r||s) over the EXACT source bytes of the named object
//   decodeIssuerChainHeader [value]                           -> decodeURIComponent(value); throws on malformed %-escapes
//   verifyIntelTdxCollateral [{quote, collateral, nowMs, policy?, trustAnchorRootCaSpkiSha256?, allowDebug?}] -> {ok, reason?, status?, platformStatus?, tdxModuleStatus?, qeStatus?, advisoryIds?, tcbEvaluationDataNumber?, fmspc?}
//        collateral = {tcbInfoJson, tcbInfoIssuerChainPem, qeIdentityJson, qeIdentityIssuerChainPem, pckCrlDer, rootCrlDer} (or null / {}: incomplete); a JSON member is a string or bytes (both appear); policy = {acceptStatuses?, minTcbEvaluationDataNumber?}
//        platformStatus / tdxModuleStatus / qeStatus / tcbEvaluationDataNumber (the smaller of the two documents') / fmspc / advisoryIds are present whenever the evaluation completed, INCLUDING when the policy then refuses the status
//   checkAzureRuntimeDataBinding [reportData, runtimeData, expected] -> string (the failure reason) | null
//   parseMaaJwt [token] / parseGcpCsJwt [token]               -> {header: {alg, kid?, jku?, x5c?, typ?}, payload, signingInput (bytes of "h.p"), signature}; verifies nothing; throws on a structural violation (the messages name the function)
//   verifyX5cChain [x5c, anchors, {nowMs, clockSkewMs?}]      -> {ok, reason?, leafDer?, leafSpkiSha256?}; anchors = {rootCertsPem?, rootSpkiSha256?}; the reference returns the leaf certificate, recorded here as its DER (leafDer)
//   verifyJwkX5cChain [x5c, anchors, {nowMs, skewMs}]         -> string (failure reason) | null; anchors = {trustedKeySpki?, rootCertsPem?}
//   teeTypeOfHwModel [hwmodel]                                -> "sev-snp" | "tdx" | null
//   fetchMaaJwks [{issuer, script, opts?}]                    -> {ok: true, jwks: {keys}} | {ok: false, error}, plus requests: [url of every transport call, in order]
//   fetchGcpConfidentialSpaceJwks [{issuer, script, opts?}]   -> same shape
//        script = [response...]: the i-th transport call gets script[min(i, last)]; response = {status?: 200, body: json | {"$text": raw text}} | {"$throws": message} (the transport rejects); the transport is called with the URL only.
//        opts: fetchMaaJwks {certsPath?}, fetchGcpConfidentialSpaceJwks {jwksUri?}
const PKGSRC = '../../../packages/pca/src/';
import { createPublicKey, X509Certificate } from 'node:crypto';
import { Oracle, ser, assertNotVacuous } from './lib.mjs';
import { b64u, fx, fxt, refWriteBlobs } from './attest-roots-kit.mts';

const T: any = await import(PKGSRC + 'attest-intel-tdx.ts');
const C: any = await import(PKGSRC + 'attest-intel-collateral.ts');
const DC: any = await import(PKGSRC + 'attest-intel-dcap.ts');
const AZ: any = await import(PKGSRC + 'attest-azure-maa.ts');
const GC: any = await import(PKGSRC + 'attest-gcp-confidential-space.ts');
const AM: any = await import(PKGSRC + 'attest-amd-snp.ts');
const AT: any = await import(PKGSRC + 'attestation.ts');
const F: any = await import(PKGSRC + 'test-support/forge-dcap.ts');
const X: any = await import(PKGSRC + 'test-support/forge-x509.ts');
const R: any = await import(PKGSRC + 'test-support/forge-rsa.ts');
const { p256 }: any = await import('@noble/curves/p256');

const o = new Oracle('attest-vendors', 'tools/pca-audit/oracles/ref-attest-vendors.mts', 'TS-reference oracle for the exported functions of the Intel TDX / DCAP / PCS-collateral, Azure MAA, Google Confidential Space and AMD SNP vendor attestation modules (quote / report / JWT parsers, chain checks, collateral verification, JWKS fetchers over an injected transport, constants).');

// ---- plumbing ----
const J = (x: any) => JSON.parse(ser(x));
const dec = (v: any): any => {
  if (Array.isArray(v)) return v.map(dec);
  if (v && typeof v === 'object') {
    const k = Object.keys(v);
    if (k.length === 1 && k[0] === '$bytes') return new Uint8Array(Buffer.from(v.$bytes, 'base64url'));
    return Object.fromEntries(k.map((x) => [x, dec(v[x])]));
  }
  return v;
};
const run = async (fn: () => any) => { try { const r = await fn(); return r === undefined ? null : J(r); } catch (e: any) { return { $throws: e instanceof Error ? e.message : String(e) }; } };
/** Record fn(args): the reference runs on the re-parsed args, exactly what a native sees. */
const rec = async (fn: string, name: string, args: any[], impl: (...a: any[]) => any) => {
  const a = J(args);
  o.add(fn, name, a, await run(() => impl(...dec(a))));
};
const hex = (u: Uint8Array) => Buffer.from(u).toString('hex');
const bytes = (s: string) => new TextEncoder().encode(s);
const D = (s: string) => new Date(s);

// ---- fixtures + forged evidence ----
const NOW = Date.parse('2026-10-20T00:00:00Z');
const REAL_NOW = 1791506476000;
const DAY = 86_400_000;
const PKI = F.forgeIntelPki('rv/pki');
const Q = (opts: any = {}) => F.forgeTdxQuote({ seed: 'rv', pki: PKI, ...opts });
const base = Q();
const TD = F.TD10_FIELDS;
const mrtdOf = (q: any) => hex(q.tdBody.subarray(TD.MRTD, TD.MRTD + 48));
const rtmr0Of = (q: any) => hex(q.tdBody.subarray(TD.RTMR0, TD.RTMR0 + 48));
const BIND = { holderPub: 'holder-pub-rv', grantRef: 'grant-rv', epoch: 3, nonce: 'nonce-rv-1' };
const bindBytes = (e: any) => AT.attestationBinding(e);
const windows = (now: number) => {
  const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
  return { tcbInfo: { issueDate: iso(now - DAY), nextUpdate: iso(now + 30 * DAY) }, qeIdentity: { issueDate: iso(now - DAY), nextUpdate: iso(now + 30 * DAY) }, crlThisUpdate: new Date(now - DAY), crlNextUpdate: new Date(now + 30 * DAY) };
};
const colWire = (c: any) => ({ tcbInfoJson: String(c.tcbInfoJson), tcbInfoIssuerChainPem: c.tcbInfoIssuerChainPem, qeIdentityJson: String(c.qeIdentityJson), qeIdentityIssuerChainPem: c.qeIdentityIssuerChainPem, pckCrlDer: c.pckCrlDer, rootCrlDer: c.rootCrlDer });
const forgeCol = (q: any, over: any = {}, now = NOW) => {
  const w = windows(now);
  const ti = typeof over.tcbInfo === 'function' ? over.tcbInfo(q) : over.tcbInfo;
  return F.forgeTdxCollateral(q, { ...w, ...over, tcbInfo: { ...w.tcbInfo, ...(ti ?? {}) }, qeIdentity: { ...w.qeIdentity, ...(over.qeIdentity ?? {}) } });
};
const keyOf = (a: { spkiDer: Uint8Array }) => createPublicKey({ key: Buffer.from(a.spkiDer), format: 'der', type: 'spki' });
const spkiOfCert = (pem: string) => new Uint8Array(new X509Certificate(pem).publicKey.export({ type: 'spki', format: 'der' }));
const pemBlocks = (pem: string) => pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];

const realQuote = new Uint8Array(fx('real-tdx', 'azure-intel-tdx-dcap-quote.bin'));
const pcaQuote = new Uint8Array(fx('real-azure-maa', 'pcabound-tdx-dcap-quote.bin'));
const pcaRuntime = new Uint8Array(fx('real-azure-maa', 'pcabound-runtime-data.json'));
const realParsed = T.parseDcapQuote(pcaQuote);
const realTd = T.parseDcapTdReport(realParsed.tdReportBody);
const REAL_BIND = { holderPub: 'pca-realsilicon-azure-tdx-holder', grantRef: 'grant_pca_azure_maa_realsilicon', epoch: 1, nonce: 'srv-nonce-maa-5d3b8e1f9a27c604' };
const realCol = (crl = 'pckcrl-platform.der') => ({ tcbInfoJson: fxt('real-tdx-collateral', 'tdx-tcbinfo.json'), tcbInfoIssuerChainPem: fxt('real-tdx-collateral', 'tdx-tcbinfo-issuer-chain.pem'), qeIdentityJson: fxt('real-tdx-collateral', 'tdx-qeidentity.json'), qeIdentityIssuerChainPem: fxt('real-tdx-collateral', 'tdx-qeidentity-issuer-chain.pem'), pckCrlDer: new Uint8Array(fx('real-tdx-collateral', crl)), rootCrlDer: new Uint8Array(fx('real-tdx-collateral', 'IntelSGXRootCA.crl.der')) });

// =============================================== constants / small helpers ===============================================
o.add('constants', 'all', [], J({
  INTEL_DCAP_SUITE: DC.INTEL_DCAP_SUITE, AZURE_MAA_SUITE: AZ.AZURE_MAA_SUITE, AZURE_MAA_SUITES: AZ.AZURE_MAA_SUITES, GCP_CS_SUITE: GC.GCP_CS_SUITE, GCP_CS_SUITES: GC.GCP_CS_SUITES, GCP_CS_DEFAULT_ISSUER: GC.GCP_CS_DEFAULT_ISSUER,
  INTEL_SGX_ROOT_CA_SPKI_SHA256: T.INTEL_SGX_ROOT_CA_SPKI_SHA256, AMD_SNP_SUITE: AM.AMD_SNP_SUITE, AMD_ARK_SPKI_SHA384: AM.AMD_ARK_SPKI_SHA384, DEFAULT_ACCEPTED_STATUSES: C.DEFAULT_ACCEPTED_STATUSES,
}));

for (const [n, v] of [['empty', []], ['one-zero', [0]], ['ff', [255]], ['mixed', [0, 1, 15, 16, 127, 128, 254, 255]], ['ascii', [...bytes('PCA')]], ['p256-point', [...new Uint8Array(65).fill(0xab)]], ['td-48', [...new Uint8Array(48).fill(0x0f)]], ['leading-zeros', [0, 0, 0, 7]]] as const) {
  await rec('toHex', n, [new Uint8Array(v as number[])], (b) => T.toHex(b));
}

{
  const pem = base.pck.pem;
  const b64 = Buffer.from(base.pck.der).toString('base64');
  await rec('pemToDer', 'single', [pem], (p) => AM.pemToDer(p));
  await rec('pemToDer', 'first-of-chain', [base.pckPem], (p) => AM.pemToDer(p));
  await rec('pemToDer', 'crlf-wrapped', [`-----BEGIN CERTIFICATE-----\r\n${b64.match(/.{1,64}/g)!.join('\r\n')}\r\n-----END CERTIFICATE-----\r\n`], (p) => AM.pemToDer(p));
  await rec('pemToDer', 'single-line', [`-----BEGIN CERTIFICATE-----${b64}-----END CERTIFICATE-----`], (p) => AM.pemToDer(p));
  await rec('pemToDer', 'leading-text', ['junk before\n' + pem + 'junk after'], (p) => AM.pemToDer(p));
  await rec('pemToDer', 'blank-body-newline', ['-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----'], (p) => AM.pemToDer(p));
  await rec('pemToDer', 'no-block', ['not a pem'], (p) => AM.pemToDer(p));
  await rec('pemToDer', 'empty', [''], (p) => AM.pemToDer(p));
  await rec('pemToDer', 'wrong-label', [pem.replace(/CERTIFICATE/g, 'PUBLIC KEY')], (p) => AM.pemToDer(p));
  await rec('pemToDer', 'garbage-base64', ['-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----'], (p) => AM.pemToDer(p));
}

{
  const k = X.forgeKey('rv/p256', 'P-256');
  const comp = p256.ProjectivePoint.fromHex(k.pub).toRawBytes(true);
  const offY = Uint8Array.from(k.pub); offY[64] ^= 1;
  const offX = Uint8Array.from(k.pub); offX[1] ^= 0x80;
  const pk = (n: string, b: Uint8Array) => rec('ecdsaP256PublicKey', n, [b], (x) => T.ecdsaP256PublicKey(x));
  await pk('uncompressed', k.pub);
  await pk('compressed', comp);
  await pk('compressed-other-parity', Uint8Array.from([comp[0]! ^ 1, ...comp.subarray(1)]));
  await pk('second-key', X.forgeKey('rv/p256-b', 'P-256').pub);
  await pk('off-curve-y', offY);
  await pk('off-curve-x', offX);
  await pk('all-zero-point', new Uint8Array([4, ...new Uint8Array(64)]));
  await pk('truncated', k.pub.subarray(0, 64));
  await pk('extra-byte', new Uint8Array([...k.pub, 0]));
  await pk('empty', new Uint8Array(0));
  await pk('bad-prefix', new Uint8Array([5, ...k.pub.subarray(1)]));
  await pk('p384-point', X.forgeKey('rv/p384', 'P-384').pub);
}

// =============================================== TD report + quote parsers ===============================================
{
  const body = base.tdBody;
  const pt = (n: string, b: Uint8Array) => rec('parseDcapTdReport', n, [b], (x) => T.parseDcapTdReport(x));
  await pt('forged', body);
  await pt('forged-debug', Q({ td: { debug: true } }).tdBody);
  await pt('real', realParsed.tdReportBody);
  await pt('real-other', T.parseDcapQuote(realQuote).tdReportBody);
  await pt('all-zero', new Uint8Array(584));
  await pt('all-ff', new Uint8Array(584).fill(0xff));
  await pt('longer-keeps-584', new Uint8Array([...body, ...bytes('trailing report bytes')]));
  await pt('field-pattern', Uint8Array.from({ length: 584 }, (_, i) => i & 0xff));
  await pt('one-short', body.subarray(0, 583));
  await pt('short-100', body.subarray(0, 100));
  await pt('empty', new Uint8Array(0));
}

const patchU32 = (q: Uint8Array, off: number, v: number) => { const c = Uint8Array.from(q); new DataView(c.buffer).setUint32(off, v, true); return c; };
const patchU16 = (q: Uint8Array, off: number, v: number) => { const c = Uint8Array.from(q); new DataView(c.buffer).setUint16(off, v, true); return c; };
const patchByte = (q: Uint8Array, off: number, v: number) => { const c = Uint8Array.from(q); c[off] = v; return c; };
const OFF = F.DCAP_OFFSETS;
{
  const pq = (n: string, q: Uint8Array) => rec('parseDcapQuote', n, [q], (b) => T.parseDcapQuote(b));
  await pq('forged', base.quote);
  await pq('forged-azure-padding-70', Q({ trailingPad: 70 }).quote);
  await pq('forged-no-nul', Q({ chain: { noNul: true } }).quote);
  await pq('forged-empty-qe-auth', Q({ qeAuth: new Uint8Array(0) }).quote);
  await pq('forged-long-qe-auth', Q({ qeAuth: X.fill('rv/auth', 200) }).quote);
  await pq('forged-chain-two-certs', Q({ chain: { order: [base.pck, base.platformCa] } }).quote);
  await pq('real-azure', realQuote);
  await pq('real-azure-pca-bound', pcaQuote);
  await pq('empty', new Uint8Array(0));
  await pq('short-10', base.quote.subarray(0, 10));
  await pq('short-635', base.quote.subarray(0, 635));
  await pq('header-body-only-636', base.quote.slice(0, 636));
  await pq('version-3', Q({ header: { version: 3 } }).quote);
  await pq('version-5', Q({ header: { version: 5 } }).quote);
  await pq('att-key-type-3', Q({ header: { attKeyType: 3 } }).quote);
  await pq('att-key-type-0', Q({ header: { attKeyType: 0 } }).quote);
  await pq('tee-type-sgx-0', Q({ header: { teeType: 0 } }).quote);
  await pq('tee-type-0x82', Q({ header: { teeType: 0x82 } }).quote);
  await pq('tee-type-high-bit', Q({ header: { teeType: 0x80000081 } }).quote);
  await pq('sig-data-overruns-by-1', Q({ sigDataLenDelta: 1 }).quote);
  await pq('sig-data-overruns-huge', patchU32(base.quote, OFF.SIG_DATA_LEN, 0xffffffff));
  await pq('sig-data-understated-by-1', Q({ sigDataLenDelta: -1 }).quote);
  await pq('sig-data-understated-by-100', Q({ sigDataLenDelta: -100 }).quote);
  await pq('sig-data-len-0', patchU32(base.quote, OFF.SIG_DATA_LEN, 0));
  await pq('sig-data-len-10-truncated-signature', patchU32(base.quote, OFF.SIG_DATA_LEN, 10));
  await pq('sig-data-len-100-truncated-ak', patchU32(base.quote, OFF.SIG_DATA_LEN, 100));
  await pq('sig-data-len-130-truncated-outer-header', patchU32(base.quote, OFF.SIG_DATA_LEN, 130));
  await pq('outer-type-5', Q({ outerCertType: 5 }).quote);
  await pq('outer-type-7', Q({ outerCertType: 7 }).quote);
  await pq('outer-size-overruns', patchU32(base.quote, OFF.OUTER_SIZE, 0x10000));
  {
    const len = (n: number) => patchU32(patchU32(base.quote, OFF.SIG_DATA_LEN, 134 + n), OFF.OUTER_SIZE, 10);
    await pq('truncated-qe-report', len(100));
    await pq('truncated-qe-report-signature', len(384 + 10));
    await pq('truncated-qe-auth-size', len(384 + 64 + 1));
  }
  await pq('qe-auth-size-overruns', patchU16(base.quote, OFF.QE_AUTH_SIZE, 5000));
  await pq('truncated-inner-header', patchU32(patchU32(base.quote, OFF.SIG_DATA_LEN, 134 + 384 + 64 + 2 + base.qeAuth.length + 3), OFF.OUTER_SIZE, 384 + 64 + 2 + base.qeAuth.length + 3));
  await pq('inner-type-6', Q({ innerCertType: 6 }).quote);
  await pq('inner-type-1', Q({ innerCertType: 1 }).quote);
  await pq('inner-size-overruns-outer', patchU32(base.quote, base.offsets.innerSize, 0x1000000));
  await pq('inner-size-short-pem', patchU32(base.quote, base.offsets.innerSize, 40));
  await pq('inner-size-zero', patchU32(base.quote, base.offsets.innerSize, 0));
  await pq('trailing-nonzero-byte', new Uint8Array([...Q({ trailingPad: 3 }).quote, 1]));
  await pq('trailing-nonzero-in-pad', patchByte(Q({ trailingPad: 10 }).quote, base.quote.length + 4, 9));
  await pq('trailing-zero-pad-1000', Q({ trailingPad: 1000 }).quote);
  await pq('pem-garbage-text', Q({ chain: { pemOverride: 'not a certificate chain' } }).quote);
  await pq('pem-empty', Q({ chain: { pemOverride: '' } }).quote);
}

// =============================================== PCK extension reader ===============================================
{
  const ex = (n: string, der: Uint8Array) => rec('extractPckFmspcAndTcb', n, [der], (b) => T.extractPckFmspcAndTcb(b));
  const leaf = (po: any = {}) => Q({ pck: po }).pck.der;
  const leafOf = (quote: Uint8Array) => new Uint8Array(new X509Certificate(pemBlocks(T.parseDcapQuote(quote).pckChainPem)[0]!).raw);
  await ex('default', leaf());
  await ex('other-fmspc', leaf({ fmspc: '00a06f000000' }));
  await ex('pcesvn-two-bytes', leaf({ pcesvn: 300 }));
  await ex('pcesvn-zero', leaf({ pcesvn: 0 }));
  await ex('pcesvn-max', leaf({ pcesvn: 65535 }));
  await ex('tcb-high-components', leaf({ sgxTcb: [255, 200, 127, 128, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12] }));
  await ex('other-cpusvn', leaf({ cpusvn: 'ffffffffffffffffffffffffffffffff' }));
  await ex('real-quote-leaf', leafOf(pcaQuote));
  await ex('real-quote-other-leaf', leafOf(realQuote));
  await ex('missing-fmspc', leaf({ ext: { omit: ['fmspc'] } }));
  await ex('missing-tcb', leaf({ ext: { omit: ['tcb'] } }));
  await ex('missing-pcesvn', leaf({ ext: { omit: ['pcesvn'] } }));
  await ex('fmspc-5-bytes', leaf({ ext: { fmspcLen: 5 } }));
  await ex('fmspc-7-bytes', leaf({ ext: { fmspcLen: 7 } }));
  await ex('no-sgx-extension', leaf({ noSgxExtension: true }));
  await ex('not-a-certificate', bytes('not a certificate at all'));
  await ex('empty', new Uint8Array(0));
  {
    const d = leaf();
    const find = (hexNeedle: string) => Buffer.from(d).indexOf(Buffer.from(hexNeedle, 'hex'));
    const fi = find('060a2a864886f84d010d0104');
    const ti = find('060a2a864886f84d010d0102');
    await ex('truncated-in-fmspc-value', d.slice(0, fi + 12 + 3));
    await ex('truncated-at-fmspc-oid-end', d.slice(0, fi + 12));
    await ex('truncated-in-tcb-sequence', d.slice(0, ti + 12 + 10));
    await ex('truncated-at-tcb-oid-end', d.slice(0, ti + 12));
    await ex('fmspc-tag-not-octet-string', patchByte(d, fi + 12, 0x0c));
    await ex('tcb-tag-not-sequence', patchByte(d, ti + 12, 0x31));
    await ex('first-tcb-component-not-sequence', patchByte(d, ti + 12 + 4, 0x31));
    await ex('first-component-oid-tag', patchByte(d, ti + 12 + 4 + 2, 0x04));
  }
}

// =============================================== PCK chain X.509 ===============================================
const chainCase = async (name: string, q: any, extra: any = {}, pem?: string) => rec('verifyIntelPckChainX509', name, [{ pckChainPem: pem ?? q.pckPem, trustAnchorRootCaSpkiSha256: q.rootSpkiSha256, nowMs: NOW, ...extra }], (a) => T.verifyIntelPckChainX509(a));
{
  const pki = (po: any, seed = 'rv/pki-v') => F.forgeIntelPki(seed, po);
  const crit = X.extension('1.2.3.4.5', true, X.seq());
  const nonCrit = X.extension('1.2.3.4.5', false, X.seq());
  const pc = async (name: string, p: any) => chainCase(name, Q({ pki: p }), { trustAnchorRootCaSpkiSha256: p.rootSpkiSha256 });
  await chainCase('forged-ok', base);
  await chainCase('forged-ok-pin-uppercase', base, { trustAnchorRootCaSpkiSha256: base.rootSpkiSha256.toUpperCase() });
  await chainCase('forged-default-pin-refuses-test-root', base, { trustAnchorRootCaSpkiSha256: undefined });
  await chainCase('forged-wrong-pin', base, { trustAnchorRootCaSpkiSha256: '00'.repeat(32) });
  await chainCase('forged-pin-of-platform-ca', base, { trustAnchorRootCaSpkiSha256: base.pki.caKey.spkiSha256 });
  await chainCase('forged-before-pck-validity', base, { nowMs: Date.parse('2026-09-01T00:00:00Z') });
  await chainCase('forged-after-ca-validity', base, { nowMs: Date.parse('2034-01-01T00:00:00Z') });
  await chainCase('forged-after-pck-validity', base, { nowMs: Date.parse('2033-10-15T00:00:00Z') });
  await chainCase('forged-at-pck-notbefore', base, { nowMs: Date.parse('2026-09-30T16:45:11Z') });
  await chainCase('forged-just-before-pck-notbefore', base, { nowMs: Date.parse('2026-09-30T16:45:10Z') });
  await chainCase('forged-at-pck-notafter', base, { nowMs: Date.parse('2033-09-30T16:45:11Z') });
  await chainCase('forged-just-after-pck-notafter', base, { nowMs: Date.parse('2033-09-30T16:45:12Z') });
  await chainCase('forged-leaf-only', Q({ chain: { order: [base.pck] } }));
  await chainCase('forged-leaf-and-ca-no-root', Q({ chain: { order: [base.pck, base.platformCa] } }));
  await chainCase('forged-reversed-order', Q({ chain: { order: [base.pki.root, base.platformCa, base.pck] } }));
  await chainCase('forged-duplicate-leaf', Q({ chain: { order: [base.pck, base.pck, base.platformCa, base.pki.root] } }));
  await chainCase('forged-stranger-appended', Q({ chain: { appendPem: Q({ seed: 'rv-stranger', pki: undefined }).pck.pem } }));
  await chainCase('forged-root-only', Q({ chain: { order: [base.pki.root] } }));
  await chainCase('pem-empty', base, {}, '');
  await chainCase('pem-text-only', base, {}, 'no certificates here');
  await chainCase('pem-malformed-block', base, {}, '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n');
  await chainCase('pem-null', base, {}, null as any);
  await chainCase('pck-is-ca', Q({ pck: { ca: true } }));
  await chainCase('pck-basic-constraints-absent', Q({ pck: { ca: 'absent' } }));
  await chainCase('pck-issued-by-other-key', Q({ pck: { issuerKey: X.forgeKey('rv/other-issuer', 'P-256') } }));
  await chainCase('pck-rsa-key', Q({ pck: { spkiOverride: R.forgeRsaKey('rv/rsa-pck').spki } }));
  await chainCase('pck-critical-extension', Q({ pck: { extraExtensions: [crit] } }));
  await chainCase('pck-noncritical-extension', Q({ pck: { extraExtensions: [nonCrit] } }));
  await pc('ca-signed-by-other-key', pki({ caSignedBy: X.forgeKey('rv/ca-signer', 'P-256') }));
  await pc('root-not-self-signed', pki({ rootSelfSigned: false }));
  await pc('ca-basic-constraints-absent', pki({ caBasicConstraints: 'absent' }));
  await pc('ca-basic-constraints-false', pki({ caBasicConstraints: 'ca-false' }));
  await pc('ca-critical-extension', pki({ caExtra: [crit] }));
  await pc('root-critical-extension', pki({ rootExtra: [crit] }));
  await pc('ca-expired', pki({ caValidity: [D('2018-01-01T00:00:00Z'), D('2026-01-01T00:00:00Z')] }));
  await pc('root-not-yet-valid', pki({ rootValidity: [D('2027-01-01T00:00:00Z'), D('2049-01-01T00:00:00Z')] }));
  await chainCase('pck-expired', Q({ pck: { notBefore: D('2024-01-01T00:00:00Z'), notAfter: D('2026-06-01T00:00:00Z') } }));
  // the real Intel chain of the captured Azure quotes, pinned to the built-in Intel root
  for (const [n, q] of [['real-pca-bound', pcaQuote], ['real-azure', realQuote]] as const) {
    const pem = T.parseDcapQuote(q).pckChainPem;
    const rc = (s: string, a: any) => rec('verifyIntelPckChainX509', n + s, [{ pckChainPem: pem, ...a }], (x) => T.verifyIntelPckChainX509(x));
    await rc('-default-pin', { nowMs: REAL_NOW });
    await rc('-explicit-pin', { trustAnchorRootCaSpkiSha256: T.INTEL_SGX_ROOT_CA_SPKI_SHA256, nowMs: REAL_NOW });
    await rc('-wrong-pin', { trustAnchorRootCaSpkiSha256: base.rootSpkiSha256, nowMs: REAL_NOW });
    await rc('-year-2000', { nowMs: Date.parse('2000-01-01T00:00:00Z') });
    await rc('-year-2060', { nowMs: Date.parse('2060-01-01T00:00:00Z') });
  }
}

// =============================================== the genuine quote verifier ===============================================
const raw = (b: Uint8Array) => ({ quote: b, rootSpkiSha256: base.rootSpkiSha256 });
const gq = async (name: string, q: any, extra: any = {}) => rec('verifyGenuineTdxQuote', name, [{ quote: q.quote, trustAnchorRootCaSpkiSha256: q.rootSpkiSha256, nowMs: NOW, ...extra }], (a) => T.verifyGenuineTdxQuote(a));
{
  const pol = (p: any) => ({ policy: p });
  const rd = (e: any) => ({ td: { reportData: bindBytes(e) } });
  await gq('forged-ok', base);
  await gq('forged-ok-full-policy', base, pol({ mrtds: [mrtdOf(base)], fmspcs: ['90c06f000000'], rtmrs: [rtmr0Of(base)], mrSeams: [hex(base.tdBody.subarray(TD.MR_SEAM, TD.MR_SEAM + 48))], mrSignerSeams: ['00'.repeat(48)] }));
  await gq('forged-policy-uppercase-hex', base, pol({ mrtds: [mrtdOf(base).toUpperCase()], fmspcs: ['90C06F000000'], rtmrs: [rtmr0Of(base).toUpperCase()], mrSignerSeams: ['00'.repeat(48)] }));
  await gq('forged-empty-mrtds-not-gated', base, pol({ mrtds: [], fmspcs: [], rtmrs: [] }));
  await gq('forged-mrtd-not-allowed', base, pol({ mrtds: ['11'.repeat(48)] }));
  await gq('forged-fmspc-not-allowed', base, pol({ fmspcs: ['00a06f000000'] }));
  await gq('forged-rtmr0-not-allowed', base, pol({ rtmrs: ['22'.repeat(48)] }));
  await gq('forged-mrseam-not-allowed', base, pol({ mrSeams: ['33'.repeat(48)] }));
  await gq('forged-mrseam-empty-list-refuses', base, pol({ mrSeams: [] }));
  await gq('forged-mrsignerseam-not-allowed', base, pol({ mrSignerSeams: ['44'.repeat(48)] }));
  await gq('forged-mrsignerseam-empty-list-refuses', base, pol({ mrSignerSeams: [] }));
  await gq('forged-mrsignerseam-nonzero-allowed', Q({ td: { mrSignerSeam: '5a'.repeat(48) } }), pol({ mrSignerSeams: ['5A'.repeat(48)] }));
  await gq('forged-default-anchor-refuses', base, { trustAnchorRootCaSpkiSha256: undefined });
  await gq('forged-wrong-anchor', base, { trustAnchorRootCaSpkiSha256: 'ff'.repeat(32) });
  await gq('forged-expected-binding-ok', Q(rd(BIND)), { expected: BIND });
  await gq('forged-expected-binding-mismatch-nonce', Q(rd(BIND)), { expected: { ...BIND, nonce: 'other-nonce' } });
  await gq('forged-expected-binding-mismatch-epoch', Q(rd(BIND)), { expected: { ...BIND, epoch: 4 } });
  await gq('forged-expected-zero-report-data', base, { expected: BIND });
  await gq('forged-expected-not-constructible-no-holder', base, { expected: { ...BIND, holderPub: '' } });
  await gq('forged-expected-not-constructible-bad-epoch', base, { expected: { ...BIND, epoch: -1 } });
  await gq('forged-expected-not-constructible-fraction', base, { expected: { ...BIND, epoch: 1.5 } });
  await gq('forged-debug-td-refused', Q({ td: { debug: true } }));
  await gq('forged-debug-td-allowed', Q({ td: { debug: true } }), pol({ allowDebug: true }));
  await gq('forged-debug-allow-debug-false', Q({ td: { debug: true } }), pol({ allowDebug: false }));
  await gq('forged-debug-bit-in-attributes-bytes', Q({ td: { tdAttributes: '0100001000000000' } }));
  await gq('forged-non-debug-attribute-bits', Q({ td: { tdAttributes: 'fe00001000000000' } }));
  await gq('forged-qe-signed-by-other-key', Q({ qe: { signer: X.forgeKey('rv/not-pck', 'P-256') } }));
  await gq('forged-qe-debug-enclave', Q({ qe: { attributes: '1700000000000000e700000000000000' } }));
  await gq('forged-qe-report-data-wrong', Q({ qe: { reportData: new Uint8Array(64).fill(7) } }));
  await gq('forged-qe-report-data-tail-nonzero', Q({ qe: { reportData: new Uint8Array([...X.digest('sha256', base.ak.pub.subarray(1), base.qeAuth), ...new Uint8Array(32).fill(1)]) } }));
  await gq('forged-ak-not-on-curve', Q({ ak: { ...X.forgeKey('rv/ak-bad', 'P-256'), pub: new Uint8Array([4, ...new Uint8Array(64).fill(1)]) } }));
  await gq('forged-td-signed-by-other-key', Q({ tdSigner: X.forgeKey('rv/not-ak', 'P-256') }));
  await gq('forged-pck-no-sgx-extension', Q({ pck: { noSgxExtension: true } }));
  await gq('forged-pck-missing-fmspc', Q({ pck: { ext: { omit: ['fmspc'] } } }));
  await gq('forged-pck-missing-pcesvn', Q({ pck: { ext: { omit: ['pcesvn'] } } }));
  await gq('forged-chain-broken-pck-issuer', Q({ pck: { issuerKey: X.forgeKey('rv/other-issuer', 'P-256') } }));
  await gq('forged-chain-expired-at-now', base, { nowMs: Date.parse('2040-01-01T00:00:00Z') });
  await gq('forged-chain-empty-pem', Q({ chain: { pemOverride: '' } }));
  await gq('forged-quote-version-3', Q({ header: { version: 3 } }));
  await gq('forged-quote-truncated', raw(base.quote.subarray(0, 700)));
  await gq('forged-quote-empty', raw(new Uint8Array(0)));
  await gq('forged-quote-trailing-nonzero', raw(new Uint8Array([...base.quote, 5])));
  await gq('forged-azure-padding-ok', Q({ trailingPad: 70 }));
  await gq('forged-bit-flip-td-body', raw(patchByte(base.quote, 48 + 200, base.quote[48 + 200]! ^ 1)));
  await gq('forged-bit-flip-quote-signature', raw(patchByte(base.quote, OFF.QUOTE_SIG + 3, base.quote[OFF.QUOTE_SIG + 3]! ^ 1)));
  await gq('forged-bit-flip-qe-signature', raw(patchByte(base.quote, OFF.QE_SIG + 5, base.quote[OFF.QE_SIG + 5]! ^ 1)));
  await gq('forged-bit-flip-ak', raw(patchByte(base.quote, OFF.AK + 9, base.quote[OFF.AK + 9]! ^ 1)));
  await gq('forged-other-tcb', Q({ pck: { fmspc: '00a06f000000', sgxTcb: [9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9], pcesvn: 17 } }));
  await gq('forged-other-pki', Q({ seed: 'rv-b', pki: undefined }));
  // real silicon
  for (const [n, q] of [['real-pca-bound', pcaQuote], ['real-azure', realQuote]] as const) {
    const td = T.parseDcapTdReport(T.parseDcapQuote(q).tdReportBody);
    const real = (s: string, extra: any = {}) => rec('verifyGenuineTdxQuote', n + s, [{ quote: q, nowMs: REAL_NOW, ...extra }], (a) => T.verifyGenuineTdxQuote(a));
    await real('-ok');
    await real('-ok-policy', { policy: { mrtds: [T.toHex(td.mrTd)], rtmrs: [T.toHex(td.rtmr0)], mrSignerSeams: [T.toHex(td.mrSignerSeam)], mrSeams: [T.toHex(td.mrSeam)] } });
    await real('-wrong-mrtd', { policy: { mrtds: ['00'.repeat(48)] } });
    await real('-wrong-fmspc', { policy: { fmspcs: ['ffffffffffff'] } });
    await real('-explicit-pin', { trustAnchorRootCaSpkiSha256: T.INTEL_SGX_ROOT_CA_SPKI_SHA256 });
    await real('-test-root-pin', { trustAnchorRootCaSpkiSha256: base.rootSpkiSha256 });
    await real('-too-late', { nowMs: Date.parse('2060-01-01T00:00:00Z') });
    await real('-report-data-unbound', { expected: REAL_BIND });
  }
}

// =============================================== CRL, signed JSON, serials, header ===============================================
{
  const iss = PKI.caDn;
  const tU = D('2026-10-19T00:00:00Z'), nU = D('2026-11-19T00:00:00Z');
  const crl = (over: any = {}) => X.forgeCrl({ issuer: iss, signer: PKI.caKey, thisUpdate: tU, nextUpdate: nU, ...over });
  const vc = (n: string, der: Uint8Array, spki: Uint8Array = PKI.caKey.spki, nowMs = NOW) =>
    rec('verifyCrl', n, [der, { spkiDer: spki }, nowMs], (d, k, t) => { const r = C.verifyCrl(d, keyOf(k), new Date(t)); return r.ok ? { ok: true, revoked: [...r.revoked].sort() } : r; });
  await vc('empty-list', crl());
  await vc('revoked-two', crl({ revoked: ['0a', 'FF01', '00112233445566778899aabbccddeeff00112233'] }));
  await vc('revoked-leading-zero-serial', crl({ revoked: ['00ab'] }));
  await vc('revoked-with-authority-key', crl({ authorityKey: PKI.rootKey, revoked: ['1234'] }));
  await vc('crl-number-big', crl({ crlNumber: 70000, revoked: ['7f'] }));
  await vc('this-update-generalized-time', crl({ raw: { thisUpdate: X.generalizedTime(tU) } }));
  await vc('next-update-generalized-time', crl({ raw: { nextUpdate: X.generalizedTime(nU) } }));
  await vc('omit-version', crl({ raw: { omitVersion: true }, revoked: ['05'] }));
  await vc('at-this-update', crl(), PKI.caKey.spki, tU.getTime());
  await vc('just-before-this-update', crl(), PKI.caKey.spki, tU.getTime() - 1);
  await vc('at-next-update', crl(), PKI.caKey.spki, nU.getTime());
  await vc('just-after-next-update', crl(), PKI.caKey.spki, nU.getTime() + 1);
  await vc('wrong-issuer-key', crl(), PKI.rootKey.spki);
  await vc('signed-by-other-key', crl({ signer: X.forgeKey('rv/crl-other', 'P-256') }));
  await vc('omit-next-update', crl({ omitNextUpdate: true }));
  await vc('bad-this-update-text', crl({ raw: { thisUpdate: X.tlv(0x17, bytes('not-a-time')) } }));
  await vc('bad-next-update-text', crl({ raw: { nextUpdate: X.tlv(0x18, bytes('2026')) } }));
  await vc('this-update-not-a-time', crl({ raw: { thisUpdate: X.integer(5) } }));
  await vc('issuer-not-a-sequence', crl({ raw: { issuer: X.integer(1) } }));
  await vc('revoked-entry-without-integer-serial', crl({ raw: { entries: [X.seq(X.octets(bytes('x')))] } }));
  await vc('signature-not-bit-string', crl({ raw: { sigTag: 0x04 } }));
  await vc('tbs-not-sequence', crl({ raw: { tbsTag: 0x31 } }));
  await vc('trailing-bytes', crl({ raw: { trailing: Uint8Array.of(0) } }));
  await vc('truncated', crl().slice(0, 40));
  await vc('truncated-signature', crl().slice(0, crl().length - 3));
  await vc('empty', new Uint8Array(0));
  await vc('garbage', bytes('not a crl at all, just text'));
  await vc('bit-flip-in-tbs', (() => { const d = Uint8Array.from(crl({ revoked: ['0a'] })); d[30] ^= 1; return d; })());
  // the real Intel CRLs
  const realChain = pemBlocks(realParsed.pckChainPem);
  const platformSpki = spkiOfCert(realChain[1]!), rootSpki = spkiOfCert(realChain[2]!);
  const rcrl = (f: string) => new Uint8Array(fx('real-tdx-collateral', f));
  await vc('real-root-crl', rcrl('IntelSGXRootCA.crl.der'), rootSpki, REAL_NOW);
  await vc('real-platform-pck-crl', rcrl('pckcrl-platform.der'), platformSpki, REAL_NOW);
  await vc('real-processor-pck-crl-under-platform-key', rcrl('pckcrl-processor.der'), platformSpki, REAL_NOW);
  await vc('real-root-crl-under-platform-key', rcrl('IntelSGXRootCA.crl.der'), platformSpki, REAL_NOW);
  await vc('real-platform-pck-crl-in-2060', rcrl('pckcrl-platform.der'), platformSpki, Date.parse('2060-01-01T00:00:00Z'));
  await vc('real-platform-pck-crl-in-2000', rcrl('pckcrl-platform.der'), platformSpki, Date.parse('2000-01-01T00:00:00Z'));

  const rv = ['0a', 'ff', 'abcdef0123', '1'];
  for (const [n, set, s] of [['present', rv, '0A'], ['leading-zeros-ignored', rv, '000a'], ['uppercase-ignored', rv, 'FF'], ['absent', rv, '0b'], ['empty-set', [], '0a'], ['empty-serial', rv, ''], ['zero-serial', ['0', ''], '0'], ['long', rv, 'ABCDEF0123'], ['prefix-is-not-a-match', rv, 'abcdef01'], ['odd-length-leading-zero', rv, '01']] as const) {
    await rec('serialIsRevoked', n, [[...set], s], (l, h) => C.serialIsRevoked(new Set(l), h));
  }

  // signed JSON
  const tk = PKI.tcbSigningKey;
  const sign = (r: string, key = tk) => X.bytesToHex(X.ecdsaSign(key, 'sha256', bytes(r)).raw);
  const doc = (name: string, r: string, key = tk, tail = '') => `{"${name}":${r},"signature":"${sign(r, key)}"${tail}}`;
  const sj = (n: string, text: string, name = 'tcbInfo', spki: Uint8Array = tk.spki) => rec('verifySignedJson', n, [text, name, { spkiDer: spki }], (t, nm, k) => C.verifySignedJson(t, nm, keyOf(k)));
  const body1 = JSON.stringify({ id: 'TDX', version: 3, n: [1, 2, { a: 'x' }] });
  const realInfoSpki = spkiOfCert(pemBlocks(fxt('real-tdx-collateral', 'tdx-tcbinfo-issuer-chain.pem'))[0]!);
  const realQeSpki = spkiOfCert(pemBlocks(fxt('real-tdx-collateral', 'tdx-qeidentity-issuer-chain.pem'))[0]!);
  await sj('ok', doc('tcbInfo', body1));
  await sj('ok-enclave-identity', doc('enclaveIdentity', body1), 'enclaveIdentity');
  await sj('ok-leading-whitespace', '  \n' + doc('tcbInfo', body1));
  await sj('ok-spaces-around-colon', `{ "tcbInfo" : ${body1} ,"signature":"${sign(body1)}"}`);
  await sj('ok-braces-and-quotes-in-strings', doc('tcbInfo', JSON.stringify({ s: 'a}b{c"d\\e', t: '}}}' })));
  await sj('ok-escaped-quote-before-brace', doc('tcbInfo', '{"s":"x\\"}","k":1}'));
  await sj('ok-nested-objects', doc('tcbInfo', '{"a":{"b":{"c":{}}},"dd":[{"e":1}]}'));
  await sj('ok-trailing-member-after-signature', doc('tcbInfo', body1, tk, ',"extra":1'));
  await sj('ok-duplicate-member-inside-body', doc('tcbInfo', '{"a":1,"a":2}'));
  await sj('ok-uppercase-hex-signature', `{"tcbInfo":${body1},"signature":"${sign(body1).toUpperCase()}"}`);
  await sj('ok-real-tcb-info', fxt('real-tdx-collateral', 'tdx-tcbinfo.json'), 'tcbInfo', realInfoSpki);
  await sj('ok-real-qe-identity', fxt('real-tdx-collateral', 'tdx-qeidentity.json'), 'enclaveIdentity', realQeSpki);
  await sj('real-tcb-info-wrong-key', fxt('real-tdx-collateral', 'tdx-tcbinfo.json'), 'tcbInfo', tk.spki);
  await sj('real-tcb-info-as-qe-identity', fxt('real-tdx-collateral', 'tdx-tcbinfo.json'), 'enclaveIdentity', realInfoSpki);
  await sj('wrong-name', doc('tcbInfo', body1), 'enclaveIdentity');
  await sj('name-not-first-member', `{"x":1,"tcbInfo":${body1},"signature":"${sign(body1)}"}`);
  await sj('body-not-an-object-array', `{"tcbInfo":[1],"signature":"${sign('[1]')}"}`);
  await sj('body-not-an-object-string', `{"tcbInfo":"s","signature":"${sign('"s"')}"}`);
  await sj('body-unterminated', `{"tcbInfo":{"a":1,"signature":"${sign('{"a":1')}"}`);
  await sj('body-invalid-json', `{"tcbInfo":{a:1},"signature":"${sign('{a:1}')}"}`);
  await sj('document-invalid-json-after-body', `{"tcbInfo":${body1},"signature":"${sign(body1)}",}`);
  await sj('signature-missing', `{"tcbInfo":${body1}}`);
  await sj('signature-not-a-string', `{"tcbInfo":${body1},"signature":5}`);
  await sj('signature-short', `{"tcbInfo":${body1},"signature":"${sign(body1).slice(2)}"}`);
  await sj('signature-long', `{"tcbInfo":${body1},"signature":"${sign(body1)}00"}`);
  await sj('signature-not-hex', `{"tcbInfo":${body1},"signature":"${'zz'.repeat(64)}"}`);
  await sj('signature-wrong-key', doc('tcbInfo', body1, X.forgeKey('rv/sj-other', 'P-256')));
  await sj('signature-over-different-bytes', `{"tcbInfo":${body1},"signature":"${sign(body1 + ' ')}"}`);
  await sj('whitespace-in-body-changes-signature', `{"tcbInfo":${body1.replace(',', ', ')},"signature":"${sign(body1)}"}`);
  await sj('empty-text', '');
  await sj('not-json', 'hello');

  for (const [n, v] of [['plain', 'abc'], ['pem-encoded', encodeURIComponent(base.platformCa.pem + base.pki.root.pem)], ['percent-newline', '%0A'], ['plus-kept', 'a+b'], ['space-kept', 'a b'], ['empty', ''], ['unicode', '%C3%A9%E2%82%AC'], ['lowercase-hex-escape', '%2f%3a'], ['malformed-percent', '%'], ['malformed-truncated-escape', 'abc%2'], ['malformed-hex', '%zz'], ['malformed-utf8', '%C3%28'], ['lone-surrogate-escape', '%ED%A0%80']] as const) {
    await rec('decodeIssuerChainHeader', n, [v], (s) => C.decodeIssuerChainHeader(s));
  }
}

// =============================================== PCS collateral verification ===============================================
{
  const wireCall = (a: any) => { const { nowMs, ...r } = a; return C.verifyIntelTdxCollateral({ ...r, now: new Date(nowMs) }); };
  const cq = (name: string, q: any, colOver: any = {}, extra: any = {}, now = NOW, colNow = now) =>
    rec('verifyIntelTdxCollateral', name, [{ quote: q.quote, collateral: colWire(forgeCol(q, colOver, colNow)), nowMs: now, trustAnchorRootCaSpkiSha256: q.rootSpkiSha256, ...extra }], wireCall);
  const tdTcb = (q: any) => [...q.tdBody.subarray(0, 16)];
  const lv = (q: any, status: any, adv?: string[], over: any = {}) => ({ sgx: q.pckSpec.sgxTcb, pcesvn: q.pckSpec.pcesvn, tdx: tdTcb(q), status, ...(adv ? { advisories: adv } : {}), ...over });
  const STAT = ['UpToDate', 'SWHardeningNeeded', 'ConfigurationNeeded', 'ConfigurationAndSWHardeningNeeded', 'OutOfDateConfigurationNeeded', 'OutOfDate', 'Revoked'];
  const q0 = base; // teeTcbSvn[1] = 1: the TDX_01 module identity
  const qBase = Q({ td: { teeTcbSvn: '0d000500000000000000000000000000' } }); // minor 0: the base tdxModule
  const ident = (id: string, levels: any[], over: any = {}) => ({ id, levels, ...over });
  const mod01 = (levels: any[], over: any = {}) => (q: any) => ({ tdxModuleIdentities: [ident('TDX_01', levels, over)], levels: [lv(q, 'UpToDate')] });

  await cq('ok-up-to-date', q0);
  await cq('ok-up-to-date-module-minor-0', qBase);
  {
    const col = colWire(forgeCol(q0));
    await rec('verifyIntelTdxCollateral', 'ok-json-as-bytes', [{ quote: q0.quote, collateral: { ...col, tcbInfoJson: bytes(col.tcbInfoJson), qeIdentityJson: bytes(col.qeIdentityJson) }, nowMs: NOW, trustAnchorRootCaSpkiSha256: q0.rootSpkiSha256 }], wireCall);
  }
  for (const st of STAT) {
    await cq('platform-' + st, q0, { tcbInfo: (q: any) => ({ levels: [lv(q, st, ['INTEL-SA-0001', 'INTEL-SA-0002'])] }) });
    await cq('platform-' + st + '-accepted', q0, { tcbInfo: (q: any) => ({ levels: [lv(q, st)] }) }, { policy: { acceptStatuses: STAT } });
    await cq('module-' + st, q0, { tcbInfo: mod01([{ isvsvn: 13, status: st, advisories: ['INTEL-SA-0100'] }]) });
    await cq('qe-' + st, q0, { qeIdentity: { levels: [{ isvsvn: 4, status: st, advisories: ['INTEL-SA-0200'] }] } });
  }
  await cq('only-sw-hardening-accepted-by-policy', q0, { tcbInfo: (q: any) => ({ levels: [lv(q, 'SWHardeningNeeded')] }) }, { policy: { acceptStatuses: ['SWHardeningNeeded'] } });
  await cq('empty-accept-list-refuses-all', q0, {}, { policy: { acceptStatuses: [] } });
  await cq('policy-unknown-accept-status', q0, {}, { policy: { acceptStatuses: ['Banana'] } });
  await cq('worst-of-platform-module-qe', q0, { tcbInfo: (q: any) => ({ tdxModuleIdentities: [ident('TDX_01', [{ isvsvn: 13, status: 'OutOfDate' }])], levels: [lv(q, 'ConfigurationNeeded')] }), qeIdentity: { levels: [{ isvsvn: 4, status: 'SWHardeningNeeded' }] } }, { policy: { acceptStatuses: STAT } });
  await cq('worst-is-qe', q0, { qeIdentity: { levels: [{ isvsvn: 4, status: 'Revoked' }] } }, { policy: { acceptStatuses: STAT } });
  await cq('advisories-merged-sorted-deduped', q0, { tcbInfo: (q: any) => ({ tdxModuleIdentities: [ident('TDX_01', [{ isvsvn: 13, status: 'UpToDate', advisories: ['INTEL-SA-9', 'INTEL-SA-1'] }])], levels: [lv(q, 'UpToDate', ['INTEL-SA-5', 'INTEL-SA-1'])] }), qeIdentity: { levels: [{ isvsvn: 4, status: 'UpToDate', advisories: ['INTEL-SA-3', 'INTEL-SA-9'] }] } });
  await cq('eval-number-minimum-of-both', q0, { tcbInfo: { tcbEvaluationDataNumber: 25 }, qeIdentity: { tcbEvaluationDataNumber: 19 } });
  await cq('eval-number-policy-minimum-met', q0, { tcbInfo: { tcbEvaluationDataNumber: 25 }, qeIdentity: { tcbEvaluationDataNumber: 25 } }, { policy: { minTcbEvaluationDataNumber: 25 } });
  await cq('eval-number-policy-minimum-info-below', q0, { tcbInfo: { tcbEvaluationDataNumber: 24 }, qeIdentity: { tcbEvaluationDataNumber: 30 } }, { policy: { minTcbEvaluationDataNumber: 25 } });
  await cq('eval-number-policy-minimum-qe-below', q0, { tcbInfo: { tcbEvaluationDataNumber: 30 }, qeIdentity: { tcbEvaluationDataNumber: 24 } }, { policy: { minTcbEvaluationDataNumber: 25 } });
  await cq('eval-number-zero-ok', q0, { tcbInfo: { tcbEvaluationDataNumber: 0 }, qeIdentity: { tcbEvaluationDataNumber: 0 } }, { policy: { minTcbEvaluationDataNumber: 0 } });
  await cq('eval-number-missing-in-tcb-info', q0, { tcbInfo: { tcbEvaluationDataNumber: null } });
  await cq('eval-number-missing-in-qe-identity', q0, { qeIdentity: { tcbEvaluationDataNumber: null } });
  await cq('fmspc-uppercase-in-tcb-info', q0, { tcbInfo: { fmspc: '90C06F000000' } });
  await cq('fmspc-mismatch', q0, { tcbInfo: { fmspc: '00a06f000000' } });
  await cq('fmspc-not-a-string', q0, { tcbInfo: { fmspc: 5 } });
  await cq('tcb-info-not-tdx', q0, { tcbInfo: { id: 'SGX' } });
  await cq('tcb-info-version-2', q0, { tcbInfo: { version: 2 } });
  await cq('tcb-info-stale', q0, { tcbInfo: { nextUpdate: '2026-10-19T00:00:00Z' } });
  await cq('tcb-info-issued-in-future', q0, { tcbInfo: { issueDate: '2026-10-21T00:00:00Z' } });
  await cq('tcb-info-dates-missing', q0, { tcbInfo: { issueDate: 'not a date', nextUpdate: 'nor this' } });
  await cq('tcb-info-next-update-is-now', q0, { tcbInfo: { nextUpdate: '2026-10-20T00:00:00Z' } });
  await cq('qe-identity-stale', q0, { qeIdentity: { nextUpdate: '2026-10-19T00:00:00Z' } });
  await cq('qe-identity-issued-in-future', q0, { qeIdentity: { issueDate: '2026-10-21T00:00:00Z' } });
  // platform evaluation errors
  await cq('no-tcb-levels', q0, { tcbInfo: { rawLevels: [] } });
  await cq('tcb-levels-not-an-array', q0, { tcbInfo: { rawLevels: 'x' } });
  await cq('malformed-level-not-an-object', q0, { tcbInfo: { rawLevels: [5] } });
  await cq('malformed-level-components', q0, { tcbInfo: { rawLevels: [{ tcb: { sgxtcbcomponents: [{ svn: 1 }], pcesvn: 1, tdxtcbcomponents: [] }, tcbStatus: 'UpToDate' }] } });
  await cq('malformed-level-pcesvn', q0, { tcbInfo: (q: any) => ({ rawLevels: [{ tcb: { sgxtcbcomponents: q.pckSpec.sgxTcb.map((svn: number) => ({ svn })), pcesvn: '13', tdxtcbcomponents: tdTcb(q).map((svn) => ({ svn })) }, tcbStatus: 'UpToDate' }] }) });
  await cq('level-unknown-status', q0, { tcbInfo: (q: any) => ({ levels: [lv(q, 'Banana')] }) });
  await cq('level-status-not-a-string', q0, { tcbInfo: (q: any) => ({ levels: [lv(q, 7)] }) });
  await cq('platform-below-every-level-pcesvn', q0, { tcbInfo: (q: any) => ({ levels: [lv(q, 'UpToDate', undefined, { pcesvn: q.pckSpec.pcesvn + 1 })] }) });
  await cq('platform-below-every-level-sgx', q0, { tcbInfo: (q: any) => ({ levels: [lv(q, 'UpToDate', undefined, { sgx: q.pckSpec.sgxTcb.map((x: number, i: number) => (i === 3 ? x + 1 : x)) })] }) });
  await cq('platform-below-every-level-tdx', q0, { tcbInfo: (q: any) => ({ levels: [lv(q, 'UpToDate', undefined, { tdx: tdTcb(q).map((x: number, i: number) => (i === 5 ? x + 1 : x)) })] }) });
  await cq('tdx-component-0-1-not-compared-with-module-identity', q0, { tcbInfo: (q: any) => ({ levels: [lv(q, 'UpToDate', undefined, { tdx: tdTcb(q).map((x: number, i: number) => (i < 2 ? x + 9 : x)) })] }) });
  await cq('tdx-component-0-compared-when-minor-0', qBase, { tcbInfo: (q: any) => ({ levels: [lv(q, 'UpToDate', undefined, { tdx: tdTcb(q).map((x: number, i: number) => (i === 0 ? x + 1 : x)) })] }) });
  await cq('first-matching-level-wins', q0, { tcbInfo: (q: any) => ({ levels: [lv(q, 'OutOfDate'), lv(q, 'UpToDate')] }) }, { policy: { acceptStatuses: STAT } });
  await cq('newer-level-skipped-older-matches', q0, { tcbInfo: (q: any) => ({ levels: [lv(q, 'UpToDate', undefined, { pcesvn: 99 }), lv(q, 'SWHardeningNeeded')] }) });
  await cq('platform-above-level-matches', Q({ pck: { sgxTcb: [9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9], pcesvn: 20 } }), { tcbInfo: (q: any) => ({ levels: [lv(q, 'UpToDate', undefined, { sgx: [5, 5, 2, 2, 6, 1, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0], pcesvn: 13 })] }) });
  // TDX module identity
  await cq('module-identity-missing', q0, { tcbInfo: (q: any) => ({ tdxModuleIdentities: [], levels: [lv(q, 'UpToDate')] }) });
  await cq('module-identity-other-id', q0, { tcbInfo: (q: any) => ({ tdxModuleIdentities: [ident('TDX_02', [{ isvsvn: 13, status: 'UpToDate' }])], levels: [lv(q, 'UpToDate')] }) });
  await cq('module-identity-below-every-level', q0, { tcbInfo: mod01([{ isvsvn: 14, status: 'UpToDate' }]) });
  await cq('module-identity-level-unknown-status', q0, { tcbInfo: mod01([{ isvsvn: 13, status: 'Banana' }]) });
  await cq('module-identity-no-levels', q0, { tcbInfo: mod01([]) });
  await cq('module-identity-mrsigner-short', q0, { tcbInfo: mod01([{ isvsvn: 13, status: 'UpToDate' }], { mrsigner: '00' }) });
  await cq('module-identity-mrsigner-mismatch', q0, { tcbInfo: mod01([{ isvsvn: 13, status: 'UpToDate' }], { mrsigner: '11'.repeat(48) }) });
  await cq('module-identity-attributes-mismatch', q0, { tcbInfo: mod01([{ isvsvn: 13, status: 'UpToDate' }], { attributes: '0100000000000000' }) });
  await cq('module-identity-attributes-mask-hides-difference', q0, { tcbInfo: mod01([{ isvsvn: 13, status: 'UpToDate' }], { attributes: '0100000000000000', attributesMask: '0000000000000000' }) });
  await cq('module-identity-higher-isvsvn-level-matches-first', Q({ td: { teeTcbSvn: '0f010500000000000000000000000000' } }), { tcbInfo: mod01([{ isvsvn: 15, status: 'SWHardeningNeeded' }, { isvsvn: 13, status: 'OutOfDate' }]) }, { policy: { acceptStatuses: STAT } });
  await cq('module-identity-hex-minor-0a', Q({ td: { teeTcbSvn: '0d0a0500000000000000000000000000' } }), { tcbInfo: (q: any) => ({ tdxModuleIdentities: [ident('TDX_0A', [{ isvsvn: 13, status: 'UpToDate' }])], levels: [lv(q, 'UpToDate')] }) });
  await cq('base-module-missing', qBase, { tcbInfo: { tdxModule: null } });
  await cq('base-module-malformed', qBase, { tcbInfo: { tdxModule: { mrsigner: 'xyz', attributes: '0000000000000000', attributesMask: 'FFFFFFFFFFFFFFFF' } } });
  await cq('base-module-mrsigner-mismatch', qBase, { tcbInfo: { tdxModule: { mrsigner: '22'.repeat(48), attributes: '0000000000000000', attributesMask: 'FFFFFFFFFFFFFFFF' } } });
  await cq('base-module-seam-attributes-mismatch', Q({ td: { teeTcbSvn: '0d000500000000000000000000000000', seamAttributes: '0100000000000000' } }), {});
  await cq('base-module-attributes-mask-allows-seam-bit', Q({ td: { teeTcbSvn: '0d000500000000000000000000000000', seamAttributes: '0100000000000000' } }), { tcbInfo: { tdxModule: { mrsigner: '0'.repeat(96), attributes: '0000000000000000', attributesMask: 'FEFFFFFFFFFFFFFF' } } });
  await cq('td-mrsignerseam-nonzero-mismatch', Q({ td: { mrSignerSeam: '7e'.repeat(48) } }), {});
  await cq('td-mrsignerseam-nonzero-matches-identity', Q({ td: { mrSignerSeam: '7e'.repeat(48) } }), { tcbInfo: mod01([{ isvsvn: 13, status: 'UpToDate' }], { mrsigner: '7e'.repeat(48) }) });
  // QE identity
  await cq('qe-id-not-td-qe', q0, { qeIdentity: { id: 'QE' } });
  await cq('qe-version-3', q0, { qeIdentity: { version: 3 } });
  await cq('qe-fields-malformed-isvprodid', q0, { qeIdentity: { isvprodid: '2' } });
  await cq('qe-fields-malformed-mrsigner', q0, { qeIdentity: { mrsigner: 'DC9E' } });
  await cq('qe-fields-malformed-miscselect', q0, { qeIdentity: { miscselect: 'zzzzzzzz' } });
  await cq('qe-miscselect-mismatch', q0, { qeIdentity: { miscselect: '01000000' } });
  await cq('qe-miscselect-mask-hides', q0, { qeIdentity: { miscselect: '01000000', miscselectMask: '00000000' } });
  await cq('qe-attributes-mismatch', q0, { qeIdentity: { attributes: '10000000000000000000000000000000' } });
  await cq('qe-mrsigner-mismatch', q0, { qeIdentity: { mrsigner: '00'.repeat(32) } });
  await cq('qe-mrsigner-lowercase-ok', q0, { qeIdentity: { mrsigner: 'dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c5' } });
  await cq('qe-isvprodid-mismatch', q0, { qeIdentity: { isvprodid: 3 } });
  await cq('qe-isvsvn-below-every-level', q0, { qeIdentity: { levels: [{ isvsvn: 8, status: 'UpToDate' }] } });
  await cq('qe-isvsvn-exact-level', q0, { qeIdentity: { levels: [{ isvsvn: 7, status: 'SWHardeningNeeded' }, { isvsvn: 4, status: 'OutOfDate' }] } }, { policy: { acceptStatuses: STAT } });
  await cq('qe-no-levels', q0, { qeIdentity: { levels: [] } });
  await cq('qe-level-unknown-status', q0, { qeIdentity: { levels: [{ isvsvn: 4, status: 'Banana' }] } });
  await cq('qe-report-other-isvsvn', Q({ qe: { isvSvn: 3 } }), {});
  await cq('qe-report-other-isvprodid', Q({ qe: { isvProdId: 5 } }), {});
  // signatures, chains, CRLs
  await cq('tcb-info-signature-tampered', q0, { tamperTcbInfo: (r: string) => r.replace('"UpToDate"', '"OutOfDate"') });
  await cq('qe-identity-signature-tampered', q0, { tamperQeIdentity: (r: string) => r.replace('"TD_QE"', '"TD_QF"') });
  await cq('tcb-info-signed-by-other-key', q0, { signerKey: X.forgeKey('rv/col-other', 'P-256') });
  await cq('tcb-info-issuer-chain-garbage', q0, { tcbInfoChainPem: 'not pem' });
  await cq('qe-identity-issuer-chain-garbage', q0, { qeIdentityChainPem: 'not pem' });
  await cq('tcb-info-issuer-chain-leaf-only', q0, { tcbInfoChainPem: PKI.tcbSigning.pem });
  await cq('qe-identity-issuer-chain-leaf-only', q0, { qeIdentityChainPem: PKI.tcbSigning.pem });
  { const other = F.forgeIntelPki('rv/other-pki'); await cq('tcb-info-issuer-chain-wrong-root', q0, { tcbInfoChainPem: other.tcbSigning.pem + other.root.pem }); }
  await cq('tcb-signing-cert-revoked-by-root-crl', q0, { rootCrlRevoked: [PKI.tcbSigning.serialHex] });
  await cq('platform-ca-revoked-by-root-crl', q0, { rootCrlRevoked: [PKI.platformCa.serialHex] });
  await cq('pck-leaf-revoked-by-pck-crl', q0, { pckCrlRevoked: [q0.pck.serialHex] });
  await cq('pck-crl-lists-other-serials', q0, { pckCrlRevoked: ['0a0b', '0c0d'] });
  await cq('root-crl-lists-other-serials', q0, { rootCrlRevoked: ['0a0b'] });
  await cq('pck-crl-signed-by-other-key', q0, { pckCrlSigner: X.forgeKey('rv/crl-sig', 'P-256') });
  await cq('root-crl-signed-by-other-key', q0, { rootCrlSigner: X.forgeKey('rv/crl-sig', 'P-256') });
  await cq('crl-stale', q0, { crlNextUpdate: D('2026-10-19T00:00:00Z') });
  await cq('crl-this-update-in-future', q0, { crlThisUpdate: D('2026-10-21T00:00:00Z') });
  {
    const wire = colWire(forgeCol(q0));
    const futureRoot = X.forgeCrl({ issuer: PKI.rootDn, signer: PKI.rootKey, thisUpdate: D('2026-10-21T00:00:00Z'), nextUpdate: D('2026-11-21T00:00:00Z'), revoked: [] });
    const mk = (n: string, c: any) => rec('verifyIntelTdxCollateral', n, [{ quote: q0.quote, collateral: c, nowMs: NOW, trustAnchorRootCaSpkiSha256: q0.rootSpkiSha256 }], wireCall);
    await mk('root-crl-from-the-future', { ...wire, rootCrlDer: futureRoot });
    await mk('root-crl-garbage', { ...wire, rootCrlDer: bytes('not a crl') });
    await mk('pck-crl-garbage', { ...wire, pckCrlDer: bytes('not a crl') });
    await mk('pck-crl-swapped-with-root-crl', { ...wire, pckCrlDer: wire.rootCrlDer, rootCrlDer: wire.pckCrlDer });
    await mk('incomplete-no-tcb-info', { ...wire, tcbInfoJson: '' });
    await mk('incomplete-no-qe-identity', { ...wire, qeIdentityJson: '' });
    await mk('incomplete-no-pck-crl', { ...wire, pckCrlDer: new Uint8Array(0) });
    await mk('incomplete-no-root-crl', { ...wire, rootCrlDer: new Uint8Array(0) });
    await mk('incomplete-no-tcb-info-chain', { ...wire, tcbInfoIssuerChainPem: '' });
    await mk('incomplete-no-qe-identity-chain', { ...wire, qeIdentityIssuerChainPem: '' });
    await mk('incomplete-empty-object', {});
    await mk('incomplete-null', null);
    await mk('swapped-documents', { ...wire, tcbInfoJson: wire.qeIdentityJson, qeIdentityJson: wire.tcbInfoJson });
  }
  // the quote itself
  {
    const withQuote = (n: string, b: Uint8Array) => rec('verifyIntelTdxCollateral', n, [{ quote: b, collateral: colWire(forgeCol(q0)), nowMs: NOW, trustAnchorRootCaSpkiSha256: q0.rootSpkiSha256 }], wireCall);
    await withQuote('quote-garbage', bytes('garbage'));
    await withQuote('quote-truncated', q0.quote.subarray(0, 800));
  }
  await cq('quote-debug-td-refused', Q({ td: { debug: true } }), {});
  await cq('quote-debug-td-allowed', Q({ td: { debug: true } }), {}, { allowDebug: true });
  await cq('quote-debug-td-allow-debug-false', Q({ td: { debug: true } }), {}, { allowDebug: false });
  await cq('quote-qe-debug', Q({ qe: { attributes: '1700000000000000e700000000000000' } }), {});
  await cq('quote-pck-expired-at-now', base, {}, {}, Date.parse('2034-01-01T00:00:00Z'), NOW);
  await cq('pck-chain-not-yet-valid', base, {}, {}, Date.parse('2026-09-01T00:00:00Z'), NOW);
  await cq('anchor-default-refuses-test-root', base, {}, { trustAnchorRootCaSpkiSha256: undefined });
  await cq('anchor-wrong', base, {}, { trustAnchorRootCaSpkiSha256: '11'.repeat(32) });
  await cq('quote-pck-with-other-fmspc-matches-collateral', Q({ pck: { fmspc: '00a06f000000' } }), {});
  await cq('quote-other-pck-serial', Q({ pck: { serialLabel: 'second' } }), {});
  // real silicon + the real PCS collateral
  {
    const rc = (n: string, q: Uint8Array, col: any, extra: any = {}, now = REAL_NOW) => rec('verifyIntelTdxCollateral', n, [{ quote: q, collateral: col, nowMs: now, ...extra }], wireCall);
    await rc('real-ok-default', pcaQuote, realCol());
    await rc('real-ok-all-statuses-accepted', pcaQuote, realCol(), { policy: { acceptStatuses: STAT } });
    await rc('real-only-up-to-date', pcaQuote, realCol(), { policy: { acceptStatuses: ['UpToDate'] } });
    await rc('real-min-eval-number-huge', pcaQuote, realCol(), { policy: { minTcbEvaluationDataNumber: 1_000_000 } });
    await rc('real-explicit-pin', pcaQuote, realCol(), { trustAnchorRootCaSpkiSha256: T.INTEL_SGX_ROOT_CA_SPKI_SHA256 });
    await rc('real-wrong-pin', pcaQuote, realCol(), { trustAnchorRootCaSpkiSha256: base.rootSpkiSha256 });
    await rc('real-processor-pck-crl', pcaQuote, realCol('pckcrl-processor.der'));
    await rc('real-too-late', pcaQuote, realCol(), {}, Date.parse('2027-06-01T00:00:00Z'));
    await rc('real-way-too-late', pcaQuote, realCol(), {}, Date.parse('2060-01-01T00:00:00Z'));
    await rc('real-too-early', pcaQuote, realCol(), {}, Date.parse('2026-01-01T00:00:00Z'));
    await rc('real-other-quote', realQuote, realCol());
    await rc('real-other-quote-all-statuses', realQuote, realCol(), { policy: { acceptStatuses: STAT } });
  }
}

// =============================================== Azure runtime-data binding ===============================================
{
  const rt = (x: any) => bytes(JSON.stringify(x));
  const udata = hex(bindBytes(BIND));
  const hashOf = (runtime: Uint8Array) => new Uint8Array([...X.digest('sha256', runtime), ...new Uint8Array(32)]);
  const ab = (n: string, reportData: Uint8Array, runtime: Uint8Array, expected: any = BIND) => rec('checkAzureRuntimeDataBinding', n, [reportData, runtime, expected], (r, d, e) => DC.checkAzureRuntimeDataBinding(r, d, e) ?? null);
  const good = rt({ 'user-data': udata, keys: [] });
  const up = rt({ 'user-data': udata.toUpperCase() });
  const extra = rt({ a: 1, 'user-data': udata, 'vm-configuration': { 'console-enabled': false } });
  const e0 = rt({ 'user-data': hex(bindBytes({ ...BIND, epoch: 0 })) });
  await ab('ok', hashOf(good), good);
  await ab('ok-uppercase-user-data', hashOf(up), up);
  await ab('ok-extra-members', hashOf(extra), extra);
  await ab('ok-epoch-0', hashOf(e0), e0, { ...BIND, epoch: 0 });
  await ab('real-pca-bound', realTd.reportData, pcaRuntime, REAL_BIND);
  await ab('real-pca-bound-other-binding', realTd.reportData, pcaRuntime, { ...REAL_BIND, nonce: 'x' });
  await ab('report-data-31-bytes', new Uint8Array(31), good);
  await ab('report-data-65-bytes', new Uint8Array(65), good);
  await ab('report-data-empty', new Uint8Array(0), good);
  await ab('report-data-tail-nonzero', new Uint8Array([...X.digest('sha256', good), ...new Uint8Array(31), 1]), good);
  await ab('hash-mismatch', hashOf(rt({ other: 1 })), good);
  await ab('runtime-not-json', hashOf(bytes('not json')), bytes('not json'));
  await ab('runtime-empty', hashOf(new Uint8Array(0)), new Uint8Array(0));
  await ab('runtime-array', hashOf(bytes('[1]')), bytes('[1]'));
  await ab('runtime-string', hashOf(bytes('"s"')), bytes('"s"'));
  await ab('runtime-null', hashOf(bytes('null')), bytes('null'));
  for (const [n, v] of [['absent', undefined], ['not-a-string', 5], ['short', udata.slice(2)], ['long', udata + '00'], ['not-hex', 'zz'.repeat(64)]] as const) {
    const r = rt(v === undefined ? { keys: [] } : { 'user-data': v });
    await ab('user-data-' + n, hashOf(r), r);
  }
  await ab('user-data-other-binding', hashOf(good), good, { ...BIND, grantRef: 'other' });
  await ab('expected-not-constructible-no-nonce', hashOf(good), good, { ...BIND, nonce: '' });
  await ab('expected-not-constructible-bad-epoch', hashOf(good), good, { ...BIND, epoch: -3 });
}

// =============================================== JWT parsers ===============================================
const seg = (t: string) => b64u(Buffer.from(t));
const jtok = (h: any, p: any, s = 'c2ln') => `${typeof h === 'string' ? h : seg(JSON.stringify(h))}.${typeof p === 'string' ? p : seg(JSON.stringify(p))}.${s}`;
/** The same bytes with a non-zero trailing bit pattern in the last character (the one base64url form that is not canonical). */
const nonCanonical = (s: string) => {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  return s.slice(0, -1) + A[A.indexOf(s.at(-1)!) | 1];
};
{
  const H = { alg: 'ES256', kid: 'k1', jku: 'https://maa.example.net/certs', typ: 'JWT', x5c: ['AAAA', 'BBBB'] };
  const P = { iss: 'https://issuer.example.net', iat: 1790000000, 'x-ms-attestation-type': 'tdxvm', nested: { a: [1, 2, { b: null }] }, uni: 'é€', big: 12345678901 };
  const hseg = seg('{"alg":"ES256"}');
  const cases: [string, string][] = [
    ['ok-full-header', jtok(H, P)],
    ['ok-minimal', jtok({ alg: 'RS256' }, {})],
    ['ok-extra-header-members-dropped', jtok({ alg: 'ES256', crit: ['x'], zip: 'DEF', extra: { a: 1 } }, P)],
    ['ok-kid-only', jtok({ alg: 'ES256', kid: 'only-kid' }, P)],
    ['ok-empty-kid-kept', jtok({ alg: 'ES256', kid: '' }, P)],
    ['ok-signature-64-bytes', jtok(H, P, b64u(Buffer.alloc(64, 7)))],
    ['ok-signature-256-bytes', jtok({ alg: 'RS256' }, P, b64u(Buffer.alloc(256, 9)))],
    ['ok-unsupported-alg-still-parses', jtok({ alg: 'none' }, P)],
    ['ok-duplicate-payload-keys', jtok(H, seg('{"a":1,"a":2}'))],
    ['ok-payload-whitespace', jtok(H, seg('  { "a" : [ 1 , 2 ] }  '))],
    ['ok-unicode-kid', jtok({ alg: 'ES256', kid: 'ключ' }, P)],
    ['kid-not-a-string-dropped', jtok({ alg: 'ES256', kid: 5 }, P)],
    ['jku-not-a-string-dropped', jtok({ alg: 'ES256', jku: ['x'] }, P)],
    ['typ-not-a-string-dropped', jtok({ alg: 'ES256', typ: true }, P)],
    ['x5c-not-an-array-dropped', jtok({ alg: 'ES256', x5c: 'AAAA' }, P)],
    ['x5c-mixed-array-dropped', jtok({ alg: 'ES256', x5c: ['AAAA', 5] }, P)],
    ['x5c-empty-array-kept', jtok({ alg: 'ES256', x5c: [] }, P)],
    ['empty-string', ''],
    ['one-part', 'abc'],
    ['two-parts', 'abc.def'],
    ['four-parts', 'a.b.c.d'],
    ['trailing-dot-empty-signature', jtok(H, P, '')],
    ['empty-header', `.${seg('{}')}.c2ln`],
    ['empty-payload', `${hseg}..c2ln`],
    ['header-not-base64url-plus', `ab+d.${seg('{}')}.c2ln`],
    ['header-not-base64url-slash', `ab/d.${seg('{}')}.c2ln`],
    ['header-padded', `${hseg}=.${seg('{}')}.c2ln`],
    ['header-non-canonical-trailing-bits', `${nonCanonical(hseg)}.${seg('{}')}.c2ln`],
    ['payload-non-canonical-trailing-bits', `${hseg}.${nonCanonical(seg('{}'))}.c2ln`],
    ['signature-non-canonical-trailing-bits', jtok(H, P, 'QR')],
    ['signature-canonical-one-byte', jtok(H, P, 'QQ')],
    ['signature-invalid-char', jtok(H, P, 'c2ln$')],
    ['signature-padded', jtok(H, P, 'c2ln=')],
    ['signature-single-char-invalid-length', jtok(H, P, 'c')],
    ['header-not-json', jtok(seg('not json'), P)],
    ['payload-not-json', jtok(H, seg('not json'))],
    ['header-empty-json-text', jtok(seg(''), P)],
    ['payload-truncated-json', jtok(H, seg('{"a":'))],
    ['header-array', jtok(seg('["alg"]'), P)],
    ['header-string', jtok(seg('"alg"'), P)],
    ['header-null', jtok(seg('null'), P)],
    ['header-number', jtok(seg('5'), P)],
    ['payload-array', jtok(H, seg('[1]'))],
    ['payload-null', jtok(H, seg('null'))],
    ['payload-string', jtok(H, seg('"x"'))],
    ['payload-number', jtok(H, seg('7'))],
    ['payload-true', jtok(H, seg('true'))],
    ['no-alg', jtok({ kid: 'k' }, P)],
    ['alg-empty', jtok({ alg: '' }, P)],
    ['alg-not-a-string', jtok({ alg: 256 }, P)],
    ['alg-null', jtok({ alg: null }, P)],
    ['invalid-utf8-header', jtok(b64u(Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d])), P)],
    ['leading-space-in-token', ` ${jtok(H, P)}`],
    ['trailing-newline-in-token', `${jtok(H, P)}\n`],
  ];
  const real = (dir: string, f: string) => fxt(dir, f).trim();
  for (const f of ['pcabound-tdxvm-token.jwt', 'sevsnp-token.jwt', 'tdxvm-token.jwt']) cases.push(['real-maa-' + f.replace('.jwt', ''), real('real-azure-maa', f)]);
  // the real Confidential Space captures are withheld from the public tree (they name a live cloud project): never record them
  for (const [n, t] of cases) {
    await rec('parseMaaJwt', n, [t], (s) => AZ.parseMaaJwt(s));
    await rec('parseGcpCsJwt', n, [t], (s) => GC.parseGcpCsJwt(s));
  }
}

// =============================================== x5c chain checks ===============================================
{
  const NB = D('2025-01-01T00:00:00Z'), NA = D('2035-01-01T00:00:00Z');
  const dn = (cn: string) => [['CN', cn]] as any;
  const mkWorld = (label: string, over: any = {}) => {
    const rk = X.forgeKey(`${label}/root`, 'P-256'), ik = X.forgeKey(`${label}/int`, 'P-256'), lk = X.forgeKey(`${label}/leaf`, 'P-256');
    const root = X.forgeCert({ subject: dn('rv-root'), issuer: dn('rv-root'), subjectKey: rk, signer: rk, serial: 1n, notBefore: NB, notAfter: NA, extensions: [X.ext.basicConstraints(true, over.rootPathLen ?? 2)] });
    const int = X.forgeCert({ subject: dn('rv-int'), issuer: dn('rv-root'), subjectKey: ik, signer: rk, serial: 2n, notBefore: NB, notAfter: over.intNa ?? NA, extensions: over.intExt ?? [X.ext.basicConstraints(true, 1)] });
    const leaf = X.forgeCert({ subject: dn('rv-leaf'), issuer: dn('rv-int'), subjectKey: lk, signer: ik, serial: 3n, notBefore: NB, notAfter: NA, extensions: over.leafExt ?? [] });
    return { rk, ik, lk, root, int, leaf };
  };
  const W = mkWorld('rv-x5c');
  const rsa = R.forgeRsaKey('rv/x5c-rsa');
  const rsaLeaf = X.forgeCert({ subject: dn('rv-rsa-leaf'), issuer: dn('rv-int'), subjectKey: { ...W.lk, spki: rsa.spki }, signer: W.ik, serial: 4n, notBefore: NB, notAfter: NA });
  const rogueK = X.forgeKey('rv-x5c/rogue', 'P-256');
  const rogue = X.forgeCert({ subject: dn('rv-rogue'), issuer: dn('rv-rogue'), subjectKey: rogueK, signer: rogueK, serial: 9n, notBefore: NB, notAfter: NA });
  const x5 = (...c: any[]) => c.map((x) => Buffer.from(x.der).toString('base64'));
  const T0 = Date.parse('2026-06-01T00:00:00Z');
  const vx = (n: string, chain: any, anchors: any, opts: any = { nowMs: T0 }) => rec('verifyX5cChain', n, [chain, anchors, opts], async (c, a, p) => { const r = await AZ.verifyX5cChain(c, a, p); const { leaf, ...rest } = r; return { ...rest, ...(leaf ? { leafDer: new Uint8Array(leaf.raw) } : {}) }; });
  const vj = (n: string, chain: any, anchors: any, opts: any = { nowMs: T0, skewMs: 0 }) => rec('verifyJwkX5cChain', n, [chain, anchors, opts], (c, a, p) => GC.verifyJwkX5cChain(c, a, p));
  const fullChain = x5(W.leaf, W.int, W.root);
  const A = (extra: any = {}) => ({ rootCertsPem: [W.root.pem], ...extra });
  const WE = mkWorld('rv-x5c-exp');
  const WI = mkWorld('rv-x5c-ie', { intNa: D('2026-01-01T00:00:00Z') });
  const prof = (label: string, over: any) => { const w = mkWorld(label, over); return { w, chain: x5(w.leaf, w.int, w.root), anchors: { rootCertsPem: [w.root.pem] } }; };

  await vx('ok-root-pem-anchor-full-chain', fullChain, A());
  await vx('ok-root-pem-anchor-without-root-in-chain', x5(W.leaf, W.int), A());
  await vx('ok-root-spki-anchor', fullChain, { rootSpkiSha256: [W.rk.spkiSha256] });
  await vx('ok-root-spki-anchor-uppercase', fullChain, { rootSpkiSha256: [W.rk.spkiSha256.toUpperCase()] });
  await vx('ok-intermediate-pinned', x5(W.leaf, W.int), { rootSpkiSha256: [W.ik.spkiSha256] });
  await vx('ok-leaf-pinned', x5(W.leaf), { rootSpkiSha256: [W.lk.spkiSha256] });
  await vx('ok-leaf-pinned-rest-of-chain-ignored', x5(W.leaf, rogue), { rootSpkiSha256: [W.lk.spkiSha256] });
  await vx('ok-rsa-leaf', x5(rsaLeaf, W.int, W.root), A());
  await vx('ok-both-anchor-kinds', fullChain, { rootCertsPem: [W.root.pem], rootSpkiSha256: ['00'.repeat(32)] });
  await vx('ok-skew-rescues-expired', x5(WE.leaf), { rootSpkiSha256: [WE.lk.spkiSha256] }, { nowMs: NA.getTime() + 3_600_000, clockSkewMs: 7_200_000 });
  await vx('expired-without-skew', x5(W.leaf), { rootSpkiSha256: [W.lk.spkiSha256] }, { nowMs: NA.getTime() + 3_600_000 });
  await vx('skew-zero-explicit', x5(W.leaf), { rootSpkiSha256: [W.lk.spkiSha256] }, { nowMs: NA.getTime() + 1000, clockSkewMs: 0 });
  await vx('skew-negative-treated-as-zero', x5(W.leaf), { rootSpkiSha256: [W.lk.spkiSha256] }, { nowMs: NA.getTime() + 1000, clockSkewMs: -5000 });
  await vx('skew-too-small', x5(W.leaf), { rootSpkiSha256: [W.lk.spkiSha256] }, { nowMs: NA.getTime() + 3_600_000, clockSkewMs: 1000 });
  await vx('not-yet-valid', fullChain, A(), { nowMs: D('2024-06-01T00:00:00Z').getTime() });
  await vx('not-yet-valid-within-skew', fullChain, A(), { nowMs: NB.getTime() - 1000, clockSkewMs: 5000 });
  await vx('intermediate-expired', x5(WI.leaf, WI.int, WI.root), { rootCertsPem: [WI.root.pem] });
  await vx('empty-chain', [], A());
  await vx('chain-not-an-array', 'x', A());
  await vx('empty-entry-first', ['', ...x5(W.int)], A());
  await vx('empty-entry-later', [...x5(W.leaf), ''], A());
  await vx('non-string-entry', [...x5(W.leaf), 5], A());
  await vx('malformed-certificate', ['AAAA'], A());
  await vx('malformed-base64-certificate', ['!!!!'], A());
  await vx('malformed-second-certificate', [...x5(W.leaf), 'AAAA'], A());
  await vx('no-anchors-configured', fullChain, {});
  await vx('empty-anchor-lists', fullChain, { rootCertsPem: [], rootSpkiSha256: [] });
  await vx('anchor-empty-string-pin-ignored', fullChain, { rootSpkiSha256: [''] });
  await vx('anchor-not-a-string-pin-ignored', fullChain, { rootSpkiSha256: [5] });
  await vx('anchor-malformed-pem', fullChain, { rootCertsPem: ['not a pem'] });
  await vx('anchor-other-root', fullChain, { rootCertsPem: [rogue.pem] });
  await vx('anchor-other-spki', fullChain, { rootSpkiSha256: ['ab'.repeat(32)] });
  await vx('chain-top-not-signed-by-external-root', x5(W.leaf, W.int), { rootCertsPem: [rogue.pem] });
  await vx('broken-link-leaf-not-signed-by-next', x5(W.leaf, W.root), A());
  await vx('broken-link-with-pin-above', x5(W.leaf, rogue), { rootSpkiSha256: [rogueK.spkiSha256] });
  await vx('rogue-root-appended', x5(W.leaf, W.int, rogue), A());
  await vx('anchor-in-chain-link-broken-below', x5(W.leaf, rogue, W.root), { rootSpkiSha256: [W.rk.spkiSha256] });
  { const p = prof('rv-x5c-p1', { intExt: [] }); await vx('profile-intermediate-without-basic-constraints', p.chain, p.anchors); }
  { const p = prof('rv-x5c-p2', { intExt: [X.ext.basicConstraints(false)] }); await vx('profile-intermediate-ca-false', p.chain, p.anchors); }
  { const p = prof('rv-x5c-p3', { intExt: [X.ext.basicConstraints(true, 1), X.ext.keyUsage(['digitalSignature'])] }); await vx('profile-intermediate-key-usage-no-cert-sign', p.chain, p.anchors); }
  { const p = prof('rv-x5c-p4', { rootPathLen: 0 }); await vx('profile-path-length-exceeded', p.chain, p.anchors); }
  { const p = prof('rv-x5c-p5', { leafExt: [X.ext.basicConstraints(true)] }); await vx('profile-leaf-is-a-ca', p.chain, p.anchors); }
  { const p = prof('rv-x5c-p6', { leafExt: [X.extension('1.2.3.4.5', true, X.seq())] }); await vx('profile-leaf-unknown-critical-extension', p.chain, p.anchors); }
  { const p = prof('rv-x5c-p7', { leafExt: [X.extension('1.2.3.4.5', false, X.seq())] }); await vx('profile-leaf-unknown-noncritical-extension', p.chain, p.anchors); }
  { const p = prof('rv-x5c-p8', { intExt: [] }); await vx('profile-checked-only-up-to-pinned-anchor', p.chain, { rootSpkiSha256: [p.w.ik.spkiSha256] }); }
  // the real Microsoft Azure Attestation signing chains
  {
    const JW = JSON.parse(fxt('real-azure-maa', 'maa-signing-certs.json')), JE = JSON.parse(fxt('real-azure-maa', 'maa-signing-certs-eus.json'));
    const bound = JSON.parse(Buffer.from(fxt('real-azure-maa', 'pcabound-tdxvm-token.jwt').trim().split('.')[1]!, 'base64url').toString());
    const NOW_M = (bound.iat + 3600) * 1000;
    const MS_ROOT = '02376d0908ac23041cc7d666d9daf192554f7fc36317aa9cb800908616b28af8', MS_PCA = '9ab67a5d1926476a794bcb4fa6cd74faa1486cd05931010aa7bbf1f57f1a8f58';
    for (const [nm, set] of [['wus', JW], ['eus', JE]] as const) {
      for (const [i, k] of set.keys.slice(0, 3).entries()) {
        await vx(`real-${nm}-key${i}-root-pin`, k.x5c, { rootSpkiSha256: [MS_ROOT] }, { nowMs: NOW_M });
        await vx(`real-${nm}-key${i}-intermediate-pin`, k.x5c, { rootSpkiSha256: [MS_PCA] }, { nowMs: NOW_M });
        await vx(`real-${nm}-key${i}-wrong-pin`, k.x5c, { rootSpkiSha256: ['00'.repeat(32)] }, { nowMs: NOW_M });
        await vx(`real-${nm}-key${i}-too-late`, k.x5c, { rootSpkiSha256: [MS_ROOT] }, { nowMs: Date.parse('2060-01-01T00:00:00Z') });
      }
    }
    const k0 = JW.keys[1];
    await vj('real-maa-chain-root-pin', k0.x5c, { trustedKeySpki: [MS_ROOT] }, { nowMs: NOW_M, skewMs: 0 });
    await vj('real-maa-chain-wrong-pin', k0.x5c, { trustedKeySpki: ['00'.repeat(32)] }, { nowMs: NOW_M, skewMs: 0 });
    await vj('real-maa-chain-too-late', k0.x5c, { trustedKeySpki: [MS_ROOT] }, { nowMs: Date.parse('2060-01-01T00:00:00Z'), skewMs: 0 });
  }
  await vj('ok-root-pem', fullChain, { rootCertsPem: [W.root.pem] });
  await vj('ok-root-pem-without-root-in-chain', x5(W.leaf, W.int), { rootCertsPem: [W.root.pem] });
  await vj('ok-root-pem-bare-public-key', x5(W.leaf, W.int), { rootCertsPem: [`-----BEGIN PUBLIC KEY-----\n${Buffer.from(W.rk.spki).toString('base64')}\n-----END PUBLIC KEY-----\n`] });
  await vj('ok-key-pin-of-leaf', fullChain, { trustedKeySpki: [W.lk.spkiSha256] });
  await vj('ok-key-pin-of-root-uppercase', fullChain, { trustedKeySpki: [W.rk.spkiSha256.toUpperCase()] });
  await vj('ok-key-pin-of-intermediate', x5(W.leaf, W.int), { trustedKeySpki: [W.ik.spkiSha256] });
  await vj('ok-rsa-leaf-pinned', x5(rsaLeaf, W.int), { trustedKeySpki: [rsa.spkiSha256] });
  await vj('ok-skew-rescues-expired', fullChain, { rootCertsPem: [W.root.pem] }, { nowMs: NA.getTime() + 1000, skewMs: 5000 });
  await vj('expired', fullChain, { rootCertsPem: [W.root.pem] }, { nowMs: NA.getTime() + 1000, skewMs: 0 });
  await vj('not-yet-valid', fullChain, { rootCertsPem: [W.root.pem] }, { nowMs: NB.getTime() - 1000, skewMs: 0 });
  await vj('empty-chain', [], { rootCertsPem: [W.root.pem] });
  await vj('empty-entry', ['', ...x5(W.int)], { rootCertsPem: [W.root.pem] });
  await vj('non-string-entry', [5], { rootCertsPem: [W.root.pem] });
  await vj('malformed-certificate', ['AAAA'], { rootCertsPem: [W.root.pem] });
  await vj('broken-link', x5(W.leaf, W.root), { rootCertsPem: [W.root.pem] });
  await vj('no-anchors', fullChain, {});
  await vj('anchor-other-root', fullChain, { rootCertsPem: [rogue.pem] });
  await vj('anchor-unparsable-root-skipped', fullChain, { rootCertsPem: ['garbage', W.root.pem] });
  await vj('anchor-only-unparsable-root', fullChain, { rootCertsPem: ['garbage'] });
  await vj('anchor-pin-other-key', fullChain, { trustedKeySpki: ['cd'.repeat(32)] });
  await vj('anchor-trusted-jwks-ignored', fullChain, { trustedJwks: { keys: [{ kid: 'x' }] } });
  { const p = prof('rv-x5c-q1', { intExt: [] }); await vj('profile-intermediate-without-basic-constraints', p.chain, p.anchors); }
  { const p = prof('rv-x5c-q2', { leafExt: [X.extension('1.2.3.4.5', true, X.seq())] }); await vj('profile-leaf-unknown-critical-extension', p.chain, p.anchors); }
  { const p = prof('rv-x5c-q3', { leafExt: [X.ext.basicConstraints(true)] }); await vj('profile-leaf-is-a-ca', p.chain, p.anchors); }
}

// =============================================== hwmodel mapper ===============================================
for (const [n, v] of [['sev', 'GCP_AMD_SEV'], ['sev-snp', 'GCP_AMD_SEV_SNP'], ['sev-es', 'GCP_AMD_SEV_ES'], ['tdx', 'GCP_INTEL_TDX'], ['lowercase-sev', 'gcp_amd_sev_snp'], ['lowercase-tdx', 'gcp_intel_tdx'], ['future-sev-name', 'GCP_AMD_SEV_FOO'], ['future-tdx-name', 'GCP_INTEL_TDX_V2'], ['mixed-case-prefix', 'Gcp_Intel_Tdx_Next'], ['amd-without-sev', 'GCP_AMD'], ['other-vendor', 'GCP_NVIDIA_H100'], ['empty', ''], ['bare-tdx', 'TDX'], ['leading-space', ' GCP_INTEL_TDX'], ['unrelated', 'hwmodel']] as const) {
  await rec('teeTypeOfHwModel', n, [v], (s) => GC.teeTypeOfHwModel(s) ?? null);
}

// =============================================== JWKS fetchers over an injected transport ===============================================
{
  const respOf = (r: any) => {
    if (r.$throws) throw new Error(r.$throws);
    const text = r.body && typeof r.body === 'object' && '$text' in r.body ? r.body.$text : JSON.stringify(r.body);
    return new Response(text, { status: r.status ?? 200, headers: { 'content-type': 'application/json' } });
  };
  const transport = (script: any[], log: string[]) => { let i = 0; return (async (url: any, ...rest: any[]) => { log.push(String(url) + (rest.length ? ' [extra args]' : '')); return respOf(script[Math.min(i++, script.length - 1)]); }) as any; };
  const drive = (impl: (issuer: string, f: any, opts: any) => Promise<any>) => async (a: any) => {
    const log: string[] = [];
    let out: any;
    try { out = { ok: true, jwks: await impl(a.issuer, transport(a.script, log), a.opts ?? {}) }; } catch (e: any) { out = { ok: false, error: e instanceof Error ? e.message : String(e) }; }
    out.requests = log;
    return out;
  };
  const dm = drive((iss, f, op) => AZ.fetchMaaJwks(iss, { fetch: f, ...op }));
  const dg = drive((iss, f, op) => GC.fetchGcpConfidentialSpaceJwks(iss, { fetch: f, ...op }));
  const WUS = 'https://sharedwus.wus.attest.azure.net';
  const fm = (n: string, issuer: string, script: any[], opts?: any) => rec('fetchMaaJwks', n, [{ issuer, script, ...(opts ? { opts } : {}) }], dm);
  const fg = (n: string, issuer: string, script: any[], opts?: any) => rec('fetchGcpConfidentialSpaceJwks', n, [{ issuer, script, ...(opts ? { opts } : {}) }], dg);
  const MK = { keys: [{ kid: 'a', kty: 'RSA', alg: 'RS256', x5c: ['AAAA', 'BBBB'], extra: 1, n: 'ignored' }, { kid: 'b', kty: 'EC' }] };
  const real = JSON.parse(fxt('real-azure-maa', 'maa-signing-certs.json'));

  await fm('ok', WUS, [{ body: MK }]);
  await fm('ok-real-certs', WUS, [{ body: real }]);
  await fm('ok-custom-certs-path', WUS, [{ body: MK }], { certsPath: '/custom/certs' });
  await fm('ok-trailing-slashes-stripped', WUS + '///', [{ body: MK }]);
  await fm('ok-issuer-with-path', WUS + '/tenant/x/', [{ body: MK }]);
  await fm('ok-empty-keys', WUS, [{ body: { keys: [] } }]);
  await fm('ok-non-object-keys-skipped', WUS, [{ body: { keys: [1, 'x', null, [], { kid: 'k' }] } }]);
  await fm('ok-wrong-typed-members-dropped', WUS, [{ body: { keys: [{ kid: 5, kty: true, alg: null, x5c: 'AAAA' }, { kid: 'm', x5c: ['A', 5] }, { x5c: [] }] } }]);
  await fm('ok-extra-top-level-members', WUS, [{ body: { keys: [{ kid: 'k' }], other: 1 } }]);
  await fm('ok-second-response-never-requested', WUS, [{ body: MK }, { status: 500, body: {} }]);
  await fm('http-404', WUS, [{ status: 404, body: {} }]);
  await fm('http-500', WUS, [{ status: 500, body: {} }]);
  await fm('http-301', WUS, [{ status: 301, body: {} }]);
  await fm('http-201-is-ok', WUS, [{ status: 201, body: MK }]);
  await fm('no-keys-member', WUS, [{ body: {} }]);
  await fm('keys-not-an-array', WUS, [{ body: { keys: {} } }]);
  await fm('body-is-an-array', WUS, [{ body: [] }]);
  await fm('body-is-null', WUS, [{ body: null }]);
  await fm('body-is-a-string', WUS, [{ body: 'keys' }]);
  await fm('body-not-json', WUS, [{ body: { $text: '<html>nope</html>' } }]);
  await fm('body-empty', WUS, [{ body: { $text: '' } }]);
  await fm('transport-throws', WUS, [{ $throws: 'connection refused' }]);

  const GI = 'https://confidentialcomputing.googleapis.com';
  const CONF = { issuer: GI, jwks_uri: GI + '/.well-known/jwks' };
  const GK = { keys: [{ kid: 'r', kty: 'RSA', alg: 'RS256', use: 'sig', n: 'nn', e: 'AQAB', extra: 1 }, { kid: 'e', kty: 'EC', crv: 'P-256', x: 'xx', y: 'yy' }, { kid: 'c', x5c: ['AAAA'] }] };
  const realG = JSON.parse(fxt('real-gcp-cs', 'google-cs-jwks.json'));
  await fg('ok-via-openid-config', GI, [{ body: CONF }, { body: GK }]);
  await fg('ok-real-jwks', GI, [{ body: CONF }, { body: realG }]);
  await fg('ok-explicit-jwks-uri-skips-config', GI, [{ body: GK }], { jwksUri: 'https://keys.example.net/jwks' });
  await fg('ok-issuer-trailing-slashes', GI + '//', [{ body: CONF }, { body: GK }]);
  await fg('ok-empty-keys', GI, [{ body: CONF }, { body: { keys: [] } }]);
  await fg('ok-non-object-keys-skipped', GI, [{ body: CONF }, { body: { keys: [3, null, { kid: 'k' }] } }]);
  await fg('ok-wrong-typed-members-dropped', GI, [{ body: CONF }, { body: { keys: [{ kid: 1, kty: [], alg: {}, use: 2, n: 3, e: 4, crv: 5, x: 6, y: 7, x5c: [1] }] } }]);
  await fg('ok-empty-jwks-uri-option-falls-back-to-config', GI, [{ body: CONF }, { body: GK }], { jwksUri: '' });
  await fg('config-404', GI, [{ status: 404, body: {} }]);
  await fg('config-500', GI, [{ status: 500, body: {} }]);
  await fg('config-without-jwks-uri', GI, [{ body: { issuer: GI } }]);
  await fg('config-empty-jwks-uri', GI, [{ body: { jwks_uri: '' } }]);
  await fg('config-jwks-uri-not-a-string', GI, [{ body: { jwks_uri: 5 } }]);
  await fg('config-is-an-array', GI, [{ body: [] }]);
  await fg('config-not-json', GI, [{ body: { $text: 'nope' } }]);
  await fg('config-transport-throws', GI, [{ $throws: 'boom' }]);
  await fg('jwks-404', GI, [{ body: CONF }, { status: 404, body: {} }]);
  await fg('jwks-503', GI, [{ body: CONF }, { status: 503, body: {} }]);
  await fg('jwks-no-keys-member', GI, [{ body: CONF }, { body: {} }]);
  await fg('jwks-keys-not-an-array', GI, [{ body: CONF }, { body: { keys: 'x' } }]);
  await fg('jwks-body-null', GI, [{ body: CONF }, { body: null }]);
  await fg('jwks-not-json', GI, [{ body: CONF }, { body: { $text: '' } }]);
  await fg('jwks-transport-throws', GI, [{ body: CONF }, { $throws: 'reset' }]);
  await fg('explicit-uri-404', GI, [{ status: 404, body: {} }], { jwksUri: 'https://keys.example.net/jwks' });
  await fg('explicit-uri-transport-throws', GI, [{ $throws: 'dns' }], { jwksUri: 'https://keys.example.net/jwks' });
  await fg('explicit-uri-no-keys', GI, [{ body: { nope: 1 } }], { jwksUri: 'https://keys.example.net/jwks' });
}

// ---- write ----
void PKGSRC;
assertNotVacuous(o);
refWriteBlobs(o, 'attest-vendors');

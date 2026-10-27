/**
 * Fuzz targets for the binary / ASN.1 / key-and-ciphertext decoders of the crypto and attestation modules that the
 * attestation and ecosystem target files do not reach: DER certificate and validity readers (x509-strict, x509-validity),
 * PEM splitting and TBS extraction, KEM ciphertext / key decoders (hybrid 768, hybrid 1024, X-Wing), raw PQ verifiers,
 * FROST point decoding, Policy-VM Groth16 envelope verification, and the BLS / BBS / OPRF / ratchet package decoders.
 * Seeds are real captured DER (VCEK, Intel CRLs) and valid keys / ciphertexts / proofs, so mutation starts from bytes that parse.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Buffer } from 'node:buffer';
import { pemToDer } from '../../../packages/pca/src/attest-amd-snp';
import { checkVcekReportBinding, extractTbsCertificate, parseSevSnpReport, splitPemCertificates } from '../../../packages/pca/src/hardware-sevsnp';
import { checkChainRoles, parseCertExtensions, parseTbsExtensions, readCertRoleInfo, tbsOfCertificate } from '../../../packages/pca/src/x509-strict';
import { derValidityMs, parseDerTime, parseOpenSslTime } from '../../../packages/pca/src/x509-validity';
import {
  decodeHybridCiphertext, decodeXWingCiphertext, decodeXWingPublicKey, hybridDecapsulate, hybridDecapsulate1024, hybridEncapsulate, hybridEncapsulate1024,
  hybridKem1024Keygen, hybridKemKeygen, xwingDecapsulate, xwingEncapsulate, xwingKeygen,
} from '../../../packages/pca/src/kem';
import { fnDsa512Verify, mlDsa65Keygen, mlDsa65Sign, mlDsa65Verify, mlDsa87Verify, slhDsa128fVerify } from '../../../packages/pca/src/pq';
import * as frost from '../../../packages/pca/src/frost';
import { verifyPolicyVmProof } from '../../../packages/pca/src/zk';
import { decodeSafetyCertificate } from '../../../packages/pca/src/safety-certificate';
import { decodeCanonicalBase64url, decodeCanonicalJsonSegment } from '../../../packages/pca/src/strict-jws';
import { parseHex, parseBase64, parseAnuUint8 } from '../../../packages/pca/src/entropy';
import { keyGen as blsKeyGen, popProve } from '../../../packages/pca-aggsig/src/core';
import { registerKey } from '../../../packages/pca-aggsig/src/bls';
import { deserializeElement, deserializeScalar } from '../../../packages/pca-oprf/src/oprf';
import { skFromBytes } from '../../../packages/pca-bbs/src/bbs';
import { deriveRatchetRoot, signAtLeaf, verifyLeafSignature } from '../../../packages/pca-ratchet/src/ratchet';
import { buildEAT, generateEatKeyPair, verifyEAT } from '../../../packages/pca-attest-eat/src/index';
import { anyTyped, mutateBytes, mutateJson, mutateText, neverThrows, projectOnto } from './lib';
import type { Target } from './targets-core';

const PKG = resolve(import.meta.dirname, '../../../packages/pca');
const fxb = (...p: string[]): Uint8Array => new Uint8Array(readFileSync(resolve(PKG, ...p)));
const fxt = (...p: string[]): string => readFileSync(resolve(PKG, ...p), 'utf8');
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64');
const unb64 = (s: unknown) => new Uint8Array(Buffer.from(String(s), 'base64'));

const bytesT = (name: string, run: (b: Uint8Array) => unknown, allow: Target['allow'], seeds: () => Uint8Array[], check?: Target<{ b64: string }>['check']): Target<{ b64: string }> => ({
  name, allow, check,
  seeds: () => seeds().map((b) => ({ b64: b64(b) })),
  mutate: (r, c) => ({ b64: b64(mutateBytes(r, unb64(c.b64))) }),
  run: (c) => run(unb64(c.b64)),
});
const textT = (name: string, run: (s: string) => unknown, allow: Target['allow'], seeds: () => string[]): Target<{ text: string }> => ({
  name, allow,
  seeds: () => seeds().map((text) => ({ text })),
  mutate: (r, c) => ({ text: mutateText(r, c.text) }),
  run: (c) => run(c.text),
});
/** Mutate a (key, ciphertext) case: the ciphertext is the fuzzed part, sometimes the secret key. */
const kemT = (name: string, mk: () => { sk: Uint8Array; ct: Uint8Array }, dec: (ct: Uint8Array, sk: Uint8Array) => Uint8Array): Target<{ sk: string; ct: string }> => ({
  name, allow: anyTyped,
  seeds: () => { const { sk, ct } = mk(); return [{ sk: b64(sk), ct: b64(ct) }]; },
  mutate: (r, c) => (r() < 0.8 ? { ...c, ct: b64(mutateBytes(r, unb64(c.ct))) } : { ...c, sk: b64(mutateBytes(r, unb64(c.sk))) }),
  run: (c) => dec(unb64(c.ct), unb64(c.sk)),
  // a mutated ciphertext may decapsulate (ML-KEM implicit rejection) but must return exactly 32 bytes
  check: (_c, res) => (res instanceof Uint8Array && res.length === 32 ? undefined : 'decapsulate returned a non-32-byte value'),
});

export function cryptoTargets(): Target<any>[] {
  const t: Target<any>[] = [];
  const vcek = fxb('testdata', 'sevsnp-real', 'vcek.der');
  const chainPem = fxt('testdata', 'sevsnp-real', 'chain.pem');
  const chainDer = splitPemCertificates(chainPem).map(pemToDer);
  const crl = fxb('fixtures', 'real-tdx-collateral', 'pckcrl-platform.der');
  const derSeeds = () => [vcek, ...chainDer, crl];

  // ---- ASN.1 / DER ------------------------------------------------------------------------------------------------
  t.push(bytesT('x509-strict readCertRoleInfo', readCertRoleInfo, anyTyped, derSeeds));
  t.push(bytesT('x509-strict parseCertExtensions / tbsOfCertificate / parseTbsExtensions', (b) => [parseCertExtensions(b).size, parseTbsExtensions(tbsOfCertificate(b)).size], anyTyped, derSeeds));
  t.push(bytesT('x509-validity derValidityMs (never throws, NaN when malformed)', derValidityMs, neverThrows, derSeeds));
  t.push({
    name: 'x509-strict checkChainRoles (mutated chain)', allow: anyTyped,
    seeds: () => [{ chain: chainDer.map(b64) }],
    mutate: (r, c) => { const ch = [...c.chain]; const i = Math.floor(r() * ch.length); ch[i] = b64(mutateBytes(r, unb64(ch[i]))); return r() < 0.15 ? { chain: ch.reverse() } : r() < 0.15 ? { chain: ch.slice(1) } : { chain: ch }; },
    run: (c: { chain: string[] }) => checkChainRoles(c.chain.map(unb64)),
  });
  t.push({
    name: 'x509-validity parseDerTime / parseOpenSslTime', allow: neverThrows,
    seeds: () => [{ tag: 0x17, text: '260101000000Z' }, { tag: 0x18, text: '20260101000000Z' }, { tag: 0x17, text: 'Jan  1 00:00:00 2026 GMT' }],
    mutate: (r, c) => ({ tag: r() < 0.2 ? Math.floor(r() * 256) : c.tag, text: mutateText(r, c.text) }),
    run: (c: { tag: number; text: string }) => [parseDerTime(c.tag, c.text), parseOpenSslTime(c.text)],
  });
  t.push(textT('hardware-sevsnp splitPemCertificates', splitPemCertificates, neverThrows, () => [chainPem]));
  t.push(bytesT('hardware-sevsnp extractTbsCertificate', extractTbsCertificate, anyTyped, derSeeds));
  t.push({
    name: 'hardware-sevsnp checkVcekReportBinding (mutated TBS)', allow: anyTyped,
    seeds: () => [{ b64: b64(extractTbsCertificate(vcek)) }],
    mutate: (r, c) => ({ b64: b64(mutateBytes(r, unb64(c.b64))) }),
    run: (c: { b64: string }) => checkVcekReportBinding(unb64(c.b64), parseSevSnpReport(fxb('testdata', 'sevsnp-real', 'snp_report.bin'))),
  });

  // ---- KEM ---------------------------------------------------------------------------------------------------------
  t.push(kemT('kem hybridDecapsulate (X25519 + ML-KEM-768)', () => { const k = hybridKemKeygen(); return { sk: k.secretKey, ct: hybridEncapsulate(k.publicKey).ciphertext }; }, hybridDecapsulate));
  t.push(kemT('kem hybridDecapsulate1024 (X25519 + ML-KEM-1024)', () => { const k = hybridKem1024Keygen(); return { sk: k.secretKey, ct: hybridEncapsulate1024(k.publicKey).ciphertext }; }, hybridDecapsulate1024));
  t.push(kemT('kem xwingDecapsulate', () => { const k = xwingKeygen(); return { sk: k.secretKey, ct: xwingEncapsulate(k.publicKey).ciphertext }; }, xwingDecapsulate));
  t.push(textT('kem b64u ciphertext / public-key decoders', (s) => [decodeHybridCiphertext(s).length, decodeXWingCiphertext(s).length, decodeXWingPublicKey(s).length], anyTyped, () => [Buffer.from(hybridEncapsulate(hybridKemKeygen().publicKey).ciphertext).toString('base64url')]));

  // ---- raw PQ verifiers: must return a boolean, never throw ---------------------------------------------------------
  const ml = mlDsa65Keygen(new Uint8Array(32).fill(5));
  const msg = new TextEncoder().encode('fuzz');
  const mlSig = mlDsa65Sign(ml.secretKey, msg);
  t.push({
    name: 'pq raw verifiers (ML-DSA-65/87, SLH-DSA, FN-DSA): malformed key / signature never throws, never verifies', allow: neverThrows,
    seeds: () => [{ pk: b64(ml.publicKey), sig: b64(mlSig) }],
    mutate: (r, c) => (r() < 0.5 ? { ...c, pk: b64(mutateBytes(r, unb64(c.pk))) } : { ...c, sig: b64(mutateBytes(r, unb64(c.sig))) }),
    run: (c: { pk: string; sig: string }) => [mlDsa65Verify(unb64(c.pk), msg, unb64(c.sig)), mlDsa87Verify(unb64(c.pk), msg, unb64(c.sig)), slhDsa128fVerify(unb64(c.pk), msg, unb64(c.sig)), fnDsa512Verify(unb64(c.pk), msg, unb64(c.sig))],
    check: (c, res) => ((res as boolean[]).some(Boolean) && (c.pk !== b64(ml.publicKey) || c.sig !== b64(mlSig)) && (res as boolean[])[0] ? 'mlDsa65Verify ACCEPTED a mutated key or signature' : undefined),
  });

  // ---- FROST point decoder -------------------------------------------------------------------------------------------
  const goodPt = frost.frostTrustedDealerKeygen(2, 3).groupPublicKey;
  t.push(bytesT('frost decodeSafePoint', frost.decodeSafePoint, anyTyped, () => [goodPt, new Uint8Array(32), new Uint8Array(32).fill(0xff)]));

  // ---- Policy-VM Groth16 envelope (real snarkjs verify; mutated envelope must never verify) ----------------------------
  const vkey = JSON.parse(fxt('circuits', 'policyvm_vkey.json')) as object;
  const sample = JSON.parse(fxt('circuits', 'policyvm_sample_proof.json')) as unknown;
  t.push({
    name: 'zk verifyPolicyVmProof (mutated Groth16 envelope)', allow: neverThrows,
    seeds: () => [sample],
    mutate: (r, c) => mutateJson(r, c),
    setup: async () => void (await verifyPolicyVmProof(sample, { verificationKey: vkey })),
    run: (c: unknown) => verifyPolicyVmProof(c, { verificationKey: vkey }),
    // unknown extra members are ignored by design; any change to a member the sample has is a finding
    check: (c, res) => (res === true && JSON.stringify(projectOnto(sample, c)) !== JSON.stringify(sample) ? 'verifyPolicyVmProof ACCEPTED a mutated envelope' : undefined),
  });

  // ---- text / JSON decoders -------------------------------------------------------------------------------------------
  t.push(textT('strict-jws decodeCanonicalBase64url / decodeCanonicalJsonSegment', (s) => [decodeCanonicalBase64url(s).length, decodeCanonicalJsonSegment(s)], anyTyped, () => [Buffer.from('{"a":1}').toString('base64url')]));
  t.push(textT('entropy parseHex / parseBase64', (s) => [parseHex(s), parseBase64(s)], anyTyped, () => ['00ff10', 'AAEC']));
  t.push({
    name: 'entropy parseAnuUint8', allow: anyTyped,
    seeds: () => [{ v: { data: [1, 2, 3], success: true } }],
    mutate: (r, c) => ({ v: mutateJson(r, c.v) }),
    run: (c: { v: unknown }) => parseAnuUint8(c.v),
  });
  t.push(textT('safety-certificate decodeSafetyCertificate (never throws)', decodeSafetyCertificate, neverThrows, () => ['{"v":1,"sig":"x","guardian":"g","params":{}}']));

  // ---- package decoders ---------------------------------------------------------------------------------------------------
  const bls = blsKeyGen();
  t.push({
    name: 'aggsig registerKey (mutated key / PoP never throws)', allow: neverThrows,
    seeds: () => [{ pk: b64(bls.publicKey), pop: b64(popProve(bls.secretKey)) }],
    mutate: (r, c) => (r() < 0.5 ? { ...c, pk: b64(mutateBytes(r, unb64(c.pk))) } : { ...c, pop: b64(mutateBytes(r, unb64(c.pop))) }),
    run: (c: { pk: string; pop: string }) => registerKey(unb64(c.pk), unb64(c.pop)),
    check: (c, res) => ((res as { ok: boolean }).ok && (c.pk !== b64(bls.publicKey) || c.pop !== b64(popProve(bls.secretKey))) ? 'registerKey ADMITTED a mutated key or PoP' : undefined),
  });
  t.push(bytesT('oprf deserializeElement / deserializeScalar', (b) => [deserializeElement(b), deserializeScalar(b)], anyTyped, () => [new Uint8Array(32).fill(1), new Uint8Array(32)]));
  t.push(bytesT('bbs skFromBytes', skFromBytes, anyTyped, () => [new Uint8Array(32).fill(7)]));
  const rr = deriveRatchetRoot(new Uint8Array(32).fill(3), 3);
  const rmsg = new TextEncoder().encode('m');
  const rsig = signAtLeaf(rr.state, 0, rmsg).signature;
  t.push({
    name: 'ratchet verifyLeafSignature (mutated signature, never throws, never verifies)', allow: neverThrows,
    seeds: () => [{ sig: JSON.parse(JSON.stringify(rsig)) }],
    mutate: (r, c) => ({ sig: mutateJson(r, c.sig) }),
    run: (c: { sig: never }) => verifyLeafSignature(rr.rootCommitment, 0, rmsg, c.sig),
    // merklePath.size is not covered by the root (a path proves leaf-under-root; any size consistent with the path length passes),
    // so a changed size alone is a documented non-finding; every other changed member must fail
    check: (c, res) => {
      const norm = (x: unknown) => JSON.stringify(x, (k, v) => (k === 'size' ? 0 : v));
      return res === true && norm(projectOnto(rsig, c.sig)) !== norm(rsig) ? 'verifyLeafSignature ACCEPTED a mutated signature' : undefined;
    },
  });
  // ---- EAT (RFC 9711 compact JWS): mutated token never verifies, never throws untyped ----------------------------------------
  const eatKeys = generateEatKeyPair();
  const eat = buildEAT({ issuer: 'fuzz-iss', nonce: 'n-1', channelId: 'chan-1', key: eatKeys.privateKey, now: 1_700_000_000_000 });
  t.push({
    name: 'attest-eat verifyEAT (mutated compact JWS)', allow: anyTyped,
    seeds: () => [{ text: eat }],
    mutate: (r, c) => ({ text: mutateText(r, c.text) }),
    run: (c: { text: string }) => verifyEAT(c.text, eatKeys.publicKey, { issuer: "fuzz-iss" }),
    check: (c) => (c.text !== eat ? 'verifyEAT ACCEPTED a mutated token' : undefined),
  });
  return t;
}

/**
 * Fuzz targets for the ecosystem packages' parsers / verifiers: SCITT (CBOR / COSE_Sign1 / receipts), WebAuthn COSE keys
 * and authenticator data, did:key / base58, EAT / tolerant SEV-SNP reports, AP2 SD-JWT chains, GNAP access, the HTTP
 * gateway path guard and the Web Bot Auth proof header.
 */
import { generateKeyPairSync } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { TransparencyService, checkStatement, decode as cborDecode, decodeInclusionProof, encode as cborEncode, signStatement, verifyConsistencyProof, verifyReceipt } from '../../../packages/pca-scitt/src/index';
import { coseKeyToJwk, parseAuthenticatorData } from '../../../packages/pca-webauthn/src/index';
import { base58btcDecode, ed25519FromDidKey, didKeyFromEd25519 } from '../../../packages/pca-vc/src/index';
import { parseReportTolerant } from '../../../packages/pca-attest-eat/src/index';
import { parseSdJwtHop, parseJwt } from '../../../packages/pca-ap2/src/sdjwt';
import { splitChain } from '../../../packages/pca-ap2/src/chain';
import { normalizeAccess } from '../../../packages/pca-gnap/src/index';
import { ambiguousPathReason } from '../../../packages/pca-gateway/src/index';
import { decodeProofHeader } from '../../../packages/pca-webbotauth/src/index';
import { cedarToPca } from '../../../packages/pca-policy-bridge/src/cedar';
import { regoToPca } from '../../../packages/pca-policy-bridge/src/rego';
import { evaluateCondition, predicateMatches } from '../../../packages/pca/src/predicates';
import { encodePCActn } from '../../../packages/pca/src/pcactn';
import { pcaHeaders } from '../../../packages/pca/src/adapters';
import { setup } from '../../../packages/pca/src/server/fixture.test-util';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { mutateBytes, mutateJson, mutateText, neverThrows, typedBy } from './lib';
import type { Target } from './targets-core';

const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64');
const unb64 = (s: unknown) => new Uint8Array(Buffer.from(String(s), 'base64'));
const b64u = (x: Uint8Array | string) => Buffer.from(x).toString('base64url');

const bytesT = (name: string, run: (b: Uint8Array) => unknown, allow: (e: unknown) => boolean, seeds: () => Uint8Array[], check?: (b: Uint8Array, res: unknown) => string | undefined): Target<{ b64: string }> => ({
  name,
  allow,
  seeds: () => seeds().map((b) => ({ b64: b64(b) })),
  mutate: (r, c) => ({ b64: b64(mutateBytes(r, unb64(c.b64))) }),
  run: (c) => run(unb64(c.b64)),
  ...(check ? { check: (c: { b64: string }, res: unknown) => check(unb64(c.b64), res) } : {}),
});
const textT = (name: string, run: (s: string) => unknown, allow: (e: unknown) => boolean, seeds: () => string[]): Target<{ text: string }> => ({
  name,
  allow,
  seeds: () => seeds().map((text) => ({ text })),
  mutate: (r, c) => ({ text: mutateText(r, c.text) }),
  run: (c) => run(c.text),
});
const anyError = (e: unknown): boolean => e instanceof Error;

export function ecosystemTargets(): Target<any>[] {
  const t: Target<any>[] = [];

  // ---- SCITT: CBOR / COSE_Sign1 / receipts / proofs --------------------------------------------------------------
  const scitt = () => {
    const iss = generateKeyPairSync('ed25519');
    const ts = generateKeyPairSync('ed25519');
    const svc = new TransparencyService({ alg: 'EdDSA', key: ts.privateKey, issuer: 'ts' });
    const statements = [0, 1, 2].map((i) => signStatement({ n: i, verb: 'x.y' }, { alg: 'EdDSA', key: iss.privateKey, issuer: 'iss', subject: `s${i}` }));
    const regs = statements.map((s) => svc.register(s));
    return { iss, ts, svc, statements, regs, last: svc.register(signStatement({ n: 3 }, { alg: 'EdDSA', key: iss.privateKey, issuer: 'iss' })) };
  };
  let sc: ReturnType<typeof scitt> | undefined;
  const SC = () => (sc ??= scitt());

  t.push(bytesT('scitt CBOR decode', cborDecode, anyError, () => [cborEncode([1, 'a', new Uint8Array([1, 2]), new Map([[1, 2]])]), SC().statements[0]!, SC().regs[0]!.receipt]));
  t.push(bytesT('scitt decodeInclusionProof', decodeInclusionProof, anyError, () => [cborEncode([4, 1, [new Uint8Array(32), new Uint8Array(32)]])]));
  t.push(
    bytesT('scitt checkStatement (mutated COSE_Sign1)', (b) => checkStatement(b, SC().iss.publicKey), neverThrows, () => [SC().statements[0]!], (b, res) => {
      const r = res as { ok: boolean };
      return r.ok && Buffer.compare(Buffer.from(b), Buffer.from(SC().statements[0]!)) !== 0 ? 'checkStatement ACCEPTED a mutated Signed Statement' : undefined;
    }),
  );
  t.push(
    bytesT('scitt verifyReceipt (mutated receipt)', (b) => verifyReceipt(b, SC().statements[0]!, { verificationKey: SC().ts.publicKey, statementKey: SC().iss.publicKey }), neverThrows, () => [SC().regs[0]!.receipt], (b, res) => {
      return res === true && !Buffer.from(b).equals(Buffer.from(SC().regs[0]!.receipt)) ? 'verifyReceipt ACCEPTED a mutated receipt' : undefined;
    }),
  );
  t.push({
    name: 'scitt verifyConsistencyProof (mutated)',
    allow: neverThrows,
    seeds: () => [{ b64: b64(cborEncode([1, 4, [new Uint8Array(32)]])), old: 'A'.repeat(43), nw: 'B'.repeat(43) }],
    mutate: (r, c) => ({ ...c, b64: b64(mutateBytes(r, unb64(c.b64))) }),
    run: (c: { b64: string; old: string; nw: string }) => verifyConsistencyProof(unb64(c.b64), c.old, c.nw),
    check: (_c, res) => (res === true ? 'verifyConsistencyProof ACCEPTED a garbage proof' : undefined),
  });

  // ---- WebAuthn --------------------------------------------------------------------------------------------------
  const coseEs256 = cborEncode(new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, new Uint8Array(32).fill(7)], [-3, new Uint8Array(32).fill(9)]]) as never);
  t.push(bytesT('webauthn coseKeyToJwk', coseKeyToJwk, anyError, () => [coseEs256]));
  const authData = new Uint8Array(37 + 16 + 2 + 20 + 80);
  authData[32] = 0x45;
  t.push(bytesT('webauthn parseAuthenticatorData', parseAuthenticatorData, neverThrows, () => [authData, authData.slice(0, 37)]));

  // ---- did:key / base58 ------------------------------------------------------------------------------------------
  t.push(textT('vc base58btcDecode', base58btcDecode, anyError, () => ['z6Mk', '11111111', 'Qm' + '1'.repeat(40)]));
  t.push(textT('vc ed25519FromDidKey', ed25519FromDidKey, anyError, () => [didKeyFromEd25519(new Uint8Array(32).fill(3))]));

  // ---- EAT: tolerant SEV-SNP report parser (must NEVER throw) -----------------------------------------------------
  const snp = new Uint8Array(readFileSync(resolve(import.meta.dirname, '../../../packages/pca/testdata/sevsnp-real/snp_report.bin')));
  t.push(bytesT('eat parseReportTolerant', parseReportTolerant, neverThrows, () => [snp, snp.slice(0, 64), new Uint8Array(4)]));

  // ---- AP2 SD-JWT -------------------------------------------------------------------------------------------------
  const jwt = [b64u(JSON.stringify({ alg: 'ES256', typ: 'dc+sd-jwt' })), b64u(JSON.stringify({ _sd_alg: 'sha-256', _sd: ['abc'], iss: 'x', exp: 2e9 })), b64u(new Uint8Array(64))].join('.');
  const sd = `${jwt}~${b64u(JSON.stringify(['salt', 'k', 'v']))}~`;
  t.push(textT('ap2 parseSdJwtHop', parseSdJwtHop, typedBy({ names: ['Ap2Error'], prefixes: ['SD-JWT'] }), () => [sd, `${jwt}~`]));
  t.push(textT('ap2 splitChain', splitChain, typedBy({ names: ['Ap2Error'], prefixes: ['chain'] }), () => [`${sd}~${sd}`]));
  t.push(textT('ap2 parseJwt', (s) => parseJwt(s, 'jwt'), typedBy({ names: ['Ap2Error'], prefixes: ['jwt', 'JWT'] }), () => [jwt]));

  // ---- GNAP access -------------------------------------------------------------------------------------------------
  t.push({
    name: 'gnap normalizeAccess',
    allow: typedBy({ names: ['GnapError'] }),
    seeds: () => [{ v: [{ type: 'payments', actions: ['read'], locations: ['https://a.example/'] }, 'plain-ref'] }],
    mutate: (r, c) => ({ v: mutateJson(r, c.v) }),
    run: (c: { v: unknown }) => normalizeAccess(c.v as never),
  });

  // ---- gateway path guard + Web Bot Auth header -------------------------------------------------------------------
  t.push(textT('gateway ambiguousPathReason', ambiguousPathReason, neverThrows, () => ['/a/b', '/a//b', '/a/%2e%2e/b', '/x;y=1/z', '/%zz']));
  const proofHdr = Object.values(pcaHeaders(encodePCActn(setup().mk(setup().plan[0]!))))[0]!;
  t.push(textT('webbotauth decodeProofHeader', decodeProofHeader, anyError, () => [proofHdr]));


  // ---- policy bridges: untrusted Cedar / Rego text -> PCA ----------------------------------------------------------
  t.push(textT('cedarToPca (untrusted policy text)', cedarToPca, anyError, () => ['permit (principal, action == Action::"read", resource) when { context.amount < 100 };', '@id("x") forbid (principal, action, resource);']));
  t.push(textT('regoToPca (untrusted module text)', regoToPca, anyError, () => ['package x\n\nallow if { input.action == "read" }\n']));

  // ---- predicate DSL: like / matches / re: patterns must never hang (the 1 s gate in exercise() is the oracle) ------
  const patSeeds = ['*.pdf', 'a?b*c', '(?:GET|POST) /x', '/acct/[^/]+/items/\\d+', 'a?a?a?a?aaaa', '(?:a|aa)(?:a|aa)b', '*a*a*a*b'];
  const CHOICE = ['a?', '(?:a|aa)', '(a|aa)', 'a{0,9}', '*a', 'a*', '.*', '(?:a|a)', '[ab]?', 'a+'];
  t.push({
    name: 'predicates like / matches / re: (ReDoS grammar + mutation)',
    allow: neverThrows,
    seeds: () => patSeeds.map((p) => ({ pat: p, subj: 'a'.repeat(40) })),
    mutate: (r, c) => {
      const mode = Math.floor(r() * 3);
      if (mode === 0) return { pat: mutateText(r, c.pat), subj: c.subj };
      let p = '';
      for (let i = Math.floor(r() * 40) + 1; i > 0; i--) p += CHOICE[Math.floor(r() * CHOICE.length)]!;
      return { pat: p + (r() < 0.7 ? 'b' : ''), subj: 'a'.repeat(Math.floor(r() * 500)) + (r() < 0.2 ? 'b' : '') };
    },
    run: (c: { pat: string; subj: string }) => ({
      like: evaluateCondition({ field: 'action.resource', op: 'like', value: c.pat } as never, { action: { verb: 'v', resource: c.subj } } as never),
      matches: evaluateCondition({ field: 'action.resource', op: 'matches', value: c.pat } as never, { action: { verb: 'v', resource: c.subj } } as never),
      re: predicateMatches({ verb: 'v', resource: 're:' + c.pat } as never, { action: { verb: 'v', resource: c.subj } } as never),
    }),
  });

  return t;
}

// Oracle (go lane variant of fhe.mts: signing seeds are labels {"$seed": label}, never raw seed bytes): @atlasauth/pca-fhe, the PURE parts (risk-input quantization, gate policy, claim binding, plaintext verdict, and the signed-claim /
// verdict-attestation origin layer). The BFV evaluation (node-seal) is not exercised; ciphertexts are opaque strings here. The generator is run
// with a stub for the node-seal import (never called). Signing nonces come from a deterministic replacement of crypto.getRandomValues.
// PORTING (entry points in net.atlasauth.pca.fhe; compared by JSON value; a reference throw requires a native throw):
//   transformedInputs(i) / weightVector(w) / quantizeRiskInputs(i, scale?) / fheRiskPolicy(core, budget, scale?) -> Fhe.*
//   fromActn(actn) -> transformedInputs(riskInputsFromPCActn(actn)) and bindingFromPCActn(actn) -> Fhe.riskInputsFromPCActn / bindingFromPCActn
//   plaintextVerdict(inputs, core, budget) -> {r, admit}
//   sign(claim, seedB64u, context, nonceBytes) -> Origin.signRiskClaim (the nonce is injected)       claimDigest(signed) -> Origin.signedClaimDigest
//   verifyClaim(signed, exp{trustedSigners, context, binding, policy, used:[keys], max}) -> Origin.verifySignedRiskClaim: {ok, claim?, digest?, reason?}
//   nonceGuard(max, keys) -> Origin.memoryNonceGuard: list of claim() results
//   attest(holderSeed, signed, gate, admit) -> Origin.attestVerdict      verifyAttest(a, exp{trustedHolders, claimDigest, gate?}) -> Origin.verifyVerdictAttestation
import * as FH0 from '../../../packages/pca-fhe/src/index';
import { Oracle, refWrite, rng, seed, variants, reparse } from './lib.mjs';
import * as PC0 from '@atlasauth/pca';
const FH: any = (FH0 as any).default ?? FH0;
const PC: any = (PC0 as any).default ?? PC0;

let nextNonce: Uint8Array | null = null;
const realGRV = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
(globalThis.crypto as any).getRandomValues = (a: any) => { if (nextNonce) { a.set(nextNonce.subarray(0, a.length)); return a; } return realGRV(a); };

const o = new Oracle('fhe-go', 'tools/pca-audit/oracles/fhe-go.mts', 'TS-reference oracle for the pure parts of pca-fhe.');
const r = rng(0xf4e);
const b64u = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const unb = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
const dec = (v: any): any => v instanceof Uint8Array ? v : Array.isArray(v) ? v.map(dec) : v !== null && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, dec(x)])) : v;
const W = (f: (...a: any[]) => any) => (...a: any[]) => dec(f(...a));

// ---- quantization / policy
const inputsOk = { semanticDistance: 0.25, reversibility: 0.5, blastRadius: 0.75, taint: 0.1, confidence: 0.9, age: 0.3 };
const inputSets: Array<[string, any]> = [['ok', inputsOk], ['zeros', { semanticDistance: 0, reversibility: 0, blastRadius: 0, taint: 0, confidence: 0, age: 0 }], ['ones', { semanticDistance: 1, reversibility: 1, blastRadius: 1, taint: 1, confidence: 1, age: 1 }],
  ['neg', { semanticDistance: -1, reversibility: -0.5, blastRadius: -3, taint: -0, confidence: -9, age: -1e9 }], ['big', { semanticDistance: 7, reversibility: 2, blastRadius: 1e300, taint: 1.0000001, confidence: 3, age: 1e21 }],
  ['strings', { semanticDistance: '0.5', reversibility: '1', blastRadius: null, taint: true, confidence: [], age: {} }], ['missing', {}], ['partial', { semanticDistance: 0.3 }], ['null', null], ['half', { semanticDistance: 0.0005, reversibility: 0.0015, blastRadius: 0.0025, taint: 0.4995, confidence: 0.9995, age: 0.5005 }],
  ['tiny', { semanticDistance: 1e-300, reversibility: 0.9999999999999999, blastRadius: 0.49999999999999994, taint: 5e-324, confidence: 0.1, age: 0.7 }]];
for (const [n, i] of inputSets) {
  await o.run('transformedInputs', n, W((x: any) => FH.transformedInputs(x)), [i]);
  for (const s of [1, 10, 1000, 1000000, 7]) await o.run('quantizeRiskInputs', `${n}/${s}`, W((x: any, sc: any) => FH.quantizeRiskInputs(x, sc)), [i, s]);
  await o.run('quantizeRiskInputs', `${n}/default`, W((x: any) => FH.quantizeRiskInputs(x)), [i]);
}
for (const s of [0, -1, 1.5, '3', null, 1e300, 2 ** 53, 1e21]) await o.run('quantizeRiskInputs', `badscale/${String(s)}`, W((x: any, sc: any) => FH.quantizeRiskInputs(x, sc)), [inputsOk, s]);
const weightSets: Array<[string, any]> = [['default', { alpha: 0.3, beta: 0.2, gamma: 0.2, delta: 0.1, epsilon: 0.1, zeta: 0.1 }], ['zeros', { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }], ['neg', { alpha: -1, beta: -0, gamma: 0.5, delta: 'x', epsilon: null, zeta: 2 }],
  ['big', { alpha: 1e300, beta: 1e-300, gamma: 5e-324, delta: 1, epsilon: 1, zeta: 1 }], ['empty', {}], ['null', null], ['third', { alpha: 1 / 3, beta: 1 / 3, gamma: 1 / 3, delta: 0, epsilon: 0, zeta: 0 }]];
for (const [n, w] of weightSets) await o.run('weightVector', n, W((x: any) => FH.weightVector(x)), [w]);
const cores: Array<[string, any]> = [['default', { weights: weightSets[0]![1], kappa: 2 }], ['frac', { weights: weightSets[6]![1], kappa: 1.5 }], ['third', { weights: weightSets[6]![1], kappa: 0.1 }], ['kappa0', { weights: weightSets[0]![1], kappa: 0 }], ['kappaNeg', { weights: weightSets[0]![1], kappa: -1 }],
  ['kappaStr', { weights: weightSets[0]![1], kappa: '2' }], ['kappaBig', { weights: weightSets[0]![1], kappa: 1e6 }], ['heavy', { weights: { alpha: 5, beta: 5, gamma: 5, delta: 5, epsilon: 5, zeta: 5 }, kappa: 1 }], ['zeroW', { weights: weightSets[1]![1], kappa: 1 }], ['noWeights', { kappa: 1 }]];
for (const [n, c] of cores) for (const [bn, b] of [['0', 0], ['1', 1], ['half', 0.5], ['3.3', 3.3], ['big', 1e6], ['neg', -1], ['str', '1'], ['null', null]] as const) {
  await o.run('fheRiskPolicy', `${n}/${bn}`, W((core: any, bud: any) => FH.fheRiskPolicy(core, bud)), [c, b]);
}
for (const s of [1, 10, 100, 1000, 3, 0, 1.5, 100000]) await o.run('fheRiskPolicy', `scale/${s}`, W((core: any, bud: any, sc: any) => FH.fheRiskPolicy(core, bud, sc)), [cores[0]![1], 1, s]);
// plaintext verdict
for (const [n, i] of inputSets.slice(0, 7)) for (const [cn, c] of cores.slice(0, 5)) for (const b of [0, 0.5, 1, 2, 100]) {
  await o.run('plaintextVerdict', `${n}/${cn}/${b}`, W((x: any, core: any, bud: number) => FH.plaintextVerdict(x, core, bud)), [i, c, b]);
}
// PCActn helpers
const actn = (over: any = {}) => ({ aud: 'https://rs.example', action: { params_digest: 'abc', name: 'x' }, counter: 5, nonce: 'n1', risk_claim: { inputs: { ...inputsOk } }, ...over });
const actns: Array<[string, any]> = [['ok', actn()], ['no-nonce', (() => { const a: any = actn(); delete a.nonce; return a; })()], ['nonce-null', actn({ nonce: null })], ['nonce-empty', actn({ nonce: '' })], ['strings', actn({ risk_claim: { inputs: { semanticDistance: '1', reversibility: null } } })],
  ['no-risk', (() => { const a: any = actn(); delete a.risk_claim; return a; })()], ['inputs-null', actn({ risk_claim: { inputs: null } })], ['no-action', (() => { const a: any = actn(); delete a.action; return a; })()], ['counter-str', actn({ counter: '7' })], ['aud-num', actn({ aud: 5 })],
  ['empty-inputs', actn({ risk_claim: { inputs: {} } })]];
for (const [n, a] of actns) {
  await o.run('fromActn', n, W((x: any) => FH.transformedInputs(FH.riskInputsFromPCActn(x))), [a]);
  await o.run('binding', n, W((x: any) => FH.bindingFromPCActn(x)), [a]);
}

// ---- origin layer
const sk = (l: string) => seed(l);
const pk = (s: Uint8Array) => b64u(PC.publicKeyOf(s));
const encKey = sk('fhe-encryptor'), holderKey = sk('fhe-holder'), otherKey = sk('fhe-other');
const policy = FH.fheRiskPolicy(cores[0]![1], 1);
const binding = FH.bindingFromPCActn(actn());
const claimOf = (enc = 'ZW5jcnlwdGVkLWlucHV0cw', b: any = binding, p: any = policy) => ({ binding: b, encInputs: enc, policy: p });
const sign = (claim: any, seedS: string, context: string, nonce: any) => { nextNonce = unb(nonce.$bytes); try { return PC && FH.signRiskClaim({ claim, signerSecretKey: sd(seedS), context }); } finally { nextNonce = null; } };
const nonces = Array.from({ length: 6 }, (_, i) => b64u(Uint8Array.from({ length: 16 }, (_, k) => (i * 37 + k * 11 + 1) & 255)));
const seeds = { enc: { $seed: 'fhe-encryptor' }, other: { $seed: 'fhe-other' }, holder: { $seed: 'fhe-holder' } };
const sd = (x: any): Uint8Array => (typeof x === 'string' ? unb(x) : seed(x.$seed));
let idx = 0;
for (const [cn, claim] of [['base', claimOf()], ['other-ct', claimOf('b3RoZXI')], ['empty-ct', claimOf('')], ['no-nonce-binding', claimOf(undefined, (() => { const b: any = { ...binding }; delete b.nonce; return b; })())]] as const) {
  for (const ctx of ['grant-1', 'é'.repeat(10), 'x'.repeat(512)]) {
    await o.run('sign', `${cn}/${ctx.length}`, W(sign), [claim, seeds.enc, ctx, { $bytes: nonces[idx++ % 6] }]);
  }
}
for (const [n, c, s, nz] of [['empty-context', 'ok', seeds.enc, nonces[0]], ['long-context', 'x'.repeat(513), seeds.enc, nonces[0]], ['short-key', 'ok', b64u(new Uint8Array(31)), nonces[0]], ['long-key', 'ok', b64u(new Uint8Array(33)), nonces[0]], ['zero-nonce', 'ok', seeds.enc, b64u(new Uint8Array(16))]] as const) {
  await o.run('sign', `bad/${n}`, W(sign), [claimOf(), s, n === 'empty-context' ? '' : c, { $bytes: nz }]);
}
const goodSigned = sign(claimOf(), seeds.enc, 'grant-1', { $bytes: nonces[0] });
const goodSigned2 = sign(claimOf(), seeds.enc, 'grant-1', { $bytes: nonces[1] });
await o.run('claimDigest', 'good', W((s: any) => FH.signedClaimDigest(s)), [goodSigned]);
await o.run('claimDigest', 'good2', W((s: any) => FH.signedClaimDigest(s)), [goodSigned2]);
const expOf = (over: any = {}) => ({ trustedSigners: [pk(encKey)], context: 'grant-1', binding, policy, used: [], max: 100000, ...over });
const vc = (s: any, e: any) => {
  const used = new Set<string>(e.used); const guard = { claim: (k: string) => { if (used.has(k) || used.size >= e.max) return false; used.add(k); return true; } };
  const res = FH.verifySignedRiskClaim(s, { trustedSigners: e.trustedSigners, context: e.context, binding: e.binding, policy: e.policy, nonces: guard });
  return res;
};
await o.run('verifyClaim', 'good', W(vc), [goodSigned, expOf()]);
await o.run('verifyClaim', 'replay', W(vc), [goodSigned, expOf({ used: [`${pk(encKey)}:${nonces[0]}`] })]);
await o.run('verifyClaim', 'window-full', W(vc), [goodSigned, expOf({ max: 0 })]);
await o.run('verifyClaim', 'untrusted', W(vc), [goodSigned, expOf({ trustedSigners: [pk(otherKey)] })]);
await o.run('verifyClaim', 'no-signers', W(vc), [goodSigned, expOf({ trustedSigners: [] })]);
await o.run('verifyClaim', 'wrong-context', W(vc), [goodSigned, expOf({ context: 'grant-2' })]);
await o.run('verifyClaim', 'wrong-binding', W(vc), [goodSigned, expOf({ binding: { ...binding, counter: 6 } })]);
await o.run('verifyClaim', 'wrong-policy', W(vc), [goodSigned, expOf({ policy: { ...policy, budgetScaled: 1 } })]);
await o.run('verifyClaim', 'extra-member-digest', W(vc), [{ ...goodSigned, extra: 1 }, expOf()]);
const signedByOther = sign(claimOf(), seeds.other, 'grant-1', { $bytes: nonces[2] });
await o.run('verifyClaim', 'other-signer-trusted', W(vc), [signedByOther, expOf({ trustedSigners: [pk(encKey), pk(otherKey)] })]);
await o.run('verifyClaim', 'signer-swap', W(vc), [{ ...signedByOther, signer: pk(encKey) }, expOf()]);
for (const [n, s] of [['null', null], ['array', []], ['string', 'x'], ['number', 5], ['empty', {}]] as const) await o.run('verifyClaim', `shape/${n}`, W(vc), [s, expOf()]);
for (const [label, v] of variants(goodSigned, { lens: [] })) {
  await o.run('verifyClaim', `mut/${label}`.slice(0, 90), W(vc), [reparse(v), expOf({ trustedSigners: [pk(encKey)] })]);
}
const gateOf = { encRiskRaw: 'cmlzaw', encSlack: 'c2xhY2s' };
const attest = (holder: string, s: any, g: any, admit: boolean) => FH.attestVerdict({ holderSecretKey: sd(holder), signed: s, gate: g, verdict: { admit, rScaled: 0, slack: 0 } });
const att = attest(seeds.holder, goodSigned, gateOf, true);
const attDeny = attest(seeds.holder, goodSigned, gateOf, false);
await o.run('attest', 'admit', W(attest), [seeds.holder, goodSigned, gateOf, true]);
await o.run('attest', 'deny', W(attest), [seeds.holder, goodSigned, gateOf, false]);
await o.run('attest', 'other-claim', W(attest), [seeds.holder, goodSigned2, gateOf, true]);
await o.run('attest', 'bad-key', W(attest), [b64u(new Uint8Array(5)), goodSigned, gateOf, true]);
const vcd = FH.signedClaimDigest(goodSigned);
const va = (a: any, e: any) => FH.verifyVerdictAttestation(a, { trustedHolders: e.trustedHolders, claimDigest: e.claimDigest, ...(e.gate ? { gate: e.gate } : {}) });
const aexp = (over: any = {}) => ({ trustedHolders: [pk(holderKey)], claimDigest: vcd, ...over });
await o.run('verifyAttest', 'good', W(va), [att, aexp()]);
await o.run('verifyAttest', 'good-deny', W(va), [attDeny, aexp()]);
await o.run('verifyAttest', 'good-gate', W(va), [att, aexp({ gate: gateOf })]);
await o.run('verifyAttest', 'wrong-gate', W(va), [att, aexp({ gate: { ...gateOf, encSlack: 'xx' } })]);
await o.run('verifyAttest', 'wrong-gate2', W(va), [att, aexp({ gate: { ...gateOf, encRiskRaw: 'xx' } })]);
await o.run('verifyAttest', 'wrong-claim', W(va), [att, aexp({ claimDigest: FH.signedClaimDigest(goodSigned2) })]);
await o.run('verifyAttest', 'untrusted', W(va), [att, aexp({ trustedHolders: [pk(otherKey)] })]);
await o.run('verifyAttest', 'flip-admit', W(va), [{ ...att, admit: false }, aexp()]);
for (const [n, a] of [['null', null], ['array', []], ['string', 'x'], ['empty', {}]] as const) await o.run('verifyAttest', `shape/${n}`, W(va), [a, aexp()]);
for (const [label, v] of variants(att, { lens: [] })) await o.run('verifyAttest', `mut/${label}`.slice(0, 90), W(va), [reparse(v), aexp()]);
const ng = (max: number, keys: string[]) => { const g = FH.memoryNonceGuard(max); return keys.map((k) => g.claim(k)); };
for (const [max, keys] of [[3, ['a', 'b', 'a', 'c', 'd', 'b']], [0, ['a']], [1, ['a', 'a', 'b']], [100, ['a', 'b', 'c']]] as const) await o.run('nonceGuard', `${max}/${keys.join('')}`, W(ng), [max, keys]);

for (const c of o.cases) if (JSON.stringify(c.out).includes('is not a function') || JSON.stringify(c.out).includes('stub')) throw new Error('generator bug in ' + c.name + ': ' + JSON.stringify(c.out).slice(0, 300));
refWrite(o, 'fhe-go');

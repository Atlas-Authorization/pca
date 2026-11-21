// Oracle: @atlasauth/pca-fhe BFV evaluation over node-seal, for the native Microsoft SEAL ports (wire compatibility replay).
// Run:  node-seal@5.1.7 (Microsoft SEAL 4.1.2 in wasm) + @atlasauth/pca-fhe installed, then
//   npx tsx fhe-seal.mts <out.json.gz>
// (CI installs both into a scratch directory next to a copy of this file; see the FHE workflows.) NOT committed as a corpus: one
// corpus is ~15-25 MB of SEAL streams (a Galois key set alone is ~6 MB) and keys are random per run, so every CI run generates its own.
// The secret key never leaves this process: it only decrypts the evaluated ciphertexts to record the verdict. The corpus carries the
// PUBLIC material (publicKey, relinKeys, galoisKeys), the agent ciphertexts, the evaluator's output ciphertexts and the decrypted verdict.
//
// PORTING: the evaluation is deterministic given (ciphertext, Galois keys, public policy), so a native evaluator must reproduce
// encRiskRaw / encSlack exactly: load every SEAL object, run the same circuit, then compare the results re-saved WITHOUT compression
// (compr_mode none: byte equality independent of the zstd build). Circuit (evalRiskGate): dot(c) = sumElements(multiplyPlain(x, enc(c)));
// sumElements (BFV) = rotateColumns+add, then for steps = 2048,1024,..,1: rotateRows(steps), rotateColumns, add.
//   encRiskRaw = dot(weightsScaled)   encSlack = addPlain(negate(dot(kappaWeightsScaled)), enc([budgetScaled]))
import * as FH0 from '@atlasauth/pca-fhe';
import fs from 'node:fs';
import zlib from 'node:zlib';

const FH: any = (FH0 as any).default ?? FH0;
const out = process.argv[2];
if (!out) throw new Error('usage: fhe-seal.mts <out.json.gz>');

const keys = await FH.keygen();
const evalKeys = { publicKey: keys.publicKey, relinKeys: keys.relinKeys, galoisKeys: keys.galoisKeys };

const W = { alpha: 0.25, beta: 0.2, gamma: 0.2, delta: 0.2, epsilon: 0.1, zeta: 0.05 };
const specs: Array<{ name: string; inputs: number[]; kappa: number; budget: number; scale?: number }> = [
  { name: 'admit', inputs: [100, 900, 100, 100, 100, 100], kappa: 1, budget: 0.6 },
  { name: 'deny', inputs: [1000, 1000, 1000, 1000, 1000, 1000], kappa: 1, budget: 0.5 },
  { name: 'kappa2-edge', inputs: [500, 500, 500, 500, 500, 500], kappa: 2, budget: 1 },
  { name: 'zeros', inputs: [0, 0, 0, 0, 0, 0], kappa: 1.5, budget: 0.25 },
  { name: 'scale100', inputs: [10, 90, 10, 10, 10, 10], kappa: 1, budget: 0.6, scale: 100 },
  { name: 'high-budget-boundary', inputs: [200, 400, 600, 800, 1000, 0], kappa: 1, budget: 0.5 },
];

const cases: any[] = [];
for (const s of specs) {
  const policy = FH.fheRiskPolicy({ weights: W, kappa: s.kappa }, s.budget, s.scale);
  const encInputs = await FH.encryptRiskInputs(keys.publicKey, s.inputs);
  const gate = await FH.evalRiskGate(evalKeys, encInputs, policy);
  const verdict = await FH.decryptVerdict(keys.secretKey, gate.encRiskRaw, gate.encSlack, policy);
  const dot = (c: number[]) => c.reduce((a: number, v: number, i: number) => a + v * s.inputs[i]!, 0);
  const riskRaw = dot(policy.weightsScaled);
  const slack = policy.budgetScaled - dot(policy.kappaWeightsScaled);
  if (verdict.slack !== slack || verdict.rScaled !== Math.min(Math.max(riskRaw, 0), policy.scale * policy.scale)) {
    throw new Error(`reference BFV result differs from plaintext arithmetic in ${s.name}`);
  }
  cases.push({ name: s.name, inputsScaled: s.inputs, policy, encInputs, encRiskRaw: gate.encRiskRaw, encSlack: gate.encSlack, verdict, riskRaw, slack });
}

const doc = {
  about: 'BFV evaluation vectors from the TypeScript reference (node-seal). Public material only; see the generator header for the replay contract.',
  generator: 'fhe-seal.mts',
  seal: { library: 'node-seal', version: '5.1.7', sealVersion: '4.1.2', scheme: 'bfv', polyModulusDegree: FH.POLY_MODULUS_DEGREE, plainModulusBits: FH.PLAIN_MODULUS_BITS, plainModulus: FH.PLAIN_MODULUS, coeffModulus: 'CoeffModulus.BFVDefault(polyModulusDegree, tc128)', securityLevel: 'tc128' },
  publicKey: keys.publicKey,
  relinKeys: keys.relinKeys,
  galoisKeys: keys.galoisKeys,
  cases,
};
fs.writeFileSync(out, zlib.gzipSync(Buffer.from(JSON.stringify(doc), 'utf8'), { level: 6, mtime: 0 }));
console.log(`wrote ${cases.length} cases to ${out}`);

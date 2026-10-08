/**
 * @atlasauth/pca-fhe — homomorphic evaluation of PCA's risk gate.
 *
 * WHAT THIS IS
 * ------------
 * PCA's admission decision (see `@atlasauth/pca` `risk.ts`) turns a vector of normalized risk
 * inputs into a scalar risk `r = Σ wᵢ·xᵢ` and admits a machine-only action while the trust budget
 * covers its cost `c = κ·r` (i.e. `κ·r ≤ B`). This package runs exactly that functional over
 * ENCRYPTED risk inputs: the evaluator computes the weighted sum and the admission slack
 * `budget − κ·r` homomorphically and never sees the plaintext inputs or the plaintext risk. Only
 * the authorized key holder (the policy / principal owner, who holds the secret key) decrypts the
 * verdict.
 *
 * Scheme: Microsoft SEAL (via `node-seal`), BFV — exact integer arithmetic, which fits PCA's
 * fixed-point integer risk model. CKKS (approximate reals) is deliberately NOT used: a risk gate
 * must reproduce the plaintext integer result bit-for-bit, not approximately.
 *
 * HONEST SCOPE (read this before trusting the guarantee)
 * ------------------------------------------------------
 *  - CONFIDENTIALITY, NOT INTEGRITY. BFV is IND-CPA. It hides the plaintext risk inputs (and the
 *    intermediate risk value) from the evaluator. It does NOT by itself prove the evaluator ran the
 *    agreed circuit, nor that the ciphertext encrypts the agent's true inputs. Binding the claim to
 *    a signed PCActn (see `encryptedRiskClaim`) and running the gate inside an attested evaluator
 *    (PCA's TEE path) are what add integrity; FHE alone does not.
 *  - THE VERDICT IS A SIGN-OF-SLACK DECRYPTED BY THE KEY HOLDER. We do not run a full homomorphic
 *    comparison circuit (which would also hide the admit/deny bit from the holder). The evaluator
 *    produces an encrypted `slack = budget − κ·r`; the key holder decrypts it and reads its sign.
 *    So the evaluator learns nothing; the key holder learns `r` and the verdict. That is the right
 *    trust split for PCA (the principal owning the key is entitled to the result), but it is a
 *    weaker property than a fully-blind decision and is stated plainly here rather than oversold.
 *  - LINEAR FUNCTIONAL ONLY. `riskScore` clamps `r` to [0,1]. The homomorphic path computes the
 *    linear sum and the key holder clamps on decrypt. For every policy whose weights sum to ≤ 1
 *    (the default policy sums to exactly 1) and inputs in [0,1], `r ≤ 1` always, so the clamp is a
 *    no-op and the FHE result equals `riskScore` exactly. For a policy with Σweights > 1 the
 *    plaintext would clamp `r` (and hence `cost`) before the budget check while the linear slack
 *    does not — in that regime the slack is a lower bound on the true (clamped) slack. Documented,
 *    not hidden.
 *  - NOISE BUDGET. BFV accumulates noise with multiplicative depth. This circuit has multiplicative
 *    depth 1: a single ciphertext×PLAINTEXT multiply (encrypted inputs × public weights) followed by
 *    additions (the slot sum, the negate, and the budget add). Plaintext multiplies and additions
 *    cost little noise and need no relinearization (relin is only for ciphertext×ciphertext). With
 *    polyModulusDegree 8192 the fresh noise budget is ~130+ bits and ~90 bits survive the gate — a
 *    wide margin, so decryption is exact. Deeper future circuits (e.g. homomorphic comparison) would
 *    need larger parameters or bootstrapping.
 */

import SEAL from 'node-seal';
import {
  type RiskInputs,
  type RiskPolicy,
  type RiskWeights,
  type PCActn,
  riskScore,
  cost,
} from '@atlasauth/pca';

// ---------------------------------------------------------------------------------------------
// BFV PARAMETERS (fixed and deterministic, so keys serialized under one context load under any
// freshly-built identical context without shipping the parameters).
// ---------------------------------------------------------------------------------------------

/** Ring dimension. 8192 gives 8192 batch slots and a ~130-bit fresh noise budget at 128-bit security. */
export const POLY_MODULUS_DEGREE = 8192;
/** Plain-modulus prime bit size. 30 bits ⇒ t = 1 073 692 673 (verified via PlainModulus.Batching). */
export const PLAIN_MODULUS_BITS = 30;
/**
 * The batching plain modulus `t` that `PlainModulus.Batching(8192, 30)` deterministically selects.
 * Signed BatchEncoder values must lie in (−t/2, t/2); {@link SIGNED_BOUND} is that half-range.
 */
export const PLAIN_MODULUS = 1_073_692_673;
/** |value| must be < this for signed decode to be exact. */
export const SIGNED_BOUND = Math.floor(PLAIN_MODULUS / 2); // 536 846 336
/** Default fixed-point scale S. Weights and inputs are quantized to integers at this scale. */
export const DEFAULT_SCALE = 1000;
/** Risk-input dimension (α,β,γ,δ,ε,ζ terms). */
export const RISK_DIM = 6;

// ---------------------------------------------------------------------------------------------
// Serialized wire types. Every SEAL object crosses the API boundary as a base64 string (its native
// `.save()`), so the three roles (key holder / agent / evaluator) exchange only strings + JSON.
// ---------------------------------------------------------------------------------------------

/** Full key material. The POLICY/principal owner keeps `secretKey`; the evaluator only ever gets {@link EvalKeys}. */
export interface FheKeyset {
  secretKey: string;
  publicKey: string;
  relinKeys: string;
  galoisKeys: string;
}

/** The keys an evaluator is given: NO secret key. `galoisKeys` powers the slot-sum; `publicKey`/`relinKeys` are carried for forward-compatibility (this depth-1 circuit does not consume them). */
export interface EvalKeys {
  publicKey: string;
  relinKeys: string;
  galoisKeys: string;
}

/**
 * The public, no-secret policy the gate is evaluated under. Carries the fixed-point weights already
 * baked at scale S, the κ-weighted weights (so κ·r is a second plaintext-weighted dot product rather
 * than an extra multiplicative level), and the budget bound at scale S². Safe to hand the evaluator.
 */
export interface FheRiskPolicy {
  /** Fixed-point scale S. */
  scale: number;
  /** Dimension (always {@link RISK_DIM}). */
  dim: number;
  /** round(wt(wᵢ)·S), order [alpha,beta,gamma,delta,epsilon,zeta] — matches `riskScore`'s weight clamp. */
  weightsScaled: number[];
  /** round(κ·wt(wᵢ)·S); Σ kappaWeightsScaled·X = κ·riskRaw at scale S². */
  kappaWeightsScaled: number[];
  /** round(B·S²): the budget bound `κ·r ≤ B` is checked as `budgetScaled − κ·riskRaw ≥ 0`. */
  budgetScaled: number;
  /** κ, retained for cross-checking against the plaintext `cost(r,κ)`. */
  kappa: number;
}

/** The two encrypted outputs of the gate. The evaluator produces these blind; only the key holder opens them. */
export interface EncryptedGate {
  /** Encrypts `riskRaw = Σ wᵢ·xᵢ` at scale S² (i.e. r·S²). */
  encRiskRaw: string;
  /** Encrypts `slack = B·S² − κ·riskRaw` at scale S²; sign of slack is the admit/deny bit. */
  encSlack: string;
}

/** The opened verdict. `rScaled` is r at scale S² (clamped to [0,S²] to mirror `riskScore`'s clamp01). */
export interface Verdict {
  rScaled: number;
  slack: number;
  admit: boolean;
}

// ---------------------------------------------------------------------------------------------
// Fixed-point helpers, replicated to match `risk.ts` EXACTLY (its clamp/unit/wt are not exported).
// ---------------------------------------------------------------------------------------------

const clamp01 = (x: number): number => (x < 0 ? 0 : x > 1 ? 1 : x);
/** non-finite ⇒ worst (1 for risk-increasing inputs, 0 for reversibility/confidence); else clamp to [0,1]. */
const unit = (x: number, worst: 0 | 1): number => (Number.isFinite(x) ? clamp01(x) : worst);
/** weight clamp: finite and > 0 keeps it, else 0 — identical to `risk.ts` `wt`. */
const wt = (x: number): number => (Number.isFinite(x) && x > 0 ? x : 0);

/**
 * The transformed risk-input vector `risk.ts` actually weights:
 * `[d, 1−rev, bl, taint, 1−conf, age]`, each put through `unit` with the same worst-case as `riskScore`.
 * Returns reals in [0,1]; {@link quantizeRiskInputs} scales these to integers.
 */
export function transformedInputs(i: RiskInputs): number[] {
  return [
    unit(i.semanticDistance, 1),
    1 - unit(i.reversibility, 0),
    unit(i.blastRadius, 1),
    unit(i.taint, 1),
    1 - unit(i.confidence, 0),
    unit(i.age, 1),
  ];
}

/** The weight vector `risk.ts` uses, in canonical order, with its `wt` clamp applied. */
export function weightVector(w: RiskWeights): number[] {
  return [wt(w.alpha), wt(w.beta), wt(w.gamma), wt(w.delta), wt(w.epsilon), wt(w.zeta)];
}

/**
 * Quantize risk inputs to the integer vector the agent encrypts: `round(xᵢ·S)` for each transformed
 * input, each in [0,S]. Quantization is the ONLY source of divergence from `riskScore(rawInputs)`,
 * bounded by the sum of per-term rounding (≤ RISK_DIM/2 at scale S² ⇒ ≤ RISK_DIM/(2S) in r).
 */
export function quantizeRiskInputs(i: RiskInputs, scale: number = DEFAULT_SCALE): number[] {
  if (!(Number.isInteger(scale) && scale > 0)) throw new Error('scale must be a positive integer');
  return transformedInputs(i).map((x) => Math.round(x * scale));
}

/**
 * Build the public FHE policy from a core {@link RiskPolicy} plus the current trust budget `B`.
 * Applies the SAME weight clamp as `riskScore`. Validates up-front that no scaled product can exceed
 * the signed plain-modulus range (overflow would silently wrap mod t and corrupt the verdict), with
 * the bound documented below.
 *
 * Overflow bound: with inputs Xᵢ ≤ S, `riskRaw ≤ (Σ weightsScaled)·S` and
 * `κ·riskRaw ≤ (Σ kappaWeightsScaled)·S`; `slack ∈ [−κ·riskRaw_max, budgetScaled]`. We require every
 * such magnitude to be < {@link SIGNED_BOUND} = ⌊t/2⌋.
 */
export function fheRiskPolicy(
  core: RiskPolicy,
  budget: number,
  scale: number = DEFAULT_SCALE,
): FheRiskPolicy {
  if (!(Number.isInteger(scale) && scale > 0)) throw new Error('scale must be a positive integer');
  if (!(Number.isFinite(budget) && budget >= 0)) throw new Error('budget must be finite and >= 0');
  const kappa = core.kappa;
  if (!(Number.isFinite(kappa) && kappa > 0)) throw new Error('policy.kappa must be finite and > 0');

  const w = weightVector(core.weights);
  const weightsScaled = w.map((v) => Math.round(v * scale));
  const kappaWeightsScaled = w.map((v) => Math.round(kappa * v * scale));
  const budgetScaled = Math.round(budget * scale * scale);

  const sum = (xs: number[]): number => xs.reduce((a, b) => a + b, 0);
  const maxRiskRaw = sum(weightsScaled) * scale;
  const maxKappaRiskRaw = sum(kappaWeightsScaled) * scale;
  const maxAbs = Math.max(maxRiskRaw, maxKappaRiskRaw, budgetScaled);
  if (maxAbs >= SIGNED_BOUND) {
    throw new Error(
      `policy/scale overflow the plain modulus: max |value| ${maxAbs} must be < SIGNED_BOUND ${SIGNED_BOUND}. ` +
        `Lower the scale or the weights/budget.`,
    );
  }
  return { scale, dim: RISK_DIM, weightsScaled, kappaWeightsScaled, budgetScaled, kappa };
}

// ---------------------------------------------------------------------------------------------
// SEAL context. `createFheContext` awaits the WASM module ONCE (module-level cached promise) and
// builds the fixed BFV context. Every other function creates a context, does its work, serializes,
// and disposes — so the WASM heap does not grow across calls.
// ---------------------------------------------------------------------------------------------

type SealLib = Awaited<ReturnType<typeof SEAL>>;
type SealContext = ReturnType<SealLib['Context']>;
type SealBatchEncoder = ReturnType<SealLib['BatchEncoder']>;

let sealPromise: Promise<SealLib> | null = null;
function loadSeal(): Promise<SealLib> {
  if (sealPromise === null) sealPromise = SEAL();
  return sealPromise;
}

/** A live SEAL BFV context plus the batch encoder, and the scheme/modulus facts the gate needs. */
export interface FheContext {
  seal: SealLib;
  context: SealContext;
  encoder: SealBatchEncoder;
  slotCount: number;
  /** Release the WASM-side objects this context owns. Safe to call once. */
  dispose(): void;
}

/** Build the deterministic BFV context. Awaits SEAL once; the module is reused on later calls. */
export async function createFheContext(): Promise<FheContext> {
  const seal = await loadSeal();
  const parms = seal.EncryptionParameters(seal.SchemeType.bfv);
  parms.setPolyModulusDegree(POLY_MODULUS_DEGREE);
  parms.setCoeffModulus(seal.CoeffModulus.BFVDefault(POLY_MODULUS_DEGREE, seal.SecurityLevel.tc128));
  const plainMod = seal.PlainModulus.Batching(POLY_MODULUS_DEGREE, PLAIN_MODULUS_BITS);
  parms.setPlainModulus(plainMod);
  const context = seal.Context(parms, true, seal.SecurityLevel.tc128);
  if (!context.parametersSet()) {
    context.delete();
    plainMod.delete();
    parms.delete();
    throw new Error('SEAL rejected the BFV parameters (parametersSet() === false)');
  }
  // Defense in depth: the live modulus MUST equal the documented constant the policy builder guards against.
  const liveModulus = plainMod.value;
  plainMod.delete();
  parms.delete();
  if (liveModulus !== BigInt(PLAIN_MODULUS)) {
    context.delete();
    throw new Error(`plain modulus drift: live ${liveModulus} !== documented ${PLAIN_MODULUS}`);
  }
  const encoder = seal.BatchEncoder(context);
  const slotCount = encoder.slotCount;
  return {
    seal,
    context,
    encoder,
    slotCount,
    dispose(): void {
      encoder.delete();
      context.delete();
    },
  };
}

/** Pack an integer vector into the first slots of a fresh zero-filled slot array. */
function packSlots(values: number[], slotCount: number): Int32Array {
  const arr = new Int32Array(slotCount);
  for (let k = 0; k < values.length; k++) arr[k] = values[k] ?? 0;
  return arr;
}

function requirePolicyDim(policy: FheRiskPolicy): void {
  if (policy.dim !== RISK_DIM) throw new Error(`policy.dim must be ${RISK_DIM}`);
  if (policy.weightsScaled.length !== RISK_DIM || policy.kappaWeightsScaled.length !== RISK_DIM) {
    throw new Error(`policy weight vectors must have length ${RISK_DIM}`);
  }
}

// ---------------------------------------------------------------------------------------------
// Role 1 — the KEY HOLDER (policy / principal owner): keygen. Keeps secretKey; distributes the rest.
// ---------------------------------------------------------------------------------------------

/**
 * Generate the key material. The secret key stays with the policy owner (the only party allowed to
 * learn the verdict). `publicKey` goes to agents (to encrypt); `{publicKey, relinKeys, galoisKeys}`
 * go to the evaluator (`galoisKeys` is what the slot-sum rotations need).
 */
export async function keygen(): Promise<FheKeyset> {
  const ctx = await createFheContext();
  const keygen = ctx.seal.KeyGenerator(ctx.context);
  const secretKey = keygen.secretKey();
  const publicKey = keygen.createPublicKey();
  const relinKeys = keygen.createRelinKeys();
  const galoisKeys = keygen.createGaloisKeys();
  const out: FheKeyset = {
    secretKey: secretKey.save(),
    publicKey: publicKey.save(),
    relinKeys: relinKeys.save(),
    galoisKeys: galoisKeys.save(),
  };
  secretKey.delete();
  publicKey.delete();
  relinKeys.delete();
  galoisKeys.delete();
  keygen.delete();
  ctx.dispose();
  return out;
}

// ---------------------------------------------------------------------------------------------
// Role 2 — the AGENT / CLIENT: encrypt the quantized risk inputs under the public key.
// ---------------------------------------------------------------------------------------------

/**
 * BFV-encrypt the quantized risk-input vector (`inputsScaled`, length {@link RISK_DIM}, each a
 * non-negative integer in [0,S]). Only the public key is needed, so the agent never holds the
 * secret. Returns the serialized ciphertext.
 */
export async function encryptRiskInputs(publicKey: string, inputsScaled: number[]): Promise<string> {
  if (inputsScaled.length !== RISK_DIM) throw new Error(`inputsScaled must have length ${RISK_DIM}`);
  for (const v of inputsScaled) {
    if (!(Number.isInteger(v) && v >= 0 && v < SIGNED_BOUND)) {
      throw new Error('each scaled input must be a non-negative integer below the signed bound');
    }
  }
  const ctx = await createFheContext();
  const pk = ctx.seal.PublicKey();
  pk.load(ctx.context, publicKey);
  const encryptor = ctx.seal.Encryptor(ctx.context, pk);
  const plain = ctx.seal.BatchEncoder(ctx.context).encode(packSlots(inputsScaled, ctx.slotCount));
  if (plain === undefined) {
    pk.delete();
    encryptor.delete();
    ctx.dispose();
    throw new Error('BatchEncoder.encode returned void');
  }
  const cipher = encryptor.encrypt(plain);
  if (cipher === undefined) {
    plain.delete();
    pk.delete();
    encryptor.delete();
    ctx.dispose();
    throw new Error('Encryptor.encrypt returned void');
  }
  const out = cipher.save();
  cipher.delete();
  plain.delete();
  pk.delete();
  encryptor.delete();
  ctx.dispose();
  return out;
}

// ---------------------------------------------------------------------------------------------
// Role 3 — the EVALUATOR: compute the gate BLIND. NEVER constructs a Decryptor; has no secret key.
// ---------------------------------------------------------------------------------------------

/**
 * Homomorphically evaluate the risk gate over the encrypted inputs. Computes, entirely on ciphertext:
 *
 *   encRiskRaw = sumSlots( encInputs × weightsScaled )           // = Σ wᵢ·xᵢ  (scale S²)
 *   encSlack   = budgetScaled − sumSlots( encInputs × κ·weightsScaled )
 *              = B·S² − κ·riskRaw                                 // sign ⇒ admit
 *
 * Both dot products are ciphertext×PLAINTEXT multiplies (multiplicative depth 1, no relinearization),
 * summed across slots with Galois rotations; the budget is folded in with a plaintext negate + add.
 * The evaluator sees only ciphertext and the public policy — never the inputs, `r`, or the verdict.
 */
export async function evalRiskGate(
  evalKeys: EvalKeys,
  encInputs: string,
  policy: FheRiskPolicy,
): Promise<EncryptedGate> {
  requirePolicyDim(policy);
  const ctx = await createFheContext();
  const scheme = ctx.seal.SchemeType.bfv;

  const galoisKeys = ctx.seal.GaloisKeys();
  galoisKeys.load(ctx.context, evalKeys.galoisKeys);
  const evaluator = ctx.seal.Evaluator(ctx.context);

  const ctX = ctx.seal.CipherText();
  ctX.load(ctx.context, encInputs);

  const ptW = ctx.encoder.encode(packSlots(policy.weightsScaled, ctx.slotCount));
  const ptKW = ctx.encoder.encode(packSlots(policy.kappaWeightsScaled, ctx.slotCount));
  const ptB = ctx.encoder.encode(packSlots([policy.budgetScaled], ctx.slotCount));
  if (ptW === undefined || ptKW === undefined || ptB === undefined) {
    throw new Error('BatchEncoder.encode returned void');
  }

  // riskRaw = Σ wᵢ·xᵢ
  const prodW = evaluator.multiplyPlain(ctX, ptW);
  if (prodW === undefined) throw new Error('multiplyPlain returned void');
  const encRiskRaw = evaluator.sumElements(prodW, galoisKeys, scheme);
  if (encRiskRaw === undefined) throw new Error('sumElements returned void');

  // κ·riskRaw = Σ (κ·wᵢ)·xᵢ, then slack = budgetScaled − κ·riskRaw
  const prodKW = evaluator.multiplyPlain(ctX, ptKW);
  if (prodKW === undefined) throw new Error('multiplyPlain returned void');
  const encKappaRisk = evaluator.sumElements(prodKW, galoisKeys, scheme);
  if (encKappaRisk === undefined) throw new Error('sumElements returned void');
  const negKappaRisk = evaluator.negate(encKappaRisk);
  if (negKappaRisk === undefined) throw new Error('negate returned void');
  const encSlack = evaluator.addPlain(negKappaRisk, ptB);
  if (encSlack === undefined) throw new Error('addPlain returned void');

  const out: EncryptedGate = { encRiskRaw: encRiskRaw.save(), encSlack: encSlack.save() };

  encSlack.delete();
  negKappaRisk.delete();
  encKappaRisk.delete();
  prodKW.delete();
  encRiskRaw.delete();
  prodW.delete();
  ptB.delete();
  ptKW.delete();
  ptW.delete();
  ctX.delete();
  evaluator.delete();
  galoisKeys.delete();
  ctx.dispose();
  return out;
}

// ---------------------------------------------------------------------------------------------
// Role 1 again — the KEY HOLDER opens the verdict. The ONLY party that decrypts.
// ---------------------------------------------------------------------------------------------

/**
 * Decrypt the gate outputs with the secret key and read the verdict. `rScaled` is r at scale S²,
 * clamped to [0,S²] to mirror `riskScore`'s final clamp01; `slack` is the decrypted admission slack;
 * `admit` is `slack ≥ 0` — the sign-of-slack decision (see HONEST SCOPE). For the default policy
 * (Σweights = 1) this equals the plaintext `riskScore`/budget outcome exactly.
 */
export async function decryptVerdict(
  secretKey: string,
  encRiskRaw: string,
  encSlack: string,
  policy: FheRiskPolicy,
): Promise<Verdict> {
  requirePolicyDim(policy);
  const ctx = await createFheContext();
  const sk = ctx.seal.SecretKey();
  sk.load(ctx.context, secretKey);
  const decryptor = ctx.seal.Decryptor(ctx.context, sk);

  const ctR = ctx.seal.CipherText();
  ctR.load(ctx.context, encRiskRaw);
  const ctS = ctx.seal.CipherText();
  ctS.load(ctx.context, encSlack);

  const ptR = decryptor.decrypt(ctR);
  const ptS = decryptor.decrypt(ctS);
  if (ptR === undefined || ptS === undefined) throw new Error('Decryptor.decrypt returned void');
  const decodedR = ctx.encoder.decode(ptR, true);
  const decodedS = ctx.encoder.decode(ptS, true);

  const rawR = decodedR[0] ?? 0;
  const slack = decodedS[0] ?? 0;
  const cap = policy.scale * policy.scale;
  const rScaled = rawR < 0 ? 0 : rawR > cap ? cap : rawR; // clamp01 at scale S²

  ptR.delete();
  ptS.delete();
  ctR.delete();
  ctS.delete();
  sk.delete();
  decryptor.delete();
  ctx.dispose();
  return { rScaled, slack, admit: slack >= 0 };
}

// ---------------------------------------------------------------------------------------------
// PCA LAYER — tie the encrypted gate to a PCActn so an agent submits an encrypted risk CLAIM the
// evaluator processes blind, in place of the plaintext `risk_claim.inputs`/`r`.
// ---------------------------------------------------------------------------------------------

/**
 * A binding that pins an encrypted risk claim to the one action it is for, so a ciphertext cannot be
 * replayed onto a different action. Mirrors the signed fields of the PCActn it came from.
 */
export interface RiskClaimBinding {
  /** The resource server / Atlas instance the action targets (PCActn `aud`). */
  aud: string;
  /** Commits the specific action: its `params_digest` (what the action does). */
  actionRef: string;
  /** PCActn monotonic `counter` (replay ordering). */
  counter: number;
  /** Optional per-action nonce. */
  nonce?: string;
}

/** An encrypted risk claim: the blind input an agent hands the evaluator in place of plaintext inputs. */
export interface EncryptedRiskClaim {
  binding: RiskClaimBinding;
  /** Serialized ciphertext of the quantized risk inputs. */
  encInputs: string;
  /** The public policy the gate runs under. */
  policy: FheRiskPolicy;
}

const INPUT_FIELDS: ReadonlyArray<keyof RiskInputs> = [
  'semanticDistance',
  'reversibility',
  'blastRadius',
  'taint',
  'confidence',
  'age',
];

/**
 * Read the six normalized risk inputs out of a PCActn's `risk_claim.inputs` map. Missing / non-numeric
 * fields are left non-finite so {@link transformedInputs}' `unit` maps them to their fail-closed
 * worst case — exactly as the plaintext verifier would treat them.
 */
export function riskInputsFromPCActn(p: PCActn): RiskInputs {
  const src = p.risk_claim.inputs;
  const read = (k: keyof RiskInputs): number => {
    const v = src[k];
    return typeof v === 'number' ? v : Number.NaN;
  };
  const out = {} as RiskInputs;
  for (const k of INPUT_FIELDS) out[k] = read(k);
  return out;
}

/** Derive the replay-binding from a signed PCActn. */
export function bindingFromPCActn(p: PCActn): RiskClaimBinding {
  const binding: RiskClaimBinding = {
    aud: p.aud,
    actionRef: p.action.params_digest,
    counter: p.counter,
  };
  if (p.nonce !== undefined) binding.nonce = p.nonce;
  return binding;
}

/**
 * Build an encrypted risk claim for a PCActn: reads the action's risk inputs, quantizes them at the
 * policy scale, encrypts under the public key, and binds the ciphertext to the action. The agent runs
 * this; the evaluator runs {@link evalEncryptedRiskClaim}. The plaintext inputs never leave the agent.
 */
export async function encryptedRiskClaim(args: {
  actn: PCActn;
  publicKey: string;
  policy: FheRiskPolicy;
}): Promise<EncryptedRiskClaim> {
  requirePolicyDim(args.policy);
  const inputs = riskInputsFromPCActn(args.actn);
  const scaled = quantizeRiskInputs(inputs, args.policy.scale);
  const encInputs = await encryptRiskInputs(args.publicKey, scaled);
  return { binding: bindingFromPCActn(args.actn), encInputs, policy: args.policy };
}

/** Evaluator-side convenience: run the gate over an {@link EncryptedRiskClaim} blind. */
export function evalEncryptedRiskClaim(
  evalKeys: EvalKeys,
  claim: EncryptedRiskClaim,
): Promise<EncryptedGate> {
  return evalRiskGate(evalKeys, claim.encInputs, claim.policy);
}

// ---------------------------------------------------------------------------------------------
// Cross-check helpers — the plaintext `risk.ts` ground truth the FHE path must reproduce.
// ---------------------------------------------------------------------------------------------

/**
 * The plaintext reference verdict, computed with the core `risk.ts` `riskScore` and `cost`:
 * `admit ⇔ cost(r,κ) ≤ budget ⇔ κ·r ≤ B`. This is the exact outcome {@link decryptVerdict} must
 * match for the same inputs/policy (within fixed-point quantization on `rScaled`).
 */
export function plaintextVerdict(
  inputs: RiskInputs,
  core: RiskPolicy,
  budget: number,
): { r: number; admit: boolean } {
  const r = riskScore(inputs, core.weights);
  return { r, admit: cost(r, core.kappa) <= budget };
}

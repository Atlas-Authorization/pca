import { buildPCActn, createProvenanceRecorder, encodeKey, generateKeyPair, memoryPcaStore, mintGrant, paramsDigest, principalDirectProvenance, authorize } from '@atlasauth/pca';
import type { AuthorizeResult, PlanNode, PcaOperation } from '@atlasauth/pca';

const AUD = 'sandbox-rs';
const PROV_KEY = new Uint8Array(32).fill(7);
const provRec = () => createProvenanceRecorder({ mediator: 'sandbox-test-harness', kid: 'k1', secretKey: PROV_KEY });

/** A grant for `resources` (every verb, any params) and a function that runs the strict pipeline for one operation. */
export function authFixture(resources: string[]) {
  const principal = generateKeyPair();
  const holder = generateKeyPair();
  const { grant } = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    holder: encodeKey(holder.publicKey),
    goal: 'sandbox tests',
    envelope: { predicates: resources.map((resource) => ({ verb: ['http.get', 'http.post', 'fs.read', 'notes.read'], resource, where: [] })), caveats: [], agent_binding: {}, risk_policy: { weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 100, lambda: 0, rho: 0.5, bMax: 1_000_000 } },
  });
  const store = memoryPcaStore();
  let counter = 0;
  const opts = {
    audience: AUD,
    resolveGrant: async (ref: string) => (ref === grant.id ? grant : null),
    budgetStore: store,
    hooks: { revocation: () => ({ enforced: true as const, ok: true as const }) },
    plan: 'single-step' as const,
    risk: () => ({ blastRadius: 0, semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 }),
    // provenance by default: the sandbox tests' operations come straight from the principal (a pinned harness recorder)
    provenance: { mediators: [provRec().pin], bundle: (_r: unknown, _p: unknown, o: PcaOperation) => principalDirectProvenance(provRec(), { verb: o.verb, resource: o.resource, params: o.params ?? {} }) },
  };
  async function allow(op: PcaOperation, signed: PcaOperation = op): Promise<AuthorizeResult> {
    const node: PlanNode = { id: 'n1', verb: signed.verb, resource: signed.resource, params_digest: paramsDigest(signed.params), reversibility_class: 'reversible' };
    const pcactn = buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n1', params: signed.params, counter: ++counter, signerSecret: holder.secretKey, aud: AUD });
    return authorize({ operation: op, pcactn }, opts);
  }
  return { allow };
}

import { generateKeyPair as genKey } from '@atlasauth/pca';
import { signRuntimeClaim, passportDigest, type RuntimeClaim, type ClaimTrust } from './runtime-claim';
import type { RuntimeClass } from './receipts';

/** A runtime claim signed by a fresh attestor, plus the trust that pins it. */
export function claimFixture(cls: RuntimeClass = 'wasi_no_ambient', over: Partial<Omit<RuntimeClaim, 'v' | 'sig' | 'attestor'>> = {}) {
  const kp = genKey();
  const passport = { agent: 'a1', note: 'signed passport stand-in' };
  const claim = signRuntimeClaim(kp.secretKey, kp.publicKey, { class: cls, passport_digest: passportDigest(passport), evidence_digest: 'ev1', iat: 0, exp: 10_000, ...over });
  const trust: ClaimTrust = { pinnedAttestors: [claim.attestor], passportDigest: passportDigest(passport), verifiedEvidenceDigests: ['ev1'], now: 1 };
  return { kp, claim, trust, runtimeClaim: { claim, trust } };
}

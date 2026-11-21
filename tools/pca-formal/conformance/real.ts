/**
 * Concretizer: builds REAL packages/pca objects from a symbolic Spec and runs the REAL verifier
 * (verifyPCActn from packages/pca/src/server/verify.ts, guardPCActnReplay + InMemoryReplayStore from replay.ts,
 * verifyThreshold from threshold.ts). Nothing here decides accept/reject itself.
 */
import {
  type Capability, type Caveat, type PCActn, InMemoryReplayStore, b64u, capHash, commitPlan, conditionsDigest,
  delegate, guardPCActnReplay, hashCanonical, mintGrant, signPCActn, verifyPCActn, DEFAULT_RISK_POLICY,
  PCACTN_VERSION, type PlanNode,
} from '../../../packages/pca/src/index';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { sign as edSign } from '../../../packages/pca/src/keys';
import { type Key } from './model';
import { ALL, NOW, PIN_VERBS, type Spec, windowOf, nowOf, wrongSigner, type Pin } from './spec';

const te = new TextEncoder();
const keyCache = new Map<string, { sk: Uint8Array; pk: string }>();
export function keyOf(name: string) {
  let k = keyCache.get(name);
  if (!k) {
    const sk = sha256(te.encode(`pca-formal-conformance-key/${name}`));
    k = { sk, pk: b64u(ed25519.getPublicKey(sk)) };
    keyCache.set(name, k);
  }
  return k;
}
export const AUD = 'rs-test';
const SALT = b64u(new Uint8Array(16).fill(7));

const envGrantCache = new Map<string, Capability>();
/** a root grant minted by `issuerKeyName`'s public identity, signed by `signerName`, holder A, envelope verbs */
export function mintRootFor(verbs: string[], issuerName: Key, signerName: Key): Capability {
  const ck = `${verbs.join(',')}|${issuerName}|${signerName}`;
  let g = envGrantCache.get(ck);
  if (!g) {
    g = mintGrant({
      principalSecret: keyOf(signerName).sk,
      principalPublic: keyOf(issuerName).pk,
      holder: keyOf('A').pk,
      goal: 'g',
      salt: SALT,
      envelope: {
        predicates: verbs.map((v) => ({ verb: v })),
        caveats: [],
        agent_binding: {},
        risk_policy: DEFAULT_RISK_POLICY,
      },
    }).grant;
    envGrantCache.set(ck, g);
  }
  return g;
}
const envCaveat = (verbs: string[]): Caveat => mintRootFor(verbs, 'P', 'P').caveats[0]!;
const pinCaveat = (p: Exclude<Pin, 'none'>): Caveat => ({ type: 'predicates', allow: [{ verb: PIN_VERBS[p] }] });

// ---- independent re-implementation of capability sealing (so faults can be injected) ----------------------
const CAP_DOMAIN = te.encode('atlas-pca/cap/v1\0');
function sigMessage(digest: string): Uint8Array {
  const d = Buffer.from(digest.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  const m = new Uint8Array(CAP_DOMAIN.length + d.length);
  m.set(CAP_DOMAIN);
  m.set(d, CAP_DOMAIN.length);
  return m;
}
export function sealHop(body: { issuer: string; holder: string; caveats: Caveat[]; parent?: string }, signerSk: Uint8Array): Capability {
  const digest = hashCanonical({ issuer: body.issuer, holder: body.holder, caveats: body.caveats, parent: body.parent ?? null });
  const cap: Capability = { id: digest, issuer: body.issuer, holder: body.holder, caveats: body.caveats, body_digest: digest, sig: b64u(edSign(signerSk, sigMessage(digest))) };
  if (body.parent !== undefined) cap.parent = body.parent;
  return cap;
}
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

export interface RealChain { chain: Capability[]; holders: Key[] }
const chainCache = new Map<string, RealChain>();
export function realChain(s: Spec): RealChain {
  const ck = JSON.stringify([s.rootVerbs, s.root, s.hops, s.empty]);
  const hit = chainCache.get(ck);
  if (hit) return hit;
  const out: RealChain = { chain: [], holders: [] };
  if (!s.empty) {
    let root: Capability;
    switch (s.root) {
      case 'G': root = mintRootFor(s.rootVerbs, 'P', 'P'); break;
      case 'foreignP': root = mintRootFor(ALL, 'P', 'P'); break;
      case 'forgedX': root = mintRootFor(s.rootVerbs, 'P', 'X'); break;
      case 'xIssued': root = mintRootFor(s.rootVerbs, 'X', 'X'); break;
      case 'stale': {
        const sealed = sealHop({ issuer: keyOf('P').pk, holder: keyOf('A').pk, caveats: [envCaveat(ALL), { type: 'marker' }] }, keyOf('P').sk);
        root = { ...sealed, caveats: [envCaveat(ALL)] };
        break;
      }
    }
    out.chain.push(root);
    out.holders.push('A');
    for (const hs of s.hops) {
      const prev = out.chain[out.chain.length - 1]!;
      const prevHolder = out.holders[out.holders.length - 1]!;
      const issuer: Key = hs.issuerFault ? 'X' : prevHolder;
      let caveats: Caveat[] = [...clone(prev.caveats), ...(hs.pin === 'none' ? [] : [pinCaveat(hs.pin)])];
      if (hs.prefixFault === 'drop') caveats = caveats.slice(1);
      if (hs.prefixFault === 'alter') caveats = [clone(envCaveat(ALL)), ...caveats.slice(1)];
      const by: Key = hs.sigFault === 'wrongKey' ? wrongSigner(issuer) : issuer;
      const parent = hs.parentFault ? hashCanonical({ broken: out.chain.length }) : capHash(prev);
      let cap: Capability;
      if (hs.sigFault === 'stale') {
        const sealed = sealHop({ issuer: keyOf(issuer).pk, holder: keyOf(hs.holder).pk, caveats: [...caveats, { type: 'marker' }], parent }, keyOf(by).sk);
        cap = { ...sealed, caveats };
      } else cap = sealHop({ issuer: keyOf(issuer).pk, holder: keyOf(hs.holder).pk, caveats, parent }, keyOf(by).sk);
      out.chain.push(cap);
      out.holders.push(hs.holder);
    }
  }
  chainCache.set(ck, out);
  return out;
}

// ---- plan + PCActn ------------------------------------------------------------------------------------------
const PLAN: PlanNode[] = [
  { id: 'n1', verb: 'v1', resource: 'r1', params_digest: hashCanonical({}), reversibility_class: 'reversible' },
  { id: 'n2', verb: 'v2', resource: 'r1', params_digest: hashCanonical({}), reversibility_class: 'reversible' },
];
const COMMITTED = commitPlan(PLAN);
const LOW_RISK = { reversibility: 1, blastRadius: 0, confidence: 1, semanticDistance: 0, taint: 0 };

export interface ActIn { verb: string; planned: boolean; aud: 'ok' | 'other'; grantRef: string; iat: number; exp: number; counter: number; nonce: string | null; leafSig: Spec['leafSig'] }
export function realAction(rc: RealChain, a: ActIn): PCActn {
  const verbNode = a.verb === 'v2' ? PLAN[1]! : PLAN[0]!;
  const action = {
    verb: a.verb, resource: a.planned ? 'r1' : 'rX', params_digest: verbNode.params_digest!, reversibility_class: 'reversible',
  };
  const leafName: Key = rc.holders.length ? rc.holders[rc.holders.length - 1]! : 'A';
  const signerName: Key = a.leafSig === 'wrongKey' ? wrongSigner(leafName) : leafName;
  const body = {
    ver: PCACTN_VERSION,
    action,
    grant_ref: a.grantRef,
    cap_chain: rc.chain,
    plan: { root: COMMITTED.root, inclusion_proof: COMMITTED.proofFor(verbNode.id), node_id: verbNode.id, conditions_digest: conditionsDigest(verbNode.pre, verbNode.post) },
    attestation: { quote_digest: '', epoch: 0, model_id: 'm', measurement: '', operator: 'o' },
    provenance: { causal_hash: '', taint_level: 0, trusted_refs: [] as string[] },
    freshness: { beacon_ref: '', epoch: 0, accumulator_witness: '' },
    counter: a.counter,
    risk_claim: { r: 0, inputs: {} },
    aud: a.aud === 'ok' ? AUD : 'other-rs',
    iat: a.iat,
    exp: a.exp,
    ...(a.nonce !== null ? { nonce: a.nonce } : {}),
  };
  const p = signPCActn(body as never, keyOf(signerName).sk);
  if (a.leafSig === 'stale') p.provenance = { ...p.provenance, causal_hash: 'post-signature-tamper' };
  return p;
}
export function grefOf(rc: RealChain, g: Spec['gref'], G: Capability): string {
  return g === 'root' ? (rc.chain[0]?.id ?? '') : g === 'G' ? G.id : g === 'other' ? hashCanonical({ unrelated: 1 }) : '';
}

export interface RealOut { allow: boolean; failed: string[]; }
export async function realVerify(s: Spec, nowMs = nowOf(s), gOverride?: Capability): Promise<{ out: RealOut; p: PCActn; rc: RealChain }> {
  const rc = realChain(s);
  const G = gOverride ?? mintRootFor(s.rootVerbs, 'P', 'P');
  const t = windowOf(s);
  const pp = realAction(rc, { verb: s.verb, planned: s.planned, aud: s.aud, grantRef: grefOf(rc, s.gref, G), iat: t.iat, exp: t.exp, counter: s.counter, nonce: s.nonce, leafSig: s.leafSig });
  const v = await verifyPCActn(pp, {
    grant: G,
    now: nowMs,
    require: [], // 0.5 default-denies on not-enforced checks; the model compares the per-check report, not that policy
    insecureSkipPlanRootCheck: true, // K5: no authorized plan configured fails plan_root_authorized; the model has no plan-root check
    audience: s.audMode === 'string' ? AUD : s.audMode === 'null' ? null : undefined,
    context: { plan: PLAN, risk: LOW_RISK, params: {}, budget: { B: 1, tau: nowMs, asOf: nowMs } },
  });
  const failed = Object.entries(v.checks).filter(([, st]) => st === 'fail').map(([k]) => k).filter((k) => k !== 'malformed').sort();
  if (!v.allow && failed.length === 0) failed.push('malformed');
  return { out: { allow: v.allow, failed }, p: pp, rc };
}
export { InMemoryReplayStore, guardPCActnReplay, verifyPCActn, delegate };
export const PLAN_NODES = PLAN;
export const BUDGET = { B: 1, tau: NOW, asOf: NOW };
export const RISK = LOW_RISK;

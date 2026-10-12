/**
 * REFERENCE MODEL -- an executable, symbolic, dependency-free decision procedure written ONLY from the
 * formal models (formal/tamarin/pca_actn.spthy, pca_threshold.spthy, formal/pca-lean/PcaProof/*.lean and
 * the normative check order documented in docs/pca/security/formal-verification.md).
 *
 * It imports NOTHING from packages/pca: no crypto, no bytes, no hashing. Keys, hashes and signatures are
 * symbolic terms exactly as in the Dolev-Yao model:
 *     sig   = { by: Key, over: Term }        verify(sig, body, k) := sig.by === k && sig.over === body
 *     h(x)  = the string "h(" + x + ")"       (injective, collision-free)
 *
 * Mapping to the formal rules (Tamarin Verify_Depth* / Lean Verifier + Replay):
 *   audience         ChkAud(aaud, vaud)                      a = b   (or opt-out / fail-closed when absent)
 *   validity         AcceptTime(exp) vs Expired(exp)         now <= exp, plus the wire bounds iat<exp<=iat+MAX, iat<=now+SKEW
 *   cap_chain        Eq(verify(sg_i, b_i, iss_i)), Eq(par_i, h(c_{i+1})), Eq(iss_i, hol_{i+1}), root issuer = anchor,
 *                    append-only caveat lists (Attenuation.lean IsPrefix), root == the verifier's stored grant G
 *   grant_ref_bound  ChkGref(gref, h(c_root)) / Verifier.lean grantRefBoundStatus (non-empty, = id of chain[0])
 *   leaf_signature   ChkLeafSig(verify(asig, act, hol_leaf))
 *   plan_inclusion   the action is a node of the committed plan
 *   policy           attenuation_root: verb permitted by the ROOT envelope  (Attenuation.lean Eff on the root hop)
 *   delegated_caveats attenuation_hop : verb permitted by every caveat the delegation hops add (Eff of the leaf hop)
 *   replay           Consume(<'n',aud,gref,holder,nonce>) / Advance(<'c',aud,gref,holder>, ctr)  (Replay.lean)
 */

export type Key = 'P' | 'A' | 'B' | 'C' | 'X';
export type Verb = 'v1' | 'v2' | 'v3';

/** a caveat atom: `env` is the root envelope (verbs the root permits); `pin` is a delegated narrowing. */
export interface Atom {
  kind: 'env' | 'pin';
  verbs: Verb[];
}
export interface SymSig {
  by: Key;
  /** the body term the signature is over; `fresh` means "exactly this hop's body", otherwise stale/other. */
  over: 'fresh' | 'stale';
}
/** A capability hop as a symbolic term. `parent` is a term ('none' | 'h(<id>)'). */
export interface SymCap {
  id: string; // symbolic identity of the hop's FULL term incl. signature (stands for h(cap) = capHash); the parent link
  bodyId: string; // identity of the signed BODY only (the code's `cap.id`/body_digest, which grant_ref binds)
  issuer: Key;
  holder: Key;
  caveats: Atom[]; // cumulative, root envelope first
  parent: string; // 'none' | h(parent id)
  sig: SymSig;
}
export interface SymAction {
  verb: Verb;
  planned: boolean; // the (verb) is a node of the committed plan
  aud: 'ok' | 'other';
  gref: 'root' | 'G' | 'other' | 'empty'; // 'root' = the id of chain[0] as presented
  iat: number;
  exp: number;
  counter: number; // non-negative integer
  nonce: string | null; // null = absent
  sig: SymSig; // leaf signature
}
export interface Verifier {
  aud: 'ok' | null | undefined; // string = own audience; null = opt-out; undefined = forgot
  now: number;
  G: SymCap; // the verifier's stored root grant
  anchor: Key; // = G.issuer
}
export const MAX_LIFETIME = 3_600_000;
export const MAX_SKEW = 60_000;
export const MAX_CHAIN_DEPTH = 16;

/** model-mutant switch for the harness self-test (each mutant must be KILLED = produce disagreements) */
const MUT = (n: string): boolean => typeof process !== 'undefined' && process.env.PCA_MODEL_MUTANT === n;
export const h = (id: string) => `h(${id})`;
const verifySig = (s: SymSig, k: Key) => s.by === k && s.over === 'fresh';
const eqAtom = (a: Atom, b: Atom) => a.kind === b.kind && a.verbs.length === b.verbs.length && a.verbs.every((v, i) => v === b.verbs[i]);
const permits = (a: Atom, v: Verb) => a.verbs.includes(v);

/** chain walk: the conjunction of the formal model's per-hop rules (Eq/verify/par/iss + append-only prefix). */
export function capChainOk(chain: SymCap[], vf: Verifier): boolean {
  if (chain.length === 0) return false; // 'empty chain'
  if (chain.length > MAX_CHAIN_DEPTH) return false;
  const root = chain[0]!;
  if (root.id !== vf.G.id) return false; // the presented root is not the verifier's grant
  if (root.parent !== 'none') return false; // Eq(par, 'none')
  if (!MUT('noAnchor') && root.issuer !== vf.anchor) return false; // Eq(iss, pkT)
  if (!verifySig(root.sig, root.issuer)) return false; // Eq(verify(sg, b, iss), true)
  for (let i = 1; i < chain.length; i++) {
    const p = chain[i - 1]!;
    const c = chain[i]!;
    if (!MUT('noParentLink') && c.parent !== h(p.id)) return false; // Eq(par_i, h(c_{i+1}))
    if (!MUT('noIssuerEq') && c.issuer !== p.holder) return false; // Eq(iss_i, hol_{i+1})
    if (!MUT('noHopSig') && !verifySig(c.sig, c.issuer)) return false;
    // append-only (Attenuation.lean IsPrefix p c): the child keeps the parent's caveats verbatim
    if (!MUT('noPrefix') && c.caveats.length < p.caveats.length) return false;
    if (!MUT('noPrefix')) for (let j = 0; j < p.caveats.length; j++) if (!eqAtom(c.caveats[j]!, p.caveats[j]!)) return false;
  }
  return true;
}

export type CheckName =
  | 'audience'
  | 'validity'
  | 'cap_chain'
  | 'grant_ref_bound'
  | 'grant_ref'
  | 'plan_inclusion'
  | 'leaf_signature'
  | 'delegated_caveats'
  | 'policy';

/** The set of FAILING checks of the verifier pipeline (empty = accept). */
export function verifyModel(chain: SymCap[], act: SymAction, vf: Verifier): Set<CheckName> {
  const failed = new Set<CheckName>();
  // audience (ChkAud). Absent audience on the verifier fails closed because the action carries a signed aud.
  if (vf.aud === null) {
    /* explicit opt-out: not-enforced */
  } else if (vf.aud === undefined) failed.add('audience');
  else if (!MUT('noAud') && act.aud !== 'ok') failed.add('audience');
  // validity (AcceptTime vs Expired + wire bounds)
  if (!(act.exp > act.iat)) failed.add('validity');
  else if (act.exp - act.iat > MAX_LIFETIME) failed.add('validity');
  else if (act.iat > vf.now + MAX_SKEW) failed.add('validity');
  else if (MUT('expiryOffByOne') ? vf.now >= act.exp : vf.now > act.exp) failed.add('validity');
  // cap_chain
  if (!capChainOk(chain, vf)) failed.add('cap_chain');
  // grant_ref_bound: non-empty and = id of the presented ROOT
  const rootId = chain.length > 0 ? chain[0]!.bodyId : undefined;
  const grefVal = act.gref === 'root' ? rootId : act.gref === 'G' ? vf.G.bodyId : act.gref === 'other' ? 'unrelated-ref' : '';
  if (!MUT('noGrefBound') && !(grefVal !== undefined && grefVal !== '' && rootId !== undefined && grefVal === rootId)) failed.add('grant_ref_bound');
  // grant_ref: = the id of the verifier's own grant
  if (grefVal !== vf.G.bodyId) failed.add('grant_ref');
  // plan inclusion
  if (!act.planned) failed.add('plan_inclusion');
  // leaf signature: under the LEAF holder of the presented chain
  const leaf = chain.length > 0 ? chain[chain.length - 1]! : undefined;
  if (!MUT('noLeafSig') && !(leaf && verifySig(act.sig, leaf.holder))) failed.add('leaf_signature');
  // policy: the verb must be permitted by the stored grant's ROOT envelope (attenuation_root)
  const rootEnv = vf.G.caveats.find((a) => a.kind === 'env');
  if (!MUT('noRootPolicy') && !(rootEnv && permits(rootEnv, act.verb))) failed.add('policy');
  // delegated caveats: everything the leaf carries beyond the grant's own caveats must permit the verb
  if (leaf) {
    const extra = leaf.caveats.slice(vf.G.caveats.length);
    if (!MUT('noAncestorCaveat') && !(MUT('onlyLeafCaveat') ? extra.slice(-1) : extra).every((a) => permits(a, act.verb))) failed.add('delegated_caveats');
  }
  return failed;
}

// ---- replay store (Replay.lean: NSt / CSt machines) -------------------------------------------------------
export interface ReplayState {
  seen: Map<string, number>; // key -> retainUntil
  streams: Map<string, number>; // stream -> last counter
}
export const newReplayState = (): ReplayState => ({ seen: new Map(), streams: new Map() });
export type ReplayVerdict = { ok: true } | { ok: false; code: 'replay' | 'malformed' };

/**
 * guardPCActnReplay as the formal machines: the nonce key is consumed iff there is no LIVE entry
 * (retainUntil >= now); the counter advances iff strictly greater than the stored value. Applied only to an
 * action the verifier accepted (ordering is a security requirement, see grant-ref-binding).
 */
export function replayModel(st: ReplayState, aud: string, gref: string, holder: Key, act: SymAction, now: number): ReplayVerdict {
  const key = JSON.stringify(['n', aud, gref, holder, act.nonce]);
  const stream = JSON.stringify(['c', aud, gref, holder]);
  if (act.nonce === null || act.nonce === '') return { ok: false, code: 'malformed' }; // requireNonce default
  const retain = act.exp + MAX_SKEW;
  const until = st.seen.get(key);
  if (!MUT('noNonceStore') && until !== undefined && (MUT('retentionStrict') ? until > now : until >= now)) return { ok: false, code: 'replay' };
  st.seen.set(key, Math.max(retain, until ?? 0));
  const last = st.streams.get(stream);
  if (!MUT('noCounter') && last !== undefined && !(MUT('counterGE') ? act.counter >= last : act.counter > last)) return { ok: false, code: 'replay' };
  st.streams.set(stream, act.counter);
  return { ok: true };
}

// ---- threshold step-up (pca_threshold.spthy) ---------------------------------------------------------------
export type Role = 'agent' | 'guardian' | 'principal';
export interface SignerReg {
  role: Role;
  key: Key | 'Y' | 'Z'; // extra keys for signer-set shape faults
}
/** a share is a signature by `key` over the share message built from (role, msgTag, setTag, t). */
export interface ShareS {
  role: Role;
  key: Key | 'Y' | 'Z';
  /** what the signature covers: the symbolic share message components */
  covers: { role: Role; msg: string; set: string; t: number };
}
export interface ThresholdIn {
  signerSet: SignerReg[];
  setTag: string; // the verifier's own signer-set hash term
  msg: string; // the verifier's message term
  t: number;
  shares: ShareS[];
  /** agent-leaf baseline: leaf holder key + whether the leaf signature covers `msg` */
  baseline?: { holder: Key | 'Y' | 'Z'; coversMsg: boolean };
}
export interface ThresholdOut {
  ok: boolean;
  count: number;
}
/**
 * verifyThreshold as pca_threshold.spthy: per-role slot tokens; a slot is filled by a share signed by the
 * role's REGISTERED key over <'share', role, h(msg), setHash, t>, or (agent only) by the leaf-signature
 * baseline under the registered agent key. The verifier accepts with >= t DISTINCT keys. A signer set that
 * registers two keys for a role, or one key under two roles, is rejected (SetDistinct restriction).
 */
export function thresholdModel(i: ThresholdIn): ThresholdOut {
  if (![1, 2, 3].includes(i.t)) return { ok: false, count: 0 };
  const keyOfRole = new Map<Role, string>();
  const roleOfKey = new Map<string, Role>();
  for (const s of i.signerSet) {
    const pk = keyOfRole.get(s.role);
    if (pk !== undefined && pk !== s.key) return { ok: false, count: 0 };
    const pr = roleOfKey.get(s.key);
    if (!MUT('thrNoSetDistinct') && pr !== undefined && pr !== s.role) return { ok: false, count: 0 };
    keyOfRole.set(s.role, s.key);
    roleOfKey.set(s.key, s.role);
  }
  const valid = new Set<string>();
  let nValid = 0;
  for (const sh of i.shares) {
    if (valid.has(sh.key) && !MUT('thrNoDistinct')) continue; // a key counts once
    const reg = keyOfRole.get(sh.role);
    if (reg === undefined || reg !== sh.key) continue;
    const c = sh.covers;
    if (!MUT('thrUnbound') && (c.role !== sh.role || c.msg !== i.msg || c.set !== i.setTag || c.t !== i.t)) continue; // bound share message
    if (MUT('thrUnbound') && c.msg !== i.msg) continue;
    valid.add(sh.key);
    nValid++;
  }
  if (i.baseline) {
    const ak = keyOfRole.get('agent');
    if (ak !== undefined && i.baseline.holder === ak && !valid.has(ak) && i.baseline.coversMsg) valid.add(ak);
  }
  const count = MUT('thrNoDistinct') ? nValid + (i.baseline && valid.has(keyOfRole.get('agent') ?? '') && nValid < valid.size ? 1 : 0) : valid.size;
  return { ok: count >= i.t, count };
}

// ---- software attestation path (pca_attest.spthy + the allowlist binding) -----------------------------------
export interface AttIn {
  present: boolean;
  pcactn: { grantRef: string; epoch: number; quote: string };
  expected: { holder: string; grant: string; epoch: number; nonce: string; nonceIssuedAt?: number };
  doc: {
    nonce: string; attestor: string; sigOk: boolean;
    binding: { holder: string; grant: string; epoch: number; nonce: string } | null; // what the signed doc is bound to
    issuedAt: number; expiresAt: number;
    model: string; weights: string; measurement: string; operator: string; prompt?: string; tools?: string;
  };
  trusted: string[];
  now: number;
  maxAge: number;
  binding: { models?: string[]; weights?: string[]; operator?: string; minMeasurement?: string; svn?: number; prompts?: string[]; tools?: string[] };
}
export type AttStage = 'present' | 'pcactn' | 'nonce' | 'attestor' | 'sig' | 'binding' | 'window' | 'nonce_age' | 'agent_binding' | 'ok';
/**
 * The binding is the injective term <'bind', holder, grant, epoch, nonce> (pca_attest.spthy report_data); the
 * accept rule requires sig-valid-by-trusted-attestor AND binding == the verifier's own expectation AND an approved
 * identity. Stage = first failed conjunct in the documented order.
 */
export function attestModel(i: AttIn): { ok: boolean; stage: AttStage } {
  const no = (stage: AttStage) => ({ ok: false, stage });
  if (!i.present) return no('present');
  if (i.pcactn.grantRef !== i.expected.grant || i.pcactn.epoch !== i.expected.epoch || i.pcactn.quote !== i.expected.nonce) return no('pcactn');
  if (i.doc.nonce !== i.expected.nonce) return no('nonce');
  if (!i.trusted.includes(i.doc.attestor)) return no('attestor');
  if (!i.doc.sigOk) return no('sig');
  const b = i.doc.binding;
  if (!(b && b.holder === i.expected.holder && b.grant === i.expected.grant && b.epoch === i.expected.epoch && b.nonce === i.expected.nonce)) return no('binding');
  if (i.doc.expiresAt < i.doc.issuedAt || i.now < i.doc.issuedAt || i.now > i.doc.expiresAt) return no('window');
  if (i.expected.nonceIssuedAt !== undefined && (i.now < i.expected.nonceIssuedAt || i.now - i.expected.nonceIssuedAt > i.maxAge)) return no('nonce_age');
  const a = i.binding;
  const d = i.doc;
  if (a.models && a.models.length && !a.models.includes(d.model)) return no('agent_binding');
  if (a.minMeasurement && d.measurement !== a.minMeasurement) return no('agent_binding');
  if (a.svn !== undefined && !(Number.isInteger(Number(d.measurement)) && d.measurement.trim() !== '' && Number(d.measurement) >= a.svn)) return no('agent_binding');
  if (a.operator && d.operator !== a.operator) return no('agent_binding');
  if (a.weights && a.weights.length && !a.weights.includes(d.weights)) return no('agent_binding');
  if (a.prompts && a.prompts.length && !(d.prompt !== undefined && a.prompts.includes(d.prompt))) return no('agent_binding');
  if (a.tools && a.tools.length && !(d.tools !== undefined && a.tools.includes(d.tools))) return no('agent_binding');
  return { ok: true, stage: 'ok' };
}

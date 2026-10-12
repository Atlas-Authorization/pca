// Deterministic corpus generator for the PCA cross-implementation audit.
//   tsx gen/generate.ts <outDir> [--seed N] [--bases N]
// Writes <outDir>/corpus.jsonl (what every implementation consumes: {id,kind,raw}) and
// <outDir>/meta.jsonl (generator-side tags the implementations never see).
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import * as pca from '../../../packages/pca/src/index';
import { emit, hasDupKeys, parse as astParse } from './jsonast';
import { safeParse } from './safejson';

const args = process.argv.slice(2);
const outDir = args[0] ?? 'out';
const opt = (k: string, d: number) => { const i = args.indexOf(k); return i >= 0 ? Number(args[i + 1]) : d; };
const SEED = opt('--seed', 20261006);
const BASES = opt('--bases', 1100);
// Fixed verification context shared with the oracle + every driver (wire v2 verifies at a fixed `now` for audience `AUD`).
const NOW = 1_800_000_000_000;
const AUD = 'rs-fuzz';

// ---------------------------------------------------------------- rng
function mulberry32(a: number) {
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rnd = mulberry32(SEED);
const int = (n: number) => Math.floor(rnd() * n);
const pick = <T,>(a: readonly T[]): T => a[int(a.length)]!;
const chance = (p: number) => rnd() < p;
const clone = <T,>(x: T): T => structuredClone(x);

// ---------------------------------------------------------------- raw-literal sentinels
// A value may be a sentinel string standing for an arbitrary JSON literal (e.g. 9007199254740993).
// rawText() substitutes the literal; P() gives the JS-parsed view the TS oracle sees.
const RAW: string[] = [];
const raw = (lit: string) => { RAW.push(lit); return `@@RAW#${RAW.length - 1}@@`; };
const rawText = (x: unknown): string => JSON.stringify(x).replace(/"@@RAW#(\d+)@@"/g, (_m, i) => RAW[Number(i)]!);
const P = <T,>(x: T): T => safeParse(rawText(x)) as T;

// ---------------------------------------------------------------- keys
const keyOf = (label: string) => {
  const sk = new Uint8Array(createHash('sha256').update(`pca-diff-fuzz/${label}`).digest());
  return { sk, pub: pca.b64u(pca.publicKeyOf(sk)) };
};
const POOL = Array.from({ length: 10 }, (_, i) => keyOf(`k${i}`));
const ROGUE = keyOf('rogue');

// ---------------------------------------------------------------- value generators
const WORDS = ['alpha', 'db/users', 'mail/out', 'ünï', 'café', '日本語', '😀', 'a b', 'x"y', 'back\\slash', 'line\nbreak', 'tab\t', 'ctl\u0001', '～', '\u{1F600}x', '', '/', '<&>', '\u007f', ' ', 'é', 'ǅ'];
const randStr = () => (chance(0.6) ? pick(WORDS) : Array.from({ length: 1 + int(8) }, () => String.fromCharCode(0x20 + int(0x5f))).join(''));
let floatMode = false;
function randNum(): number {
  // v2: every generated number is IN the strict profile (safe int, or plain decimal <=15 sig digits, >=1e-6).
  // Out-of-profile numbers are injected only by the explicit adversarial mutators.
  if (!floatMode) return chance(0.7) ? int(1_000_000) : -(1 + int(1000));
  switch (int(8)) {
    case 0: return int(10);
    case 1: return int(1_000_000);
    case 2: return Math.round(rnd() * 1e9) / 1e6;
    case 3: return (Math.round(rnd() * 1e6) + 1) / 1e6 * (chance(0.5) ? 1 : -1);
    case 4: return Math.round(rnd() * 1e6) / 100;
    case 5: return Math.floor(rnd() * (2 ** 53 - 1));
    case 6: return 2 ** int(53);
    default: return -(1 + int(1000));
  }
}
function randVal(d = 0): unknown {
  const k = int(d > 2 ? 5 : 8);
  if (k === 0) return randStr();
  if (k === 1) return randNum();
  if (k === 2) return chance(0.5);
  if (k === 3) return null;
  if (k === 4) return int(100);
  if (k === 5) return Array.from({ length: int(4) }, () => randVal(d + 1));
  const o: Record<string, unknown> = {};
  for (let i = 0; i < 1 + int(4); i++) o[randStr()] = randVal(d + 1);
  return o;
}
function randCaveat(): Record<string, unknown> {
  const c: Record<string, unknown> = { type: chance(0.7) ? pick(['max_spend', 'resource_prefix', 'note', 'verb_allow', 'not_after']) : randStr() };
  for (let i = 0; i < int(4); i++) { const k = randStr(); if (k !== 'type') c[k] = randVal(); }
  return c;
}

// ---------------------------------------------------------------- capability / pcactn builders
type Key = { sk: Uint8Array; pub: string };
const te = new TextEncoder();
function sealHop(parent: any | null, issuer: Key, holderPub: string, caveats: unknown[], signer: Key = issuer, overrides: Record<string, unknown> = {}): any {
  const parentHash = parent ? pca.capHash(P(parent)) : null;
  const body = { issuer: issuer.pub, holder: holderPub, caveats, parent: parentHash };
  const body_digest = pca.hashCanonical(P(body));
  const msg = new Uint8Array([...te.encode('atlas-pca/cap/v1\0'), ...pca.unb64u(body_digest)]);
  const cap: any = { id: body_digest, issuer: issuer.pub, holder: holderPub, caveats, body_digest, sig: pca.b64u(pca.sign(signer.sk, msg)) };
  if (parentHash !== null) cap.parent = parentHash;
  return { ...cap, ...overrides };
}

interface Base {
  grant: any;
  chain: any[];
  holders: Key[]; // holders[i] holds chain[i]
  nodes: pca.PlanNode[];
  nodeId: string;
  pc: any;
  params: Record<string, unknown>;
}

function randNodes(size: number): pca.PlanNode[] {
  return Array.from({ length: size }, (_, i) => {
    const n: any = { id: `n${i}${chance(0.2) ? '~' + randStr() : ''}`, verb: pick(['read', 'write', 'delete', 'send', 'x', randStr()]), resource: chance(0.8) ? `${pick(['db', 'mail', 'fs'])}/${randStr()}` : randStr() };
    if (chance(0.5)) n.params_digest = pca.paramsDigest(randVal());
    if (chance(0.3)) n.reversibility_class = pick(['reversible', 'irreversible', 'compensable', randStr()]);
    if (chance(0.3)) { n.pre = randVal(); n.post = randVal(); }
    return n;
  });
}

function leafSign(pc: any, key: Key): string {
  const { sig: _s, threshold: _t, ...body } = P(pc);
  return pca.b64u(pca.sign(key.sk, pca.thresholdMessage(body)));
}

function makeBase(o: { depth?: number; planSize?: number; caveatsFor?: (hop: number) => unknown[]; counter?: number | string } = {}): Base {
  const depth = o.depth ?? pick([1, 1, 1, 2, 2, 3, 4, 5]);
  const principal = pick(POOL);
  const holders: Key[] = [pick(POOL)];
  const cavs = o.caveatsFor ?? (() => Array.from({ length: int(3) }, randCaveat));
  let acc = cavs(0);
  const chain: any[] = [sealHop(null, principal, holders[0]!.pub, acc)];
  for (let h = 1; h < depth; h++) {
    const next = pick(POOL);
    acc = [...acc, ...cavs(h)];
    chain.push(sealHop(chain[h - 1], holders[h - 1]!, next.pub, acc));
    holders.push(next);
  }
  const size = o.planSize ?? pick([1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 31, 33, 64]);
  const nodes = randNodes(size);
  const node = pick(nodes);
  const params = node.params_digest !== undefined ? null : (randVal() as any);
  // keep node/action consistent: if the node pins a digest we cannot reproduce params, drop the pin.
  if (node.params_digest !== undefined) delete (node as any).params_digest;
  const useParams = chance(0.5) ? { qty: int(10), sku: randStr() } : undefined;
  const paramsFinal = useParams ?? {};
  (node as any).params_digest = pca.paramsDigest(useParams);
  void params;
  const committed = pca.commitPlan(nodes);
  const grant = chain[0];
  const life = pick([1000, 60_000, 600_000, 1_200_000, 3_600_000]);
  const iatOk = chance(0.1) ? NOW + int(60_001) : NOW - int(life + 1); // inside the accepted window: iat <= now+60s, now <= exp
  const pcBody: any = {
    ver: 2,
    action: { verb: node.verb, resource: node.resource, params_digest: pca.paramsDigest(useParams), reversibility_class: node.reversibility_class ?? 'reversible' },
    grant_ref: grant.id,
    cap_chain: chain,
    plan: { root: committed.root, inclusion_proof: committed.proofFor(node.id), node_id: node.id, conditions_digest: pca.conditionsDigest(node.pre, node.post) },
    attestation: { quote_digest: chance(0.8) ? '' : randStr(), epoch: chance(0.8) ? 0 : int(1000), model_id: chance(0.8) ? 'unattested' : randStr(), measurement: chance(0.8) ? '' : randStr(), operator: chance(0.8) ? 'unattested' : randStr() },
    provenance: { causal_hash: chance(0.8) ? '' : randStr(), taint_level: chance(0.8) ? 0 : pick([1, 2, 0.5, 0.25]), trusted_refs: chance(0.8) ? [] : Array.from({ length: 1 + int(3) }, randStr) },
    freshness: { beacon_ref: chance(0.8) ? '' : randStr(), epoch: chance(0.8) ? 0 : int(1000), accumulator_witness: chance(0.8) ? '' : randStr() },
    counter: o.counter ?? pick([0, 1, 7, int(1000), int(2 ** 31), 2 ** 53 - 1]),
    risk_claim: { r: floatMode && chance(0.5) ? Math.round(rnd() * 1e6) / 1e6 : 0, inputs: chance(0.5) ? {} : { a: randVal() } },
    aud: AUD,
    iat: iatOk,
    exp: iatOk + life,
  };
  // optional signed slots (each present ~25%)
  if (chance(0.25)) pcBody.nonce = chance(0.5) ? `n-${int(1e9)}` : pick(['é', '日本語', '😀', 'a b', 'x"y', 'n\u0001']) + int(99);
  if (chance(0.2)) pcBody.caution = pick([0, 1, 0.5, 0.25, 0.123456, 0.999999, 0.000001]);
  if (chance(0.2)) pcBody.rationale_commitment = pca.paramsDigest({ why: randStr() });
  if (chance(0.15)) pcBody.progress_step = { step: int(10), note: randStr(), n: randVal(1) };
  if (chance(0.15)) pcBody.prohibition_evidence = chance(0.5) ? { rule: randStr(), v: randVal(1) } : [randVal(1), randVal(1)];
  if (chance(0.15)) pcBody.tool_binding = pca.paramsDigest({ tool: randStr() });
  if (chance(0.1)) pcBody.zk_compliance = randVal(1);
  if (chance(0.1)) pcBody.bond_ref = randStr();
  if (chance(0.1)) pcBody.threshold = { shares: [{ role: pick(['guardian', 'principal']), publicKey: pca.paramsDigest({ k: int(9) }), sig: pca.b64u(new Uint8Array(64).fill(int(255))) }] };
  const holder = holders[holders.length - 1]!;
  pcBody.sig = leafSign(pcBody, holder);
  return { grant, chain, holders, nodes, nodeId: node.id, pc: pcBody, params: paramsFinal };
}

// ---------------------------------------------------------------- oracle (for self-checking the generator only)
async function oracle(pcText: string, grantText: string) {
  try {
    const p = pca.decodePCActn(pcText);
    const r = await pca.verifyPCActnCore(p, { grant: safeParse(grantText) as any, nowEpoch: NOW, audience: AUD });
    return { allow: r.allow, c: r.checks };
  } catch { return null; }
}

// ---------------------------------------------------------------- case state + mutators
interface St { pc: any; grant: any; base: Base; textPatch?: (s: string) => string; grantPatch?: (s: string) => string; }
interface MutResult { breaks?: string[]; mustReject?: boolean; resign?: Key | boolean; note?: string }
type Mutator = { name: string; group: string; minDepth?: number; fn: (st: St) => MutResult | null };

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const flipChar = (s: string, i = int(s.length)) => (s.length === 0 ? s : s.slice(0, i) + B64[(B64.indexOf(s[i]!) + 1 + int(60)) % 64] + s.slice(i + 1));
const flipBit = (s: string) => { const b = pca.unb64u(s); if (!b.length) return s; b[int(b.length)]! ^= 1 << int(8); return pca.b64u(b); };
// Non-canonical base64url: change ONLY the unused trailing bits of the final character.
const nonCanonTail = (s: string) => {
  const rem = (s.length * 6) % 8; // unused bits in the last char
  if (rem === 0) return null;
  const last = B64.indexOf(s[s.length - 1]!);
  const mask = (1 << rem) - 1;
  const alt = (last & ~mask) | (((last & mask) + 1) & mask || 1);
  return alt === last ? null : s.slice(0, -1) + B64[alt];
};

type Path = (string | number)[];
function leaves(x: unknown, p: Path = [], out: { path: Path; v: unknown }[] = []) {
  if (Array.isArray(x)) x.forEach((y, i) => leaves(y, [...p, i], out));
  else if (x && typeof x === 'object') for (const k of Object.keys(x)) leaves((x as any)[k], [...p, k], out);
  else out.push({ path: p, v: x });
  return out;
}
const getAt = (x: any, p: Path) => p.reduce((a, k) => a?.[k], x);
const setAt = (x: any, p: Path, v: unknown) => { const par = getAt(x, p.slice(0, -1)); par[p[p.length - 1]!] = v; };
const delAt = (x: any, p: Path) => { const par = getAt(x, p.slice(0, -1)); if (Array.isArray(par)) par.splice(Number(p[p.length - 1]), 1); else delete par[p[p.length - 1]!]; };

const EDGE_NUMS = ['0', '-0', '-0.0', '1.0', '1e0', '1E2', '1e+2', '0.1', '0.5', '1e-7', '1e-6', '0.000001', '0.0000001', '-1e-7', '1e21', '1e22', '100000000000000000000', '123456789012345678901234567890', '9007199254740991', '9007199254740992', '9007199254740993', '-9007199254740993', '4.9e-324', '5e-324', '1.7976931348623157e308', '1e308', '1e309', '1e400', '-1e400', '0e5', '12345.6789e-3', '1.5e300', '2.5', '0.30000000000000004', '123456789.123456789', '1e23', '4.35', '0.1e1', '10e-1', '9.999999999999999e22'];
const EDGE_STRS = ['"\\u0000"', '"\\u007f"', '"\\u2028\\u2029"', '"\\ud800"', '"\\udc00"', '"\\ud83d"', '"\\ud83d\\ude00"', '"\\ude00\\ud83d"', '"e\\u0301"', '"\\u00e9"', '"\\ufeff"', '"\\/"', '"\\u0041"', '"\\u001f\\u0020"', '"\\uffff"', '"\\ufffe"', '"\\b\\f\\n\\r\\t"', '"\\u2603\\u{1F600}"'.replace('\\u{1F600}', '\\ud83d\\ude00')];
const EDGE_KEYS = ['￿', '\u{1F600}', '', 'a', 'A', '', '10', '9', '__proto__', 'constructor', 'toString', 'length', '～', 'é', 'é', '\u0000', '퟿', '～', '0', '-1'];

const M: Mutator[] = [];
const add = (name: string, group: string, fn: Mutator['fn'], minDepth?: number) => M.push({ name, group, fn, minDepth });
const rej = (breaks: string[]): MutResult => ({ breaks, mustReject: true });

// --- signed-field tamper WITHOUT re-sign
add('sig-flip-char', 'sig', (s) => { s.pc.sig = flipChar(s.pc.sig); return rej(['leaf_signature']); });
add('sig-flip-bit', 'sig', (s) => { s.pc.sig = flipBit(s.pc.sig); return rej(['leaf_signature']); });
add('sig-truncate', 'sig', (s) => { s.pc.sig = s.pc.sig.slice(0, int(s.pc.sig.length)); return rej(['leaf_signature']); });
add('sig-empty', 'sig', (s) => { s.pc.sig = ''; return rej(['leaf_signature']); });
add('sig-nonstring', 'sig', (s) => { s.pc.sig = pick([null, 0, true, [], {}, 7]); return rej(['leaf_signature']); });
add('sig-oversize', 'sig', (s) => { s.pc.sig += 'A'.repeat(1 + int(200)); return rej(['leaf_signature']); });
add('sig-padded', 'sig', (s) => { s.pc.sig += pick(['=', '==']); return rej(['leaf_signature']); });
add('sig-standard-b64-chars', 'sig', (s) => { s.pc.sig = s.pc.sig.replace(/-/g, '+').replace(/_/g, '/') + (/[-_]/.test(s.pc.sig) ? '' : '+'); return rej(['leaf_signature']); });
add('sig-missing', 'sig', (s) => { delete s.pc.sig; return rej(['leaf_signature']); });
add('sig-noncanonical-tail', 'b64amb', (s) => { const t = nonCanonTail(s.pc.sig); if (!t) return null; s.pc.sig = t; return { mustReject: true }; });
add('sig-with-ws', 'b64amb', (s) => { s.pc.sig = pick([' ', '\n']) + s.pc.sig; return rej(['leaf_signature']); });
add('counter-tamper-nosign', 'sig', (s) => { s.pc.counter = (typeof s.pc.counter === 'number' ? s.pc.counter : 0) + 1; return rej(['leaf_signature']); });
for (const f of ['verb', 'resource', 'params_digest', 'reversibility_class'] as const) {
  add(`action-${f}-tamper-nosign`, 'tamper', (s) => { s.pc.action[f] = flipChar(String(s.pc.action[f]) || 'x') || 'x'; return rej(['plan_inclusion', 'leaf_signature']); });
  add(`action-${f}-tamper-resigned`, 'tamper', (s) => { s.pc.action[f] = (String(s.pc.action[f]) + 'x'); return { breaks: ['plan_inclusion'], mustReject: true, resign: true }; });
}
add('action-extra-field-resigned', 'tamper', (s) => { s.pc.action.extra = randVal(); return { mustReject: true, resign: true }; });
add('node-id-tamper-nosign', 'tamper', (s) => { s.pc.plan.node_id += 'x'; return rej(['plan_inclusion', 'leaf_signature']); });
add('node-id-tamper-resigned', 'tamper', (s) => { s.pc.plan.node_id += 'x'; return { breaks: ['plan_inclusion'], mustReject: true, resign: true }; });
add('plan-root-flip-resigned', 'tamper', (s) => { s.pc.plan.root = flipChar(s.pc.plan.root); return { breaks: ['plan_inclusion'], mustReject: true, resign: true }; });
add('conditions-digest-tamper-resigned', 'tamper', (s) => { s.pc.plan.conditions_digest = pca.conditionsDigest({ x: int(9) + 5 }, null); return { breaks: ['plan_inclusion'], mustReject: true, resign: true }; });
add('conditions-digest-removed-resigned', 'tamper', (s) => { delete s.pc.plan.conditions_digest; return { resign: true }; }); // legal only if node had default conditions
add('conditions-digest-nonstring-resigned', 'tamper', (s) => { s.pc.plan.conditions_digest = pick([null, 0, {}, false, [], 7]); return { mustReject: true, resign: true }; });
add('grant-ref-tamper', 'tamper', (s) => { s.pc.grant_ref = flipChar(s.pc.grant_ref); return { breaks: ['leaf_signature'], mustReject: true }; });
add('grant-ref-tamper-resigned', 'tamper', (s) => { s.pc.grant_ref = flipChar(s.pc.grant_ref); return { resign: true }; }); // informational field
add('ver-not-2-resigned', 'tamper', (s) => { s.pc.ver = pick([1, 3, 0, -1, 1.5, '2', true, null, [2]]); return { mustReject: true, resign: true }; });
add('ver-missing-resigned', 'tamper', (s) => { delete s.pc.ver; return { mustReject: true, resign: true }; });
add('extra-top-field-nosign', 'tamper', (s) => { s.pc.extra = randVal(); return rej(['leaf_signature']); });
add('extra-top-field-resigned', 'tamper', (s) => { s.pc.extra = randVal(); return { mustReject: true, resign: true }; });
add('threshold-field-added', 'tamper', (s) => { s.pc.threshold = { t: 2, shares: [] }; return {}; }); // excluded from signed body
add('zk-bond-fields-resigned', 'tamper', (s) => { s.pc.zk_compliance = randVal(); s.pc.bond_ref = randStr(); return { resign: true }; });
add('unsigned-subfield-tamper', 'tamper', (s) => { s.pc.attestation.model_id = 'forged'; s.pc.risk_claim.r = 0.99; return rej(['leaf_signature']); });
for (const top of ['ver', 'action', 'grant_ref', 'cap_chain', 'plan', 'counter', 'sig', 'attestation', 'risk_claim', 'provenance', 'freshness', 'aud', 'iat', 'exp']) {
  add(`missing-${top}`, 'shape', (s) => { delete s.pc[top]; return { mustReject: true }; });
  add(`missing-${top}-resigned`, 'shape', (s) => { delete s.pc[top]; return { mustReject: true, resign: true }; });
  add(`null-${top}`, 'shape', (s) => { s.pc[top] = null; return { mustReject: true }; });
}
for (const k of ['action', 'plan', 'cap_chain']) {
  add(`type-swap-${k}`, 'shape', (s) => { s.pc[k] = pick([[], {}, 'x', 7, true, [s.pc[k]]]); return { mustReject: true }; });
}
add('pcactn-is-array', 'shape', (s) => { s.pc = [s.pc]; return { mustReject: true }; });
add('pcactn-is-null', 'shape', (s) => { s.pc = null; return { mustReject: true }; });
add('pcactn-is-string', 'shape', (s) => { s.pc = 'x'; return { mustReject: true }; });
add('grant-issuer-tamper', 'chain', (s) => { s.grant.issuer = flipChar(s.grant.issuer); return rej(['chain']); });
add('grant-caveat-tamper', 'chain', (s) => { s.grant = clone(s.grant); s.grant.caveats = [...s.grant.caveats, { type: 'extra' }]; return rej(['chain']); });
add('grant-sig-flip', 'chain', (s) => { s.grant.sig = flipChar(s.grant.sig); return rej(['chain']); });
add('grant-key-reorder-only', 'chain', (s) => { s.grant = Object.fromEntries(Object.entries(s.grant).reverse()); return {}; });

// --- Ed25519 strictness: malleability + small-order key forgeries (TS verifier is strict RFC 8032)
const L_ORDER = 7237005577332262213973186563042994240857116359379907606001950938285454250989n;
const addL = (sigB64: string) => {
  const b = pca.unb64u(sigB64);
  let sv = 0n; for (let i = 31; i >= 0; i--) sv = (sv << 8n) | BigInt(b[32 + i]!);
  sv += L_ORDER;
  if (sv >= 1n << 256n) throw new Error('skip');
  const o = new Uint8Array(b); for (let i = 0; i < 32; i++) { o[32 + i] = Number(sv & 0xffn); sv >>= 8n; }
  return pca.b64u(o);
};
const SMALL_ORDER: Record<string, Uint8Array> = {
  identity: Uint8Array.from([1, ...new Array(31).fill(0)]),
  order2: Uint8Array.from([0xec, ...new Array(30).fill(0xff), 0x7f]),
  identityNoncanonY: Uint8Array.from([0xee, ...new Array(30).fill(0xff), 0x7f]), // y = p+1 == 1 (non-canonical encoding)
};
add('sig-S-plus-L-malleable', 'ed25519', (s) => { s.pc.sig = addL(s.pc.sig); return rej(['leaf_signature']); });
add('chain-hop-sig-S-plus-L', 'ed25519', (s) => { const i = int(s.pc.cap_chain.length); s.pc.cap_chain[i].sig = addL(s.pc.cap_chain[i].sig); return { breaks: ['chain'], mustReject: true, resign: true }; });
add('grant-and-root-sig-S-plus-L', 'ed25519', (s) => { s.grant = clone(s.grant); s.grant.sig = addL(s.grant.sig); s.pc.cap_chain[0].sig = s.grant.sig; return { breaks: ['chain'], mustReject: true, resign: true }; });
for (const [nm, pt] of Object.entries(SMALL_ORDER)) {
  add(`forge-leaf-small-order-holder-${nm}`, 'ed25519', (s) => {
    const principal = POOL.find((p) => p.pub === s.pc.cap_chain[0].issuer)!;
    const holderPub = pca.b64u(pt);
    const root = sealHop(null, principal, holderPub, []);
    const base = makeBase({ depth: 1, caveatsFor: () => [] });
    const pcBody = clone(base.pc); pcBody.cap_chain = [root]; pcBody.grant_ref = root.id;
    pcBody.sig = pca.b64u(new Uint8Array([...pt, ...new Array(32).fill(0)])); // R = small-order point, S = 0
    Object.assign(s, { pc: pcBody, grant: root, base });
    return { breaks: ['leaf_signature'], mustReject: true };
  });
  add(`forge-leaf-small-order-holder-${nm}-R-torsion-sig`, 'ed25519', (s) => {
    const principal = POOL.find((p) => p.pub === s.pc.cap_chain[0].issuer)!;
    const root = sealHop(null, principal, pca.b64u(pt), []);
    const base = makeBase({ depth: 1, caveatsFor: () => [] });
    const pcBody = clone(base.pc); pcBody.cap_chain = [root]; pcBody.grant_ref = root.id;
    pcBody.sig = pca.b64u(new Uint8Array([...SMALL_ORDER.identity!, ...new Array(32).fill(0)]));
    Object.assign(s, { pc: pcBody, grant: root, base });
    return { breaks: ['leaf_signature'], mustReject: true };
  });
}
add('forge-hop-small-order-root-issuer', 'ed25519', (s) => { // root issuer = identity point, hop sig = (identity, 0): forged principal
  const pt = SMALL_ORDER.identity!;
  const issuerPub = pca.b64u(pt);
  const holder = pick(POOL);
  const body = { issuer: issuerPub, holder: holder.pub, caveats: [] as unknown[], parent: null };
  const body_digest = pca.hashCanonical(body);
  const root = { id: body_digest, issuer: issuerPub, holder: holder.pub, caveats: [], body_digest, sig: pca.b64u(new Uint8Array([...pt, ...new Array(32).fill(0)])) };
  const base = makeBase({ depth: 1, caveatsFor: () => [] });
  const pcBody = clone(base.pc); pcBody.cap_chain = [root]; pcBody.grant_ref = root.id; pcBody.sig = leafSign(pcBody, holder);
  Object.assign(s, { pc: pcBody, grant: root, base: { ...base, holders: [holder] } });
  return { breaks: ['chain'], mustReject: true };
});

// --- mixed-order (honest key + torsion) forgeries: a verifier that only checks the equation or only cofactored-verifies accepts these
import { ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
const EdP = ed25519.ExtendedPoint;
const hexb = (h: string) => Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));
const TORSION: Record<string, Uint8Array> = {
  order8: hexb('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'),
  order4: new Uint8Array(32),
  order2: SMALL_ORDER.order2!,
};
const Lq = ed25519.CURVE.n;
const leToBig = (b: Uint8Array) => { let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]!); return v; };
const bigToLe = (v: bigint, n: number) => { const o = new Uint8Array(n); for (let i = 0; i < n; i++) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; };
// Sign `msg` so that the cofactored equation holds for pubkey `aPrime` (= A + T) and nonce point `rPoint` (+ optional T): S = r + k*a.
function craftSig(key: Key, msg: Uint8Array, tPub: Uint8Array | null, tR: Uint8Array | null): { pub: Uint8Array; sig: Uint8Array } {
  const ext = ed25519.utils.getExtendedPublicKey(key.sk);
  const A = EdP.fromHex(pca.unb64u(key.pub));
  const Ap = tPub ? A.add(EdP.fromHex(tPub)) : A;
  const r = leToBig(sha512(new Uint8Array([...key.sk, ...msg]))) % Lq || 1n;
  let R = EdP.BASE.multiply(r);
  if (tR) R = R.add(EdP.fromHex(tR));
  const Rb = R.toRawBytes(), Ab = Ap.toRawBytes();
  const k = leToBig(sha512(new Uint8Array([...Rb, ...Ab, ...msg]))) % Lq;
  const S = (r + k * ext.scalar) % Lq;
  return { pub: Ab, sig: new Uint8Array([...Rb, ...bigToLe(S, 32)]) };
}
for (const [tn, T] of Object.entries(TORSION)) {
  for (const mode of ['pub', 'R', 'both'] as const) {
    add(`forge-mixed-order-${mode}-${tn}`, 'ed25519', (s) => {
      const holderKey = pick(POOL);
      const principal = pick(POOL);
      // two-pass: the holder key (and so the root hop / grant_ref) depends on A+T, which does not depend on the message
      const probe = craftSig(holderKey, new Uint8Array(1), mode === 'R' ? null : T, null);
      const root = sealHop(null, principal, pca.b64u(probe.pub), []);
      const base = makeBase({ depth: 1, caveatsFor: () => [] });
      const pcBody = clone(base.pc); pcBody.cap_chain = [root]; pcBody.grant_ref = root.id;
      const crafted = craftSig(holderKey, pca.thresholdMessage((({ sig: _s, threshold: _t, ...b }) => P(b))(pcBody) as any), mode === 'R' ? null : T, mode === 'pub' ? null : T);
      pcBody.sig = pca.b64u(crafted.sig);
      Object.assign(s, { pc: pcBody, grant: root, base });
      return { breaks: ['leaf_signature'], mustReject: true };
    });
  }
}

// --- Merkle proof tamper (resigned so only inclusion can object)
const proof = (s: St) => s.pc.plan.inclusion_proof;
const PR = (f: (s: St, p: any) => void, name: string, br = true) => add(name, 'merkle', (s) => { f(s, proof(s)); return { breaks: br ? ['plan_inclusion'] : undefined, mustReject: br || undefined, resign: true }; });
PR((s, p) => { p.index += 1; }, 'proof-index-plus1');
PR((s, p) => { p.index -= 1; }, 'proof-index-minus1');
PR((s, p) => { p.index = -1; }, 'proof-index-negative');
PR((s, p) => { p.index = p.size; }, 'proof-index-eq-size');
PR((s, p) => { p.size += 1; }, 'proof-size-plus1', false); // size is NOT committed by the root: a shape-preserving size change still verifies
PR((s, p) => { p.size -= 1; }, 'proof-size-minus1', false);
PR((s, p) => { p.size = 0; }, 'proof-size-zero');
PR((s, p) => { p.index = pick([0.5, '1', null, true, [0], 1e300]); }, 'proof-index-badtype');
PR((s, p) => { p.size = pick([1.5, '3', null, 1e300, -1]); }, 'proof-size-badtype');
PR((s, p) => { p.index = raw(pick(['1.0', '1e0', String(p.index) + '.0', String(p.index) + 'e0'])); }, 'proof-index-float-literal');
PR((s, p) => { p.size = raw(String(p.size) + '.0'); }, 'proof-size-float-literal');
PR((s, p) => { p.index = raw('9007199254740993'); }, 'proof-index-unsafe');
PR((s, p) => { p.size = raw('9007199254740993'); }, 'proof-size-unsafe');
PR((s, p) => { delete p.index; }, 'proof-index-missing');
PR((s, p) => { delete p.size; }, 'proof-size-missing');
PR((s, p) => { delete p.path; }, 'proof-path-missing');
PR((s, p) => { p.path = pick([null, {}, 'x', 0]); }, 'proof-path-badtype');
PR((s, p) => { p.path.push({ side: 'L', hash: pca.paramsDigest() }); }, 'proof-path-extend');
PR((s, p) => { p.path.pop(); }, 'proof-path-truncate');
PR((s, p) => { p.path.reverse(); if (p.path.length < 2) throw new Error('skip'); }, 'proof-path-reverse', false);
PR((s, p) => { p.path[int(p.path.length)].hash = flipChar(p.path[0].hash); }, 'proof-sibling-flip-char');
PR((s, p) => { const i = int(p.path.length); p.path[i].hash = flipBit(p.path[i].hash); }, 'proof-sibling-flip-bit');
PR((s, p) => { const i = int(p.path.length); p.path[i].hash = p.path[i].hash.slice(0, 40); }, 'proof-sibling-truncate');
PR((s, p) => { const i = int(p.path.length); p.path[i].hash = p.path[i].hash + 'AAAA'; }, 'proof-sibling-extend');
PR((s, p) => { const i = int(p.path.length); p.path[i].hash = pca.b64u(new Uint8Array(33)); }, 'proof-sibling-33bytes');
PR((s, p) => { const i = int(p.path.length); p.path[i].hash = pick(['', '!!!', pick(WORDS)]); }, 'proof-sibling-garbage');
PR((s, p) => { const i = int(p.path.length); p.path[i].side = p.path[i].side === 'L' ? 'R' : 'L'; }, 'proof-side-flip');
PR((s, p) => { const i = int(p.path.length); p.path[i].side = pick(['l', 'r', 'X', '', null, 0]); }, 'proof-side-garbage');
PR((s, p) => { const i = int(p.path.length); delete p.path[i].side; }, 'proof-side-missing');
PR((s, p) => { const i = int(p.path.length); delete p.path[i].hash; }, 'proof-hash-missing');
PR((s, p) => { const i = int(p.path.length); const t = nonCanonTail(p.path[i].hash); if (!t) throw new Error('skip'); p.path[i].hash = t; }, 'proof-sibling-noncanonical-tail');
PR((s, p) => { const i = int(p.path.length); p.path[i] = null; }, 'proof-step-null');
PR((s, p) => { p.path[int(p.path.length)].hash = proof(s).path[0].hash; }, 'proof-sibling-swap', false);
add('proof-tamper-nosign', 'merkle', (s) => { proof(s).index += 1; return rej(['plan_inclusion', 'leaf_signature']); });
add('proof-extra-fields', 'merkle', (s) => { proof(s).extra = 1; proof(s).path.forEach((x: any) => (x.extra = 'e')); return { resign: true }; });
add('proof-step-hash-from-other-leaf', 'merkle', (s) => {
  const others = s.base.nodes.filter((n) => n.id !== s.base.nodeId);
  if (!others.length) throw new Error('skip');
  const cp = pca.commitPlan(s.base.nodes);
  s.pc.plan.inclusion_proof = cp.proofFor(pick(others).id);
  return { breaks: ['plan_inclusion'], mustReject: true, resign: true };
});

// --- chain splicing / tamper (resigned leaf where needed)
const hopSigFlip = (s: St, i: number) => { s.pc.cap_chain[i].sig = flipChar(s.pc.cap_chain[i].sig); };
add('chain-hop-sig-flip', 'chain', (s) => { hopSigFlip(s, int(s.pc.cap_chain.length)); return { breaks: ['chain'], mustReject: true, resign: true }; });
add('chain-hop-sig-bit', 'chain', (s) => { const i = int(s.pc.cap_chain.length); s.pc.cap_chain[i].sig = flipBit(s.pc.cap_chain[i].sig); return { breaks: ['chain'], mustReject: true, resign: true }; });
for (const f of ['id', 'issuer', 'holder', 'body_digest', 'parent']) {
  add(`chain-hop-${f}-flip`, 'chain', (s) => { const i = f === 'parent' ? 1 : int(s.pc.cap_chain.length); const h = s.pc.cap_chain[i]; if (typeof h?.[f] !== 'string') throw new Error('skip'); h[f] = flipChar(h[f]); return { breaks: ['chain'], mustReject: true, resign: true }; }, f === 'parent' ? 2 : 1);
}
add('chain-hop-caveat-injected', 'chain', (s) => { const i = int(s.pc.cap_chain.length); s.pc.cap_chain[i].caveats.push({ type: 'inj' }); return { breaks: ['chain'], mustReject: true, resign: true }; });
add('chain-hop-caveat-field-flip', 'chain', (s) => { const i = int(s.pc.cap_chain.length); const h = s.pc.cap_chain[i]; if (!h.caveats.length) { h.caveats.push({ type: 't' }); } else h.caveats[0].zz = 1; return { breaks: ['chain'], mustReject: true, resign: true }; });
add('chain-hop-missing-field', 'chain', (s) => { const i = int(s.pc.cap_chain.length); delete s.pc.cap_chain[i][pick(['id', 'issuer', 'holder', 'caveats', 'body_digest', 'sig'])]; return { breaks: ['chain'], mustReject: true, resign: true }; });
add('chain-hop-caveats-nonarray', 'chain', (s) => { const i = int(s.pc.cap_chain.length); s.pc.cap_chain[i].caveats = pick([null, {}, 'x', 0]); return { breaks: ['chain'], mustReject: true, resign: true }; });
add('chain-hop-caveat-notobject', 'chain', (s) => { const i = int(s.pc.cap_chain.length); s.pc.cap_chain[i].caveats.push(pick(['x', 1, null, [], true])); return { breaks: ['chain'], mustReject: true, resign: true }; });
add('chain-hop-caveat-no-type', 'chain', (s) => { const i = int(s.pc.cap_chain.length); s.pc.cap_chain[i].caveats.push({ a: 1 }); return { breaks: ['chain'], mustReject: true, resign: true }; });
add('chain-root-has-parent', 'chain', (s) => { s.pc.cap_chain[0].parent = pca.paramsDigest(); return { breaks: ['chain'], mustReject: true, resign: true }; });
add('chain-drop-hop', 'chain', (s) => { s.pc.cap_chain.splice(1 + int(s.pc.cap_chain.length - 2), 1); return { breaks: ['chain'], mustReject: true, resign: true }; }, 3);
add('chain-drop-leaf-hop', 'chain', (s) => { s.pc.cap_chain.pop(); return { resign: true }; }, 2);
add('chain-dup-hop', 'chain', (s) => { const i = int(s.pc.cap_chain.length); s.pc.cap_chain.splice(i, 0, clone(s.pc.cap_chain[i])); return { breaks: ['chain'], mustReject: true, resign: true }; });
add('chain-reorder', 'chain', (s) => { s.pc.cap_chain.reverse(); return { breaks: ['chain'], mustReject: true, resign: true }; }, 2);
add('chain-empty', 'chain', (s) => { s.pc.cap_chain = []; return { breaks: ['chain', 'leaf_signature'], mustReject: true, resign: true }; });
add('chain-foreign-hop', 'chain', (s) => { const other = makeBase({ depth: s.pc.cap_chain.length }); const i = int(s.pc.cap_chain.length); s.pc.cap_chain[i] = other.chain[i]; return { breaks: ['chain'], mustReject: true, resign: true }; });
add('chain-extra-unsigned-hop', 'chain', (s) => { s.pc.cap_chain.push({ ...clone(s.pc.cap_chain[s.pc.cap_chain.length - 1]), parent: pca.paramsDigest() }); return { breaks: ['chain'], mustReject: true, resign: true }; });
add('chain-self-delegation-valid', 'chain', (s) => { // legal: append hop to same holder, resign leaf with same key
  const last = s.pc.cap_chain[s.pc.cap_chain.length - 1];
  const key = s.base.holders[s.base.holders.length - 1]!;
  s.pc.cap_chain.push(sealHop(last, key, key.pub, [...last.caveats, { type: 'extra-valid' }]));
  return { resign: true };
});
add('chain-leaf-wrong-signer-rogue', 'sig', (s) => ({ breaks: ['leaf_signature'], mustReject: true, resign: ROGUE }));
add('chain-leaf-signed-by-issuer', 'sig', (s) => { const k = s.base.holders[s.base.holders.length - 2] ?? POOL.find((p) => p.pub === s.pc.cap_chain[0].issuer) ?? ROGUE; if (k.pub === s.base.holders[s.base.holders.length - 1]!.pub) throw new Error('skip'); return { breaks: ['leaf_signature'], mustReject: true, resign: k }; });
add('chain-too-long-17', 'chain', (s) => { const b = makeBase({ depth: 17, caveatsFor: () => [] }); Object.assign(s, { pc: b.pc, grant: b.grant, base: b }); return { breaks: ['chain'], mustReject: true }; });
add('chain-exact-16-valid', 'chain', (s) => { const b = makeBase({ depth: 16, caveatsFor: () => [] }); Object.assign(s, { pc: b.pc, grant: b.grant, base: b }); return {}; });
add('chain-deep-caveat-growth-valid', 'chain', (s) => { const b = makeBase({ depth: 8, caveatsFor: (h) => [{ type: `c${h}`, n: raw(pick(EDGE_NUMS.slice(0, 20))) }] }); Object.assign(s, { pc: b.pc, grant: b.grant, base: b }); return {}; });

// widen / alter caveats in the leaf hop with a VALID signature (only attenuation can catch it)
const resealLeaf = (s: St, mk: (parentCaveats: any[]) => any[]) => {
  const n = s.pc.cap_chain.length;
  const parent = s.pc.cap_chain[n - 2];
  const issuer = s.base.holders[n - 2]!;
  s.pc.cap_chain[n - 1] = sealHop(parent, issuer, s.base.holders[n - 1]!.pub, mk(clone(parent.caveats)));
};
add('caveat-widen-edit', 'caveat', (s) => { resealLeaf(s, (c) => { if (!c.length) throw new Error('skip'); const k = Object.keys(c[0]).filter((x) => x !== 'type'); if (k.length) c[0][k[0]!] = randVal(); else c[0].widened = true; return [...c, { type: 'tail' }]; }); return { breaks: ['chain'], mustReject: true, resign: true }; }, 2);
add('caveat-widen-drop', 'caveat', (s) => { resealLeaf(s, (c) => { if (!c.length) throw new Error('skip'); c.splice(int(c.length), 1); return c; }); return { breaks: ['chain'], mustReject: true, resign: true }; }, 2);
add('caveat-widen-reorder', 'caveat', (s) => { resealLeaf(s, (c) => { if (c.length < 2) throw new Error('skip'); c.reverse(); return c; }); return { breaks: ['chain'], mustReject: true, resign: true }; }, 2);
add('caveat-widen-replace-all', 'caveat', (s) => { resealLeaf(s, (c) => { if (!c.length) throw new Error('skip'); return [{ type: 'allow_all' }]; }); return { breaks: ['chain'], mustReject: true, resign: true }; }, 2);
add('caveat-widen-key-added-to-existing', 'caveat', (s) => { resealLeaf(s, (c) => { if (!c.length) throw new Error('skip'); c[0].extra = 1; return c; }); return { breaks: ['chain'], mustReject: true, resign: true }; }, 2);
add('caveat-attenuate-append-valid', 'caveat', (s) => { resealLeaf(s, (c) => [...c, randCaveat()]); return { resign: true }; }, 2);
add('caveat-key-order-only-valid', 'caveat', (s) => { resealLeaf(s, (c) => c.map((x: any) => Object.fromEntries(Object.entries(x).reverse()))); return { resign: true }; }, 2);

// --- canonicalization edge values inside SIGNED caveats (valid signatures; no expected verdict beyond oracle)
function withEdgeCaveat(s: St, cav: Record<string, unknown>) {
  const depth = pick([1, 2]);
  try {
    const b = makeBase({ depth, caveatsFor: (h) => (h === 0 ? [cav] : []) });
    Object.assign(s, { pc: b.pc, grant: b.grant, base: b });
  } catch {
    // The value is outside the strict profile (so the reference cannot even hash it): build a clean base and splice the
    // literal text in. The PCActn is then (correctly) a wire failure everywhere; the stale signature is irrelevant.
    const b = makeBase({ depth, caveatsFor: (h) => (h === 0 ? [{ type: 'n' }] : []) });
    Object.assign(s, { pc: b.pc, grant: b.grant, base: b });
    const ct = rawText(cav);
    s.textPatch = (t) => t.split('"caveats":[{"type":"n"}]').join(`"caveats":[${ct}]`); // grant keeps the clean placeholder (it is never consulted once the wire check fails)
  }
}
add('edge-number-in-caveat', 'canon', (s) => { withEdgeCaveat(s, { type: 'n', v: raw(pick(EDGE_NUMS)), w: [raw(pick(EDGE_NUMS)), raw(pick(EDGE_NUMS))] }); return {}; });
add('edge-number-in-caveat-deep', 'canon', (s) => { withEdgeCaveat(s, { type: 'n', o: { p: { q: raw(pick(EDGE_NUMS)) } } }); return {}; });
add('edge-string-in-caveat', 'canon', (s) => { withEdgeCaveat(s, { type: 's', v: raw(pick(EDGE_STRS)) }); return {}; });
add('edge-string-as-type', 'canon', (s) => { withEdgeCaveat(s, { type: raw(pick(EDGE_STRS)) }); return {}; });
add('edge-keys-in-caveat', 'canon', (s) => { const c: Record<string, unknown> = { type: 'k' }; for (let i = 0; i < 2 + int(5); i++) c[pick(EDGE_KEYS)] = int(9); withEdgeCaveat(s, c); return {}; });
add('edge-keys-all', 'canon', (s) => { const c: Record<string, unknown> = { type: 'k' }; for (const k of EDGE_KEYS) c[k] = k.length; withEdgeCaveat(s, c); return {}; });
add('edge-dupkey-in-caveat', 'canon', (s) => { withEdgeCaveat(s, raw(`{"type":"d","a":${int(9)},"a":${int(9)},"b":1}`) as any); return {}; });
add('edge-escaped-key-caveat', 'canon', (s) => { withEdgeCaveat(s, raw('{"type":"e","\\u0061":1,"\\ud83d\\ude00":2,"\\/":3}') as any); return {}; });
add('edge-deep-nest-caveat-50', 'canon', (s) => { let v: any = 1; for (let i = 0; i < 50; i++) v = i % 2 ? { a: v } : [v]; withEdgeCaveat(s, { type: 'deep', v }); return {}; });
add('edge-deep-nest-caveat-300', 'canon', (s) => { let v: any = 1; for (let i = 0; i < 300; i++) v = i % 2 ? { a: v } : [v]; withEdgeCaveat(s, { type: 'deep', v }); return {}; });
add('edge-deep-nest-caveat-1200', 'canon', (s) => { let v: any = 1; for (let i = 0; i < 1200; i++) v = i % 2 ? { a: v } : [v]; withEdgeCaveat(s, { type: 'deep', v }); return {}; });
add('edge-big-string-caveat', 'canon', (s) => { withEdgeCaveat(s, { type: 'big', v: 'é😀'.repeat(20000) }); return {}; });
add('edge-many-caveats', 'canon', (s) => { const b = makeBase({ depth: 1, caveatsFor: () => Array.from({ length: 500 }, (_, i) => ({ type: 't', i })) }); Object.assign(s, { pc: b.pc, grant: b.grant, base: b }); return {}; });
add('edge-oversized-resource-resigned', 'canon', (s) => { s.pc.action.resource = 'r'.repeat(200000); return { breaks: ['plan_inclusion'], mustReject: true, resign: true }; });
add('edge-empty-strings-resigned', 'canon', (s) => { s.pc.action.verb = ''; s.pc.action.resource = ''; return { breaks: ['plan_inclusion'], mustReject: true, resign: true }; });
add('edge-unicode-action-resigned', 'canon', (s) => { s.pc.action.verb = pick(WORDS); return { resign: true }; });

// --- number representations at numeric signed fields
for (const f of ['counter', 'ver', 'proof.size', 'proof.index', 'risk_claim.r', 'attestation.epoch', 'taint', 'iat', 'exp', 'freshness.epoch']) {
  add(`edge-numeric-${f}`, 'numeric', (s) => {
    const lit = raw(pick(EDGE_NUMS));
    if (f === 'counter') s.pc.counter = lit;
    else if (f === 'ver') { s.pc.ver = raw(pick(['2.0', '2e0', '20e-1', '0.2e1', '2.00', '2E0', '2e+0', '02', '+2'])); return { mustReject: true, resign: true }; }
    else if (f === 'proof.size') s.pc.plan.inclusion_proof.size = raw(String(s.pc.plan.inclusion_proof.size) + pick(['.0', 'e0', '.00', 'E0']));
    else if (f === 'proof.index') s.pc.plan.inclusion_proof.index = raw(String(s.pc.plan.inclusion_proof.index) + pick(['.0', 'e0', '.00', 'E0']));
    else if (f === 'iat' || f === 'exp') s.pc[f] = lit;
    else if (f === 'freshness.epoch') s.pc.freshness.epoch = lit;
    else if (f === 'risk_claim.r') s.pc.risk_claim.r = lit;
    else if (f === 'attestation.epoch') s.pc.attestation.epoch = lit;
    else s.pc.provenance.taint_level = lit;
    return { resign: true };
  });
}
for (const lit of ['-0', '0', '1.0', '7.0', '7e0', '70e-1', '2147483648', '4294967296', '9007199254740991', '9007199254740992', '9007199254740993', '18446744073709551616', '1e21', '1e22', '1.5', '-1', '-0.0', '1e400', '"7"', 'null', 'true', '[]', '{}']) {
  add(`counter-literal-${lit.replace(/[^a-z0-9]/gi, '_')}`, 'numeric', (s) => { s.pc.counter = raw(lit); return { resign: true }; });
}

// --- v2 freshness binding + optional signed slots
const FR = (name: string, fn: (s: St) => MutResult | null) => add(name, 'fresh', fn);
FR('aud-other-resigned', (s) => { s.pc.aud = pick(['rs-other', AUD + 'x', 'x' + AUD, AUD.toUpperCase(), AUD + ' ', ' ' + AUD, AUD.slice(0, -1), 'rs\u2011fuzz', 'rs-fuz\u0455']); return { breaks: ['audience'], mustReject: true, resign: true }; });
FR('aud-other-nosign', (s) => { s.pc.aud = 'rs-other'; return { breaks: ['audience', 'leaf_signature'], mustReject: true }; });
FR('aud-bad-resigned', (s) => { s.pc.aud = pick(['', null, 0, [], {}, 'a'.repeat(257), 'a'.repeat(1000)]); return { mustReject: true, resign: true }; });
FR('aud-len-boundary', (s) => { s.pc.aud = 'a'.repeat(pick([255, 256, 257])); return { breaks: ['audience'], mustReject: true, resign: true }; });
FR('aud-astral-len-boundary', (s) => { s.pc.aud = (chance(0.5) ? '\u{1F600}'.repeat(pick([63, 64, 65])) : '\u00e9'.repeat(pick([127, 128, 129]))); return { breaks: ['audience'], mustReject: true, resign: true }; });
FR('aud-nfd-vs-nfc', (s) => { s.pc.aud = 'caf\u00e9'; return { breaks: ['audience'], mustReject: true, resign: true }; });
FR('expired-resigned', (s) => { const L = pick([1000, 600_000, 3_600_000]); s.pc.exp = NOW - pick([1, 2, 1000, 86_400_000]); s.pc.iat = s.pc.exp - L; return { breaks: ['validity'], mustReject: true, resign: true }; });
FR('expired-nosign', (s) => { s.pc.exp = NOW - 1; s.pc.iat = NOW - 1001; return { breaks: ['validity', 'leaf_signature'], mustReject: true }; });
FR('exp-boundary-valid', (s) => { s.pc.exp = NOW; s.pc.iat = NOW - pick([1, 1000, 3_600_000]); return { resign: true }; }); // now == exp is NOT expired
FR('exp-boundary-expired', (s) => { s.pc.exp = NOW - 1; s.pc.iat = NOW - pick([2, 1000, 3_600_000]); return { breaks: ['validity'], mustReject: true, resign: true }; });
FR('iat-future-boundary-valid', (s) => { s.pc.iat = NOW + 60_000; s.pc.exp = s.pc.iat + pick([1, 1000, 3_600_000]); return { resign: true }; });
FR('iat-future-too-far', (s) => { s.pc.iat = NOW + pick([60_001, 61_000, 3_600_000]); s.pc.exp = s.pc.iat + pick([1, 1000]); return { breaks: ['validity'], mustReject: true, resign: true }; });
FR('lifetime-boundary', (s) => { const L = pick([3_599_999, 3_600_000, 3_600_001, 7_200_000]); s.pc.iat = NOW - 1; s.pc.exp = s.pc.iat + L; return L > 3_600_000 ? { breaks: ['validity'], mustReject: true, resign: true } : { resign: true }; });
FR('exp-le-iat', (s) => { const d = pick([0, -1, -1000]); s.pc.iat = NOW - 5; s.pc.exp = s.pc.iat + d; return { breaks: ['validity'], mustReject: true, resign: true }; });
FR('seconds-not-ms', (s) => { s.pc.iat = Math.floor((NOW - 100) / 1000); s.pc.exp = s.pc.iat + 600; return { breaks: ['validity'], mustReject: true, resign: true }; });
FR('iat-exp-badtype', (s) => { const f = pick(['iat', 'exp']); s.pc[f] = pick([null, '1800000000000', true, [], {}, 1.5, -1, raw('1800000000000.0'), raw('1.8e12'), raw('9007199254740993'), raw('-0')]); return { mustReject: true, resign: true }; });
FR('iat-exp-unsafe-int', (s) => { s.pc.iat = raw('9007199254740992'); s.pc.exp = raw('9007199254740993'); return { mustReject: true, resign: true }; });
FR('iat-exp-negative', (s) => { s.pc.iat = -pick([1, 1000]); s.pc.exp = s.pc.iat + 1000; return { breaks: ['validity'], mustReject: true, resign: true }; });
FR('nonce-bad', (s) => { s.pc.nonce = pick(['', null, 0, [], {}, 'n'.repeat(129), 'n'.repeat(400)]); return { mustReject: true, resign: true }; });
FR('nonce-len-boundary', (s) => { s.pc.nonce = 'n'.repeat(pick([127, 128, 129])); return { resign: true }; });
FR('nonce-astral-len-boundary', (s) => { s.pc.nonce = (chance(0.5) ? '\u{1F600}'.repeat(pick([31, 32, 33])) : '\u00e9'.repeat(pick([63, 64, 65]))); return { resign: true }; });
FR('nonce-present-valid', (s) => { s.pc.nonce = pick(['x', 'é', '日本語', '\u0001', 'a"b\\c', '\u{1F600}']); return { resign: true }; });
FR('nonce-nosign', (s) => { s.pc.nonce = 'forged'; return { breaks: ['leaf_signature'], mustReject: true }; });
FR('caution-bad', (s) => { s.pc.caution = pick([-0.1, 1.1, 2, -1, '0.5', null, true, [], {}, raw('1.0'), raw('0.50'), raw('5e-1'), raw('NaN')]); return { mustReject: true, resign: true }; });
FR('caution-valid', (s) => { s.pc.caution = pick([0, 1, 0.5, 0.000001, 0.999999, 0.123456789012345]); return { resign: true }; });
FR('caution-nosign', (s) => { s.pc.caution = 0.5; return { breaks: ['leaf_signature'], mustReject: true }; });
FR('slot-b64-bad', (s) => { const f = pick(['rationale_commitment', 'tool_binding']); const v = pca.paramsDigest({ z: 1 }); s.pc[f] = pick([v.slice(0, 40), v + 'A', nonCanonTail(v) ?? v + 'A', '', 5, null, v.replace(/./, '=')]); return { mustReject: true, resign: true }; });
FR('slot-b64-valid', (s) => { s.pc.rationale_commitment = pca.paramsDigest({ a: randStr() }); s.pc.tool_binding = pca.paramsDigest({ b: randStr() }); return { resign: true }; });
FR('slot-nosign', (s) => { s.pc[pick(['rationale_commitment', 'tool_binding'])] = pca.paramsDigest({ q: 1 }); return { breaks: ['leaf_signature'], mustReject: true }; });
FR('progress-prohibition-types', (s) => { const w = int(4); if (w === 0) s.pc.progress_step = pick([[], 'x', 5, null, true]); else if (w === 1) s.pc.prohibition_evidence = pick(['x', 5, null, true]); else if (w === 2) s.pc.progress_step = { a: randVal(1), b: [randVal(1)] }; else s.pc.prohibition_evidence = pick([{}, [], [1, 'a', null]]); return w < 2 ? { mustReject: true, resign: true } : { resign: true }; });
FR('optional-unknown-key', (s) => { s.pc[pick(['Nonce', 'NONCE', 'nonce ', 'caution_', 'aud2', 'exp_', 'x-slot', 'rationale'])] = 'x'; return { mustReject: true, resign: true }; });
FR('threshold-valid-unsigned', (s) => { s.pc.threshold = { shares: [{ role: pick(['guardian', 'principal']), publicKey: pca.paramsDigest({ g: int(5) }), sig: pca.b64u(new Uint8Array(64).fill(7)) }] }; return {}; }); // threshold is NOT signed: leaf sig must still verify
FR('threshold-bad', (s) => { const sh = { role: 'guardian', publicKey: pca.paramsDigest({ g: 1 }), sig: pca.b64u(new Uint8Array(64).fill(1)) }; const w = int(6); if (w === 0) s.pc.threshold = { shares: [{ ...sh, publicKey: 'AAAA' }] }; else if (w === 1) s.pc.threshold = { shares: [{ ...sh, sig: nonCanonTail(sh.sig) ?? 'A' }] }; else if (w === 2) s.pc.threshold = { shares: [{ ...sh, role: 5 }] }; else if (w === 3) s.pc.threshold = { shares: 'x' }; else if (w === 4) s.pc.threshold = []; else s.pc.threshold = null; return { mustReject: true }; });
FR('threshold-with-tampered-body', (s) => { s.pc.threshold = { shares: [] }; s.pc.counter += 1; return { breaks: ['leaf_signature'], mustReject: true }; });
FR('zk-bond-types', (s) => { s.pc.bond_ref = pick([5, null, [], {}]); return { mustReject: undefined, resign: true }; }); // bond_ref type is NOT constrained by wire v2: oracle decides
FR('edge-deep-nest-inputs', (s) => { const d = 24 + int(10); let v: any = 1; for (let i = 0; i < d; i++) v = i % 2 ? { a: v } : [v]; s.pc.risk_claim.inputs = { v }; return { resign: true }; });
FR('edge-deep-nest-progress', (s) => { const d = 24 + int(10); let v: any = 1; for (let i = 0; i < d; i++) v = i % 2 ? { a: v } : [v]; s.pc.progress_step = { v }; return { resign: true }; });
FR('slot-number-edge', (s) => { s.pc.risk_claim.inputs = { a: raw(pick(EDGE_NUMS)), b: [raw(pick(EDGE_NUMS))] }; return { resign: true }; });
FR('taint-edge', (s) => { s.pc.provenance.taint_level = raw(pick(['0', '1', '0.5', '0.25', '2', '-1', '1e0', '1.0', '0.1234567890123456', '9007199254740993'])); return { resign: true }; });
FR('attestation-types', (s) => { const f = pick(['quote_digest', 'model_id', 'measurement', 'operator']); s.pc.attestation[f] = pick([5, null, [], {}, true]); return { mustReject: true, resign: true }; });
FR('attestation-epoch-bad', (s) => { s.pc.attestation.epoch = pick([-1, 1.5, '0', null, raw('1.0'), raw('9007199254740993')]); return { mustReject: typeof s.pc.attestation.epoch === 'number' && s.pc.attestation.epoch === -1 ? undefined : true, resign: true }; });
FR('provenance-bad', (s) => { const w = int(4); if (w === 0) s.pc.provenance.trusted_refs = [1]; else if (w === 1) s.pc.provenance.trusted_refs = 'x'; else if (w === 2) s.pc.provenance.causal_hash = 5; else s.pc.provenance.taint_level = '0'; return { mustReject: true, resign: true }; });
FR('freshness-bad', (s) => { const w = int(4); if (w === 0) s.pc.freshness.epoch = 1.5; else if (w === 1) s.pc.freshness.beacon_ref = 5; else if (w === 2) s.pc.freshness.accumulator_witness = null; else s.pc.freshness.epoch = '0'; return { mustReject: true, resign: true }; });
FR('risk-claim-bad', (s) => { const w = int(3); if (w === 0) s.pc.risk_claim.r = '0'; else if (w === 1) s.pc.risk_claim.inputs = []; else s.pc.risk_claim.inputs = null; return { mustReject: true, resign: true }; });
FR('action-field-types', (s) => { s.pc.action[pick(['verb', 'resource', 'reversibility_class'])] = pick([5, null, [], {}, true]); return { mustReject: true, resign: true }; });
FR('plan-field-bad', (s) => { const w = int(3); if (w === 0) s.pc.plan.node_id = 5; else if (w === 1) s.pc.plan.root = nonCanonTail(s.pc.plan.root) ?? 'A'; else s.pc.plan.extra = 1; return { mustReject: true, resign: true }; });
FR('cap-hop-b64-bad', (s) => { const i = int(s.pc.cap_chain.length); const f = pick(['id', 'issuer', 'holder', 'body_digest', 'sig']); const v = s.pc.cap_chain[i][f]; s.pc.cap_chain[i][f] = pick([nonCanonTail(v) ?? v + 'A', v.slice(0, -2), v + '=', '', 5, null]); return { breaks: ['chain'], mustReject: true, resign: true }; });
FR('cap-hop-parent-bad', (s) => { const i = 1; if (s.pc.cap_chain.length < 2) throw new Error('skip'); s.pc.cap_chain[i].parent = pick([5, '', null, s.pc.cap_chain[i].parent.slice(0, -1)]); return { breaks: ['chain'], mustReject: true, resign: true }; });
FR('cap-hop-extra-key', (s) => { s.pc.cap_chain[int(s.pc.cap_chain.length)][pick(['extra', 'Id', 'sig2', 'meta', ''])] = pick([1, 'x', null, {}]); return { mustReject: true, resign: true }; }); // hop key set is CLOSED // wire v2 does not close cap hop keys: oracle decides
FR('cap-hop-parent-null', (s) => { s.pc.cap_chain[int(s.pc.cap_chain.length)].parent = null; return { breaks: ['chain'], mustReject: true, resign: true }; });
FR('cap-caveat-type-bad', (s) => { const i = int(s.pc.cap_chain.length); s.pc.cap_chain[i].caveats.push(pick([{ type: 5 }, { type: null }, { type: [] }, {}])); return { breaks: ['chain'], mustReject: true, resign: true }; });
FR('plan-proof-side-case', (s) => { const p = s.pc.plan.inclusion_proof; if (!p.path.length) throw new Error('skip'); p.path[int(p.path.length)].side = pick(['l', 'r', 'LEFT', 'RIGHT', 'L ', ' R', 'LR', '0', '1']); return { mustReject: true, resign: true }; });
FR('plan-proof-step-extra-key', (s) => { const p = s.pc.plan.inclusion_proof; if (!p.path.length) throw new Error('skip'); p.path[int(p.path.length)].extra = 1; return { mustReject: true, resign: true }; });
FR('plan-proof-index-size-consistency', (s) => { const p = s.pc.plan.inclusion_proof; const w = int(4); if (w === 0) { p.size = p.size * 2; } else if (w === 1) { p.index = p.index + p.size; } else if (w === 2) { p.size = Math.max(1, p.size - 1); p.index = Math.min(p.index, p.size - 1); } else { p.size = p.size + 1; } return { resign: true }; });
FR('key-order-shuffled-valid', (s) => { s.pc = Object.fromEntries(Object.entries(s.pc).reverse()); return {}; });

// --- text-level patches (duplicate keys, invalid JSON)
const dupKey = (k: string, first: boolean) => (s: St) => {
  const orig = typeof s.pc === 'object' && s.pc && k in s.pc ? rawText(s.pc[k]) : null;
  if (orig === null) throw new Error('skip');
  const alt = k === 'counter' ? String(Number(orig) + 1) : k === 'ver' ? '1' : JSON.stringify('forged');
  s.textPatch = (t) => { const needle = `"${k}":${orig}`; const at = t.indexOf(needle); if (at < 0) return t; const dupe = first ? `"${k}":${alt},${needle}` : `${needle},"${k}":${alt}`; return t.slice(0, at) + dupe + t.slice(at + needle.length); };
  return { mustReject: true };
};
for (const k of ['counter', 'ver', 'grant_ref']) {
  add(`dupkey-${k}-last-wins-real`, 'dupkey', dupKey(k, true)); // real value last: JS sees original
  add(`dupkey-${k}-first-real`, 'dupkey', dupKey(k, false)); // real value first: JS sees forged
}
add('dupkey-sig', 'dupkey', (s) => { const orig = s.pc.sig; s.textPatch = (t) => t.replace(`"sig":"${orig}"`, `"sig":"${flipChar(orig)}","sig":"${orig}"`); return { mustReject: true }; });
const BADJSON: [string, (t: string) => string][] = [
  ['nan-literal', (t) => t.replace(/"counter":(\d+)/, '"counter":NaN')],
  ['infinity-literal', (t) => t.replace(/"counter":(\d+)/, '"counter":Infinity')],
  ['leading-zero', (t) => t.replace(/"counter":(\d+)/, '"counter":0$1')],
  ['plus-sign', (t) => t.replace(/"counter":(\d+)/, '"counter":+$1')],
  ['dot-prefix', (t) => t.replace(/"counter":(\d+)/, '"counter":.$1')],
  ['dot-suffix', (t) => t.replace(/"counter":(\d+)/, '"counter":$1.')],
  ['hex-number', (t) => t.replace(/"counter":(\d+)/, '"counter":0x$1')],
  ['trailing-comma-obj', (t) => t.replace('"ver":2', '"ver":2,')],
  ['trailing-comma-arr', (t) => t.replace('"trusted_refs":[]', '"trusted_refs":[,]')],
  ['single-quotes', (t) => t.replace('"ver"', "'ver'")],
  ['unquoted-key', (t) => t.replace('"ver"', 'ver')],
  ['comment', (t) => t.replace('"ver":2', '"ver":2/*c*/')],
  ['bom-prefix', (t) => '﻿' + t],
  ['trailing-garbage', (t) => t + 'x'],
  ['trailing-second-doc', (t) => t + t],
  ['nul-byte-in-string', (t) => t.replace('"operator":"unattested"', '"operator":"un\u0000attested"')],
  ['raw-newline-in-string', (t) => t.replace('"operator":"unattested"', '"operator":"un\nattested"')],
  ['raw-tab-in-string', (t) => t.replace('"operator":"unattested"', '"operator":"un\tattested"')],
  ['bad-escape', (t) => t.replace('"operator":"unattested"', '"operator":"un\\qattested"')],
  ['short-u-escape', (t) => t.replace('"operator":"unattested"', '"operator":"un\\u12attested"')],
  ['unterminated', (t) => t.slice(0, t.length - 3)],
  ['empty-doc', () => ''],
  ['whitespace-only', () => '  \n'],
  ['top-level-array', (t) => '[' + t + ']'],
  ['top-level-null', () => 'null'],
  ['top-level-number', () => '1'],
  ['negative-zero-int', (t) => t.replace(/"counter":(\d+)/, '"counter":-0')],
  ['exp-capital-sign', (t) => t.replace(/"counter":(\d+)/, '"counter":$1E+0')],
  ['nested-depth-600-array', (t) => t.replace('"trusted_refs":[]', '"trusted_refs":' + '['.repeat(600) + ']'.repeat(600))],
  ['nested-depth-5000-array', (t) => t.replace('"trusted_refs":[]', '"trusted_refs":' + '['.repeat(5000) + ']'.repeat(5000))],
  ['ws-nbsp', (t) => t.replace('"ver":2', '"ver":\u00a02')],
  ['ws-formfeed', (t) => t.replace('"ver":2', '"ver":\f2')],
  ['ws-vtab', (t) => t.replace('"ver":2', '"ver":\v2')],
  ['ws-u2028', (t) => t.replace('"ver":2', '"ver":\u20282')],
  ['ws-mixed-ok', (t) => t.replace('"ver":2', '"ver" \t:\r\n 2')],
  ['key-escaped-dup', (t) => t.replace('"ver":2', '"ver":2,"v\\u0065r":2')],
  ['lone-low-surrogate-escape', (t) => t.replace('"operator":"unattested"', '"operator":"\\udc00"')],
  ['astral-escape-pair-ok', (t) => t.replace('"operator":"unattested"', '"operator":"\\ud83d\\ude00"')],
  ['reversed-pair', (t) => t.replace('"operator":"unattested"', '"operator":"\\ude00\\ud83d"')],
  ['neg-zero-fraction', (t) => t.replace(/"counter":(\d+)/, '"counter":-0.0')],
  ['frac-trailing-zero-in-r', (t) => t.replace('"r":0', '"r":0.50')],
  ['exp-in-r', (t) => t.replace('"r":0', '"r":5e-1')],
  ['r-below-1e-6', (t) => t.replace('"r":0', '"r":0.0000005')],
  ['r-16-digits', (t) => t.replace('"r":0', '"r":0.1234567890123456')],
  ['r-15-digits-ok', (t) => t.replace('"r":0', '"r":0.123456789012345')],
  ['r-1e-6-ok', (t) => t.replace('"r":0', '"r":0.000001')],
  ['invalid-utf8-surrogate-escape-lone', (t) => t.replace('"operator":"unattested"', '"operator":"\\ud800"')],
];
for (const [n, f] of BADJSON) add(`badjson-${n}`, 'badjson', (s) => { s.textPatch = f; return /-ok$/.test(n) ? {} : { mustReject: true }; });

// ---------------------------------------------------------------- canonical-primitive cases
// "canon" kind: raw is ANY JSON text; every impl canonicalizes+hashes its own parse; TS is the oracle.
const canonCases: { raw: string; tag: string }[] = [];
for (const n of EDGE_NUMS) { canonCases.push({ raw: n, tag: 'num' }); canonCases.push({ raw: `[${n}]`, tag: 'num-arr' }); canonCases.push({ raw: `{"v":${n}}`, tag: 'num-obj' }); }
for (const s of EDGE_STRS) canonCases.push({ raw: s, tag: 'str' });
for (let c = 0; c < 0x80; c++) canonCases.push({ raw: JSON.stringify(String.fromCharCode(c)), tag: 'ascii-escape' });
for (const c of [0x80, 0x9f, 0xa0, 0xad, 0x2028, 0x2029, 0xd7ff, 0xe000, 0xfeff, 0xfffd, 0xffff]) canonCases.push({ raw: JSON.stringify(String.fromCharCode(c)), tag: 'bmp-char' });
for (const c of [0x10000, 0x1f600, 0x10ffff, 0x1d11e]) canonCases.push({ raw: JSON.stringify(String.fromCodePoint(c)), tag: 'astral' });
canonCases.push({ raw: '"\\ud800"', tag: 'lone-hi' }, { raw: '"\\udc00"', tag: 'lone-lo' }, { raw: '"\\ud800a"', tag: 'lone-hi-then-ascii' }, { raw: '"\\ud800\\ud800"', tag: 'two-hi' });
for (let i = 0; i < 300; i++) {
  // randomized key-order stress: keys drawn from EDGE_KEYS, UTF-16 vs code-point vs byte order differ
  const o: Record<string, unknown> = {};
  for (let j = 0; j < 2 + int(8); j++) o[pick(EDGE_KEYS)] = randVal(1);
  canonCases.push({ raw: JSON.stringify(o), tag: 'key-order' });
}
for (let i = 0; i < 400; i++) canonCases.push({ raw: JSON.stringify(randVal()), tag: 'random-value' });
for (let i = 0; i < 300; i++) { const d = Math.pow(10, int(40) - 20) * rnd() * (chance(0.5) ? 1 : -1); canonCases.push({ raw: JSON.stringify(d), tag: 'random-double' }); }
for (let i = 0; i < 200; i++) { const d = new DataView(new ArrayBuffer(8)); d.setUint32(0, int(2 ** 32)); d.setUint32(4, int(2 ** 32)); const x = d.getFloat64(0); if (Number.isFinite(x)) canonCases.push({ raw: JSON.stringify(x), tag: 'random-bits-double' }); }
for (const e of [-24, -22, -21, -20, -7, -6, -5, 0, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 30, 100, 300]) for (const m of ['1', '1.5', '9.5', '123456789']) canonCases.push({ raw: `${m}e${e}`, tag: 'exp-boundary' });
for (let i = 1; i <= 24; i++) canonCases.push({ raw: '9'.repeat(i), tag: 'int-digits' });
for (const p of [52, 53, 54, 63, 64, 65, 100]) for (const d of [-1, 0, 1]) canonCases.push({ raw: (BigInt(2) ** BigInt(p) + BigInt(d)).toString(), tag: 'pow2' });
// v2 number-profile probes: plain decimals around the 15-significant-digit / 1e-6 / trailing-zero / lexeme-vs-value limits
for (let k = 1; k <= 18; k++) {
  for (let t = 0; t < 4; t++) {
    const digs = Array.from({ length: k }, (_, i) => String(i === 0 ? 1 + int(9) : int(10))).join('');
    const pt = int(k + 1);
    const lex = pt === 0 ? '0.' + digs : pt === k ? digs + '.5' : digs.slice(0, pt) + '.' + digs.slice(pt);
    canonCases.push({ raw: lex, tag: 'dec-digits' });
    canonCases.push({ raw: '-' + lex, tag: 'dec-digits' });
  }
}
for (const lex of ['0.1', '0.10', '1.50', '0.000001', '0.0000010', '0.0000009', '0.00000100000000000000000001', '0.1000000000000000055511151231257827', '1.0000000000000001', '1.000000000000001', '123456789012345.6', '12345678901234.56', '0.000123456789012345', '0.0001234567890123456', '9007199254740991', '-9007199254740991', '9007199254740992', '0.5', '-0.5', '0.0', '-0.0', '00.5', '0.50', '.5', '5.', '1.5e0', '1E5', '100', '-100', '1000000000000000', '9999999999999999', '10000000000000000']) canonCases.push({ raw: lex, tag: 'dec-edge' });
// strict-JSON-profile probes (whitespace / escapes / structure) as standalone documents
for (const t of ['{"a":1}\n', '\t{"a":1}', '{"a":1}\u00a0', '\u00a0{"a":1}', '{"a":1}\f', '\v{"a":1}', '\u2028{"a":1}', '\ufeff{"a":1}', '{"a" : 1 , "b" : [ 1 , 2 ] }', '{"a":1,}', '[1,]', '[,1]', '{,}', '{"a" 1}', '{"a":1 "b":2}', '/*x*/{}', '{}//x', '{"a":/*x*/1}', '"\\u00e9"', '"\\ud83d\\ude00"', '"\\ude00"', '"\\ud83d"', '"\\ud83dx"', '"\\uD83D\\uDE00"', '"\\u00E9"', '"\\x41"', '"\\\'"', '"a\tb"', '"\u007f"', '"\u2028"', '{"\\u0061":1,"a":2}', '{"a":1,"\\u0061":2}', '{"a":{"b":1,"b":2}}', '[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]', '[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]', 'nul', 'nulll', 'truefalse', 'True', 'NaN', '-', '--1', '+1', '01', '-01', '1e', '1.e1', '0x1', 'Infinity', '-Infinity', '"', '"\\', '[', '{', '{"a"', '{"a":', '']) canonCases.push({ raw: t, tag: 'profile' });
canonCases.push({ raw: '{"a":1,"a":2}', tag: 'dupkey' }, { raw: '{"__proto__":{"x":1}}', tag: 'proto-key' }, { raw: '{"__proto__":1,"a":2}', tag: 'proto-key2' }, { raw: '{"":1}', tag: 'empty-key' }, { raw: '[]', tag: 'empty-arr' }, { raw: '{}', tag: 'empty-obj' }, { raw: 'null', tag: 'null' }, { raw: ' [ 1 , 2 ] ', tag: 'ws' });

// ---------------------------------------------------------------- assemble
interface Meta { numClass?: string; id: string; tag: string; mutator?: string; group?: string; breaks?: string[]; mustReject?: boolean; base?: string; meta?: string; kind: string; }
const corpus: { id: string; kind: string; raw: string; grant?: string; now?: number; aud?: string }[] = [];
const metas: Meta[] = [];
const seen = new Set<string>();
let nextId = 0;
const push = (kind: string, rawStr: string, m: Omit<Meta, 'id' | 'kind'>, grantText?: string): string | null => {
  const key = kind + '\0' + rawStr + '\0' + (grantText ?? '');
  if (seen.has(key)) return null;
  seen.add(key);
  const id = `c${String(nextId++).padStart(6, '0')}`;
  // verify: `raw` is the PCActn JSON TEXT (strict-parsed by every verifier); `grant` is the verifier's own trusted grant (lenient parse).
  corpus.push(kind === 'verify' ? { id, kind, raw: rawStr, grant: grantText, now: NOW, aud: AUD } : { id, kind, raw: rawStr });
  metas.push({ id, kind, numClass: numClassOf(rawStr), ...m });
  return id;
};

// 'int' = every number literal is a plain safe integer; 'float' = has fraction/exponent literal;
// 'unsafe-int' = integer literal beyond 2^53; 'nojson' = not parseable / too deep to classify.
function numClassOf(text: string): string {
  let ast;
  try { ast = astParse(text); } catch { return 'nojson'; }
  let cls = 'int';
  const walk = (n: any): void => {
    if (n.t === 'arr') n.items.forEach(walk);
    else if (n.t === 'obj') n.kv.forEach((kv: any) => walk(kv[1]));
    else if (n.t === 'lit' && /^-?[0-9.eE+-]+$/.test(n.s)) {
      if (!/^-?(0|[1-9][0-9]*)$/.test(n.s)) { if (cls !== 'unsafe-int') cls = 'float'; }
      else if (BigInt(n.s) > 9007199254740991n || BigInt(n.s) < -9007199254740991n) cls = 'unsafe-int';
    }
  };
  try { walk(ast); } catch { return 'nojson'; }
  return cls;
}
// The grant is the VERIFIER'S OWN trusted input (not wire bytes): emit it as strict-canonical text when possible so every
// language's lenient parser reads exactly the same value (no dup keys / exponent numbers / depth games in the grant).
const grantTextOf = (grant: any): string => { try { return pca.canonicalizeStrict(P(grant)); } catch { return rawText(grant); } };
const caseText = (pc: any, grant: any) => ({ text: rawText(pc), grantText: grantTextOf(grant) });

async function applyMutator(base: Base, m: Mutator): Promise<{ text: string; grantText: string; res: MutResult } | null> {
  const st: St = { pc: clone(base.pc), grant: clone(base.grant), base };
  let res: MutResult | null;
  try { res = m.fn(st); } catch { return null; }
  if (!res) return null;
  if (res.resign) {
    const key = res.resign === true ? st.base.holders[st.base.holders.length - 1]! : res.resign;
    try { st.pc.sig = leafSign(st.pc, key); } catch { /* leave stale sig */ }
  }
  const ct = caseText(st.pc, st.grant);
  let text = ct.text;
  let grantText = ct.grantText;
  if (st.textPatch) { const t2 = st.textPatch(text); if (t2 === text && res.mustReject && !res.breaks) res = { ...res, mustReject: undefined }; text = t2; }
  if (st.grantPatch) grantText = st.grantPatch(grantText);
  return { text, grantText, res };
}

async function main() {
  const t0 = Date.now();
  // 1. exhaustive: every mutator against fixed bases of several depths, 3 draws each
  // 2. random: BASES random valid bases, each gets a random handful of mutators
  const validBases: { id: string; base: Base; text: string }[] = [];
  for (let b = 0; b < BASES; b++) {
    floatMode = chance(0.15);
    const base = makeBase();
    const { text, grantText } = caseText(base.pc, base.grant);
    const o = await oracle(text, grantText);
    if (!o?.allow) throw new Error('generator bug: base not accepted by oracle: ' + JSON.stringify(o) + ' ' + text.slice(0, 300));
    const id = push('verify', text, { tag: 'valid', group: 'valid' }, grantText);
    if (id) validBases.push({ id, base, text });
  }
  console.error(`bases done ${(Date.now() - t0) / 1000}s`);
  floatMode = false;
  const exhaustiveBases = [1, 2, 3, 5].flatMap((d) => [makeBase({ depth: d, planSize: pick([5, 8, 33]) }), makeBase({ depth: d, planSize: 1 })]);
  for (const base of exhaustiveBases) {
    const bt = caseText(base.pc, base.grant);
    const bid = push('verify', bt.text, { tag: 'valid', group: 'valid' }, bt.grantText);
    for (const m of M) {
      if (m.minDepth && base.chain.length < m.minDepth) continue;
      for (let k = 0; k < 2; k++) {
        const t1 = Date.now(); if (process.env.TRACE) console.error("run", m.name);
        const r = await applyMutator(base, m);
        if (Date.now() - t1 > 1500) console.error(`slow mutator ${m.name}: ${Date.now() - t1}ms`);
        if (r) push('verify', r.text, { tag: 'mutant', mutator: m.name, group: m.group, breaks: r.res.breaks, mustReject: r.res.mustReject, base: bid ?? undefined }, r.grantText);
      }
    }
  }
  for (const vb of validBases) {
    floatMode = false;
    const n = 4 + int(4);
    for (let k = 0; k < n; k++) {
      const m = pick(M);
      if (m.minDepth && vb.base.chain.length < m.minDepth) continue;
      const r = await applyMutator(vb.base, m);
      if (r) push('verify', r.text, { tag: 'mutant', mutator: m.name, group: m.group, breaks: r.res.breaks, mustReject: r.res.mustReject, base: vb.id }, r.grantText);
    }
    // generic leaf sweep: random path, random op, with and without re-sign
    const lv = leaves(vb.base.pc).filter((l) => l.path[0] !== 'sig');
    for (let k = 0; k < 2; k++) {
      const st: St = { pc: clone(vb.base.pc), grant: clone(vb.base.grant), base: vb.base };
      const l = pick(lv);
      const op = int(6);
      const p = l.path;
      try {
        if (op === 0 && typeof l.v === 'string') setAt(st.pc, p, flipChar(l.v));
        else if (op === 1 && typeof l.v === 'string') setAt(st.pc, p, l.v.slice(0, -1));
        else if (op === 2) delAt(st.pc, p);
        else if (op === 3) setAt(st.pc, p, null);
        else if (op === 4) setAt(st.pc, p, typeof l.v === 'number' ? l.v + 1 : typeof l.v === 'string' ? 7 : 'x');
        else setAt(st.pc, p, typeof l.v === 'string' ? l.v + pick(WORDS) : l.v);
      } catch { continue; }
      const resign = chance(0.5);
      if (resign) { try { st.pc.sig = leafSign(st.pc, vb.base.holders[vb.base.holders.length - 1]!); } catch { /* */ } }
      const gct = caseText(st.pc, st.grant);
      push('verify', gct.text, { tag: 'mutant', mutator: `generic-leaf-op${op}${resign ? '-resigned' : ''}`, group: 'generic', base: vb.id }, gct.grantText);
    }
  }
  // singletons: input-size limit (2^20 characters) probes on the first valid base, padded with trailing JSON whitespace
  {
    const b0 = validBases.find((v) => /^[\x00-\x7f]*$/.test(v.text))!; // ASCII-only so 'characters' == UTF-16 units == code points == bytes
    const g0 = caseText(b0.base.pc, b0.base.grant).grantText;
    const LIM = 1 << 20;
    const pad = (t: string, n: number) => t + ' '.repeat(n - t.length);
    for (const [nm, n, rej] of [['size-at-limit', LIM, false], ['size-over-limit', LIM + 1, true], ['size-far-over', LIM * 2, true]] as const) {
      push('verify', pad(b0.text, n), { tag: 'mutant', mutator: `badjson-${nm}`, group: 'badjson', mustReject: rej || undefined, base: b0.id }, g0);
    }
    // astral: the limit is UTF-8 BYTES (not UTF-16 units / code points)
    const st: St = { pc: clone(b0.base.pc), grant: clone(b0.base.grant), base: b0.base };
    st.pc.progress_step = { v: '\u{1F600}'.repeat(1000) };
    st.pc.sig = leafSign(st.pc, b0.base.holders[b0.base.holders.length - 1]!);
    const at = caseText(st.pc, st.grant).text;
    const bytes = Buffer.byteLength(at, 'utf8');
    const cps = [...at].length;
    for (const [nm, padn, rej] of [['astral-bytes-at-limit', LIM - bytes, false], ['astral-bytes-over-limit', LIM - bytes + 1, true], ['astral-cp-at-limit', LIM - cps, true], ['astral-units-at-limit', LIM - at.length, true]] as const) {
      push('verify', at + ' '.repeat(padn), { tag: 'mutant', mutator: `badjson-size-${nm}`, group: 'badjson', mustReject: rej || undefined, base: b0.id }, g0);
    }
    // multibyte 2-byte char (é): byte length > code points
    const st2: St = { pc: clone(b0.base.pc), grant: clone(b0.base.grant), base: b0.base };
    st2.pc.progress_step = { v: '\u00e9'.repeat(2000) };
    st2.pc.sig = leafSign(st2.pc, b0.base.holders[b0.base.holders.length - 1]!);
    const at2 = caseText(st2.pc, st2.grant).text;
    push('verify', at2 + ' '.repeat(LIM - Buffer.byteLength(at2, 'utf8')), { tag: 'mutant', mutator: 'badjson-size-2byte-bytes-at-limit', group: 'badjson', base: b0.id }, g0);
    push('verify', at2 + ' '.repeat(LIM - Buffer.byteLength(at2, 'utf8') + 1), { tag: 'mutant', mutator: 'badjson-size-2byte-bytes-over-limit', group: 'badjson', mustReject: true, base: b0.id }, g0);
    push('verify', at2 + ' '.repeat(LIM - at2.length), { tag: 'mutant', mutator: 'badjson-size-2byte-units-at-limit', group: 'badjson', mustReject: true, base: b0.id }, g0);
  }
  const nMut = corpus.length;

  // 3. metamorphic, semantics-PRESERVING: format-only rewrites of VALID and of MUTANT bases
  const rng2 = mulberry32(SEED ^ 0x9e3779b9);
  const sources = metas.map((m, i) => ({ m, c: corpus[i]! })).filter((x) => x.m.kind === 'verify' && x.c.raw.length < 30000);
  let metaCount = 0;
  for (let i = 0; i < sources.length && metaCount < 2600; i += 1 + (i % 3)) {
    const src = sources[i]!;
    let ast;
    try { ast = astParse(src.c.raw); emit(ast, { rng: rng2, ws: false, escapeStrings: false, shuffleKeys: false, numRepr: false }); } catch { continue; } // invalid-JSON / too-deep mutants have no preserving rewrite
    const dup = hasDupKeys(ast);
    const variants: [string, Partial<Parameters<typeof emit>[1]>][] = [
      ['ws', { ws: true }],
      ['shuffle', { shuffleKeys: true }],
      ['escape', { escapeStrings: true }],
      ['all', { ws: true, shuffleKeys: true, escapeStrings: true }],
    ];
    for (const [vn, vo] of variants) {
      if (dup && vo.shuffleKeys) continue; // reordering duplicate keys can change last-wins semantics
      const text = emit(ast, { rng: rng2, ws: false, escapeStrings: false, shuffleKeys: false, numRepr: false, ...vo });
      if (push('verify', text, { tag: 'meta-preserving', meta: vn, group: 'metamorphic', base: src.m.id }, src.c.grant)) metaCount++;
    }
    if (!dup && i % 9 === 0) {
      const text = emit(ast, { rng: rng2, ws: false, escapeStrings: false, shuffleKeys: false, numRepr: true });
      if (push('verify', text, { tag: 'meta-numrepr', meta: 'numrepr', group: 'metamorphic', base: src.m.id, mustReject: true }, src.c.grant)) metaCount++;
    }
  }
  for (const c of canonCases) push('canon', c.raw, { tag: 'canon', group: c.tag });

  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, 'corpus.jsonl'), corpus.map((c) => JSON.stringify(c)).join('\n') + '\n');
  writeFileSync(join(outDir, 'meta.jsonl'), metas.map((c) => JSON.stringify(c)).join('\n') + '\n');
  const byTag: Record<string, number> = {};
  for (const m of metas) byTag[m.tag] = (byTag[m.tag] ?? 0) + 1;
  console.log(JSON.stringify({ seed: SEED, total: corpus.length, mutants: nMut, byTag, mutators: M.length, secs: (Date.now() - t0) / 1000 }));
}
main().catch((e) => { console.error(e); process.exit(1); });

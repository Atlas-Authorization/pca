// Stage 5 of the conformance pipeline (run AFTER gen-conformance-r6.mjs; idempotent): JSON nesting-depth limits on
// every untrusted-input entry point (MAX_JSON_DEPTH = 32), at limit-1 / limit / limit+1 and at a huge depth.
//
//   primitives.depth[]  { name, description, api, depth, input, valid [, expand] [, ts_reason] }
//     api          chain | threshold_share | pcactn_json | json_parse   (same dispatch as primitives.malformed)
//                    chain:           input = { chain, expected_root_issuer } -> valid == verify_chain(...).ok
//                    threshold_share: input = a threshold_share entry          -> valid == the share counts for entry.role
//                                     (exactly as threshold_set: strict b64u threshold_message, share.role == role,
//                                     verifyThreshold({shares:[share]}, msg, signer_set, t) lists role)
//                    pcactn_json:     input = { text, grant, now, aud }       -> valid == strict parse ok AND verify allows
//                    json_parse:      input = { text }                        -> valid == the strict parser accepts text
//     depth        total container nesting depth of the untrusted value AFTER expansion, counted like the strict parser
//                  (the outermost container = 1): the chain array, the threshold_share entry object, the PCActn document,
//                  the parsed text. NOTE where the cap bites: a chain hop is canonicalised (and so depth-capped) on its own,
//                  so a chain of depth N holds hops of depth N-1; the threshold_share entry's extra fields are never
//                  canonicalised by the reference, so they are not depth-limited there (the cases say so in `valid`).
//     valid        the reference (TypeScript) verdict. Every case must be a clean verdict: no exception, panic, stack
//                  overflow or crash may escape the public entry point.
//     expand       OPTIONAL, only on the huge-depth cases (a 100000-deep literal would exceed the depth limit of the
//                  ordinary JSON loaders that read this file): { marker, levels, leaf }. Before running the case,
//                    - chain / threshold_share: replace the (single) string value equal to `marker` anywhere in `input`
//                      with `levels` nested arrays around `leaf`  (levels=3, leaf=1  ->  [[[1]]]);
//                    - pcactn_json / json_parse: replace the (single) substring `marker` of input.text with
//                      "[" x levels + JSON(leaf) + "]" x levels.
//                  Build the value ITERATIVELY (the point of the case is that the verifier, not the runner, faces it).
//
//     node packages/pca/scripts/gen-conformance-depth.mjs           (writes vectors.json)
//     node packages/pca/scripts/gen-conformance-depth.mjs --probe   (prints the reference behaviour table; THROWS reported, nothing written)
import { createHash } from 'node:crypto';
import * as pca from '../dist/index.js';
import { readCore, writeCore } from './conformance-io.mjs';

const PROBE = process.argv.includes('--probe');
const LIMIT = 32;
if (pca.MAX_JSON_DEPTH !== undefined && pca.MAX_JSON_DEPTH !== LIMIT) throw new Error('MAX_JSON_DEPTH changed: ' + pca.MAX_JSON_DEPTH);
const HUGE = 100_000;
const MARKER = '@@pca-depth-nest@@';
const NOW = 1_800_000_000_000;
const AUD = 'rs-conformance';
const file = readCore();

const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/depth/${l}`).digest());
const ed = (l) => { const s = seed(l); return { sk: s, pub: pca.b64u(pca.publicKeyOf(s)) }; };
const principal = ed('principal'), agent = ed('agent'), guardian = ed('guardian');

/** `levels` nested arrays around `leaf`, built iteratively. */
const nest = (levels, leaf = 1) => { let v = leaf; for (let i = 0; i < levels; i++) v = [v]; return v; };
const nestText = (levels, leaf = 1) => '['.repeat(levels) + JSON.stringify(leaf) + ']'.repeat(levels);
/** strict-parser depth of a JS value (iterative). */
function depthOf(v) {
  let max = 0;
  const st = [[v, 1]];
  while (st.length) {
    const [x, d] = st.pop();
    if (x === null || typeof x !== 'object') continue;
    if (d > max) max = d;
    for (const y of Array.isArray(x) ? x : Object.values(x)) st.push([y, d + 1]);
  }
  return max;
}
/** strict-parser depth of a JSON text (bracket scan outside strings). */
function depthOfText(t) {
  let d = 0, max = 0, inStr = false;
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (inStr) { if (c === '\\') i++; else if (c === '"') inStr = false; continue; }
    if (c === '"') inStr = true;
    else if (c === '[' || c === '{') { d++; if (d > max) max = d; }
    else if (c === ']' || c === '}') d--;
  }
  return max;
}
/** replace the string value === MARKER inside a (non-huge) value with `repl` (returns a new value). */
function subst(v, repl) {
  if (v === MARKER) return repl;
  if (Array.isArray(v)) return v.map((x) => subst(x, repl));
  if (v !== null && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, subst(x, repl)]));
  return v;
}
const expandInput = (api, input, ex) => {
  if (!ex) return input;
  if (api === 'pcactn_json' || api === 'json_parse') return { ...input, text: input.text.replace(ex.marker, nestText(ex.levels, ex.leaf)) };
  return subst(input, nest(ex.levels, ex.leaf));
};

// ------------------------------------------------------------------ the reference verdicts
const thMsg = new Uint8Array(createHash('sha256').update('atlas-pca-conformance/depth/thmsg').digest());
async function reference(api, input) {
  switch (api) {
    case 'chain': {
      const r = pca.verifyChain(input.chain, input.expected_root_issuer);
      return { valid: r.ok, reason: r.reason ?? null };
    }
    case 'threshold_share': {
      const e = input;
      if (e === null || typeof e !== 'object' || Array.isArray(e)) return { valid: false, reason: 'entry not an object' };
      const msg = pca.decodeB64uStrict(e.threshold_message);
      if (msg === null) return { valid: false, reason: 'threshold_message is not canonical base64url' };
      const v = pca.verifyThreshold({ shares: [e.share] }, msg, e.signer_set, e.t);
      return { valid: !!(e.share && e.share.role === e.role && v.roles.includes(e.role)), reason: v.reason ?? null };
    }
    case 'pcactn_json': {
      let tree;
      try { tree = pca.strictParse(input.text); } catch (err) { return { valid: false, reason: 'strict parse: ' + err.message }; }
      const r = await pca.verifyPCActnCore(tree, { insecureSkipPlanRootCheck: true, grant: input.grant, nowEpoch: input.now, audience: input.aud });
      return { valid: r.allow, reason: r.allow ? null : (r.reason ?? JSON.stringify(r.checks ?? null)) };
    }
    case 'json_parse':
      try { pca.strictParse(input.text); return { valid: true, reason: null }; } catch (err) { return { valid: false, reason: err.message }; }
  }
  throw new Error('unknown api ' + api);
}

const cases = [];
const add = (name, description, api, input, intended, expand) => cases.push({ name: 'depth-' + name, description, api, input, intended, expand });

// ------------------------------------------------------------------ chain
/** Sign a root hop body. `lenient` signs over the uncapped canonical form, so a verifier WITHOUT the depth cap accepts it. */
const CAP = 'atlas-pca/cap/v1\0';
function signRoot(caveats, lenient = false) {
  const body = { issuer: principal.pub, holder: agent.pub, caveats, parent: null };
  const digest = lenient ? pca.hashCanonicalLenient(body) : pca.hashCanonical(body);
  const msg = new Uint8Array([...pca.utf8(CAP), ...pca.unb64u(digest)]);
  return { id: digest, issuer: principal.pub, holder: agent.pub, caveats, body_digest: digest, sig: pca.b64u(pca.sign(principal.sk, msg)) };
}
// chain(1) > hop(2) > caveats(3) > caveat(4) > v: levels arrays  =>  chain depth = 4 + levels, hop depth = 3 + levels.
for (const total of [LIMIT - 1, LIMIT, LIMIT + 1, LIMIT + 2]) {
  const levels = total - 4;
  const hop = total - 1;
  const root = signRoot([{ type: 'max_spend', usd: 100 }, { type: 'note', v: nest(levels) }], hop > LIMIT);
  add(`chain-${total}`, `A root whose note caveat nests ${levels} arrays: chain depth ${total}, hop (canonicalised) depth ${hop}` +
    (hop > LIMIT ? ' > MAX_JSON_DEPTH: refused (signed over the uncapped canonical form, so only the cap refuses it).' : ' <= MAX_JSON_DEPTH: verifies.'),
    'chain', { chain: [root], expected_root_issuer: principal.pub }, hop <= LIMIT);
}
{
  // huge: the same root shape, the caveat value expanded to HUGE levels (signature over a placeholder: never reached)
  const root = signRoot([{ type: 'max_spend', usd: 100 }, { type: 'note', v: MARKER }]);
  add('chain-huge', `A root whose note caveat nests ${HUGE} arrays (via expand): clean refusal, no stack exhaustion.`, 'chain',
    { chain: [root], expected_root_issuer: principal.pub }, false, { marker: MARKER, levels: HUGE, leaf: 1 });
}

// ------------------------------------------------------------------ threshold_share
const E = [{ role: 'agent', publicKey: agent.pub }, { role: 'guardian', publicKey: guardian.pub }, { role: 'principal', publicKey: principal.pub }];
const share = pca.signShare('agent', agent.sk, thMsg, { signerSet: E, t: 1 });
const entry = (o = {}) => ({ role: 'agent', t: 1, signer_set: E, threshold_message: pca.b64u(thMsg), share, ...o });
for (const total of [LIMIT - 1, LIMIT, LIMIT + 1]) {
  // entry(1) > signer_set(2) > member(3) > x: levels arrays
  const levels = total - 3;
  add(`share-member-extra-${total}`, `An extra signer_set member field nesting ${levels} arrays (entry depth ${total}). The reference never ` +
    'canonicalises extra member fields (the signer-set hash covers role, publicKey, pq_pk only), so the share counts at any depth.',
    'threshold_share', entry({ signer_set: [{ ...E[0], x: nest(levels) }, E[1], E[2]] }), true);
  // entry(1) > t: levels arrays
  add(`share-t-nested-${total}`, `t is ${total} nested arrays around 1 (entry depth ${total}): not an integer, refused.`,
    'threshold_share', entry({ t: nest(total - 1) }), false);
  // entry(1) > share(2) > role: levels arrays
  add(`share-role-nested-${total}`, `share.role is ${total - 2} nested arrays (entry depth ${total}): malformed share, refused.`,
    'threshold_share', entry({ share: { ...share, role: nest(total - 2, 'agent') } }), false);
}
add('share-t-nested-huge', `t is ${HUGE} nested arrays (via expand): refused; the refusal reason must not stringify the value recursively.`,
  'threshold_share', entry({ t: MARKER }), false, { marker: MARKER, levels: HUGE, leaf: 1 });
add('share-role-nested-huge', `share.role is ${HUGE} nested arrays (via expand): refused, no stack exhaustion.`,
  'threshold_share', entry({ share: { ...share, role: MARKER } }), false, { marker: MARKER, levels: HUGE, leaf: 'agent' });
add('share-member-role-nested-huge', `A signer_set member's role is ${HUGE} nested arrays (via expand): the set is malformed, refused.`,
  'threshold_share', entry({ signer_set: [E[0], { ...E[1], role: MARKER }, E[2]] }), false, { marker: MARKER, levels: HUGE, leaf: 'guardian' });
add('share-member-extra-huge', `An extra signer_set member field nesting ${HUGE} arrays (via expand): never canonicalised by the reference, the share counts; no stack exhaustion.`,
  'threshold_share', entry({ signer_set: [{ ...E[0], x: MARKER }, E[1], E[2]] }), true, { marker: MARKER, levels: HUGE, leaf: 1 });

// ------------------------------------------------------------------ pcactn_json
const grant = pca.mintRoot({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, caveats: [{ type: 'resource_prefix', prefix: 'db/' }] });
const plan = [{ id: 'n1', verb: 'read', resource: 'db/users' }];
const SIG_DOMAIN = file.sig_domain;
if (typeof SIG_DOMAIN !== 'string') throw new Error('vectors.json sig_domain missing');
/** a PCActn whose risk_claim.inputs.x holds `x`; `lenient` signs the uncapped canonical form. */
function pcactnText(x, lenient = false) {
  const p = pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant, chain: [grant], plan, nodeId: 'n1', counter: 1, signerSecret: agent.sk, riskClaim: { r: 0, inputs: { x: 0 } } });
  const { sig: _s, ...body } = p;
  body.risk_claim = { r: 0, inputs: { x } };
  if (!lenient) return JSON.stringify(pca.signPCActn(body, agent.sk));
  const d = pca.sha256(pca.utf8(pca.canonicalize(body)));
  const msg = new Uint8Array([...pca.utf8(SIG_DOMAIN), ...d]);
  return JSON.stringify({ ...body, sig: pca.b64u(pca.sign(agent.sk, msg)) });
}
// doc(1) > risk_claim(2) > inputs(3) > x: levels arrays  =>  depth 3 + levels
for (const total of [LIMIT - 1, LIMIT, LIMIT + 1]) {
  const levels = total - 3;
  add(`pcactn-${total}`, `A signed PCActn whose risk_claim.inputs.x nests ${levels} arrays (document depth ${total})` +
    (total > LIMIT ? ': the strict parser refuses it (signed over the uncapped canonical form, so only the cap refuses it).' : ': allowed.'),
    'pcactn_json', { text: pcactnText(nest(levels), total > LIMIT), grant, now: NOW, aud: AUD }, total <= LIMIT);
}
add('pcactn-huge', `A PCActn whose risk_claim.inputs.x nests ${HUGE} arrays (via expand): the strict parser refuses it, no stack exhaustion.`,
  'pcactn_json', { text: pcactnText(0).replace('"x":0', `"x":${JSON.stringify(MARKER)}`), grant, now: NOW, aud: AUD }, false, { marker: JSON.stringify(MARKER), levels: HUGE, leaf: 1 });

// ------------------------------------------------------------------ json_parse
for (const total of [LIMIT - 1, LIMIT, LIMIT + 1]) {
  add(`json-array-${total}`, `${total} nested arrays.`, 'json_parse', { text: nestText(total - 1, []) }, total <= LIMIT);
  add(`json-object-${total}`, `${total} nested objects.`, 'json_parse', { text: '{"a":'.repeat(total) + '1' + '}'.repeat(total) }, total <= LIMIT);
}
add('json-array-huge', `${HUGE} nested arrays (via expand): refused, no stack exhaustion.`, 'json_parse', { text: MARKER }, false, { marker: MARKER, levels: HUGE, leaf: 1 });

// ------------------------------------------------------------------ evaluate
const out = [];
let bad = 0;
for (const c of cases) {
  const inp = expandInput(c.api, c.input, c.expand);
  const depth = c.api === 'pcactn_json' || c.api === 'json_parse' ? depthOfText(inp.text) : c.api === 'chain' ? depthOf(inp.chain) : depthOf(inp);
  let r;
  try { r = await reference(c.api, inp); } catch (e) { r = { threw: `${e?.constructor?.name}: ${String(e?.message).slice(0, 120)}` }; }
  const verdict = r.threw ? 'THREW ' + r.threw : r.valid ? 'valid' : 'deny  (' + String(r.reason).slice(0, 90) + ')';
  console.log(`${c.name.padEnd(36)} ${c.api.padEnd(16)} depth ${String(depth).padStart(6)}  ${verdict}`);
  if (r.threw || r.valid !== c.intended) { bad++; continue; }
  out.push({ name: c.name, description: c.description, api: c.api, depth, input: c.input, valid: r.valid, ...(c.expand ? { expand: c.expand } : {}), ...(!r.valid && r.reason ? { ts_reason: String(r.reason).slice(0, 200) } : {}) });
}
if (bad) {
  console.error(`${bad} case(s) threw or differ from the intended verdict`);
  process.exit(PROBE ? 0 : 1);
}
if (!PROBE) {
  const f = readCore();
  f.primitives.depth = out;
  writeCore(f);
  console.log(`depth ${out.length} (${out.filter((x) => x.valid).length} valid)`);
}

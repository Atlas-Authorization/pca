/**
 * Bounded-exhaustive cross-check of the LEAN definitions against the REAL TypeScript implementation.
 *   lake exe xcheck | grep -E '^(EFF|REPLAY|GREF)' > lean.txt ; tsx compare.ts lean.txt
 * Lean prints, for every point of a small scope, the value of its (machine-checked executable) definitions; this
 * program recomputes the same table with packages/pca and diffs line by line.
 */
import { readFileSync } from 'node:fs';
import {
  InMemoryReplayStore, attenuate, delegate, evaluateAgentCaveats, hashCanonical, mintRoot, verifyChain, verifyPCActnCore, b64u,
  type Caveat, type Capability, type PCActn,
} from '../../../packages/pca/src/index';
import { keyOf, realAction, realChain, mintRootFor } from '../conformance/real';
import { baseSpec } from '../conformance/spec';

const lines = readFileSync(process.argv[2]!, 'utf8').split('\n').filter((l) => /^(EFF|REPLAY|GREF) /.test(l));
const leanBy = (p: string) => lines.filter((l) => l.startsWith(p + ' '));

// ---- EFF -------------------------------------------------------------------------------------------------------
const ALPHA: Array<[string, Caveat]> = [
  ['V1', { type: 'predicates', allow: [{ verb: 'v1' }] }],
  ['V12', { type: 'predicates', allow: [{ verb: ['v1', 'v2'] }] }],
  ['V23', { type: 'predicates', allow: [{ verb: ['v2', 'v3'] }] }],
  ['R1', { type: 'predicates', allow: [{ verb: '*', resource: 'r1' }] }],
  ['R12', { type: 'predicates', allow: [{ verb: '*', resource: 'r1' }, { verb: '*', resource: 'r2' }] }],
  ['B0', { type: 'max_blast_radius', max: 0 }],
  ['B1', { type: 'max_blast_radius', max: 0.1 }],
];
const EXT: Array<[string, Caveat[]]> = [['-', []], ...ALPHA.map(([n, c]): [string, Caveat[]] => [n, [c]])];
function* genExts(n: number): Generator<Array<[string, Caveat[]]>> {
  yield [];
  if (n === 0) return;
  for (const o of EXT) for (const rest of genExts(n - 1)) yield [o, ...rest];
}
const ACTIONS: Array<{ verb: string; resource: string; blast: number }> = [];
for (let v = 1; v <= 3; v++) for (let r = 1; r <= 2; r++) for (let b = 0; b <= 2; b++) ACTIONS.push({ verb: `v${v}`, resource: `r${r}`, blast: b });
const P = keyOf('P'), A = keyOf('A');
function effBits(hop: Capability): string {
  return ACTIONS.map((a) => (evaluateAgentCaveats(hop.caveats, { now: 0, blastRadius: a.blast / 10 }, { action: { verb: a.verb, resource: a.resource, params: {} } }).ok ? '1' : '0')).join('');
}
const effExpected = leanBy('EFF');
let effIdx = 0, effAgree = 0, effChainVerified = 0, effBad: string[] = [];
for (const [rn, rc] of EXT) {
  for (const exts of genExts(3)) {
    const root = mintRoot({ principalSecret: P.sk, principalPublic: P.pk, holder: A.pk, caveats: rc });
    const chain: Capability[] = [root];
    for (const [, cv] of exts) chain.push(attenuate(chain[chain.length - 1]!, cv, A.sk)); // same holder: attenuate = delegate to self
    const v = verifyChain(chain, P.pk);
    if (v.ok) effChainVerified++;
    const got = `EFF root=${rn} exts=[${exts.map((e) => e[0]).join(', ')}]|${chain.map(effBits).join(',')}`;
    const want = effExpected[effIdx++];
    if (got === want && v.ok) effAgree++; else if (effBad.length < 5) effBad.push(`want ${want}\n got ${got} chainOk=${v.ok}`);
  }
}

async function main() {
// ---- REPLAY ----------------------------------------------------------------------------------------------------
const replayLean = leanBy('REPLAY');
const opsOf = (desc: string): string[] => (desc.length ? desc.split(', ') : []);
let repAgree = 0, repBad: string[] = [];
for (const l of replayLean) {
  const m = /^REPLAY \[(.*)\]\|(.*)$/.exec(l)!;
  const ops = opsOf(m[1]!);
  const store = new InMemoryReplayStore();
  let clock = 0, out = '';
  for (const op of ops) {
    if (op[0] === 't') { clock += Number(op.slice(1)); out += 't'; }
    else if (op[0] === 'c') {
      const [k, r] = op.slice(1).split('.').map(Number);
      let ok = false;
      try { ok = await store.consumeOnce(`k${k}`, r!, clock); } catch { ok = false; }
      out += ok ? 'T' : 'F';
    } else if (op === 'p') { store.prune(clock); out += 'p'; }
    else if (op[0] === 'a') {
      const [s, c] = op.slice(1).split('.').map(Number);
      let ok = false;
      try { ok = await store.advance(`s${s}`, c!); } catch { ok = false; }
      out += ok ? 'T' : 'F';
    }
  }
  if (out === m[2]) repAgree++; else if (repBad.length < 5) repBad.push(`${l}  real=${out}`);
}

// ---- GREF ------------------------------------------------------------------------------------------------------
const tok = (s: string) => hashCanonical({ sym: s });
const gref = leanBy('GREF');
let grAgree = 0, grBad: string[] = [];
const G = mintRootFor(['v1'], 'P', 'P');
for (const l of gref) {
  const m = /^GREF g=(.*) ids=\[(.*)\]\|(\w+)$/.exec(l)!;
  const g = m[1]!, ids = m[2]!.length ? m[2]!.split(', ') : [];
  const rc = realChain(baseSpec());
  const base = realAction({ chain: [], holders: [] }, { verb: 'v1', planned: true, aud: 'ok', grantRef: g === '' ? '' : tok(g), iat: 1, exp: 2, counter: 1, nonce: 'n', leafSig: 'ok' });
  void rc;
  const fake = ids.map((i): Capability => ({ id: tok(i), issuer: tok('iss'), holder: tok('hol'), caveats: [], body_digest: tok(i), sig: b64u(new Uint8Array(64)) }));
  const p = { ...base, cap_chain: fake } as PCActn;
  const r = await verifyPCActnCore(p, { grant: G, nowEpoch: 1, audience: null });
  const status = r.checks.grant_ref_bound ?? (r.checks.wire === 'fail' ? 'fail' : 'absent');
  if (status === m[3]) grAgree++; else if (grBad.length < 5) grBad.push(`${l} real=${status}`);
}
void delegate;
console.log(JSON.stringify({
  lean: { eff: effExpected.length, replay: replayLean.length, gref: gref.length },
  eff: { tableRows: effIdx, agree: effAgree, realChainsVerifiedByVerifyChain: effChainVerified, mismatches: effBad },
  replay: { sequences: replayLean.length, agree: repAgree, mismatches: repBad },
  gref: { rows: gref.length, agree: grAgree, mismatches: grBad },
}, null, 1));
}
main().catch((e) => { console.error(e); process.exit(1); });

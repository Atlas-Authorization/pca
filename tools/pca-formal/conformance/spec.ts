/**
 * Scenario space shared by the reference model (model.ts) and the real-verifier driver (real.ts).
 * A `Spec` is a SYMBOLIC description (no bytes). `toModel` builds the model's symbolic terms; `real.ts`
 * builds real objects from the SAME spec. Disagreement => bug in the code, the model, or the concretizer.
 */
import {
  type Atom, type SymAction, type SymCap, type Verb, type Verifier, type Key, h,
} from './model';

export const NOW = Date.UTC(2026, 9, 6, 12, 0, 0);
export const ALL: Verb[] = ['v1', 'v2', 'v3'];

export type Pin = 'none' | 'v1' | 'v12' | 'v2' | 'v23';
export const PIN_VERBS: Record<Exclude<Pin, 'none'>, Verb[]> = { v1: ['v1'], v12: ['v1', 'v2'], v2: ['v2'], v23: ['v2', 'v3'] };
export type SigFault = 'ok' | 'wrongKey' | 'stale';
export type PrefixFault = 'none' | 'drop' | 'alter';
export interface HopSpec {
  holder: 'A' | 'B' | 'C';
  pin: Pin;
  issuerFault: boolean;
  sigFault: SigFault;
  parentFault: boolean;
  prefixFault: PrefixFault;
}
export type RootKind = 'G' | 'foreignP' | 'forgedX' | 'stale' | 'xIssued';
export type TimeKind = 'valid' | 'atExp' | 'expired' | 'futureIat' | 'skewEdge' | 'expLEiat' | 'tooLong' | 'maxEdge';
export interface Spec {
  rootVerbs: Verb[]; // G's envelope
  root: RootKind;
  hops: HopSpec[]; // delegated hops after the root
  empty: boolean;
  verb: Verb;
  planned: boolean;
  leafSig: 'ok' | 'wrongKey' | 'stale';
  gref: 'root' | 'G' | 'other' | 'empty';
  aud: 'ok' | 'other';
  audMode: 'string' | 'null' | 'undef';
  time: TimeKind;
  counter: number;
  nonce: string | null;
  /** sequence tests: action window starts at NOW+win (exp = iat+600000) and the verifier clock is NOW+nowOff */
  win?: number;
  nowOff?: number;
}

export const ROOT_VERBS: Verb[][] = [['v1', 'v2'], ['v1'], ['v1', 'v2', 'v3'], ['v2']];
export const PINS: Pin[] = ['none', 'v1', 'v12', 'v2', 'v23'];
export const HOLDERS: HopSpec['holder'][] = ['A', 'B', 'C'];

export const timeOf = (t: TimeKind): { iat: number; exp: number } => {
  switch (t) {
    case 'valid': return { iat: NOW, exp: NOW + 600_000 };
    case 'atExp': return { iat: NOW - 600_000, exp: NOW };
    case 'expired': return { iat: NOW - 600_000, exp: NOW - 1 };
    case 'futureIat': return { iat: NOW + 60_001, exp: NOW + 61_001 };
    case 'skewEdge': return { iat: NOW + 60_000, exp: NOW + 61_000 };
    case 'expLEiat': return { iat: NOW, exp: NOW };
    case 'tooLong': return { iat: NOW, exp: NOW + 3_600_001 };
    case 'maxEdge': return { iat: NOW, exp: NOW + 3_600_000 };
  }
};

export const windowOf = (s: Spec): { iat: number; exp: number } =>
  s.win !== undefined ? { iat: NOW + s.win, exp: NOW + s.win + 600_000 } : timeOf(s.time);
export const nowOf = (s: Spec): number => NOW + (s.nowOff ?? 0);

export const baseHop = (holder: HopSpec['holder'] = 'A', pin: Pin = 'none'): HopSpec => ({
  holder, pin, issuerFault: false, sigFault: 'ok', parentFault: false, prefixFault: 'none',
});
export const baseSpec = (): Spec => ({
  rootVerbs: ['v1', 'v2'], root: 'G', hops: [], empty: false, verb: 'v1', planned: true,
  leafSig: 'ok', gref: 'root', aud: 'ok', audMode: 'string', time: 'valid', counter: 1, nonce: 'n1',
});

// ---- symbolic realisation of a Spec for the model ---------------------------------------------------------
const idOf = (c: Omit<SymCap, 'id' | 'bodyId'>) => JSON.stringify([c.issuer, c.holder, c.caveats, c.parent, c.sig]);
const bodyIdOf = (c: Omit<SymCap, 'id' | 'bodyId'>) => JSON.stringify([c.issuer, c.holder, c.caveats, c.parent]) + (c.sig.over === 'stale' ? '!stale' : '');
const mkCap = (c: Omit<SymCap, 'id' | 'bodyId'>): SymCap => ({ ...c, id: idOf(c), bodyId: bodyIdOf(c) });
const env = (verbs: Verb[]): Atom => ({ kind: 'env', verbs });
export const pinAtom = (p: Exclude<Pin, 'none'>): Atom => ({ kind: 'pin', verbs: PIN_VERBS[p] });

export function modelGrant(rootVerbs: Verb[]): SymCap {
  return mkCap({ issuer: 'P', holder: 'A', caveats: [env(rootVerbs)], parent: 'none', sig: { by: 'P', over: 'fresh' } });
}
export function modelRoot(s: Spec): SymCap {
  switch (s.root) {
    case 'G': return modelGrant(s.rootVerbs);
    case 'foreignP': return mkCap({ issuer: 'P', holder: 'A', caveats: [env(ALL)], parent: 'none', sig: { by: 'P', over: 'fresh' } });
    case 'forgedX': return mkCap({ issuer: 'P', holder: 'A', caveats: [env(s.rootVerbs)], parent: 'none', sig: { by: 'X', over: 'fresh' } });
    case 'stale': return mkCap({ issuer: 'P', holder: 'A', caveats: [env(ALL)], parent: 'none', sig: { by: 'P', over: 'stale' } });
    case 'xIssued': return mkCap({ issuer: 'X', holder: 'A', caveats: [env(s.rootVerbs)], parent: 'none', sig: { by: 'X', over: 'fresh' } });
  }
}
export const wrongSigner = (issuer: Key): Key => (issuer === 'X' ? 'C' : 'X');
export function modelChain(s: Spec): SymCap[] {
  if (s.empty) return [];
  const chain = [modelRoot(s)];
  for (const hs of s.hops) {
    const prev = chain[chain.length - 1]!;
    const issuer: Key = hs.issuerFault ? 'X' : prev.holder;
    let caveats: Atom[] = [...prev.caveats, ...(hs.pin === 'none' ? [] : [pinAtom(hs.pin)])];
    if (hs.prefixFault === 'drop') caveats = caveats.slice(1);
    if (hs.prefixFault === 'alter') caveats = [env(ALL), ...caveats.slice(1)];
    const by: Key = hs.sigFault === 'wrongKey' ? wrongSigner(issuer) : issuer;
    chain.push(mkCap({
      issuer, holder: hs.holder, caveats,
      parent: hs.parentFault ? 'h(broken)' : h(prev.id),
      sig: { by, over: hs.sigFault === 'stale' ? 'stale' : 'fresh' },
    }));
  }
  return chain;
}
export function modelAction(s: Spec, leafHolder: Key): SymAction {
  const { iat, exp } = windowOf(s);
  const by: Key = s.leafSig === 'wrongKey' ? wrongSigner(leafHolder) : leafHolder;
  return {
    verb: s.verb, planned: s.planned && s.verb !== 'v3', aud: s.aud, gref: s.gref, iat, exp, counter: s.counter, nonce: s.nonce,
    sig: { by, over: s.leafSig === 'stale' ? 'stale' : 'fresh' },
  };
}
export function modelVerifier(s: Spec, now = NOW): Verifier {
  return { aud: s.audMode === 'string' ? 'ok' : s.audMode === 'null' ? null : undefined, now, G: modelGrant(s.rootVerbs), anchor: 'P' };
}
export const leafHolderOf = (chain: SymCap[]): Key => (chain.length ? chain[chain.length - 1]!.holder : 'A');

// ---- deterministic RNG ------------------------------------------------------------------------------------
export function rng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    next,
    int: (n: number) => Math.floor(next() * n),
    pick: <T>(xs: readonly T[]): T => xs[Math.floor(next() * xs.length)]!,
    bool: (p = 0.5) => next() < p,
  };
}
export type Rng = ReturnType<typeof rng>;

// ---- mutation menu (every attack variant of the formal models, plus the ones the code adds) -----------------
export interface Mut { name: string; attack: string; apply(s: Spec): void }
export function mutationMenu(maxHops = 3): Mut[] {
  const m: Mut[] = [];
  const A = (name: string, attack: string, apply: (s: Spec) => void) => m.push({ name, attack, apply });
  A('gref=other', 'dropped_grant_ref (NO_GREF_CHECK)', (s) => { s.gref = 'other'; });
  A('gref=G', 'dropped_grant_ref (NO_GREF_CHECK)', (s) => { s.gref = 'G'; });
  A('gref=empty', 'dropped_grant_ref (NO_GREF_CHECK)', (s) => { s.gref = 'empty'; });
  A('aud=other', 'wrong_audience (NO_AUD_CHECK)', (s) => { s.aud = 'other'; });
  A('audMode=undef', 'wrong_audience (NO_AUD_CHECK)', (s) => { s.audMode = 'undef'; });
  A('audMode=null', 'audience_optout', (s) => { s.audMode = 'null'; });
  for (const t of ['atExp', 'expired', 'futureIat', 'skewEdge', 'expLEiat', 'tooLong', 'maxEdge'] as TimeKind[]) A(`time=${t}`, 'expired (NO_EXPIRY_CHECK)', (s) => { s.time = t; });
  A('leafSig=wrongKey', 'forged_leaf (NO_LEAF_SIG)', (s) => { s.leafSig = 'wrongKey'; });
  A('leafSig=stale', 'forged_leaf (NO_LEAF_SIG)', (s) => { s.leafSig = 'stale'; });
  for (const r of ['foreignP', 'forgedX', 'stale', 'xIssued'] as RootKind[]) A(`root=${r}`, 'forged_root', (s) => { s.root = r; });
  A('empty', 'empty_chain', (s) => { s.empty = true; });
  A('unplanned', 'action_not_in_plan', (s) => { s.planned = false; });
  for (const v of ALL) A(`verb=${v}`, 'verb_outside_scope', (s) => { s.verb = v; });
  for (let i = 0; i < maxHops; i++) {
    const at = (s: Spec, f: (h: HopSpec) => void) => { if (s.hops[i]) f(s.hops[i]!); };
    A(`hop${i + 1}.issuerFault`, 'relayed_hop', (s) => at(s, (x) => { x.issuerFault = true; }));
    A(`hop${i + 1}.sig=wrongKey`, 'forged_hop', (s) => at(s, (x) => { x.sigFault = 'wrongKey'; }));
    A(`hop${i + 1}.sig=stale`, 'tampered_hop', (s) => at(s, (x) => { x.sigFault = 'stale'; }));
    A(`hop${i + 1}.parentFault`, 'spliced_chain', (s) => at(s, (x) => { x.parentFault = true; }));
    A(`hop${i + 1}.prefix=drop`, 'dropped_ancestor_caveat (NO_ANCESTOR_CAV)', (s) => at(s, (x) => { x.prefixFault = 'drop'; }));
    A(`hop${i + 1}.prefix=alter`, 'widened_caveat', (s) => at(s, (x) => { x.prefixFault = 'alter'; }));
  }
  return m;
}

/** all benign base specs: root verbs x hop count x per-hop pin x per-hop holder x verb (and planned) */
export function* benignBases(maxHops = 3): Generator<Spec> {
  for (const rv of ROOT_VERBS) {
    for (let n = 0; n <= maxHops; n++) {
      const combos = (PINS.length * HOLDERS.length) ** n;
      for (let c = 0; c < combos; c++) {
        let x = c;
        const hops: HopSpec[] = [];
        for (let i = 0; i < n; i++) {
          const k = x % (PINS.length * HOLDERS.length);
          x = Math.floor(x / (PINS.length * HOLDERS.length));
          hops.push(baseHop(HOLDERS[k % 3]!, PINS[Math.floor(k / 3)]!));
        }
        for (const verb of ALL) {
          const s = baseSpec();
          s.rootVerbs = rv; s.hops = hops; s.verb = verb;
          yield s;
        }
      }
    }
  }
}
export const cloneSpec = (s: Spec): Spec => JSON.parse(JSON.stringify(s)) as Spec;

/** uniformly random benign base */
export function randomBase(r: Rng, maxHops = 3): Spec {
  const s = baseSpec();
  s.rootVerbs = r.pick(ROOT_VERBS);
  const n = r.int(maxHops + 1);
  s.hops = Array.from({ length: n }, () => baseHop(r.pick(HOLDERS), r.pick(PINS)));
  s.verb = r.pick(ALL);
  s.counter = r.int(4);
  s.nonce = r.pick(['n1', 'n2', null, 'n3']);
  return s;
}

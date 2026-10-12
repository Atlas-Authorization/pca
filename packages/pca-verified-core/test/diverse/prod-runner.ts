// prod-runner.ts : run the case file through the PRODUCTION bridge (src/*.ts over generated/pca_core.js) and
// print one canonical result line per case, in exactly the format Harness.dfy prints (so transcripts are `cmp`-able).
// Where a case holds integers beyond 2^53 (the typed bridge only takes safe integers) the raw Dafny-JS API is used.
import BigNumber from 'bignumber.js';
import * as PNS from '../../src/index';
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const P: any = (PNS as any).default ?? PNS;
import type * as PT from '../../src/index';
import * as BRNS from '../../src/bridge';
const BR: any = (BRNS as any).default ?? BRNS;
const { D, Verdict: VD, Replay: RP, Caveats: CV, dstr, seq: dseq } = BR;

const st = (c: number) => (c === 0 ? 'pass' : c === 1 ? 'fail' : 'not-enforced') as PT.Status;
const S = (s: PT.Status | undefined) => (s === undefined ? '-' : s === 'pass' ? 'P' : s === 'fail' ? 'F' : 'N');
const B = (b: boolean) => (b ? '1' : '0');
const okErr = (v: number): PT.Res<number> => (v < 0 ? { ok: true } : { ok: false, m: v });
const ceq = (mode: number) => (a: number, b: number) => (mode === 0 ? a === b : mode === 1 ? ((a % 3) + 3) % 3 === ((b % 3) + 3) % 3 : mode === 2);
const checksS = (cs: [string, PT.Status][]) => cs.map(([n, s]) => `${n}=${S(s)};`).join('');
const isSafe = (t: string) => /^-?\d+$/.test(t) && Number.isSafeInteger(Number(t));
const MKR = (n: string, c: PT.Status | undefined) => n.length * 7 + (c === undefined ? 1 : c === 'pass' ? 2 : c === 'fail' ? 3 : 4);
const SV = (v: string | undefined) => (v === undefined ? '-' : v === 'not-allowed' ? 'na' : v === 'no-pq-commitment' ? 'nopq' : 'mm');

class Rd { i = 0; constructor(public t: string[]) {} str() { return this.t[this.i++] ?? ''; } int() { return Number(this.str()); } raw() { return this.str(); } bool() { return Number(this.str()) !== 0; } nat() { return Math.min(Math.max(Number(this.str()), 0), 64); } oint(): number | undefined { const s = this.str(); return s === 'n' ? undefined : Number(s); } }

export function runCase(line: string): string {
  const tk = line.split(' ').filter((x) => x.length);
  if (!tk.length) return '';
  const r = new Rd(tk.slice(1));
  switch (tk[0]) {
    case 'aud': { const h = r.bool(), a = r.int(), e = r.bool(); return S(P.audienceStatus(h, a === 0 ? 'absent' : a === 1 ? 'null' : 'string', e)); }
    case 'val': {
      const c = r.bool(), iat = r.raw(), exp = r.raw(), now = r.raw();
      if ([iat, exp, now].every(isSafe)) return P.validityDecision(c, Number(iat), Number(exp), Number(now)).replace('bad-clock', 'badclock').replace('not-greater', 'notgreater').replace('too-long', 'toolong');
      const v = VD.__default.ValidityDecision(c, new BigNumber(iat), new BigNumber(exp), new BigNumber(c ? now : 0));
      return v.is_VPass ? 'pass' : v.is_VBadClock ? 'badclock' : v.is_VNotGreater ? 'notgreater' : v.is_VTooLong ? 'toolong' : v.is_VFuture ? 'future' : 'expired';
    }
    case 'ver': return S(P.versionStatus(r.bool()));
    case 'gref': { const a = r.bool(), b = r.bool(), c = r.bool(); return S(P.grantRefBoundStatus(a, b, c)); }
    case 'ctr': return S(P.counterStatus(r.bool()));
    case 'suite': { const a = r.bool(), b = r.bool(); return SV(P.suitePolicy(a, b)); }
    case 'pqb': { const a = r.bool(), b = r.bool(), c = r.bool(), d = r.bool(); return SV(P.pqBinding(a, b, c, d)); }
    case 'pqr': { const [a, b, c, d, e, f, g] = [0, 1, 2, 3, 4, 5, 6].map(() => r.bool()); return P.pqResolve({ trusted: a, artifactKeyOk: b, pinPresent: c, pinEquals: d, commitPresent: e, commitMatches: f, allowUnbound: g }); }
    case 'leaf': {
      const p = r.bool(), se = r.int(), ss = r.bool(), vf = r.bool();
      const o = P.leafDecision<number>(p, () => okErr(se), ss, () => vf);
      return o.kind === 'pass' ? 'pass' : o.kind === 'suite-error' ? `suiteerr${o.m}` : 'badsig';
    }
    case 'cap': {
      const ne = r.bool(), rg = r.bool(), w = r.int();
      const o = P.capChainStatus<number>(ne, () => rg, () => okErr(w));
      return o.kind === 'empty' ? 'empty' : o.kind === 'root-not-grant' ? 'rootnotgrant' : o.ok ? 'walked:ok' : `walked:err${o.m}`;
    }
    case 'hook': { const e = r.bool(), o = r.bool(); return S(P.hookStatus(e, o)); }
    case 'plan': { const s = r.bool(), m = r.bool(), a = r.int(); const o = P.planDecision(s, m, a < 0 ? undefined : a !== 0); return o === 'not-enforced' ? 'ne' : o === 'unauthorized' ? 'unauth' : o; }
    case 'beacon': { const a = r.bool(), b = r.bool(), c = r.bool(), d = r.bool(); const o = P.beaconDecision(a, b, c, d); return o === 'not-enforced' ? 'ne' : o; }
    case 'rev': {
      const d = r.int(), s = r.int(); const so = s < 0 ? undefined : s; const o = P.reversibilityDecision(d, so);
      return (o === 'no-server-class' ? 'nosc' : o === 'less-restrictive' ? 'less' : 'pass') + B(P.useDeclaredClass(d, so));
    }
    case 'thr': { const t = r.int(), rel = r.bool(), th = r.int(), ht = r.oint(); const o = P.thresholdRule(t, rel, th < 0 ? undefined : st(th), ht); return o === 'no-verifier' ? 'nov' : o; }
    case 'core': {
      let s = P.CoreState.init<string, number>(); const n = r.nat();
      for (let k = 0; k < n; k++) {
        const op = r.str(), name = r.str();
        if (op === 'F') { const w = r.int(); s = s.fail(name, () => w); }
        else if (op === 'S') s = s.set(name, st(r.int()));
        else if (op === 'W') { const w = r.int(); s = P.CoreState.wireFail<string, number>(name, w); }
        else if (op === 'M') { const w = r.int(); s = s.malformed(name, w); }
        else if (op === 'Z') { const w = r.int(); s = s.zkRule(name, () => w); }
        else { const g = r.bool(), rq = r.bool(), w = r.int(); s = s.attestGate(name, g, rq, () => w); }
      }
      // `terminal` is not exposed by the typed API: read it off the raw state
      const term = (s as unknown as { st: { dtor_terminal: boolean } }).st.dtor_terminal;
      const rs = s.reason;
      return `${checksS(s.checks)}|${B(term)}|${B(s.allow)}|${rs === undefined ? '-' : rs}`;
    }
    case 'vst': {
      let s = P.VerdictState.init<string, number>(); const n = r.nat();
      for (let k = 0; k < n; k++) {
        const op = r.str();
        if (op === 'F') { const name = r.str(), w = r.int(); s = s.fail(name, () => w); }
        else if (op === 'S') { const name = r.str(); s = s.set(name, st(r.int())); }
        else if (op === 'P') s = s.push(r.int());
        else if (op === 'Q') { const c = r.nat(); const ms: number[] = []; for (let j = 0; j < c; j++) ms.push(r.int()); s = s.pushAll(ms); }
        else { const name = r.str(), tReq = r.int(), rel = r.bool(), th = r.int(), ht = r.oint(); s = s.applyThreshold(name, tReq, rel, th < 0 ? undefined : st(th), ht, (o) => (o === 'below' ? 1 : o === 'rejected' ? 2 : o === 'no-verifier' ? 3 : 0)); }
      }
      const rel = r.bool(), ca = r.bool(), ra = r.bool(), an = r.str(); const nreq = r.nat(); const req: string[] = []; for (let j = 0; j < nreq; j++) req.push(r.str());
      const fa = s.finalAllow(rel, ca), arf = s.attestationRequiredFails(ra, an);
      const en = P.enforceRequired<string, number>(fa, s.checks, s.reasons, req, MKR);
      const fin = VD.__default.Finalize((s as unknown as { st: unknown }).st, rel, ca, seq(req), (n: string, c: any) => MKR(n, c.is_Some ? (c.dtor_v.is_Pass ? 'pass' : c.dtor_v.is_Fail ? 'fail' : 'not-enforced') : undefined));
      const finChecks = (Array.from(fin[1]) as any[]).map((t) => [t[0], t[1].is_Pass ? 'pass' : t[1].is_Fail ? 'fail' : 'not-enforced'] as [string, PT.Status]);
      const wd = P.withDeniedFallback<number>(en.allow, en.reasons, 99);
      const rs = (xs: readonly number[]) => xs.map((x) => `${x},`).join('');
      return `${checksS(s.checks)}|${rs(s.reasons)}|${B(fa)}|${B(arf)}|${B(en.allow)}:${checksS(en.checks)}:${rs(en.reasons)}|${B(fin[0])}:${checksS(finChecks)}:${rs(Array.from(fin[2]) as number[])}|${rs(wd)}`;
    }
    case 'cav': {
      const n = r.nat(); const cs: any[] = [];
      for (let k = 0; k < n; k++) {
        const kind = r.int(), cnt = r.nat();
        if (kind === 0 || kind === 1) { let ss = D._dafny.Set.Empty; for (let j = 0; j < cnt; j++) ss = ss.Union(D._dafny.Set.fromElements(dstr(r.str()))); cs.push(kind === 0 ? CV.Caveat.create_VerbIn(ss) : CV.Caveat.create_ResIn(ss)); }
        else if (kind === 2) cs.push(CV.Caveat.create_ExpiresAt(new BigNumber(r.raw())));
        else cs.push(CV.Caveat.create_Opaque(dstr(r.str())));
      }
      const a = CV.Act.create_Act(dstr(r.str()), dstr(r.str()), new BigNumber(r.raw()));
      const ee = CV.__default.EffExpiry(dseq(cs)); let s = (ee.is_Some ? ee.dtor_v.toFixed() : '-') + '|';
      for (let k = 0; k < cs.length; k++) s += B(CV.__default.Allows(cs[k], a)) + B(CV.__default.Same(cs[k], cs[(k + 1) % cs.length]));
      return s;
    }
    case 'chain': {
      const mode = r.int(), n = r.nat(), al = r.int(); const hops: PT.ChainHop<number, number>[] = [];
      for (let k = 0; k < n; k++) {
        const wt = r.bool(), hp = r.bool(), ri = r.bool(), nc = r.nat(); const cav: number[] = []; for (let j = 0; j < nc; j++) cav.push(r.int());
        const pl = r.bool(), ih = r.bool(), su = r.int(), pq = r.int(), sg = r.int();
        hops.push({ wellTyped: wt, hasParent: hp, rootIssuerOk: ri, caveats: cav, parentLinkOk: () => pl, issuerIsParentHolder: () => ih, suite: () => okErr(su), pq: () => okErr(pq), sig: () => okErr(sg) });
      }
      const d = P.decideChain<number, number>(hops.length, (i) => hops[i]!, ceq(mode), () => okErr(al));
      if (d.ok) return 'ok';
      const e = d.error;
      switch (e.kind) {
        case 'empty': return 'empty'; case 'too-long': return 'toolong'; case 'malformed': return `malformed${e.hop}`; case 'root-has-parent': return 'roothasparent'; case 'root-issuer': return 'rootissuer';
        case 'suite': case 'pq': case 'sig': return `${e.kind}${e.hop}:${e.m}`;
        case 'parent-link': return `parentlink${e.hop}`; case 'issuer-not-holder': return `issuernotholder${e.hop}`; case 'drops': return `drops${e.hop}`;
        case 'altered': return `altered${e.hop}.${e.caveat}`; case 'alloc': return `alloc${e.m}`;
      }
      return '?';
    }
    case 'th':
    case 'th2': {
      const th2 = tk[0] === 'th2'; // th2 also carries each share's pqPkOk (recorded production facts)
      const t = r.int(); const ns = r.nat(); const R = ['agent', 'guardian', 'principal'] as const; const ro = (c: number) => (c < 0 ? undefined : R[c]);
      const sigs: PT.SignerFacts<number>[] = []; for (let k = 0; k < ns; k++) { const rl = r.int(), ko = r.bool(), po = r.bool(), key = r.int(); sigs.push({ role: ro(rl), keyOk: ko, pqOk: po, key }); }
      const nsh = r.nat(); const shs: PT.ShareFacts<number>[] = []; for (let k = 0; k < nsh; k++) { const wf = r.bool(), rl = r.int(), key = r.int(), ak = r.bool(), pq = th2 ? r.bool() : true, sg = r.bool(); shs.push({ wellFormed: wf, role: ro(rl), key, algKnown: ak, pqPkOk: pq, sigOk: () => sg }); }
      const hb = r.bool(); let bl: PT.BaselineFacts<number> | undefined;
      if (hb) { const his = r.bool(), h = r.int(), pk = r.bool(), ls = r.bool(); bl = { holderIsString: his, holder: h, pqKeyOk: () => pk, leafSigOk: () => ls }; }
      const v = P.decideThreshold(sigs, shs, t, bl);
      const rc = v.reason; const K: Record<string, string> = { 'invalid-t': 'invalidt', 'set-malformed': 'setmalformed', 'set-pq': 'setpq', 'one-key-two-roles': 'onekeytworoles', 'malformed-share': 'malformedshare', 'need-more': 'needmore', 'two-keys-for-role': 'twokeys', 'role-not-in-set': 'rolenotinset', 'key-not-registered': 'keynotreg', 'unknown-alg': 'unknownalg', 'pq-pk-mismatch': 'pqpkmismatch', 'invalid-sig': 'invalidsig' };
      const rs = rc === undefined ? '-' : K[rc.kind] + ('entry' in rc ? rc.entry : 'share' in rc ? rc.share : '');
      return `${B(v.ok)}|${v.count}|${v.roles.map((x) => x[0]).join('')}|${rs}`;
    }
    case 'rp': {
      const [nowOk, vaOk, io, am, iatOk, expOk] = [0, 1, 2, 3, 4, 5].map(() => r.bool()); const iat = r.raw(), exp = r.raw(), now = r.raw(), skew = r.raw();
      const [lo, co, cto, hn, no, rn, hc] = [0, 1, 2, 3, 4, 5, 6].map(() => r.bool());
      const dn = (o: any) => (o.is_None ? '-' : o.dtor_v.is_Malformed ? 'malformed' : o.dtor_v.is_Audience ? 'audience' : o.dtor_v.is_NotYetValid ? 'notyet' : o.dtor_v.is_Expired ? 'expired' : o.dtor_v.is_Replay ? 'replay' : 'storeunavail');
      const f = RP.Facts.create_Facts(nowOk, vaOk, io, am, iatOk, expOk, new BigNumber(iat), new BigNumber(exp), new BigNumber(now), new BigNumber(skew), lo, co, cto, hn, no, rn, hc);
      const na = RP.__default.NonceStage(f);
      const viaBridge = [iat, exp, now, skew].every(isSafe);
      let pre: string, nonce: string, retain: string, dec: string;
      if (viaBridge) {
        const rf: PT.ReplayFacts = { nowOk, verifierAudOk: vaOk, isObject: io, audMatches: am, iatOk, expOk, iat: Number(iat), exp: Number(exp), now: Number(now), skew: Number(skew), leafOk: lo, componentsOk: co, counterOk: cto, hasNonce: hn, nonceOk: no, requireNonce: rn, hasCounters: hc };
        const dd = (x: string | undefined) => (x === undefined ? '-' : x === 'not_yet_valid' ? 'notyet' : x === 'store_unavailable' ? 'storeunavail' : x);
        pre = dd(P.replayPre(rf)); nonce = P.replayNonceStage(rf); retain = String(P.replayRetainUntilExact(rf));
        const exact = RP.__default.RetainUntil(f).toFixed();
        if (exact !== retain) retain = `BRIDGE-MISMATCH:${retain}/${exact}`;
        const sum = BigInt(exp) + BigInt(skew);
        let threw = false;
        try { P.replayRetainUntil(rf); } catch (e) { threw = e instanceof RangeError; }
        if (threw !== (sum > BigInt(Number.MAX_SAFE_INTEGER))) retain = `BRIDGE-MISMATCH:numberapi-threw=${threw}`;
        dec = [[false, false], [false, true], [true, false], [true, true]].map(([a, b]) => dd(P.replayDecide(rf, a!, b!))).join(',');
      } else {
        pre = dn(RP.__default.Pre(f)); nonce = na.is_SkipNonce ? 'skip' : na.is_ConsumeNonce ? 'consume' : 'deny'; retain = RP.__default.RetainUntil(f).toFixed();
        dec = [[false, false], [false, true], [true, false], [true, true]].map(([a, b]) => dn(RP.__default.Decide(f, a, b))).join(',');
      }
      if (viaBridge) { const rawNonce = na.is_SkipNonce ? 'skip' : na.is_ConsumeNonce ? 'consume' : 'deny'; if (rawNonce !== nonce) nonce = `BRIDGE-MISMATCH:${nonce}/${rawNonce}`; }
      return `${pre}|${nonce}|${retain}|${dec}`;
    }
    case 'store': {
      const maxE = r.nat() , n = r.nat(); const m = new P.VerifiedReplayStoreModel(maxE); let out = '';
      const O = (x: string) => (x === 'accepted' ? 'A' : x === 'dup' ? 'D' : 'R');
      for (let k = 0; k < n; k++) {
        const o = r.str();
        if (o === 'C') { const key = r.str(), rt = r.int(), now = r.int(); out += O(m.consumeOnce(key, rt, now)); }
        else if (o === 'P') { m.prune(r.int()); out += 'A'; }
        else { const sname = r.str(), c = r.int(); out += O(m.advance(sname, c)); }
      }
      const raw = (m as unknown as { s: { dtor_seen: { length: number }; dtor_streams: { length: number } } }).s;
      return `${out}|${raw.dtor_seen.length}|${raw.dtor_streams.length}`;
    }
  }
  return '?';
}
function seq(a: readonly unknown[]) { return dseq(a as any[]); }


/* eslint-disable @typescript-eslint/no-explicit-any */
// goal.ts - typed bridge over the Dafny-proved goal compiler (formal/dafny/Goal*.dfy, compiled to generated/pca_goal.js).
// No Dafny datatype crosses this boundary: callers pass and receive TOKEN TAPES (keywords, exact integers, exact strings), the same
// tapes the differential harness reads (formal/dafny/difftargets/GoalHarness.dfy). The module is loaded lazily so a tree without the
// generated file only fails when the goal compiler is actually used.
import BigNumber from 'bignumber.js';
import { hardenDafnyRuntime } from './runtime';

/** One tape token: a structural keyword, an exact safe integer, or an exact string. */
export type Tok = readonly ['k', number] | readonly ['i', number] | readonly ['s', string];
export type Tape = readonly Tok[];

export class GoalUnavailable extends Error {
  constructor(cause: unknown) {
    super(`pca-verified-core/goal: generated/pca_goal.js is missing (run formal/dafny/build-ext.sh Goal and commit it): ${String(cause)}`);
    this.name = 'GoalUnavailable';
  }
}

let cached: { D: any; F: any } | undefined;
function load(): { D: any; F: any } {
  if (cached) return cached;
  let gen: { _dafny: any; GoalApi: any };
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    gen = require('../generated/pca_goal.js');
  } catch (e) {
    throw new GoalUnavailable(e);
  }
  cached = { D: hardenDafnyRuntime(gen._dafny), F: gen.GoalApi.__default };
  return cached;
}

const bn = (n: number): BigNumber => {
  if (!Number.isSafeInteger(n)) throw new RangeError(`goal tape: ${n} is not a safe integer`);
  return new BigNumber(n);
};

function toDafny(tape: Tape): any {
  const { D, F } = load();
  const a = D.Seq.of();
  for (const t of tape) {
    if (t[0] === 'k') a.push(F.MkKw(bn(t[1])));
    else if (t[0] === 'i') a.push(F.MkI(bn(t[1])));
    else {
      if (typeof t[1] !== 'string') throw new TypeError('goal tape: string token expected');
      a.push(F.MkS(D.Seq.UnicodeFromString(t[1])));
    }
  }
  return a;
}

function fromDafny(seq: any): Tape {
  const { F } = load();
  const out: Tok[] = [];
  for (let i = 0; i < seq.length; i++) {
    const t = seq[i];
    const kind = F.TokKind(t).toNumber();
    if (kind === 0) out.push(['k', F.TokKw(t).toNumber()]);
    else if (kind === 1) out.push(['i', F.TokInt(t).toNumber()]);
    else out.push(['s', F.TokStr(t).toVerbatimString(false)]);
  }
  return out;
}

export type GoalOp = 'typecheck' | 'compile' | 'decideg' | 'decidep' | 'render';

/** Run one proved entry point. `tapes` = goal, ontology, action, history (trailing ones omitted for typecheck/compile/render). */
export function goalCall(op: GoalOp, goal: Tape, ontology: Tape = [], act: Tape = [], hist: Tape = []): Tape {
  const { F } = load();
  const g = toDafny(goal);
  const o = toDafny(ontology);
  switch (op) {
    case 'typecheck': return fromDafny(F.TypecheckT(g, o));
    case 'compile': return fromDafny(F.CompileT(g, o));
    case 'decideg': return fromDafny(F.DecideGoalT(g, o, toDafny(act), toDafny(hist)));
    case 'decidep': return fromDafny(F.DecidePolicyT(g, o, toDafny(act), toDafny(hist)));
    case 'render': return fromDafny(F.RenderT(g));
  }
}

/** Tape <-> harness text (`kN`, `iN`, `s<hex>.<hex>`), the case-file syntax of GoalHarness.dfy. */
export function tapeToText(t: Tape): string {
  return t.map((x) => (x[0] === 'k' ? `k${x[1]}` : x[0] === 'i' ? `i${x[1]}` : `s${[...x[1]].map((c) => c.codePointAt(0)!.toString(16)).join('.')}`)).join(' ');
}
export function tapeFromText(s: string): Tape {
  return s.split(' ').filter((x) => x.length > 0).map((x): Tok => {
    const b = x.slice(1);
    if (x[0] === 'k') return ['k', Number(b)];
    if (x[0] === 'i') return ['i', Number(b)];
    return ['s', b === '' ? '' : String.fromCodePoint(...b.split('.').map((h) => parseInt(h, 16)))];
  });
}

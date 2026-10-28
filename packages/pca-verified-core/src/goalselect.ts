/* eslint-disable @typescript-eslint/no-explicit-any */
// goalselect.ts - typed bridge over the Dafny-modelled selector expansion (formal/dafny/GoalSelect.dfy, compiled to
// generated/pca_goalselect.js). Only string-level entry points cross the boundary: the class-verb list (G-A4) and role-path
// resolution, which the differential harness compares with the TypeScript expansion in @atlasauth/pca-goal. Lazy: a tree without
// the generated file fails only when these functions are called.
import BigNumber from 'bignumber.js';
import type { Tape, Tok } from './goal';
import { hardenDafnyRuntime } from './runtime';

export class GoalSelectUnavailable extends Error {
  constructor(cause: unknown) {
    super(`pca-verified-core/goalselect: generated/pca_goalselect.js is missing (run formal/dafny/build-ext.sh GoalSelect and commit it): ${String(cause)}`);
    this.name = 'GoalSelectUnavailable';
  }
}

let cached: { D: any; F: any; A: any } | undefined;
function load(): { D: any; F: any; A: any } {
  if (cached) return cached;
  let gen: { _dafny: any; GoalSelect: any; GoalApi: any };
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    gen = require('../generated/pca_goalselect.js');
  } catch (e) {
    throw new GoalSelectUnavailable(e);
  }
  cached = { D: hardenDafnyRuntime(gen._dafny), F: gen.GoalSelect.__default, A: gen.GoalApi.__default };
  return cached;
}

const str = (s: string): any => load().D.Seq.UnicodeFromString(s);
const strs = (xs: readonly string[]): any => load().D.Seq.of(...xs.map(str));
const strss = (xss: readonly (readonly string[])[]): any => load().D.Seq.of(...xss.map(strs));
const back = (seq: any): string[] => { const out: string[] = []; for (let i = 0; i < seq.length; i++) out.push(seq[i].toVerbatimString(false)); return out; };

/** The verbs of the catalog (`entries[i]` = [verb, ...trait closure]) whose closure has every `allOf` and none of the `noneOf` trait. */
export const selClassVerbs = (entries: readonly (readonly string[])[], allOf: readonly string[], noneOf: readonly string[]): string[] =>
  back(load().F.ClassVerbsT(strss(entries), strs(allOf), strs(noneOf)));

/** The verbs a class PROHIBITION or bound covers: the class plus every unconfirmed verb (closure has `pca.unreviewed`), whatever the selector says. */
export const selFloatClassVerbs = (entries: readonly (readonly string[])[], allOf: readonly string[], noneOf: readonly string[]): string[] =>
  back(load().F.FloatClassVerbsT(strss(entries), strs(allOf), strs(noneOf)));

/** The verbs a class ALLOW covers: the class minus every unconfirmed verb. */
export const selAllowClassVerbs = (entries: readonly (readonly string[])[], allOf: readonly string[], noneOf: readonly string[]): string[] =>
  back(load().F.AllowClassVerbsT(strss(entries), strs(allOf), strs(noneOf)));

/** The unique parameter path carrying `role` on `verb` (`roles[i]` = [verb, role, path, role, path, ...]); '' when none or several. */
export const selRolePath = (roles: readonly (readonly string[])[], verb: string, role: string): string =>
  load().F.RolePathT(strss(roles), str(verb), str(role)).toVerbatimString(false);

// ---- tapes (the same token tapes as the goal bridge)
function toDafny(tape: Tape): any {
  const { D, A } = load();
  const out = D.Seq.of();
  for (const t of tape) {
    if (t[0] === 'k') out.push(A.MkKw(new BigNumber(t[1])));
    else if (t[0] === 'i') out.push(A.MkI(new BigNumber(t[1])));
    else out.push(A.MkS(D.Seq.UnicodeFromString(t[1])));
  }
  return out;
}
function fromDafny(seq: any): Tape {
  const { A } = load();
  const out: Tok[] = [];
  for (let i = 0; i < seq.length; i++) {
    const t = seq[i];
    const kind = A.TokKind(t).toNumber();
    out.push(kind === 0 ? ['k', A.TokKw(t).toNumber()] : kind === 1 ? ['i', A.TokInt(t).toNumber()] : ['s', A.TokStr(t).toVerbatimString(false)]);
  }
  return out;
}
/**
 * The whole selector expansion of the extracted model. `goal` is the carrier tape of the selector goal, `ont` the ontology tape,
 * `cat` the catalog tape. Result: [i0, ...expanded goal tape] | [i1, i n, s reason...] | [i2] (undecodable input).
 */
export const selExpandTape = (goal: Tape, ont: Tape, cat: Tape): Tape => fromDafny(load().F.ExpandT(toDafny(goal), toDafny(ont), toDafny(cat)));

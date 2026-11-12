/* eslint-disable @typescript-eslint/no-explicit-any */
// Tests for the typed bridges over the generated goal / selector modules. The generated JavaScript is replaced by a small model
// of its Dafny API installed through the CommonJS resolver, so the TypeScript marshalling (tapes in, tapes out, strings, the
// lazy load and its failure) is pinned exactly and independently of whether the generated files exist in the tree.
import Module from 'node:module';
import BigNumber from 'bignumber.js';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { tapeFromText, tapeToText, type Tape } from '../src/goal';

const M = Module as any;
const FAKE = '/pca-verified-core-test-stub';

/** Serve `value` (or throw it, if it is an Error) for any require ending in `/<file>`. */
function install(file: string, value: unknown): void {
  const orig = M._resolveFilename;
  const fake = `${FAKE}/${file}`;
  M._resolveFilename = function (this: unknown, request: string, ...rest: unknown[]) {
    if (typeof request === 'string' && request.endsWith(`/${file}`)) {
      if (value instanceof Error) throw value;
      return fake;
    }
    return orig.call(this, request, ...rest);
  };
  M._cache[fake] = value instanceof Error ? undefined : { id: fake, filename: fake, loaded: true, exports: value, children: [], paths: [] };
  if (value instanceof Error) delete M._cache[fake];
  restores.push(() => {
    M._resolveFilename = orig;
    delete M._cache[fake];
  });
}
const restores: (() => void)[] = [];
afterEach(() => {
  while (restores.length > 0) restores.pop()!();
});
beforeEach(() => {
  vi.resetModules();
});

class Str {
  constructor(readonly s: string) {}
  toVerbatimString(flag: boolean): string {
    return flag ? `<verbatim:${this.s}>` : this.s;
  }
}
const runtime = (): any => {
  const Seq: any = function Seq() {};
  Seq.of = (...xs: unknown[]) => [...xs];
  Seq.UnicodeFromString = (s: string) => new Str(s);
  return Seq;
};
const tok = {
  MkKw: (n: BigNumber) => ({ kind: 0, n }),
  MkI: (n: BigNumber) => ({ kind: 1, n }),
  MkS: (s: Str) => ({ kind: 2, s }),
  TokKind: (t: any) => new BigNumber(t.kind),
  TokKw: (t: any) => t.n,
  TokInt: (t: any) => t.n,
  TokStr: (t: any) => t.s,
};
const kw = (n: number) => tok.MkKw(new BigNumber(n));
const int = (n: number) => tok.MkI(new BigNumber(n));
const echo = (code: number, ...seqs: unknown[][]) => [kw(code), ...seqs.map((s) => int(s.length))];

const caught = (fn: () => unknown): any => {
  try {
    fn();
  } catch (e) {
    return e;
  }
  throw new Error('expected a throw');
};

describe('goal bridge', () => {
  const goalModule = () => {
    let reads = 0;
    const _dafny = { Seq: runtime() };
    const api = {
      ...tok,
      TypecheckT: (g: unknown[], o: unknown[]) => echo(100, g, o),
      CompileT: (g: unknown[], o: unknown[]) => [...g, ...o],
      DecideGoalT: (g: unknown[], o: unknown[], a: unknown[], h: unknown[]) => echo(102, g, o, a, h),
      DecidePolicyT: (g: unknown[], o: unknown[], a: unknown[], h: unknown[]) => echo(103, g, o, a, h),
      RenderT: () => [kw(104), int(7), tok.MkS(new Str('héllo'))],
    };
    const exp = {
      _dafny,
      get GoalApi() {
        reads++;
        return { __default: api };
      },
    };
    return { exp, reads: () => reads, Seq: _dafny.Seq };
  };
  const load = async () => {
    const m = goalModule();
    install('pca_goal.js', m.exp);
    return { ...(await import('../src/goal')), m };
  };

  it('reports a missing generated module with its name and message', async () => {
    install('pca_goal.js', new Error('no such file'));
    const { goalCall, GoalUnavailable } = await import('../src/goal');
    const e = caught(() => goalCall('typecheck', []));
    expect(e).toBeInstanceOf(GoalUnavailable);
    expect(e.name).toBe('GoalUnavailable');
    expect(e.message).toBe('pca-verified-core/goal: generated/pca_goal.js is missing (run formal/dafny/build-ext.sh Goal and commit it): Error: no such file');
  });
  it('loads once, hardens the runtime and calls the right entry point', async () => {
    const { goalCall, m } = await load();
    expect(goalCall('typecheck', [['k', 1], ['i', 2]], [['s', 'x']])).toEqual([['k', 100], ['i', 2], ['i', 1]]);
    expect(goalCall('decideg', [['k', 1]], [], [['k', 1], ['k', 2]], [['i', 1], ['i', 2], ['i', 3]])).toEqual([['k', 102], ['i', 1], ['i', 0], ['i', 2], ['i', 3]]);
    expect(goalCall('decidep', [['k', 1]], [['k', 1]], [], [['k', 1]])).toEqual([['k', 103], ['i', 1], ['i', 1], ['i', 0], ['i', 1]]);
    expect(goalCall('render', [['k', 1]])).toEqual([['k', 104], ['i', 7], ['s', 'héllo']]);
    expect(m.reads()).toBe(1);
    expect(typeof m.Seq.Concat).toBe('function');
  });
  it('omitted trailing tapes are empty', async () => {
    const { goalCall } = await load();
    expect(goalCall('decideg', [['k', 1]])).toEqual([['k', 102], ['i', 1], ['i', 0], ['i', 0], ['i', 0]]);
    expect(goalCall('decidep', [['k', 1]], [['k', 1]])).toEqual([['k', 103], ['i', 1], ['i', 1], ['i', 0], ['i', 0]]);
    expect(goalCall('decidep', [['k', 1]], [['k', 1]], [['k', 1]])).toEqual([['k', 103], ['i', 1], ['i', 1], ['i', 1], ['i', 0]]);
  });
  it('round-trips every token kind exactly', async () => {
    const { goalCall } = await load();
    const tape: Tape = [['k', 3], ['i', -5], ['s', 'aé€\u{1f600}'], ['s', ''], ['i', Number.MAX_SAFE_INTEGER], ['k', 0]];
    expect(goalCall('compile', tape, [['k', 9]])).toEqual([...tape, ['k', 9]]);
  });
  it('refuses a number that is not a safe integer and a non-string string token', async () => {
    const { goalCall } = await load();
    const big = caught(() => goalCall('typecheck', [['k', 2 ** 53]]));
    expect(big).toBeInstanceOf(RangeError);
    expect(big.message).toBe('goal tape: 9007199254740992 is not a safe integer');
    const frac = caught(() => goalCall('typecheck', [['i', 1.5]]));
    expect(frac).toBeInstanceOf(RangeError);
    expect(frac.message).toBe('goal tape: 1.5 is not a safe integer');
    const s = caught(() => goalCall('typecheck', [['s', 5 as unknown as string]]));
    expect(s).toBeInstanceOf(TypeError);
    expect(s.message).toBe('goal tape: string token expected');
  });
});

describe('tape text', () => {
  it('prints k/i/s tokens with hexadecimal code points', () => {
    expect(tapeToText([['k', 3], ['i', -5], ['s', 'aé€\u{1f600}'], ['s', '']])).toBe('k3 i-5 s61.e9.20ac.1f600 s');
    expect(tapeToText([])).toBe('');
  });
  it('parses it back, ignoring extra spaces', () => {
    expect(tapeFromText('k3  i-5 s61.e9.20ac.1f600 s k0')).toEqual([['k', 3], ['i', -5], ['s', 'aé€\u{1f600}'], ['s', ''], ['k', 0]]);
    expect(tapeFromText('')).toEqual([]);
    expect(tapeFromText('i12')).toEqual([['i', 12]]);
    expect(tapeFromText('sff')).toEqual([['s', 'ÿ']]);
  });
});

describe('goalselect bridge', () => {
  const join = (x: Str[]) => x.map((s) => s.s).join(',');
  const verbs = (tag: string) => (e: Str[][], a: Str[], n: Str[]) => [new Str(`${tag}:${e.map(join).join(';')}`), new Str(`${tag}-all:${join(a)}`), new Str(`${tag}-none:${join(n)}`)];
  const selModule = () => {
    let reads = 0;
    const _dafny = { Seq: runtime() };
    const exp = {
      _dafny,
      get GoalSelect() {
        reads++;
        return {
          __default: {
            ClassVerbsT: verbs('cv'),
            FloatClassVerbsT: verbs('fl'),
            AllowClassVerbsT: verbs('al'),
            RolePathT: (roles: Str[][], verb: Str, role: Str) => new Str(`${verb.s}|${role.s}|${roles.map(join).join(';')}`),
            ExpandT: (g: unknown[], o: unknown[], c: unknown[]) => [...g, ...o, ...c],
          },
        };
      },
      GoalApi: { __default: { ...tok } },
    };
    return { exp, reads: () => reads, Seq: _dafny.Seq };
  };
  const load = async () => {
    const m = selModule();
    install('pca_goalselect.js', m.exp);
    return { ...(await import('../src/goalselect')), m };
  };

  it('reports a missing generated module with its name and message', async () => {
    install('pca_goalselect.js', new Error('no such file'));
    const { selClassVerbs, GoalSelectUnavailable } = await import('../src/goalselect');
    const e = caught(() => selClassVerbs([], [], []));
    expect(e).toBeInstanceOf(GoalSelectUnavailable);
    expect(e.name).toBe('GoalSelectUnavailable');
    expect(e.message).toBe('pca-verified-core/goalselect: generated/pca_goalselect.js is missing (run formal/dafny/build-ext.sh GoalSelect and commit it): Error: no such file');
  });
  it('marshals the string lists and reads the result back as plain strings', async () => {
    const { selClassVerbs, selFloatClassVerbs, selAllowClassVerbs, selRolePath, m } = await load();
    const entries = [['v1', 'a', 'b'], ['v2']];
    expect(selClassVerbs(entries, ['x', 'y'], ['z'])).toEqual(['cv:v1,a,b;v2', 'cv-all:x,y', 'cv-none:z']);
    expect(selFloatClassVerbs(entries, ['x'], [])).toEqual(['fl:v1,a,b;v2', 'fl-all:x', 'fl-none:']);
    expect(selAllowClassVerbs([], [], ['q'])).toEqual(['al:', 'al-all:', 'al-none:q']);
    expect(selRolePath([['v', 'r', 'p'], ['w']], 'v', 'r')).toBe('v|r|v,r,p;w');
    expect(m.reads()).toBe(1);
    expect(typeof m.Seq.Concat).toBe('function');
  });
  it('round-trips every token kind through the whole expansion', async () => {
    const { selExpandTape } = await load();
    const goal: Tape = [['k', 1], ['i', -2], ['s', 'aé']];
    expect(selExpandTape(goal, [['k', 3], ['s', '']], [['s', 'x'], ['i', 7]])).toEqual([...goal, ['k', 3], ['s', ''], ['s', 'x'], ['i', 7]]);
    expect(selExpandTape([], [], [])).toEqual([]);
  });
});

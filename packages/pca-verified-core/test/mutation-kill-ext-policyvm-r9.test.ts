/* eslint-disable @typescript-eslint/no-explicit-any */
// 0.4.2 mutation kill (Stryker run 39706550807): the glue re-checks that the proved RootCaveats selection is a subsequence of the
// ORIGINAL caveat objects and refuses (with this exact reason) if it is not. The proof makes that unreachable for the real function,
// so the proved entry point is replaced for one call by one that returns a value that is not one of the inputs.
import { afterEach, describe, expect, it } from 'vitest';
import { PolicyVmUnsupported, createPolicyVm, toValue } from '../src/ext-policyvm';

// eslint-disable-next-line @typescript-eslint/no-require-imports
const gen = require('../generated/pca_policyvm.js') as { _dafny: any; PolicyVm: any };
const dflt = gen.PolicyVm.__default;
const real = dflt.RootCaveats;
afterEach(() => {
  dflt.RootCaveats = real;
});

describe('rootCaveats: subsequence guard', () => {
  const vm = createPolicyVm({ safeRegex: () => true, regexFullMatch: () => true });
  it('a selection that is not made of the input caveats is refused with the named reason', () => {
    const cav = [{ type: 'expires', at: 1 }, { type: 'budget', limit: 5 }];
    dflt.RootCaveats = () => gen._dafny.Seq.of(toValue({ type: 'forged' }));
    expect(() => vm.rootCaveats(cav as never)).toThrow(new PolicyVmUnsupported('rootCaveats: selection is not a subsequence'));
    expect(() => vm.rootCaveats(cav as never)).toThrow('pca-verified-core/policyvm: unsupported input (rootCaveats: selection is not a subsequence)');
  });
  it('a selection with more members than the input is refused too', () => {
    const cav = [{ type: 'expires', at: 1 }];
    dflt.RootCaveats = (s: any) => gen._dafny.Seq.of(...Array.from(s as any[]), toValue({ type: 'extra' }));
    expect(() => vm.rootCaveats(cav as never)).toThrow(PolicyVmUnsupported);
  });
});

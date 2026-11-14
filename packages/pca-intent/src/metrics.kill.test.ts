import { describe, expect, it } from 'vitest';
import {
  acceptabilityOf,
  createLearner,
  DEFAULT_HARM,
  estimateResidualRiskMC,
  hoeffdingHalfWidth,
  measureGrant,
  measureGrantExact,
  wilsonInterval,
  type Acceptability,
  type HarmModel,
  type IntentLearner,
  type Omega,
  type VerbSpace,
} from './index';

const AM = 'action.params.amount';
const VR: VerbSpace = { verb: 'v.r', reversibility: 'reversible', weight: 0.5, dims: [{ kind: 'num', path: AM, lo: 0, hi: 3, cuts: [1, 2, 3], dist: 'uniform' }] };
const VI: VerbSpace = { verb: 'v.i', reversibility: 'irreversible', weight: 0.5, dims: [] };
const om: Omega = { v: 1, verbs: [VR, VI], approximate: [] };
const grant = { predicates: [{ verb: 'v.r', resource: '*' }] };
// fractional acceptability so 1 - a, a and the harm factor all matter
const acc: Acceptability = (vs, o) => (vs.verb === 'v.r' ? ((o.values[AM] as number) <= 1 ? 0.75 : 0.25) : 0.5);
const harm2: HarmModel = { verb: (vs) => (vs.verb === 'v.r' ? 2 : 3), dim: (_d, x) => 1 + (x as number) };

describe('acceptabilityOf and the Hoeffding half-width', () => {
  it('admitted is 1, not admitted is 0', () => {
    expect(acceptabilityOf(grant)(VR, { verb: 'v.r', values: {} })).toBe(1);
    expect(acceptabilityOf(grant)(VI, { verb: 'v.i', values: {} })).toBe(0);
  });

  it('exact widths at the default and an explicit confidence', () => {
    expect(hoeffdingHalfWidth(2, 50)).toBe(0.38412911652796833);
    expect(hoeffdingHalfWidth(2, 50, 0.1)).toBe(0.34616367652045704);
  });
});

describe('measureGrant (seeded Monte Carlo)', () => {
  it('defaults: 20000 samples, seed 1, the default harm and the observed maximum harm', () => {
    expect(measureGrant(om, grant, acc)).toEqual({ risk: 0.25507700000000477, burden: 0.249525, riskMax: 2.7503269999999107, fidelity: 0.9072557554065341, samples: 20000, riskHalfWidth: 0.09603227913199208 });
  });

  it('explicit samples and seed are used', () => {
    expect(measureGrant(om, grant, acc, { samples: 40, seed: 3 })).toEqual({ risk: 0.261875, burden: 0.2625, riskMax: 2.886875, fidelity: 0.9092877246157177, samples: 40, riskHalfWidth: hoeffdingHalfWidth(10, 40) });
    expect(measureGrant(om, grant, acc, { samples: 40 })).toEqual({ risk: 0.26131249999999995, burden: 0.2375, riskMax: 2.6363125, fidelity: 0.9008795429221688, samples: 40, riskHalfWidth: hoeffdingHalfWidth(10, 40) });
  });

  it('an explicit harm and H_max are used', () => {
    expect(measureGrant(om, grant, acc, { samples: 40, seed: 3, harm: harm2, hMax: 100 })).toEqual({ risk: 1.6375, burden: 0.2625, riskMax: 2.425, fidelity: 0.32474226804123707, samples: 40, riskHalfWidth: hoeffdingHalfWidth(100, 40) });
  });

  it('with nothing unacceptable the fidelity is exactly 1', () => {
    expect(measureGrant(om, grant, () => 1, { samples: 40, seed: 3 })).toEqual({ risk: 0, burden: 0.525, riskMax: 0, fidelity: 1, samples: 40, riskHalfWidth: hoeffdingHalfWidth(10, 40) });
  });
});

describe('measureGrantExact', () => {
  it('exact sums over every cell with the default harm', () => {
    expect(measureGrantExact(om, grant, acc)).toEqual({ risk: 0.255, burden: 0.25, riskMax: 2.755, fidelity: 0.9074410163339383, meanHarm: 5.5075 });
  });

  it('an explicit harm is used', () => {
    expect(measureGrantExact(om, grant, acc, harm2)).toEqual({ risk: 1.5, burden: 0.25, riskMax: 2.25, fidelity: 0.33333333333333337, meanHarm: 4 });
  });

  it('with nothing unacceptable the fidelity is exactly 1', () => {
    expect(measureGrantExact(om, grant, () => 1)).toEqual({ risk: 0, burden: 0.5, riskMax: 0, fidelity: 1, meanHarm: 5.5075 });
  });
});

describe('wilsonInterval', () => {
  it('no trials is the uninformative interval', () => {
    expect(wilsonInterval(0, 0)).toEqual({ p: NaN, lo: 0, hi: 1 });
  });

  it('exact bounds, clamped into [0, 1], at the default and an explicit z', () => {
    expect(wilsonInterval(3, 10)).toEqual({ p: 0.3, lo: 0.10779126740630099, hi: 0.6032218525388546 });
    expect(wilsonInterval(0, 5)).toEqual({ p: 0, lo: 0, hi: 0.43448246478317476 });
    expect(wilsonInterval(5, 5)).toEqual({ p: 1, lo: 0.5655175352168251, hi: 1 });
    expect(wilsonInterval(3, 10, 1)).toEqual({ p: 0.3, lo: 0.1788208207567646, hi: 0.45754281560687166 });
  });
});

describe('estimateResidualRiskMC', () => {
  // cells amount 0..2 are in the grant at acceptance 1, 0.75, 0.5; amount 3 is out; v.i is in at acceptance 1
  const learner = () => {
    const l = createLearner(om, { tau: 0.4 });
    l.observe({ verb: 'v.r', values: { [AM]: 0 } }, 1);
    l.observe({ verb: 'v.i', values: {} }, 1);
    return l;
  };

  it('defaults: 20000 samples at seed 7', () => {
    expect(estimateResidualRiskMC(learner())).toBe(0.09641350000000387);
  });

  it('draws exactly the requested number of samples', () => {
    for (const samples of [1, 2, 5]) {
      let calls = 0;
      const stub = {
        omega: om,
        harm: DEFAULT_HARM,
        synthesize: () => ({ predicates: [{ verb: 'v.r', resource: '*' }, { verb: 'v.i', resource: '*' }] }),
        acceptance: () => {
          calls++;
          return 1;
        },
      } as unknown as IntentLearner;
      expect(estimateResidualRiskMC(stub, { samples, seed: 3 })).toBe(0);
      expect(calls).toBe(samples);
    }
  });

  it('explicit samples and seed are used', () => {
    expect(estimateResidualRiskMC(learner(), { samples: 40, seed: 3 })).toBe(0.101625);
    expect(estimateResidualRiskMC(learner(), { samples: 40 })).toBe(0.06337499999999999);
  });
});

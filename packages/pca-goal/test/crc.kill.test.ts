import { describe, expect, it } from 'vitest';
import { ASSUMPTIONS, renderReportMarkdown, type DomainReport } from '../src/crc';

const pay: DomainReport = {
  domain: 'pay', modelSet: 'm', alpha: 0.1, levels: ['L0', 'L1'],
  calibration: { level: 1, n: 30, feasible: true, correctedRisk: 0.1, minN: 9, levelName: 'L1' },
  test: { n: 40, widening: { k: 2, rate: 0.05, cpUpper95: 0.1234567 }, escalationRate: 0.25, falseRestrictionRate: 0.125, meanQuestions: 1.5 },
  gatePassed: true,
  perLevel: [
    { level: 'L0', widening: { k: 3, n: 30, cpUpper95: 0.2 }, escalationRate: 0.1 },
    { level: 'L1', widening: { k: 1, n: 30, cpUpper95: 0.5 }, escalationRate: 1 / 3 },
  ],
  compileWidening: { k: 0, n: 30 },
};
const mail: DomainReport = {
  ...pay, domain: 'mail', alpha: 0.05, gatePassed: false,
  calibration: { level: 0, n: 12, feasible: false, correctedRisk: 0.5, minN: 19, levelName: 'L0' },
  test: { n: 7, widening: { k: 0, rate: 0, cpUpper95: 1 }, escalationRate: 0, falseRestrictionRate: 1, meanQuestions: 0 },
  perLevel: [{ level: 'L0', widening: { k: 0, n: 12, cpUpper95: 0.25 }, escalationRate: 0.5 }],
  compileWidening: { k: 0, n: 12 },
};
const TABLE = '| Domain | alpha | n (test) | widening k | rate | 95% upper (Clopper-Pearson) | escalation | false restriction | mean questions | gate |';
const TAIL = [
  '', '## Guarantee and assumptions', '',
  'Under the assumptions below, E[loss] <= alpha (finite-sample corrected, proved in Crc.lean), where loss = 1 when the auto-accepted policy permits a probe the principal rejects.', '',
  ...ASSUMPTIONS.map((a) => `- ${a}`),
];

describe('renderReportMarkdown', () => {
  it('renders the live report exactly, one section per domain', () => {
    const want = [
      '# Intent fidelity report (live models)', '', 'Model set: ms1', '',
      TABLE, '|---|---|---|---|---|---|---|---|---|---|',
      '| pay | 0.1 | 40 | 2 | 0.0500 | 0.1235 | 0.250 | 0.125 | 1.50 | pass |',
      '| mail | 0.05 | 7 | 0 | 0.0000 | 1.0000 | 0.000 | 1.000 | 0.00 | FAIL |',
      '', '## Calibrated threshold per domain', '',
      '- pay: level "L1" (feasible: true; calibration n = 30; corrected risk 0.1000; minimum n for alpha: 9)',
      '- mail: level "L0" (feasible: false; calibration n = 12; corrected risk 0.5000; minimum n for alpha: 19)',
      '', '## Per level (all cases)', '',
      '### pay', '', '| Level | widening k/n | 95% upper | escalation rate |', '|---|---|---|---|',
      '| L0 | 3/30 | 0.2000 | 0.100 |', '| L1 | 1/30 | 0.5000 | 0.333 |', '',
      '### mail', '', '| Level | widening k/n | 95% upper | escalation rate |', '|---|---|---|---|',
      '| L0 | 0/12 | 0.2500 | 0.500 |', '',
      '## Compile-widening (IR to policy)', '', 'Must be exactly zero; any nonzero value blocks the release.', '',
      '- pay: 0 of 30', '- mail: 0 of 12',
      ...TAIL,
    ].join('\n') + '\n';
    expect(renderReportMarkdown([pay, mail], { source: 'live', modelSet: 'ms1' })).toBe(want);
  });
  it('renders the fixture header and an empty report exactly', () => {
    const want = [
      '# Intent fidelity report (recorded fixtures)', '', 'Model set: fx', '',
      TABLE, '|---|---|---|---|---|---|---|---|---|---|',
      '', '## Calibrated threshold per domain', '',
      '', '## Per level (all cases)', '',
      '## Compile-widening (IR to policy)', '', 'Must be exactly zero; any nonzero value blocks the release.', '',
      ...TAIL,
    ].join('\n') + '\n';
    expect(renderReportMarkdown([], { source: 'fixture', modelSet: 'fx' })).toBe(want);
  });
});

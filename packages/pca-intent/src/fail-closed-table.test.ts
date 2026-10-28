/**
 * Missing-X -> result tables for the refusal paths of the intent layer that the module tests do not name. Whole results are
 * asserted (messages, states), not "did not throw".
 */
import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import { buildCatalog, defineAction } from '@atlasauth/pca/ext/research';
import { clopperPearsonUpper, commitIntentMap, createLearner, deriveOmega, DriftDetector, emitIntentMap, routeAction, verifyOutcome, type IntentSlots } from './index';

const AMT = 'action.params.amount';
const slots: IntentSlots = { verbs: ['stripe.refund'], constraints: [{ path: AMT, max: 200 }] };
const catalog = buildCatalog([defineAction({ connector: 'stripe', action: 'refund', reversibility: 'rate_limited', blastRadius: 0.5, amountField: 'amount', description: 'test refund' })]);
const omega = deriveOmega({ policies: [], slots, catalog });

describe('clopperPearsonUpper: missing X -> result', () => {
  it('no trials, or every trial failed, is the widest bound', () => {
    expect(clopperPearsonUpper(0, 0, 0.05)).toBe(1);
    expect(clopperPearsonUpper(7, 7, 0.05)).toBe(1);
  });
  it.each([
    [-1, 10, 0.05],
    [11, 10, 0.05],
    [1.5, 10, 0.05],
    [1, 10.5, 0.05],
    [Number.NaN, 10, 0.05],
  ])('k=%s n=%s is refused', (k, n, a) => {
    expect(() => clopperPearsonUpper(k, n, a)).toThrow('clopperPearsonUpper: need integers 0 <= k <= n');
  });
  it.each([0, 1, -0.1, 1.5, Number.NaN])('alpha=%s is refused', (a) => {
    expect(() => clopperPearsonUpper(1, 10, a)).toThrow('clopperPearsonUpper: alpha must be in (0, 1)');
  });
  it('the bound never drops below the observed rate', () => {
    expect(clopperPearsonUpper(2, 400, 0.05)).toBeGreaterThan(2 / 400);
    expect(clopperPearsonUpper(0, 400, 0.05)).toBeGreaterThan(0);
  });
});

describe('DriftDetector: missing X -> result', () => {
  it.each([
    [{ rho0: 0 }, 'DriftDetector: need 0 < rho0 < rho1 < 1'],
    [{ rho0: 0.3, rho1: 0.2 }, 'DriftDetector: need 0 < rho0 < rho1 < 1'],
    [{ rho1: 1 }, 'DriftDetector: need 0 < rho0 < rho1 < 1'],
    [{ rho0: Number.NaN }, 'DriftDetector: need 0 < rho0 < rho1 < 1'],
    [{ h: 0 }, 'DriftDetector: h must be positive'],
    [{ h: Number.NaN }, 'DriftDetector: h must be positive'],
  ])('options %j are refused', (o, msg) => {
    expect(() => new DriftDetector(o)).toThrow(msg);
  });
  it('a first divergence moves the statistic by log(rho1/rho0) and raises no alarm below the threshold', () => {
    const d = new DriftDetector();
    const s = d.update(true);
    expect(s.informative).toBe(1);
    expect(s.divergences).toBe(1);
    expect(s.statistic).toBeCloseTo(Math.log(0.25 / 0.02), 12);
    expect(s.alarm).toBe(false);
  });
  it('agreement never takes the statistic below zero', () => {
    const d = new DriftDetector();
    expect(d.update(false)).toEqual({ statistic: 0, alarm: false, informative: 1, divergences: 0 });
  });
  it('once raised, the alarm stays raised', () => {
    const d = new DriftDetector();
    let s = d.update(true);
    for (let i = 0; i < 5; i++) s = d.update(true);
    expect(s.alarm).toBe(true);
    for (let i = 0; i < 200; i++) s = d.update(false);
    expect(s.alarm).toBe(true);
  });
});

describe('outcomes and routing outside the outcome space', () => {
  it('verifyOutcome for a verb not in the outcome space throws', () => {
    const l = createLearner(omega, { nullMass: 0.05 });
    expect(() => verifyOutcome(l, { verb: 'gmail.send', values: {} }, {})).toThrow('verifyOutcome: no verb gmail.send in Ω');
  });
  it('a verb outside the outcome space is routed to deny', () => {
    const l = createLearner(omega, { nullMass: 0.05 });
    expect(routeAction(l, { verb: 'gmail.send', values: {} }).route).toBe('deny');
  });
});

describe('commitIntentMap: a map that does not list every cell is refused', () => {
  const k = generateKeyPair();
  const l = createLearner(omega, { nullMass: 0.05 });
  const m = emitIntentMap(l);
  it('a dropped cell', () => {
    expect(() => commitIntentMap({ ...m, cells: m.cells.slice(1) }, k.secretKey)).toThrow(/^commitIntentMap: the map does not list every cell of stripe\.refund$/);
  });
  it('a cell with the wrong arity', () => {
    const bad = { ...m, cells: m.cells.map((c, i) => (i === 0 ? { ...c, cell: [...c.cell, 0] } : c)) };
    expect(() => commitIntentMap(bad, k.secretKey)).toThrow('commitIntentMap: cell of stripe.refund has the wrong arity');
  });
  it('a cell index out of range', () => {
    const bad = { ...m, cells: m.cells.map((c, i) => (i === 0 ? { ...c, cell: c.cell.map(() => 99999) } : c)) };
    expect(() => commitIntentMap(bad, k.secretKey)).toThrow('commitIntentMap: cell index out of range for stripe.refund');
  });
});

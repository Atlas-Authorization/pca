import { createHmac, timingSafeEqual } from 'node:crypto';
import { decideCase } from './examples';
import type { Act, Decision, Goal, Hist, Ontology, RelDecl, ResSel } from './ir';

/**
 * Runtime drift monitoring (spec F8), tighten-only. A monitor compares the action stream to the goal's expected profile
 * (verbs, resources, magnitude, rate, novelty). Anomalies convert Allow to Escalate; the strike counter is a ratchet
 * (never decreases); at `lockdown` strikes every Allow becomes Escalate. `applyDrift` is pointwise <= its input on the
 * Deny < Escalate < Allow order (property-tested): it can never relax a decision.
 */
export interface DriftOptions { windowMs?: number; maxPerWindow?: number; maxNovel?: number; magnitudeFactor?: number; warmup?: number; lockdown?: number }
export interface DriftState { strikes: number; times: number[]; novel: string[]; seen: Record<string, number[]> }
export interface DriftSignal { anomalous: boolean; strikes: number; lockdown: boolean; reasons: string[] }

export const DEFAULT_DRIFT: Required<DriftOptions> = { windowMs: 60_000, maxPerWindow: 20, maxNovel: 3, magnitudeFactor: 3, warmup: 5, lockdown: 5 };

export function expectedVerbs(g: Goal): Set<string> { return new Set(g.grants.map((x) => x.verb)); }
const resIds = (s: ResSel): string[] => (s.k === 'exact' ? [s.id] : s.k === 'oneof' ? s.ids : s.k === 'all_of' ? s.parts.flatMap(resIds) : []);
const knownResources = (g: Goal): Set<string> => new Set(g.grants.flatMap((x) => resIds(x.res)));

export class DriftMonitor {
  private st: DriftState = { strikes: 0, times: [], novel: [], seen: {} };
  private readonly o: Required<DriftOptions>;
  constructor(private readonly goal: Goal, opts: DriftOptions = {}) { this.o = { ...DEFAULT_DRIFT, ...opts }; }

  observe(a: Act, t: number): DriftSignal {
    const reasons: string[] = [];
    if (!expectedVerbs(this.goal).has(a.verb)) reasons.push(`verb ${a.verb} outside the goal profile`);
    const known = knownResources(this.goal);
    if (known.size > 0 && !known.has(a.res) && !this.st.novel.includes(a.res)) { this.st.novel.push(a.res); }
    if (this.st.novel.length > this.o.maxNovel) reasons.push('novel resources beyond the allowance');
    this.st.times = [...this.st.times.filter((x) => x > t - this.o.windowMs), t];
    if (this.st.times.length > this.o.maxPerWindow) reasons.push('rate above the profile');
    for (const [p, l] of Object.entries(a.params)) {
      if (l.k !== 'q') continue;
      const hist = this.st.seen[p] ?? [];
      const v = l.q.n;
      if (hist.length >= this.o.warmup) { const mean = hist.reduce((s, x) => s + x, 0) / hist.length; if (mean > 0 && v > mean * this.o.magnitudeFactor) reasons.push(`${p} magnitude ${this.o.magnitudeFactor}x above the running mean`); }
      this.st.seen[p] = [...hist, v].slice(-50);
    }
    if (reasons.length) this.st.strikes += 1; // ratchet: only ever increases
    return { anomalous: reasons.length > 0, strikes: this.st.strikes, lockdown: this.st.strikes >= this.o.lockdown, reasons };
  }

  state(): Readonly<DriftState> { return this.st; }

  /** Sealed state: durable and not agent-writable (the monitor key is held outside the agent). */
  seal(key: Buffer): { state: DriftState; mac: string } {
    return { state: this.st, mac: createHmac('sha256', key).update(JSON.stringify(this.st)).digest('hex') };
  }
  /** Restore; a state that fails its MAC (tampered, or a rollback to fewer strikes with a forged MAC is impossible) locks down. */
  static restore(goal: Goal, sealed: { state: DriftState; mac: string }, key: Buffer, opts: DriftOptions = {}): DriftMonitor {
    const m = new DriftMonitor(goal, opts);
    const want = createHmac('sha256', key).update(JSON.stringify(sealed.state)).digest();
    const got = Buffer.from(sealed.mac, 'hex');
    if (got.length === want.length && timingSafeEqual(got, want)) m.st = sealed.state;
    else m.st = { strikes: m.o.lockdown, times: [], novel: [], seen: {} }; // fail closed
    return m;
  }
}

/** Tighten-only: Allow becomes Escalate on an anomaly or lockdown; nothing else changes; never relaxes. */
export function applyDrift(d: Decision, s: DriftSignal): Decision {
  return d === 'allow' && (s.anomalous || s.lockdown) ? 'escalate' : d;
}

/** Convenience: decide, observe, tighten. */
export function guardedDecide(goal: Goal, ont: Ontology, mon: DriftMonitor, c: { act: Act; rels: RelDecl[]; hist?: Hist }, t: number): { decision: Decision; signal: DriftSignal } {
  const base = decideCase(goal, ont, c).decision;
  const signal = mon.observe(c.act, t);
  return { decision: applyDrift(base, signal), signal };
}

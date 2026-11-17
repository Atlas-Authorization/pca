import type { AgentRecord, Directive, FleetRecord, Lift, StoredDirective, Subject } from './types';

export interface DirectiveQuery {
  /** Only directives on one of these subjects. */
  subjects?: readonly Subject[];
  /** Only directives that are not lifted and not expired at this time. */
  activeAt?: number;
  /** Only directives with seq greater than this. */
  afterSeq?: number;
  order?: 'asc' | 'desc';
  limit: number;
}

export type PutDirective = { created: true } | { created: false; existing: StoredDirective };

/**
 * Storage the engine runs on. Every method is atomic on its own; there are no multi-call transactions, so any
 * backend with a single-row compare-and-swap can implement it. `store-conformance` (see {@link runStoreConformance})
 * checks the properties the engine relies on.
 */
export interface ControlPlaneStore {
  /** True when acknowledged writes survive a restart. */
  readonly durable: boolean;
  /** The next directive sequence number: strictly increasing, never reused, even under concurrency. */
  nextSeq(): Promise<number>;
  /** Advance a source's replay floor. True only when `seq` is greater than every earlier value. */
  advanceSourceSeq(source: string, seq: number): Promise<boolean>;
  /** True the first time `key` is seen until `expiresAt`. */
  consumeNonce(key: string, expiresAt: number, now: number): Promise<boolean>;
  /** Atomic read-modify-write of one agent record. `fn` must be pure; a backend may call it more than once. */
  updateAgent(agent: string, fn: (prev: AgentRecord | undefined) => AgentRecord): Promise<AgentRecord>;
  getAgent(agent: string): Promise<AgentRecord | undefined>;
  /** Highest threat score first, then most recently seen. */
  listAgents(limit: number): Promise<AgentRecord[]>;
  countAgents(): Promise<number>;
  updateFleet(fn: (prev: FleetRecord | undefined) => FleetRecord): Promise<FleetRecord>;
  getFleet(): Promise<FleetRecord | undefined>;
  /**
   * Insert a directive. A second directive with the same id, or a freeze on a subject that already has an unlifted
   * freeze, is not inserted: the existing one is returned. Exactly one of any number of racing freezes is created.
   */
  putDirective(d: Directive): Promise<PutDirective>;
  getDirective(id: string): Promise<StoredDirective | undefined>;
  listDirectives(q: DirectiveQuery): Promise<StoredDirective[]>;
  /** Mark a directive lifted. True for the first caller only; a lifted directive is never un-lifted. */
  liftDirective(id: string, lift: Lift): Promise<boolean>;
}

const clone = <T>(x: T): T => structuredClone(x);
const subjectKey = (s: Subject) => `${s.kind}\u0000${s.id}`;

/** In-process store. Not durable; use it for tests and single-process tools. */
export class InMemoryControlPlaneStore implements ControlPlaneStore {
  readonly durable = false;
  private seq = 0;
  private readonly floors = new Map<string, number>();
  private readonly nonces = new Map<string, number>();
  private readonly agents = new Map<string, AgentRecord>();
  private fleet: FleetRecord | undefined;
  private readonly directives = new Map<string, StoredDirective>();

  async nextSeq() {
    return ++this.seq;
  }
  async advanceSourceSeq(source: string, seq: number) {
    if (!Number.isSafeInteger(seq) || seq <= (this.floors.get(source) ?? 0)) return false;
    this.floors.set(source, seq);
    return true;
  }
  async consumeNonce(key: string, expiresAt: number, now: number) {
    const until = this.nonces.get(key);
    if (until !== undefined && until >= now) return false;
    this.nonces.set(key, expiresAt);
    return true;
  }
  async updateAgent(agent: string, fn: (prev: AgentRecord | undefined) => AgentRecord) {
    const prev = this.agents.get(agent);
    const next = { ...fn(prev ? clone(prev) : undefined), agent, ver: (prev?.ver ?? 0) + 1 };
    this.agents.set(agent, clone(next));
    return clone(next);
  }
  async getAgent(agent: string) {
    const r = this.agents.get(agent);
    return r ? clone(r) : undefined;
  }
  async listAgents(limit: number) {
    return [...this.agents.values()]
      .sort((a, b) => b.score - a.score || b.last_seen - a.last_seen || (a.agent < b.agent ? -1 : 1))
      .slice(0, Math.max(0, limit))
      .map(clone);
  }
  async countAgents() {
    return this.agents.size;
  }
  async updateFleet(fn: (prev: FleetRecord | undefined) => FleetRecord) {
    const next = { ...fn(this.fleet ? clone(this.fleet) : undefined), ver: (this.fleet?.ver ?? 0) + 1 };
    this.fleet = clone(next);
    return clone(next);
  }
  async getFleet() {
    return this.fleet ? clone(this.fleet) : undefined;
  }
  async putDirective(d: Directive): Promise<PutDirective> {
    const same = this.directives.get(d.id);
    if (same) return { created: false, existing: clone(same) };
    if (d.kind === 'freeze') {
      for (const s of this.directives.values()) {
        if (s.directive.kind === 'freeze' && !s.lift && subjectKey(s.directive.subject) === subjectKey(d.subject)) return { created: false, existing: clone(s) };
      }
    }
    this.directives.set(d.id, { directive: clone(d) });
    return { created: true };
  }
  async getDirective(id: string) {
    const s = this.directives.get(id);
    return s ? clone(s) : undefined;
  }
  async listDirectives(q: DirectiveQuery) {
    const keys = q.subjects ? new Set(q.subjects.map(subjectKey)) : undefined;
    const rows = [...this.directives.values()].filter(
      (s) =>
        (!keys || keys.has(subjectKey(s.directive.subject))) &&
        (q.afterSeq === undefined || s.directive.seq > q.afterSeq) &&
        (q.activeAt === undefined || (!s.lift && (s.directive.exp === undefined || s.directive.exp > q.activeAt))),
    );
    rows.sort((a, b) => (q.order === 'desc' ? b.directive.seq - a.directive.seq : a.directive.seq - b.directive.seq));
    return rows.slice(0, Math.max(0, q.limit)).map(clone);
  }
  async liftDirective(id: string, lift: Lift) {
    const s = this.directives.get(id);
    if (!s || s.lift) return false;
    s.lift = clone(lift);
    return true;
  }
}

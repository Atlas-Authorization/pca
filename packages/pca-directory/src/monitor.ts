/**
 * The monitor / auditor: follow one log, check that it only ever grows, and say so loudly when it does not.
 *
 * Each `poll` fetches the log's head, verifies it (pinned key, witness quorum, freshness), demands a consistency proof from the
 * head it pinned last time, downloads the new entries and recomputes the whole tree from them, so a log cannot serve a head that
 * its own entries do not produce. `gossip` compares a head learned from somewhere else (another monitor, a witness, a bundle) with
 * the pinned one: two validly signed heads of one size with different roots are a split view, and the pair is the evidence.
 */
import type { SignedTreeHead, WitnessPolicy } from '@atlasauth/pca/ext/ledger';
import { detectTreeHeadEquivocation, ledgerRootOf, verifyTreeHead } from '@atlasauth/pca/ext/ledger';
import { headExtends, resolveLogKey, retiredAtSize, type SignedKeyTransition } from './rotation';
import type { PqPinPolicy } from '@atlasauth/pca';
import type { EntryView, LogClient } from './client';
import { entryCommit, isDirectoryEntry } from './entry';

export type AlertType =
  | 'bad_head'
  | 'witness_shortfall'
  | 'stale_head'
  | 'rollback'
  | 'equivocation'
  | 'inconsistent'
  | 'feed_mismatch'
  | 'unreachable'
  | 'watch_hit';

export interface Alert {
  type: AlertType;
  detail?: string;
  /** For `equivocation`: both signed heads. Anyone can verify the pair against the log's key. */
  evidence?: { a: SignedTreeHead; b: SignedTreeHead };
  /** For `watch_hit`: the entry that matched. */
  entry?: EntryView;
}

export interface MonitoredLog {
  id: string;
  guardian: string;
  instanceId?: string;
  principal?: string;
}

export interface MonitorOptions {
  log: MonitoredLog;
  client: LogClient;
  /** Witness quorum a head must carry; omit to monitor without it (a head is then only as good as the operator). */
  witnesses?: WitnessPolicy;
  maxHeadAgeMs?: number;
  /** Called for every new entry; returning true raises a `watch_hit` (e.g. a passport appears for your operator or your agent's key). */
  watch?: (e: EntryView) => boolean;
  pins?: PqPinPolicy;
  now?: () => number;
  pageSize?: number;
}

export interface MonitorState {
  pinned?: SignedTreeHead;
  /** Commits of every entry verified so far, in log order. */
  commits: string[];
}

export interface PollReport {
  ok: boolean;
  head?: SignedTreeHead;
  newEntries: number;
  alerts: Alert[];
}

export class Monitor {
  private pinned: SignedTreeHead | undefined;
  private commits: string[] = [];

  constructor(private readonly o: MonitorOptions, state?: MonitorState) {
    if (state) {
      this.pinned = state.pinned;
      this.commits = [...state.commits];
    }
  }

  /** What to persist between runs. */
  state(): MonitorState {
    return { ...(this.pinned ? { pinned: this.pinned } : {}), commits: [...this.commits] };
  }

  private headProblem(h: SignedTreeHead, tr: readonly SignedKeyTransition[]): Alert | null {
    const l = this.o.log;
    if ((l.instanceId !== undefined && h.instance_id !== l.instanceId) || (l.principal !== undefined && h.principal !== l.principal)) return { type: 'bad_head', detail: 'not for this log' };
    // The signer is the pinned key, or the end of a witnessed chain of key transitions from it. Rotation needs a witness quorum to be believed.
    const wt = this.o.witnesses ? { ...this.o.witnesses, threshold: Math.max(1, this.o.witnesses.threshold) } : undefined;
    const k = wt ? resolveLogKey(l.guardian, h.guardian, tr, wt, { instanceId: h.instance_id, principal: h.principal }) : h.guardian === l.guardian ? { ok: true as const, key: l.guardian } : { ok: false as const };
    if (!k.ok) return { type: 'bad_head', detail: 'not signed by the pinned key or a witnessed successor of it' };
    const retired = wt ? retiredAtSize(h.guardian, tr, wt, { instanceId: h.instance_id, principal: h.principal }) : undefined;
    if (retired !== undefined && h.size > retired) return { type: 'bad_head', detail: `signed by a key retired at size ${retired}` };
    if (!verifyTreeHead(h, k.key, undefined, this.o.pins)) return { type: 'bad_head', detail: 'signature does not verify' };
    if (this.o.witnesses && !verifyTreeHead(h, h.guardian, this.o.witnesses, this.o.pins)) return { type: 'witness_shortfall', detail: `fewer than ${this.o.witnesses.threshold} trusted cosignatures` };
    const now = (this.o.now ?? Date.now)();
    if (this.o.maxHeadAgeMs !== undefined && now - h.timestamp > this.o.maxHeadAgeMs) return { type: 'stale_head', detail: `${Math.round((now - h.timestamp) / 1000)}s old` };
    return null;
  }

  /** Compare a head learned elsewhere with the pinned one. Returns an alert when it proves a problem, otherwise null. */
  gossip(other: SignedTreeHead): Alert | null {
    const a = this.pinned;
    if (!a) return null;
    if (detectTreeHeadEquivocation(a, other, a.guardian, this.o.pins)) return { type: 'equivocation', detail: `two signed roots at size ${a.size}`, evidence: { a, b: other } };
    return null;
  }

  async poll(): Promise<PollReport> {
    const alerts: Alert[] = [];
    const fail = (a: Alert): PollReport => ({ ok: false, newEntries: 0, alerts: [...alerts, a], ...(this.pinned ? { head: this.pinned } : {}) });
    let h: SignedTreeHead;
    try {
      h = await this.o.client.sth();
    } catch (e) {
      return fail({ type: 'unreachable', detail: e instanceof Error ? e.message : 'error' });
    }
    let tr: SignedKeyTransition[] = [];
    try {
      tr = (await this.o.client.transitions?.()) ?? [];
    } catch {
      tr = []; // a head from a rotated key then fails to resolve and is reported as bad_head
    }
    const problem = this.headProblem(h, tr);
    if (problem) return fail(problem);

    const p = this.pinned;
    if (p) {
      if (h.size < p.size) return fail({ type: 'rollback', detail: `head ${h.size} is behind the pinned head ${p.size}` });
      if (h.size === p.size && h.root !== p.root) {
        const g = this.gossip(h);
        return fail(g ?? { type: 'inconsistent', detail: 'same size, different root' });
      }
      if (h.size > p.size) {
        try {
          const proof = await this.o.client.consistency(p.size, h.size);
          if (!headExtends(p, h, proof, this.o.pins)) return fail({ type: 'inconsistent', detail: 'new head does not extend the pinned head' });
        } catch (e) {
          return fail({ type: 'unreachable', detail: e instanceof Error ? e.message : 'error' });
        }
      }
    }

    // Download and check the new entries, then recompute the root: the entries must produce exactly the signed head.
    const fetched: EntryView[] = [];
    try {
      const page = this.o.pageSize ?? 200;
      while (this.commits.length + fetched.length < h.size) {
        const from = this.commits.length + fetched.length;
        const got = await this.o.client.entries(from, Math.min(page, h.size - from));
        if (got.length === 0) return fail({ type: 'feed_mismatch', detail: `the log has no entry ${from} but its head claims ${h.size}` });
        for (const e of got) {
          if (e.index !== this.commits.length + fetched.length || !isDirectoryEntry(e.entry) || e.entry.log !== this.o.log.id || entryCommit(e.entry) !== e.commit) {
            return fail({ type: 'feed_mismatch', detail: `entry ${e.index} is not what the log committed to` });
          }
          fetched.push(e);
          if (this.commits.length + fetched.length > h.size) return fail({ type: 'feed_mismatch', detail: 'more entries than the head covers' });
        }
      }
    } catch (e) {
      return fail({ type: 'unreachable', detail: e instanceof Error ? e.message : 'error' });
    }
    const all = [...this.commits, ...fetched.map((e) => e.commit)];
    if (all.length !== h.size || ledgerRootOf(all) !== h.root) return fail({ type: 'feed_mismatch', detail: 'entries do not hash to the signed root' });

    // Continuity across a rotation: every transition must hand over exactly the history this monitor has verified.
    if (this.o.witnesses) {
      const k = resolveLogKey(this.o.log.guardian, h.guardian, tr, { ...this.o.witnesses, threshold: Math.max(1, this.o.witnesses.threshold) }, { instanceId: h.instance_id, principal: h.principal });
      for (const t of k.ok ? k.chain : []) {
        if (t.at_size > all.length || ledgerRootOf(all.slice(0, t.at_size)) !== t.at_root) return fail({ type: 'inconsistent', detail: `key transition ${t.seq} hands over a history that is not this log's` });
      }
    }
    this.commits = all;
    this.pinned = h;
    for (const e of fetched) if (this.o.watch?.(e)) alerts.push({ type: 'watch_hit', entry: e });
    return { ok: true, head: h, newEntries: fetched.length, alerts };
  }
}

/**
 * A witness: an independent party that cosigns a log's tree heads, but only heads that extend the last one it cosigned.
 *
 * It follows the C2SP witness rules: it pins the log's key, remembers the newest head it cosigned for each log, cosigns a
 * newer head only against a valid consistency proof from that head, cosigns an identical head again, and refuses everything else.
 * An honest witness therefore never cosigns two roots of one size, which is what makes a cosigned head evidence against a split view.
 * A log it caught signing two roots of one size is halted until an operator clears it.
 */
import { b64u, publicKeyOf } from '@atlasauth/pca';
import { cosignTransition, resolveLogKey, transitionSignaturesOk, type SignedKeyTransition } from './rotation';
import {
  cosignTreeHead,
  detectTreeHeadEquivocation,
  verifyLedgerConsistency,
  verifyTreeHead,
  type ConsistencyProof,
  type LedgerSuiteOpts,
  type SignedTreeHead,
  type WitnessCosignature,
  type WitnessPolicy,
} from '@atlasauth/pca/ext/ledger';

export interface WitnessedLog {
  /** The log's pinned signing key. */
  guardian: string;
  instanceId?: string;
  principal?: string;
}

export interface WitnessLogState {
  size: number;
  root: string;
  /** The head that was cosigned (kept as evidence should the log ever sign a second root of this size). */
  head?: SignedTreeHead;
  /** The log's STH scope, kept for a key that was learned from a transition (it is not in the witness's configuration). */
  scope?: { instanceId?: string; principal?: string };
  /** Set when a witnessed transition retired this key: it may not sign anything larger than `size` any more. */
  retiredTo?: string;
  /** Set when the log was caught signing two roots at one size; the witness cosigns nothing more for it. */
  halted?: { reason: string; a: SignedTreeHead; b: SignedTreeHead };
}

/** Where the witness remembers what it cosigned. Must be durable: forgetting it lets a log roll the witness back. */
export interface WitnessState {
  get(guardian: string): Promise<WitnessLogState | undefined>;
  set(guardian: string, s: WitnessLogState): Promise<void>;
}

export class MemoryWitnessState implements WitnessState {
  private readonly m = new Map<string, WitnessLogState>();
  async get(g: string) {
    return this.m.get(g);
  }
  async set(g: string, s: WitnessLogState) {
    this.m.set(g, s);
  }
}

export type CosignRefusal = 'unknown_log' | 'bad_head' | 'rollback' | 'equivocation' | 'halted' | 'proof_required' | 'bad_proof' | 'stale_state' | 'retired' | 'bad_transition';
export type CosignResult = { ok: true; cosignature: WitnessCosignature; size: number; root: string } | { ok: false; reason: CosignRefusal; known?: { size: number; root: string } };

export class Witness {
  readonly publicKey: string;
  private chain: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly secret: Uint8Array,
    private readonly logs: readonly WitnessedLog[],
    private readonly state: WitnessState = new MemoryWitnessState(),
    private readonly suite?: LedgerSuiteOpts,
  ) {
    this.publicKey = b64u(publicKeyOf(secret));
  }

  /** Cosign `sth`, with the consistency proof from the witness's last cosigned size when the head is newer. Serialised per witness. */
  cosign(sth: SignedTreeHead, proof?: ConsistencyProof): Promise<CosignResult> {
    const run = this.chain.then(() => this.run(sth, proof));
    this.chain = run.catch(() => undefined);
    return run;
  }

  private async run(sth: SignedTreeHead, proof?: ConsistencyProof): Promise<CosignResult> {
    try {
      let log: WitnessedLog | undefined = this.logs.find((l) => l.guardian === sth?.guardian);
      if (!log && typeof sth?.guardian === 'string') {
        const learned = await this.state.get(sth.guardian);
        if (learned?.scope) log = { guardian: sth.guardian, ...learned.scope };
      }
      if (!log) return { ok: false, reason: 'unknown_log' };
      if (!verifyTreeHead(sth, log.guardian) || (log.instanceId !== undefined && sth.instance_id !== log.instanceId) || (log.principal !== undefined && sth.principal !== log.principal)) {
        return { ok: false, reason: 'bad_head' };
      }
      const prev = await this.state.get(log.guardian);
      if (prev?.halted) return { ok: false, reason: 'halted', known: { size: prev.size, root: prev.root } };
      if (prev?.retiredTo && sth.size > prev.size) return { ok: false, reason: 'retired', known: { size: prev.size, root: prev.root } };
      if (prev) {
        const known = { size: prev.size, root: prev.root };
        if (sth.size < prev.size) return { ok: false, reason: 'rollback', known };
        if (sth.size === prev.size) {
          if (sth.root !== prev.root) {
            const other = prev.head;
            if (other && detectTreeHeadEquivocation(other, sth, log.guardian)) {
              await this.state.set(log.guardian, { ...prev, halted: { reason: 'two signed roots at one size', a: other, b: sth } });
            }
            return { ok: false, reason: 'equivocation', known };
          }
        } else if (prev.size > 0) {
          if (!proof || proof.oldSize !== prev.size || proof.newSize !== sth.size) return { ok: false, reason: 'proof_required', known };
          if (!verifyLedgerConsistency(prev.root, sth.root, proof)) return { ok: false, reason: 'bad_proof', known };
        }
      }
      // remember before signing: a crash between the two must never leave a cosignature the state does not know about
      if (!prev || sth.size > prev.size) await this.state.set(log.guardian, { ...(prev?.scope ? { scope: prev.scope } : {}), size: sth.size, root: sth.root, head: sth });
      return { ok: true, cosignature: cosignTreeHead(sth, this.secret, this.suite), size: sth.size, root: sth.root };
    } catch {
      return { ok: false, reason: 'bad_head' };
    }
  }


  /**
   * Cosign a key transition of a log this witness follows. It must be well signed by both keys, name the old key it follows, and
   * hand over EXACTLY the head this witness last cosigned (so the witness has seen the final head, no more and no less). The witness
   * then retires the old key (nothing larger than the handed-over size) and follows the new key from the same place.
   */
  cosignTransition(t: SignedKeyTransition): Promise<{ ok: true; cosignature: WitnessCosignature } | { ok: false; reason: CosignRefusal }> {
    const run = this.chain.then(async (): Promise<{ ok: true; cosignature: WitnessCosignature } | { ok: false; reason: CosignRefusal }> => {
      try {
        if (!transitionSignaturesOk(t)) return { ok: false, reason: 'bad_transition' };
        const followed = this.logs.find((l) => l.guardian === t.from);
        const scope = followed ? { instanceId: followed.instanceId, principal: followed.principal } : (await this.state.get(t.from))?.scope;
        if (!followed && !scope) return { ok: false, reason: 'unknown_log' };
        if ((scope?.instanceId !== undefined && scope.instanceId !== t.instance_id) || (scope?.principal !== undefined && scope.principal !== t.principal)) return { ok: false, reason: 'bad_transition' };
        const prev = await this.state.get(t.from);
        if (!prev) return { ok: false, reason: 'stale_state' };
        if (prev.halted) return { ok: false, reason: 'halted' };
        if (prev.size !== t.at_size || prev.root !== t.at_root) return { ok: false, reason: 'stale_state' };
        const known = { instanceId: scope?.instanceId ?? t.instance_id, principal: scope?.principal ?? t.principal };
        await this.state.set(t.to, { size: prev.size, root: prev.root, scope: known });
        await this.state.set(t.from, { ...prev, retiredTo: t.to });
        return { ok: true, cosignature: cosignTransition(t, this.secret) };
      } catch {
        return { ok: false, reason: 'bad_transition' };
      }
    });
    this.chain = run.catch(() => undefined);
    return run;
  }


  /**
   * Adopt a rotated key without blind reconfiguration: a witness that was down during a rotation checks the published, witnessed
   * transition chain from the key it follows (`from`) to the new key (`to`) and moves its state along it.
   *
   * It refuses unless: the chain resolves through valid, consecutive transitions each cosigned by `witnesses.threshold` (at least 1)
   * of the trusted witnesses; this witness never cosigned the old key beyond the first handover (`ahead`); and what it did cosign is
   * part of the handed-over history (the same head, or a consistency proof from its last head to the handover, from `consistency`).
   * A witness with no state for the old key adopts the chain on the witnesses' word (trust on first use, like any new log).
   */
  followTransitions(o: {
    from: string;
    to: string;
    transitions: readonly unknown[];
    witnesses: WitnessPolicy;
    /** Fetches the RFC 9162 consistency proof between two sizes from the log (needed only when this witness is behind the handover). */
    consistency?: (from: number, to: number) => Promise<ConsistencyProof>;
  }): Promise<{ ok: true; size: number; root: string; rotations: number } | { ok: false; reason: 'unknown_log' | 'no_chain' | 'ahead' | 'root_mismatch' | 'proof_required' | 'bad_proof' | 'halted' }> {
    type R = { ok: true; size: number; root: string; rotations: number } | { ok: false; reason: 'unknown_log' | 'no_chain' | 'ahead' | 'root_mismatch' | 'proof_required' | 'bad_proof' | 'halted' };
    const run = this.chain.then(async (): Promise<R> => {
      const followed = this.logs.find((l) => l.guardian === o.from);
      const prev = await this.state.get(o.from);
      const scope = followed ? { instanceId: followed.instanceId, principal: followed.principal } : prev?.scope;
      if (!followed && !prev?.scope) return { ok: false, reason: 'unknown_log' };
      if (prev?.halted) return { ok: false, reason: 'halted' };
      const wp: WitnessPolicy = { ...o.witnesses, threshold: Math.max(1, o.witnesses.threshold) };
      const r = resolveLogKey(o.from, o.to, o.transitions, wp, { ...(scope?.instanceId !== undefined ? { instanceId: scope.instanceId } : {}), ...(scope?.principal !== undefined ? { principal: scope.principal } : {}) });
      if (!r.ok || r.chain.length === 0) return { ok: false, reason: 'no_chain' };
      const first = r.chain[0]!;
      if (prev) {
        if (prev.size > first.at_size) return { ok: false, reason: 'ahead' };
        if (prev.size === first.at_size) {
          if (prev.root !== first.at_root) return { ok: false, reason: 'root_mismatch' };
        } else if (prev.size > 0) {
          if (!o.consistency) return { ok: false, reason: 'proof_required' };
          let proof: ConsistencyProof;
          try {
            proof = await o.consistency(prev.size, first.at_size);
          } catch {
            return { ok: false, reason: 'proof_required' };
          }
          if (proof?.oldSize !== prev.size || proof?.newSize !== first.at_size || !verifyLedgerConsistency(prev.root, first.at_root, proof)) return { ok: false, reason: 'bad_proof' };
        }
      }
      const known = { instanceId: scope?.instanceId ?? first.instance_id, principal: scope?.principal ?? first.principal };
      for (const t of r.chain) {
        await this.state.set(t.from, { size: t.at_size, root: t.at_root, scope: known, retiredTo: t.to });
        await this.state.set(t.to, { size: t.at_size, root: t.at_root, scope: known });
      }
      const last = r.chain[r.chain.length - 1]!;
      return { ok: true, size: last.at_size, root: last.at_root, rotations: r.chain.length };
    });
    this.chain = run.catch(() => undefined);
    return run;
  }

  /** Undo the retirement a transition caused, when the log abandoned that rotation (the new key's state is dropped to the same place). */
  async cancelRetirement(guardian: string): Promise<void> {
    const s = await this.state.get(guardian);
    if (s?.retiredTo) {
      const { retiredTo: _r, ...rest } = s;
      void _r;
      await this.state.set(guardian, rest);
    }
  }

  /** Lift a halt after the operator has looked at the evidence (and, say, decided which fork to follow). */
  async clearHalt(guardian: string, to?: { size: number; root: string }): Promise<void> {
    const s = await this.state.get(guardian);
    if (!s) return;
    await this.state.set(guardian, to ? { size: to.size, root: to.root } : { size: s.size, root: s.root, ...(s.head ? { head: s.head } : {}) });
  }
}

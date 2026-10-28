/**
 * Durable enforcement of a signed behavioural contract (see `contracts.ts`).
 *
 * `advanceContract` is a pure function of (state, action, contract). A deployment also needs the state to live somewhere
 * two processes cannot both advance, to survive a restart, and to stay refused once the agent has broken the contract.
 * `ContractEnforcer` is that: the monitor state is one document in a `DurableKv`, and the whole read-check-advance runs
 * inside the kv's atomic `update`, so concurrent callers are serialised (one wins each sequence number, the others see the
 * advanced state) and a stale or rolled-back state can never be advanced.
 *
 * Guarantees: only a contract signed by the PINNED principal is loaded; the state document is bound to the contract id
 * (another contract's state is refused); every malformed, corrupt or unreadable state or store error DENIES; a real
 * contract violation LATCHES the enforcer (default) so every later action is denied until the principal signs a reset.
 * Not guaranteed: liveness (a contract only says what must not happen; `responds_within` is a bounded safety obligation),
 * and nothing is enforced for actions that never pass through `check`. Contracts are safety properties.
 */
import { b64u, sha256, utf8 } from './hash';
import { sign, verifyB64u } from './keys';
import {
  checkAndAdvanceContract,
  checkContract,
  contractId,
  verifyContract,
  type ActionContext,
  type SignedContract,
} from './contracts';
import type { DurableKv } from './durable-state';
import { emptyState, stateProblem, type MonitorState } from './prohibitions';

export const CONTRACT_RESET_DOMAIN = 'atlas-pca/contract-reset/v1\0';
const DOC_VERSION = 1;

interface EnforcerDoc {
  v: 1;
  contract_id: string;
  state: MonitorState;
  /** Set when an admitted-trace contract violation was observed; cleared only by a principal-signed reset. */
  latched?: { seq: number; violated: string[] };
}

export type EnforceReason = 'ok' | 'violated' | 'latched' | 'permission' | 'state-error' | 'store-error';
export interface EnforceResult {
  allow: boolean;
  reason: EnforceReason;
  /** Violated clause / invariant ids (empty unless `reason` is 'violated' or 'latched'). */
  violated: string[];
  reasons: string[];
  /** Admitted-action count after this call. */
  seq: number;
}

export class ContractEnforcerError extends Error {
  constructor(message: string) {
    super(`ContractEnforcer: ${message}`);
    this.name = 'ContractEnforcerError';
  }
}

export interface ContractEnforcerOptions {
  /** The principal key (b64u) the contract must be signed by. Required: there is no trust-on-first-use. */
  principal: string;
  /** Key of the state document in the kv. Default `contract/<contract id>`. */
  key?: string;
  /** Wall clock (epoch ms). The state clock never goes back: the later of this and the stored `now` is used. */
  now?: () => number;
  /** Latch on a contract violation (default true). With false, a violating action is just denied. */
  latchOnViolation?: boolean;
}

const msg = (id: string, seq: number): Uint8Array => {
  const pre = utf8(CONTRACT_RESET_DOMAIN);
  const d = sha256(utf8(`${id}:${seq}`));
  const m = new Uint8Array(pre.length + d.length);
  m.set(pre);
  m.set(d, pre.length);
  return m;
};

/** The principal's authorisation to un-latch `contractId` at sequence `seq` (binds both, so it cannot be replayed later). */
export function signContractReset(principalSecret: Uint8Array, contractIdValue: string, seq: number): string {
  return b64u(sign(principalSecret, msg(contractIdValue, seq)));
}

const isDoc = (d: unknown, id: string): d is EnforcerDoc => {
  if (d === null || typeof d !== 'object') return false;
  const x = d as EnforcerDoc;
  if (x.v !== DOC_VERSION || x.contract_id !== id || stateProblem(x.state) !== null) return false;
  if (x.latched === undefined) return true;
  return Number.isInteger(x.latched.seq) && Array.isArray(x.latched.violated) && x.latched.violated.every((v) => typeof v === 'string');
};

export class ContractEnforcer {
  private constructor(
    private readonly kv: DurableKv,
    private readonly contract: SignedContract,
    private readonly key: string,
    private readonly now: () => number,
    private readonly latch: boolean,
  ) {}

  /** Throws `ContractEnforcerError` unless the contract verifies under the pinned principal. */
  static open(kv: DurableKv, contract: SignedContract, opts: ContractEnforcerOptions): ContractEnforcer {
    if (typeof opts?.principal !== 'string' || opts.principal.length === 0) throw new ContractEnforcerError('a pinned principal is required');
    const v = verifyContract(contract, opts.principal);
    if (!v.ok) throw new ContractEnforcerError(`contract refused: ${v.reason}`);
    return new ContractEnforcer(kv, contract, opts.key ?? `contract/${contractId(contract)}`, opts.now ?? Date.now, opts.latchOnViolation !== false);
  }

  /** Check one action against the permission verdict AND the contract, advancing the durable state iff both allow. Never throws. */
  async check(action: ActionContext, permitted = true): Promise<EnforceResult> {
    const id = this.contract.id;
    let out: EnforceResult = { allow: false, reason: 'store-error', violated: [], reasons: ['store unavailable'], seq: 0 };
    try {
      const wall = this.now();
      await this.kv.update(this.key, (prev) => {
        if (prev !== undefined && !isDoc(prev, id)) {
          out = { allow: false, reason: 'state-error', violated: [], reasons: ['<state>: stored state is corrupt or belongs to another contract'], seq: 0 };
          return undefined;
        }
        if (prev !== undefined && !Number.isFinite(wall)) {
          out = { allow: false, reason: 'state-error', violated: [], reasons: ['<state>: clock is not finite'], seq: prev.state.seq };
          return undefined;
        }
        const doc: EnforcerDoc = prev ?? { v: DOC_VERSION, contract_id: id, state: emptyState(Number.isFinite(wall) ? wall : 0) };
        if (doc.latched) {
          out = { allow: false, reason: 'latched', violated: doc.latched.violated, reasons: [`<latched>: contract violated at seq ${doc.latched.seq}`], seq: doc.state.seq };
          return undefined;
        }
        const r = checkAndAdvanceContract(permitted, doc.state, action, this.contract, { now: Math.max(wall, doc.state.now), expectedSeq: doc.state.seq });
        if (r.allow) {
          out = { allow: true, reason: 'ok', violated: [], reasons: [], seq: r.next.seq };
          return { ...doc, state: r.next };
        }
        const structural = r.decidedBy === 'state';
        const real = !structural && r.violated.length > 0;
        out = { allow: false, reason: structural ? 'state-error' : real ? 'violated' : 'permission', violated: real ? r.violated : [], reasons: r.reasons, seq: doc.state.seq };
        return real && this.latch ? { ...doc, latched: { seq: doc.state.seq, violated: r.violated } } : undefined;
      });
    } catch {
      out = { allow: false, reason: 'store-error', violated: [], reasons: ['store error (fail closed)'], seq: 0 };
    }
    return out;
  }

  /**
   * Read-only evaluation of `action` against the stored state: nothing is advanced or latched. Used to refuse BEFORE a replay
   * counter is spent; `check` then commits once the action is actually admitted. Never throws.
   */
  async peek(action: ActionContext): Promise<EnforceResult> {
    try {
      const prev = await this.kv.get(this.key);
      if (prev !== undefined && !isDoc(prev, this.contract.id)) return { allow: false, reason: 'state-error', violated: [], reasons: ['<state>: stored state is corrupt or belongs to another contract'], seq: 0 };
      const doc = prev as EnforcerDoc | undefined;
      if (doc?.latched) return { allow: false, reason: 'latched', violated: doc.latched.violated, reasons: [`<latched>: contract violated at seq ${doc.latched.seq}`], seq: doc.state.seq };
      const wall = this.now();
      const r = checkContract(action, this.contract, doc?.state ?? emptyState(Number.isFinite(wall) ? wall : 0));
      const seq = doc?.state.seq ?? 0;
      if (r.ok) return { allow: true, reason: 'ok', violated: [], reasons: [], seq };
      return { allow: false, reason: 'violated', violated: r.violated, reasons: r.reasons, seq };
    } catch {
      return { allow: false, reason: 'store-error', violated: [], reasons: ['store error (fail closed)'], seq: 0 };
    }
  }

  /** The current stored state, or undefined when nothing was admitted yet. Throws ContractEnforcerError on a corrupt document. */
  async state(): Promise<{ state: MonitorState; latched: boolean } | undefined> {
    const d = await this.kv.get(this.key);
    if (d === undefined) return undefined;
    if (!isDoc(d, this.contract.id)) throw new ContractEnforcerError('stored state is corrupt or belongs to another contract');
    return { state: d.state, latched: d.latched !== undefined };
  }

  /** Un-latch with the principal's signature (see `signContractReset`) at the latched sequence. Returns whether it cleared. */
  async reset(sig: string): Promise<boolean> {
    let cleared = false;
    try {
      await this.kv.update(this.key, (prev) => {
        if (!isDoc(prev, this.contract.id) || !prev.latched) return undefined;
        if (typeof sig !== 'string' || !verifyB64u(this.contract.principal, msg(this.contract.id, prev.latched.seq), sig)) return undefined;
        cleared = true;
        const { latched: _l, ...rest } = prev;
        void _l;
        return rest;
      });
    } catch {
      return false;
    }
    return cleared;
  }
}

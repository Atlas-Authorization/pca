/**
 * The witness core: decide whether to cosign a signed tree head, and remember what was cosigned.
 *
 * A witness is a small, boring, independent party. For every log it is configured for it keeps ONE thing: the latest tree head
 * it cosigned. It cosigns a new head only if the head is genuinely signed by that log's pinned guardian key AND is consistent
 * with the last one it cosigned (an RFC 9162 proof it checks itself). So it will never help an operator present a rewritten
 * history, and a guardian that signs two roots for one size is caught red-handed: both heads are stored as evidence anyone can
 * verify. A client that insists on a witness cosignature (`verifyTreeHead` with a witness policy) is thereby protected against
 * split views, as long as at least one witness it trusts is honest and independent of the operator.
 *
 * Trust on first use: the first head a witness sees for a log is accepted (there is nothing earlier to be consistent with).
 * Configure a log only after you have checked its guardian key and, ideally, its first head out of band.
 */
import { b64u, publicKeyOf } from '@atlasauth/pca';
import {
  type ConsistencyProof,
  type SignedTreeHead,
  type WitnessCosignature,
  cosignTreeHead,
  detectTreeHeadEquivocation,
  verifyHeadConsistency,
  verifyTreeHead,
} from '@atlasauth/pca/ext/ledger';
import type { DurableKv } from '@atlasauth/pca/durable-state';

export interface WitnessLog {
  instance_id: string;
  principal: string;
  /** The guardian public key (b64u) this log's heads must verify under. */
  guardian_public: string;
}

export interface WitnessOptions {
  kv: DurableKv;
  /** The witness's own Ed25519 secret key (32 bytes). */
  witnessSecret: Uint8Array;
  logs: readonly WitnessLog[];
}

export interface WitnessEvidence {
  a: SignedTreeHead;
  b: SignedTreeHead;
}
interface LogState {
  v: 1;
  latest: SignedTreeHead;
  cosignature: WitnessCosignature;
  evidence: WitnessEvidence[];
}

export type WitnessErrorCode = 'malformed_request' | 'unknown_log' | 'bad_signature' | 'proof_required' | 'inconsistent' | 'rollback' | 'equivocation' | 'state_unavailable';
export type WitnessResponse =
  | { status: 200; body: { witness: string; cosignature: WitnessCosignature; head: { size: number; root: string }; first_sight: boolean } }
  | { status: 400 | 403 | 404 | 409 | 500; body: { error: WitnessErrorCode; detail?: string; evidence?: WitnessEvidence } };

const MAX_EVIDENCE = 16;
const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);
const keyOf = (instance: string, principal: string): string => `witness/v1/${JSON.stringify([instance, principal])}`;

function decodeState(raw: unknown): LogState | undefined {
  if (raw === undefined) return undefined;
  if (!isObj(raw) || raw.v !== 1 || !isObj(raw.latest) || !isObj(raw.cosignature) || !Array.isArray(raw.evidence)) throw new Error('malformed witness state');
  return raw as unknown as LogState;
}

export class Witness {
  readonly publicKey: string;
  private readonly logs = new Map<string, WitnessLog>();

  constructor(private readonly opts: WitnessOptions) {
    if (!opts?.kv || typeof opts.kv.update !== 'function') throw new TypeError('Witness: a DurableKv is required');
    if (!(opts.witnessSecret instanceof Uint8Array) || opts.witnessSecret.length !== 32) throw new TypeError('Witness: witnessSecret must be 32 bytes');
    if (!Array.isArray(opts.logs) || opts.logs.length === 0) throw new TypeError('Witness: at least one log must be configured');
    this.publicKey = b64u(publicKeyOf(opts.witnessSecret));
    for (const l of opts.logs) {
      if (![l?.instance_id, l?.principal, l?.guardian_public].every((x) => typeof x === 'string') || !l.guardian_public) throw new TypeError('Witness: every log needs instance_id, principal and guardian_public');
      this.logs.set(keyOf(l.instance_id, l.principal), l);
    }
  }

  /** The configured logs (public data). */
  configuredLogs(): WitnessLog[] {
    return [...this.logs.values()].map((l) => ({ ...l }));
  }

  /** The last head this witness cosigned for a log, with its cosignature and any equivocation evidence. */
  async state(instance: string, principal: string): Promise<{ latest: SignedTreeHead; cosignature: WitnessCosignature; evidence: WitnessEvidence[] } | undefined> {
    if (!this.logs.has(keyOf(instance, principal))) return undefined;
    const s = decodeState(await this.opts.kv.get(keyOf(instance, principal)));
    return s && { latest: s.latest, cosignature: s.cosignature, evidence: s.evidence };
  }

  /**
   * Handle one cosign request `{ sth, proof? }`. The decision and the state change are ONE atomic read-modify-write, so two
   * concurrent requests cannot both advance from the same state, and a cosignature is never returned for a head that was not
   * durably recorded first.
   */
  async cosign(req: unknown): Promise<WitnessResponse> {
    if (!isObj(req) || !isObj(req.sth)) return { status: 400, body: { error: 'malformed_request', detail: 'expected { sth, proof? }' } };
    const sth = req.sth as unknown as SignedTreeHead;
    if (typeof sth.instance_id !== 'string' || typeof sth.principal !== 'string') return { status: 400, body: { error: 'malformed_request', detail: 'sth lacks instance_id / principal' } };
    const log = this.logs.get(keyOf(sth.instance_id, sth.principal));
    if (!log) return { status: 404, body: { error: 'unknown_log' } };
    // Only the head itself is stored and cosigned: strip any cosignatures other witnesses attached.
    const { witnesses: _w, ...bare } = sth;
    void _w;
    const head = bare as SignedTreeHead;
    if (!verifyTreeHead(head, log.guardian_public)) return { status: 403, body: { error: 'bad_signature' } };
    const proof = req.proof as ConsistencyProof | undefined;

    let res: WitnessResponse | undefined;
    try {
      await this.opts.kv.update(keyOf(sth.instance_id, sth.principal), (prevRaw) => {
        const prev = decodeState(prevRaw);
        const sign = (first: boolean): { next: LogState; res: WitnessResponse } => {
          const cosignature = cosignTreeHead(head, this.opts.witnessSecret);
          return {
            next: { v: 1, latest: head, cosignature, evidence: prev?.evidence ?? [] },
            res: { status: 200, body: { witness: this.publicKey, cosignature, head: { size: head.size, root: head.root }, first_sight: first } },
          };
        };
        if (!prev) {
          const r = sign(true);
          res = r.res;
          return r.next;
        }
        const last = prev.latest;
        if (head.size < last.size) {
          res = { status: 409, body: { error: 'rollback', detail: `the last cosigned head has size ${last.size}` } };
          return undefined;
        }
        if (head.size === last.size) {
          if (head.root === last.root) {
            // the same head again (a retry): cosign it again without changing the recorded state
            res = { status: 200, body: { witness: this.publicKey, cosignature: cosignTreeHead(head, this.opts.witnessSecret), head: { size: head.size, root: head.root }, first_sight: false } };
            return undefined;
          }
          const evidence = detectTreeHeadEquivocation(last, head, log.guardian_public) ? { a: last, b: head } : undefined;
          res = { status: 409, body: { error: 'equivocation', ...(evidence ? { evidence } : {}) } };
          if (!evidence || prev.evidence.some((e) => e.b.root === head.root)) return undefined;
          return { ...prev, evidence: [...prev.evidence, evidence].slice(-MAX_EVIDENCE) }; // persist the proof of misbehaviour
        }
        if (!isObj(proof)) {
          res = { status: 409, body: { error: 'proof_required', detail: `a consistency proof from size ${last.size} is required` } };
          return undefined;
        }
        if (!verifyHeadConsistency(last, head, proof, log.guardian_public)) {
          res = { status: 409, body: { error: 'inconsistent', detail: `the head is not an extension of the last cosigned head (size ${last.size})` } };
          return undefined;
        }
        const r = sign(false);
        res = r.res;
        return r.next;
      });
    } catch {
      return { status: 500, body: { error: 'state_unavailable' } };
    }
    return res ?? { status: 500, body: { error: 'state_unavailable' } };
  }
}

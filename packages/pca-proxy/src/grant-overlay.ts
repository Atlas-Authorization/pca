/**
 * An ISSUED grant, enforced. The guided setup (and `pca autopilot`) ends with a grant a human signed. With `agent.issuedGrant`
 * (or `--grant FILE --signer KEY`) the proxy loads it, checks the signature against the signer key the operator pinned, and from
 * then on admits a call only when the grant's envelope admits it: its predicates (verb, resource, parameter caps) and its caveats
 * (expiry, rate, reversibility). It can only TIGHTEN what the operator rules allow: a call the grant does not admit is refused
 * whatever the rule says, and a call it admits no longer waits for a human (the signed grant IS the standing approval), unless the
 * session has seen untrusted content, which still holds a write.
 *
 * What it does not do: the grant's risk budget is not replayed (the proxy keeps its own); and the recent-action times behind a
 * `rate` caveat are kept in the proxy state, so a state directory that is wiped resets the window.
 */
import { readFileSync } from 'node:fs';
import { evaluateCaveats, evaluatePredicates, readEnvelope, verifyChain, type Capability, type Caveat, type Predicate } from '@atlasauth/pca';
import { ConfigError } from './config';
import type { DurableKv } from '@atlasauth/pca/durable-state';

const KEEP = 2000;
const KEEP_MS = 24 * 3_600_000;
const KEY = 'issued-grant-recent';

export interface OverlayDecision {
  /** `auto`: the grant admits it. `deny`: it does not (or a caveat failed). */
  outcome: 'auto' | 'deny';
  reason?: string;
}

export class GrantOverlay {
  readonly predicates: Predicate[];
  readonly caveats: Caveat[];
  readonly grantId: string;

  constructor(grant: Capability, signer: string) {
    if (grant === null || typeof grant !== 'object') throw new ConfigError('the issued grant is not a capability');
    const v = verifyChain([grant], signer);
    if (!v.ok) throw new ConfigError(`the issued grant does not verify under the pinned signer: ${v.reason ?? 'refused'}`);
    const env = readEnvelope(grant);
    if (env === null) throw new ConfigError('the issued grant carries no envelope');
    this.predicates = env.predicates;
    this.caveats = env.caveats;
    this.grantId = grant.id;
  }

  /** Read and verify a grant file. Throws (the proxy does not start) when the file or the signature is wrong. */
  static load(file: string, signer: string, read: (p: string) => string = (p) => readFileSync(p, 'utf8')): GrantOverlay {
    let doc: unknown;
    try {
      doc = JSON.parse(read(file));
    } catch (e) {
      throw new ConfigError(`the issued grant ${file} cannot be read: ${e instanceof Error ? e.message : 'error'}`);
    }
    return new GrantOverlay(doc as Capability, signer);
  }

  /** Does the grant admit this call now? `reversibility` is the action's class; `kv` keeps the rate window across restarts. */
  async decide(call: { verb: string; resource: string; params: Record<string, unknown>; reversibility: string; blastRadius: number }, now: number, kv?: DurableKv): Promise<OverlayDecision> {
    const pred = evaluatePredicates(this.predicates, { action: { verb: call.verb, resource: call.resource, params: call.params, reversibility_class: call.reversibility } } as never);
    if (!pred.allowed) return { outcome: 'deny', reason: pred.reason ?? 'the issued grant does not admit this action' };
    const recent = await this.recent(now, kv);
    const cav = evaluateCaveats(this.caveats, { now, blastRadius: call.blastRadius, reversibilityClass: call.reversibility, recentActionTimes: recent });
    if (!cav.ok) return { outcome: 'deny', reason: `the issued grant's caveat failed: ${cav.failed.join(', ')}` };
    return { outcome: 'auto' };
  }

  /** Count an admitted call towards the rate window. */
  async record(now: number, kv?: DurableKv): Promise<void> {
    if (kv === undefined) {
      this.mem.push(now);
      this.mem = this.trim(this.mem, now);
      return;
    }
    await kv.update(KEY, (prev) => this.trim([...(Array.isArray(prev) ? (prev as number[]) : []), now], now));
  }

  private mem: number[] = [];
  private trim(xs: number[], now: number): number[] {
    return xs.filter((t) => typeof t === 'number' && Number.isFinite(t) && now - t <= KEEP_MS).slice(-KEEP);
  }
  private async recent(now: number, kv?: DurableKv): Promise<number[]> {
    if (kv === undefined) return this.mem;
    const v = await kv.get(KEY);
    return Array.isArray(v) ? this.trim(v as number[], now) : [];
  }
}

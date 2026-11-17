/**
 * Step-up approvals over the existing CIBA broker (`@atlasauth/pca-ciba`): a held call becomes a step-up request that carries the
 * canonical approval render of the exact arguments, a human decides it out of band (`pca-proxy approvals approve <id>`), and the
 * proxy waits for the decision up to `approvals.waitSeconds`. The decision is single use. An optional signed webhook
 * (`@atlasauth/pca-events`) tells an inbox, a chat bot or a pager that a request is waiting.
 */

import { buildGoalLineage, hashCanonical, approvalRenderDigest, readEnvelope, type Agent, type ApprovalRender, type StepUpRequest } from '@atlasauth/pca';
import { createDurableCibaBroker, createFileApprovalStore, type ApprovalBroker, type ApprovalStore } from '@atlasauth/pca-ciba';
import { buildStepUpEvent, serializeEvent, webhookHeaders, type StepUpEventType } from '@atlasauth/pca-events';

export type ApprovalOutcome = { status: 'approved'; id: string; by: string } | { status: 'denied' | 'expired'; id: string };

/** An in-process store: approvals do not survive a restart and cannot be decided from another process. */
export function memoryApprovalStore(): ApprovalStore {
  const m = new Map<string, { version: number; value: unknown }>();
  return {
    get: (k) => m.get(k),
    cas: (k, exp, value) => {
      if ((m.get(k)?.version ?? 0) !== exp) return false;
      m.set(k, { version: exp + 1, value });
      return true;
    },
  };
}

export interface ApprovalsOptions {
  storePath?: string;
  waitSeconds: number;
  webhook?: { url: string; secret: string };
  now?: () => number;
  /** Called when a request is waiting (an embedding application can decide it programmatically). */
  onRequest?: (id: string, step: StepUpRequest) => void;
  sleep?: (ms: number) => Promise<void>;
  fetchImpl?: typeof fetch;
}

export class Approvals {
  readonly broker: ApprovalBroker;
  private readonly now: () => number;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(private readonly o: ApprovalsOptions) {
    this.now = o.now ?? Date.now;
    this.sleep = o.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.broker = createDurableCibaBroker({ store: o.storePath !== undefined ? createFileApprovalStore(o.storePath) : memoryApprovalStore(), now: this.now, decisionTtlSec: 300 });
  }

  /** The step-up request for a held call: the verb, resource and exact arguments, the goal lineage and the canonical render. */
  step(agent: Agent, verb: string, resource: string, args: Record<string, unknown>, reason: string, r: number, render: ApprovalRender): StepUpRequest {
    const at = this.now();
    return {
      id: hashCanonical({ d: 'pca-proxy/stepup/v1', verb, resource, params: args, at }),
      verb,
      resource,
      tier: 3,
      reason: reason.slice(0, 300),
      goalCommit: readEnvelope(agent.grant)?.goal_commit ?? '',
      lineage: buildGoalLineage(agent, verb, resource, args),
      r,
      requestedAt: at,
      render,
      renderDigest: approvalRenderDigest(render),
    };
  }

  private async notify(type: StepUpEventType, agent: Agent, step: StepUpRequest, approvalId: string, actor?: string): Promise<void> {
    const w = this.o.webhook;
    if (w === undefined) return;
    try {
      const ev = buildStepUpEvent(type, { grant_ref: agent.grant.id, action: { verb: step.verb, resource: step.resource }, tier: 3, ...(actor !== undefined ? { actor } : {}), at: this.now() });
      const body = serializeEvent(ev);
      await (this.o.fetchImpl ?? fetch)(w.url, { method: 'POST', headers: { ...webhookHeaders(w.secret, body), 'pca-approval-id': approvalId }, body, signal: AbortSignal.timeout(5000) });
    } catch {
      /* a notifier that fails must not decide anything: the request stays pending and the CLI still works */
    }
  }

  /** Put the request to a human and wait for the decision (or the end of the wait). */
  async ask(agent: Agent, step: StepUpRequest): Promise<ApprovalOutcome> {
    const req = await this.broker.start(step, { expiresInSec: this.o.waitSeconds, stepUpScope: false, interval: 1 });
    const id = req.auth_req_id;
    await this.notify('step_up.created', agent, step, id);
    this.o.onRequest?.(id, step);
    const deadline = this.now() + this.o.waitSeconds * 1000;
    for (;;) {
      const s = await this.broker.get(id);
      if (s === undefined) return { status: 'expired', id };
      if (s.status === 'denied') {
        await this.notify('step_up.denied', agent, step, id, s.decidedBy);
        return { status: 'denied', id };
      }
      if (s.status === 'approved') {
        // single use: a second wait on the same approval gets invalid_grant
        const t = await this.broker.token(id);
        if (!t.ok) return { status: t.error === 'access_denied' ? 'denied' : 'expired', id };
        await this.notify('step_up.approved', agent, step, id, s.decidedBy);
        return { status: 'approved', id, by: s.decidedBy ?? 'unknown' };
      }
      if (s.status === 'expired' || this.now() >= deadline) {
        await this.notify('step_up.expired', agent, step, id);
        return { status: 'expired', id };
      }
      await this.sleep(250);
    }
  }
}

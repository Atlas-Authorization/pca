import { describe, expect, it } from 'vitest';
import { b64u, hashCanonical } from './hash';
import { publicKeyOf } from './keys';
import { signStepReceipt, wfOutput, workflowReceiptError, type WorkflowBody } from './workflow';

const P = new Uint8Array(32).fill(91);
const RS = new Uint8Array(32).fill(92);
const PK = b64u(publicKeyOf(P));
const RSK = b64u(publicKeyOf(RS));
const NOW = 1_800_000_000_000;
const D = (s: string) => hashCanonical({ v: s });
const step = (id: string, deps: string[] = []) => ({ id, verb: 'v', resource: 'r', params_digest: null, deps, sink: null, deny_labels: [], escalate_labels: [], fresh_ms: null, cost: {} });
const body = (): WorkflowBody =>
  ({ v: 1, id: 'w', principal: PK, goal_digest: null, plan_root: null, issued_at: NOW - 10, expires_at: NOW + 10, steps: [step('a')], edges: [], budget: { max_steps: 5, caps: {} } }) as WorkflowBody;

describe('a non-finite clock never accepts a receipt chain (workflow)', () => {
  it('a finite clock accepts the receipt', () => {
    const b = body();
    const r = signStepReceipt(RS, { workflow: b, step: 'a', outcome: 'ok', paramsDigest: D('p'), outputs: { out: wfOutput('x') }, issuedAt: NOW - 1 } as never);
    expect(workflowReceiptError(b, RSK, [r], NOW)).toBeNull();
    // old check `issued_at > now` was false for NaN, so a receipt claiming any time was accepted at a NaN clock
    expect(workflowReceiptError(b, RSK, [r], Number.NaN)).toEqual({ at: 0 });
    expect(workflowReceiptError(b, RSK, [r], Number.NEGATIVE_INFINITY)).toEqual({ at: 0 });
  });
});

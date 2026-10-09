import { describe, expect, it } from 'vitest';
import { type Agent, agent, generateKeyPair } from '@atlasauth/pca';
import {
  type AgentRunContext,
  type AgentTool,
  type GuardrailArgs,
  PcaToolDenied,
  pcaInputGuardrail,
  pcaNeedsApproval,
  pcaToolGuard,
  pcaTools,
  pendingStepUps,
  reviewToolCall,
  withApproval,
  withPcaTool,
} from './index';

const AUD = 'ins_test';

/** An agent whose grant chains verify under AUD, with a $500/day refund cap. */
function refundAgent(): Agent {
  return agent({
    principal: generateKeyPair(),
    goal: 'refunds',
    permissions: { stripe: ['refund'] },
    limits: { refund: '$500/day' },
    aud: AUD,
  });
}

/** A risk-budget agent so `files.delete` (high blast) needs a step-up and `files.read` auto-admits. */
function opsAgent(): Agent {
  return agent({
    principal: generateKeyPair(),
    goal: 'ops',
    permissions: { files: ['read', 'delete'] },
    budgetModel: 'risk',
    aud: AUD,
  });
}

/** Assert a thrown value is a PcaToolDenied and return it narrowed (no cast). */
function asDenied(err: unknown): PcaToolDenied {
  expect(err).toBeInstanceOf(PcaToolDenied);
  if (!(err instanceof PcaToolDenied)) throw err;
  return err;
}

type RefundArgs = { amount: number; currency: string; charge: string };

/** A fake Agents-SDK tool that records whether (and with what) its execute ran. */
function refundTool(sink: { ran?: unknown }): AgentTool<RefundArgs, { ok: true }> {
  return {
    name: 'refund',
    description: 'Refund a charge',
    parameters: { type: 'object' },
    execute: async (input) => {
      sink.ran = input;
      return { ok: true };
    },
  };
}

/** Build a real, valid proof for a refund of `amount`, returning its forms + the run-context carrier. */
function proveRefund(a: Agent, amount: number) {
  const input: RefundArgs = { amount, currency: 'usd', charge: 'ch_1' };
  const { pcactn, encoded } = a.act('stripe.refund', `charge:${input.charge}`, input, { aud: AUD });
  // the SDK threads `run(agent, input, { context })` → tool.execute(input, runContext) with runContext.context
  const ctx: AgentRunContext = { context: { pca: encoded } };
  return { input, pcactn, encoded, ctx };
}

describe('withPcaTool — agent tool-execution guard', () => {
  it('runs the original execute when a valid proof rides on the run context', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    let verifiedVerb: string | undefined;
    const { input, pcactn, ctx } = proveRefund(a, 20);
    const tool = withPcaTool(refundTool(sink), {
      verify: { grant: a.grant, nowEpoch: pcactn.iat },
      audience: AUD,
      verb: 'stripe.refund',
      onVerified: (_r, p) => (verifiedVerb = p.action.verb),
    });
    const out = await tool.execute!(input, ctx);
    expect(out).toEqual({ ok: true });
    expect(sink.ran).toEqual(input); // original execute ran, with the original input
    expect(verifiedVerb).toBe('stripe.refund');
  });

  it('accepts a proof passed as the PCActn object via a custom require', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    const { input, pcactn } = proveRefund(a, 20);
    const tool = withPcaTool(refundTool(sink), {
      require: () => pcactn, // object form, not a string
      verify: { grant: a.grant, nowEpoch: pcactn.iat },
      audience: AUD,
    });
    await expect(tool.execute!(input)).resolves.toEqual({ ok: true });
    expect(sink.ran).toEqual(input);
  });

  it('blocks a call with NO proof (typed PcaToolDenied/missing), original not called', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    let denied: PcaToolDenied | undefined;
    const tool = withPcaTool(refundTool(sink), {
      verify: { grant: a.grant },
      audience: AUD,
      verb: 'stripe.refund',
      onDeny: (e) => (denied = e),
    });
    const err = await Promise.resolve(tool.execute!({ amount: 20, currency: 'usd', charge: 'ch_1' }, {})).catch((e: unknown) => e);
    expect(asDenied(err).kind).toBe('missing');
    expect(denied).toBe(err); // onDeny observed the same error
    expect(sink.ran).toBeUndefined();
  });

  it('blocks a malformed proof string (PcaToolDenied/malformed), original not called', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    const tool = withPcaTool(refundTool(sink), {
      require: () => 'not-a-real-proof',
      verify: { grant: a.grant },
      audience: AUD,
    });
    const err = await Promise.resolve(tool.execute!({ amount: 20, currency: 'usd', charge: 'ch_1' })).catch((e: unknown) => e);
    expect(asDenied(err).kind).toBe('malformed');
    expect(sink.ran).toBeUndefined();
  });

  it('blocks an INVALID proof (wrong audience → verify fail), original not called', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    const { input, pcactn, ctx } = proveRefund(a, 20);
    const tool = withPcaTool(refundTool(sink), {
      verify: { grant: a.grant, nowEpoch: pcactn.iat },
      audience: 'ins_other', // the proof is bound to AUD, not this
    });
    const err = await Promise.resolve(tool.execute!(input, ctx)).catch((e: unknown) => e);
    const denied = asDenied(err);
    expect(denied.kind).toBe('verify');
    expect(denied.checks?.audience).toBe('fail');
    expect(sink.ran).toBeUndefined();
  });

  it('blocks a proof whose verb does not bind to this tool (binding)', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    const { input, pcactn, ctx } = proveRefund(a, 20);
    const tool = withPcaTool(refundTool(sink), {
      verify: { grant: a.grant, nowEpoch: pcactn.iat },
      audience: AUD,
      verb: 'stripe.payout', // the proof is for stripe.refund
    });
    const err = await Promise.resolve(tool.execute!(input, ctx)).catch((e: unknown) => e);
    expect(asDenied(err).kind).toBe('binding');
    expect(sink.ran).toBeUndefined();
  });

  it('preserves non-execute fields on the wrapped tool', () => {
    const a = refundAgent();
    const tool = withPcaTool(refundTool({}), { verify: { grant: a.grant }, audience: AUD });
    expect(tool.name).toBe('refund');
    expect(tool.description).toBe('Refund a charge');
    expect(tool.parameters).toEqual({ type: 'object' });
  });
});

describe('pcaTools — record wrapper', () => {
  it('guards every tool in the record (each refuses without a proof)', async () => {
    const a = refundAgent();
    const sinks = { a: {} as { ran?: unknown }, b: {} as { ran?: unknown } };
    const wrapped = pcaTools(
      { refund: refundTool(sinks.a), refundTwo: refundTool(sinks.b) },
      { verify: { grant: a.grant }, audience: AUD },
    );
    for (const name of ['refund', 'refundTwo'] as const) {
      const err = await Promise.resolve(wrapped[name].execute!({ amount: 20, currency: 'usd', charge: 'ch_1' }, {})).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(PcaToolDenied);
    }
    expect(sinks.a.ran).toBeUndefined();
    expect(sinks.b.ran).toBeUndefined();
  });

  it('a guarded tool still runs with a valid proof; per-tool verb override binds it', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    const { input, pcactn, ctx } = proveRefund(a, 20);
    const wrapped = pcaTools(
      { refund: refundTool(sink) },
      { verify: { grant: a.grant, nowEpoch: pcactn.iat }, audience: AUD, per: { refund: { verb: 'stripe.refund' } } },
    );
    await expect(wrapped.refund.execute!(input, ctx)).resolves.toEqual({ ok: true });
    expect(sink.ran).toEqual(input);
  });

  it('`only` leaves unlisted tools untouched', () => {
    const a = refundAgent();
    const passthrough: AgentTool = { name: 'lookup', description: 'read', execute: async () => 'ok' };
    const wrapped = pcaTools(
      { refund: refundTool({}), lookup: passthrough },
      { verify: { grant: a.grant }, audience: AUD, only: ['refund'] },
    );
    expect(wrapped.lookup).toBe(passthrough); // identical reference = not wrapped
    expect(wrapped.refund).not.toBe(passthrough);
  });
});

describe('guardrails — reject a run / tool call lacking a valid proof', () => {
  it('pcaInputGuardrail trips on a run with no proof and passes with a valid one', async () => {
    const a = refundAgent();
    const { pcactn, ctx } = proveRefund(a, 20);
    const guardrail = pcaInputGuardrail({ verify: { grant: a.grant, nowEpoch: pcactn.iat }, audience: AUD, verb: 'stripe.refund' });

    const missing = await guardrail.execute({ input: 'refund ch_1', context: {} } satisfies GuardrailArgs);
    expect(missing.tripwireTriggered).toBe(true);

    const ok = await guardrail.execute({ input: 'refund ch_1', context: ctx } satisfies GuardrailArgs);
    expect(ok.tripwireTriggered).toBe(false);
  });

  it('pcaToolGuard trips on a wrong-audience proof', async () => {
    const a = refundAgent();
    const { pcactn, ctx } = proveRefund(a, 20);
    const guard = pcaToolGuard({ verify: { grant: a.grant, nowEpoch: pcactn.iat }, audience: 'ins_other' });
    const out = await guard.execute({ context: ctx } satisfies GuardrailArgs);
    expect(out.tripwireTriggered).toBe(true);
    expect(guard.name).toBe('pca-tool-guard');
  });
});

describe('step-up — needsApproval / interruption flow via reviewToolCall', () => {
  const intent = (tool: string, input?: Record<string, unknown>) => {
    if (tool === 'deleteFile') return { verb: 'files.delete', resource: String(input?.['path'] ?? 'file:*') };
    if (tool === 'readFile') return { verb: 'files.read', resource: 'file:*' };
    return null;
  };

  it('flags a risky tool as step_up (tier >= 2) and a safe tool as auto', () => {
    const a = opsAgent();
    const risky = reviewToolCall(a, 'deleteFile', { path: 'file:/etc/hosts' }, { intent });
    const safe = reviewToolCall(a, 'readFile', {}, { intent });
    expect(risky.review.kind).toBe('step_up');
    if (risky.review.kind === 'step_up') {
      expect(risky.review.request.verb).toBe('files.delete');
      expect(risky.review.request.tier).toBeGreaterThanOrEqual(2);
    }
    expect(safe.review.kind).toBe('auto');
  });

  it('pcaNeedsApproval returns true for a risky tool and routes a step-up, false for a safe one', () => {
    const a = opsAgent();
    const seen: string[] = [];
    const needsDelete = pcaNeedsApproval(a, { intent, toolName: 'deleteFile', onStepUp: (p) => seen.push(p.tool) });
    const needsRead = pcaNeedsApproval(a, { intent, toolName: 'readFile' });
    const runContext: AgentRunContext = { context: {} };

    expect(needsDelete(runContext, { path: 'file:/etc/hosts' })).toBe(true);
    expect(seen).toEqual(['deleteFile']); // routed to the approval round
    expect(needsRead(runContext, {})).toBe(false);
  });

  it('withApproval sets needsApproval on the tool; an already-approved step-up is let through', () => {
    const a = opsAgent();
    const deleteTool: AgentTool<{ path: string }, { ok: true }> = {
      name: 'deleteFile',
      execute: async () => ({ ok: true }),
    };
    const guarded = withApproval(deleteTool, a, { intent, approved: () => true });
    expect(typeof guarded.needsApproval).toBe('function');
    const fn = guarded.needsApproval;
    if (typeof fn !== 'function') throw new Error('expected a needsApproval function');
    // approved: () => true → no interruption needed
    expect(fn({ context: {} }, { path: 'file:/etc/hosts' })).toBe(false);
    // and a fresh (unapproved) gate does interrupt
    const fresh = withApproval(deleteTool, a, { intent });
    const freshFn = fresh.needsApproval;
    if (typeof freshFn !== 'function') throw new Error('expected a needsApproval function');
    expect(freshFn({ context: {} }, { path: 'file:/etc/hosts' })).toBe(true);
  });

  it('pendingStepUps collects only the step_up reviews', () => {
    const a = opsAgent();
    const reviews = [
      reviewToolCall(a, 'deleteFile', { path: 'file:/x' }, { intent }),
      reviewToolCall(a, 'readFile', {}, { intent }),
    ];
    expect(pendingStepUps(reviews).map((p) => p.tool)).toEqual(['deleteFile']);
  });
});

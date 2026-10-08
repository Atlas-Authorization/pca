import { describe, expect, it } from 'vitest';
import { type Agent, agent, generateKeyPair } from '@atlasauth/pca';
import { type AiSdkTool } from '@atlasauth/pca-ai-sdk';
import {
  PcaToolDenied,
  type PcaToolExecuteOptions,
  pcaPrepareStep,
  pcaTools,
  pendingStepUps,
  reviewToolCall,
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

/** A fake Vercel AI SDK tool that records whether (and with what) its execute ran. */
function refundTool(sink: { ran?: unknown }): AiSdkTool<RefundArgs, { ok: true }> {
  return {
    description: 'Refund a charge',
    inputSchema: { type: 'object' },
    execute: async (args) => {
      sink.ran = args;
      return { ok: true };
    },
  };
}

/** Build a real, valid proof for a refund of `amount` under agent `a`, returning its encoded + object forms. */
function proveRefund(a: Agent, amount: number) {
  const args: RefundArgs = { amount, currency: 'usd', charge: 'ch_1' };
  const { pcactn, encoded } = a.act('stripe.refund', `charge:${args.charge}`, args, { aud: AUD });
  return { args, pcactn, encoded, ctx: { experimental_context: { pca: encoded } } satisfies PcaToolExecuteOptions };
}

describe('withPcaTool — execution guard', () => {
  it('runs the original execute when a valid proof rides on experimental_context', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    let verifiedVerb: string | undefined;
    const { args, pcactn, ctx } = proveRefund(a, 20);
    const tool = withPcaTool(refundTool(sink), {
      // default require → reads the encoded proof from options.experimental_context.pca
      verify: { grant: a.grant, nowEpoch: pcactn.iat },
      audience: AUD,
      verb: 'stripe.refund',
      onVerified: (_r, p) => (verifiedVerb = p.action.verb),
    });
    const out = await tool.execute!(args, ctx);
    expect(out).toEqual({ ok: true });
    expect(sink.ran).toEqual(args); // original execute ran, with the original args
    expect(verifiedVerb).toBe('stripe.refund');
  });

  it('accepts a proof passed as the PCActn object via a custom require', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    const { args, pcactn } = proveRefund(a, 20);
    const tool = withPcaTool(refundTool(sink), {
      require: () => pcactn, // object form, not a string
      verify: { grant: a.grant, nowEpoch: pcactn.iat },
      audience: AUD,
    });
    await expect(tool.execute!(args)).resolves.toEqual({ ok: true });
    expect(sink.ran).toEqual(args);
  });

  it('blocks a call with NO proof (typed PcaToolDenied/missing), original not called', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    const tool = withPcaTool(refundTool(sink), { verify: { grant: a.grant }, audience: AUD, verb: 'stripe.refund' });
    const err = await Promise.resolve(tool.execute!({ amount: 20, currency: 'usd', charge: 'ch_1' }, {})).catch((e: unknown) => e);
    expect(asDenied(err).kind).toBe('missing');
    expect(sink.ran).toBeUndefined();
  });

  it('blocks an INVALID proof (wrong audience → verify fail), original not called', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    const { args, pcactn, ctx } = proveRefund(a, 20);
    const tool = withPcaTool(refundTool(sink), {
      verify: { grant: a.grant, nowEpoch: pcactn.iat },
      audience: 'ins_other', // the proof is bound to AUD, not this
    });
    const err = await Promise.resolve(tool.execute!(args, ctx)).catch((e: unknown) => e);
    const denied = asDenied(err);
    expect(denied.kind).toBe('verify');
    expect(denied.checks?.audience).toBe('fail');
    expect(sink.ran).toBeUndefined();
  });

  it('blocks a proof whose verb does not bind to this tool (binding)', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    const { args, pcactn, ctx } = proveRefund(a, 20);
    const tool = withPcaTool(refundTool(sink), {
      verify: { grant: a.grant, nowEpoch: pcactn.iat },
      audience: AUD,
      verb: 'stripe.payout', // the proof is for stripe.refund
    });
    const err = await Promise.resolve(tool.execute!(args, ctx)).catch((e: unknown) => e);
    expect(asDenied(err).kind).toBe('binding');
    expect(sink.ran).toBeUndefined();
  });

  it('preserves non-execute fields on the wrapped tool', () => {
    const a = refundAgent();
    const tool = withPcaTool(refundTool({}), { verify: { grant: a.grant }, audience: AUD });
    expect(tool.description).toBe('Refund a charge');
    expect(tool.inputSchema).toEqual({ type: 'object' });
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
    const { args, pcactn, ctx } = proveRefund(a, 20);
    const wrapped = pcaTools(
      { refund: refundTool(sink) },
      { verify: { grant: a.grant, nowEpoch: pcactn.iat }, audience: AUD, per: { refund: { verb: 'stripe.refund' } } },
    );
    await expect(wrapped.refund.execute!(args, ctx)).resolves.toEqual({ ok: true });
    expect(sink.ran).toEqual(args);
  });

  it('`only` leaves unlisted tools untouched', () => {
    const a = refundAgent();
    const passthrough: AiSdkTool = { description: 'read', execute: async () => 'ok' };
    const wrapped = pcaTools(
      { refund: refundTool({}), lookup: passthrough },
      { verify: { grant: a.grant }, audience: AUD, only: ['refund'] },
    );
    expect(wrapped.lookup).toBe(passthrough); // identical reference = not wrapped
    expect(wrapped.refund).not.toBe(passthrough);
  });
});

describe('pcaPrepareStep — step-up on the agent loop', () => {
  const intent = (tool: string, args?: Record<string, unknown>) => {
    if (tool === 'deleteFile') return { verb: 'files.delete', resource: String(args?.['path'] ?? 'file:*') };
    if (tool === 'readFile') return { verb: 'files.read', resource: 'file:*' };
    return null;
  };

  it('flags a risky tool as step_up and a safe tool as auto', () => {
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

  it('prepareStep removes a risky tool from the next step and routes it to step-up', () => {
    const a = opsAgent();
    const seen: string[] = [];
    const prepare = pcaPrepareStep(a, {
      intent,
      tools: ['readFile', 'deleteFile'],
      onStepUp: (pending) => seen.push(...pending.map((p) => p.tool)),
    });
    const result = prepare({
      stepNumber: 1,
      steps: [{ toolCalls: [{ toolName: 'deleteFile', input: { path: 'file:/etc/hosts' } }] }],
    });
    expect(result).toBeDefined();
    expect(result?.activeTools).toEqual(['readFile']); // risky tool withheld
    expect(seen).toEqual(['deleteFile']); // routed to the approval round
  });

  it('prepareStep lets an already-approved step-up through (no change)', () => {
    const a = opsAgent();
    const prepare = pcaPrepareStep(a, { intent, tools: ['readFile', 'deleteFile'], approved: () => true });
    const result = prepare({ stepNumber: 1, steps: [{ toolCalls: [{ toolName: 'deleteFile', input: { path: 'file:/etc/hosts' } }] }] });
    expect(result).toBeUndefined();
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

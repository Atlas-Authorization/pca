import { describe, expect, it } from 'vitest';
import { type Agent, agent, generateKeyPair } from '@atlasauth/pca';
import {
  type MastraStep,
  type MastraTool,
  type MastraToolExecuteContext,
  type RuntimeContextLike,
  PcaStepDenied,
  PcaStepUpRequired,
  PcaToolDenied,
  guardStep,
  pcaHeaders,
  pcaTools,
  pendingStepUps,
  proofFromContextHeaders,
  reviewStep,
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

/** A Mastra-style run context (`RuntimeContext`: a typed Map with get/set). */
function runContext(entries: Record<string, unknown> = {}): RuntimeContextLike & { set(k: string, v: unknown): void } {
  const m = new Map<string, unknown>(Object.entries(entries));
  return { get: (k: string) => m.get(k), set: (k: string, v: unknown) => void m.set(k, v) };
}

type RefundArgs = { amount: number; currency: string; charge: string };

/** A fake Mastra tool (what `createTool` returns) that records whether (and with what) its execute ran. */
function refundTool(sink: { ran?: unknown }): MastraTool<RefundArgs, { ok: true }> {
  return {
    id: 'refund',
    description: 'Refund a charge',
    inputSchema: { type: 'object' },
    outputSchema: { type: 'object' },
    execute: async ({ context }) => {
      sink.ran = context;
      return { ok: true };
    },
  };
}

/** Build a real, valid proof for a refund of `amount`, returning its encoded form + a ready execute ctx. */
function proveRefund(a: Agent, amount: number) {
  const context: RefundArgs = { amount, currency: 'usd', charge: 'ch_1' };
  const { pcactn, encoded } = a.act('stripe.refund', `charge:${context.charge}`, context, { aud: AUD });
  const ctx: MastraToolExecuteContext<RefundArgs> = { context, runtimeContext: runContext({ pca: encoded }) };
  return { context, pcactn, encoded, ctx };
}

describe('withPcaTool — Mastra execution guard', () => {
  it('runs the original execute when a valid proof rides on the run context', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    let verifiedVerb: string | undefined;
    const { context, pcactn, ctx } = proveRefund(a, 20);
    const tool = withPcaTool(refundTool(sink), {
      // default require → reads the encoded proof from runtimeContext.get('pca')
      verify: { grant: a.grant, nowEpoch: pcactn.iat },
      audience: AUD,
      verb: 'stripe.refund',
      onVerified: (_r, p) => (verifiedVerb = p.action.verb),
    });
    const out = await tool.execute!(ctx);
    expect(out).toEqual({ ok: true });
    expect(sink.ran).toEqual(context); // original execute ran, with the original context
    expect(verifiedVerb).toBe('stripe.refund');
  });

  it('accepts a proof passed as the PCActn object via a custom require', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    const { context, pcactn } = proveRefund(a, 20);
    const tool = withPcaTool(refundTool(sink), {
      require: () => pcactn, // object form, not a string, and not from the run context
      verify: { grant: a.grant, nowEpoch: pcactn.iat },
      audience: AUD,
    });
    await expect(tool.execute!({ context })).resolves.toEqual({ ok: true });
    expect(sink.ran).toEqual(context);
  });

  it('reads a PCA-Action header from the tool context via proofFromContextHeaders', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    type ArgsWithHeaders = RefundArgs & { headers?: Record<string, string> };
    const context: RefundArgs = { amount: 20, currency: 'usd', charge: 'ch_1' };
    const { pcactn, encoded } = a.act('stripe.refund', `charge:${context.charge}`, context, { aud: AUD });
    const headerValue = pcaHeaders(encoded)['PCA-Action']!;
    const tool: MastraTool<ArgsWithHeaders, { ok: true }> = {
      id: 'refund',
      execute: async ({ context: c }) => {
        sink.ran = c;
        return { ok: true };
      },
    };
    const guarded = withPcaTool(tool, {
      require: proofFromContextHeaders<ArgsWithHeaders>(),
      verify: { grant: a.grant, nowEpoch: pcactn.iat },
      audience: AUD,
    });
    await expect(guarded.execute!({ context: { ...context, headers: { 'PCA-Action': headerValue } } })).resolves.toEqual({ ok: true });
    expect(sink.ran).toBeDefined();
  });

  it('blocks a call with NO proof (typed PcaToolDenied/missing), original not called', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    const tool = withPcaTool(refundTool(sink), { verify: { grant: a.grant }, audience: AUD, verb: 'stripe.refund' });
    const err = await Promise.resolve(
      tool.execute!({ context: { amount: 20, currency: 'usd', charge: 'ch_1' }, runtimeContext: runContext() }),
    ).catch((e: unknown) => e);
    expect(asDenied(err).kind).toBe('missing');
    expect(sink.ran).toBeUndefined();
  });

  it('blocks a malformed proof (typed PcaToolDenied/malformed), original not called', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    const tool = withPcaTool(refundTool(sink), { verify: { grant: a.grant }, audience: AUD });
    const ctx: MastraToolExecuteContext<RefundArgs> = {
      context: { amount: 20, currency: 'usd', charge: 'ch_1' },
      runtimeContext: runContext({ pca: 'not-a-valid-pcactn' }),
    };
    const err = await Promise.resolve(tool.execute!(ctx)).catch((e: unknown) => e);
    expect(asDenied(err).kind).toBe('malformed');
    expect(sink.ran).toBeUndefined();
  });

  it('blocks an INVALID proof (wrong audience → verify fail), original not called', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    const { pcactn, ctx } = proveRefund(a, 20);
    const tool = withPcaTool(refundTool(sink), {
      verify: { grant: a.grant, nowEpoch: pcactn.iat },
      audience: 'ins_other', // the proof is bound to AUD, not this
    });
    const err = await Promise.resolve(tool.execute!(ctx)).catch((e: unknown) => e);
    const denied = asDenied(err);
    expect(denied.kind).toBe('verify');
    expect(denied.checks?.audience).toBe('fail');
    expect(sink.ran).toBeUndefined();
  });

  it('blocks a proof whose verb does not bind to this tool (binding)', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    const { pcactn, ctx } = proveRefund(a, 20);
    const tool = withPcaTool(refundTool(sink), {
      verify: { grant: a.grant, nowEpoch: pcactn.iat },
      audience: AUD,
      verb: 'stripe.payout', // the proof is for stripe.refund
    });
    const err = await Promise.resolve(tool.execute!(ctx)).catch((e: unknown) => e);
    expect(asDenied(err).kind).toBe('binding');
    expect(sink.ran).toBeUndefined();
  });

  it('preserves non-execute fields on the wrapped tool', () => {
    const a = refundAgent();
    const tool = withPcaTool(refundTool({}), { verify: { grant: a.grant }, audience: AUD });
    expect(tool.id).toBe('refund');
    expect(tool.description).toBe('Refund a charge');
    expect(tool.inputSchema).toEqual({ type: 'object' });
    expect(tool.outputSchema).toEqual({ type: 'object' });
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
      const err = await Promise.resolve(
        wrapped[name].execute!({ context: { amount: 20, currency: 'usd', charge: 'ch_1' }, runtimeContext: runContext() }),
      ).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(PcaToolDenied);
    }
    expect(sinks.a.ran).toBeUndefined();
    expect(sinks.b.ran).toBeUndefined();
  });

  it('a guarded tool still runs with a valid proof; per-tool verb override binds it', async () => {
    const a = refundAgent();
    const sink: { ran?: unknown } = {};
    const { context, pcactn, ctx } = proveRefund(a, 20);
    const wrapped = pcaTools(
      { refund: refundTool(sink) },
      { verify: { grant: a.grant, nowEpoch: pcactn.iat }, audience: AUD, per: { refund: { verb: 'stripe.refund' } } },
    );
    await expect(wrapped.refund.execute!(ctx)).resolves.toEqual({ ok: true });
    expect(sink.ran).toEqual(context);
  });

  it('`only` leaves unlisted tools untouched', () => {
    const a = refundAgent();
    const passthrough: MastraTool = { id: 'lookup', description: 'read', execute: async () => 'ok' };
    const wrapped = pcaTools(
      { refund: refundTool({}), lookup: passthrough },
      { verify: { grant: a.grant }, audience: AUD, only: ['refund'] },
    );
    expect(wrapped.lookup).toBe(passthrough); // identical reference = not wrapped
    expect(wrapped.refund).not.toBe(passthrough);
  });
});

describe('workflow step-up helpers', () => {
  const intent = (step: string, input?: Record<string, unknown>) => {
    if (step === 'deleteFile') return { verb: 'files.delete', resource: String(input?.['path'] ?? 'file:*') };
    if (step === 'readFile') return { verb: 'files.read', resource: 'file:*' };
    return null;
  };

  it('reviewStep flags a risky step as step_up and a safe step as auto', () => {
    const a = opsAgent();
    const risky = reviewStep(a, 'deleteFile', { path: 'file:/etc/hosts' }, { intent });
    const safe = reviewStep(a, 'readFile', {}, { intent });
    expect(risky.review.kind).toBe('step_up');
    if (risky.review.kind === 'step_up') {
      expect(risky.review.request.verb).toBe('files.delete');
      expect(risky.review.request.tier).toBeGreaterThanOrEqual(2);
    }
    expect(safe.review.kind).toBe('auto');
  });

  it('pendingStepUps collects only the step_up reviews', () => {
    const a = opsAgent();
    const reviews = [
      reviewStep(a, 'deleteFile', { path: 'file:/x' }, { intent }),
      reviewStep(a, 'readFile', {}, { intent }),
    ];
    expect(pendingStepUps(reviews).map((p) => p.step)).toEqual(['deleteFile']);
  });

  it('guardStep throws PcaStepUpRequired on a risky step and routes it to onStepUp (original not run)', async () => {
    const a = opsAgent();
    const ran: string[] = [];
    const seen: string[] = [];
    const step: MastraStep<{ path: string }, { deleted: true }> = {
      id: 'deleteFile',
      execute: async ({ inputData }) => {
        ran.push(inputData.path);
        return { deleted: true };
      },
    };
    const guarded = guardStep(step, { agent: a, intent, onStepUp: (p) => seen.push(p.step) });
    const err = await Promise.resolve(guarded.execute!({ inputData: { path: 'file:/etc/hosts' } })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PcaStepUpRequired);
    if (err instanceof PcaStepUpRequired) expect(err.request.verb).toBe('files.delete');
    expect(seen).toEqual(['deleteFile']);
    expect(ran).toEqual([]); // original step never ran
  });

  it('guardStep runs a safe step through, and lets an approved step-up through', async () => {
    const a = opsAgent();
    const ran: string[] = [];
    const safeStep: MastraStep<Record<string, unknown>, { read: true }> = {
      id: 'readFile',
      execute: async () => {
        ran.push('readFile');
        return { read: true };
      },
    };
    const safeGuarded = guardStep(safeStep, { agent: a, intent });
    await expect(safeGuarded.execute!({ inputData: {} })).resolves.toEqual({ read: true });

    const deleteStep: MastraStep<{ path: string }, { deleted: true }> = {
      id: 'deleteFile',
      execute: async () => {
        ran.push('deleteFile');
        return { deleted: true };
      },
    };
    const approvedGuarded = guardStep(deleteStep, { agent: a, intent, approved: () => true });
    await expect(approvedGuarded.execute!({ inputData: { path: 'file:/tmp/x' } })).resolves.toEqual({ deleted: true });
    expect(ran).toEqual(['readFile', 'deleteFile']);
  });

  it('guardStep throws PcaStepDenied when the grant forbids the step', async () => {
    const a = refundAgent(); // has no files.* permission → dryRun denies
    const step: MastraStep<{ path: string }, { deleted: true }> = {
      id: 'deleteFile',
      execute: async () => ({ deleted: true }),
    };
    const guarded = guardStep(step, { agent: a, intent });
    const err = await Promise.resolve(guarded.execute!({ inputData: { path: 'file:/x' } })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PcaStepDenied);
  });
});

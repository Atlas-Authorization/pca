// 0.5 (T5): full-policy mode (`authorize`). The reviewer acceptance test: a validly signed $400 refund under a $100
// grant, a replayed proof and a revoked grant are each refused BEFORE the tool's execute runs.
import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair, type Agent } from '@atlasauth/pca';
import { BUILTIN_ACTIONS, buildCatalog, defineAction } from '@atlasauth/pca/ext/research';
import { type MastraTool, type MastraToolExecuteContext, PcaToolDenied, memoryPcaStore, pcaTools, withPcaTool, type WithPcaToolOptions } from './index';

// 0.5: the built-in stripe.refund is irreversible (never auto-approved, even within a cap); these tests exercise the within-cap
// allow path, so they grant the pre-0.5 rate_limited refund instead.
const RATE_LIMITED_REFUND = buildCatalog([...BUILTIN_ACTIONS, defineAction({ connector: 'stripe', action: 'refund', reversibility: 'rate_limited', blastRadius: 0.9, amountField: 'amount', description: 'Refund a charge (rate-limited).' })]);
const AUD = 'ins_t5';
const VERB = 'stripe.refund';

type RefundArgs = { charge: string; amount: number };

/** Await `p`; a rejection is returned (not thrown), so a test asserts the exact outcome. */
async function settle<T>(p: T | Promise<T>): Promise<{ ok: true; value: T } | { ok: false; error: unknown }> {
  try {
    return { ok: true, value: await p };
  } catch (error) {
    return { ok: false, error };
  }
}

/** The denial as plain data (kind, verb, message), or the value when the call ran. */
async function outcome<T>(p: T | Promise<T>): Promise<unknown> {
  const r = await settle(p);
  if (r.ok) return { ran: r.value };
  if (!(r.error instanceof PcaToolDenied)) throw r.error;
  return { kind: r.error.kind, verb: r.error.verb, message: r.error.message };
}

function world() {
  const a: Agent = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$100/day' }, aud: AUD, catalog: RATE_LIMITED_REFUND });
  const executed: RefundArgs[] = [];
  const tool: MastraTool<RefundArgs, { ok: true }> = {
    id: 'refund',
    execute: async ({ context }) => {
      executed.push(context);
      return { ok: true };
    },
  };
  const revoked = { v: false };
  const authorize = { grant: a.grant, state: memoryPcaStore(), isRevoked: () => revoked.v };
  const guarded = withPcaTool(tool, { audience: AUD, verb: VERB, authorize });
  const call = (amount: number, input?: RefundArgs) => {
    const signed = { charge: 'ch_1', amount };
    a.provenance!.principal(`Refund ${amount} on charge ch_1`); // the user's request: the action derives from it
    const { encoded, pcactn, provenance } = a.act(VERB, 'charge:ch_1', signed);
    const ctx: MastraToolExecuteContext<RefundArgs> = { context: input ?? signed, runtimeContext: { get: (k: string) => (k === 'pca' ? encoded : k === 'pcaProvenance' ? provenance : undefined) } };
    return { ctx, encoded, pcactn };
  };
  return { a, tool, guarded, executed, revoked, authorize, call };
}

const denied = (kind: string, message: string) => ({ kind, verb: VERB, message: `PCA tool denied (${kind}) for ${VERB}: ${message}` });

describe('pca-mastra full-policy mode: reviewer acceptance', () => {
  it('a validly signed $400 refund under a $100 grant is refused before execute runs', async () => {
    const w = world();
    const { ctx } = w.call(400);
    expect(await outcome(w.guarded.execute!(ctx))).toEqual(denied('policy', 'policy: amount <= 100 not satisfied for stripe.refund on charge:ch_1'));
    expect(w.executed).toEqual([]);
  });

  it('the same proof passes signature-only mode, which is now an explicit choice (the gap full mode closes)', async () => {
    const w = world();
    const { ctx } = w.call(400);
    const sigOnly = withPcaTool(w.tool, { audience: AUD, verb: VERB, mode: 'signature-only', verify: { insecureSkipPlanRootCheck: true, grant: w.a.grant } });
    expect(await outcome(sigOnly.execute!(ctx))).toEqual({ ran: { ok: true } });
    expect(w.executed).toEqual([{ charge: 'ch_1', amount: 400 }]);
  });

  it('a $50 refund runs once; the replayed proof is refused before execute runs', async () => {
    const w = world();
    const { ctx, pcactn } = w.call(50);
    expect(await outcome(w.guarded.execute!(ctx))).toEqual({ ran: { ok: true } });
    const n = pcactn.counter;
    expect(await outcome(w.guarded.execute!(ctx))).toEqual(denied('replay', `replay: ${n} is not greater than last seen ${n} (replay)`));
    expect(w.executed).toEqual([{ charge: 'ch_1', amount: 50 }]);
  });

  it('a revoked grant is refused before execute runs', async () => {
    const w = world();
    w.revoked.v = true;
    const { ctx } = w.call(50);
    const r = await outcome(w.guarded.execute!(ctx));
    expect(r).toMatchObject({ kind: 'revoked', verb: VERB });
    expect(w.executed).toEqual([]);
  });
});

describe('pca-mastra full-policy mode: binding and configuration', () => {
  it('a tool input that differs from the signed params is refused', async () => {
    const w = world();
    const { ctx } = w.call(50, { charge: 'ch_1', amount: 90 });
    expect(await outcome(w.guarded.execute!(ctx))).toEqual(denied('policy', 'params_digest: supplied params do not hash to action.params_digest'));
    expect(w.executed).toEqual([]);
  });

  it('`operation` binds the resource: a proof for another charge is refused', async () => {
    const w = world();
    const g = withPcaTool(w.tool, { audience: AUD, authorize: { ...w.authorize, operation: (c) => ({ verb: VERB, resource: `charge:${c.context.charge}x`, params: c.context }) } });
    const { ctx } = w.call(50);
    expect(await outcome(g.execute!(ctx))).toEqual(denied('binding', 'the proof is for stripe.refund on charge:ch_1, but this call is stripe.refund on charge:ch_1x'));
    expect(w.executed).toEqual([]);
  });

  it('a missing component throws at construction (fail closed, never a downgrade to signature-only)', () => {
    const w = world();
    const base = { audience: AUD, verb: VERB };
    const build = (o: Partial<WithPcaToolOptions<RefundArgs>>) => () => withPcaTool(w.tool, { ...base, ...o } as WithPcaToolOptions<RefundArgs>);
    expect(build({ authorize: { ...w.authorize, state: undefined as never } })).toThrow(new TypeError('withPcaTool: full policy mode is missing state'));
    expect(build({ authorize: { ...w.authorize, isRevoked: undefined as never } })).toThrow(new TypeError('withPcaTool: full policy mode is missing isRevoked'));
    expect(build({ authorize: { ...w.authorize, grant: undefined } })).toThrow(new TypeError('withPcaTool: full policy mode is missing grant or resolveGrant'));
    expect(build({ audience: null, authorize: w.authorize })).toThrow(new TypeError('withPcaTool: full policy mode is missing audience'));
    expect(build({ verb: undefined, authorize: w.authorize })).toThrow(new TypeError("withPcaTool: full policy mode is missing operation (or the guard's verb)"));
    expect(build({ authorize: w.authorize, verify: { insecureSkipPlanRootCheck: true, grant: w.a.grant } })).toThrow(new TypeError("withPcaTool: `verify` checks the signature only: set mode: 'signature-only' to use it, and drop `authorize`"));
    expect(build({})).toThrow(new TypeError("withPcaTool: pass `authorize` (full policy, the default mode), or set mode: 'signature-only' with `verify` to check the signature only"));
    // 0.5: `verify` alone no longer selects the weaker mode
    expect(build({ verify: { insecureSkipPlanRootCheck: true, grant: w.a.grant } })).toThrow(new TypeError("withPcaTool: pass `authorize` (full policy, the default mode), or set mode: 'signature-only' with `verify` to check the signature only"));
    expect(build({ mode: 'signature-only' })).toThrow(new TypeError("withPcaTool: mode 'signature-only' needs `verify`"));
    expect(build({ mode: 'signature-only', verify: { insecureSkipPlanRootCheck: true, grant: w.a.grant }, authorize: w.authorize })).toThrow(new TypeError("withPcaTool: `authorize` is the full mode; drop it, or drop mode: 'signature-only'"));
    expect(build({ mode: 'sloppy' as never, verify: { insecureSkipPlanRootCheck: true, grant: w.a.grant } })).toThrow(new TypeError("withPcaTool: unknown mode 'sloppy'"));
  });

  it('pcaTools forwards `authorize`, and a per-tool `verify` replaces it for that tool', async () => {
    const w = world();
    const tools = pcaTools({ refund: w.tool, legacy: w.tool }, { audience: AUD, verb: VERB, authorize: w.authorize, per: { legacy: { mode: 'signature-only', verify: { insecureSkipPlanRootCheck: true, grant: w.a.grant } } } });
    const over = w.call(400);
    expect(await outcome(tools.refund.execute!(over.ctx))).toMatchObject({ kind: 'policy' });
    expect(await outcome(tools.legacy.execute!(over.ctx))).toEqual({ ran: { ok: true } });
  });
});

describe('pca-mastra full-policy mode: provenance by default', () => {
  it('with a recorder, the guarded tool records its result as untrusted tool output in the session chain', async () => {
    const w = world();
    const g = withPcaTool(w.tool, { audience: AUD, verb: VERB, authorize: w.authorize, recorder: w.a.provenance! });
    const { ctx } = w.call(50);
    expect(await outcome(g.execute!(ctx))).toEqual({ ran: { ok: true } });
    expect(w.a.provenance!.receipts().map((r) => r.origin)).toEqual(['principal', 'action', 'tool']);
  });
  it('a call without its provenance bundle is refused before execute runs (unlabelled: escalate)', async () => {
    const w = world();
    const g = withPcaTool(w.tool, { audience: AUD, verb: VERB, authorize: w.authorize });
    const enc = w.call(50).encoded;
    const bare = { context: { charge: 'ch_1', amount: 50 }, runtimeContext: { get: (k: string) => (k === 'pca' ? enc : undefined) } };
    expect(await outcome(g.execute!(bare))).not.toEqual({ ran: { ok: true } });
    expect(w.executed).toEqual([]);
  });
});

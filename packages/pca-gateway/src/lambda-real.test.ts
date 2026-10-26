/**
 * Offline replay of the REAL AWS Lambda runtime run (fixtures/lambda-run).
 *
 * The fixtures were captured by invoking the authorizer bundle inside the official
 * public.ecr.aws/lambda/nodejs:{20,22} images through the Runtime Interface Emulator on a Linux VM
 * (scripts/lambda/run-lambda-test.sh). Every recorded {event, response} pair is replayed here through the
 * same adapter with the recorded grants and a clock pinned to the mint time, and must reproduce the
 * response byte for byte. This pins the adapter's behaviour inside the Lambda runtime to what is
 * checked in; it does not run Lambda, and it does not exercise API Gateway itself.
 * In 0.5 the verdict's `counter` check was renamed `counter_format`; the recorded verdict strings in invocations.jsonl carry
 * that one key rename and nothing else.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Capability } from '@atlasauth/pca';
import { LAMBDA_TEST_ROUTES } from '../scripts/lambda/config';
import { lambdaAuthorizer, lambdaSimpleAuthorizer, memoryReplayGuard, type GatewayOptions, type LambdaRequestAuthorizerEvent } from './index';

/** Signature-only on purpose (0.5: an explicit mode): these tests are about routing, adapters and binding; full mode is in full-policy.test.ts. */
const SIG_ONLY = { policy: { mode: 'signature-only' as const }, replayGuard: { claim: async () => true }, requireChecks: [] as string[] };

const DIR = join(__dirname, '..', 'fixtures', 'lambda-run');
const read = (n: string): string => readFileSync(join(DIR, n), 'utf8');
const jsonl = <T>(n: string): T[] => read(n).trim().split('\n').map((l) => JSON.parse(l) as T);

interface Record1 {
  image: string;
  handler: 'rest' | 'simple' | 'restReplay';
  scenario: string;
  event?: LambdaRequestAuthorizerEvent;
  response?: unknown;
  responses?: string[];
  mintedAtMs?: number;
  pass: boolean;
}

const records = jsonl<Record1>('invocations.jsonl');

function opts(tag: string, mintedAtMs: number, extra?: Partial<GatewayOptions>): GatewayOptions {
  const grants = JSON.parse(read(`grants-nodejs${tag}.json`)) as Record<string, Capability>;
  return {
    audience: 'ins_acme',
    routes: LAMBDA_TEST_ROUTES,
    resolveGrant: async (ref) => grants[ref] ?? null,
    now: () => mintedAtMs + 1000,
    // The recorded proofs predate R2-11 (request binding default-on, 86f30a78): they do not commit the request binding,
    // so the replay reproduces the recorded run with binding off. The default-on denial is asserted separately below.
    bindRequest: false,
    ...SIG_ONLY,
    ...extra,
  };
}

describe('real Lambda runtime run: recorded invocations', () => {
  it('has both Node.js runtimes, all three handlers, and every recorded scenario passed', () => {
    expect(records.length).toBeGreaterThanOrEqual(46);
    expect(new Set(records.map((r) => r.image))).toEqual(new Set(['nodejs:20', 'nodejs:22']));
    expect(new Set(records.map((r) => r.handler))).toEqual(new Set(['rest', 'simple', 'restReplay']));
    expect(records.filter((r) => !r.pass)).toEqual([]);
  });

  for (const tag of ['20', '22']) {
    for (const handler of ['rest', 'simple', 'restReplay'] as const) {
      const mine = records.filter((r) => r.image === `nodejs:${tag}` && r.handler === handler && r.event !== undefined);
      describe(`nodejs:${tag} handler.${handler}`, () => {
        const minted = mine[0]?.mintedAtMs ?? 0;
        const rest = lambdaAuthorizer(opts(tag, minted));
        const simple = lambdaSimpleAuthorizer(opts(tag, minted));
        const replay = lambdaAuthorizer(opts(tag, minted, { replayGuard: memoryReplayGuard(100_000, () => minted + 1000) }));
        const fn = { rest, simple, restReplay: replay }[handler];
        // Sequential, in recorded order: the replay guard is stateful exactly as in the warm container.
        it(`reproduces all ${mine.length} recorded responses`, async () => {
          expect(mine.length).toBeGreaterThan(0);
          for (const r of mine) {
            const got = await fn(r.event as LambdaRequestAuthorizerEvent);
            expect(JSON.parse(JSON.stringify(got)), r.scenario).toEqual(r.response);
          }
        });
      });
    }
  }

  it('with the default (request binding ON) the recorded, unbound proofs are denied as request-mismatch', async () => {
    const allowRows = records.filter((r) => r.handler === 'rest' && r.event !== undefined && JSON.stringify(r.response).includes('"Effect":"Allow"'));
    expect(allowRows.length).toBeGreaterThan(0);
    for (const r of allowRows) {
      const tag = r.image.split(':')[1]!;
      const o = opts(tag, r.mintedAtMs ?? records.find((x) => x.image === r.image && x.handler === 'rest' && x.mintedAtMs)?.mintedAtMs ?? 0);
      const { bindRequest: _off, ...dflt } = o;
      void _off;
      const got = JSON.parse(JSON.stringify(await lambdaAuthorizer(dflt as GatewayOptions)(r.event as LambdaRequestAuthorizerEvent)));
      expect(got.policyDocument.Statement[0].Effect, r.scenario).toBe('Deny');
      expect(got.context.pcaCode, r.scenario).toBe('request-mismatch');
    }
  });

  it('the 8 sequential presentations of one proof allowed exactly once in the real runtime', () => {
    const rows = records.filter((r) => r.scenario === '8 sequential presentations of one proof');
    expect(rows).toHaveLength(2);
    for (const r of rows) expect(r.responses?.filter((e) => e === 'Allow')).toHaveLength(1);
  });
});

describe('real Lambda runtime run: AWS documented response contract (as returned by the real runtime)', () => {
  const iam = records.filter((r) => r.handler !== 'simple' && r.response !== undefined && r.event !== undefined);
  it('every IAM-policy response has the documented shape and a string-only context', () => {
    for (const r of iam) {
      const b = r.response as { principalId: unknown; policyDocument: { Version: string; Statement: Record<string, unknown>[] }; context: Record<string, unknown> };
      expect(Object.keys(b).sort()).toEqual(['context', 'policyDocument', 'principalId']);
      expect(typeof b.principalId).toBe('string');
      expect(b.policyDocument.Version).toBe('2012-10-17');
      expect(b.policyDocument.Statement).toHaveLength(1);
      expect(Object.keys(b.policyDocument.Statement[0] ?? {}).sort()).toEqual(['Action', 'Effect', 'Resource']);
      for (const v of Object.values(b.context)) expect(typeof v).toBe('string');
    }
  });
  it('no response carries a caching field: TTL is an authorizer setting, not a response field', () => {
    for (const r of records) {
      if (r.response === undefined) continue;
      const keys = Object.keys(r.response as object);
      expect(keys.filter((k) => /ttl|cache/i.test(k))).toEqual([]);
    }
  });
  it('an Allow context stays far below the 8 KB mark in practice (largest recorded response)', () => {
    const max = Math.max(...records.filter((r) => r.response !== undefined).map((r) => JSON.stringify(r.response).length));
    expect(max).toBeLessThan(2048);
  });
});

describe('SAM local API Gateway emulation: events as the emulated gateway sent them', () => {
  const events = jsonl<Record<string, unknown>>('sam-authorizer-events.jsonl');
  const results = jsonl<{ scenario: string; got: string; want: string; pass: boolean }>('sam-results.jsonl');
  it('every SAM scenario matched its expectation', () => {
    expect(results.length).toBe(11);
    expect(results.filter((r) => !r.pass)).toEqual([]);
  });
  it('the adapter finds method and route in every emulated event (a known proof header with an unknown grant is denied as unknown-grant, never unmapped-route / no-proof)', async () => {
    const handler = lambdaAuthorizer({ audience: 'ins_acme', routes: LAMBDA_TEST_ROUTES, resolveGrant: async () => null, ...SIG_ONLY });
    let checked = 0;
    for (const e of events) {
      if (e.headers === undefined) continue; // TOKEN-shape event: no headers, fails closed
      const res = await handler(e as LambdaRequestAuthorizerEvent);
      expect(res.policyDocument.Statement[0]?.Effect).toBe('Deny');
      expect(res.context.pcaCode).toBe('unknown-grant');
      checked++;
    }
    expect(checked).toBeGreaterThanOrEqual(5);
  });
  it('TOKEN-shape events (authorizationToken only) fail closed with no-proof', async () => {
    const handler = lambdaAuthorizer({ audience: 'ins_acme', routes: LAMBDA_TEST_ROUTES, resolveGrant: async () => null, ...SIG_ONLY });
    const tok = events.filter((e) => typeof e.authorizationToken === 'string' && e.headers === undefined);
    expect(tok.length).toBeGreaterThan(0);
    for (const e of tok) {
      const res = await handler(e as LambdaRequestAuthorizerEvent);
      expect(res.policyDocument.Statement[0]?.Effect).toBe('Deny');
      expect(res.context.pcaCode).toBe('no-proof');
    }
  });
});

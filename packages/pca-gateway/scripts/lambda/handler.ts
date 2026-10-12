/**
 * Lambda entry points for the real-runtime test. Bundled with esbuild into a single handler.mjs and run
 * inside the official AWS Lambda Node.js base image. The grants a proof descends from are read from
 * grants.json next to the handler (written by mint.ts at test time); a missing file fails closed.
 *   handler.rest        -> lambdaAuthorizer        (IAM policy response; REST + HTTP API payload 1.0 / 2.0)
 *   handler.restReplay  -> lambdaAuthorizer + memoryReplayGuard (single-use proofs across warm invocations)
 *   handler.simple      -> lambdaSimpleAuthorizer  (HTTP API payload 2.0 simple response)
 *   handler.backend     -> echoes the authorizer context the gateway forwarded (SAM start-api only)
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Capability } from '@atlasauth/pca';
import { LAMBDA_TEST_ROUTES } from './config';
import { lambdaAuthorizer, lambdaSimpleAuthorizer, memoryReplayGuard, type GatewayOptions } from '../../src/index';

const AUDIENCE = process.env.PCA_AUDIENCE ?? 'ins_acme';
const grants = new Map<string, Capability>(
  Object.entries(JSON.parse(readFileSync(join(__dirname, 'grants.json'), 'utf8')) as Record<string, Capability>),
);

function options(extra?: Partial<GatewayOptions>): GatewayOptions {
  return {
    audience: AUDIENCE,
    bindRequest: false, // conformance harness: unbound proofs
    routes: LAMBDA_TEST_ROUTES,
    resolveGrant: async (ref) => grants.get(ref) ?? null,
    ...extra,
  };
}

/** Test-only: PCA_TRACE_EVENT=1 prints the exact event the invoker (SAM's API Gateway emulation) sent. */
function traced<E, R>(fn: (event: E) => Promise<R>): (event: E) => Promise<R> {
  return async (event: E): Promise<R> => {
    if (process.env.PCA_TRACE_EVENT === '1') console.log(`PCA_TRACE_EVENT ${JSON.stringify(event)}`);
    const out = await fn(event);
    if (process.env.PCA_TRACE_EVENT === '1') console.log(`PCA_TRACE_RESPONSE ${JSON.stringify(out)}`);
    return out;
  };
}

export const rest = traced(lambdaAuthorizer(options()));
export const restReplay = traced(lambdaAuthorizer(options({ replayGuard: memoryReplayGuard() })));
export const simple = traced(lambdaSimpleAuthorizer(options()));
export const backend = async (event: { requestContext?: { authorizer?: unknown } }): Promise<unknown> => ({
  statusCode: 200,
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ reached: true, authorizer: event.requestContext?.authorizer ?? null }),
});

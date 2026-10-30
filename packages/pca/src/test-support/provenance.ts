/**
 * Test support for provenance by default: tests whose subject is another rule present every operation as coming straight from
 * the principal (a principal-direct bundle under a pinned harness key), so the provenance gate passes and the outcome is that
 * of the rule under test. Spread `principalDirect()` into the authorize options: `{ ...opts, provenance: principalDirect() }`.
 */
import { createProvenanceRecorder, principalDirectProvenance, type ProvActionInfo, type ProvenanceBundle } from '../arg-provenance';
import type { PcaOperation } from '../server/verify';

const KEY = new Uint8Array(32).fill(1);
const recorder = () => createProvenanceRecorder({ mediator: 'test-harness', kid: 'k1', secretKey: KEY });
export const TEST_PROV_PIN = recorder().pin;

/** The principal-direct bundle for one operation. */
export const provOf = (o: { verb: string; resource: string; params?: Record<string, unknown> }): ProvenanceBundle =>
  principalDirectProvenance(recorder(), { verb: o.verb, resource: o.resource, params: o.params ?? {} });

/** Authorize `provenance` options: pin the harness key and present a principal-direct bundle for the bound operation. */
export const principalDirect = (actions?: (o: PcaOperation) => ProvActionInfo | undefined) => ({
  mediators: [TEST_PROV_PIN],
  bundle: (_req: unknown, _p: unknown, o: PcaOperation) => provOf(o),
  ...(actions ? { actions } : {}),
});

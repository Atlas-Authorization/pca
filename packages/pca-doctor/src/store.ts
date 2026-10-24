/**
 * Replay / counter store checks through the conformance kit's adapter interface: a REAL concurrent conflicting write
 * (many clients consume one fresh key at once: exactly one may win; counters race on one stream) and durability (write,
 * close, restart when the adapter can, read back). Short by design; the full kit (`pca-store-conformance`) goes further.
 */
import {
  checkHistory,
  detectKinds,
  formatOps,
  loadAdapter as kitLoadAdapter,
  runBurst,
  runDurability,
  type HistoryCheck,
  type StoreAdapter,
} from '@atlasauth/pca-store-conformance';
import type { CheckResult, DoctorConfig } from './types';

const OP = { consume: 'consumeOnce', advance: 'advance' } as const;

export const ATOMICITY_REMEDIATION =
  'Make consumeOnce / advance one atomic operation on the shared store, e.g. Postgres INSERT .. ON CONFLICT (key) DO UPDATE .. WHERE until < $now RETURNING and UPDATE .. WHERE counter < $n RETURNING, Redis SET key NX PX or a Lua compare-and-set; never read, then write. Then run the full kit: pca-store-conformance --adapter <your adapter>.';
export const DURABILITY_REMEDIATION =
  'Keep consumed keys and counters in a store with synchronous, persistent commits (Postgres synchronous_commit=on; Redis appendfsync always and maxmemory-policy noeviction), shared by every verifier instance. An in-memory store is only correct for a single process whose lifetime covers the action lifetime.';

function firstCounterexample(h: HistoryCheck): string {
  const v = h.violations[0];
  return v ? ` First violating key ${v.key}: ${formatOps(v.counterexample ?? []).join(' | ')}` : '';
}

export async function checkStore(cfg: DoctorConfig, deps: { loadAdapter?: typeof kitLoadAdapter } = {}): Promise<CheckResult[]> {
  const spec = cfg.store?.adapter;
  if (!spec) {
    const detail = 'no store adapter given (--store ./adapter.mjs); the replay store cannot be exercised remotely';
    return [
      { id: 'store.atomicity', status: 'skip', detail },
      { id: 'store.durability', status: 'skip', detail },
    ];
  }
  let adapter: StoreAdapter;
  try {
    adapter = await (deps.loadAdapter ?? kitLoadAdapter)(spec, cfg.store?.options ?? {});
  } catch (e) {
    return [{ id: 'store.atomicity', status: 'fail', detail: `cannot load the store adapter ${spec}: ${(e as Error).message}`, remediation: 'Point --store at a module exporting a store adapter (see the store conformance kit guide).' }];
  }
  try {
    const kinds = await detectKinds(adapter);
    return [await atomicity(adapter, kinds, cfg), await durability(adapter, kinds)];
  } catch (e) {
    return [{ id: 'store.atomicity', status: 'fail', detail: `the store adapter failed: ${(e as Error).message}`, remediation: ATOMICITY_REMEDIATION }];
  } finally {
    await adapter.teardown?.();
  }
}

async function atomicity(adapter: StoreAdapter, kinds: readonly ('consume' | 'advance')[], cfg: DoctorConfig): Promise<CheckResult> {
  const clients = cfg.store?.concurrency ?? 32;
  const rounds = cfg.store?.rounds ?? 10;
  const parts: string[] = [];
  const observed: Record<string, unknown> = {};
  let status: CheckResult['status'] = 'pass';
  let cx = '';
  for (const kind of kinds) {
    const w = await runBurst(adapter, kind, { clients, rounds, values: 8 });
    const h = checkHistory(w.ops);
    const winners = new Set(w.ops.filter((o) => o.res === 'true').map((o) => o.key)).size;
    observed[kind] = { ops: h.ops, keys: h.keys, outcomes: h.outcomes, violations: h.violations.length, unresolved: h.unresolved.length };
    const definite = h.outcomes.true + h.outcomes.false;
    if (h.violations.length > 0) {
      status = 'fail';
      cx ||= firstCounterexample(h);
      parts.push(`${OP[kind]}: ${h.violations.length} of ${rounds} same-key rounds NOT linearizable (${clients} concurrent clients)`);
    } else if (definite === 0 || h.unresolved.length > 0) {
      if (status === 'pass') status = 'warn';
      parts.push(`${OP[kind]}: inconclusive (${w.errors} of ${h.ops} calls failed or timed out${h.unresolved.length ? `, ${h.unresolved.length} key(s) undecided` : ''})`);
    } else {
      parts.push(`${OP[kind]}: ${rounds} rounds of ${clients} concurrent conflicting calls linearizable${kind === 'consume' ? ` (${winners} of ${rounds} rounds had exactly one TRUE)` : ''}${w.errors ? `, ${w.errors} calls failed closed` : ''}`);
    }
  }
  return {
    id: 'store.atomicity',
    status,
    detail: `${adapter.name}: ${parts.join('; ')}.${cx}`,
    ...(status === 'pass' ? {} : { remediation: ATOMICITY_REMEDIATION }),
    observed,
  };
}

async function durability(adapter: StoreAdapter, kinds: readonly ('consume' | 'advance')[]): Promise<CheckResult> {
  if (adapter.capabilities?.durable === false) {
    return { id: 'store.durability', status: 'warn', detail: `${adapter.name} declares itself non-durable: a restart forgets consumed nonces`, remediation: DURABILITY_REMEDIATION };
  }
  const parts: string[] = [];
  let status: CheckResult['status'] = 'pass';
  let cx = '';
  for (const kind of kinds) {
    const w = await runDurability(adapter, kind);
    const h = checkHistory(w.ops);
    if (h.violations.length > 0) {
      status = 'fail';
      cx ||= firstCounterexample(h);
      parts.push(`${OP[kind]}: state LOST across close/restart`);
    } else if (h.outcomes.true + h.outcomes.false < w.ops.length) {
      if (status === 'pass') status = 'warn';
      parts.push(`${OP[kind]}: inconclusive (${w.errors} calls failed)`);
    } else {
      parts.push(`${OP[kind]}: survived`);
    }
  }
  const how = adapter.restart ? 'write, close, restart() the backend, read back' : 'write, close, re-open (no restart() hook: the backend itself was not restarted)';
  return {
    id: 'store.durability',
    status,
    detail: `${adapter.name} (${how}): ${parts.join('; ')}.${cx}`,
    ...(status === 'pass' ? {} : { remediation: DURABILITY_REMEDIATION }),
  };
}

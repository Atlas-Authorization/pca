/**
 * The proxy's state behind one interface: the replay counters and the trust budget (`AtomicPcaStateStore`), plus the small
 * records the proxy itself keeps (the grant's identity and window, the session taint flags, the per-action rate windows).
 *
 * `file` (the default) is `openDurableState` of `@atlasauth/pca/durable-state`: every write is fsync'd and hash-chained, a
 * mutation is an atomic read-modify-write under a cross-process lock, and a corrupt, truncated or rolled-back directory makes
 * every operation throw instead of starting empty. A call whose state cannot be read or written is refused (fail closed). The
 * directory holds the seed the grant's keys are derived from: keep it mode 0700 (it is created that way) and, if you can, set
 * `state.hmacKeyEnv` so the journal cannot be re-chained by someone who can write the directory.
 *
 * `memory` exists for development and tests, and has to be asked for by name.
 */

import { durablePcaStateStore, decodeB64uStrict, type AtomicPcaStateStore } from '@atlasauth/pca';
import { createMemoryDurableKv, openDurableState, type DurableKv } from '@atlasauth/pca/durable-state';
import { createHash } from 'node:crypto';
import type { ProvObservation } from '@atlasauth/pca';
import type { ProvenanceLog } from '@atlasauth/pca-gateway';
import { ConfigError, type ProxyConfig } from './config';

export interface ProxyState {
  /** False for the development memory backend. */
  readonly durable: boolean;
  /** Replay counters and budgets, atomic. */
  readonly pca: AtomicPcaStateStore;
  /** The proxy's own records. */
  readonly kv: DurableKv;
}

/** Wrap any atomic key/value store (a test double, another backend) as the proxy's state. */
export function stateFromKv(kv: DurableKv, durable: boolean): ProxyState {
  return { durable, kv, pca: durablePcaStateStore(kv, { prefix: 'pca-state:', scope: durable ? 'shared' : 'process' }) };
}

/** Open the state the configuration names. Throws (the proxy does not start) when it cannot be opened or is corrupt. */
export async function openProxyState(cfg: ProxyConfig, env: Record<string, string | undefined> = process.env): Promise<ProxyState> {
  if (cfg.state.backend === 'memory') return stateFromKv(createMemoryDurableKv(), false);
  let hmacKey: Uint8Array | undefined;
  if (cfg.state.hmacKeyEnv !== undefined) {
    const k = decodeB64uStrict(env[cfg.state.hmacKeyEnv]);
    if (k === null || k.length < 32) throw new ConfigError(`${cfg.state.hmacKeyEnv} must hold a base64url key of at least 32 bytes`);
    hmacKey = k;
  }
  const kv = await openDurableState({ dir: cfg.state.dir, ...(hmacKey ? { hmacKey } : {}) });
  return stateFromKv(kv, true);
}

/**
 * The gateway's record of what it let through to each agent session (verify mode), kept in the proxy's state so it survives a
 * restart. A read or a write that fails throws: the gateway then refuses the request.
 */
export function durableProvenanceLog(kv: DurableKv): ProvenanceLog {
  const key = (session: string): string => `gwlog:${createHash('sha256').update(session).digest('hex')}`;
  return {
    async seen(session) {
      const v = await kv.get(key(session));
      return Array.isArray(v) ? (v as ProvObservation[]) : [];
    },
    async add(session, o) {
      await kv.update(key(session), (prev) => {
        const cur = Array.isArray(prev) ? (prev as ProvObservation[]) : [];
        if (cur.some((x) => x.origin === o.origin && x.source === o.source) || cur.length >= 256) return undefined;
        return [...cur, o];
      });
    },
  };
}

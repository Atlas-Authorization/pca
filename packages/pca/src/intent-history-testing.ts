/**
 * TEST DOUBLE for the intent session store (`@atlasauth/pca/ext/intent-testing`). Volatile: it is not part of `@atlasauth/pca/ext/intent`
 * (0.5, B16); production implements `IntentSessionStore` over a database and keeps `requireDurable` at its default.
 */
import type { IntentEvent, IntentSessionStore, SessionTx } from './intent-history';

/**
 * In-process store with a per-session promise-chain mutex (tests, single-process sites). It is VOLATILE (`durable` is false):
 * a restart forgets every session's history, so every cap and monitor starts again from zero. A deployment whose caps must
 * outlive the process implements {@link IntentSessionStore} over its database and passes `requireDurable: true` to
 * {@link admitIntentAction}.
 */
export class MemoryIntentSessionStore implements IntentSessionStore {
  readonly durable = false;
  private readonly logs = new Map<string, IntentEvent[]>();
  private readonly locks = new Map<string, Promise<unknown>>();

  async withSession<T>(session: string, fn: (tx: SessionTx) => Promise<T>): Promise<T> {
    const prev = this.locks.get(session) ?? Promise.resolve();
    let release!: () => void;
    const mine = new Promise<void>((r) => (release = r));
    const chained = prev.then(() => mine);
    this.locks.set(session, chained);
    await prev;
    try {
      const log = this.logs.get(session) ?? [];
      this.logs.set(session, log);
      const tx: SessionTx = {
        events: async () => log.map((e) => ({ ...e })),
        append: async (e) => {
          if (log.some((x) => x.id === e.id)) throw new Error('duplicate event id');
          log.push({ ...e });
        },
        setStatus: async (id, status) => {
          const e = log.find((x) => x.id === id);
          if (!e) return false;
          e.status = status;
          return true;
        },
      };
      return await fn(tx);
    } finally {
      release();
      if (this.locks.get(session) === chained) this.locks.delete(session);
    }
  }

  snapshot(session: string): IntentEvent[] {
    return (this.logs.get(session) ?? []).map((e) => ({ ...e }));
  }
}


/**
 * The adapter interface a store author implements to run the conformance kit against THEIR store.
 *
 * The contract under test is the one in `@atlasauth/pca` (`ReplayStore` / `CounterStore`, `replay.ts`):
 *  - `consumeOnce(key, retainUntilMs, nowMs)` resolves `true` iff there is no live record for `key` (live = its stored
 *    horizon is `>= nowMs`), then records `retainUntilMs`. A record may be forgotten only after its horizon has passed.
 *  - `advance(stream, counter)` resolves `true` iff `counter` is strictly greater than the stored value, then stores it.
 *  - both are atomic across every client of the same backend, durable, and FAIL CLOSED (reject when they cannot decide).
 */

/** One connection / verifier instance talking to the shared backend. Implement whichever of the two operations you ship. */
export interface StoreClient {
  consumeOnce?(key: string, retainUntilMs: number, nowMs: number): Promise<boolean>;
  advance?(streamKey: string, counter: number): Promise<boolean>;
  /** Release the connection. The backend's state must survive it. */
  close?(): Promise<void>;
}

export interface StoreCapabilities {
  /** The adapter implements `consumeOnce` (default: detected from the first client). */
  consumeOnce?: boolean;
  /** The adapter implements `advance` (default: detected from the first client). */
  advance?: boolean;
  /**
   * The store claims durability: consumed keys and counters survive closing every client and `restart()`. Default true:
   * a replay store that forgets on restart resurrects nonces. Declare `false` ONLY for a single-process in-memory store
   * whose lifetime covers the action lifetime; the durability test is then skipped (and reported as such).
   */
  durable?: boolean;
}

export interface StoreAdapter {
  /** Shown in reports. */
  name: string;
  capabilities?: StoreCapabilities;
  /** Open one client against the shared backend. Called once per simulated verifier instance. */
  open(): Promise<StoreClient>;
  /**
   * Optional: restart the BACKEND (e.g. restart the database / server process, or re-open the files) after every client
   * was closed. Without it the durability test only closes and re-opens clients.
   */
  restart?(): Promise<void>;
  /** Optional: crash the backend abruptly (kill -9 equivalent). Followed by `restart()`. Used by the crash test. */
  crash?(): Promise<void>;
  /** Optional: release everything the adapter holds (pools, temp dirs). Never drop shared data here. */
  teardown?(): Promise<void>;
}

/** What an adapter module exports: an adapter, or a factory taking the CLI's `--option k=v` pairs. */
export type AdapterFactory = (options: Record<string, string>) => StoreAdapter | Promise<StoreAdapter>;

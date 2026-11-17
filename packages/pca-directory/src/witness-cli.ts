/**
 * The witness operator's commands behind `pca-directory-witness cancel-retirement` and `pca-directory-witness follow`.
 * Node-only (files, fetch); the checks themselves are `Witness.followTransitions` and `Witness.cancelRetirement`.
 */
import { readFileSync } from 'node:fs';
import { httpLogClient } from './client';
import { FileWitnessState, loadOrCreateSecret } from './node';
import { Witness } from './witness';
import type { WitnessState } from './witness';

type FetchLike = NonNullable<Parameters<typeof httpLogClient>[1]>['fetch'];

/** Read transitions from a file or an http(s) URL: an array, `{ data: [...] }` (the log's /key-transitions), `{ transition }` or one transition. */
export async function readTransitions(source: string, fetchImpl?: FetchLike): Promise<unknown[]> {
  let body: unknown;
  if (/^https?:\/\//.test(source)) {
    const f = fetchImpl ?? ((globalThis as { fetch?: FetchLike }).fetch as FetchLike);
    const res = await f!(source, { headers: { accept: 'application/json' } });
    if (!res.ok) throw new Error(`${source}: HTTP ${res.status}`);
    body = await res.json();
  } else {
    body = JSON.parse(readFileSync(source, 'utf8'));
  }
  const b = body as { data?: unknown; transition?: unknown } | unknown[] | null;
  if (Array.isArray(b)) return b;
  if (b && typeof b === 'object') {
    if (Array.isArray((b as { data?: unknown }).data)) return (b as { data: unknown[] }).data;
    if ((b as { transition?: unknown }).transition) return [(b as { transition: unknown }).transition];
    return [b];
  }
  throw new Error(`${source}: not a transition, a list of transitions or a /key-transitions response`);
}

export interface FollowOptions {
  key: string;
  state: string;
  /** The key this witness follows today (from its configuration). */
  from: string;
  /** Base URL of the log's routes and the NEW key to adopt. */
  log: { url: string; guardian: string };
  /** A file or URL holding the published transition(s). */
  transition: string;
  /** Trusted witness keys and how many must have cosigned each transition. */
  witnesses: string[];
  threshold: number;
  fetch?: FetchLike;
  /** Test seam: use this state instead of the file. */
  stateImpl?: WitnessState;
}

/** Verify the witnessed transition chain from `from` to the new key and adopt it. Returns the lines to print; throws on refusal. */
export async function followCommand(o: FollowOptions): Promise<string[]> {
  if (o.witnesses.length === 0 || !(o.threshold >= 1) || o.threshold > o.witnesses.length) throw new Error('follow needs --witness keys and a --threshold from 1 to their number: a rotation is trusted only on a witness quorum');
  const { secret } = loadOrCreateSecret(o.key);
  const state = o.stateImpl ?? new FileWitnessState(o.state);
  const w = new Witness(secret, [{ guardian: o.from }], state);
  const transitions = await readTransitions(o.transition, o.fetch);
  const client = httpLogClient(o.log.url, o.fetch ? { fetch: o.fetch } : {});
  const r = await w.followTransitions({
    from: o.from,
    to: o.log.guardian,
    transitions,
    witnesses: { witnessKeys: o.witnesses, threshold: o.threshold },
    consistency: (a, b) => client.consistency(a, b),
  });
  if (!r.ok) throw new Error(`refused: ${r.reason}`);
  return [`now following ${o.log.guardian} from size ${r.size} (${r.rotations} key transition(s) verified)`];
}

/** Undo the retirement a transition caused, when the log abandoned that rotation. */
export async function cancelRetirementCommand(o: { key: string; state: string; guardian: string; stateImpl?: WitnessState }): Promise<string[]> {
  const { secret } = loadOrCreateSecret(o.key);
  const state = o.stateImpl ?? new FileWitnessState(o.state);
  const before = await state.get(o.guardian);
  if (!before) throw new Error('this witness has no state for that key');
  if (!before.retiredTo) return [`${o.guardian} is not retired; nothing to do`];
  await new Witness(secret, [{ guardian: o.guardian }], state).cancelRetirement(o.guardian);
  return [`${o.guardian} may sign again (the retirement toward ${before.retiredTo} was cancelled)`];
}

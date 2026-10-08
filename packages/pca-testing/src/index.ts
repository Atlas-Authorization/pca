/**
 * Testing kit for Proof-Carrying Authority (`@atlasauth/pca`).
 *
 * Factories, fakes and assertion helpers so an integrator can unit-test their PCA wiring WITHOUT a
 * backend, a network, or a running resource server. You mint a real {@link Agent} with test defaults,
 * build real PCActns from it, and run the REAL core verifier (`verifyPCActnCore`) against them in
 * process — the same code path a resource server runs, minus the later-milestone hooks.
 *
 * HONEST: nothing here authorizes anything, and `fakeVerify` is "fake" only in the sense that it stands
 * in for the resource server by rooting the check at the PCActn's own grant and accepting the PCActn's
 * own audience by default — so a clean round-trip verifies. It is NOT a weakened verifier: it is
 * `verifyPCActnCore` unchanged, so tampering (a swapped verb, a mutated param) is caught exactly as it
 * would be in production via the `plan_inclusion` / `leaf_signature` checks. The later-milestone checks
 * (attestation, taint, threshold, revocation, zk, bond) report `not-enforced` here just as the core
 * verifier does when no hook is supplied.
 */

import {
  type Agent,
  type Capability,
  type KeyPair,
  type Limits,
  type PCActn,
  type PermissionMap,
  type VerifyResult,
  agent,
  decodePCActn,
  encodePCActn,
  generateKeyPair,
  verifyPCActnCore,
} from '@atlasauth/pca';

// ---- factories ------------------------------------------------------------------------------------

/** Human-level overrides for {@link testAgent}. Anything omitted falls back to a sensible test default. */
export interface TestAgentOverrides {
  /** Connector -> allowed actions. Default `{ stripe: ['refund'] }`. */
  permissions?: PermissionMap;
  /** Per-action limits. Default `{ refund: '$500/day' }`. Pass `{}` for no limits. */
  limits?: Limits;
  /** Plaintext goal (only its salted commitment goes in the grant). Default `'test'`. */
  goal?: string;
  /** Default audience (resource-server / instance id) stamped on every `act`. Default `'ins_test'`. */
  aud?: string;
  /** Principal (human) keypair that roots + signs the grant. A fresh pair is generated when omitted. */
  principal?: KeyPair;
  /** Agent (holder) keypair that signs PCActns. A fresh pair is generated when omitted. */
  holder?: KeyPair;
}

/**
 * Mint a REAL {@link Agent} with test defaults. Thin wrapper over `agent()` — the returned handle is the
 * genuine article (real signed grant, real `act`/`dryRun`/`subAgent`), so a PCActn it builds verifies
 * against {@link fakeVerify} out of the box.
 */
export function testAgent(overrides: TestAgentOverrides = {}): Agent {
  return agent({
    principal: overrides.principal ?? generateKeyPair(),
    goal: overrides.goal ?? 'test',
    permissions: overrides.permissions ?? { stripe: ['refund'] },
    limits: overrides.limits ?? { refund: '$500/day' },
    aud: overrides.aud ?? 'ins_test',
    ...(overrides.holder !== undefined ? { holder: overrides.holder } : {}),
  });
}

/**
 * Build a PCActn from `a` for one action — a thin wrapper over `a.act(...)` that returns just the
 * `pcactn` + wire-`encoded` pair (the local dry-run is dropped; use `a.act` directly if you need it).
 * `counter` auto-increments per holder when omitted.
 */
export function makePCActn(
  a: Agent,
  verb: string,
  resource: string,
  params?: Record<string, unknown>,
  opts?: { counter?: number; now?: number },
): { pcactn: PCActn; encoded: string } {
  const res = a.act(verb, resource, params, {
    ...(opts?.counter !== undefined ? { counter: opts.counter } : {}),
    ...(opts?.now !== undefined ? { now: opts.now } : {}),
  });
  return { pcactn: res.pcactn, encoded: res.encoded };
}

// ---- fake verifier --------------------------------------------------------------------------------

/** Options for {@link fakeVerify} / {@link expectVerifies} / {@link expectDenied}. */
export interface FakeVerifyOptions {
  /**
   * The verifier's own audience. Omit to accept the PCActn's OWN `aud` (so a round-trip verifies);
   * pass a mismatching string to force the `audience` check to fail; pass `null` to opt out entirely.
   */
  audience?: string | null;
  /** Clock (epoch ms) for the validity window. Defaults to `Date.now()` inside the core verifier. */
  now?: number;
  /** Root grant to verify against. Defaults to the PCActn's own chain root (`cap_chain[0]`). */
  grant?: Capability;
}

/**
 * Run the REAL `verifyPCActnCore` against `pcactn`, rooting the check at `opts.grant ?? pcactn.cap_chain[0]`
 * and defaulting the verifier audience to the PCActn's own `aud` (so a faithfully-built action verifies).
 * Returns the full {@link VerifyResult} — inspect `allow` / `checks` / `reason`.
 */
export async function fakeVerify(pcactn: PCActn, opts?: FakeVerifyOptions): Promise<VerifyResult> {
  const grant = opts?.grant ?? pcactn.cap_chain[0];
  if (!grant) {
    throw new Error('fakeVerify: PCActn has an empty cap_chain and no grant was supplied via opts.grant');
  }
  // Explicit `audience` (including `null`) is honoured; otherwise default to the PCActn's own aud.
  const audience: string | null = opts && 'audience' in opts ? (opts.audience ?? null) : pcactn.aud;
  return verifyPCActnCore(pcactn, {
    grant,
    audience,
    ...(opts?.now !== undefined ? { nowEpoch: opts.now } : {}),
  });
}

function failingChecks(res: VerifyResult): string[] {
  return Object.entries(res.checks)
    .filter(([, status]) => status === 'fail')
    .map(([name]) => name);
}

/**
 * Assert that `pcactn` verifies. Runs {@link fakeVerify} and THROWS a plain `Error` naming the failing
 * checks (and the core verifier's `reason`) when `allow` is false; returns the {@link VerifyResult}
 * otherwise. Framework-agnostic — it throws, so it works under any test runner.
 */
export async function expectVerifies(pcactn: PCActn, opts?: FakeVerifyOptions): Promise<VerifyResult> {
  const res = await fakeVerify(pcactn, opts);
  if (!res.allow) {
    const failed = failingChecks(res);
    throw new Error(
      `expectVerifies: PCActn was denied. failing checks: [${failed.join(', ')}]` +
        (res.reason ? ` — ${res.reason}` : ''),
    );
  }
  return res;
}

/**
 * The inverse of {@link expectVerifies}: assert that `pcactn` is DENIED. Throws a plain `Error` when the
 * PCActn unexpectedly verifies; returns the {@link VerifyResult} otherwise.
 */
export async function expectDenied(pcactn: PCActn, opts?: FakeVerifyOptions): Promise<VerifyResult> {
  const res = await fakeVerify(pcactn, opts);
  if (res.allow) {
    throw new Error(
      `expectDenied: PCActn verified but was expected to be denied. checks: ${JSON.stringify(res.checks)}`,
    );
  }
  return res;
}

// ---- in-memory state store ------------------------------------------------------------------------

/**
 * Per-holder replay/budget state a resource server threads across actions. Defined locally (NOT imported
 * from `@atlasauth/backend`) so the kit depends only on `@atlasauth/pca`; the shape is a structural
 * drop-in for the backend's store.
 */
export interface State {
  budget?: unknown;
  lastCounter?: number;
  lastEpoch?: number;
  lastBeaconSeq?: number;
}

/** Structural store shape: an async key -> {@link State} map. Drop-in as a `budgetStore` in tests. */
export interface StateStore {
  get(key: string): Promise<State | undefined>;
  put(key: string, state: State): Promise<void>;
}

/** An in-memory {@link StateStore} backed by a `Map`. Nothing persists beyond the process. */
export function memoryStateStore(): StateStore {
  const m = new Map<string, State>();
  return {
    async get(key: string): Promise<State | undefined> {
      return m.get(key);
    },
    async put(key: string, state: State): Promise<void> {
      m.set(key, state);
    },
  };
}

// ---- tampering ------------------------------------------------------------------------------------

/**
 * Decode an encoded PCActn, let `mutate` corrupt it in place, then re-encode it (via `encodePCActn`) so
 * a test can assert the corruption is caught. Any field change that touches the signed body (e.g. the
 * action verb) breaks `leaf_signature`; a change under the action breaks `plan_inclusion` too.
 */
export function tamper(encoded: string, mutate: (p: Record<string, unknown>) => void): string {
  // The spread yields an anonymous object type (eligible for an implicit index signature), so it assigns
  // to Record<string, unknown> with no cast; the JSON round-trip re-types it as a PCActn for encodePCActn.
  const rec: Record<string, unknown> = { ...decodePCActn(encoded) };
  mutate(rec);
  return encodePCActn(decodePCActn(JSON.stringify(rec)));
}

import { ContractEnforcer, signContractReset } from '../contract-enforcer';
import { advanceContract, checkContract, CONTRACT_VERSION, MAX_CLAUSE_DEPTH, MAX_CLAUSES, signContract, validateContract, verifyContract, type Clause, type Contract, type SignedContract } from '../contracts';
import { createMemoryDurableKv } from '../durable-state';
import { sha256, utf8 } from '../hash';
import { encodeKey, publicKeyOf } from '../keys';
import type { ActionContext } from '../predicates';
import { emptyState, stateDigest, type MonitorState } from '../prohibitions';

/**
 * Shared vectors for temporal contracts (conformance/contracts-vectors.json), generated from the TypeScript reference.
 *  - `validate`: validateContract problems (the fail-closed table of contracts-fail-closed-table.test.ts).
 *  - `check`: checkContract (no advance) from a given state.
 *  - `advance`: step sequences through advanceContract (precedence latches, bounded-liveness deadlines, stale-head refusals).
 *  - `verify`: verifyContract outcomes for a signed contract (deterministic Ed25519; the key is derived from a public test seed).
 *  - `enforcer`: ContractEnforcer decisions over an in-memory durable store, with a fixed clock.
 * Not a secret: the signing key is derived from the string below and exists only to make signatures reproducible.
 */
const SEED = sha256(utf8('atlas-pca/conformance/contracts-vectors/test-principal'));
const OTHER = sha256(utf8('atlas-pca/conformance/contracts-vectors/other-principal'));
const PRIN = encodeKey(publicKeyOf(SEED));
const NOW = 1_700_000_000_000;
const act = (verb: string, resource = '/r'): ActionContext => ({ action: { verb, resource } });
const W = (verb: string) => ({ verb });
const base = (clauses: unknown, extra: Record<string, unknown> = {}): Contract => ({ version: CONTRACT_VERSION, principal: PRIN, clauses: clauses as Clause[], ...extra });
const nest = (n: number): Clause => {
  let c: Clause = { id: 'leaf', kind: 'never', p: W('x') };
  for (let i = 0; i < n; i++) c = { id: `and${i}`, kind: 'and', clauses: [c] };
  return c;
};
const NEVER = { id: 'a', kind: 'never', p: W('x') };

export async function buildContractsVectors(): Promise<unknown> {
  const validateCases: Array<{ name: string; contract: unknown }> = [
    { name: 'well formed: never + precedes', contract: base([NEVER, { id: 'o', kind: 'precedes', p: W('review'), q: W('deploy') }]) },
    { name: 'well formed with no clauses', contract: base([]) },
    { name: 'not an object', contract: null },
    { name: 'wrong version', contract: { version: 2, principal: PRIN } },
    { name: 'no principal', contract: { version: 1 } },
    { name: 'clauses not an array', contract: { version: 1, principal: PRIN, clauses: {} } },
    { name: 'clause not an object', contract: base([5]) },
    { name: 'clause without id', contract: base([{ kind: 'never', p: W('x') }]) },
    { name: 'unknown clause kind', contract: base([{ id: 'u', kind: 'eventually', p: W('x') }]) },
    { name: 'forbidden id', contract: base([{ ...NEVER, id: '__proto__' }]) },
    { name: 'duplicate ids', contract: base([NEVER, NEVER]) },
    { name: 'duplicate id across nesting', contract: base([NEVER, { id: 'n', kind: 'and', clauses: [NEVER] }]) },
    { name: 'within 0', contract: base([{ id: 'r', kind: 'responds_within', p: W('x'), q: W('y'), within: 0 }]) },
    { name: 'within fractional', contract: base([{ id: 'r', kind: 'responds_within', p: W('x'), q: W('y'), within: 1.5 }]) },
    { name: 'within 1 is fine', contract: base([{ id: 'r', kind: 'responds_within', p: W('x'), q: W('y'), within: 1 }]) },
    { name: 'empty and', contract: base([{ id: 'n', kind: 'and', clauses: [] }]) },
    { name: `${MAX_CLAUSES} clauses are fine`, contract: base(Array.from({ length: MAX_CLAUSES }, (_, i) => ({ id: `c${i}`, kind: 'never', p: W('x') }))) },
    { name: `${MAX_CLAUSES + 1} clauses are refused`, contract: base(Array.from({ length: MAX_CLAUSES + 1 }, (_, i) => ({ id: `c${i}`, kind: 'never', p: W('x') }))) },
    { name: `nesting of ${MAX_CLAUSE_DEPTH - 1} levels is fine`, contract: base([nest(MAX_CLAUSE_DEPTH - 1)]) },
    { name: `nesting of ${MAX_CLAUSE_DEPTH} levels is refused`, contract: base([nest(MAX_CLAUSE_DEPTH)]) },
    { name: 'an embedded invariant id that collides with a clause id', contract: base([NEVER], { invariants: [{ id: 'a', kind: 'never', when: W('delete') }] }) },
  ];
  const validate = validateCases.map((c) => ({ name: c.name, contract: c.contract, expect: { problems: validateContract(c.contract) } }));

  const gen = emptyState(NOW);
  const ordered = base([{ id: 'order', kind: 'precedes', p: W('review'), q: W('deploy') }]);
  const rich = base([{ id: 'no-delete', kind: 'never', p: W('delete') }, { id: 'order', kind: 'precedes', p: W('review'), q: W('deploy') }, { id: 'ack', kind: 'responds_within', p: W('alarm'), q: W('ack'), within: 2 }], { invariants: [{ id: 'no-wire', kind: 'never', when: W('wire') }] });
  const onlyRead = base([{ id: 'only-read', kind: 'always', p: W('read') }]);
  const checkCases: Array<{ name: string; contract: unknown; action: ActionContext; state?: MonitorState }> = [
    { name: 'never: a matching action violates', contract: rich, action: act('delete') },
    { name: 'always: a non-matching action violates', contract: onlyRead, action: act('write') },
    { name: 'always: a matching action passes', contract: onlyRead, action: act('read') },
    { name: 'never + embedded invariant + deadline clauses all pass for read', contract: rich, action: act('read') },
    { name: 'embedded invariant violation is listed with the clauses', contract: rich, action: act('wire') },
    { name: 'precedes: guarded action before the prerequisite', contract: ordered, action: act('deploy') },
    { name: 'precedes: an unrelated action passes', contract: ordered, action: act('read') },
    { name: 'a malformed contract is refused as <contract>', contract: { version: 9 }, action: act('read') },
    { name: 'a malformed action is refused as <action>', contract: ordered, action: { action: { verb: 1, resource: '/r' } } as never },
    { name: 'a malformed state is refused as <state>', contract: ordered, action: act('review'), state: { ...gen, seq: -1 } },
    { name: 'an unknown clause kind smuggled past validation is refused', contract: base([{ id: 'u', kind: 'eventually', p: W('x') }]), action: act('read') },
  ];
  const check = checkCases.map((c) => ({ name: c.name, contract: c.contract, action: c.action, state: c.state ?? gen, expect: checkContract(c.action, c.contract as Contract, c.state ?? gen) }));

  type Step = { action: ActionContext; options?: { now?: number; expectedSeq?: number; stale_digest_of_genesis?: boolean } };
  const scenarios: Array<{ name: string; contract: Contract; steps: Step[] }> = [
    { name: 'precedes: review unlocks deploy; seq and chain advance', contract: ordered, steps: [{ action: act('review') }, { action: act('deploy') }] },
    { name: 'precedes: deploy first is a contract violation and the state does not move', contract: ordered, steps: [{ action: act('deploy') }, { action: act('review') }] },
    { name: 'responds_within: the response inside the deadline discharges it', contract: rich, steps: [{ action: act('alarm') }, { action: act('read') }, { action: act('ack') }, { action: act('read') }] },
    { name: 'responds_within: the action that exhausts the deadline is the violation', contract: base([{ id: 'ack', kind: 'responds_within', p: W('alarm'), q: W('ack'), within: 2 }]), steps: [{ action: act('alarm') }, { action: act('read') }, { action: act('read') }, { action: act('read') }] },
    { name: 'stale head: expectedSeq that is not the current seq is refused', contract: ordered, steps: [{ action: act('review') }, { action: act('deploy'), options: { expectedSeq: 0 } }, { action: act('deploy'), options: { expectedSeq: 1 } }] },
    { name: 'stale head: the genesis digest after one step is refused', contract: ordered, steps: [{ action: act('review') }, { action: act('deploy'), options: { stale_digest_of_genesis: true } }] },
    { name: 'a clock that goes backwards is refused', contract: ordered, steps: [{ action: act('review') }, { action: act('deploy'), options: { now: NOW - 1 } }] },
  ];
  const advance = scenarios.map((s) => {
    let st: MonitorState = emptyState(NOW);
    const steps = s.steps.map((step) => {
      const o: { now?: number; expectedSeq?: number; expectedStateDigest?: string } = {};
      if (step.options?.now !== undefined) o.now = step.options.now;
      if (step.options?.expectedSeq !== undefined) o.expectedSeq = step.options.expectedSeq;
      if (step.options?.stale_digest_of_genesis) o.expectedStateDigest = stateDigest(emptyState(NOW));
      const r = advanceContract(st, step.action, s.contract, o);
      if (r.ok) st = r.next;
      return { action: step.action, ...(step.options ? { options: step.options } : {}), expect: { ok: r.ok, decidedBy: r.decidedBy, violated: r.violated, reasons: r.reasons, seq: r.next.seq, deadlines: r.next.deadlines ?? {}, latched: Object.keys(r.next.latched).sort(), state_digest: stateDigest(r.next) } };
    });
    return { name: s.name, contract: s.contract, genesis_now: NOW, steps };
  });

  const signed: SignedContract = signContract(ordered, SEED);
  const verifyCases: Array<{ name: string; contract: unknown; principal?: string }> = [
    { name: 'valid under the pinned principal', contract: signed, principal: PRIN },
    { name: 'valid with no pinned principal', contract: signed },
    { name: 'wrong pinned principal', contract: signed, principal: encodeKey(publicKeyOf(OTHER)) },
    { name: 'tampered content changes the id', contract: { ...signed, clauses: [{ id: 'order', kind: 'precedes', p: W('x'), q: W('y') }] }, principal: PRIN },
    { name: 'signature from another key', contract: { ...signed, sig: signContract(ordered, OTHER).sig }, principal: PRIN },
    { name: 'missing signature', contract: { ...signed, sig: undefined }, principal: PRIN },
    { name: 'not an object', contract: null },
  ];
  const verify = verifyCases.map((c) => ({ name: c.name, contract: c.contract, ...(c.principal ? { principal: c.principal } : {}), expect: verifyContract(c.contract as SignedContract, c.principal) }));

  return {
    version: 1,
    note: 'Generated by scripts/gen-conformance-contracts.ts from the TypeScript reference. `validate`, `check`, `advance`, `verify` and `enforcer` replay against the contract plane; `advance` steps run from the genesis state at genesis_now and each carries the next state digest. The signing keys are derived from public test seeds only to make signatures reproducible.',
    principal: PRIN,
    validate,
    check,
    advance,
    verify,
    enforcer: await buildEnforcerVectors(),
  };
}

type EnfStep = { op: 'check'; action: ActionContext; permitted?: boolean; wall?: number } | { op: 'peek'; action: ActionContext } | { op: 'reset'; seq?: number; signer?: 'principal' | 'other' } | { op: 'state' };

/** The enforcer scenarios are async (a durable store); built separately so the other tables stay synchronous. */
export async function buildEnforcerVectors(): Promise<unknown[]> {
  const contract = signContract(base([{ id: 'no-delete', kind: 'never', p: W('delete') }, { id: 'review-first', kind: 'precedes', p: W('review'), q: W('deploy') }]), SEED);
  const scenarios: Array<{ name: string; latch?: boolean; steps: EnfStep[]; corrupt?: boolean }> = [
    { name: 'admits in order and advances seq', steps: [{ op: 'check', action: act('review') }, { op: 'check', action: act('deploy') }, { op: 'state' }] },
    { name: 'permission denied: reason permission, no latch, state unchanged', steps: [{ op: 'check', action: act('review'), permitted: false }, { op: 'check', action: act('review') }] },
    { name: 'a violation is refused and latches: even a harmless action is then refused', steps: [{ op: 'check', action: act('deploy') }, { op: 'check', action: act('review') }, { op: 'state' }] },
    { name: 'latchOnViolation false: a violation is only denied', latch: false, steps: [{ op: 'check', action: act('delete') }, { op: 'check', action: act('review') }] },
    { name: 'peek is read only: a violation is reported but not latched', steps: [{ op: 'peek', action: act('delete') }, { op: 'check', action: act('review') }] },
    { name: 'reset needs the principal signature at the latched seq', steps: [{ op: 'check', action: act('review') }, { op: 'check', action: act('delete') }, { op: 'reset', seq: 1, signer: 'other' }, { op: 'reset', seq: 0, signer: 'principal' }, { op: 'check', action: act('review') }, { op: 'reset', seq: 1, signer: 'principal' }, { op: 'reset', seq: 1, signer: 'principal' }, { op: 'check', action: act('deploy') }] },
    { name: 'a stored document for another contract is a state error', corrupt: true, steps: [{ op: 'check', action: act('review') }, { op: 'peek', action: act('review') }] },
    { name: 'a clock that goes backwards never moves the state clock back', steps: [{ op: 'check', action: act('review'), wall: NOW + 5000 }, { op: 'check', action: act('deploy'), wall: NOW }, { op: 'state' }] },
  ];
  const out: unknown[] = [];
  for (const s of scenarios) {
    const kv = createMemoryDurableKv();
    let wall = NOW;
    const e = ContractEnforcer.open(kv, contract, { principal: PRIN, now: () => wall, ...(s.latch === false ? { latchOnViolation: false } : {}) });
    if (s.corrupt) await kv.set(`contract/${contract.id}`, { v: 1, contract_id: 'someone-else', state: emptyState(NOW) });
    const steps: unknown[] = [];
    for (const st of s.steps) {
      if (st.op === 'check') {
        wall = st.wall ?? NOW;
        steps.push({ ...st, expect: await e.check(st.action, st.permitted) });
      } else if (st.op === 'peek') steps.push({ ...st, expect: await e.peek(st.action) });
      else if (st.op === 'state') {
        const r = await e.state();
        steps.push({ ...st, expect: r === undefined ? null : { seq: r.state.seq, now: r.state.now, latched: r.latched, state_digest: stateDigest(r.state) } });
      } else {
        const sig = signContractReset(st.signer === 'other' ? OTHER : SEED, contract.id, st.seq ?? 0);
        steps.push({ ...st, sig, expect: { cleared: await e.reset(sig) } });
      }
    }
    out.push({ name: s.name, ...(s.latch === false ? { options: { latchOnViolation: false } } : {}), ...(s.corrupt ? { stored_document: { v: 1, contract_id: 'someone-else', state: emptyState(NOW) } } : {}), steps });
  }
  return [{ contract, principal: PRIN, clock: NOW }, ...out];
}

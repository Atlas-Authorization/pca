/**
 * Shared authorize-level fixtures for server-side PQ pins (`pqPins`), signed by the TypeScript reference with REAL post-quantum
 * grants and replayed end to end by every native SDK through its authorize entry point (the pq-pin vectors test the helper only).
 *
 *   tsx scripts/gen-authorize-pq-pin-fixtures.ts [--check]     (from packages/pca; writes conformance/authorize-pq-pin-fixtures.json)
 *
 * Each case is a stored grant (the resolver's answer for `grant.id`), a signed PCActn, the operation, the server-side `pq_pins`
 * (issuer -> pq_pk) and the exact authorize outcome. Every case is also run through the TypeScript authorize(); the generator
 * throws on drift. Keys are fixed (test-only seeds); the grant salt is injected, so the file is byte-reproducible.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { mintGrant } from '../src/envelope';
import { b64u } from '../src/hash';
import { encodeKey, publicKeyOf } from '../src/keys';
import { paramsDigest, type PlanNode } from '../src/merkle';
import { mintRoot, type Capability } from '../src/capability';
import { buildPCActn } from '../src/pcactn';
import { mlDsa65Keygen, mlDsa87Keygen } from '../src/pq';
import type { RiskPolicy } from '../src/risk';
import { createAuthorizer } from '../src/server/authorize';
import { memoryPcaStore } from '../src/server/require-pca';

const NOW = Date.UTC(2026, 10, 11, 12, 0, 0);
const AUD = 'pq-pin-rs';
const ZERO_RISK: RiskPolicy = { weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 100, lambda: 0, rho: 0.5, bMax: 1_000_000 };
const seedBytes = (n: number) => new Uint8Array(32).fill(n);
const principal = { secretKey: seedBytes(111), publicKey: publicKeyOf(seedBytes(111)) };
const agent = { secretKey: seedBytes(112), publicKey: publicKeyOf(seedBytes(112)) };
const pPub = encodeKey(principal.publicKey);
const aPub = encodeKey(agent.publicKey);
const mlSeed = (n: number) => new Uint8Array(32).fill(n);
const principalMl65 = mlDsa65Keygen(mlSeed(121));
const otherMl87 = mlDsa87Keygen(mlSeed(122));
const OP = { verb: 'orders.quote', resource: 'orders/42', params: { order: 'o42' } } as const;

const classical = mintGrant({
  principalSecret: principal.secretKey, principalPublic: pPub, holder: aPub, goal: 'quote orders', salt: b64u(new Uint8Array(16).fill(5)),
  // the signed opt-out of the provenance gate: nothing here is injected content, and natives need no provenance bundle to replay this file
  envelope: { predicates: [{ verb: '*', resource: '*', where: [] }], caveats: [], agent_binding: {}, risk_policy: ZERO_RISK, provenance: { mode: 'insecure_off' } },
}).grant;
// the SAME envelope, signed by the principal under a pure ML-DSA-65 suite (the root hop of the chain)
const pqGrant: Capability = mintRoot({ principalSecret: principal.secretKey, principalPublic: pPub, holder: aPub, caveats: classical.caveats, suite: { alg: 'ml-dsa-65', mlDsa: principalMl65 } });
if (pqGrant.alg !== 'ml-dsa-65' || typeof pqGrant.pq_pk !== 'string') throw new Error('the PQ grant is not an ml-dsa-65 grant');
const wrongSuitePk = b64u(otherMl87.publicKey);

const node = (): PlanNode => ({ id: 'n1', verb: OP.verb, resource: OP.resource, params_digest: paramsDigest(OP.params), reversibility_class: 'reversible' });
let counter = 0;
const signFor = (g: Capability) => buildPCActn({ grant: g, chain: [g], plan: [node()], nodeId: 'n1', params: OP.params, counter: ++counter, signerSecret: agent.secretKey, aud: AUD, now: NOW });

interface Expect { allow: boolean; decision: string; status: number; failed_includes: string[]; checks: Record<string, string>; reason?: string }
interface Case { name: string; description: string; grant: Capability; pcactn: unknown; pq_pins: Record<string, string> | null; expect: Expect }
const cases: Case[] = [];
const NOPIN = (alg: string) => `pq_pin: no server-side PQ pin for the grant issuer (suite ${alg})`;
const WRONG = 'pq_pin: the grant pq_pk does not match the server-side pin';
const CLASSICAL = 'pq_pin: the grant issuer is pinned to a post-quantum key; a classical grant is refused';
const add = (name: string, description: string, grant: Capability, pins: Record<string, string> | null, expect: Expect) => cases.push({ name, description, grant, pcactn: signFor(grant), pq_pins: pins, expect });
const ALLOW = (pq: 'pass' | 'absent'): Expect => ({ allow: true, decision: 'allow', status: 200, failed_includes: [], checks: { pq_pin: pq } });
const DENY = (reason: string): Expect => ({ allow: false, decision: 'deny', status: 401, failed_includes: ['pq_pin'], checks: { pq_pin: 'fail' }, reason });

add('pq-grant-pinned', 'A pure ml-dsa-65 grant whose issuer is pinned to the grant pq_pk: allowed, pq_pin passes.', pqGrant, { [pqGrant.issuer]: pqGrant.pq_pk as string }, ALLOW('pass'));
add('pq-grant-no-pin-for-the-issuer', 'The same grant with pins that name only another issuer: denied, naming the suite.', pqGrant, { other: pqGrant.pq_pk as string }, DENY(NOPIN('ml-dsa-65')));
add('pq-grant-empty-pins', 'The same grant with an empty pin map: denied (an empty map is still a configured pin set).', pqGrant, {}, DENY(NOPIN('ml-dsa-65')));
add('pq-grant-pin-of-another-suite', 'The issuer is pinned to an ML-DSA-87 key: not the grant pq_pk, denied.', pqGrant, { [pqGrant.issuer]: wrongSuitePk }, DENY(WRONG));
add('pq-grant-pin-is-a-prefix', 'The pin is only the first 20 characters of the grant pq_pk: byte-equality, denied.', pqGrant, { [pqGrant.issuer]: (pqGrant.pq_pk as string).slice(0, 20) }, DENY(WRONG));
add('pq-grant-pins-omitted', 'pq_pins not configured at all: the check is not reported and the stored grant is the root (allowed).', pqGrant, null, ALLOW('absent'));
add('classical-grant-from-a-pinned-issuer-is-refused', 'DOWNGRADE: an Ed25519 grant naming an issuer that has a PQ pin is refused (otherwise anyone holding the issuer Ed25519 key would mint a grant the pin never sees). The principal here holds both keys: the pin is keyed by the Ed25519 issuer identity, which a classical grant carries.', classical, { [pqGrant.issuer]: pqGrant.pq_pk as string }, DENY(CLASSICAL));
add('classical-grant-from-an-unpinned-issuer-passes', 'An Ed25519 grant whose issuer has no pin (the pins name another issuer) is allowed: no PQ key to pin.', classical, { other: wrongSuitePk }, ALLOW('pass'));
add('classical-grant-empty-pins', 'An Ed25519 grant with an empty pin map (no issuer is pinned): allowed.', classical, {}, ALLOW('pass'));

const run = async (c: Case) => {
  const az = createAuthorizer({
    audience: AUD, resolveGrant: async (r) => (r === c.grant.id ? c.grant : null), budgetStore: memoryPcaStore(), hooks: { revocation: () => ({ enforced: true, ok: true }) }, now: () => NOW,
    plan: 'single-step', risk: () => ({ blastRadius: 0, semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 }),
    ...(c.pq_pins !== null ? { pqPins: c.pq_pins } : {}),
  });
  return az({ operation: OP as never, pcactn: c.pcactn as never });
};
const text = async () => {
  for (const c of cases) {
    const r = await run(c);
    const failed = Object.entries(r.verdict.checks).filter(([, v]) => v === 'fail').map(([k]) => k).sort();
    const pq = c.pq_pins === null ? 'absent' : (r.verdict.checks as Record<string, string>)['pq_pin'];
    const got = { allow: r.allow, decision: r.decision, status: r.status, failed: c.expect.failed_includes.every((f) => failed.includes(f)) && (c.expect.allow ? failed.length === 0 : true), pq };
    const want = { allow: c.expect.allow, decision: c.expect.decision, status: c.expect.status, failed: true, pq: c.expect.checks['pq_pin'] };
    if (JSON.stringify(got) !== JSON.stringify(want)) throw new Error(`drift ${c.name}: ${JSON.stringify(got)} != ${JSON.stringify(want)} (${r.allow ? '' : r.reason})`);
    if (c.expect.reason !== undefined && !(!r.allow && r.reason.includes(c.expect.reason))) throw new Error(`drift ${c.name}: reason ${r.allow ? 'allowed' : r.reason}`);
  }
  const out = {
    format: 'pca-authorize-pq-pin-fixtures/1',
    description: 'Server-side PQ pins through authorize(): each case stores one grant (the resolver answers it by id), presents a signed PCActn and states the exact outcome. `pq_pins: null` means the option is not configured. Run with plan "single-step", the audience below, the clock below, a revocation hook that is enforced and ok, a zero risk, and a fresh replay store per case. The grant carries the signed provenance opt-out, so no provenance bundle is needed. Compared: allow, decision, status, that every check in `failed_includes` is among the failing checks (a wrong PQ pin also fails the own policy check of the chain in TypeScript, so the set is a lower bound; an allow has none), the pq_pin check status (`pass`, `fail`, or `absent` when it is not reported) and, on a denial, that the reason contains `expect.reason`. A native that cannot verify an ml-dsa-65 root hop must answer `unsupported_suite` rather than allow.',
    now: NOW, audience: AUD, operation: OP, principal: pPub, cases,
  };
  return `${JSON.stringify(out, null, 2)}\n`;
};
const file = join(__dirname, '..', 'conformance', 'authorize-pq-pin-fixtures.json');
text().then((t) => {
  if (process.argv.includes('--check')) {
    if (readFileSync(file, 'utf8') !== t) { console.error('authorize-pq-pin-fixtures.json is stale'); process.exit(1); }
  } else { writeFileSync(file, t); console.log(`wrote ${file}`); }
}).catch((e) => { console.error(e); process.exit(1); });

/**
 * Caveat language: third-party caveats (discharges), seal, a narrow block, max_uses and derive.
 * Every outcome below is printed; the script exits non-zero if any differs from the guide.
 */
import {
  InMemoryReplayStore,
  attenuate,
  b64u,
  boundCaveats,
  capHash,
  encodeKey,
  evaluateAgentCaveats,
  evaluateK1,
  generateKeyPair,
  mintRoot,
  reserveMaxUses,
  signDischarge,
  signNarrow,
  verifyChain,
  type Capability,
  type Caveat,
  type DischargePin,
} from '@atlasauth/pca';
import { expectEq, run } from './check.js';

const NOW = 1_800_000_000_000;
const key = () => {
  const k = generateKeyPair();
  return { sk: k.secretKey, pub: encodeKey(k.publicKey) };
};
const principal = key();
const agent = key();
const approver = key(); // the third party: it signs discharges, and the verifier pins its public key
const stranger = key();
const nonce = (n: number) => b64u(new Uint8Array(16).fill(n));
const root = (caveats: Caveat[]): Capability => mintRoot({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, caveats });

run(async () => {
  // 1. A third-party caveat: valid only with a discharge signed by a key the VERIFIER pinned.
  const pin: DischargePin = { label: 'risk-team', class: 'human', pk: approver.pub };
  const needsApproval: Caveat = {
    type: 'needs_discharge', id: 'kyc', issuer: 'risk-team', issuer_class: 'human', bind: 'chain_hop', ttl_ms: 600_000,
    require: [{ claim: 'risk_score', op: 'lte', value: 30 }],
  };
  const g = root([needsApproval]);
  const discharge = (claims: Record<string, number>, sk = approver.sk) =>
    signDischarge({ v: 1, kind: 'pca-discharge', caveat_id: 'kyc', issuer: 'risk-team', cap_hash: capHash(g), bind: 'chain_hop', claims, iat: NOW - 1000, not_after: NOW + 1000, nonce: nonce(5) } as never, sk);
  const eval1 = (discharges: unknown[]) => evaluateK1(g, [g], { pins: [pin], discharges }, { now: NOW });
  expectEq('no discharge: refused', eval1([]).failed, ['needs_discharge']);
  expectEq('discharge with an acceptable claim: allowed', eval1([discharge({ risk_score: 20 })]).ok, true);
  expectEq('discharge whose claim fails the requirement: refused', eval1([discharge({ risk_score: 80 })]).failed, ['needs_discharge']);
  expectEq('discharge signed by a key nobody pinned: refused', eval1([discharge({ risk_score: 20 }, stranger.sk)]).failed, ['needs_discharge']);

  // 2. Seal: nobody may add a hop below the hop that carries it.
  const sealed = root([{ type: 'sealed' }]);
  const below = attenuate(sealed, [], agent.sk);
  expectEq('a hop appended below a seal is structurally valid', verifyChain([sealed, below], principal.pub).ok, true);
  expectEq('...but the seal is never satisfied', evaluateK1(sealed, [sealed, below], {}, { now: NOW }).failed, ['sealed']);
  expectEq('the sealed hop itself still works', evaluateK1(sealed, [sealed], {}, { now: NOW }).ok, true);

  // 3. A narrow block: the holder tightens its own authority for a few minutes, with no new hop.
  const open = root([]);
  const narrowBody = (caveats: Caveat[]) => ({ v: 1 as const, kind: 'pca-narrow' as const, cap_hash: capHash(open), holder: agent.pub, caveats, iat: NOW - 1, not_after: NOW + 60_000, nonce: nonce(3) });
  const narrow = signNarrow(narrowBody([{ type: 'expires', at: NOW + 60_000 }]), agent.sk);
  const withNarrow = evaluateK1(open, [open], { narrow }, { now: NOW });
  expectEq('a narrow block by the leaf holder is accepted and adds its caveat', [withNarrow.ok, withNarrow.plain], [true, [{ type: 'expires', at: NOW + 60_000 }]]);
  expectEq('the added caveat holds before its time', evaluateAgentCaveats(withNarrow.plain, { now: NOW }, { action: { verb: 'x', resource: 'y' } }).ok, true);
  expectEq('and refuses after it', evaluateAgentCaveats(withNarrow.plain, { now: NOW + 120_000 }, { action: { verb: 'x', resource: 'y' } }).ok, false);
  const forged = signNarrow(narrowBody([{ type: 'expires', at: NOW + 1 }]), stranger.sk);
  expectEq('a narrow block signed by anyone but the leaf holder: refused', evaluateK1(open, [open], { narrow: forged }, { now: NOW }).failed, ['narrow']);

  // 4. max_uses: exactly n uses, counted in the verifier's replay store.
  const limited = root([{ type: 'max_uses', id: 'refunds', n: 2, until: NOW + 10_000 }]);
  const store = new InMemoryReplayStore();
  const bound = boundCaveats(limited, [limited]) ?? [];
  const uses: boolean[] = [];
  for (let i = 0; i < 3; i++) uses.push((await reserveMaxUses(store, bound, NOW)).ok);
  expectEq('three attempts at n=2: allow, allow, refuse', uses, [true, true, false]);

  // 5. derive: a bounded check over the action, the verifier's own history and verified discharge claims.
  const guard: Caveat = {
    type: 'derive', id: 'refund-guard',
    defs: [
      { name: 'amount', kind: 'param', path: 'amount' },
      { name: 'recent', kind: 'count', window_ms: 3_600_000, verb: 'refund.issue' },
    ],
    check: { op: 'and', args: [{ op: 'lte', a: { ref: 'amount' }, b: { const: 100 } }, { op: 'lt', a: { ref: 'recent' }, b: { const: 3 } }] },
  };
  const d = root([guard]);
  const act = (params: Record<string, number>) => ({ verb: 'refund.issue', resource: 'orders/1', params });
  const past = (n: number) => Array.from({ length: n }, (_, i) => ({ t: NOW - 1000 * (i + 1), verb: 'refund.issue', resource: 'orders/1' }));
  const dv = (params: Record<string, number>, history = past(0)) => evaluateK1(d, [d], { history }, { now: NOW, action: act(params) }).ok;
  expectEq('derive: small refund, no recent refunds', dv({ amount: 50 }), true);
  expectEq('derive: amount over the limit', dv({ amount: 500 }), false);
  expectEq('derive: three refunds in the last hour', dv({ amount: 50 }, past(3)), false);
  expectEq('derive: a missing fact is unknown, and unknown refuses', dv({}), false);

  // A verifier never configured for the caveat language refuses every one of these caveats.
  expectEq('no caveat-language input at all: refused', evaluateK1(sealed, [sealed], undefined, { now: NOW }).ok, false);
});

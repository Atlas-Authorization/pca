import { describe, expect, it } from 'vitest';
import {
  TransparencyLedger,
  encodeKey,
  generateKeyPair,
  pcactnDigest,
  verifyClaim,
  verifyLedgerInclusion,
  verifyPCActnCore,
} from '@atlasauth/pca';
import { buildPaymentMandate, type PaymentMandateParams } from './mandate';
import { chargeToPCActn, openChargeBond } from './charge-action';

const principal = generateKeyPair();
const agent = generateKeyPair();
const pub = (k: { publicKey: Uint8Array }) => encodeKey(k.publicKey);
const NOW = 1_700_000_000_000;
const AUD = 'ins_pca_payments_test';

const params: PaymentMandateParams = {
  principalSecret: principal.secretKey,
  principalPublic: pub(principal),
  agentPublic: pub(agent),
  merchants: ['openai'],
  currency: 'USD',
  perTransactionCap: 500,
  autoApproveThreshold: 200,
  cumulativeCap: 1000,
  now: NOW,
};

describe('chargeToPCActn → proof-carrying action', () => {
  it('builds a PCActn for a charge that passes the M0 core verifier', async () => {
    const m = buildPaymentMandate(params);
    const { pcactn, node } = chargeToPCActn(m, { merchant: 'openai', amount: 120, currency: 'USD' }, {
      signerSecret: agent.secretKey,
      aud: AUD,
      counter: 1,
      now: NOW,
    });
    expect(node.resource).toBe('merchant:openai');
    expect(pcactn.action.resource).toBe('merchant:openai');
    expect(pcactn.action.verb).toBe('charge');
    expect(pcactn.risk_claim.r).toBeCloseTo(120 / 500);

    const res = await verifyPCActnCore(pcactn, { grant: m.grant, audience: AUD, nowEpoch: NOW + 1000 });
    expect(res.allow).toBe(true);
    expect(res.checks.cap_chain).toBe('pass');
    expect(res.checks.plan_inclusion).toBe('pass');
    expect(res.checks.leaf_signature).toBe('pass');
    expect(res.checks.audience).toBe('pass');
  });

  it('anchors each charge as a verifiable entry in the transparency ledger', () => {
    const m = buildPaymentMandate(params);
    const ledger = new TransparencyLedger(m.grant.id);
    const charges = [
      { merchant: 'openai', amount: 10, currency: 'USD' },
      { merchant: 'openai', amount: 20, currency: 'USD' },
    ];
    const commits: string[] = [];
    charges.forEach((c, i) => {
      const { pcactn } = chargeToPCActn(m, c, { signerSecret: agent.secretKey, aud: AUD, counter: i + 1, now: NOW });
      commits.push(ledger.append(pcactn).commit);
    });
    const head = ledger.head();
    expect(head.size).toBe(2);
    // Each charge has an independently-verifiable inclusion proof against the published head.
    commits.forEach((commit, i) => {
      expect(verifyLedgerInclusion(head.root, ledger.inclusionProof(i), commit)).toBe(true);
    });
  });

  it('opens an optimistic bond (dispute/refund window) for a reversible charge', () => {
    const m = buildPaymentMandate(params);
    const { pcactn } = chargeToPCActn(m, { merchant: 'openai', amount: 120, currency: 'USD' }, {
      signerSecret: agent.secretKey,
      aud: AUD,
      counter: 1,
      now: NOW,
    });
    const claim = openChargeBond(
      pcactn,
      { bondRef: 'bond_charge_1', claimedR: pcactn.risk_claim.r, challengeWindowMs: 5 * 60_000, serverNow: NOW },
      agent.secretKey,
    );
    expect(claim.pcactn_digest).toBe(pcactnDigest(pcactn));
    expect(verifyClaim(claim, pcactn, pub(agent), { serverNow: NOW }).ok).toBe(true);
  });
});

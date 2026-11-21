import { describe, expect, it } from 'vitest';
import { type AgentPassport, issuePassport } from '@atlasauth/pca/ext/attestation';
import { generateKeyPair } from 'jose';
import { issueAgentFacts, verifyAgentFacts } from './index';

const NOW = 1_800_000_000_000;
const passport: AgentPassport = issuePassport({
  model_id: 'm',
  weights_digest: 'wd',
  system_prompt_digest: 'sp',
  tool_manifest_digest: 'tm',
  operator: 'op',
  hardware_rooted: true,
  weights_measured: true,
  issued_at: NOW,
});

describe('a non-finite verification clock never admits an attestation', () => {
  // pre-fix: `now < from` and `now > until` were both false for NaN, so the window read as open
  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('now of %s', async (now) => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { extractable: true });
    const f = await issueAgentFacts(passport, {
      attestorKey: privateKey,
      attests: {},
      validFrom: new Date(NOW).toISOString(),
      validUntil: new Date(NOW + 1000).toISOString(),
    });
    expect((await verifyAgentFacts(f, { key: publicKey, now })).ok).toBe(false);
  });
});

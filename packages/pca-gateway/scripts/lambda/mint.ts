/**
 * Test-only: mints PCA proofs for the real-runtime Lambda test and writes grants.json (public grants,
 * no private keys) plus proofs.json (PCA-Action header values). Private keys are never written.
 *   node mint.mjs <outDir>
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { agent, generateKeyPair, pcaHeaders, PCA_HEADER, decodePCActn, decodePcaHeader, type Capability } from '@atlasauth/pca';

const AUD = process.env.PCA_AUDIENCE ?? 'ins_acme';
const out = process.argv[2] ?? '.';
mkdirSync(out, { recursive: true });
const grants: Record<string, Capability> = {};
const proofs: Record<string, string> = {};

function mint(name: string, o?: { aud?: string; verb?: string; tamper?: boolean }): void {
  const a = agent({
    principal: generateKeyPair(),
    goal: 'refunds',
    permissions: { stripe: ['refund'] },
    limits: { refund: '$500/day' },
    aud: AUD,
  });
  const { encoded, pcactn } = a.act(
    o?.verb ?? 'stripe.refund',
    'charge:ch_1',
    { amount: 20, currency: 'usd' },
    { counter: 1, ...(o?.aud !== undefined ? { aud: o.aud } : {}) },
  );
  grants[pcactn.grant_ref] = a.grant as Capability;
  let value = pcaHeaders(encoded)[PCA_HEADER] as string;
  if (o?.tamper === true) {
    const t = decodePCActn(decodePcaHeader(value)) as unknown as { action: { resource: string } };
    t.action.resource = 'charge:ch_EVIL';
    value = Buffer.from(JSON.stringify(t)).toString('base64url');
  }
  proofs[name] = value;
}

mint('valid');
mint('valid2');
mint('valid3');
mint('valid4');
mint('replay');
mint('payout-verb', { verb: 'stripe.payout' });
mint('wrong-aud', { aud: 'ins_other' });
mint('tampered', { tamper: true });
writeFileSync(join(out, 'grants.json'), JSON.stringify(grants));
writeFileSync(join(out, 'proofs.json'), JSON.stringify({ mintedAtMs: Date.now(), proofs }));
console.log(`minted ${Object.keys(proofs).length} proofs`);

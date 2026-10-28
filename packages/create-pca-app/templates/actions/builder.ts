// The same action as actions/acme.yaml, written with the TypeScript builder. Both forms expand to one definition,
// so they have one digest: `npm run digest` prints both and exits nonzero if they differ.
import { readFileSync } from 'node:fs';
import { action, defDigest, loadActionsText, p } from '@atlasauth/pca-actions';

const sendInvoice = action('acme.invoice.send', {
  title: 'Send an invoice',
  description: 'Emails an existing invoice to the customer.',
  effects: ['send'],
  resource: 'acme.invoice:inv_*',
  params: { invoice: p.id('acme.invoice'), to: p.email(), note: p.message(500) },
  since: '0.1.0',
});

const fromYaml = loadActionsText(readFileSync('actions/acme.yaml', 'utf8'));
if (fromYaml.errors.length > 0 || fromYaml.defs[0] === undefined) throw new Error(fromYaml.errors[0]?.message ?? 'no actions');

const a = defDigest(sendInvoice);
const b = defDigest(fromYaml.defs[0]);
console.log(`builder ${a}\nyaml    ${b}\n${a === b ? 'same digest' : 'DIFFERENT'}`);
if (a !== b) process.exitCode = 1;

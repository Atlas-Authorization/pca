// emit-rules.ts - write / check / sign the published suggestion rule set (rules/suggest-rules.json).
//   emit-rules.ts            write the sealed (digest, unsigned) rule set
//   emit-rules.ts --check    fail unless the committed file is exactly the sealed rule set (or, if it carries a signature, that
//                            signature is over this digest: verified against PCA_RULES_PUBKEY=<kid>:<b64u pk>)
//   emit-rules.ts --sign     sign at release time with the key supplied in the environment: PCA_RULES_SIGNING_KEY (base64url
//                            32-byte Ed25519 secret) and PCA_RULES_KID. The key is never read from a file, printed or stored by
//                            this script; which key that is (the registry's rules-publisher key) is the owner's decision.
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { unb64u } from '@atlasauth/pca';
import { DEFAULT_RULES, sealRules, signRules, verifyRules, type SignedSuggestRules } from '../src';

const file = join(__dirname, '..', 'rules', 'suggest-rules.json');
const text = (r: SignedSuggestRules): string => JSON.stringify(r, null, 2) + '\n';
const argv = process.argv.slice(2);

if (argv.includes('--sign')) {
  const sk = process.env.PCA_RULES_SIGNING_KEY, kid = process.env.PCA_RULES_KID;
  if (!sk || !kid) { console.error('--sign needs PCA_RULES_SIGNING_KEY and PCA_RULES_KID in the environment (supplied at release time)'); process.exit(2); }
  let secret: Uint8Array;
  try { secret = unb64u(sk); if (secret.length !== 32) throw new Error(); } catch { console.error('PCA_RULES_SIGNING_KEY must be a base64url 32-byte Ed25519 secret'); process.exit(2); }
  writeFileSync(file, text(signRules(DEFAULT_RULES, kid, secret!)));
  console.log(`signed rule set written for key ${kid}`);
} else if (argv.includes('--check')) {
  const cur = JSON.parse(readFileSync(file, 'utf8')) as SignedSuggestRules;
  const sealed = sealRules(DEFAULT_RULES);
  if (cur.digest !== sealed.digest || JSON.stringify({ ...cur, sig: undefined }) !== JSON.stringify({ ...sealed, sig: undefined })) { console.error('rules/suggest-rules.json does not match the rules in source; run scripts/emit-rules.ts'); process.exit(1); }
  if (cur.sig) {
    const pin = process.env.PCA_RULES_PUBKEY?.split(':');
    if (!pin || pin.length !== 2) { console.error('the committed rule set is signed: set PCA_RULES_PUBKEY=<kid>:<b64u public key> to verify it'); process.exit(1); }
    const v = verifyRules(cur, [{ kid: pin[0]!, pk: pin[1]! }]);
    if (!v.ok) { console.error('signature check failed: ' + v.reason); process.exit(1); }
    console.log('rule set is current and its signature verifies');
  } else console.log('rule set is current (unsigned: signed at release time)');
} else {
  writeFileSync(file, text(sealRules(DEFAULT_RULES)));
  console.log('sealed rule set written');
}

// e2e helper: re-asks the running container is not needed: verifies the cosignature file written by e2e.sh against the policy.
const path = require('node:path');
const fs = require('node:fs');
const dist = process.env.PCA_DIST || path.join(__dirname, '..', '..', 'packages', 'pca', 'dist');
const led = require(path.join(dist, 'ext', 'ledger.js'));
const dir = process.argv[2];
const rd = (f) => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
const guardian = fs.readFileSync(path.join(dir, 'guardian.pub'), 'utf8').trim();
const witness = fs.readFileSync(path.join(dir, 'witness.pub'), 'utf8').trim();
for (const [head, res] of [['head-8.json', 'r1.json'], ['head-12.json', 'r2.json']]) {
  const sth = rd(head).sth;
  const r = rd(res);
  if (r.witness !== witness) { console.error('witness key mismatch'); process.exit(1); }
  if (!led.verifyTreeHead({ ...sth, witnesses: [r.cosignature] }, guardian, { witnessKeys: [witness], threshold: 1 })) { console.error(`cosignature for ${head} does not verify`); process.exit(1); }
}

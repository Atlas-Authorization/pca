// e2e helper: writes logs.json and the head requests used by e2e.sh, using the bundled-source PCA library via tsx-free JS (CommonJS dist).
// usage: node e2e-fixture.js <dir>     (requires a built @atlasauth/pca on the module path: PCA_DIST, default ../../packages/pca/dist)
const path = require('node:path');
const fs = require('node:fs');
const dist = process.env.PCA_DIST || path.join(__dirname, '..', '..', 'packages', 'pca', 'dist');
const core = require(path.join(dist, 'index.js'));
const led = require(path.join(dist, 'ext', 'ledger.js'));
const dir = process.argv[2];
const g = core.generateKeyPair();
const log = new led.TransparencyLedger('grant-1');
const leaf = (i) => core.b64u(Buffer.from(`leaf-${i}-padding-padding-padding`)).slice(0, 43);
for (let i = 0; i < 12; i++) log.appendCommitment(leaf(i));
const head = (size, root) => led.signTreeHead(g.secretKey, { instance_id: 'inst-1', principal: 'grant-1', size, root: root ?? log.rootAt(size), prev_root: size > 0 ? log.rootAt(size - 1) : '', timestamp: 1800000000000 + size });
const w = (f, v) => fs.writeFileSync(path.join(dir, f), JSON.stringify(v));
w('logs.json', [{ instance_id: 'inst-1', principal: 'grant-1', guardian_public: core.encodeKey(g.publicKey) }]);
w('head-8.json', { sth: head(8) });
w('head-5.json', { sth: head(5) });
const fork = new led.TransparencyLedger('grant-1');
for (let i = 0; i < 7; i++) fork.appendCommitment(leaf(i));
fork.appendCommitment(leaf(777));
w('head-8-fork.json', { sth: head(8, fork.head().root) });
w('head-12.json', { sth: head(12), proof: log.consistencyProof(8, 12) });
fs.writeFileSync(path.join(dir, 'guardian.pub'), core.encodeKey(g.publicKey));

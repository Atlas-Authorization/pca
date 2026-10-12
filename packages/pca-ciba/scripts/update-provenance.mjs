// Records the sha256 and capture metadata of fixtures/keycloak-ciba-transcripts.json in fixtures/PROVENANCE.json.
// Run by run-keycloak-ciba.sh after a PCA_CIBA_RECORD=1 test run.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
const file = 'keycloak-ciba-transcripts.json';
const raw = readFileSync(join(dir, file));
const t = JSON.parse(raw.toString('utf8'));
const prov = JSON.parse(readFileSync(join(dir, 'PROVENANCE.json'), 'utf8'));
prov.files = prov.files.filter((f) => f.file !== file);
prov.files.push({
  file,
  kind: 'real-provider-transcript',
  source: `Keycloak ${t.version} (official release distribution, start-dev, throwaway local realm), recorded by src/keycloak.integration.test.ts via scripts/run-keycloak-ciba.sh`,
  recordedAt: t.recordedAt,
  sha256: createHash('sha256').update(raw).digest('hex'),
  note: 'HTTP exchanges between the pca-ciba client, Keycloak and a mock authentication-channel device. Access/ID/refresh tokens, auth_req_id values, client_notification_token and credentials are redacted. Re-record with PCA_CIBA_RECORD=1.',
});
writeFileSync(join(dir, 'PROVENANCE.json'), `${JSON.stringify(prov, null, 2)}\n`);

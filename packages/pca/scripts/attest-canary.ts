// Run the vendor-attestation canary against a manifest (recorded or live). Exit 0 only when every case passes.
//   tsx scripts/attest-canary.ts fixtures/attest-canary/manifest.json
import { runCanary } from '../src/attest-canary.test-util';

const path = process.argv[2];
if (!path) {
  console.error('usage: tsx scripts/attest-canary.ts <manifest.json>');
  process.exit(2);
}
runCanary(path).then(
  ({ results, ok }) => {
    console.log(JSON.stringify({ ok, results }, null, 2));
    process.exit(ok ? 0 : 1);
  },
  (e: unknown) => {
    console.error(`canary error (fail closed): ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  },
);

// vitest globalSetup: make sure the compliance circuit fixtures exist (circuits/ensure-build.sh). Throws if it cannot.
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export default function setup() {
  execFileSync('bash', [fileURLToPath(new URL('../circuits/ensure-build.sh', import.meta.url))], { stdio: 'inherit' });
}

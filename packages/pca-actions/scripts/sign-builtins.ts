// sign-builtins.ts - RELEASE STEP. Signs the built-in defs with the release reviewer key and writes
// src/builtin-release.generated.ts (the pinned PUBLIC key and one attestation per built-in verb).
//   sign-builtins.ts --sign --kid <kid> [--ts <unix seconds>]
//        needs PCA_RELEASE_REVIEW_KEY in the environment (base64url 32-byte Ed25519 secret). The key is never read from a file,
//        printed or stored here; which key it is is the release owner's decision.
//   sign-builtins.ts --check
//        verifies the committed file: every attestation verifies under the pinned key. With PCA_REQUIRE_BUILTIN_RELEASE=1 it also
//        fails unless EVERY built-in is attested (set in the release pipeline; unset in ordinary CI before the first release).
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { b64u, publicKeyOf, unb64u } from '@atlasauth/pca';
import { BUILTIN_DEFS, CORE_REGISTRY, attestationVerifier, signBuiltins, traitsDigest, defDigest, type ActionDef } from '../src';
import { BUILTIN_RELEASE } from '../src/builtin-release.generated';

const file = join(__dirname, '..', 'src', 'builtin-release.generated.ts');
const argv = process.argv.slice(2);
const arg = (n: string): string | undefined => { const i = argv.indexOf(n); return i < 0 ? undefined : argv[i + 1]; };

if (argv.includes('--sign')) {
  const sk = process.env.PCA_RELEASE_REVIEW_KEY, kid = arg('--kid');
  if (!sk || !kid) { console.error('--sign needs PCA_RELEASE_REVIEW_KEY in the environment and --kid <kid>'); process.exit(2); }
  let secret: Uint8Array;
  try { secret = unb64u(sk); if (secret.length !== 32) throw new Error(); } catch { console.error('PCA_RELEASE_REVIEW_KEY must be a base64url 32-byte Ed25519 secret'); process.exit(2); }
  const ts = Number(arg('--ts') ?? Math.floor(Date.now() / 1000));
  const signed = signBuiltins({ kid, secret: secret!, ts });
  const att: Record<string, unknown> = {};
  for (const d of signed) att[d.verb] = d.review.attestation;
  const pins = { keys: [{ kid, pk: b64u(publicKeyOf(secret!)), roles: ['reviewer'] }] };
  writeFileSync(file, [
    '// GENERATED at release time by scripts/sign-builtins.ts - do not edit.',
    "import type { ReviewRef } from './def';",
    "import type { ReviewerPins } from './confirmation';",
    '',
    `export const BUILTIN_RELEASE: { pins: ReviewerPins | null; attestations: Readonly<Record<string, ReviewRef>> } = ${JSON.stringify({ pins, attestations: att }, null, 2)} as never;`,
    '',
  ].join('\n'));
  console.log(`signed ${signed.length} built-in defs for key ${kid}; traits digest ${traitsDigest(CORE_REGISTRY)}`);
} else {
  const pins = BUILTIN_RELEASE.pins;
  const missing = BUILTIN_DEFS.filter((d) => BUILTIN_RELEASE.attestations[d.verb] === undefined);
  if (pins === null) {
    if (process.env.PCA_REQUIRE_BUILTIN_RELEASE === '1') { console.error('no release attestation is committed (PCA_REQUIRE_BUILTIN_RELEASE=1)'); process.exit(1); }
    console.log('no release attestation committed: built-in defs are unconfirmed until the release signing step runs');
  } else {
    const ok = attestationVerifier({ pins, registry: CORE_REGISTRY });
    const bad = BUILTIN_DEFS.filter((d) => { const a = BUILTIN_RELEASE.attestations[d.verb]; return a !== undefined && !ok({ ...d, review: { state: 'confirmed', attestation: a } } as ActionDef); });
    if (bad.length > 0) { console.error(`attestation does not verify (stale def or registry) for: ${bad.map((d) => `${d.verb}@${defDigest(d)}`).join(', ')}`); process.exit(1); }
    if (missing.length > 0 && process.env.PCA_REQUIRE_BUILTIN_RELEASE === '1') { console.error(`built-ins without attestation: ${missing.map((d) => d.verb).join(', ')}`); process.exit(1); }
    console.log(`release attestations verify (${BUILTIN_DEFS.length - missing.length}/${BUILTIN_DEFS.length} built-ins attested)`);
  }
}

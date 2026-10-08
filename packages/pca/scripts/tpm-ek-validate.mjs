#!/usr/bin/env node
/**
 * tpm-ek-validate.mjs — END-TO-END validation of the TPM 2.0 Endorsement-Key-backed PUF root on REAL hardware.
 *
 * Run this on a machine WITH a TPM 2.0 vTPM — e.g. an Azure Confidential or Trusted Launch VM (/dev/tpmrm0) —
 * with `tpm2-tools` installed. It exercises `TpmEkPufProvider` end to end against the live EK:
 *
 *   1. ensures the device's RSA Endorsement Key is present at a persistent handle (creates + persists if not);
 *   2. ENROLLS from the real, device-unique EK (fuzzy extractor → stable key → PUF-derived signing identity);
 *   3. REPRODUCES the key from a fresh EK read and signs an attestation statement;
 *   4. VERIFIES that statement under the enrolled public key (the unclonable-root acceptance path);
 *   5. emits a JSON fixture to STDOUT — EK-public SHA-256 + the enrolled PUBLIC key + public helper data.
 *      NO private material is ever printed (the PUF-derived secret never leaves the derivation; the EK private
 *      key is non-exportable by construction).
 *
 * Human-readable progress goes to STDERR, so STDOUT is pure JSON and can be piped/saved as a fixture:
 *     node scripts/tpm-ek-validate.mjs > tpm-ek-fixture.json
 *
 * Prerequisites on the host:
 *   - tpm2-tools (tpm2_readpublic, tpm2_createek, tpm2_evictcontrol) on PATH, able to reach the TPM;
 *   - the package built (`npm run build` in packages/pca) so dist/ exists.
 *
 * Environment overrides (all optional):
 *   TPM_EK_HANDLE   persistent EK handle              (default 0x81010001, the TCG-standard RSA EK handle)
 *   PUF_REP         fuzzy-extractor repetition factor (default 7, odd)
 *   PUF_MSG_BITS    fuzzy-extractor message bits      (default 64)
 *   PUF_SUITE       derived key suite                 (default ml-dsa-65 | ml-dsa-87 | ed25519)
 *   PUF_PROVIDER_ID device/provider id               (default tpm-ek-<hostname>)
 *   PUF_CHALLENGE   hex challenge                     (default a fixed 4-byte label)
 */
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes as nodeRandomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { hostname } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { existsSync } from 'node:fs';

const require = createRequire(import.meta.url);
const HERE = dirname(fileURLToPath(import.meta.url));

const log = (...a) => process.stderr.write(a.join(' ') + '\n');
const die = (msg) => {
  log('FAIL:', msg);
  process.exit(1);
};

// ── load the built package ───────────────────────────────────────────────────────────────────────
const DIST = resolve(HERE, '..', 'dist', 'attest-puf.js');
if (!existsSync(DIST)) {
  die(`built module not found at ${DIST}\n  Build the package first:  (cd ${resolve(HERE, '..')} && npm run build)`);
}
const mod = require(DIST);
const { TpmEkPufProvider, enrollPuf, createPufAttestor, createPufVerifier, createPufEnrollmentRegistry } = mod;
for (const [name, fn] of Object.entries({ TpmEkPufProvider, enrollPuf, createPufAttestor, createPufVerifier, createPufEnrollmentRegistry })) {
  if (typeof fn !== 'function') die(`dist export '${name}' missing — rebuild the package`);
}

// ── config ───────────────────────────────────────────────────────────────────────────────────────
const EK_HANDLE = process.env.TPM_EK_HANDLE || '0x81010001';
const REP = Number(process.env.PUF_REP || 7);
const MSG_BITS = Number(process.env.PUF_MSG_BITS || 64);
const SUITE = process.env.PUF_SUITE || 'ml-dsa-65';
const PROVIDER_ID = process.env.PUF_PROVIDER_ID || `tpm-ek-${hostname()}`;
const CHALLENGE = process.env.PUF_CHALLENGE ? Buffer.from(process.env.PUF_CHALLENGE, 'hex') : Buffer.from('atlas-pca-ek', 'utf8');
const N = REP * MSG_BITS;
if (!Number.isInteger(REP) || REP < 1 || REP % 2 === 0) die('PUF_REP must be an odd positive integer');
if (!Number.isInteger(MSG_BITS) || MSG_BITS < 1) die('PUF_MSG_BITS must be a positive integer');

// ── tpm2-tools helpers ─────────────────────────────────────────────────────────────────────────
function tpm(args, { allowFail = false } = {}) {
  try {
    const out = execFileSync('tpm2', args, { stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 20 });
    return { ok: true, stdout: out };
  } catch (e) {
    // tpm2-tools can be invoked either as `tpm2 <cmd>` or `tpm2_<cmd>`; fall back to the latter.
    if (e && (e.code === 'ENOENT' || e.code === 'EACCES')) {
      try {
        const out = execFileSync(`tpm2_${args[0]}`, args.slice(1), { stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 20 });
        return { ok: true, stdout: out };
      } catch (e2) {
        if (allowFail) return { ok: false, err: e2 };
        die(`tpm2-tools not found or not runnable (${e2.code || e2.message}). Install tpm2-tools and ensure TPM access.`);
      }
    }
    if (allowFail) return { ok: false, err: e };
    const stderr = e && e.stderr ? e.stderr.toString() : e && e.message ? e.message : 'unknown error';
    die(`tpm2 ${args.join(' ')} failed: ${stderr.trim()}`);
  }
}

// ── 0. preflight: verify tpm2-tools + a reachable TPM, ensure the EK is persisted ─────────────────
log('== TPM EK PUF validation ==');
log(`host=${hostname()} ek_handle=${EK_HANDLE} rep=${REP} msg_bits=${MSG_BITS} n=${N} suite=${SUITE}`);

tpm(['getcap', 'properties-fixed']); // proves tpm2-tools works and a TPM responds
log('tpm2-tools OK; TPM responds');

// Is the RSA EK already at the persistent handle?
let haveEk = tpm(['readpublic', '-c', EK_HANDLE, '-Q'], { allowFail: true }).ok;
if (!haveEk) {
  log(`EK not present at ${EK_HANDLE}; creating + persisting the RSA Endorsement Key…`);
  const ekCtx = resolve(process.env.TMPDIR || '/tmp', `atlas-ek-${process.pid}.ctx`);
  tpm(['createek', '-G', 'rsa', '-c', ekCtx, '-Q']);
  const ev = tpm(['evictcontrol', '-C', 'o', '-c', ekCtx, EK_HANDLE, '-Q'], { allowFail: true });
  if (!ev.ok) log(`note: evictcontrol reported an error (EK may already be persisted elsewhere); continuing`);
  haveEk = tpm(['readpublic', '-c', EK_HANDLE, '-Q'], { allowFail: true }).ok;
  if (!haveEk) die(`could not read the EK public at ${EK_HANDLE} after create/persist`);
}
log(`EK present at ${EK_HANDLE}`);

// ── 1. build the provider over the REAL EK (default runner shells to tpm2_readpublic) ─────────────
const provider = new TpmEkPufProvider({ id: PROVIDER_ID, length: N, ekHandle: EK_HANDLE });
const ekPublic = provider.readEkPublic(); // PUBLIC EK area bytes
const ekHash = createHash('sha256').update(ekPublic).digest('hex');
log(`EK public read: ${ekPublic.length} bytes, sha256=${ekHash}`);

// ── 2. enroll from the real EK ────────────────────────────────────────────────────────────────────
const enrollment = enrollPuf(provider, new Uint8Array(CHALLENGE), {
  rep: REP,
  messageBits: MSG_BITS,
  alg: SUITE,
  randomBytes: (n) => new Uint8Array(nodeRandomBytes(n)),
});
log(`enrolled: alg=${enrollment.alg} publicKey.len=${enrollment.publicKey.length} helper.n=${enrollment.helper.n}`);

// ── 3. reproduce + sign a statement (fresh EK read → fuzzy reproduce → derived signer) ────────────
const EXPECTED = {
  holderPub: Buffer.from(nodeRandomBytes(32)).toString('base64url'),
  grantRef: 'tpm-ek-validate',
  epoch: 1,
  nonce: Buffer.from(nodeRandomBytes(12)).toString('base64url'),
  nonceIssuedAt: Date.now() - 1000,
};
const MEASUREMENT = 'tpm-ek-validate-measurement';
const statement = createPufAttestor(new TpmEkPufProvider({ id: PROVIDER_ID, length: N, ekHandle: EK_HANDLE }), enrollment).attest({
  measurement: MEASUREMENT,
  holder_pub: EXPECTED.holderPub,
  grant_ref: EXPECTED.grantRef,
  epoch: EXPECTED.epoch,
  nonce: EXPECTED.nonce,
});
log('reproduced key and signed an attestation statement from a fresh EK read');

// ── 4. verify under the enrolled public key ───────────────────────────────────────────────────────
const registry = createPufEnrollmentRegistry([enrollment]);
const verifier = createPufVerifier({
  resolveEnrollment: (id) => registry.lookup(id),
  policy: { measurements: [MEASUREMENT] },
  resolveEvidence: () => statement,
});
const result = await verifier.verify({ document: {}, ctx: {}, nowMs: Date.now(), expected: EXPECTED });
if (!result || result.ok !== true) die(`verification did NOT pass: ${result && result.reason ? result.reason : 'unknown'}`);
log('VERIFIED ✓ — the reproduced PUF statement verifies under the enrolled EK-rooted public key');

// ── 5. emit the fixture (no private material) ─────────────────────────────────────────────────────
const fixture = {
  kind: 'atlas-pca/tpm-ek-puf-validation/v1',
  generated_at: new Date().toISOString(),
  host: hostname(),
  ek_handle: EK_HANDLE,
  ek_public_sha256: ekHash,
  ek_public_bytes: ekPublic.length,
  provider_id: PROVIDER_ID,
  challenge_hex: Buffer.from(CHALLENGE).toString('hex'),
  fuzzy: { rep: REP, message_bits: MSG_BITS, n: N },
  enrolled: {
    alg: enrollment.alg,
    public_key_b64u: enrollment.publicKey, // PUBLIC key — the unclonable EK-rooted identity
    helper: enrollment.helper, // PUBLIC helper data (reveals only the code redundancy)
    helper_commitment: enrollment.helperCommitment,
  },
  verify_ok: true,
};
process.stdout.write(JSON.stringify(fixture, null, 2) + '\n');
log('fixture written to stdout');

/**
 * Reference runner for a SINGLE network FROST guardian signer, in its OWN OS process.
 * ====================================================================================
 *
 * This is the piece that makes the "separate trust domain" guarantee real at the PROCESS level: each
 * invocation starts ONE {@link GuardianSignerService} holding EXACTLY ONE FROST share and exposes it over
 * loopback HTTP. Run n of these (one per guardian) and a quorum of them is driven by a {@link NetworkCoordinator}
 * in a different process — no single process ever holds more than one share.
 *
 * Config is read from a JSON file (argv[2], or $FROST_SIGNER_CONFIG) so the secret share never appears in a
 * command line / process table. Shape ({@link SignerRunnerConfig}):
 *   { identifier, share, groupPublicKey, threshold, policyAuthorityPublicKey, port? }   // bytes base64url
 *
 * On listen it prints EXACTLY one JSON line to stdout, prefixed `FROST_SIGNER_READY `, so a parent can parse
 * the actual URL (the port is ephemeral unless pinned). It runs until SIGTERM/SIGINT.
 *
 * Usage:  tsx frost-net-runner.ts <config.json>
 */
import { readFileSync } from 'node:fs';
import { decodeB64uStrict } from './hash';
import { GuardianSignerService, startSignerHttpServer, type SignerHttpServer } from './frost-net';

export interface SignerRunnerConfig {
  identifier: number;
  /** base64url 32-byte secret FROST share. */
  share: string;
  /** base64url 32-byte group public key. */
  groupPublicKey: string;
  threshold: number;
  /** base64url 32-byte policy-authority Ed25519 public key. */
  policyAuthorityPublicKey: string;
  /** Pin a port (default: ephemeral). */
  port?: number;
  host?: string;
}

const READY_PREFIX = 'FROST_SIGNER_READY ';

function requireBytes(b64: string, len: number, field: string): Uint8Array {
  const out = decodeB64uStrict(b64, len);
  if (!out) throw new Error(`frost-net-runner: field '${field}' is not ${len}-byte canonical base64url`);
  return out;
}

export function buildService(cfg: SignerRunnerConfig): GuardianSignerService {
  return new GuardianSignerService({
    identifier: cfg.identifier,
    share: requireBytes(cfg.share, 32, 'share'),
    groupPublicKey: requireBytes(cfg.groupPublicKey, 32, 'groupPublicKey'),
    threshold: cfg.threshold,
    policyAuthorityPublicKey: requireBytes(cfg.policyAuthorityPublicKey, 32, 'policyAuthorityPublicKey'),
  });
}

export async function runSigner(cfg: SignerRunnerConfig): Promise<SignerHttpServer> {
  const service = buildService(cfg);
  const http = await startSignerHttpServer(service, {
    ...(cfg.port !== undefined ? { port: cfg.port } : {}),
    ...(cfg.host !== undefined ? { host: cfg.host } : {}),
  });
  // One machine-parseable ready line for the parent.
  process.stdout.write(`${READY_PREFIX}${JSON.stringify({ identifier: cfg.identifier, url: http.url, port: http.port })}\n`);
  return http;
}

async function main(): Promise<void> {
  const path = process.argv[2] ?? process.env.FROST_SIGNER_CONFIG;
  if (!path) {
    process.stderr.write('usage: tsx frost-net-runner.ts <config.json>  (or set FROST_SIGNER_CONFIG)\n');
    process.exit(2);
  }
  const cfg = JSON.parse(readFileSync(path, 'utf8')) as SignerRunnerConfig;
  const http = await runSigner(cfg);
  const shutdown = (): void => {
    void http.close().then(() => process.exit(0));
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

// Run only when invoked directly (not when imported by a test).
if (require.main === module) {
  main().catch((e) => {
    process.stderr.write(`frost-net-runner: ${e instanceof Error ? e.stack ?? e.message : String(e)}\n`);
    process.exit(1);
  });
}

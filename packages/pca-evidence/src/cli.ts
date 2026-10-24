#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { strictParse } from '@atlasauth/pca';
import { evidenceDigest, bundleShapeError, type EvidenceBundle } from './bundle';
import { accTrustError, principalsTrustError, verifyEvidenceBundle, type EvidenceTrust } from './verify';

/**
 * `pca-evidence`: the standalone replay verifier.
 *
 *   pca-evidence verify <bundle.json> [--trust trust.json] [--json] [--allow-unpinned]
 *   pca-evidence digest <bundle.json>
 *
 * Exit codes:
 *   0  consistent AND attributed (every signing session-root key is pinned in `principals`); unverified findings are
 *      listed but do not fail;
 *   1  at least one finding failed (this wins over 3);
 *   2  usage or parse error (including a malformed trust file);
 *   3  consistent but NOT attributed: no pinned principal keys, so the bundle may be fabricated by whoever made its keys.
 *      With `--allow-unpinned` this case exits 0 and prints the keys to verify out of band.
 * The trust file is JSON with any of: siteKeys, principals, sessionRootDigest, minTier, jitTier,
 * typedValues, credentials, canaryLabels, oracleKeys, judges, labelKeys, anchorGuardian, acc ({max_receipt_age_s?, max_keyset_age_s?}). Ports (functions) cannot
 * come from JSON: artifacts that need one are reported as unverified.
 */

export interface CliIo {
  readFile(path: string): string;
  stdout(s: string): void;
  stderr(s: string): void;
}

const USAGE = 'usage: pca-evidence verify <bundle.json> [--trust trust.json] [--json] [--allow-unpinned]\n       pca-evidence digest <bundle.json>';

const TRUST_KEYS = ['siteKeys', 'principals', 'sessionRootDigest', 'minTier', 'jitTier', 'typedValues', 'credentials', 'canaryLabels', 'oracleKeys', 'judges', 'labelKeys', 'anchorGuardian', 'acc'];

function readJson(io: CliIo, path: string): unknown {
  return strictParse(io.readFile(path));
}

export async function runCli(argv: readonly string[], io: CliIo): Promise<number> {
  const [cmd, ...rest] = argv;
  if (cmd !== 'verify' && cmd !== 'digest') {
    io.stderr(USAGE);
    return 2;
  }
  let file: string | undefined;
  let trustFile: string | undefined;
  let json = false;
  let allowUnpinned = false;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (a === '--json') json = true;
    else if (a === '--allow-unpinned' && cmd === 'verify') allowUnpinned = true;
    else if (a === '--trust' && cmd === 'verify') {
      trustFile = rest[++i];
      if (trustFile === undefined) {
        io.stderr(USAGE);
        return 2;
      }
    } else if (!a.startsWith('--') && file === undefined) file = a;
    else {
      io.stderr(USAGE);
      return 2;
    }
  }
  if (file === undefined) {
    io.stderr(USAGE);
    return 2;
  }
  let bundle: unknown;
  let trust: EvidenceTrust = {};
  try {
    bundle = readJson(io, file);
    if (trustFile !== undefined) {
      const t = readJson(io, trustFile);
      if (t === null || typeof t !== 'object' || Array.isArray(t)) throw new Error('trust file must be a JSON object');
      for (const k of Object.keys(t)) if (!TRUST_KEYS.includes(k)) throw new Error(`unknown trust member "${k}"`);
      const ae = accTrustError((t as Record<string, unknown>).acc);
      if (ae) throw new Error(ae);
      const pe = principalsTrustError((t as Record<string, unknown>).principals);
      if (pe) throw new Error(pe);
      trust = t as EvidenceTrust;
    }
  } catch (e) {
    io.stderr(`pca-evidence: ${(e as Error).message}`);
    return 2;
  }
  if (cmd === 'digest') {
    const bad = bundleShapeError(bundle);
    if (bad) {
      io.stderr(`pca-evidence: ${bad}`);
      return 2;
    }
    io.stdout(evidenceDigest(bundle as EvidenceBundle));
    return 0;
  }
  const report = await verifyEvidenceBundle(bundle, trust);
  const unattributed = report.consistent && !report.attributed;
  const keys = report.summary.attribution.keys_to_check;
  if (json) io.stdout(JSON.stringify(report, null, 2));
  else {
    const verdict = report.ok ? 'OK' : unattributed ? 'CONSISTENT BUT NOT ATTRIBUTED' : 'FAILED';
    const lines = [
      `bundle ${report.digest ?? '(malformed)'}: ${verdict}${report.complete ? '' : ' (incomplete: some artifacts not verified here)'}`,
      ...report.findings.map((x) => `[${x.status}] ${x.code}${x.refs.length ? ` ${x.refs.join(' ')}` : ''}: ${x.text}`),
      'Proven:',
      ...report.summary.proven.map((s) => `  - ${s}`),
      'Not proven:',
      ...report.summary.not_proven.map((s) => `  - ${s}`),
      `report ${report.report_digest}`,
    ];
    io.stdout(lines.join('\n'));
  }
  if (!report.consistent) return 1;
  if (unattributed) {
    if (allowUnpinned) {
      io.stderr(`pca-evidence: principal keys to verify out of band: ${keys.join(', ')}`);
      return 0;
    }
    io.stderr(`pca-evidence: the bundle is internally consistent but NOT attributed to any known principal (no pinned "principals" in the trust file). Keys to verify out of band: ${keys.join(', ')}. Pass --allow-unpinned to accept anyway.`);
    return 3;
  }
  return report.ok ? 0 : 1;
}

if (require.main === module) {
  void runCli(process.argv.slice(2), {
    readFile: (p) => readFileSync(p, 'utf8'),
    stdout: (s) => process.stdout.write(`${s}\n`),
    stderr: (s) => process.stderr.write(`${s}\n`),
  }).then((code) => {
    process.exitCode = code;
  });
}

import { createPublicKey, createHash, type KeyObject } from 'node:crypto';
import { checkStatement, signStatement, statementPayload } from '@atlasauth/pca-scitt';
import { verifyCiAttestation, type CiAttestation, type CiPolicy, type Tier } from './attest';
import { bundledManifest, loadBundledCorpus, type CorpusManifest, type LoadedCorpus } from './corpus';
import { verifyReport, type Implementation, type Report } from './run';
import { b64u, canonicalJson, fromB64u, isObj, RUNNER_NAME, runnerVersion, type Json } from './util';

export const STATEMENT_FORMAT = 'pca-verified-statement/1';
export const STATEMENT_TYPE = 'pca-verified/statement';
export const STATEMENT_CONTENT_TYPE = 'application/pca-verified-statement+json';

export interface StatementPayload {
  type: typeof STATEMENT_TYPE;
  version: 1;
  implementation: Implementation;
  runner: { name: string; version: string };
  protocol: string;
  corpus: { version: string; sha256: string };
  profile: string;
  result: 'pass';
  summary: { total: number; passed: number; by_layer: Record<string, { total: number; passed: number }> };
  results_digest: string;
  declared_suites: string[];
  /** The signer's public key (SPKI, base64url): bound into the signed payload so the key cannot be swapped. */
  signer_key: string;
  /** Epoch milliseconds. */
  issued_at: number;
}

/** The file a third party receives: the COSE Signed Statement, the key that signed it, and the decoded payload for people. */
export interface StatementEnvelope {
  format: typeof STATEMENT_FORMAT;
  /** COSE_Sign1 bytes, base64url. This is the attestation; `payload` is only a convenience copy and is checked against it. */
  statement: string;
  public_key: string;
  payload: StatementPayload;
}

export const publicKeyB64u = (k: KeyObject): string => b64u(createPublicKey(k).export({ type: 'spki', format: 'der' }));
export const keyFingerprint = (spkiB64u: string): string => createHash('sha256').update(fromB64u(spkiB64u)).digest('hex').slice(0, 16);

/** One signed statement per profile the report fully passes. A failing, unsupported or incomplete profile gets none. */
export function createStatements(report: Report, opts: { key: KeyObject; issuer: string; now?: number }): StatementEnvelope[] {
  if (!report.complete || report.protocol_violations > 0) return [];
  const pub = publicKeyB64u(opts.key);
  const out: StatementEnvelope[] = [];
  for (const [profile, r] of Object.entries(report.profiles)) {
    if (r.status !== 'pass') continue;
    const payload: StatementPayload = {
      type: STATEMENT_TYPE,
      version: 1,
      implementation: report.implementation,
      runner: { name: RUNNER_NAME, version: runnerVersion() },
      protocol: report.protocol,
      corpus: { version: report.corpus.version, sha256: report.corpus.sha256 },
      profile,
      result: 'pass',
      summary: { total: r.total, passed: r.passed, by_layer: r.by_layer },
      results_digest: r.results_digest,
      declared_suites: report.declared_suites,
      signer_key: pub,
      issued_at: opts.now ?? Date.now(),
    };
    const cose = signStatement(payload, { alg: 'EdDSA', key: opts.key, issuer: opts.issuer, subject: `${report.implementation.name}@${report.implementation.version}#${profile}`, contentType: STATEMENT_CONTENT_TYPE });
    out.push({ format: STATEMENT_FORMAT, statement: b64u(cose), public_key: pub, payload });
  }
  return out;
}

export interface VerifyStatementOptions {
  /** Corpora whose statements are acceptable (default: the one bundled with this runner). A statement for any other corpus hash is refused. */
  corpora?: readonly CorpusManifest[];
  /** When given, the signer must be one of these public keys (SPKI base64url). */
  trustKeys?: readonly string[];
  /** The full report the statement was made from: its results digest, implementation and verdict must match, and it must itself follow from the corpus. */
  report?: Report;
  /** Corpus used to re-derive `report` (default: the bundled one, which must be the statement's corpus). */
  reportCorpus?: LoadedCorpus;
  /**
   * A Sigstore build-provenance bundle for this statement, made in a GitHub Actions run, and what it must say. When given it must verify
   * (a bundle that does not is a failure, never a silent downgrade); the statement is then CI-attested instead of self-attested.
   */
  attestation?: { bundle: unknown; policy: CiPolicy };
  /** Refuse a statement below this tier. */
  requireTier?: Tier;
}

export interface VerifyResult {
  ok: boolean;
  reasons: string[];
  payload?: StatementPayload;
  /** `self-attested`: signed by whoever holds the key. `ci-attested`: the same, and a GitHub Actions workflow of the named repository attested these exact bytes. */
  tier?: Tier;
  /** Who attested, for a CI-attested statement. */
  attestation?: CiAttestation;
}

const HEX64 = /^[0-9a-f]{64}$/;

/** Check an envelope. Fail-closed, never throws: every reason found is listed. */
export function verifyStatementEnvelope(env: StatementEnvelope, opts: VerifyStatementOptions = {}): VerifyResult {
  const reasons: string[] = [];
  let tier: Tier = 'self-attested';
  let ci: CiAttestation | undefined;
  const bad = (r: string): VerifyResult => ({ ok: false, reasons: [...reasons, r] });
  try {
    if (!isObj(env) || env.format !== STATEMENT_FORMAT || typeof env.statement !== 'string' || typeof env.public_key !== 'string' || !isObj(env.payload)) return bad('malformed: not a pca-verified statement file');
    let cose: Uint8Array;
    let key: KeyObject;
    try {
      cose = fromB64u(env.statement);
      const der = fromB64u(env.public_key);
      key = createPublicKey({ key: Buffer.from(der), format: 'der', type: 'spki' });
      if (key.asymmetricKeyType !== 'ed25519') return bad('signer key is not an Ed25519 key');
    } catch (e) {
      return bad(`malformed: ${(e as Error).message}`);
    }
    const sig = checkStatement(cose, key);
    if (!sig.ok) return bad(`signature: ${sig.reason}`);
    let signed: StatementPayload;
    try {
      signed = JSON.parse(Buffer.from(statementPayload(cose)).toString('utf8')) as StatementPayload;
    } catch {
      return bad('signed payload is not JSON');
    }
    // the decoded copy beside the COSE bytes is for people; only the signed bytes count
    if (canonicalJson(signed) !== canonicalJson(env.payload)) reasons.push('payload copy differs from the signed payload');
    if (signed.type !== STATEMENT_TYPE || signed.version !== 1) return bad('not a version 1 conformance statement');
    if (signed.signer_key !== env.public_key) reasons.push('signer key is not the one bound in the statement');
    if (signed.result !== 'pass') reasons.push('statement does not claim a pass');
    if (!Number.isSafeInteger(signed.issued_at) || signed.issued_at < 0) reasons.push('issued_at is not a valid time');
    if (!isObj(signed.implementation) || typeof signed.implementation.name !== 'string' || typeof signed.implementation.version !== 'string' || !signed.implementation.name || !signed.implementation.version) reasons.push('implementation name and version are required');

    const corpora = opts.corpora ?? [bundledManifest()];
    const m = corpora.find((c) => c.sha256 === signed.corpus?.sha256);
    if (!m) {
      reasons.push(`corpus ${String(signed.corpus?.sha256).slice(0, 16)} is not a corpus this verifier trusts`);
    } else {
      if (m.corpus_version !== signed.corpus.version) reasons.push('corpus version does not match the corpus hash');
      if (m.protocol_version !== signed.protocol) reasons.push('protocol version does not match the corpus');
      const p = m.profiles[signed.profile];
      if (!p) reasons.push(`unknown profile ${String(signed.profile)}`);
      else {
        const s = signed.summary;
        // a partial run must not pass for the profile: totals must equal the whole profile, every layer, every item passed
        if (!isObj(s) || s.total !== p.items || s.passed !== p.items) reasons.push('summary does not cover the whole profile');
        else {
          const want = Object.fromEntries(Object.entries(p.layer_items).map(([l, n]) => [l, { total: n, passed: n }]));
          if (canonicalJson(s.by_layer) !== canonicalJson(want)) reasons.push('per-layer summary does not cover the whole profile');
        }
        const need = p.requires_suites ?? [];
        if (!Array.isArray(signed.declared_suites) || need.some((x) => !signed.declared_suites.includes(x))) reasons.push('declared suites do not meet the profile requirement');
      }
    }
    if (typeof signed.results_digest !== 'string' || !HEX64.test(signed.results_digest)) reasons.push('results digest is malformed');
    if (opts.trustKeys && !opts.trustKeys.includes(env.public_key)) reasons.push('signer is not a trusted key');

    if (opts.attestation) {
      const c = verifyCiAttestation(cose, opts.attestation.bundle, opts.attestation.policy);
      if (c.ok) { tier = 'ci-attested'; ci = c.attestation; } else reasons.push(`attestation: ${c.reason}`);
    }
    if (opts.requireTier === 'ci-attested' && tier !== 'ci-attested' && !reasons.some((r) => r.startsWith('attestation:'))) reasons.push('attestation: a CI-attested statement is required and none was given');

    if (opts.report) {
      let corpus: LoadedCorpus | undefined = opts.reportCorpus;
      if (!corpus) {
        const b = loadBundledCorpus();
        corpus = b.manifest.sha256 === signed.corpus?.sha256 ? b : undefined;
      }
      if (!corpus) reasons.push('no corpus available to re-derive the report');
      else {
        const rc = verifyReport(opts.report, corpus);
        for (const r of rc.reasons) reasons.push(`report: ${r}`);
        const pr = opts.report.profiles?.[signed.profile];
        if (!pr) reasons.push('report does not cover the statement profile');
        else {
          if (pr.results_digest !== signed.results_digest) reasons.push('report results digest differs from the statement');
          if (pr.status !== 'pass') reasons.push('report does not show a pass for the profile');
        }
        if (canonicalJson(opts.report.implementation) !== canonicalJson(signed.implementation)) reasons.push('report is for a different implementation');
      }
    }
  } catch (e) {
    reasons.push(`unexpected: ${(e as Error).message}`);
  }
  return { ok: reasons.length === 0, reasons, ...(reasons.length === 0 ? { payload: env.payload, tier, ...(ci ? { attestation: ci } : {}) } : {}) };
}

export type { Json };

/** allowedSuites / pqPins / allowUnboundPq sanity against the library's closed suite registry. */
import { SIG_SUITES } from '@atlasauth/pca';
import type { CheckResult, DoctorConfig } from './types';

const B64U = /^[A-Za-z0-9_-]+$/;
const ED25519_ID = /^[A-Za-z0-9_-]{43}$/;

export const SUITES_REMEDIATION =
  "Set the verifier's allowedSuites to exactly the suites your issuers sign with (names from SIG_SUITES), e.g. ['ed25519'] or ['hybrid-ed25519-ml-dsa-65'].";
export const PQ_REMEDIATION =
  'Never set allowUnboundPq. For pure-PQ or hybrid roots, configure pqPins (issuer Ed25519 identity -> PQ public key, from pqPinFor) or verify against your stored root grant (trustedRoot; requirePCA / verifyPCActnCore do this).';

const isPq = (alg: string): boolean => !!(SIG_SUITES as Record<string, { needsPqPk: boolean }>)[alg]?.needsPqPk;

export function checkAllowedSuites(cfg: DoctorConfig, registry: Readonly<Record<string, unknown>> = SIG_SUITES): CheckResult {
  const id = 'suites.allowed';
  const v = cfg.verifier;
  if (!v) return { id, status: 'skip', detail: 'no verifier configuration given (config verifier.*)' };
  const list = v.allowedSuites;
  const known = Object.keys(registry);
  if (list === undefined) {
    return { id, status: 'warn', detail: `allowedSuites is unset: every registered suite is accepted (${known.length}: ${known.join(', ')})`, remediation: SUITES_REMEDIATION };
  }
  if (!Array.isArray(list) || list.length === 0) {
    return { id, status: 'fail', detail: 'allowedSuites is empty or not a list: no PCActn can verify', remediation: SUITES_REMEDIATION };
  }
  const unknown = list.filter((s) => typeof s !== 'string' || !Object.prototype.hasOwnProperty.call(registry, s));
  if (unknown.length > 0) {
    return { id, status: 'fail', detail: `allowedSuites names suite(s) outside the registry: ${unknown.map(String).join(', ')} (known: ${known.join(', ')})`, remediation: SUITES_REMEDIATION };
  }
  return { id, status: 'pass', detail: `allowedSuites = ${list.join(', ')}` };
}

export function checkPqBinding(cfg: DoctorConfig): CheckResult {
  const id = 'suites.pq-binding';
  const v = cfg.verifier;
  if (!v) return { id, status: 'skip', detail: 'no verifier configuration given (config verifier.*)' };
  const fail = (detail: string): CheckResult => ({ id, status: 'fail', detail, remediation: PQ_REMEDIATION });
  if (v.allowUnboundPq === true) return fail('allowUnboundPq is set: PQ keys are read from the artifact, so a hybrid gives no protection against an Ed25519 forger and a pure-PQ hop can be signed by any key');
  const pins = v.pqPins;
  if (pins !== undefined) {
    if (!pins || typeof pins !== 'object' || Array.isArray(pins)) return fail('pqPins is not an object of { ed25519 identity: pq public key }');
    const bad = Object.entries(pins).filter(([k, val]) => !ED25519_ID.test(k) || typeof val !== 'string' || !B64U.test(val));
    if (bad.length > 0) return fail(`pqPins has malformed entries (key must be a 43-char base64url Ed25519 identity, value a base64url PQ key): ${bad.map(([k]) => k).join(', ')}`);
  }
  const pq = (v.allowedSuites ?? Object.keys(SIG_SUITES)).filter(isPq);
  if (pq.length === 0) return { id, status: 'pass', detail: 'no post-quantum suite is accepted (Ed25519 only: no PQ binding needed, and no PQ protection)' };
  const pinned = pins !== undefined && Object.keys(pins).length > 0;
  if (!pinned && v.trustedRoot !== true) {
    return {
      id,
      status: 'warn',
      detail: `post-quantum suite(s) accepted (${pq.join(', ')}) with neither pqPins nor a stored trustedRoot: a non-Ed25519 root is refused (fail closed) or its PQ key is not pinned`,
      remediation: PQ_REMEDIATION,
    };
  }
  return { id, status: 'pass', detail: `PQ suites (${pq.join(', ')}) are bound: ${pinned ? `${Object.keys(pins!).length} pin(s)` : 'stored trustedRoot'}; allowUnboundPq off` };
}

/**
 * The `pca` developer CLI — the honest inspector for Proof-Carrying Authority.
 *
 * Four pure command functions, each taking parsed arguments and returning a string (or a small
 * structured result) so they are unit-testable without spawning a process. They lean ENTIRELY on
 * `@atlasauth/pca`'s own primitives — the same decode / verify / compile / simulate code the
 * resource server and the facade use — so what the CLI prints is what the verifier actually does.
 *
 * HONEST about scope: nothing here authorizes anything. `decode` and `explain` are read-only
 * inspectors; `explain` runs the REAL `verifyPCActnCore` against a grant it reads straight out of
 * the PCActn's own capability chain, so a "verdict" it prints is the local, grant-relative view —
 * the resource server, with its stored counter / revocation / attestation state, remains the
 * authority. `keygen` mints a throwaway dev keypair (never a production holder). `simulate` is a
 * pure offline planning replay: it mutates nothing, signs nothing, and reaches no network.
 */

import {
  b64u,
  buildDiscoveryDocument,
  compilePolicy,
  decodePCActn,
  generateKeyPair,
  lintPolicy,
  simulate,
  unb64u,
  verifyPCActnCore,
} from '@atlasauth/pca';

// ---- small helpers --------------------------------------------------------------------------------

/** Message of an unknown throwable without an `any`/suppression cast. */
function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Parse JSON into `unknown` (never `any`) with a labelled error. */
function parseJson(s: string, label: string): unknown {
  try {
    return JSON.parse(s) as unknown;
  } catch (e) {
    throw new Error(`${label}: invalid JSON: ${errMessage(e)}`);
  }
}

/** Epoch-ms → ISO 8601, or a clear marker when the value is not a finite instant. */
function iso(ms: unknown): string {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return '(none)';
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? '(invalid)' : d.toISOString();
}

/** Right-pad to `width` for simple fixed-column tables. */
function pad(s: string, width: number): string {
  return s.length >= width ? s : s + ' '.repeat(width - s.length);
}

// ---- decode ---------------------------------------------------------------------------------------

/**
 * Parse CLI input that is EITHER PCActn JSON text or its base64url wire form. Detection is
 * structural: a leading `{` (after trimming) is JSON; anything else is tried as base64url whose
 * decoded bytes must be UTF-8 PCActn JSON. Either way the bytes go through the strict
 * `decodePCActn` parser, so a malformed object throws a clear Error.
 */
export function parsePCActnInput(input: string): ReturnType<typeof decodePCActn> {
  const trimmed = input.trim();
  if (trimmed.length === 0) throw new Error('empty input: expected a PCActn as JSON text or base64url');

  if (trimmed.startsWith('{')) {
    try {
      return decodePCActn(trimmed);
    } catch (e) {
      throw new Error(`not a valid PCActn (JSON): ${errMessage(e)}`);
    }
  }

  let bytes: Uint8Array;
  try {
    bytes = unb64u(trimmed);
  } catch (e) {
    throw new Error(`input is neither JSON (no leading '{') nor valid base64url: ${errMessage(e)}`);
  }
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error('base64url decoded to bytes that are not valid UTF-8; not a PCActn');
  }
  try {
    return decodePCActn(text);
  } catch (e) {
    throw new Error(`base64url decoded but is not a valid PCActn: ${errMessage(e)}`);
  }
}

/**
 * Decode a PCActn (JSON or base64url) and return a readable summary: verb, resource, audience, the
 * issued/expiry window (ISO + raw ms), counter, capability-chain depth, the claimed risk, and
 * whether a threshold or zk-compliance field rides along. Throws a clear Error on malformed input.
 */
export function cmdDecode(input: string): string {
  const p = parsePCActnInput(input);
  const chainDepth = Array.isArray(p.cap_chain) ? p.cap_chain.length : 0;
  const riskR =
    isRecord(p.risk_claim) && typeof p.risk_claim.r === 'number' ? String(p.risk_claim.r) : '(none)';
  const lines = [
    'PCActn summary',
    `  verb          ${p.action.verb}`,
    `  resource      ${p.action.resource}`,
    `  reversibility ${p.action.reversibility_class}`,
    `  audience      ${p.aud || '(none)'}`,
    `  issued (iat)  ${iso(p.iat)}  [${p.iat}]`,
    `  expires (exp) ${iso(p.exp)}  [${p.exp}]`,
    `  counter       ${p.counter}`,
    `  cap-chain     depth ${chainDepth}`,
    `  risk_claim.r  ${riskR}`,
    `  threshold     ${p.threshold !== undefined ? 'present' : 'absent'}`,
    `  zk_compliance ${p.zk_compliance !== undefined ? 'present' : 'absent'}`,
  ];
  return lines.join('\n');
}

// ---- explain --------------------------------------------------------------------------------------

const STATUS_LABEL: Record<string, string> = { pass: 'PASS', fail: 'FAIL', 'not-enforced': '—' };

export interface ExplainResult {
  allow: boolean;
  checks: Record<string, string>;
  reasons: string[];
  text: string;
}

/**
 * The "why did it (not) verify?" explainer. Decodes the PCActn, takes its `cap_chain[0]` as the root
 * grant (the capability the whole chain descends from), and runs the REAL `verifyPCActnCore` against
 * it, then formats each check as PASS / FAIL / — (not enforced at this milestone) with a final
 * verdict line. `--aud` supplies this verifier's audience; omit it to accept any audience.
 */
export async function cmdExplain(
  input: string,
  opts: { audience?: string; now?: number },
): Promise<ExplainResult> {
  const p = parsePCActnInput(input);
  const grant = Array.isArray(p.cap_chain) ? p.cap_chain[0] : undefined;
  if (!grant) throw new Error('cannot explain: the PCActn has an empty capability chain (no root grant)');

  const result = await verifyPCActnCore(p, {
    grant,
    audience: opts.audience ?? null,
    nowEpoch: opts.now,
  });

  const checks: Record<string, string> = {};
  for (const [name, status] of Object.entries(result.checks)) {
    checks[name] = STATUS_LABEL[status] ?? status;
  }

  const reasons: string[] = [];
  if (result.reason) reasons.push(result.reason);

  const audLine = opts.audience === undefined ? 'any (not supplied)' : opts.audience;
  const width = Math.max(...Object.keys(checks).map((k) => k.length), 0) + 2;
  const checkLines = Object.entries(result.checks).map(([name, status]) => {
    const label = STATUS_LABEL[status] ?? status;
    const note = status === 'not-enforced' ? ' (not enforced at this milestone)' : '';
    return `  ${pad(name, width)}${label}${note}`;
  });

  const text = [
    'PCActn verification (explain)',
    `  verb            ${p.action.verb}`,
    `  resource        ${p.action.resource}`,
    `  action audience ${p.aud || '(none)'}`,
    `  verifier aud    ${audLine}`,
    '',
    ...checkLines,
    '',
    `  VERDICT: ${result.allow ? 'ALLOW' : 'DENY'}`,
    ...(reasons.length ? ['', '  reasons:', ...reasons.map((r) => `    - ${r}`)] : []),
  ].join('\n');

  return { allow: result.allow, checks, reasons, text };
}

// ---- keygen ---------------------------------------------------------------------------------------

export interface KeygenResult {
  publicKey: string;
  secretKey: string;
  text: string;
}

/**
 * Mint a throwaway Ed25519 dev keypair and return both keys base64url-encoded plus a clearly labelled
 * block. This is a DEV convenience — not a production holder key. The secret signs PCActns as this
 * holder and must stay private; the public key is what a grant binds to (`holder`).
 */
export function cmdKeygen(): KeygenResult {
  const kp = generateKeyPair();
  const publicKey = b64u(kp.publicKey);
  const secretKey = b64u(kp.secretKey);
  const text = [
    'PCA dev keypair (Ed25519)',
    `  public  ${publicKey}`,
    `  secret  ${secretKey}`,
    '',
    '  Keep the SECRET key private — it signs PCActns as this holder.',
    '  Share only the public key (a grant binds to it as `holder`).',
  ].join('\n');
  return { publicKey, secretKey, text };
}

export interface DiscoveryCmdOptions {
  audience: string;
  suites?: string[];
  endpoints?: { attestation_challenge?: string; revocation_epoch?: string; liveness_beacon?: string; stepup?: string; grant?: string };
}

/** Emit a `.well-known/pca-configuration` document for a resource server to publish. */
export function cmdDiscovery(opts: DiscoveryCmdOptions): string {
  const doc = buildDiscoveryDocument({
    audience: opts.audience,
    ...(opts.suites && opts.suites.length ? { signatureSuites: opts.suites } : {}),
    ...(opts.endpoints && Object.keys(opts.endpoints).length ? { endpoints: opts.endpoints } : {}),
  });
  return JSON.stringify(doc, null, 2);
}

// ---- simulate -------------------------------------------------------------------------------------

interface ParsedSimAction {
  verb: string;
  resource: string;
  params?: Record<string, unknown>;
  at?: number;
}

function parsePolicySpec(policyJson: string): { permissions: Record<string, string[]>; limits?: Record<string, string> } {
  const spec = parseJson(policyJson, 'policy');
  if (!isRecord(spec)) throw new Error('policy must be a JSON object { permissions, limits? }');
  if (!isRecord(spec.permissions)) throw new Error('policy.permissions must be an object { connector: [action, ...] }');

  const permissions: Record<string, string[]> = {};
  for (const [connector, acts] of Object.entries(spec.permissions)) {
    if (!Array.isArray(acts)) throw new Error(`policy.permissions.${connector} must be an array of action names`);
    const names: string[] = [];
    for (const a of acts) {
      if (typeof a !== 'string') throw new Error(`policy.permissions.${connector} must contain only strings`);
      names.push(a);
    }
    permissions[connector] = names;
  }

  if (spec.limits === undefined) return { permissions };
  if (!isRecord(spec.limits)) throw new Error('policy.limits must be an object { action: "$X/period" }');
  const limits: Record<string, string> = {};
  for (const [k, v] of Object.entries(spec.limits)) {
    if (typeof v !== 'string') throw new Error(`policy.limits.${k} must be a string like "$500/day"`);
    limits[k] = v;
  }
  return { permissions, limits };
}

function parseSimActions(actionsJson: string): ParsedSimAction[] {
  const arr = parseJson(actionsJson, 'actions');
  if (!Array.isArray(arr)) throw new Error('actions must be a JSON array of { verb, resource, params?, at? }');
  return arr.map((raw, i) => {
    if (!isRecord(raw)) throw new Error(`actions[${i}] must be an object`);
    if (typeof raw.verb !== 'string') throw new Error(`actions[${i}].verb must be a string`);
    if (typeof raw.resource !== 'string') throw new Error(`actions[${i}].resource must be a string`);
    const out: ParsedSimAction = { verb: raw.verb, resource: raw.resource };
    if (raw.params !== undefined) {
      if (!isRecord(raw.params)) throw new Error(`actions[${i}].params must be an object`);
      out.params = raw.params;
    }
    if (raw.at !== undefined) {
      if (typeof raw.at !== 'number' || !Number.isFinite(raw.at)) throw new Error(`actions[${i}].at must be a number (epoch ms)`);
      out.at = raw.at;
    }
    return out;
  });
}

/**
 * Compile a policy spec `{ permissions, limits? }` and replay an actions array against it, printing a
 * per-action table (auto / step_up / deny + the trust budget remaining after each), the static lints
 * `lintPolicy` found, and the autonomy bound (the most this grant can spend/risk between human
 * co-signs). Pure and offline — the resource server's verifier remains the authority at run time.
 */
export function cmdSimulate(policyJson: string, actionsJson: string): string {
  const { permissions, limits } = parsePolicySpec(policyJson);
  const policy = compilePolicy({ permissions, ...(limits !== undefined ? { limits } : {}) });
  const actions = parseSimActions(actionsJson);

  const report = simulate(policy, actions);
  const lints = lintPolicy(policy);

  const { bMax, kappa } = policy.riskPolicy;
  const safety = kappa > 0 ? Math.max(0, bMax) / kappa : 0;
  const autonomyBound = safety * kappa;

  const header = `  ${pad('#', 3)}${pad('verb', 18)}${pad('resource', 20)}${pad('outcome', 10)}budgetAfter`;
  const rows = report.results.map((r, i) =>
    `  ${pad(String(i + 1), 3)}${pad(r.action.verb, 18)}${pad(r.action.resource, 20)}${pad(r.outcome, 10)}${r.budgetAfter.toFixed(2)}`,
  );

  const lintLines = lints.length
    ? lints.map((l) => `  [${l.level}] ${l.code}: ${l.message}`)
    : ['  (none)'];

  return [
    `Policy simulation (${report.results.length} action${report.results.length === 1 ? '' : 's'})`,
    '',
    header,
    ...rows,
    '',
    `  auto=${report.auto}  step_up=${report.stepUp}  deny=${report.deny}  endBudget=${report.endBudget.toFixed(2)}  peakRisk=${report.peakRisk.toFixed(3)}`,
    `  autonomy bound: ${autonomyBound.toFixed(2)} (most this grant can spend/risk between human co-signs)`,
    '',
    'Lints:',
    ...lintLines,
  ].join('\n');
}

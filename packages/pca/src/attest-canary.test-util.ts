/**
 * Real-evidence CANARY harness for the vendor attestation verifiers (AMD SEV-SNP, Intel TDX, Azure MAA, NVIDIA H100).
 *
 * A manifest names cases; each case points at captured (or live-collected) evidence files and pins. The same manifest
 * format drives two runs:
 *   - RECORDED: `fixtures/attest-canary/manifest.json` over the evidence recorded in this repo (runs in the test suite);
 *   - LIVE: the operator collects fresh evidence from their machines into a directory with its own manifest of the same
 *     shape and runs `tsx scripts/attest-canary.ts <dir>/manifest.json` on a schedule (see docs: "Attestation canary").
 *
 * A case PASSES only when ALL of these hold, so a verifier that has silently become fail-open cannot keep the canary green:
 *   1. the evidence verifies (`ok`, `bound`, a measured identity);
 *   2. every NEGATIVE CONTROL is denied: a relayed binding (other nonce), one flipped byte in the primary evidence, and a
 *      wrong trust pin;
 *   3. no certificate in the evidence is within `warnDays` of expiry (collateral-expiry alarm).
 * Missing evidence files are a FAILURE, never a skip. Nothing here is a trust anchor; pins come from the manifest.
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { X509Certificate } from 'node:crypto';
import { createAmdSnpVerifier, pemToDer } from './attest-amd-snp';
import { createAzureMaaVerifier, type MaaJwks } from './attest-azure-maa';
import { createIntelDcapVerifier } from './attest-intel-dcap';
import type { IntelTdxCollateral } from './attest-intel-collateral';
import { createNvidiaSpdmVerifier } from './attest-nvidia-spdm';
import { nvidiaCollateralHook, type NvidiaCollateralBundle } from './attest-nvidia-rim';
import type { AttestationDocument, ExpectedAttestationBinding, HardwareAttestationResult, HardwareAttestationVerifier } from './attestation';

export interface CanaryBase {
  id: string;
  /** Evaluation time, epoch ms, or `"now"` for a live run. */
  now: number | 'now';
  expected: ExpectedAttestationBinding;
}
export interface CanarySnp extends CanaryBase {
  vendor: 'sev-snp';
  family: 'milan' | 'genoa' | 'turin';
  binding: 'report-data' | 'azure-runtime-data';
  /** Raw report file; `reportOffset` skips a wrapper (the Azure HCL blob carries the 1184-byte report at 32). */
  reportFile: string;
  reportOffset?: number;
  /** Either an Azure-style JSON `{ vcekCert, certificateChain }` or separate VCEK (DER or PEM) and ASK+ARK PEM files. */
  certsJsonFile?: string;
  vcekFile?: string;
  chainFile?: string;
  runtimeDataFile?: string;
  measurements: string[];
}
export interface CanaryTdx extends CanaryBase {
  vendor: 'tdx';
  binding: 'report-data' | 'azure-runtime-data';
  quoteFile: string;
  runtimeDataFile?: string;
  collateral: { tcbInfo: string; tcbInfoChain: string; qeIdentity: string; qeIdentityChain: string; pckCrl: string; rootCrl: string };
  mrtds: string[];
}
export interface CanaryMaa extends CanaryBase {
  vendor: 'azure-maa';
  tokenFile: string;
  jwksFile: string;
  issuer: string;
  signerSpkiSha256: string[];
  tdxMrtds: string[];
}
export interface CanaryH100 extends CanaryBase {
  vendor: 'nvidia-h100';
  reportFile: string;
  certChainFile: string;
  driverRimFile: string;
  vbiosRimFile: string;
  crlFiles: string[];
  rootSpkiSha256: string[];
  rimRootSpkiSha256: string[];
  leafSubjectIncludes: string;
  requireCrlIssuers: string[];
}
export type CanaryCase = CanarySnp | CanaryTdx | CanaryMaa | CanaryH100;
export interface CanaryManifest {
  /** Alarm when any certificate / collateral document expires within this many days of the case time (default 14). */
  warnDays?: number;
  cases: CanaryCase[];
}

export interface CanaryResult {
  id: string;
  vendor: string;
  positive: { ok: boolean; reason?: string };
  controls: Array<{ name: string; denied: boolean; reason?: string }>;
  expiry: { earliestNotAfter: string | null; daysLeft: number | null; alarm: boolean };
  /** `pass` only when everything above holds; otherwise `fail` with the first problem in `why`. */
  verdict: 'pass' | 'fail';
  why?: string;
}

export interface Built {
  verify(over?: { expected?: ExpectedAttestationBinding; flip?: boolean; wrongPin?: boolean; mutate?: (primary: Uint8Array) => Uint8Array }): Promise<HardwareAttestationResult>;
  /** Certificates (PEM or DER) whose expiry the alarm watches, and collateral `nextUpdate` instants (ms). */
  certs: Array<string | Uint8Array>;
  nextUpdates: number[];
}

const DOC = {} as unknown as AttestationDocument;
const CTX = {} as never;
const flipByte = (b: Uint8Array, at = 60): Uint8Array => {
  const c = new Uint8Array(b);
  c[at % c.length] = c[at % c.length]! ^ 0x01;
  return c;
};
const bad = (n: number) => 'ff'.repeat(n);
type Mut = { flip?: boolean; wrongPin?: boolean; mutate?: (primary: Uint8Array) => Uint8Array };
const mut = (o: Mut, primary: Uint8Array): Uint8Array => (o.mutate ? o.mutate(primary) : o.flip ? flipByte(primary) : primary);

export function buildCanary(c: CanaryCase, dir: string, nowMs: number): Built {
  const f = (p: string): Buffer => {
    try {
      return readFileSync(resolve(dir, p));
    } catch (e) {
      throw new Error(`evidence file '${p}' is missing or unreadable: ${(e as Error).message}`);
    }
  };
  const bytes = (p: string) => new Uint8Array(f(p));
  const text = (p: string) => f(p).toString('utf8');
  const run = (v: HardwareAttestationVerifier, expected: ExpectedAttestationBinding) => Promise.resolve(v.verify({ document: DOC, ctx: CTX, nowMs, expected }));

  if (c.vendor === 'sev-snp') {
    const all = bytes(c.reportFile);
    const report = all.slice(c.reportOffset ?? 0, (c.reportOffset ?? 0) + 1184);
    let vcekDer: Uint8Array, askArkPem: string;
    if (c.certsJsonFile) {
      const j = JSON.parse(text(c.certsJsonFile)) as { vcekCert: string; certificateChain: string };
      vcekDer = pemToDer(j.vcekCert);
      askArkPem = j.certificateChain;
    } else {
      const raw = f(c.vcekFile!);
      vcekDer = raw.toString('utf8').includes('BEGIN CERTIFICATE') ? pemToDer(raw.toString('utf8')) : new Uint8Array(raw);
      askArkPem = text(c.chainFile!);
    }
    const runtimeData = c.runtimeDataFile ? bytes(c.runtimeDataFile) : undefined;
    const mk = (o: Mut) =>
      createAmdSnpVerifier({
        family: o.wrongPin ? (c.family === 'milan' ? 'turin' : 'milan') : c.family,
        binding: c.binding,
        policy: { measurements: c.measurements },
        resolveEvidence: () => ({ report: mut(o, report), vcekDer, askArkPem, ...(runtimeData ? { runtimeData } : {}) }),
      });
    return { certs: [vcekDer, askArkPem], nextUpdates: [], verify: (o = {}) => run(mk(o), o.expected ?? c.expected) };
  }

  if (c.vendor === 'tdx') {
    const quote = bytes(c.quoteFile);
    const runtimeData = c.runtimeDataFile ? bytes(c.runtimeDataFile) : undefined;
    const col: IntelTdxCollateral = {
      tcbInfoJson: text(c.collateral.tcbInfo),
      tcbInfoIssuerChainPem: text(c.collateral.tcbInfoChain),
      qeIdentityJson: text(c.collateral.qeIdentity),
      qeIdentityIssuerChainPem: text(c.collateral.qeIdentityChain),
      pckCrlDer: bytes(c.collateral.pckCrl),
      rootCrlDer: bytes(c.collateral.rootCrl),
    };
    const nextUpdateOf = (j: string) => Date.parse(String((Object.values(JSON.parse(j) as Record<string, Record<string, unknown>>)[0] as Record<string, unknown> | undefined)?.['nextUpdate'])); // first member is tcbInfo / enclaveIdentity
    const nextUpdates = [text(c.collateral.tcbInfo), text(c.collateral.qeIdentity)].map(nextUpdateOf);
    const mk = (o: Mut) =>
      createIntelDcapVerifier({
        binding: c.binding,
        policy: { mrtds: c.mrtds },
        ...(o.wrongPin ? { trustAnchorRootCaSpkiSha256: bad(32) } : {}),
        resolveEvidence: () => ({ quote: mut(o, quote), collateral: col, ...(runtimeData ? { runtimeData } : {}) }),
      });
    return { certs: [col.tcbInfoIssuerChainPem, col.qeIdentityIssuerChainPem], nextUpdates, verify: (o = {}) => run(mk(o), o.expected ?? c.expected) };
  }

  if (c.vendor === 'azure-maa') {
    const token = text(c.tokenFile).trim();
    const jwks = JSON.parse(text(c.jwksFile)) as MaaJwks;
    const mk = (o: Mut) => {
      const [h, p, s] = token.split('.');
      const sig = Buffer.from(s!, 'base64url');
      sig[0] = sig[0]! ^ 0x01;
      return createAzureMaaVerifier({
        trustedIssuers: [c.issuer],
        trustAnchors: { rootSpkiSha256: o.wrongPin ? [bad(32)] : c.signerSpkiSha256 },
        policy: { tdxMrtds: c.tdxMrtds, runtimeUserDataBinding: true },
        resolveEvidence: () => ({ token: o.mutate ? Buffer.from(o.mutate(new Uint8Array(Buffer.from(token)))).toString('latin1') : o.flip ? `${h}.${p}.${sig.toString('base64url')}` : token, jwks }),
      });
    };
    const certs = jwks.keys.flatMap((k) => (k.x5c ?? []).map((b) => new Uint8Array(Buffer.from(b, 'base64'))));
    return { certs, nextUpdates: [], verify: (o = {}) => run(mk(o), o.expected ?? c.expected) };
  }

  const report = bytes(c.reportFile);
  const certChainPem = text(c.certChainFile);
  const bundle: NvidiaCollateralBundle = { driverRimXml: text(c.driverRimFile), vbiosRimXml: text(c.vbiosRimFile), crls: c.crlFiles.map(bytes) };
  const mk = (o: Mut) =>
    createNvidiaSpdmVerifier({
      rootSpkiSha256: o.wrongPin ? [bad(32)] : c.rootSpkiSha256,
      policy: { measurements: {}, leafSubjectIncludes: c.leafSubjectIncludes },
      resolveEvidence: () => ({ evidence: mut(o, report), certChainPem }),
      postVerify: nvidiaCollateralHook({ rimRootSpkiSha256: c.rimRootSpkiSha256, resolve: () => bundle, requireCrlIssuers: c.requireCrlIssuers }),
    });
  return { certs: [certChainPem], nextUpdates: [], verify: (o = {}) => run(mk(o), o.expected ?? c.expected) };
}

const PEM = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
function notAfters(certs: Array<string | Uint8Array>): number[] {
  const out: number[] = [];
  for (const c of certs) {
    const items = typeof c === 'string' ? (c.match(PEM) ?? []) : [Buffer.from(c)];
    for (const it of items) out.push(new X509Certificate(it).validToDate.getTime());
  }
  return out;
}

/** Judge a built case: positive verification, negative controls, expiry alarm. Never throws. */
export async function judgeCanary(b: Built, c: Pick<CanaryBase, 'id' | 'expected'> & { vendor: string }, nowMs: number, warnDays: number): Promise<CanaryResult> {
  const res: CanaryResult = { id: c.id, vendor: c.vendor, positive: { ok: false }, controls: [], expiry: { earliestNotAfter: null, daysLeft: null, alarm: false }, verdict: 'fail' };
  try {
    const pos = await b.verify();
    res.positive = { ok: pos.ok === true && pos.bound === true && pos.measured !== undefined, ...(pos.reason ? { reason: pos.reason } : {}) };
    const ctl = async (name: string, over: Parameters<Built['verify']>[0]) => {
      const r = await b.verify(over);
      res.controls.push({ name, denied: r.ok !== true, ...(r.reason ? { reason: r.reason } : {}) });
    };
    await ctl('relayed-binding', { expected: { ...c.expected, nonce: `${c.expected.nonce}-relayed` } });
    await ctl('flipped-evidence-byte', { flip: true });
    await ctl('wrong-trust-pin', { wrongPin: true });
    const ends = [...notAfters(b.certs), ...b.nextUpdates].filter((n) => Number.isFinite(n));
    if (ends.length > 0) {
      const earliest = Math.min(...ends);
      const daysLeft = Math.floor((earliest - nowMs) / 86_400_000);
      res.expiry = { earliestNotAfter: new Date(earliest).toISOString(), daysLeft, alarm: daysLeft < warnDays };
    }
    if (!res.positive.ok) res.why = `positive verification failed: ${res.positive.reason ?? 'not bound / no measured identity'}`;
    else if (res.controls.some((x) => !x.denied)) res.why = `negative control accepted: ${res.controls.filter((x) => !x.denied).map((x) => x.name).join(', ')}`;
    else if (ends.length === 0) res.why = 'no certificate or collateral expiry could be read from the evidence';
    else if (res.expiry.alarm) res.why = `collateral expires in ${res.expiry.daysLeft} days (< ${warnDays})`;
    else res.verdict = 'pass';
  } catch (e) {
    res.why = `canary error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`;
  }
  return res;
}

/** Run one case. Never throws: any problem (including missing evidence) is a failing verdict. */
export async function runCanaryCase(c: CanaryCase, dir: string, warnDays = 14): Promise<CanaryResult> {
  const nowMs = c.now === 'now' ? Date.now() : c.now;
  try {
    return await judgeCanary(buildCanary(c, dir, nowMs), c, nowMs, warnDays);
  } catch (e) {
    return { id: c.id, vendor: c.vendor, positive: { ok: false }, controls: [], expiry: { earliestNotAfter: null, daysLeft: null, alarm: false }, verdict: 'fail', why: `canary error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` };
  }
}

/** Run a whole manifest file. */
export async function runCanary(manifestPath: string): Promise<{ results: CanaryResult[]; ok: boolean }> {
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as CanaryManifest;
  if (!Array.isArray(manifest.cases) || manifest.cases.length === 0) return { results: [], ok: false };
  const dir = dirname(manifestPath);
  const results: CanaryResult[] = [];
  for (const c of manifest.cases) results.push(await runCanaryCase(c, dir, manifest.warnDays));
  return { results, ok: results.every((r) => r.verdict === 'pass') };
}

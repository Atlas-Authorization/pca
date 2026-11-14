#!/usr/bin/env node
/** pca-doctor: check a live PCA deployment's assumptions. Exit 1 on any fail (and on warn with --strict), 2 on usage errors. */
import { CHECK_GROUPS, configFromEnv, formatResults, loadConfigFile, mergeConfig, runDoctor, verdictOf, type CheckGroup } from './doctor';
import { scrubText } from './scrub';
import type { DoctorConfig } from './types';

export const USAGE = `pca-doctor [--url <deployment>] [options]

  --url URL              the live deployment (base URL of the API that verifies PCActns)
  --config FILE          JSON or JS config (see the pca-doctor guide); env and flags override it
  --store MODULE         replay-store adapter module (store conformance kit interface) for the atomicity / durability checks
  --store-option k=v     passed to the adapter factory (repeatable)
  --reference URL|local  clock reference (default https://www.google.com/generate_204)
  --max-skew-ms N        clock fail threshold (default 60000)
  --trusted-proxy-count N, --proxy-header H, --proxy-hops N   the deployment's proxy settings and the real hop count
  --pca-dir DIR          the deployed application's directory (its installed @atlasauth/pca is probed)
  --only a,b | --skip a,b   check groups: ${CHECK_GROUPS.join(', ')}
  --no-probe             do not send forged forwarding headers to the deployment
  --strict               warnings fail too
  --json                 machine-readable output

Env: PCA_DOCTOR_URL, PCA_DOCTOR_REFERENCE_URL, PCA_DOCTOR_STORE, TRUSTED_PROXY_COUNT, TRUSTED_PROXY_HEADER, PCA_TRUSTED_PROXY_HOPS,
     PCA_ALLOWED_SUITES (comma list), PCA_PQ_PINS (JSON), PCA_ALLOW_UNBOUND_PQ.`;

export interface DoctorArgs {
  config?: string;
  flags: DoctorConfig;
  only: CheckGroup[];
  json: boolean;
  strict: boolean;
  help: boolean;
}

const groups = (flag: string, v: string | undefined): CheckGroup[] => {
  const g = (v ?? '').split(',').filter(Boolean);
  const bad = g.filter((x) => !(CHECK_GROUPS as readonly string[]).includes(x));
  if (bad.length || g.length === 0) throw new Error(`${flag}: unknown check group(s) ${bad.join(', ') || '(none given)'}`);
  return g as CheckGroup[];
};
const num = (flag: string, v: string | undefined): number => {
  const n = Number(v);
  if (v === undefined || v === '' || !Number.isFinite(n)) throw new Error(`${flag} needs a number`);
  return n;
};

export function parseDoctorArgs(argv: readonly string[]): DoctorArgs {
  const a: DoctorArgs = { flags: {}, only: [...CHECK_GROUPS], json: false, strict: false, help: false };
  const f = a.flags;
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i]!;
    const next = (): string | undefined => argv[++i];
    switch (k) {
      case '--url':
        f.url = next();
        break;
      case '--config':
        a.config = next();
        break;
      case '--store':
        f.store = { ...f.store, adapter: next() };
        break;
      case '--store-option': {
        const kv = next() ?? '';
        const eq = kv.indexOf('=');
        if (eq < 1) throw new Error('--store-option needs k=v');
        f.store = { ...f.store, options: { ...f.store?.options, [kv.slice(0, eq)]: kv.slice(eq + 1) } };
        break;
      }
      case '--reference':
        f.clock = { ...f.clock, referenceUrl: next() };
        break;
      case '--max-skew-ms':
        f.clock = { ...f.clock, maxSkewMs: num(k, next()) };
        break;
      case '--trusted-proxy-count':
        f.proxy = { ...f.proxy, trustedProxyCount: num(k, next()) };
        break;
      case '--proxy-header':
        {
          const h = (next() ?? '').toLowerCase();
          if (!['x-forwarded-for', 'forwarded', 'x-real-ip'].includes(h)) throw new Error('--proxy-header must be x-forwarded-for, forwarded or x-real-ip');
          f.proxy = { ...f.proxy, header: h as never };
        }
        break;
      case '--proxy-hops':
        f.proxy = { ...f.proxy, hops: num(k, next()) };
        break;
      case '--no-probe':
        f.proxy = { ...f.proxy, probe: false };
        break;
      case '--pca-dir':
        f.verifier = { ...f.verifier, pcaDir: next() };
        break;
      case '--only':
        a.only = groups(k, next());
        break;
      case '--skip': {
        const s = groups(k, next());
        a.only = a.only.filter((g) => !s.includes(g));
        break;
      }
      case '--strict':
        a.strict = true;
        break;
      case '--json':
        a.json = true;
        break;
      case '-h':
      case '--help':
        a.help = true;
        break;
      default:
        throw new Error(`unknown argument ${k}`);
    }
  }
  return a;
}

export async function main(
  argv: readonly string[],
  env: Record<string, string | undefined> = process.env,
  print: (s: string) => void = console.log,
  printErr: (s: string) => void = console.error,
): Promise<number> {
  let a: DoctorArgs;
  let cfg: DoctorConfig;
  try {
    a = parseDoctorArgs(argv);
    if (a.help) {
      print(USAGE);
      return 0;
    }
    cfg = mergeConfig(a.config ? await loadConfigFile(a.config) : {}, configFromEnv(env), a.flags);
  } catch (e) {
    printErr(`${scrubText((e as Error).message)}\n\n${USAGE}`);
    return 2;
  }
  const results = await runDoctor(cfg, a.only);
  const verdict = verdictOf(results, a.strict);
  print(a.json ? JSON.stringify({ target: cfg.url ?? null, verdict, results }, null, 2) : formatResults(results, cfg.url, a.strict));
  return verdict === 'fail' ? 1 : 0;
}

// Stryker disable next-line all: process entry glue
if (require.main === module) void main(process.argv.slice(2)).then((code) => { process.exitCode = code; });

/**
 * Release tool: (re-)corroborate the Azure MAA key pins from independently captured vantage files and re-sign the
 * built-in pin manifest (src/attest-maa-pins.data.ts).
 *
 *   tsx scripts/sign-maa-pins.ts init-keys [--keys <file>]
 *   tsx scripts/sign-maa-pins.ts sign --vantage <label>=<file.json> (>= k times) --ms-root <der> --method "<text>"
 *                                     [--k 3] [--days 365] [--backdate-days 2] [--keys <file>] [--out <data.ts>] [--now <ms>] [--version <n>]
 *
 * A vantage file is the JSON printed by the capture script (`{ "<host>": [ { kid, chain: [ { cert_sha256, spki_sha256 } ] } ] }`,
 * leaf first). Signing is REFUSED unless: at least k distinct vantage labels are supplied; for every host every
 * vantage shows the identical stable key material (self-signed leaf SPKIs; for chained keys the intermediate and
 * root SPKIs - the chained leaf rotates and is not compared); and the chain root equals the SPKI of the Microsoft
 * root certificate you supply with --ms-root, which must be the `Microsoft Root Certificate Authority 2011`
 * (SHA-1 thumbprint 8F43288AD272F3103B6FB1428485EA3014C0BCFE, a value Microsoft publishes). Fetch that file from
 * Microsoft's PKI repository yourself and cross-check it against your OS trust store.
 *
 * Private key: ~/.pca-vm-state/pins-issuer-keys.json (mode 0600). NEVER commit it. Only the public key and the
 * signed manifest go into the data file.
 */
import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { createAllowlistManifest, signAllowlistManifest, verifyAllowlistManifest, type AllowlistEntry } from '../src/attest-allowlist';
import { b64u, canonicalBytes, unb64u } from '../src/hash';
import { generateKeyPair, publicKeyOf } from '../src/keys';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from '../src/pq';

const ALG = 'hybrid-ed25519-ml-dsa-65' as const;
const MS_ROOT_SHA1 = '8f43288ad272f3103b6fb1428485ea3014c0bcfe';
const MS_ROOT_CN = 'Microsoft Root Certificate Authority 2011';
const MS_INTERMEDIATE_CN = 'Microsoft Azure Attestation PCA 2019';
const DAY = 86_400_000;

interface KeyFile {
  issuer: string;
  alg: typeof ALG;
  edSecret: string;
  edPublic: string;
  mlDsaSecret: string;
  mlDsaPublic: string;
}
interface VantageKey {
  kid: string;
  chain: Array<{ cert_sha256: string; spki_sha256: string }>;
}
type VantageFile = Record<string, VantageKey[]>;

function arg(name: string, argv: string[]): string | undefined {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
}
function args(name: string, argv: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) if (argv[i] === `--${name}` && argv[i + 1] !== undefined) out.push(argv[i + 1]!);
  return out;
}
const die = (m: string): never => {
  process.stderr.write(`sign-maa-pins: ${m}\n`);
  process.exit(1);
};
const keyPath = (argv: string[]): string => arg('keys', argv) ?? join(homedir(), '.pca-vm-state', 'pins-issuer-keys.json');
const sha256hex = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex');
const spkiOf = (c: X509Certificate): string => sha256hex(new Uint8Array(c.publicKey.export({ type: 'spki', format: 'der' })));

function initKeys(argv: string[]): void {
  const path = keyPath(argv);
  if (existsSync(path)) die(`${path} already exists; refusing to overwrite a release key`);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const ed = generateKeyPair();
  const ml = mlDsa65Keygen(new Uint8Array(randomBytes(32)));
  const kf: KeyFile = {
    issuer: `pca-release-maa-pins-${new Date().getUTCFullYear()}-${randomBytes(3).toString('hex')}`,
    alg: ALG,
    edSecret: b64u(ed.secretKey),
    edPublic: b64u(ed.publicKey),
    mlDsaSecret: b64u(ml.secretKey),
    mlDsaPublic: encodeMlDsaPublicKey(ml.publicKey),
  };
  writeFileSync(path, `${JSON.stringify(kf, null, 2)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
  process.stdout.write(`wrote ${path} (0600); issuer ${kf.issuer}\n`);
}

function loadKeys(argv: string[]): KeyFile {
  const path = keyPath(argv);
  const kf = JSON.parse(readFileSync(path, 'utf8')) as KeyFile;
  if (kf.alg !== ALG) die('unexpected key file alg');
  if (b64u(publicKeyOf(unb64u(kf.edSecret))) !== kf.edPublic) die('key file ed25519 secret/public mismatch');
  return kf;
}

function sign(argv: string[]): void {
  const k = Number(arg('k', argv) ?? '3');
  if (!Number.isSafeInteger(k) || k < 3) die('k must be an integer >= 3');
  const vantages = new Map<string, VantageFile>();
  for (const spec of args('vantage', argv)) {
    const eq = spec.indexOf('=');
    if (eq < 1) die(`bad --vantage '${spec}' (want label=file)`);
    const label = spec.slice(0, eq);
    if (vantages.has(label)) die(`duplicate vantage label '${label}'`);
    vantages.set(label, JSON.parse(readFileSync(spec.slice(eq + 1), 'utf8')) as VantageFile);
  }
  if (vantages.size < k) die(`${vantages.size} distinct vantages < k=${k}`);
  const msRootPath = arg('ms-root', argv) ?? die('--ms-root <der> is required');
  const method = arg('method', argv) ?? die('--method is required');
  if (!/^[\x20-\x7e]{1,100}$/.test(method)) die('--method must be 1..100 printable ASCII chars');

  // Microsoft root: identity by subject + published thumbprint; its SPKI is the chain-root pin.
  const msRoot = new X509Certificate(readFileSync(msRootPath as string));
  const sha1 = createHash('sha1').update(new Uint8Array(msRoot.raw)).digest('hex');
  if (!msRoot.subject.includes(`CN=${MS_ROOT_CN}`) || msRoot.issuer !== msRoot.subject || !msRoot.verify(msRoot.publicKey)) die('--ms-root is not the self-signed Microsoft root');
  if (sha1 !== MS_ROOT_SHA1) die(`--ms-root SHA-1 ${sha1} != published ${MS_ROOT_SHA1}`);
  const rootSpki = spkiOf(msRoot);

  // Per host, every vantage must agree on the stable material.
  const hosts = new Set<string>();
  for (const v of vantages.values()) for (const h of Object.keys(v)) hosts.add(h);
  const selfSigned = new Map<string, string[]>();
  let intermediate: string | undefined;
  const evidence: Record<string, unknown> = {};
  for (const host of [...hosts].sort()) {
    let agreed: string | undefined;
    for (const [label, v] of vantages) {
      const keys = v[host];
      if (!keys) die(`vantage '${label}' has no data for ${host}`);
      const stable = (keys as VantageKey[])
        .map((kk) => {
          const first = kk.chain[0]!;
          const last = kk.chain[kk.chain.length - 1]!;
          return kk.chain.length === 1 ? `ss:${first.spki_sha256}` : `ch:${kk.chain[1]!.spki_sha256}>${last.spki_sha256}:${kk.chain.length}`;
        })
        .sort();
      const fp = JSON.stringify([...new Set(stable)]);
      if (agreed === undefined) agreed = fp;
      else if (agreed !== fp) die(`VANTAGE DISAGREEMENT for ${host}: '${label}' differs from the others`);
      (evidence[label] ??= {} as Record<string, unknown>) as Record<string, unknown>;
      (evidence[label] as Record<string, unknown>)[host] = [...new Set(stable)];
    }
    for (const s of JSON.parse(agreed!) as string[]) {
      if (s.startsWith('ss:')) selfSigned.set(host, [...(selfSigned.get(host) ?? []), s.slice(3)]);
      else {
        const m = /^ch:([0-9a-f]{64})>([0-9a-f]{64}):3$/.exec(s);
        if (!m) die(`unsupported chain shape '${s}' for ${host} (want leaf>PCA>root)`);
        if (m![2] !== rootSpki) die(`chain root ${m![2]} for ${host} is NOT the supplied Microsoft root ${rootSpki}`);
        if (intermediate !== undefined && intermediate !== m![1]) die('chained keys disagree on the intermediate');
        intermediate = m![1];
      }
    }
  }
  if (intermediate === undefined) die('no Microsoft-chained key in the vantage data');
  const pcaDer = arg('ms-intermediate', argv);
  if (pcaDer !== undefined) {
    const pca = new X509Certificate(readFileSync(pcaDer));
    if (!pca.subject.includes(`CN=${MS_INTERMEDIATE_CN}`) || !pca.verify(msRoot.publicKey) || spkiOf(pca) !== intermediate) die('--ms-intermediate does not match the pinned intermediate or is not signed by the Microsoft root');
  }

  const now = Number(arg('now', argv) ?? Date.now());
  const days = Number(arg('days', argv) ?? '365');
  const kf = loadKeys(argv);
  const entries: AllowlistEntry[] = [];
  for (const [host, spkis] of [...selfSigned].sort()) {
    for (const s of [...new Set(spkis)].sort()) entries.push({ kind: 'maa-signing-spki', value: s, label: `https://${host}` });
  }
  entries.push({ kind: 'maa-chain-root-spki', value: rootSpki, label: MS_ROOT_CN });
  entries.push({ kind: 'maa-chain-intermediate-spki', value: intermediate as string, label: MS_INTERMEDIATE_CN });
  entries.push({
    kind: 'attest-corroboration',
    value: sha256hex(canonicalBytes({ evidence, msRootSha1: sha1, k })),
    label: `vantages=${vantages.size};method=${method}`,
  });

  // Version = previous + 1 unless forced.
  const outPath = resolve(arg('out', argv) ?? join(dirname(new URL(import.meta.url).pathname), '..', 'src', 'attest-maa-pins.data.ts'));
  let version = Number(arg('version', argv) ?? '0');
  if (!version) {
    const m = existsSync(outPath) ? /BUILTIN_PINS_MIN_VERSION = (\d+)/.exec(readFileSync(outPath, 'utf8')) : null;
    version = m ? Number(m[1]) + 1 : 1;
  }
  // notBefore is backdated (default 2 days) so artifacts produced just before this release still fall in the window.
  const backdate = Number(arg('backdate-days', argv) ?? '2');
  const body = createAllowlistManifest({ version, issuedAt: now, notBefore: now - backdate * DAY, expiresAt: now + days * DAY, entries });
  const manifest = signAllowlistManifest(body, {
    issuer: kf.issuer,
    alg: ALG,
    secrets: { edSecret: unb64u(kf.edSecret), mlDsa: { secretKey: unb64u(kf.mlDsaSecret), publicKey: unb64u(kf.mlDsaPublic) } },
  });
  const issuerKey = { alg: ALG, keys: { edPub: kf.edPublic, mlDsaPub: kf.mlDsaPublic } };
  const check = verifyAllowlistManifest(manifest, { issuerKeys: { [kf.issuer]: issuerKey }, nowMs: now, minVersion: version });
  if (!check.ok) die(`self-check failed: ${check.code} ${check.reason}`);

  const ts = `// GENERATED by scripts/sign-maa-pins.ts - do not edit by hand. Contains ONLY public key material and a signed manifest.
// Regenerate: tsx scripts/sign-maa-pins.ts sign --vantage a=... --vantage b=... --vantage c=... --ms-root <der> --method "<text>"
import type { AllowlistIssuerKey, SignedAllowlistManifest } from './attest-allowlist';

export const BUILTIN_PINS_ISSUER_ID = ${JSON.stringify(kf.issuer)};
export const BUILTIN_PINS_MIN_VERSION = ${version};
export const BUILTIN_PINS_ISSUER_KEY: AllowlistIssuerKey = ${JSON.stringify(issuerKey, null, 2)};
export const BUILTIN_PINS_MANIFEST: SignedAllowlistManifest = ${JSON.stringify(manifest, null, 2)};
`;
  writeFileSync(outPath, ts);
  process.stdout.write(`signed v${version}: ${entries.length} entries, ${vantages.size} vantages, expires ${new Date(now + days * DAY).toISOString()} -> ${outPath}\n`);
}

const [cmd, ...rest] = process.argv.slice(2);
if (cmd === 'init-keys') initKeys(rest);
else if (cmd === 'sign') sign(rest);
else die('usage: sign-maa-pins.ts init-keys | sign --vantage label=file ... --ms-root der --method text');

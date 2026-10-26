/**
 * Multi-party Groth16 phase-2 ceremony tool (wraps snarkjs). Run from packages/pca:
 *   npx tsx circuits/ceremony/ceremony.ts <command> ...
 * Commands (full walk-through: docs/pca/validation/ceremony-runbook.md):
 *   init        --dir D --circuit ID --curve bn128|bls12-381 --r1cs F --ptau F --ptau-sha256 H [--min N]
 *   contribute  --in prev.zkey --out next.zkey --name NAME [--entropy TEXT]        (participant, offline)
 *   accept      --dir D --zkey next.zkey --name NAME                               (coordinator)
 *   beacon      --dir D --hash HEX64 [--iterations-exp 10]
 *   finalize    --dir D
 *   verify      --dir D [--min N] [--r1cs-sha256 H] [--transcript-sha256 H]       (anyone; exit 1 on any problem)
 *   publish     --dir D --out OUT                                                  (transcript, vkey, hashes)
 * Every command fails closed: it throws, exits non-zero and writes nothing it could not check.
 */
import { createHash, randomBytes } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkTranscript, transcriptSha256, vkId, type CeremonyTranscript } from '../../src/zk-ceremony';

const PKG = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SNARKJS = join(PKG, 'node_modules', 'snarkjs', 'build', 'cli.cjs');
const snark = (...a: string[]): string => execFileSync('node', [SNARKJS, ...a], { encoding: 'utf8', maxBuffer: 1 << 26, env: { ...process.env, NODE_OPTIONS: process.env.NODE_OPTIONS ?? '--max-old-space-size=12000' } });
const sha = (f: string): string => createHash('sha256').update(readFileSync(f)).digest('hex');
const need = (f: string): string => { if (!existsSync(f)) throw new Error(`missing file: ${f}`); return f; };
const readT = (dir: string): CeremonyTranscript => JSON.parse(readFileSync(need(join(dir, 'transcript.json')), 'utf8'));
const writeT = (dir: string, t: CeremonyTranscript): void => writeFileSync(join(dir, 'transcript.json'), JSON.stringify(t, null, 2) + '\n');
const zk = (dir: string, name: string): string => join(dir, 'zkeys', name);
const curveArg = (c: string): string => (c === 'bn128' ? 'bn128' : 'bls12381');

function args(argv: string[]): Record<string, string> {
  const o: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 2) {
    const k = argv[i];
    if (!k?.startsWith('--') || argv[i + 1] === undefined) throw new Error(`bad argument near ${k}`);
    o[k.slice(2)] = argv[i + 1]!;
  }
  return o;
}
const req = (o: Record<string, string>, k: string): string => { const v = o[k]; if (!v) throw new Error(`--${k} is required`); return v; };

export interface VerifyResult { ok: boolean; problems: string[]; transcriptSha256?: string; vkId?: string }

/** Verify a ceremony directory end to end. Never throws; any failure is a problem and `ok` is false. */
export function verifyCeremony(dir: string, o: { min?: number; r1csSha256?: string; transcriptSha256?: string } = {}): VerifyResult {
  const problems: string[] = [];
  try {
    const t = readT(dir);
    const bad = checkTranscript(t, { minContributions: o.min, r1csSha256: o.r1csSha256 });
    if (bad) problems.push(bad);
    const th = transcriptSha256(t);
    if (o.transcriptSha256 && o.transcriptSha256 !== th) problems.push('transcript hash differs from the pinned hash');
    const r1cs = join(dir, 'circuit.r1cs'), ptau = join(dir, 'phase1.ptau');
    if (!existsSync(r1cs) || sha(r1cs) !== t.r1csSha256) problems.push('circuit.r1cs missing or its hash differs from the transcript');
    if (!existsSync(ptau) || sha(ptau) !== t.ptauSha256) problems.push('phase1.ptau missing or its hash differs from the transcript');
    const chain: Array<[string, string]> = [['0000.zkey', t.initZkeySha256], ...t.contributions.map((c, i): [string, string] => [`${String(i + 1).padStart(4, '0')}.zkey`, c.zkeySha256]), ['final.zkey', t.finalZkeySha256 ?? '']];
    for (const [f, h] of chain) {
      if (!existsSync(zk(dir, f))) problems.push(`missing ${f}`);
      else if (sha(zk(dir, f)) !== h) problems.push(`${f} hash differs from the transcript`);
    }
    if (problems.length === 0) {
      // cryptographic check of the whole chain of contributions and the beacon back to the initial key and the phase-1 file
      const out = snark('zkey', 'verify', r1cs, ptau, zk(dir, 'final.zkey'));
      if (!/ZKey Ok!/.test(out)) problems.push('snarkjs zkey verify did not report ZKey Ok');
      if (!out.toLowerCase().includes(t.beacon!.hashHex.toLowerCase())) problems.push('the beacon hash is not recorded in the final key');
      const vk = join(dir, 'verification_key.json');
      if (!existsSync(vk)) problems.push('missing verification_key.json');
      else {
        snark('zkey', 'export', 'verificationkey', zk(dir, 'final.zkey'), join(dir, '.vk-check.json'));
        const a = readFileSync(vk, 'utf8'), b = readFileSync(join(dir, '.vk-check.json'), 'utf8');
        if (JSON.stringify(JSON.parse(a)) !== JSON.stringify(JSON.parse(b))) problems.push('verification_key.json is not the key of the final proving key');
        if (vkId(JSON.parse(a)) !== t.vkId) problems.push('vkId in the transcript does not match verification_key.json');
      }
    }
    return { ok: problems.length === 0, problems, transcriptSha256: th, vkId: t.vkId };
  } catch (e) {
    problems.push(`error: ${(e as Error).message.split('\n')[0]}`);
    return { ok: false, problems };
  }
}

function main(argv: string[]): void {
  const [cmd, ...rest] = argv;
  const o = args(rest);
  if (cmd === 'init') {
    const dir = req(o, 'dir');
    const curve = req(o, 'curve');
    if (curve !== 'bn128' && curve !== 'bls12-381') throw new Error('--curve must be bn128 or bls12-381');
    if (existsSync(join(dir, 'transcript.json'))) throw new Error('refusing to re-initialise an existing ceremony');
    const ptau = need(req(o, 'ptau'));
    const pin = req(o, 'ptau-sha256').toLowerCase();
    if (sha(ptau) !== pin) throw new Error('phase-1 file does not match --ptau-sha256 (pin the published, widely contributed file)');
    mkdirSync(join(dir, 'zkeys'), { recursive: true });
    copyFileSync(need(req(o, 'r1cs')), join(dir, 'circuit.r1cs'));
    copyFileSync(ptau, join(dir, 'phase1.ptau'));
    snark('groth16', 'setup', join(dir, 'circuit.r1cs'), join(dir, 'phase1.ptau'), zk(dir, '0000.zkey'));
    writeT(dir, { version: 1, circuit: req(o, 'circuit'), curve, r1csSha256: sha(join(dir, 'circuit.r1cs')), ptauSha256: pin, initZkeySha256: sha(zk(dir, '0000.zkey')), minContributions: Number(o.min ?? 3), contributions: [] });
    console.log(`initialised ${dir}; send zkeys/0000.zkey to the first participant (curve ${curveArg(curve)})`);
  } else if (cmd === 'contribute') {
    const inF = need(req(o, 'in')), outF = req(o, 'out'), name = req(o, 'name');
    if (existsSync(outF)) throw new Error('--out already exists');
    // snarkjs mixes this with its own CSPRNG; add your own text with --entropy (a keyboard mash, a dice roll), then forget it.
    snark('zkey', 'contribute', inF, outF, `--name=${name}`, `-e=${randomBytes(64).toString('hex')}${o.entropy ?? ''}`);
    const r = { name, prevZkeySha256: sha(inF), zkeySha256: sha(outF) };
    writeFileSync(`${outF}.receipt.json`, JSON.stringify(r, null, 2) + '\n');
    console.log(`contributed. Keep this receipt and publish it yourself:\n${JSON.stringify(r)}\nSend ${outF} back to the coordinator. Destroy any copy of your entropy. Never reuse the toxic waste of this run (there is none stored).`);
  } else if (cmd === 'accept') {
    const dir = req(o, 'dir'), t = readT(dir), name = req(o, 'name'), f = need(req(o, 'zkey'));
    if (t.beacon) throw new Error('the beacon is already applied; no more contributions');
    const prev = t.contributions.length ? t.contributions[t.contributions.length - 1]!.zkeySha256 : t.initZkeySha256;
    const i = t.contributions.length + 1;
    const dest = zk(dir, `${String(i).padStart(4, '0')}.zkey`);
    copyFileSync(f, dest);
    const out = snark('zkey', 'verify', join(dir, 'circuit.r1cs'), join(dir, 'phase1.ptau'), dest);
    if (!/ZKey Ok!/.test(out)) throw new Error('contribution rejected: zkey verify failed');
    if (t.contributions.some((c) => c.name === name)) throw new Error('duplicate participant name');
    t.contributions.push({ index: i - 1, name, prevZkeySha256: prev, zkeySha256: sha(dest) });
    // the contribution must have changed the key and extended the chain by exactly one step
    if (t.contributions[i - 1]!.zkeySha256 === prev) throw new Error('contribution rejected: key unchanged');
    writeT(dir, t);
    console.log(`accepted contribution ${i} from ${name}; send ${dest} to the next participant`);
  } else if (cmd === 'beacon') {
    const dir = req(o, 'dir'), t = readT(dir), h = req(o, 'hash').toLowerCase(), exp = Number(o['iterations-exp'] ?? 10);
    if (!/^[0-9a-f]{64}$/.test(h)) throw new Error('--hash must be 64 hex characters (e.g. a future block hash announced in advance)');
    if (t.contributions.length < 2 || t.contributions.length < t.minContributions) throw new Error('not enough contributions before the beacon');
    if (t.beacon) throw new Error('beacon already applied');
    const last = t.contributions[t.contributions.length - 1]!;
    snark('zkey', 'beacon', zk(dir, `${String(t.contributions.length).padStart(4, '0')}.zkey`), zk(dir, 'final.zkey'), h, String(exp), '-n=beacon');
    t.beacon = { hashHex: h, iterationsExp: exp, prevZkeySha256: last.zkeySha256, zkeySha256: sha(zk(dir, 'final.zkey')) };
    t.finalZkeySha256 = t.beacon.zkeySha256;
    writeT(dir, t);
    console.log('beacon applied; run finalize');
  } else if (cmd === 'finalize') {
    const dir = req(o, 'dir'), t = readT(dir);
    if (!t.beacon) throw new Error('apply the beacon first');
    const vk = join(dir, 'verification_key.json');
    snark('zkey', 'export', 'verificationkey', zk(dir, 'final.zkey'), vk);
    t.vkId = vkId(JSON.parse(readFileSync(vk, 'utf8')));
    writeT(dir, t);
    const v = verifyCeremony(dir);
    if (!v.ok) throw new Error(`finalize: verification failed: ${v.problems.join('; ')}`);
    console.log(`finalized. vkId ${t.vkId}\ntranscript sha256 ${v.transcriptSha256} (publish this hash out of band)`);
  } else if (cmd === 'verify') {
    const v = verifyCeremony(req(o, 'dir'), { min: o.min ? Number(o.min) : undefined, r1csSha256: o['r1cs-sha256'], transcriptSha256: o['transcript-sha256'] });
    if (!v.ok) { console.error(`verify FAILED:\n- ${v.problems.join('\n- ')}`); process.exit(1); }
    console.log(`verify ok. vkId ${v.vkId}\ntranscript sha256 ${v.transcriptSha256}`);
  } else if (cmd === 'publish') {
    const dir = req(o, 'dir'), out = req(o, 'out');
    const v = verifyCeremony(dir);
    if (!v.ok) throw new Error(`refusing to publish an unverified ceremony: ${v.problems.join('; ')}`);
    mkdirSync(out, { recursive: true });
    for (const f of ['transcript.json', 'verification_key.json']) copyFileSync(join(dir, f), join(out, f));
    const t = readT(dir);
    const hashes = { transcriptSha256: v.transcriptSha256, vkId: v.vkId, r1csSha256: t.r1csSha256, ptauSha256: t.ptauSha256, finalZkeySha256: t.finalZkeySha256, contributions: t.contributions.map((c) => ({ name: c.name, zkeySha256: c.zkeySha256 })) };
    writeFileSync(join(out, 'HASHES.json'), JSON.stringify(hashes, null, 2) + '\n');
    console.log(`published to ${out}; the proving keys are published separately (large)`);
  } else {
    throw new Error(`unknown command "${cmd ?? ''}" (init|contribute|accept|beacon|finalize|verify|publish)`);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try { main(process.argv.slice(2)); } catch (e) { console.error(`ceremony: ${(e as Error).message}`); process.exit(1); }
}

// source.ts - fetch (out of band), pin and load a pinned source. The generator refuses on a digest mismatch.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { load as yamlLoad } from 'js-yaml';
import { sha256hex } from './pack';
import type { SourceDecl } from './types';

export const SRC_DIR = join(__dirname, '../packs');
export const urlOf = (s: SourceDecl): string => s.url ?? `https://raw.githubusercontent.com/${s.repo}/${s.ref}/${s.path}`;
export const sourcesFile = (pack: string): string => join(SRC_DIR, `${pack}.sources.json`);

export function readSources(pack: string): SourceDecl[] {
  return JSON.parse(readFileSync(sourcesFile(pack), 'utf8')) as SourceDecl[];
}

async function download(url: string): Promise<Buffer> {
  for (let i = 0; i < 4; i++) {
    try {
      const r = await fetch(url, { headers: { 'user-agent': 'pca-actions-packs' } });
      if (!r.ok) throw new Error(`${r.status} ${url}`);
      return Buffer.from(await r.arrayBuffer());
    } catch (e) {
      if (i === 3) throw e;
      await new Promise((res) => setTimeout(res, 1500 * (i + 1)));
    }
  }
  throw new Error('unreachable');
}

/** Resolve a branch/HEAD ref to a commit sha (git ls-remote), for GitHub sources. */
export function resolveRef(repo: string, ref: string): string {
  if (/^[0-9a-f]{40}$/.test(ref)) return ref;
  const out = execFileSync('git', ['ls-remote', `https://github.com/${repo}.git`, ref === 'HEAD' ? 'HEAD' : `refs/heads/${ref}`], { encoding: 'utf8' });
  const sha = out.split(/\s+/)[0];
  if (!sha || !/^[0-9a-f]{40}$/.test(sha)) throw new Error(`cannot resolve ${repo}@${ref}`);
  return sha;
}

export async function ensureBytes(pack: string, s: SourceDecl, dir: string): Promise<Buffer> {
  const f = join(dir, pack, s.id.replace(/[^A-Za-z0-9._-]/g, '_'));
  if (existsSync(f)) return readFileSync(f);
  const b = await download(urlOf(s));
  mkdirSync(dirname(f), { recursive: true });
  writeFileSync(f, b);
  return b;
}

/** Download every source of a pack, resolve refs to commits, write sha256 + bytes into the sources file. */
export async function pin(pack: string, dir: string): Promise<void> {
  const srcs = readSources(pack);
  for (const s of srcs) {
    if (s.repo) s.ref = resolveRef(s.repo, s.ref ?? 'HEAD');
    const f = join(dir, pack, s.id.replace(/[^A-Za-z0-9._-]/g, '_'));
    if (existsSync(f)) { try { writeFileSync(f, ''); } catch { /* ignore */ } }
    const b = await download(urlOf(s));
    mkdirSync(dirname(f), { recursive: true });
    writeFileSync(f, b);
    s.sha256 = sha256hex(b);
    s.bytes = b.length;
  }
  writeFileSync(sourcesFile(pack), `${JSON.stringify(srcs, null, 2)}\n`);
}

/** Load a pinned source: verify the digest, gunzip, parse. */
export async function loadSource(pack: string, s: SourceDecl, dir: string): Promise<unknown> {
  if (!s.sha256) throw new Error(`${pack}/${s.id}: not pinned (run pin)`);
  const raw = await ensureBytes(pack, s, dir);
  if (sha256hex(raw) !== s.sha256) throw new Error(`${pack}/${s.id}: spec digest mismatch (upstream changed; re-pin and re-review)`);
  const b = s.gz ? gunzipSync(raw) : raw;
  const text = b.toString('utf8');
  if (s.kind === 'graphql') return text;
  const name = (s.path ?? s.url ?? s.id).toLowerCase();
  return /\.ya?ml$/.test(name) ? yamlLoad(text) : JSON.parse(text);
}

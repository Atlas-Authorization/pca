/**
 * A file-backed {@link MeshWitnessStore} (NODE ONLY: imports node:fs; not re-exported from the package index).
 *
 * Every save writes a temporary file, fsyncs it, renames it over the real file and fsyncs the directory, so a
 * crash leaves the old state or the new one, never a torn file. The file carries a digest of its state; a file
 * that does not parse, has the wrong shape or fails the digest makes `load` throw. A witness never starts empty
 * over a damaged file. A missing file is a first run. Single process: two witnesses must not share one file.
 */
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, renameSync, writeSync } from 'node:fs';
import { dirname } from 'node:path';
import { hashCanonical } from './hash';
import type { MeshWitnessState, MeshWitnessStore } from './mesh';

export class FileMeshWitnessStore implements MeshWitnessStore {
  constructor(private readonly path: string) {}

  load(): MeshWitnessState | undefined {
    if (!existsSync(this.path)) return undefined;
    let doc: unknown;
    try {
      doc = JSON.parse(readFileSync(this.path, 'utf8'));
    } catch {
      throw new Error('FileMeshWitnessStore: the state file is not valid JSON; refusing to start empty');
    }
    const d = doc as { v?: unknown; state?: unknown; digest?: unknown } | null;
    if (d === null || typeof d !== 'object' || d.v !== 1 || typeof d.digest !== 'string' || typeof d.state !== 'object' || d.state === null) {
      throw new Error('FileMeshWitnessStore: the state file has an unexpected shape; refusing to start empty');
    }
    if (hashCanonical(d.state) !== d.digest) throw new Error('FileMeshWitnessStore: the state file fails its digest; refusing to start empty');
    return d.state as MeshWitnessState;
  }

  save(state: MeshWitnessState): void {
    const body = JSON.stringify({ v: 1, state, digest: hashCanonical(state) });
    const tmp = `${this.path}.tmp`;
    const fd = openSync(tmp, 'w', 0o600);
    try {
      writeSync(fd, body);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, this.path);
    const dfd = openSync(dirname(this.path), 'r');
    try {
      fsyncSync(dfd);
    } finally {
      closeSync(dfd);
    }
  }
}

import { execFileSync } from 'node:child_process';
import { b64u, generateKeyPair } from '@atlasauth/pca';
import type { Git, InitDeps } from './types';

/** The real git. Any failure (not a repository, git missing) is a non-zero code, never a throw. */
export const realGit: Git = (cwd, args) => {
  try {
    return { code: 0, out: execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 15_000 }) };
  } catch (e) {
    const status = (e as { status?: number }).status;
    return { code: typeof status === 'number' && status > 0 ? status : 1, out: '' };
  }
};

export const realDeps: InitDeps = {
  git: realGit,
  newKey: () => {
    const kp = generateKeyPair();
    return { secret: b64u(kp.secretKey), publicKey: b64u(kp.publicKey) };
  },
};

export interface GitState {
  repo: boolean;
  dirty: boolean;
  tracked: (path: string) => boolean;
}

export function gitState(git: Git, dir: string): GitState {
  const repo = git(dir, ['rev-parse', '--is-inside-work-tree']).code === 0;
  if (!repo) return { repo, dirty: false, tracked: () => false };
  return {
    repo,
    dirty: git(dir, ['status', '--porcelain', '--', '.']).out.trim() !== '',
    tracked: (path) => git(dir, ['ls-files', '--error-unmatch', '--', path]).code === 0,
  };
}

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';

const calls: Array<{ cmd: string; args: string[]; opts: unknown }> = [];
vi.mock('node:child_process', () => ({
  execFileSync: (cmd: string, args: string[], opts: unknown) => {
    calls.push({ cmd, args, opts });
    return Buffer.alloc(0);
  },
}));

import { generateIdentity } from './certs';

describe('generateIdentity executes openssl with piped stdio (no terminal leakage of key material)', () => {
  it('both invocations use exactly { stdio: "pipe" } and the given binary', () => {
    const d = mkdtempSync(join(tmpdir(), 'pca-certs-exec-'));
    generateIdentity(join(d, 'x'), 'cn-1', '/opt/openssl-custom');
    generateIdentity(join(d, 'y'), 'cn-2');
    rmSync(d, { recursive: true, force: true });
    expect(calls.length).toBe(4);
    expect(calls.map((c) => c.cmd)).toEqual(['/opt/openssl-custom', '/opt/openssl-custom', 'openssl', 'openssl']);
    for (const c of calls) expect(c.opts).toEqual({ stdio: 'pipe' });
    expect(calls[0]!.args.slice(0, 5)).toEqual(['ecparam', '-name', 'prime256v1', '-genkey', '-noout']);
    expect(calls[1]!.args).toContain('/CN=cn-1');
  });
});

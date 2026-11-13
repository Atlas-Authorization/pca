import { isAuthorizedFor } from '@atlasauth/pca';
import type { AuthorizeResult, PcaGuardResult, PcaOperation } from '@atlasauth/pca';

/** What one authorized operation needs from the OS, written by the tool author like the egress mapping. */
export interface Needs {
  fs?: { path: string; mode: 'r' | 'rw' | 'x' }[];
  net?: { host: string; port: number }[];
}

export interface SandboxPolicy {
  v: 1;
  fs: { read: string[]; write: string[]; exec: string[] };
  /** The only network route is the egress proxy; `hosts` is what the proxy will be asked to admit (documentation, not enforcement here). */
  net: { proxy: { host: '127.0.0.1' | '::1'; port: number } | null; hosts: string[] };
}

export type AuthorizedOp = { result: AuthorizeResult | PcaGuardResult; operation: PcaOperation };

// Absolute, normalized, and only characters that need no escaping in a seccomp/Landlock/SBPL string. Refuse, never escape.
const PATH_RE = /^\/[A-Za-z0-9._+@=,:~ /-]*$/;
const HOST_RE = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/;

function checkPath(p: string): string {
  if (!PATH_RE.test(p) || p.includes('//') || (p.length > 1 && p.endsWith('/')) || p.split('/').some((s) => s === '.' || s === '..')) throw new Error(`bad_path: ${JSON.stringify(p).slice(0, 80)}`);
  return p;
}

/**
 * Compile the OS policy from what was actually authorized: only operations that `isAuthorizedFor` allows contribute, so a
 * denied or unrelated operation widens nothing. Paths and hosts are validated strictly (a path with a quote or a
 * parenthesis is refused, not escaped), duplicates are merged, output is sorted so the same grant gives the same bytes.
 * `write` implies read of the same path.
 */
export function compilePolicy(items: readonly AuthorizedOp[], needsOf: (op: PcaOperation) => Needs | null, proxyPort: number | null = null): SandboxPolicy {
  const needs: Needs[] = [];
  for (const { result, operation } of items) {
    if (!isAuthorizedFor(result, operation)) throw new Error('not_authorized: result does not allow exactly this operation');
    const n = needsOf(operation);
    if (n) needs.push(n);
  }
  return policyFromNeeds(needs, proxyPort);
}

/** The pure core of {@link compilePolicy}: validate, merge, sort. Shared test vectors pin its output and every generator's output byte for byte. */
export function policyFromNeeds(needs: readonly Needs[], proxyPort: number | null = null): SandboxPolicy {
  const read = new Set<string>();
  const write = new Set<string>();
  const exec = new Set<string>();
  const hosts = new Set<string>();
  for (const n of needs) {
    for (const f of n.fs ?? []) {
      const p = checkPath(f.path);
      if (f.mode === 'x') exec.add(p);
      else if (f.mode === 'r' || f.mode === 'rw') {
        read.add(p);
        if (f.mode === 'rw') write.add(p);
      } else throw new Error('bad_mode');
    }
    for (const h of n.net ?? []) {
      if (!HOST_RE.test(h.host) || !Number.isInteger(h.port) || h.port < 1 || h.port > 65535) throw new Error('bad_net_need');
      hosts.add(`${h.host}:${h.port}`);
    }
  }
  if (hosts.size > 0 && proxyPort === null) throw new Error('net_needs_proxy: network access exists only through the egress proxy; pass its port');
  if (proxyPort !== null && (!Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535)) throw new Error('bad_proxy_port');
  const s = (x: Set<string>) => [...x].sort();
  return { v: 1, fs: { read: s(read), write: s(write), exec: s(exec) }, net: { proxy: proxyPort === null ? null : { host: '127.0.0.1', port: proxyPort }, hosts: s(hosts) } };
}

/** Syscalls for a statically linked tool that reads, computes and exits. A starting point: confirm with your tool under strace. */
const BASE = ['read', 'write', 'close', 'fstat', 'newfstatat', 'statx', 'lseek', 'mmap', 'mprotect', 'munmap', 'mremap', 'brk', 'madvise', 'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn', 'sigaltstack', 'pread64', 'pwrite64', 'readv', 'writev', 'openat', 'getdents64', 'fcntl', 'getcwd', 'readlink', 'readlinkat', 'dup', 'dup3', 'pipe2', 'poll', 'ppoll', 'epoll_create1', 'epoll_ctl', 'epoll_pwait', 'eventfd2', 'futex', 'set_tid_address', 'set_robust_list', 'rseq', 'arch_prctl', 'prlimit64', 'sched_yield', 'nanosleep', 'clock_nanosleep', 'clock_gettime', 'gettimeofday', 'getrandom', 'getpid', 'gettid', 'getuid', 'geteuid', 'getgid', 'getegid', 'uname', 'tgkill', 'exit', 'exit_group'];
const NET = ['connect', 'getsockopt', 'setsockopt', 'getsockname', 'getpeername', 'sendto', 'recvfrom', 'sendmsg', 'recvmsg', 'shutdown'];
const EXEC = ['execve', 'execveat'];
const AF_INET = 2;
const AF_INET6 = 10;

/** Docker/OCI-format seccomp profile: deny by default; network syscalls only when the policy has a proxy; `socket` only for AF_INET/AF_INET6; exec only when the grant names a binary. seccomp cannot see paths or addresses: pair it with the Landlock rules or a network namespace. */
export function seccompProfile(p: SandboxPolicy) {
  const syscalls: { names: string[]; action: string; args?: { index: number; value: number; op: string }[] }[] = [{ names: [...BASE].sort(), action: 'SCMP_ACT_ALLOW' }];
  if (p.net.proxy) {
    syscalls.push({ names: [...NET].sort(), action: 'SCMP_ACT_ALLOW' });
    for (const d of [AF_INET, AF_INET6]) syscalls.push({ names: ['socket'], action: 'SCMP_ACT_ALLOW', args: [{ index: 0, value: d, op: 'SCMP_CMP_EQ' }] });
  }
  if (p.fs.exec.length > 0) syscalls.push({ names: [...EXEC], action: 'SCMP_ACT_ALLOW' });
  return {
    defaultAction: 'SCMP_ACT_ERRNO',
    defaultErrnoRet: 1,
    archMap: [
      { architecture: 'SCMP_ARCH_X86_64', subArchitectures: [] as string[] },
      { architecture: 'SCMP_ARCH_AARCH64', subArchitectures: [] as string[] },
    ],
    syscalls,
  };
}

/** Landlock ruleset (access-right names from the kernel UAPI; network rules need ABI 4). Handle every right, allow only what the grant names. */
export function landlockRuleset(p: SandboxPolicy) {
  const handled_fs = ['EXECUTE', 'WRITE_FILE', 'READ_FILE', 'READ_DIR', 'REMOVE_DIR', 'REMOVE_FILE', 'MAKE_CHAR', 'MAKE_DIR', 'MAKE_REG', 'MAKE_SOCK', 'MAKE_FIFO', 'MAKE_BLOCK', 'MAKE_SYM', 'REFER', 'TRUNCATE'].map((x) => `LANDLOCK_ACCESS_FS_${x}`);
  const paths = [...new Set([...p.fs.read, ...p.fs.write, ...p.fs.exec])].sort();
  const fs = paths.map((path) => ({
    path,
    // execve opens the binary for reading, so the kernel also demands READ_FILE for an exec grant (EACCES otherwise)
    access: [
      ...new Set([
        ...(p.fs.exec.includes(path) ? ['EXECUTE', 'READ_FILE'] : []),
        ...(p.fs.read.includes(path) ? ['READ_FILE', 'READ_DIR'] : []),
        ...(p.fs.write.includes(path) ? ['WRITE_FILE', 'TRUNCATE', 'MAKE_REG', 'MAKE_DIR', 'REMOVE_FILE', 'REMOVE_DIR'] : []),
      ]),
    ].map((x) => `LANDLOCK_ACCESS_FS_${x}`),
  }));
  return {
    v: 1,
    abi_min: 4,
    handled_access_fs: handled_fs,
    handled_access_net: ['LANDLOCK_ACCESS_NET_BIND_TCP', 'LANDLOCK_ACCESS_NET_CONNECT_TCP'],
    rules: { fs, net: p.net.proxy ? [{ port: p.net.proxy.port, access: ['LANDLOCK_ACCESS_NET_CONNECT_TCP'] }] : [] },
  };
}

/** macOS sandbox profile (SBPL for sandbox-exec(1), deprecated but present): deny by default; the base lines are what a dynamically linked binary needs to start. */
export function macosProfile(p: SandboxPolicy): string {
  const q = (s: string) => `"${s}"`; // paths were validated to need no escaping
  const lines = [
    '(version 1)',
    '(deny default)',
    '(allow sysctl-read)',
    '(allow process-fork)',
    '(allow mach-lookup)',
    '(allow file-read-metadata)',
    '(allow file-read* (literal "/") (literal "/dev/null") (literal "/dev/urandom") (subpath "/usr/lib") (subpath "/System/Library") (subpath "/private/var/db/dyld") (subpath "/System/Volumes/Preboot/Cryptexes"))',
  ];
  for (const x of p.fs.exec) lines.push(`(allow process-exec (literal ${q(x)}))`, `(allow file-read* (literal ${q(x)}))`);
  for (const r of p.fs.read) lines.push(`(allow file-read* (subpath ${q(r)}))`);
  for (const w of p.fs.write) lines.push(`(allow file-write* (subpath ${q(w)}))`);
  if (p.net.proxy) lines.push(`(allow network-outbound (remote tcp ${q(`localhost:${p.net.proxy.port}`)}))`);
  return `${lines.join('\n')}\n`;
}

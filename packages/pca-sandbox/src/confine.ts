import { landlockRuleset, seccompProfile, type SandboxPolicy } from './profiles';

/**
 * Flatten the GENERATED seccomp and Landlock profiles into the flags of the reference helper `linux/pca-confine.c`, so what the
 * helper enforces is exactly what the generators produced (it never reads a second source of truth). Run it as
 * `pca-confine <flags> -- <command>`.
 */
export function confineArgs(policy: SandboxPolicy): string[] {
  const ll = landlockRuleset(policy);
  const sc = seccompProfile(policy);
  const short = (n: string) => n.replace(/^LANDLOCK_ACCESS_/, '');
  const args: string[] = ['--fs-handled', ll.handled_access_fs.map(short).join(',')];
  if (ll.rules.net.length > 0 || policy.net.proxy) args.push('--net-handled', ll.handled_access_net.map(short).join(','));
  for (const r of ll.rules.fs) args.push('--fs', `${r.path}:${r.access.map(short).join(',')}`);
  for (const r of ll.rules.net) args.push('--net', `${r.port}:${r.access.map(short).join(',')}`);
  for (const s of sc.syscalls) {
    if (s.args) for (const a of s.args) for (const n of s.names) args.push('--allow-arg', `${n}:${a.index}:${a.value}`);
    else for (const n of s.names) args.push('--allow', n);
  }
  return args;
}

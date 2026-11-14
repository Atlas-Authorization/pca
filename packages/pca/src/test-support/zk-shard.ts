/** Selection of circuit witness-perturbation cases for one CI job: PCA_ZK_CIRCUIT=<circuit> and PCA_ZK_SHARD=k/n (both unset = everything). */
export type ZkCircuit = 'compliance' | 'policyvm' | 'policyvm_bound';
export const ZK_CIRCUITS: readonly ZkCircuit[] = ['compliance', 'policyvm', 'policyvm_bound'];

/** Parse "k/n" (1 <= k <= n); throws on anything else so a typo in the workflow fails loudly instead of running nothing. */
export function parseShard(s: string | undefined): { k: number; n: number } {
  if (s === undefined || s === '') return { k: 1, n: 1 };
  const m = /^([1-9][0-9]*)\/([1-9][0-9]*)$/.exec(s);
  if (!m || Number(m[1]) > Number(m[2])) throw new Error(`bad PCA_ZK_SHARD ${JSON.stringify(s)} (want k/n with 1 <= k <= n)`);
  return { k: Number(m[1]), n: Number(m[2]) };
}

/** Round-robin: item i belongs to shard (i mod n) + 1, so the shards partition the list exactly. */
export function shardItems<T>(items: readonly T[], k: number, n: number): T[] {
  return items.filter((_, i) => i % n === k - 1);
}

/** True when this job runs `circuit` (PCA_ZK_CIRCUIT unset = all; an unknown name throws). */
export function circuitSelected(circuit: ZkCircuit, env = process.env.PCA_ZK_CIRCUIT): boolean {
  if (env === undefined || env === '') return true;
  if (!ZK_CIRCUITS.includes(env as ZkCircuit)) throw new Error(`bad PCA_ZK_CIRCUIT ${JSON.stringify(env)}`);
  return env === circuit;
}

/** The slice of `items` this job owns for `circuit` (empty when the job targets another circuit). */
export function myShard<T>(circuit: ZkCircuit, items: readonly T[], env = process.env): T[] {
  if (!circuitSelected(circuit, env.PCA_ZK_CIRCUIT)) return [];
  const { k, n } = parseShard(env.PCA_ZK_SHARD);
  return shardItems(items, k, n);
}

/** The control cases run once per circuit family: in the job that owns shard 1 of policyvm_bound (or when unfiltered). */
export function runsControls(env = process.env): boolean {
  return circuitSelected('policyvm_bound', env.PCA_ZK_CIRCUIT) && parseShard(env.PCA_ZK_SHARD).k === 1;
}

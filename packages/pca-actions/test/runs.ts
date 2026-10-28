// PCA_PROP_RUNS lowers every property test's case count (the mutation run and local smoke runs); unset = the full count.
export const runs = (n: number): number => Math.min(n, Number(process.env.PCA_PROP_RUNS ?? n));

// Oracle (python lane): the pca-state profile of @atlasauth/pca-store-conformance. Writes out/ref-store-conformance-pca-state-py.json.gz.
// PORTING: pcaStateRun({adapter}) -> run_pca_state_conformance(REFERENCE_ADAPTERS[adapter], tests, rounds=3, copies=8, instances=3);
//   out: {test: [status, admitted]} for one-instance, instances, crash-after-claim and retry-after-timeout (the claim-* tests and the process half are not compared).
// Only deterministic adapters: the good reference stores and the two bad ones whose defect needs no scheduling luck.
const K: any = await import('../../../packages/pca-store-conformance/src/index.ts');
const { Oracle, refWrite } = await import('./lib.mjs');

const o = new Oracle('store-conformance-pca-state-py', 'tools/pca-audit/oracles/store-conformance-pca-state-py.mts', 'TS-reference oracle for the pca-state conformance profile (python lane).');
const TESTS = ['one-instance', 'instances', 'crash-after-claim', 'retry-after-timeout'];
for (const name of ['in-memory', 'durable-file', 'bad-volatile', 'bad-unshared']) {
  await o.run('pcaStateRun', name, async (a: any) => {
    const adapter = K.PCA_STATE_REFERENCE_ADAPTERS[a.adapter]({});
    const r = await K.runPcaStateConformance(adapter, { tests: TESTS, rounds: 3, copies: 8, instances: 3 });
    await adapter.teardown?.();
    return Object.fromEntries(r.tests.map((t: any) => [t.test, [t.status, t.admitted ?? null]]));
  }, [{ adapter: name }]);
}
refWrite(o, 'store-conformance-pca-state-py');

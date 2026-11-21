// Oracle (python lane): signBuiltins of @atlasauth/pca-actions. Writes out/ref-actions-signbuiltins-py.json.gz.
// PORTING: signBuiltins({kid, secret: {$seed: label}, ts, defsFrom, defsTo}) -> sign_builtins(kid, secret, ts, defs=BUILTIN_DEFS[from:to]); out = the attestation per verb.
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import * as R0 from '../../../packages/pca-actions/src/builtin-review.ts';
import { Oracle, refWrite, seed } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const BI = un(B0), RV = un(R0);
const o = new Oracle('actions-signbuiltins-py', 'tools/pca-audit/oracles/actions-signbuiltins-py.mts', 'TS-reference oracle for signBuiltins (python lane); the secret is a seed label, never key material.');
const N = BI.BUILTIN_DEFS.length;
const run = (name: string, label: string, kid: string, ts: number, from: number, to: number) =>
  o.run('signBuiltins', name, (a: any) => {
    const signed = RV.signBuiltins({ kid: a.kid, secret: seed(label), ts: a.ts, defs: BI.BUILTIN_DEFS.slice(a.from, a.to) });
    return signed.map((d: any) => [d.verb, d.review.state, d.review.attestation]);
  }, [{ secret: { $seed: label }, kid, ts, from, to }]);
await run('all', 'actions-signbuiltins-py/rev', 'release-1', 1000, 0, N);
await run('other key', 'actions-signbuiltins-py/rev2', 'release-2', 1700000000, 0, N);
await run('head', 'actions-signbuiltins-py/rev', 'r', 0, 0, 3);
await run('empty', 'actions-signbuiltins-py/rev', 'r', 5, 0, 0);
refWrite(o, 'actions-signbuiltins-py');

// Oracle (go lane): the built-in action defs and signBuiltins. Writes out/ref-signbuiltins-go.json.gz and out/ref-signbuiltins-go-defs.json
// (the defs the go package embeds). The reviewer key is a seed label, never key material: sha256("atlas-pca-conformance/" + label).
import fs from 'node:fs';
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import * as R0 from '../../../packages/pca-actions/src/builtin-review.ts';
import { Oracle, refWrite, seed, Ref_OUT } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const BI = un(B0), RV = un(R0);
const o = new Oracle('signbuiltins-go', 'tools/pca-audit/oracles/signbuiltins-go.mts', 'TS-reference oracle for signBuiltins over the built-in defs (go lane); the secret is a seed label.');
const defsJson = JSON.stringify(BI.BUILTIN_DEFS, null, 1);
if (JSON.stringify(JSON.parse(defsJson)) !== JSON.stringify(BI.BUILTIN_DEFS)) throw new Error('BUILTIN_DEFS does not round-trip through JSON');
fs.mkdirSync(Ref_OUT, { recursive: true });
fs.writeFileSync(Ref_OUT + 'ref-signbuiltins-go-defs.json', defsJson + '\n');
await o.run('builtinDefs', 'all', () => BI.BUILTIN_DEFS, []);
const sign = (a: any) => RV.signBuiltins({ kid: a.kid, secret: seed(a.seed), ts: a.ts });
for (const [label, kid, ts] of [['signbuiltins-go/a', 'rel-1', 1000], ['signbuiltins-go/b', 'rel-2', 1_700_000_000], ['signbuiltins-go/a', 'rel-1', 0]] as const)
  await o.run('signBuiltins', `${kid} ${ts}`, sign, [{ seed: label, kid, ts }]);
await o.run('signBuiltins', 'negative ts', sign, [{ seed: 'signbuiltins-go/a', kid: 'rel-1', ts: -1 }]);
refWrite(o, 'signbuiltins-go');

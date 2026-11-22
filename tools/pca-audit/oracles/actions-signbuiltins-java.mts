// Oracle: @atlasauth/pca-actions builtin-review.ts signBuiltins (confirmDef over every built-in def with the release reviewer key).
// PORTING: signBuiltins({seed, kid, ts, defs?}) -> ActionBuiltin.signBuiltins(CORE, kid, seedBytes, ts, defs|null); a seed is a label whose
//   Ed25519 seed is sha256("atlas-pca-conformance/" + label). No key material is stored in the corpus.
import { Oracle, refWrite, seed } from './lib.mjs';
import * as BR0 from '../../../packages/pca-actions/src/builtin-review.ts';
import * as BI0 from '../../../packages/pca-actions/src/builtin.ts';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const BR = un(BR0), BI = un(BI0);
const o = new Oracle('actions-signbuiltins', 'tools/pca-audit/oracles/actions-signbuiltins-java.mts', 'TS-reference oracle for signBuiltins.');
const run = (c: any) => BR.signBuiltins({ kid: c.kid, secret: seed(c.seed), ts: c.ts, ...(c.defs ? { defs: c.defs } : {}) });
const D = BI.BUILTIN_DEFS;
await o.run('signBuiltins', 'all label-a', run, [{ seed: 'builtin-release-a', kid: 'release-a', ts: 1700000000 }]);
await o.run('signBuiltins', 'all label-b', run, [{ seed: 'builtin-release-b', kid: 'release-b', ts: 0 }]);
await o.run('signBuiltins', 'first 3', run, [{ seed: 'builtin-release-a', kid: 'release-a', ts: 5, defs: D.slice(0, 3) }]);
await o.run('signBuiltins', 'empty', run, [{ seed: 'builtin-release-a', kid: 'release-a', ts: 5, defs: [] }]);
await o.run('signBuiltins', 'negative ts', run, [{ seed: 'builtin-release-a', kid: 'release-a', ts: -1, defs: D.slice(0, 1) }]);
await o.run('signBuiltins', 'fractional ts', run, [{ seed: 'builtin-release-a', kid: 'release-a', ts: 1.5, defs: D.slice(0, 1) }]);
await o.run('signBuiltins', 'unknown trait', run, [{ seed: 'builtin-release-a', kid: 'release-a', ts: 5, defs: [{ ...D[0], traits: ['no.such.trait'] }] }]);
await o.run('signBuiltins', 'duplicate traits', run, [{ seed: 'builtin-release-a', kid: 'release-a', ts: 5, defs: [{ ...D[0], traits: [...(D[0].traits ?? []), ...(D[0].traits ?? [])] }] }]);
refWrite(o, 'actions-signbuiltins');

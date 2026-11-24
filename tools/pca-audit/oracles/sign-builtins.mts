// Oracle: @atlasauth/pca-actions signBuiltins (release signing of the built-in defs). One corpus for the php and ruby lanes.
// Case args are [label, kid, ts]; the reviewer key is sha256("atlas-pca-conformance/" + label), never stored. Out is {verb: attestation}.
import { createHash } from 'node:crypto';
import * as BR0 from '../../../packages/pca-actions/src/builtin-review.ts';
import { Oracle, refWrite } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const BR = un(BR0);
const o = new Oracle('sign-builtins', 'tools/pca-audit/oracles/sign-builtins.mts', 'TS-reference oracle for signBuiltins (reviewer key derived from a seed label).');
const key = (label: string) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${label}`).digest());
const sign = (label: string, kid: string, ts: number) => {
  const out: Record<string, any> = {};
  for (const d of BR.signBuiltins({ kid, secret: key(label), ts })) out[d.verb] = d.review.attestation;
  return out;
};
for (const [label, kid, ts] of [['sign-builtins/a', 'rel-1', 1000], ['sign-builtins/b', 'rel-2', 1_700_000_000]] as const) await o.run('signBuiltins', `${kid} ${ts}`, sign, [label, kid, ts]);
await o.run('signBuiltins', 'negative ts', sign, ['sign-builtins/a', 'rel-1', -1]);
refWrite(o, 'sign-builtins');

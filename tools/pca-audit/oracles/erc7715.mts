// Oracle: @atlasauth/pca-erc7715 (grant -> ERC-7715 permission request, supported-permissions filter, revoke params, granted-permission verification, grant digest).
// Deterministic. BigInt options cross as decimal strings: chainId is the string form of the BigInt; a string that is not a clean decimal is not generated.
// PORTING (fn(args) -> native entry point, comparison rule; "Erc7715" = net.atlasauth.pca.erc7715.Erc7715, JSON by value):
//   grantToPermissionRequest(g, o)               Erc7715.grantToPermissionRequest; o.chainId (decimal string) becomes a java.math.BigInteger first
//   supportsRequest(supported, req)              same name; boolean
//   revokeParams(ctx)                            same name
//   verifyGrantedPermission(g, sent, got, o)     Erc7715.verifyGrantedPermission; o = {allowedManagers, owners?}: owners maps a context handle to the grant digest it is bound to
//                                                (contextOwner = ctx -> owners[ctx]); null when within the grant, else the reason string
//   grantDigestOf(grant)                         same name; a throw must throw
import { Oracle, HOSTILE, refWrite, variants } from './lib.mjs';

const M: any = await import('../../../packages/pca-erc7715/src/index.ts');
const o = new Oracle('erc7715', 'tools/pca-audit/oracles/erc7715.mts', 'TS-reference oracle for the ERC-7715 permission mapping and verification.');

const A1 = '0x' + 'ab'.repeat(20), A2 = '0x' + 'Cd'.repeat(20), A3 = '0x' + '12'.repeat(20), MGR = '0x' + '9f'.repeat(20);
const G = { grantDigest: 'GD', capMinor: 5000, expiresAtSec: 1_800_000_000 };
const conv = (x: any) => (x && typeof x === 'object' && typeof x.chainId === 'string' ? { ...x, chainId: BigInt(x.chainId) } : x);

// ---- grantToPermissionRequest -------------------------------------------------------------------------------------------
const gs: any[] = [G, { ...G, capMinor: 1 }, { ...G, capMinor: 0 }, { ...G, capMinor: -1 }, { ...G, capMinor: 1.5 }, { ...G, capMinor: 2 ** 53 }, { ...G, capMinor: 2 ** 53 - 1 }, { ...G, capMinor: -0 }, { ...G, capMinor: '5' }, { ...G, capMinor: null }, { ...G, capMinor: undefined },
  { ...G, expiresAtSec: 0 }, { ...G, expiresAtSec: -1 }, { ...G, expiresAtSec: 1.5 }, { ...G, expiresAtSec: 2 ** 53 - 1 }, { ...G, expiresAtSec: '1' }, { ...G, expiresAtSec: undefined }, { capMinor: 5, expiresAtSec: 5 }, null, 5, 'x', [], {}];
const base = { chainId: '1', sessionAccount: A1, baseUnitsPerMinor: '10' };
const os: any[] = [base, { ...base, tokenAddress: A2 }, { ...base, from: A3 }, { ...base, tokenAddress: A2, from: A3, isAdjustmentAllowed: false }, { ...base, isAdjustmentAllowed: null }, { ...base, isAdjustmentAllowed: 'no' }, { ...base, isAdjustmentAllowed: 0 },
  { ...base, chainId: '8453' }, { ...base, chainId: '0' }, { ...base, chainId: '-5' }, { ...base, chainId: '115792089237316195423570985008687907853269984665640564039457584007913129639935' }, { ...base, chainId: undefined },
  { ...base, sessionAccount: A2 }, { ...base, sessionAccount: '0X' + 'ab'.repeat(20) }, { ...base, sessionAccount: 'ab'.repeat(20) }, { ...base, sessionAccount: '0x' + 'ab'.repeat(19) }, { ...base, sessionAccount: '0x' + 'ab'.repeat(21) }, { ...base, sessionAccount: '0x' + 'zz'.repeat(20) },
  { ...base, sessionAccount: undefined }, { ...base, sessionAccount: null }, { ...base, sessionAccount: 5 }, { ...base, sessionAccount: [A1] }, { ...base, sessionAccount: A1 + '\n' }, { ...base, from: null }, { ...base, from: 'x' }, { ...base, from: A1.toUpperCase() }, { ...base, tokenAddress: null }, { ...base, tokenAddress: 'x' }, { ...base, tokenAddress: undefined },
  { ...base, baseUnitsPerMinor: '1' }, { ...base, baseUnitsPerMinor: '0' }, { ...base, baseUnitsPerMinor: '' }, { ...base, baseUnitsPerMinor: '-1' }, { ...base, baseUnitsPerMinor: '01' }, { ...base, baseUnitsPerMinor: '1.5' }, { ...base, baseUnitsPerMinor: '10000000000000000000000' }, { ...base, baseUnitsPerMinor: 5 }, { ...base, baseUnitsPerMinor: 0 },
  { ...base, baseUnitsPerMinor: null }, { ...base, baseUnitsPerMinor: undefined }, { ...base, baseUnitsPerMinor: '1\n' }, { ...base, baseUnitsPerMinor: ' 1' }, { ...base, baseUnitsPerMinor: [7] }, { ...base, baseUnitsPerMinor: 1e21 }, null, 5, {}];
for (const [gi, g] of gs.entries()) for (const [oi, op] of os.entries()) {
  if (gi > 0 && oi % 5 !== 0) continue;
  await o.run('grantToPermissionRequest', `g${gi}o${oi}`, (gg: any, x: any) => M.grantToPermissionRequest(gg, conv(x)), [g, op]);
}

// ---- supportsRequest ------------------------------------------------------------------------------------------------------------
const REQ = M.grantToPermissionRequest(G, conv(base));
const REQ20 = M.grantToPermissionRequest(G, conv({ ...base, tokenAddress: A2 }));
const supp = (extra: any = {}) => ({ 'native-token-allowance': { chainIds: ['0x1', '0x2105'], ruleTypes: ['expiry'] }, 'erc20-token-allowance': { chainIds: ['0X1'], rulesTypes: ['expiry', 'other'] }, ...extra });
const supps: any[] = [supp(), {}, null, 5, 'x', [], { 'native-token-allowance': null }, { 'native-token-allowance': {} }, { 'native-token-allowance': { chainIds: [] } }, { 'native-token-allowance': { chainIds: 'x' } }, { 'native-token-allowance': { chainIds: ['0x1'] } },
  { 'native-token-allowance': { chainIds: ['0x1'], ruleTypes: [] } }, { 'native-token-allowance': { chainIds: ['0x1'], ruleTypes: 'expiry' } }, { 'native-token-allowance': { chainIds: ['0x1'], ruleTypes: null, rulesTypes: ['expiry'] } }, { 'native-token-allowance': { chainIds: ['0X1'], ruleTypes: ['expiry'] } },
  { 'native-token-allowance': { chainIds: [1], ruleTypes: ['expiry'] } }, { 'native-token-allowance': { chainIds: ['0x1', 5], ruleTypes: ['expiry'] } }, { 'native-token-allowance': { chainIds: ['0x1'], ruleTypes: ['Expiry'] } }, { 'native-token-allowance': { chainIds: ['0x1'], ruleTypes: ['expiry', 'x'], rulesTypes: [] } },
  { constructor: { chainIds: ['0x1'] } }, { '__proto__': { chainIds: ['0x1'] } }, { 'erc20-token-allowance': { chainIds: ['0x1'], ruleTypes: ['expiry'] } }];
const reqs: any[] = [REQ, REQ20, { ...REQ, rules: [] }, { ...REQ, rules: undefined }, { ...REQ, rules: null }, { ...REQ, rules: 'ab' }, { ...REQ, rules: {} }, { ...REQ, rules: [null] }, { ...REQ, rules: [5] }, { ...REQ, rules: [{}] }, { ...REQ, rules: [{ type: 'other' }] }, { ...REQ, rules: [{ type: 'expiry' }, { type: 'other' }] },
  { ...REQ, chainId: '0X1' }, { ...REQ, chainId: 1 }, { ...REQ, chainId: undefined }, { ...REQ, permission: { ...REQ.permission, type: 'unknown' } }, { ...REQ, permission: null }, { ...REQ, permission: {} }, { ...REQ, permission: { type: 5 } }, { ...REQ, permission: { type: 'constructor' } }, { ...REQ, permission: { type: '__proto__' } }, null, 5, 'x', [], {}];
for (const [si, s] of supps.entries()) for (const [ri, r] of reqs.entries()) {
  if (si > 6 && ri > 12) continue;
  await o.run('supportsRequest', `s${si}r${ri}`, M.supportsRequest, [s, r]);
}
for (const [i, c] of [A1, '', 'x', 5, null, undefined, [], {}, { a: 1 }, 'é'].entries()) await o.run('revokeParams', `c${i}`, (x: any) => M.revokeParams(x), [c ?? null]);
await o.run('revokeParams', 'undefined', () => M.revokeParams(undefined), []);

// ---- verifyGrantedPermission -----------------------------------------------------------------------------------------------------
const CTX = '0x' + '1234abcd';
const mkResp = (sent: any, extra: any = {}) => ({ ...sent, context: CTX, dependencies: [], delegationManager: MGR, ...extra });
const withPerm = (resp: any, patch: any, data: any = {}) => ({ ...resp, permission: { ...resp.permission, ...patch, data: { ...resp.permission.data, ...data } } });
const sents: any[] = [REQ, REQ20, M.grantToPermissionRequest(G, conv({ ...base, from: A3 })), M.grantToPermissionRequest(G, conv({ ...base, isAdjustmentAllowed: false }))];
const opts: any[] = [{ allowedManagers: [MGR] }, { allowedManagers: [MGR.toUpperCase().replace('0X', '0x')] }, { allowedManagers: [] }, { allowedManagers: ['0x' + '11'.repeat(20)] }, { allowedManagers: [MGR], owners: { [CTX]: 'GD' } }, { allowedManagers: [MGR], owners: { [CTX]: 'OTHER' } },
  { allowedManagers: [MGR], owners: { other: 'x' } }, { allowedManagers: [5] }, { allowedManagers: 'x' }, { allowedManagers: [MGR, 5] }, { allowedManagers: null }, {}];
const gVariants: any[] = [G, { ...G, expiresAtSec: 1_700_000_000 }, { ...G, grantDigest: undefined }, { ...G, expiresAtSec: undefined }, null];
for (const [si, sent] of sents.entries()) {
  const resp = mkResp(sent);
  const narrower = withPerm(resp, {}, { allowance: '0x1' });
  const cases: [string, any][] = [['same', resp], ['narrower', narrower], ['wider', withPerm(resp, {}, { allowance: '0x' + 'f'.repeat(40) })], ['equal-hex-upper', withPerm(resp, {}, { allowance: resp.permission.data.allowance.toUpperCase().replace('0X', '0x') })],
    ['adj-widen', withPerm({ ...resp, permission: { ...resp.permission, isAdjustmentAllowed: false } }, { isAdjustmentAllowed: true })], ['adj-narrow', withPerm(resp, { isAdjustmentAllowed: false })], ['adj-str', withPerm(resp, { isAdjustmentAllowed: 'true' })],
    ['early', { ...resp, rules: [{ type: 'expiry', data: { timestamp: G.expiresAtSec - 10 } }] }], ['late', { ...resp, rules: [{ type: 'expiry', data: { timestamp: G.expiresAtSec + 1 } }] }], ['norules', { ...resp, rules: [] }], ['dup', { ...resp, rules: [...resp.rules, ...resp.rules] }],
    ['unknown-rule', { ...resp, rules: [...resp.rules, { type: 'other', data: {} }] }], ['unknown-first', { ...resp, rules: [{ type: 'other', data: {} }, ...resp.rules] }], ['rules-str', { ...resp, rules: 'x' }], ['rules-undef', { ...resp, rules: undefined }], ['ts-negzero', { ...resp, rules: [{ type: 'expiry', data: { timestamp: -0 } }] }],
    ['ts-float', { ...resp, rules: [{ type: 'expiry', data: { timestamp: 1.5 } }] }], ['ts-str', { ...resp, rules: [{ type: 'expiry', data: { timestamp: '5' } }] }], ['ts-missing', { ...resp, rules: [{ type: 'expiry', data: {} }] }], ['data-missing', { ...resp, rules: [{ type: 'expiry' }] }], ['rule-null', { ...resp, rules: [null] }],
    ['ctx-bad', { ...resp, context: 'xyz' }], ['ctx-0x', { ...resp, context: '0x' }], ['ctx-num', { ...resp, context: 5 }], ['mgr-bad', { ...resp, delegationManager: 'x' }], ['mgr-other', { ...resp, delegationManager: '0x' + '11'.repeat(20) }], ['mgr-undef', { ...resp, delegationManager: undefined }],
    ['chain-upper', { ...resp, chainId: resp.chainId.toUpperCase().replace('0X', '0x') }], ['chain-other', { ...resp, chainId: '0x2' }], ['chain-num', { ...resp, chainId: 1 }], ['chain-undef', { ...resp, chainId: undefined }], ['to-upper', { ...resp, to: resp.to.toUpperCase().replace('0X', '0x') }], ['to-other', { ...resp, to: A3 }], ['to-undef', { ...resp, to: undefined }],
    ['from-upper', { ...resp, from: A3.toUpperCase().replace('0X', '0x') }], ['from-other', { ...resp, from: A1 }], ['from-undef', { ...resp, from: undefined }], ['type-other', withPerm(resp, { type: 'other' })], ['type-swap', withPerm(resp, { type: resp.permission.type === 'native-token-allowance' ? 'erc20-token-allowance' : 'native-token-allowance' })],
    ['tok-other', withPerm(resp, {}, { tokenAddress: A3 })], ['tok-upper', withPerm(resp, {}, { tokenAddress: A2.toUpperCase().replace('0X', '0x') })], ['tok-null', withPerm(resp, {}, { tokenAddress: null })], ['tok-add', withPerm(resp, {}, { tokenAddress: A2 })],
    ['amt-num', withPerm(resp, {}, { allowance: 5 })], ['amt-dec', withPerm(resp, {}, { allowance: '100' })], ['amt-0x', withPerm(resp, {}, { allowance: '0x' })], ['amt-00', withPerm(resp, {}, { allowance: '0x00' })], ['amt-zero', withPerm(resp, {}, { allowance: '0x0' })], ['amt-undef', withPerm(resp, {}, { allowance: undefined })],
    ['perm-null', { ...resp, permission: null }], ['perm-str', { ...resp, permission: 'x' }], ['perm-arr', { ...resp, permission: [] }], ['data-null', { ...resp, permission: { ...resp.permission, data: null } }], ['data-str', { ...resp, permission: { ...resp.permission, data: 'x' } }], ['data-undef', { ...resp, permission: { type: resp.permission.type, isAdjustmentAllowed: true } }],
    ['null', null], ['num', 5], ['str', 'x'], ['arr', []], ['empty', {}]];
  for (const [label, got] of cases) for (const [oi, op] of opts.entries()) {
    if (label !== 'same' && label !== 'narrower' && label !== 'wider' && oi > 5) continue;
    for (const [gi, g] of gVariants.entries()) {
      if (gi > 0 && (oi > 0 || si > 1)) continue;
      await o.run('verifyGrantedPermission', `s${si}${label}o${oi}g${gi}`, (gg: any, ss: any, gt: any, x: any) => M.verifyGrantedPermission(gg, ss, gt, { allowedManagers: x.allowedManagers, ...(x.owners ? { contextOwner: (c: string) => x.owners[c] } : {}) }) ?? null, [g, sent, got, op]);
    }
  }
  for (const [label, v] of variants(resp, { depth: 4, maxPaths: 70 })) await o.run('verifyGrantedPermission', `s${si}v${o.cases.length}`, (gg: any, ss: any, gt: any, x: any) => M.verifyGrantedPermission(gg, ss, gt, { allowedManagers: x.allowedManagers }) ?? null, [G, sent, v, { allowedManagers: [MGR] }]);
}
const badSent: any[] = [{ ...REQ, chainId: undefined }, { ...REQ, chainId: 5 }, { ...REQ, to: undefined }, { ...REQ, from: null }, { ...REQ, permission: undefined }, { ...REQ, permission: null }, { ...REQ, permission: { ...REQ.permission, data: undefined } }, { ...REQ, permission: { ...REQ.permission, data: { allowance: undefined } } },
  { ...REQ, permission: { ...REQ.permission, data: { allowance: '5' } } }, { ...REQ, permission: { ...REQ.permission, data: { allowance: '' } } }, { ...REQ, permission: { ...REQ.permission, data: { allowance: 5 } } }, { ...REQ, permission: { ...REQ.permission, data: { allowance: ' 0x10 ' } } },
  { ...REQ, permission: { ...REQ.permission, data: { allowance: '0b11' } } }, { ...REQ, permission: { ...REQ.permission, data: { allowance: '1.5' } } }, { ...REQ, permission: { ...REQ.permission, data: { allowance: true } } }, { ...REQ, permission: { ...REQ.permission, data: { allowance: '-1' } } }, null, 5, {}];
for (const [i, s] of badSent.entries()) await o.run('verifyGrantedPermission', `badsent${i}`, (gg: any, ss: any, gt: any, x: any) => M.verifyGrantedPermission(gg, ss, gt, x) ?? null, [G, s, mkResp(REQ, { permission: { ...REQ.permission, data: { allowance: '0x1' } } }), { allowedManagers: [MGR] }]);

// ---- grantDigestOf -----------------------------------------------------------------------------------------------------------------------
for (const [i, v] of [...HOSTILE, G, { b: 1, a: [1, 2], c: { d: null } }, { n: 0.1 }, { n: 1e-7 }, { 'é': 1, a: 2 }, [[], {}]].entries()) await o.run('grantDigestOf', `v${i}`, M.grantDigestOf, [v]);

refWrite(o, 'erc7715');

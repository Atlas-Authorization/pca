import { describe, expect, it } from 'vitest';
import { grantToPermissionRequest, revokeParams, supportsRequest, verifyGrantedPermission, type GrantEnvelope, type PermissionRequest } from './index';

const g: GrantEnvelope = { grantDigest: 'gd1', capMinor: 1000, expiresAtSec: 1_800_086_400 };
const SESSION = '0x' + '11'.repeat(20);
const TOKEN = '0x' + '22'.repeat(20);
const MGR = '0x' + '33'.repeat(20);
const req = grantToPermissionRequest(g, { chainId: 8453n, sessionAccount: SESSION, tokenAddress: TOKEN, baseUnitsPerMinor: '10000' });
const resp = (over: Record<string, unknown> = {}, data: Record<string, unknown> = {}) => ({ ...req, context: '0xabc123', dependencies: [], delegationManager: MGR, ...over, permission: { ...req.permission, data: { ...req.permission.data, ...data } } });
const ok = { allowedManagers: [MGR] };

describe('grant -> ERC-7715 request (C-288)', () => {
  it('maps cap, expiry and addresses; exact integer unit conversion', () => {
    expect(req.chainId).toBe('0x2105');
    expect(req.permission.type).toBe('erc20-token-allowance');
    expect(req.permission.data).toEqual({ allowance: '0x' + (10_000_000n).toString(16), tokenAddress: TOKEN });
    expect(req.rules).toEqual([{ type: 'expiry', data: { timestamp: g.expiresAtSec } }]);
    expect(grantToPermissionRequest(g, { chainId: 1n, sessionAccount: SESSION, baseUnitsPerMinor: '1' }).permission.type).toBe('native-token-allowance');
  });
  it('refuses bad inputs: fractional ratio, zero, bad address, bad envelope', () => {
    for (const r of ['1.5', '0', '', '-1']) expect(() => grantToPermissionRequest(g, { chainId: 1n, sessionAccount: SESSION, baseUnitsPerMinor: r })).toThrow();
    expect(() => grantToPermissionRequest(g, { chainId: 1n, sessionAccount: '0x12', baseUnitsPerMinor: '1' })).toThrow();
    expect(() => grantToPermissionRequest({ ...g, capMinor: 0 }, { chainId: 1n, sessionAccount: SESSION, baseUnitsPerMinor: '1' })).toThrow();
  });
  it('supports discovery, either spelling of ruleTypes, and revoke params', () => {
    expect(supportsRequest({ 'erc20-token-allowance': { chainIds: ['0x2105'], ruleTypes: ['expiry'] } }, req)).toBe(true);
    expect(supportsRequest({ 'erc20-token-allowance': { chainIds: ['0x2105'], rulesTypes: ['expiry'] } }, req)).toBe(true);
    expect(supportsRequest({ 'erc20-token-allowance': { chainIds: ['0x1'], ruleTypes: ['expiry'] } }, req)).toBe(false);
    expect(supportsRequest({}, req)).toBe(false);
    expect(revokeParams('0xabc')).toEqual({ permissionContext: '0xabc' });
  });
});

describe('verify granted permission against the grant (C-289, C-290)', () => {
  it('accepts the permission as requested and a narrowed one', () => {
    expect(verifyGrantedPermission(g, req, resp(), ok)).toBeNull();
    expect(verifyGrantedPermission(g, req, resp({}, { allowance: '0x1' }), ok)).toBeNull();
    expect(verifyGrantedPermission(g, req, resp({ rules: [{ type: 'expiry', data: { timestamp: g.expiresAtSec - 5 } }] }), ok)).toBeNull();
  });
  const cases: Array<[string, Record<string, unknown>, Record<string, unknown>, string]> = [
    ['amount widened', {}, { allowance: '0x' + (10_000_001n).toString(16) }, 'amount_widened'],
    ['amount not hex', {}, { allowance: '10' }, 'amount_malformed'],
    ['other token', {}, { tokenAddress: '0x' + '44'.repeat(20) }, 'token_mismatch'],
    ['other chain', { chainId: '0x1' }, {}, 'chain_mismatch'],
    ['other recipient', { to: '0x' + '55'.repeat(20) }, {}, 'recipient_mismatch'],
    ['untrusted manager', { delegationManager: '0x' + '66'.repeat(20) }, {}, 'delegation_manager_not_allowed'],
    ['expiry extended', { rules: [{ type: 'expiry', data: { timestamp: g.expiresAtSec + 1 } }] }, {}, 'expiry_extended'],
    ['no expiry', { rules: [] }, {}, 'expiry_missing'],
    ['rules absent', { rules: undefined }, {}, 'expiry_missing'],
    ['unknown rule', { rules: [{ type: 'redeemer', data: {} }] }, {}, 'unknown_rule_type'],
    ['type changed', { permission: { type: 'native-token-allowance', isAdjustmentAllowed: true, data: req.permission.data } }, {}, 'permission_type_mismatch'],
    ['bad context', { context: 'abc' }, {}, 'context_malformed'],
  ];
  for (const [name, over, data, reason] of cases) it(`refuses: ${name}`, () => expect(verifyGrantedPermission(g, req, { ...resp(over, data), ...(over.permission !== undefined ? { permission: over.permission } : {}) }, ok)).toBe(reason));
  it('refuses a wallet that turns adjustment on (the EIP lets it attenuate either way; we only accept a reduction)', () => {
    const strict = { ...req, permission: { ...req.permission, isAdjustmentAllowed: false } };
    expect(verifyGrantedPermission(g, strict, { ...resp(), permission: { ...strict.permission, isAdjustmentAllowed: true } }, ok)).toBe('adjustment_widened');
  });
  it('refuses a context already bound to another grant, and garbage', () => {
    expect(verifyGrantedPermission(g, req, resp(), { ...ok, contextOwner: () => 'other' })).toBe('context_bound_to_other_grant');
    expect(verifyGrantedPermission(g, req, null, ok)).toBe('response_malformed');
    expect(verifyGrantedPermission(g, req as PermissionRequest, { permission: null }, ok)).toBe('response_malformed');
  });
});

// ---- exact-outcome boundary tests (mutation kill set, T-700..704) ----
describe('request mapping boundaries (C-288)', () => {
  const base = { chainId: 1n, sessionAccount: SESSION, baseUnitsPerMinor: '1' };
  it('the native request has exactly the EIP shape; from is carried when given', () => {
    const r = grantToPermissionRequest(g, base);
    expect(r).toEqual({ chainId: '0x1', to: SESSION, permission: { type: 'native-token-allowance', isAdjustmentAllowed: true, data: { allowance: '0x3e8' } }, rules: [{ type: 'expiry', data: { timestamp: g.expiresAtSec } }] });
    const f = grantToPermissionRequest(g, { ...base, from: '0x' + '77'.repeat(20), isAdjustmentAllowed: false });
    expect(f.from).toBe('0x' + '77'.repeat(20));
    expect(f.permission.isAdjustmentAllowed).toBe(false);
  });
  it('cap, expiry, chain and ratio bounds', () => {
    expect(() => grantToPermissionRequest({ ...g, capMinor: 1 }, base)).not.toThrow();
    expect(() => grantToPermissionRequest({ ...g, capMinor: 0 }, base)).toThrow();
    expect(() => grantToPermissionRequest({ ...g, capMinor: 1.5 }, base)).toThrow();
    expect(() => grantToPermissionRequest({ ...g, expiresAtSec: 0 }, base)).toThrow();
    expect(() => grantToPermissionRequest(g, { ...base, chainId: 0n })).toThrow();
    expect(() => grantToPermissionRequest(g, { ...base, baseUnitsPerMinor: '01' })).toThrow();
    expect(() => grantToPermissionRequest(g, { ...base, tokenAddress: '0x12' })).toThrow();
    expect(() => grantToPermissionRequest(g, { ...base, from: 'nope' })).toThrow();
  });
});

describe('verification boundaries (C-289)', () => {
  it('the allowance may equal the request and the expiry may equal the grant end', () => {
    expect(verifyGrantedPermission(g, req, resp({ rules: [{ type: 'expiry', data: { timestamp: g.expiresAtSec } }] }), ok)).toBeNull();
    expect(verifyGrantedPermission(g, req, resp({}, { allowance: '0x' + (10_000_000n).toString(16) }), ok)).toBeNull();
    expect(verifyGrantedPermission(g, req, resp({}, { allowance: '0x0' }), ok)).toBeNull();
  });
  it('hex comparison is numeric, not lexicographic', () => {
    const small = grantToPermissionRequest({ ...g, capMinor: 9 }, { chainId: 8453n, sessionAccount: SESSION, tokenAddress: TOKEN, baseUnitsPerMinor: '1' }); // 0x9
    const wide = { ...resp({}, {}), ...small, context: '0xabc123', dependencies: [], delegationManager: MGR };
    expect(verifyGrantedPermission(g, small, { ...wide, permission: { ...small.permission, data: { ...small.permission.data, allowance: '0xa' } } }, ok)).toBe('amount_widened');
    expect(verifyGrantedPermission(g, small, { ...wide, permission: { ...small.permission, data: { ...small.permission.data, allowance: '0x10' } } }, ok)).toBe('amount_widened');
  });
  it('from, when requested, must match; manager and address comparison ignore case', () => {
    const withFrom = { ...req, from: '0x' + 'ab'.repeat(20) };
    expect(verifyGrantedPermission(g, withFrom, { ...resp(), from: '0x' + 'AB'.repeat(20) }, ok)).toBeNull();
    expect(verifyGrantedPermission(g, withFrom, { ...resp(), from: '0x' + 'cd'.repeat(20) }, ok)).toBe('from_mismatch');
    expect(verifyGrantedPermission(g, req, resp({ delegationManager: MGR.toUpperCase().replace('0X', '0x') }), ok)).toBeNull();
    expect(verifyGrantedPermission(g, req, resp({ delegationManager: '0x12' }), { allowedManagers: ['0x12'] })).toBe('delegation_manager_not_allowed');
  });
  it('expiry must be a safe integer and the type allow-list is closed', () => {
    expect(verifyGrantedPermission(g, req, resp({ rules: [{ type: 'expiry', data: { timestamp: 1.5 } }] }), ok)).toBe('expiry_malformed');
    expect(verifyGrantedPermission(g, req, resp({ rules: [{ type: 'expiry', data: {} }] }), ok)).toBe('expiry_malformed');
  });
  it('supportsRequest needs the type, the chain and every rule type', () => {
    expect(supportsRequest({ 'erc20-token-allowance': { chainIds: ['0x2105'], ruleTypes: [] } }, req)).toBe(false);
    expect(supportsRequest({ 'erc20-token-allowance': { chainIds: ['0X2105'], ruleTypes: ['expiry'] } }, req)).toBe(true);
    expect(supportsRequest(null, req)).toBe(false);
  });
});

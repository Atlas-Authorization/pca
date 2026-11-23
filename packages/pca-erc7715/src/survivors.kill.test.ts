import { describe, expect, it } from 'vitest';
import { grantToPermissionRequest, supportsRequest, verifyGrantedPermission, type GrantEnvelope, type PermissionRequest } from './index';

const g: GrantEnvelope = { grantDigest: 'gd1', capMinor: 1000, expiresAtSec: 1_800_086_400 };
const SESSION = '0x' + '11'.repeat(20);
const TOKEN = '0x' + '22'.repeat(20);
const MGR = '0x' + '33'.repeat(20);
const ok = { allowedManagers: [MGR] };

const erc20Req = (): PermissionRequest => grantToPermissionRequest(g, { chainId: 8453n, sessionAccount: SESSION, tokenAddress: TOKEN, baseUnitsPerMinor: '10000' });
const nativeReq = (): PermissionRequest => grantToPermissionRequest(g, { chainId: 1n, sessionAccount: SESSION, baseUnitsPerMinor: '3' });
const respOf = (req: PermissionRequest, over: Record<string, unknown> = {}): Record<string, unknown> => ({
  ...req,
  context: '0xabc123',
  dependencies: [],
  delegationManager: MGR,
  ...over,
});
const expiry = (timestamp: number) => ({ type: 'expiry', data: { timestamp } });

describe('grantToPermissionRequest exact outputs and messages', () => {
  it('converts minor units by multiplication', () => {
    const r = erc20Req();
    expect(r.permission.data.allowance).toBe('0x' + (10_000_000n).toString(16));
    expect(nativeReq().permission.data.allowance).toBe('0xbb8');
  });
  it('the erc20 shape carries the token and defaults adjustment to true', () => {
    expect(erc20Req()).toStrictEqual({
      chainId: '0x2105',
      to: SESSION,
      permission: { type: 'erc20-token-allowance', isAdjustmentAllowed: true, data: { tokenAddress: TOKEN, allowance: '0x' + (10_000_000n).toString(16) } },
      rules: [expiry(g.expiresAtSec)],
    });
  });
  it('the native shape omits from when absent and defaults adjustment to true', () => {
    const r = nativeReq();
    expect(Object.keys(r)).toEqual(['chainId', 'to', 'permission', 'rules']);
    expect(r.permission.isAdjustmentAllowed).toBe(true);
    expect(r.permission.type).toBe('native-token-allowance');
    const f = grantToPermissionRequest(g, { chainId: 1n, sessionAccount: SESSION, baseUnitsPerMinor: '1', from: '0x' + '77'.repeat(20) });
    expect(f.from).toBe('0x' + '77'.repeat(20));
  });
  it('refusals carry their exact messages', () => {
    const o = { chainId: 1n, sessionAccount: SESSION, baseUnitsPerMinor: '1' };
    expect(() => grantToPermissionRequest({ ...g, capMinor: 0 }, o)).toThrow(new RangeError('grantToPermissionRequest: bad envelope'));
    expect(() => grantToPermissionRequest(g, { ...o, sessionAccount: '0x12' })).toThrow(new RangeError('grantToPermissionRequest: bad address'));
    expect(() => grantToPermissionRequest(g, { ...o, baseUnitsPerMinor: '0' })).toThrow(
      new RangeError('grantToPermissionRequest: baseUnitsPerMinor must be a positive integer string'),
    );
    expect(() => grantToPermissionRequest(g, { ...o, chainId: 0n })).toThrow(new RangeError('grantToPermissionRequest: bad chain'));
  });
});

describe('supportsRequest', () => {
  const sup = { 'erc20-token-allowance': { chainIds: ['0x2105'], ruleTypes: ['expiry'] } };
  it('a request without rules is supported', () => {
    expect(supportsRequest(sup, { ...erc20Req(), rules: undefined })).toBe(true);
  });
  it('every rule type must be supported, not just one', () => {
    const req = { ...erc20Req(), rules: [{ type: 'expiry', data: {} }, { type: 'other', data: {} }] };
    expect(supportsRequest(sup, req)).toBe(false);
  });
  it('chainIds must be a real array', () => {
    const fake = { 'erc20-token-allowance': { chainIds: { map: () => ['0x2105'] }, ruleTypes: ['expiry'] } };
    expect(supportsRequest(fake, erc20Req())).toBe(false);
  });
});

describe('verifyGrantedPermission refusal precision', () => {
  it('a native permission as requested is accepted', () => {
    const req = nativeReq();
    expect(verifyGrantedPermission(g, req, respOf(req, { rules: [expiry(g.expiresAtSec)] }), ok)).toBeNull();
  });
  it('an unknown permission type is refused even when the wallet echoes it', () => {
    const req = { ...erc20Req(), permission: { ...erc20Req().permission, type: 'custom-allowance' } };
    expect(verifyGrantedPermission(g, req, respOf(req, { rules: [expiry(g.expiresAtSec)] }), ok)).toBe('permission_type_mismatch');
  });
  it('comparison lower-cases rather than upper-cases', () => {
    const req = { ...erc20Req(), to: 'K' };
    expect(verifyGrantedPermission(g, req, respOf(req, { to: 'k', rules: [expiry(g.expiresAtSec)] }), ok)).toBeNull();
  });
  it('non-object responses are refused', () => {
    const req = erc20Req();
    const asFunction = Object.assign(() => undefined, respOf(req, { rules: [expiry(g.expiresAtSec)] }));
    expect(verifyGrantedPermission(g, req, asFunction, ok)).toBe('response_malformed');
    expect(verifyGrantedPermission(g, req, 5, ok)).toBe('response_malformed');
    expect(verifyGrantedPermission(g, req, undefined, ok)).toBe('response_malformed');
  });
  it('a non-object permission is refused as malformed', () => {
    const req = erc20Req();
    expect(verifyGrantedPermission(g, req, respOf(req, { permission: 5 }), ok)).toBe('response_malformed');
    expect(verifyGrantedPermission(g, req, respOf(req, { permission: undefined }), ok)).toBe('response_malformed');
  });
  it('a permission without data fails closed as malformed', () => {
    const req = erc20Req();
    const permission = { type: req.permission.type, isAdjustmentAllowed: true };
    expect(verifyGrantedPermission(g, req, respOf(req, { permission }), ok)).toBe('response_malformed');
  });
  it('the context must be a hex string, fully matched', () => {
    const req = erc20Req();
    const v = (context: unknown) => verifyGrantedPermission(g, req, respOf(req, { context, rules: [expiry(g.expiresAtSec)] }), ok);
    expect(v(['0xabc'])).toBe('context_malformed');
    expect(v('zz0xabc')).toBe('context_malformed');
    expect(v('0xabc!')).toBe('context_malformed');
    expect(v('0xabc')).toBeNull();
  });
  it('a context owned by the same grant is accepted', () => {
    const req = erc20Req();
    expect(verifyGrantedPermission(g, req, respOf(req, { rules: [expiry(g.expiresAtSec)] }), { ...ok, contextOwner: () => g.grantDigest })).toBeNull();
  });
  it('a non-string delegation manager is refused with the typed reason', () => {
    const req = erc20Req();
    expect(verifyGrantedPermission(g, req, respOf(req, { delegationManager: [MGR], rules: [expiry(g.expiresAtSec)] }), ok)).toBe('delegation_manager_not_allowed');
  });
  it('a non-string allowance is refused as malformed', () => {
    const req = erc20Req();
    const permission = { ...req.permission, data: { ...req.permission.data, allowance: ['0x1'] } };
    expect(verifyGrantedPermission(g, req, respOf(req, { permission, rules: [expiry(g.expiresAtSec)] }), ok)).toBe('amount_malformed');
  });
  it('a wallet turning adjustment off is a narrowing and is accepted', () => {
    const req = erc20Req();
    const permission = { ...req.permission, isAdjustmentAllowed: false };
    expect(verifyGrantedPermission(g, req, respOf(req, { permission, rules: [expiry(g.expiresAtSec)] }), ok)).toBeNull();
  });
  it('a null rule is an unknown rule type, a repeated expiry is a duplicate', () => {
    const req = erc20Req();
    expect(verifyGrantedPermission(g, req, respOf(req, { rules: [null] }), ok)).toBe('unknown_rule_type');
    expect(verifyGrantedPermission(g, req, respOf(req, { rules: [expiry(g.expiresAtSec), expiry(g.expiresAtSec)] }), ok)).toBe('duplicate_expiry');
  });
});

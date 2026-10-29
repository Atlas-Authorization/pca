// pca-erc7715 - ERC-7715 (wallet_requestExecutionPermissions) for PCA grants. K4, C-288..C-291.
//
// Source: ethereum/ERCs ERCS/erc-7715.md at commit 2adc3783667334a371eab433fecbe9953dc848e2 (2026-01-16), status Draft. What the text
// defines: the request {chainId, from?, to, permission{type,isAdjustmentAllowed,data}, rules?[{type,data}]}; the response adds
// {context, dependencies[{factory,factoryData}], delegationManager}; the `expiry` rule {timestamp}; wallet_getSupportedExecutionPermissions
// (keyed by permission type, with `ruleTypes` in the prose and `rulesTypes` in the example); wallet_getGrantedExecutionPermissions;
// wallet_revokeExecutionPermission {permissionContext}. What the text does NOT define: any permission `type` or its `data`. The only
// shape it shows is `native-token-allowance` with `data.allowance` (hex) and the NAME `erc20-token-allowance` in the supported-permissions
// example. This package therefore maps to those two names: native-token-allowance {allowance} is the EIP's own example; for
// erc20-token-allowance the data {tokenAddress, allowance} is a PCA PROFILE, not from the EIP, and must be confirmed against the target
// wallet's permission ERC. The EIP says a wallet MAY attenuate "(reduce or increase)" a permission when isAdjustmentAllowed: this package
// accepts reduce only and refuses an increase, because an increase would exceed the grant.
//
// SCOPE: pure mapping and verification. NO chain access, NO redemption through a delegation manager (that stays out of the core).
// Amounts: the grant is in minor units of a fiat currency; ERC-20 amounts are in token base units. There is NO price oracle here:
// the caller states an explicit exact integer ratio `baseUnitsPerMinor`. Fail-strict: unknown permission type, unknown rule type,
// any widening versus the request or the grant, a missing expiry, an unexpected chain/account/manager: refused.

import { hashCanonical } from '@atlasauth/pca';

export type PermissionType = 'native-token-allowance' | 'erc20-token-allowance';
export interface Rule { type: string; data: Record<string, unknown> }
export interface PermissionRequest {
  chainId: string;
  from?: string;
  to: string;
  permission: { type: string; isAdjustmentAllowed: boolean; data: Record<string, unknown> };
  rules?: Rule[];
}
export interface PermissionResponse extends PermissionRequest {
  context: string;
  dependencies: Array<{ factory: string; factoryData: string }>;
  delegationManager: string;
}

/** The money envelope of a PCA grant, as the mapping needs it. All from the signed mandate; nothing here is chosen by the agent. */
export interface GrantEnvelope {
  /** hashCanonical(grant). */
  grantDigest: string;
  /** Cumulative cap over the grant's life, integer minor units (the mandate's cumulative cap). */
  capMinor: number;
  /** Epoch seconds at which the grant ends: becomes the `expiry` rule. */
  expiresAtSec: number;
}

const HEX_ADDR = /^0x[0-9a-fA-F]{40}$/;
const HEX_QTY = /^0x(0|[1-9a-fA-F][0-9a-fA-F]*)$/;
const DEC = /^(0|[1-9][0-9]*)$/;
const lower = (s: string): string => s.toLowerCase();
const hexOf = (n: bigint): string => `0x${n.toString(16)}`;

export interface MapOptions {
  chainId: bigint;
  /** Session-key account the permission is granted to. */
  sessionAccount: string;
  /** Undefined => native token. */
  tokenAddress?: string;
  /** Exact integer ratio: token base units per ONE minor unit of the grant currency (decimal string). */
  baseUnitsPerMinor: string;
  from?: string;
  isAdjustmentAllowed?: boolean;
}

export function grantToPermissionRequest(g: GrantEnvelope, o: MapOptions): PermissionRequest {
  if (!Number.isSafeInteger(g.capMinor) || g.capMinor <= 0 || !Number.isSafeInteger(g.expiresAtSec) || g.expiresAtSec <= 0) throw new RangeError('grantToPermissionRequest: bad envelope');
  if (!HEX_ADDR.test(o.sessionAccount) || (o.from !== undefined && !HEX_ADDR.test(o.from)) || (o.tokenAddress !== undefined && !HEX_ADDR.test(o.tokenAddress))) throw new RangeError('grantToPermissionRequest: bad address');
  if (!DEC.test(o.baseUnitsPerMinor) || o.baseUnitsPerMinor === '0') throw new RangeError('grantToPermissionRequest: baseUnitsPerMinor must be a positive integer string');
  if (o.chainId <= 0n) throw new RangeError('grantToPermissionRequest: bad chain');
  const allowance = hexOf(BigInt(g.capMinor) * BigInt(o.baseUnitsPerMinor));
  return {
    chainId: hexOf(o.chainId),
    ...(o.from !== undefined ? { from: o.from } : {}),
    to: o.sessionAccount,
    permission: o.tokenAddress !== undefined
      ? { type: 'erc20-token-allowance', isAdjustmentAllowed: o.isAdjustmentAllowed ?? true, data: { tokenAddress: o.tokenAddress, allowance } }
      : { type: 'native-token-allowance', isAdjustmentAllowed: o.isAdjustmentAllowed ?? true, data: { allowance } },
    rules: [{ type: 'expiry', data: { timestamp: g.expiresAtSec } }],
  };
}

/** wallet_getSupportedExecutionPermissions result filtered to what a grant could use. Pure; the caller made the RPC. */
export function supportsRequest(supported: unknown, req: PermissionRequest): boolean {
  try {
    const s = (supported as Record<string, { chainIds?: string[]; ruleTypes?: string[]; rulesTypes?: string[] }>)[req.permission.type];
    if (s === undefined || !Array.isArray(s.chainIds) || !s.chainIds.map(lower).includes(lower(req.chainId))) return false;
    const rt = s.ruleTypes ?? s.rulesTypes; // the draft spells both
    return (req.rules ?? []).every((r) => Array.isArray(rt) && rt.includes(r.type));
  } catch { return false; }
}

export const revokeParams = (context: string): { permissionContext: string } => ({ permissionContext: context });

export interface VerifyOptions {
  /** Delegation managers the operator trusts for this chain (lower-case compare). */
  allowedManagers: readonly string[];
  /** The context handles already bound to this grant digest, to refuse a context bound to a different grant. */
  contextOwner?: (context: string) => string | undefined;
}

/**
 * Verify what the wallet actually granted against the request we sent and the grant. Returns null when the permission is within the
 * grant, else a reason. A wallet may NARROW (isAdjustmentAllowed); it may never widen: amount, expiry later, a
 * different token, chain, recipient or manager are all refused.
 */
export function verifyGrantedPermission(g: GrantEnvelope, sent: PermissionRequest, got: unknown, o: VerifyOptions): string | null {
  try {
    const r = got as PermissionResponse;
    if (r === null || typeof r !== 'object' || typeof r.permission !== 'object' || r.permission === null) return 'response_malformed';
    if (typeof r.context !== 'string' || !/^0x[0-9a-fA-F]+$/.test(r.context)) return 'context_malformed';
    const owner = o.contextOwner?.(r.context);
    if (owner !== undefined && owner !== g.grantDigest) return 'context_bound_to_other_grant';
    if (typeof r.delegationManager !== 'string' || !HEX_ADDR.test(r.delegationManager) || !o.allowedManagers.map(lower).includes(lower(r.delegationManager))) return 'delegation_manager_not_allowed';
    if (lower(String(r.chainId)) !== lower(sent.chainId)) return 'chain_mismatch';
    if (lower(String(r.to)) !== lower(sent.to)) return 'recipient_mismatch';
    if (sent.from !== undefined && lower(String(r.from)) !== lower(sent.from)) return 'from_mismatch';
    if (r.permission.type !== sent.permission.type || (r.permission.type !== 'native-token-allowance' && r.permission.type !== 'erc20-token-allowance')) return 'permission_type_mismatch';
    const d = r.permission.data as Record<string, unknown>;
    const sd = sent.permission.data;
    if (lower(String(d.tokenAddress ?? '')) !== lower(String(sd.tokenAddress ?? ''))) return 'token_mismatch';
    if (typeof d.allowance !== 'string' || !HEX_QTY.test(d.allowance)) return 'amount_malformed';
    if (BigInt(d.allowance) > BigInt(sd.allowance as string)) return 'amount_widened';
    if (r.permission.isAdjustmentAllowed !== sent.permission.isAdjustmentAllowed && r.permission.isAdjustmentAllowed === true) return 'adjustment_widened';
    if (!Array.isArray(r.rules)) return 'expiry_missing';
    let expiry: number | undefined;
    for (const rule of r.rules) {
      if (rule?.type !== 'expiry') return 'unknown_rule_type';
      if (expiry !== undefined) return 'duplicate_expiry';
      expiry = (rule.data as { timestamp?: unknown }).timestamp as number;
      if (!Number.isSafeInteger(expiry)) return 'expiry_malformed';
    }
    if (expiry === undefined) return 'expiry_missing';
    if (expiry > g.expiresAtSec) return 'expiry_extended';
    return null;
  } catch {
    return 'response_malformed';
  }
}

export const grantDigestOf = (grant: unknown): string => hashCanonical(grant);

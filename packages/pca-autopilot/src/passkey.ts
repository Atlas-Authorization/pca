/**
 * Passkey approval, browser side. The reviewer's authenticator signs a challenge that IS the approval commitment (proposal
 * digest, report digest, confirmed ids, expiry), so a passkey touch cannot be replayed against another proposal. The helper
 * only builds the approval record; `verifyApproval` (server side) is what decides, with user verification required.
 */
import { b64u } from '@atlasauth/pca';
import { DEFAULT_APPROVAL_TTL_MS, MAX_APPROVAL_TTL_MS, approvalChallenge, gate, type PasskeyApproval } from './signoff';
import type { Report } from './verify';
import type { Proposal } from './types';

/** The part of `AuthenticatorAssertionResponse` the approval needs (`ArrayBuffer` or any view). */
export interface AssertionResponseLike {
  authenticatorData: ArrayBuffer | ArrayBufferView;
  clientDataJSON: ArrayBuffer | ArrayBufferView;
  signature: ArrayBuffer | ArrayBufferView;
}

export interface PasskeyRequest {
  /** The label the server pins this credential under (the key of `credentials` in `verifyApproval`). */
  principal: string;
  at: number;
  ttlMs?: number;
  confirmed?: readonly string[];
}

const bytes = (x: ArrayBuffer | ArrayBufferView): Uint8Array => {
  if (x instanceof ArrayBuffer) return new Uint8Array(x);
  if (ArrayBuffer.isView(x)) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
  throw new TypeError('expected an ArrayBuffer or a view');
};

/** The challenge to hand to `navigator.credentials.get`, and the exact fields the approval must then carry. */
export function passkeyChallenge(p: Proposal, r: Report, o: PasskeyRequest): { challenge: Uint8Array; confirmed: string[]; expires_at: number } {
  gate(p, r);
  const ttl = o.ttlMs ?? DEFAULT_APPROVAL_TTL_MS;
  if (!Number.isFinite(ttl) || ttl <= 0 || ttl > MAX_APPROVAL_TTL_MS) throw new RangeError('approval ttl must be positive and at most 24h');
  if (!Number.isSafeInteger(o.at)) throw new RangeError('at must be an integer epoch-millisecond time');
  const confirmed = [...(o.confirmed ?? p.confirmedSensitive)].sort();
  const expires_at = o.at + ttl;
  return { challenge: approvalChallenge(p, r, confirmed, expires_at), confirmed, expires_at };
}

/** Build the approval from a finished assertion. `o` must be the same request the challenge was made from. */
export function buildPasskeyApproval(p: Proposal, r: Report, response: AssertionResponseLike, o: PasskeyRequest): PasskeyApproval {
  const { confirmed, expires_at } = passkeyChallenge(p, r, o);
  return {
    v: 1, kind: 'pca-autopilot-approval', method: 'passkey', proposal_digest: p.digest, report_digest: r.digest, confirmed, principal: o.principal, at: o.at, expires_at,
    assertion: { authenticatorData: b64u(bytes(response.authenticatorData)), clientDataJSON: b64u(bytes(response.clientDataJSON)), signature: b64u(bytes(response.signature)) },
  };
}

/** The slice of `navigator.credentials` used. */
export interface CredentialsLike {
  get(o: { publicKey: { challenge: Uint8Array; rpId: string; userVerification: 'required'; timeout: number; allowCredentials?: { type: 'public-key'; id: Uint8Array }[] } }): Promise<{ response: AssertionResponseLike } | null>;
}

/**
 * Ask the reviewer's passkey to approve (browser). Pass `credentials` (default `navigator.credentials`) and, when the reviewer
 * has more than one passkey, the registered `credentialId`. User verification is always required.
 */
export async function requestPasskeyApproval(p: Proposal, r: Report, o: PasskeyRequest & { rpId: string; credentialId?: Uint8Array; credentials?: CredentialsLike; timeoutMs?: number }): Promise<PasskeyApproval> {
  const creds = o.credentials ?? (globalThis as { navigator?: { credentials?: CredentialsLike } }).navigator?.credentials;
  if (creds === undefined) throw new Error('no WebAuthn credentials API here: run this in a browser or pass `credentials`');
  const { challenge } = passkeyChallenge(p, r, o);
  const cred = await creds.get({ publicKey: { challenge, rpId: o.rpId, userVerification: 'required', timeout: o.timeoutMs ?? 60_000, ...(o.credentialId !== undefined ? { allowCredentials: [{ type: 'public-key' as const, id: o.credentialId }] } : {}) } });
  if (cred === null || cred === undefined) throw new Error('the passkey ceremony was cancelled');
  return buildPasskeyApproval(p, r, cred.response, o);
}

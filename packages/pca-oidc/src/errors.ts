/** The typed error of ID-token verification (kept in its own module so `jwks.ts` and `verify.ts` share it without an import cycle). */

/** A stable classification of why ID-token verification failed. */
export type OidcVerificationErrorCode =
  | 'config'
  | 'invalid_token'
  | 'signature'
  | 'issuer'
  | 'audience'
  | 'expired'
  | 'issued_at'
  | 'not_before'
  | 'nonce'
  | 'azp'
  | 'at_hash'
  | 'c_hash'
  | 'keys'
  | 'claims';

/** The error thrown for any ID-token verification failure. `code` classifies the cause. */
export class OidcVerificationError extends Error {
  override readonly name = 'OidcVerificationError';
  readonly code: OidcVerificationErrorCode;
  constructor(code: OidcVerificationErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.code = code;
  }
}

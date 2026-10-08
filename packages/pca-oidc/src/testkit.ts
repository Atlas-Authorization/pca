/**
 * Test-only helpers: a local OIDC issuer (an in-memory JWKS + an ID-token minter) and a PCA principal
 * keypair whose public key is advertised as the ID token's `cnf` OKP JWK. Nothing here touches the
 * network. Not exported from the package barrel.
 */
import { SignJWT, exportJWK, generateKeyPair, type JWK, type JWTPayload, type KeyLike } from 'jose';
import { b64u, generateKeyPair as generatePcaKeyPair, type KeyPair } from '@atlasauth/pca';

export interface LocalIssuer {
  issuer: string;
  /** The IdP's signing key (private). */
  signingKey: KeyLike;
  /** The IdP's public verification key — pass as `verifyIdToken`'s `key`. */
  publicKey: KeyLike;
  /** The IdP's public JWK (with a `kid`), e.g. to assemble a JWKS. */
  publicJwk: JWK;
  /** Mint a signed ID token from a claims payload (sets alg + kid header). */
  mint(payload: JWTPayload, header?: { alg?: string; kid?: string; typ?: string }): Promise<string>;
}

const KID = 'test-key-1';

/** Create an in-memory EdDSA OIDC issuer. */
export async function makeIssuer(issuer = 'https://idp.example.com'): Promise<LocalIssuer> {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { extractable: true });
  const publicJwk: JWK = { ...(await exportJWK(publicKey)), kid: KID, alg: 'EdDSA', use: 'sig' };
  return {
    issuer,
    signingKey: privateKey,
    publicKey,
    publicJwk,
    async mint(payload, header = {}) {
      return new SignJWT(payload)
        .setProtectedHeader({ alg: header.alg ?? 'EdDSA', kid: header.kid ?? KID, ...(header.typ !== undefined ? { typ: header.typ } : {}) })
        .sign(privateKey);
    },
  };
}

/** A PCA principal keypair plus its public key as an OIDC `cnf` OKP JWK (`cnf.jwk.x` === b64u(pub)). */
export interface PrincipalBinding {
  keyPair: KeyPair;
  /** b64u Ed25519 public key — the core's `principalPublic` / `expectedRootIssuer`. */
  principalPublic: string;
  /** The `cnf` claim to embed in the ID token proving possession of the principal key. */
  cnf: { jwk: JWK };
}

/** Generate a core PCA keypair and the matching `cnf` OKP JWK for the ID token. */
export function makePrincipalBinding(): PrincipalBinding {
  const keyPair = generatePcaKeyPair();
  const principalPublic = b64u(keyPair.publicKey);
  const jwk: JWK = { kty: 'OKP', crv: 'Ed25519', x: principalPublic };
  return { keyPair, principalPublic, cnf: { jwk } };
}

/** Standard, valid ID-token claims for `issuer`/`audience`, `ttlSec` from `nowSec`. */
export function baseClaims(args: {
  issuer: string;
  audience: string;
  sub?: string;
  nowSec?: number;
  ttlSec?: number;
  extra?: JWTPayload;
}): JWTPayload {
  const now = args.nowSec ?? Math.floor(Date.now() / 1000);
  return {
    iss: args.issuer,
    sub: args.sub ?? 'user-123',
    aud: args.audience,
    iat: now,
    exp: now + (args.ttlSec ?? 3600),
    ...args.extra,
  };
}

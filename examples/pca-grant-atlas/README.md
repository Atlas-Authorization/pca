# pca_grant over OAuth

Keep your authorization server. Add one authorization-details type and one check at the resource server.

The authorization server issues an ordinary access token whose `authorization_details` names the grant by digest:

```json
{ "type": "pca_grant", "chain_digest": "...", "chain_len": 1, "locations": ["https://api.example.com"] }
```

The resource server reads it with `authorizePcaGrantToken` from `@atlasauth/pca-oauth` and still requires a verified
per-action proof (a PCActn) on every call. The token alone is never enough; a token cannot be lent to a different agent
because the proof must carry the chain the token names.

## Run it

```bash
npm install
npm start
```

```
authorization_details = %5B%7B%22type%22...
token + verified proof -> ALLOWED
token alone            -> DENIED
```

## Against an Atlas instance

Atlas implements RFC 9396. Enable the type for the instance (`oauthProvider.authorizationDetailsTypesSupported` includes
`pca_grant`), request a token with the `authorization_details` the script prints, and run the script with `ATLAS_ISSUER`,
`ATLAS_CLIENT_ID`, `ATLAS_CLIENT_SECRET` and `ATLAS_ACCESS_TOKEN` set. Atlas stores the requested details on the grant and
returns them in the token response and in introspection (`/oauth2/introspect`), which is where the script reads them.

Atlas checks the *type* against the instance allowlist; the shape of a `pca_grant` entry is checked by the resource
server (`parsePcaGrantDetails`), so a malformed entry is refused at the point of use.

The same pattern works with any authorization server that documents RFC 9396 custom types. Auth0 and Atlas do; for Entra ID, WorkOS, Stytch and Descope the public documentation read on 2026-10-26 does not show support (see the guide "Carry a PCA grant in your OAuth server" for sources).

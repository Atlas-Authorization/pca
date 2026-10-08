# @atlasauth/pca-cli

The pca dev CLI: decode and explain a PCActn (why it passed or failed each check), mint a dev grant/key, and simulate a policy over actions.

## Install

```sh
npm i -g @atlasauth/pca-cli
# or: npx @atlasauth/pca-cli <command>
```

Installs the `pca` binary. Depends on the core `@atlasauth/pca`.

## Usage

```sh
# Summarize a PCActn (JSON or base64url; '-' reads STDIN).
pca decode action.json
pca decode -

# Run the REAL verifier and explain each check (PASS / FAIL / —), with a final ALLOW/DENY.
pca explain action.json --aud ins_acme

# Mint a throwaway Ed25519 dev keypair.
pca keygen

# Replay actions against a compiled policy (auto / step_up / deny + budget).
pca simulate policy.json actions.json
```

The programmatic functions (`cmdDecode`, `cmdExplain`, `cmdKeygen`, `cmdSimulate`) are also exported. `decode` / `explain` are read-only inspectors — `explain` runs `verifyPCActnCore` against the grant in the PCActn's own capability chain, so its verdict is the local, grant-relative view. Nothing here authorizes anything; the resource server's verifier, with its stored counter / revocation state, remains the authority.

Part of Proof-Carrying Authority — see `@atlasauth/pca`.

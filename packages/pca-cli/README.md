# @atlasauth/pca-cli

The `pca` developer CLI for Proof-Carrying Authority (PCA). Decode a PCActn, run the verifier and see why it passed or failed each check, mint a throwaway dev keypair, simulate a policy over a list of actions, and emit a `.well-known/pca-configuration` discovery document.

## Install

```sh
npm i -g @atlasauth/pca-cli
# or run without installing:
npx @atlasauth/pca-cli <command>
```

This installs the `pca` binary. It depends on `@atlasauth/pca`.

## Usage

```sh
# Summarize a PCActn (JSON or base64url). A file path, or '-' to read STDIN.
pca decode action.txt
pca decode -

# Run the core verifier and explain each check (PASS / FAIL / -), ending in ALLOW or DENY.
pca explain action.txt --aud ins_acme

# Mint a throwaway Ed25519 dev keypair (base64url).
pca keygen

# Replay actions against a compiled policy: auto / step_up / deny, with the trust budget after each.
pca simulate policy.json actions.json

# Emit a discovery document for a resource server to publish.
pca discovery --aud ins_acme [--suites ed25519,ml-dsa-65] [--stepup <url>] [--revocation <url>] [--beacon <url>] [--attest <url>]
```

Input files:

```jsonc
// policy.json
{ "permissions": { "stripe": ["refund"] }, "limits": { "refund": "$500/day" } }
// actions.json
[ { "verb": "stripe.refund", "resource": "charge:ch_1", "params": { "amount": 42 } } ]
```

The command functions (`cmdDecode`, `cmdExplain`, `cmdKeygen`, `cmdSimulate`, `cmdDiscovery`) are also exported for programmatic use.

## Status

`decode`, `explain` and `simulate` are read-only inspectors for development. `explain` verifies against the grant in the PCActn's own capability chain, so its verdict is the local, grant-relative view; checks that need server-side state (revocation, attestation, threshold co-signatures, taint) are shown as not enforced. Nothing here authorizes anything: the resource server's verifier, with its stored counter and revocation state, remains the authority. Cryptography in PCA is unaudited.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE

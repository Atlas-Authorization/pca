# @atlasauth/pca-cli

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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

## Action definitions

`pca actions` describes your own actions, their business rules, and publishes them. A project is a directory (default `actions/`) of YAML files and a `pca.config.json`. Every action is unconfirmed, and treated as the most dangerous kind, until a reviewer confirms it.

```sh
# Scaffold. Templates: minimal, saas, db, mcp, or a starter pack for a business type:
# ecommerce, fintech, healthcare, saas_admin, devtools (typical actions, custom traits, business rules; all unconfirmed).
pca actions init --ns shop --template ecommerce

# Draft actions from an existing description: openapi, mcp, graphql, grpc, asyncapi, jsonschema.
pca actions import openapi.json --from openapi --ns shop --out actions/shop.yaml

pca actions explain shop.order.refund   # the policy card and each business rule in plain language
pca actions lint                         # definition and business-rule findings (LR-001..LR-004)
pca actions test                         # every example, including the rules examples

# Review and sign (a reviewer key); also signs the business rules into pca.rules-reviews.json.
pca actions confirm shop.order.refund --file actions/shop.yaml --kid rv_ada --reviewer-key "$REVIEWER_KEY" --yes

pca actions build                                          # .pca/: pack, schema, cards, rules.json, ...
pca actions sign --kid shop-publisher --key @publisher.key # signs the schema and the pack
pca actions publish --api https://YOUR_INSTANCE_API        # secret key from --sk or ATLAS_SECRET_KEY

# Re-import the sources listed in pca.config.json ("sources": [{"name", "from", "url" | "file"}]).
pca actions sync            # writes <name>.sync.yaml and the pca.sync.json lock
pca actions sync --check    # writes nothing; exit 1 when a source changed (for CI)
```

`publish --api` writes `.well-known/pca-actions.json`, anchors the schema in the instance, and publishes the signed pack with its business rules and custom traits to the instance's action registry. The instance accepts it only when the pack is signed by a publisher key it pins, and refuses (`widen_unreviewed`) a version that lets any action do more than before without a reviewer's signature; the refusal names the actions. On success it prints the new version and what changed for each action. Removed actions are deprecated.

`sync` reports each operation as added, changed, unchanged or removed. Added and changed actions land unconfirmed; unchanged ones keep their confirmation and their business rules; removed ones are deprecated at the next publish.

## GitHub Action

The repository ships a composite action that runs `pca actions sync`. Check on pull requests, sync on a schedule:

```yaml
- uses: Atlas-Authorization/pca/packages/pca-cli/github-action@v0.5.0
  with:
    dir: actions
    mode: check   # fails when a source changed; "sync" rewrites the generated files and sets the output `changed`
```

Inputs: `dir` (default `actions`), `mode` (`check` or `sync`), `source` (one source only), `cli-version`, `node-version`, and, in sync mode, `publish: 'true'` with `api-url`, `secret-key`, `signing-kid` and `signing-key` to lint, test, build, sign and publish after syncing. Pass keys from secrets only. Committing the synced files is up to your workflow.

See the guide "Define your own actions" for business rules, the dashboard workflow and the full workflow example.

## Status

`decode`, `explain` and `simulate` are read-only inspectors for development. `explain` verifies against the grant in the PCActn's own capability chain, so its verdict is the local, grant-relative view; checks that need server-side state (revocation, attestation, threshold co-signatures, taint) are shown as not enforced. Nothing here authorizes anything: the resource server's verifier, with its stored counter and revocation state, remains the authority.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE

# create-pca-app

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Scaffold a runnable Proof-Carrying Authority (PCA) app in one command. The starter mints a capability, has an agent sign proof-carrying actions, and shows a resource server verifying them: valid actions pass, tampered or out-of-scope ones fail.

## Install

Nothing to install; run it with your package manager's `create` command:

```sh
npm create pca-app@latest my-pca-app
cd my-pca-app
npm install
npm start
```

or `npx create-pca-app my-pca-app`. Run without a directory to be prompted; pass `--yes` to accept defaults.

## Usage

The default template (`pca-demo`) starts a local resource server, a FROST 3-of-5 guardian and an agent, plays nine scripted outcomes (allow, off-plan deny, step-up, replay, tamper, budget exhaustion, sub-agent attenuation, offline receipt) and exits nonzero if any deviates. `npm run step` pauses between steps; `npm run json` prints a machine-readable result. No cloud account, Docker or API key is needed.

The generated project contains `story.mjs` (the script, readable top to bottom), `run.mjs` (the runner, with `--step`, `--json`, `--no-color`) and `load.mjs`. The agent proves each action and the server's verifier allows or denies; nothing in the starter authorizes on its own.

## Templates

```sh
create-pca-app my-app --template pca-demo         # default: the nine-outcome story
create-pca-app my-app --template pca-quickstart   # an Express route guarded by requirePCA()
create-pca-app my-app --template node-quickstart  # the whole loop in one file, no server
create-pca-app my-app --template express-rs       # a resource server verifying the PCA-Action header, plus a client
create-pca-app my-app --template mcp              # an MCP server whose tools require a PCActn, plus an MCP agent
create-pca-app my-app --template attacks          # seven agent attacks vs OAuth, RAR, macaroons/Biscuit, UCAN and PCA
create-pca-app my-app --template actions          # define actions in YAML; lint, test, explain, build and sign them
create-pca-app my-app --template payments         # an agent that pays under $200/day alone and asks a person above $50
create-pca-app my-app --template delegation       # a narrower sub-agent, protect() on the server, revocation, explainRefusal()
create-pca-app my-app --template goal             # goal to policy: draft, review, sign, enforce
```

Options: `-t, --template <name>`, `-y, --yes`, `-h, --help`.

## Fail-closed behaviour

| Missing or invalid | Result |
|---|---|
| Unknown `--template` value | Exits 1 with the list of valid templates; nothing is written |
| `--template` with no value | Exits 1; nothing is written |
| Target directory exists and is not empty | Refuses and exits 1; existing files are never overwritten |
| Template files missing from the installed package | Exits 1 with an error; no project is created |
| The generated demo deviates from its scripted outcomes | `npm start` exits nonzero |

## Limits

- It only copies a starter project; it does not install dependencies, contact a network service or authorize anything.
- The generated apps are learning material with throwaway keys and in-memory state, not production code.
- It does not choose a store, audience or grant for you; replace those before real use.

## Status

The generated apps depend on `@atlasauth/pca` and, depending on the template, `@atlasauth/pca-fetch`, `@atlasauth/pca-express` or `@atlasauth/pca-mcp` (with `@modelcontextprotocol/sdk`). The cryptography in these packages has not been independently audited; treat the starters as learning material, not production code.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE

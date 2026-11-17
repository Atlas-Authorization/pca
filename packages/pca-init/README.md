# @atlasauth/pca-init

> Maturity: **production**. Breaking changes to APIs or defaults are never made in a patch release. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Add Proof-Carrying Authority to an app you already have, with one command.

```sh
npx @atlasauth/pca-cli init            # detect your project and show the plan as a diff (writes nothing)
npx @atlasauth/pca-cli init --yes      # apply it
```

`pca init` is also a library. The command is the `init` subcommand of `@atlasauth/pca-cli`.

## What it does

1. **Detects** the language and framework from your manifests: Express, Fastify, Hono, Next.js and NestJS; FastAPI, Flask and Django; Rails and Sinatra; net/http, Gin, Echo and chi; Spring Boot; ASP.NET Core; Laravel and Symfony; axum and actix; Vapor. It also lists the agent frameworks (LangChain, the OpenAI Agents SDK, the Anthropic SDK, the Vercel AI SDK, LlamaIndex, MCP SDKs) and the MCP servers your project defines.
2. **Shows the plan** as a diff. Without `--yes` it is always a dry run, so in CI it never changes anything unless you ask.
3. **Applies it** with `--yes`:
   - adds the right PCA package (`@atlasauth/pca` plus the Express, Fastify, Hono or Next.js adapter) to `package.json`;
   - JavaScript and TypeScript: writes a wiring file and adds exactly one import and one registration line to your entry file, using the TypeScript compiler to find the line that creates the app. If it cannot find that line with certainty (two apps, a file that does not parse) it prints the lines instead of editing;
   - other languages: prints the install command and the exact snippet with the file and line to paste it at. Nothing in your source is edited blind;
   - generates a local dev key in `.pca/dev.key` (mode 0600), adds it and the local logs to `.gitignore`, and refuses if the key path is already tracked by git or git would not ignore it;
   - writes `pca.init.json` with **observe** mode on, so nothing breaks on day one;
   - drafts action definitions from an OpenAPI file, an MCP tool list (`mcp-tools.json`) or the routes it reads from your source. Every one is unconfirmed (treated as the most dangerous kind) until a reviewer signs it.
4. **Prints what to do next**, with the exact commands for your project.

It refuses to apply on a dirty git tree unless you pass `--force`, never overwrites a key, an action file, or a wiring file you edited, and is idempotent: running it again plans nothing.

## No code at all: `--proxy`

```sh
npx @atlasauth/pca-cli init --proxy --yes
```

Writes a `pca-proxy.yaml` (one per MCP server when there are several) in observe mode, validated with the proxy's own parser, and prints the one command that runs it. Your app does not change. MCP server environment variables are never copied: only their names are reported.

## Observe, then enforce

In observe mode the wiring records every request that succeeded to `.pca/observed.jsonl` and blocks nothing. A failed request is never recorded, so it cannot widen what is learned.

```sh
npx @atlasauth/pca-cli autopilot observe .pca/observed.jsonl
npx @atlasauth/pca-cli autopilot propose autopilot.traces.json
npx @atlasauth/pca-cli autopilot verify autopilot.proposal.json autopilot.traces.json
npx @atlasauth/pca-cli autopilot review autopilot.proposal.json autopilot.report.json \
    --reviewer-key=@.pca/dev.key --holder "$(cat .pca/dev.key.pub)" --goal "my agent" --grant-out autopilot.grant.json --yes
npx @atlasauth/pca-cli init --mode enforce
```

Enforce mode runs the real adapter with `protect()` from `@atlasauth/pca` (default deny, bound to the operation each route executes) against `autopilot.grant.json`, and the app refuses to start without it. Only a human's signature creates that grant; nothing observed enables enforcement by itself. Use a durable replay store before running more than one process.

The guards for Python, Ruby, Go, Java, .NET, PHP, Rust and Swift have no observe mode: the printed snippet registers them only when `PCA_MODE=enforce`. To observe first, use `--proxy`.

## Verbs match your actions

When init imports actions from an OpenAPI file or the route table, it also writes `pca.routes.json`: the method and path template of each action and its verb. The generated wiring resolves every request through it with the same route matcher pca-proxy uses (a literal segment beats a parameter; segments match exactly), so what is observed, proposed and enforced carries the verb of its action. A route with no action definition is logged as `unmapped` in observe mode (so autopilot can propose it) and denied in enforce mode. With no imported routes the verb is `<ns>.<method>` and nothing is denied as unmapped.

## Report to the control plane: `--connect`

```sh
npx @atlasauth/pca-cli init --yes --connect <setup token> [--connect-url https://api.atlasauth.net]
```

Create the single-use setup token in the dashboard (Agents, Get started). Init generates a separate source key (`.pca/source.key`, gitignored), registers its public half with the control plane using the token (the token is sent once and never stored), and the generated wiring then reports each observed event, signed with the source key, in addition to the local file. The server pins the key under the setup run's source id and ignores any id we propose, so events are reported under the `source` it returns (saved in `.pca/connect.json`, with the instance's grant signer). The ingest key is scoped to ingest only. If the reply is lost, run the same command again: the same token with the same key returns a fresh ingest key. Events carry the verb and the resource; add `--include-params amount,quantity` to also let those parameters (safe integers and booleans only, never a name that looks like a credential or personal data) travel with a digest that binds them to the event, so proposals built on the control plane can bound amounts. JavaScript and TypeScript wiring only for now.

### Enforce with the issued grant

```sh
npx @atlasauth/pca-cli init --enforce --grant grant.json          # the diff first
npx @atlasauth/pca-cli init --enforce --grant grant.json --yes    # then apply it
npx @atlasauth/pca-cli init --observe --yes                       # and back
```

The grant must verify under the signer saved at connect (or `--signer KEY`): a tampered grant or the wrong signer is refused, now and again at every start of the app. The wiring then enforces exactly what the grant admits and can only tighten what you allow; allowed requests are reported with mode `enforce`. It refuses to enforce without a grant, and running it again changes nothing.

## Check an integration

```sh
npx @atlasauth/pca-cli init --check [--url https://my-app.example]
```

Verifies the package, the registration, the configuration, that the key is neither tracked nor readable by other users, and the mode. In enforce mode it also runs the `@atlasauth/pca-doctor` suite checks, and with `--url` the doctor's clock and proxy checks against the running app. Exit code 1 on any failure.

## Flags

| Flag | Meaning |
| --- | --- |
| `--yes` | apply the plan (default is a dry run) |
| `--dry-run` | print the plan only, even with `--yes` |
| `--force` | apply on a dirty git tree |
| `--app DIR` | the app to initialize in a monorepo (asked for when there are several) |
| `--proxy` | the zero-code path |
| `--server NAME` | with `--proxy`, one MCP server |
| `--upstream URL` | with `--proxy` for an HTTP service, its address |
| `--mode observe\|enforce` | switch mode (enforce needs the signed grant) |
| `--ns NAME` | the action namespace (default: your package name) |
| `--no-import` | skip drafting actions |
| `--check`, `--url URL` | verify an existing integration |
| `--enforce --grant FILE`, `--signer KEY`, `--observe` | switch to enforce with an issued grant, and back |
| `--include-params a,b` | parameters allowed to be reported with `--connect` |
| `--connect TOKEN`, `--connect-url URL` | register a source key with the control plane and report observed events |

## Limits

- The generated wiring derives each operation from the HTTP method and path (`<ns>.<method>` on the path). It is the starting point; map your routes to richer verbs by editing the generated file.
- Observed parameters are numbers and booleans only: strings can carry personal data and are neither logged nor learned.
- The wiring reads `pca.init.json` from the working directory (or `PCA_DIR`): run the app from its own folder.

# @atlasauth/pca-dev-mcp

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Most developers add PCA by asking their coding agent to. This package makes that work the first time: an MCP server the
agent calls to learn what your project is and exactly what to change, and rules and skills that teach Claude Code, Cursor,
Codex, Windsurf, Cline and Gemini CLI when and how to use it.

The server is **read-only by default**. It plans and explains; your coding agent makes the edits.

## Set it up (one command)

```sh
npx @atlasauth/pca-cli agent-kit install
```

It finds the coding agents configured in your repo, writes the matching rule or skill file for each, and prints the MCP
config for each. Then add the server to your agent:

```sh
claude mcp add pca -- npx -y @atlasauth/pca-dev-mcp          # Claude Code
```

Cursor (`.cursor/mcp.json`), Windsurf, Cline and Gemini CLI take the same `mcpServers` entry; Codex takes a TOML entry. The
install command prints each.

| Agent | File written |
|---|---|
| Claude Code | `.claude/skills/pca/SKILL.md` (a skill; triggers on "add PCA", "agent authorization", "protect this MCP server") |
| Cursor | `.cursor/rules/pca.mdc` |
| Codex and any `AGENTS.md` reader | a marked block in `AGENTS.md` |
| Windsurf | `.windsurf/rules/pca.md` |
| Cline | `.clinerules/pca.md` |
| Gemini CLI | a marked block in `GEMINI.md` |

A file the installer did not write is never overwritten, and a shared file keeps everything outside the marked block.
`--harness cursor,claude` picks agents, `--all` writes every format, `--dry-run` shows what it would do.

Then say to your agent: "add PCA to this project".

## Tools

| Tool | What it does |
|---|---|
| `pca_detect` | What the project is (detected by the same code as `npx @atlasauth/pca-cli init`) (languages, frameworks, MCP server, OpenAPI) and which integration fits: a proxy in front of an MCP server or API (no code change), a guard in your framework, or the agent side. |
| `pca_plan_integration` | The plan `pca init` would apply (it is produced by the same function, so the CLI and your agent always agree), as structured steps: one apply command, then each file change, install command and snippet. Steps that need a human decision or signature are marked `human: true`. |
| `pca_explain` | Run the real verifier on a PCActn and explain each check, or explain a refusal reason (or a proxy audit line) with the fix. |
| `pca_lint_policy` | Lint a policy, grant or delegation chain: over-broad grants, privilege escalation, redundant caveats. |
| `pca_simulate` | Replay actions against a policy offline: auto, step-up or deny, and the budget left. |
| `pca_actions_import` | Draft actions from OpenAPI, an MCP tool list, GraphQL, gRPC, AsyncAPI or JSON Schema. Everything drafted is unreviewed until a human confirms it. |
| `pca_doctor` | Check a deployment's assumptions: clocks, replay store, proxy hops, suite policy. May send requests to the URL you give it. |
| `pca_docs_search` | Search the PCA docs bundled with the package. Local; no network. |

### Writing

`pca-dev-mcp --allow-write` adds one more tool, `pca_apply_step`, which writes one planned file: a new file is never written over an
existing one, and an edit is written only if the file is exactly as the plan saw it. It refuses on a dirty git tree, never writes
key material, never runs a command and never signs anything. Without the flag no tool
changes a file. `pca_doctor` only loads a store adapter module with `--allow-write` (an adapter is code).

### Options

```
pca-dev-mcp [--root DIR] [--allow-write]
```

`--root` is the project the tools default to (default: the current directory). Tool `path` arguments stay inside it.

## Library

```ts
import { createServer, fsInspector, installKit } from '@atlasauth/pca-dev-mcp';

const server = createServer({ root: process.cwd() });          // pass { inspector } to replace project detection
await server.serve(process.stdin, (line) => process.stdout.write(line + '\n'));
installKit(process.cwd(), { harnesses: ['cursor'] });
```

## What the rules teach

The integration recipe per language and framework; default deny; observe before enforce; never disable a check to make a
test pass; keys are never committed; anything learned or inferred is a proposal a human signs; and the usual refusals and
their fixes.

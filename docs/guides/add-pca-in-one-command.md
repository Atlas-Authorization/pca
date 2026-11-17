# Add PCA to your app in one command

You have an app, or an agent with MCP servers, and you want Proof-Carrying Authority in front of it without reading a spec first. This is the path: one command to set it up in a mode that blocks nothing, then a short loop that turns what your app actually does into a signed policy.

```sh
cd my-app
npx @atlasauth/pca-cli init          # shows the plan as a diff and writes nothing
npx @atlasauth/pca-cli init --yes    # applies it
```

## What you get

`init` reads your manifests and detects the language and framework (Express, Fastify, Hono, Next.js, NestJS, FastAPI, Flask, Django, Rails, Sinatra, Go net/http, Gin, Echo, chi, Spring Boot, ASP.NET Core, Laravel, Symfony, axum, actix, Vapor), plus any agent frameworks and MCP servers it finds. With `--yes` it:

- adds the PCA package for your framework to `package.json` (run your install afterwards);
- for JavaScript and TypeScript, writes `pca.setup.ts` (or `.js`) and adds one import and one registration line to the file that creates your app. If it cannot find that line with certainty it prints the lines for you to paste;
- for every other language, prints the install command and the exact snippet, with the file and line to put it at;
- creates `.pca/dev.key` (mode 0600), adds it to `.gitignore`, and refuses if that path is tracked by git;
- writes `pca.init.json` with **observe** mode, so nothing breaks;
- drafts action definitions from your OpenAPI file, your MCP tool list or your routes. Each is unconfirmed until a reviewer signs it.

It refuses to apply on a dirty git tree (pass `--force` to override), and running it twice changes nothing the second time. In a monorepo it asks which app; pass `--app services/api`.

## No code at all

If you would rather not touch the app, put the proxy in front of it:

```sh
npx @atlasauth/pca-cli init --proxy --yes
```

This writes a `pca-proxy.yaml` for your MCP servers (found in `.mcp.json`, `mcp.json`, `.cursor/mcp.json` or `.vscode/mcp.json`) or for your HTTP service, in observe mode, and prints the one command that runs it. Your MCP client launches that command instead of the server.

## Then: observe, propose, review, enforce

1. **Run your app.** In observe mode every successful request is recorded to `.pca/observed.jsonl`, and nothing is blocked. (With `--proxy`, the log is `.pca/proxy-audit.jsonl`.)
2. **Learn from it.**

   ```sh
   npx @atlasauth/pca-cli autopilot observe .pca/observed.jsonl
   ```

3. **Propose the tightest grant, and prove it covers what happened.**

   ```sh
   npx @atlasauth/pca-cli autopilot propose autopilot.traces.json
   npx @atlasauth/pca-cli autopilot verify autopilot.proposal.json autopilot.traces.json
   ```

4. **Review it and sign once.** Nothing is authority until a human signs.

   ```sh
   npx @atlasauth/pca-cli autopilot review autopilot.proposal.json autopilot.report.json \
       --reviewer-key=@.pca/dev.key --holder "$(cat .pca/dev.key.pub)" --goal "my agent" \
       --grant-out autopilot.grant.json --yes
   ```

   The dev key is for trying this out. For production, sign with a key (or passkey) only you hold.

5. **Switch to enforce.**

   ```sh
   npx @atlasauth/pca-cli init --mode enforce
   ```

   Requests without a valid proof for the operation they perform are now refused, and the app will not start without `autopilot.grant.json`.

## Check it any time

```sh
npx @atlasauth/pca-cli init --check
```

Reports whether the package is installed, the guard is registered, the configuration is valid, the key is untracked, ignored and private, and which mode you are in. In enforce mode it also runs the PCA doctor; add `--url https://my-app.example` to check the running app's clock and proxy settings.

## Notes

- Guards for Python, Ruby, Go, Java, .NET, PHP, Rust and Swift enforce only: the printed snippet registers them when `PCA_MODE=enforce`. Use `--proxy` to observe those apps first.
- The generated wiring maps each request to an operation by method and path. Edit the generated file to use your own verbs.
- Use a shared replay store before you run more than one process in enforce mode.

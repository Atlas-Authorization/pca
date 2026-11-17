# PCA in a box

Try the whole flow on your machine in a few minutes: an API and an MCP server that an agent can reach only through
`pca-proxy`, first watched (observe mode), then locked down (enforce mode) from what a human reviewed and signed.

```sh
git clone https://github.com/Atlas-Authorization/pca && cd pca/packages/pca-proxy/deploy/pca-in-a-box
make demo
```

That needs Docker with Compose v2 and `make`. The first run builds one image from this repository's source (a few minutes);
dev keys are generated into a Docker volume on first start and nothing secret is in the repository. Everything listens on
`127.0.0.1` only. When it finishes, open **http://127.0.0.1:8080** for the live decisions.

## What is in the box

| Service | What it is |
|---|---|
| `orders-api` | A small orders API. It accepts one credential, the proxy's, and publishes no port: an agent cannot reach it directly. |
| `pca-proxy` | `pca-proxy http` in front of the API, on `127.0.0.1:8788`. Decides every call with the full PCA pipeline and writes a hash-chained receipt before forwarding. Starts in **observe** mode. |
| notes MCP server | A stdio MCP server with `search_notes`, `create_note` and `delete_note`. The agent reaches it through `pca-proxy mcp`, the way Claude Code or Cursor would launch it. |
| agent | A script that does what an agent would: create, list, get, refund and delete orders, call the three tools, and try a route that is not in the API. It holds no API credential and no SDK. |
| `dashboard` | A page that tails both audit logs: allowed, would-be-refused (observe) and refused (enforce), with the reason. |
| `directory-log`, `directory-witness` | Optional (`make trust`): an append-only log of agent passports and an independent witness that cosigns its heads. |

The proxy is the verifier here: it checks each call against the grant it holds (limits, caveats, replay counter, budget,
provenance) before the sample API sees it.

## The guided walk

`make demo` runs these four steps in order; run them one at a time to read each result.

**1. Observe.** `make up` starts the stack in observe mode and `make observe` runs the agent's routine work: create, list and read
orders through the API proxy, create and search notes through the MCP proxy. Every call goes through and is recorded in a hash-chained
audit log; `audit.observedParams` also records the numeric parameters autopilot needs. The command ends by checking the log, not the
agent's output.

**2. Autopilot proposes.** `make propose` verifies both audit logs and runs `pca autopilot observe`, `propose` and `verify` on each: it learns
the tightest grant for what the agent actually did and replays every observed action through the real verifier. This is a **proposal**.
It grants nothing, and anything sensitive or denied stays out unless a human confirms it.

**3. A human signs.** `make sign` runs `pca autopilot review --yes` for each proposal. In the box the dev reviewer key from the volume
signs, so the demo can run unattended; with your own project you read the plain-language summary (`pca autopilot review` without
`--yes` prints it) and sign with your own key. The result is a signed approval and an issued grant per proxy, in `/data/autopilot`.

**4. Enforce the signed grant.** `make enforce` refuses until step 3 has signed. It then writes each proxy's enforce config with
`agent.issuedGrant`: the grant file and the reviewer's public key, which is the only signer the proxy accepts. From then on a call runs
only if the signed grant admits it (its verb, resource, parameter caps and caveats), and what the grant admits needs no further human.
The agent runs again: its routine work is inside the grant and works; it also tries a refund, a delete, a note deletion and a route that
is not in the API. Nobody observed or signed those, so the grant refuses them (`grant_denied`) whatever the operator rules say, and the
unmapped route is refused by default deny. `make check` asserts exactly that from the audit log, and the hash chain continues unbroken
from observe mode.

The operator rules in `config/` describe what each action *is* (read or write, reversible or not); the signed grant decides what may run.
A grant can only tighten what the rules allow.

## Commands

```sh
make demo      # everything above
make up        # start in observe mode
make observe   # run the agent's routine work in observe mode, then check the log
make propose   # autopilot observe + propose + verify, for both proxies
make sign      # the human signs both proposals; grants are issued
make enforce   # enforce the signed grants, run the agent, check the log (needs make sign first)
make check     # run the agent in enforce mode again (fresh proxy state) and assert the audit log
make trust     # also start the trust directory log and witness
make logs      # follow the services
make down      # stop
make clean     # stop and delete the volume (keys, logs, state)
```

Try it yourself while the stack is up:

```sh
curl -s http://127.0.0.1:8788/orders                     # through the proxy: a mapped read
curl -s -X DELETE http://127.0.0.1:8788/orders/1         # observe: forwarded and recorded; enforce: refused (outside the signed grant)
docker compose -p pca-box --profile tools run --rm -T tools pca-proxy audit verify /data/audit/http.audit.jsonl
```

In enforce mode a write after the proxy relayed any content is held for a human (that is the prompt-injection defence), so `make check`
restarts the proxy with fresh enforce-mode state before it runs the agent; run the agent once per start.

## Put it in your cluster

`../helm/pca-proxy` is a Helm chart for the same proxy as a gateway or a sidecar, with the control-plane reporting agent. See its README.

## Notes

- One image serves every role (`Dockerfile`, build context is the repository root); `Dockerfile.dockerignore` keeps the context small.
- The containers run as root inside the box because it is a local demo; the Helm chart runs the proxy non-root with a read-only filesystem.
- Dev keys live in the `data` volume under `/data/keys`. Never reuse them. `make clean` deletes them.

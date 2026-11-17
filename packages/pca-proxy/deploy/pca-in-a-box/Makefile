# PCA in a box. Needs Docker with Compose v2. Run from this directory:  make demo
#   make demo      the whole story: observe -> autopilot propose -> sign -> enforce, on the sample, then check the audit logs
#   make up        start the stack in observe mode (dashboard: http://127.0.0.1:8080, proxy: http://127.0.0.1:8788)
#   make trust     also start the trust directory log and a witness
#   make down      stop; `make clean` also deletes the volume (keys, logs, state)
C := docker compose -p pca-box
RUN := $(C) --profile tools run --rm -T
HTTP_LOG := /data/audit/http.audit.jsonl
MCP_LOG := /data/audit/mcp.audit.jsonl
AP := /data/autopilot

.PHONY: demo up trust observe propose sign enforce check down clean logs

demo: up observe propose sign enforce
	@echo; echo "Dashboard: http://127.0.0.1:8080   (make down to stop, make clean to delete the volume)"

up:
	$(C) up -d --build --wait pca-proxy dashboard
	$(RUN) tools node /box/tools/mcp-config.mjs observe

trust:
	$(C) --profile trust up -d --build directory-log directory-witness
	@echo "log head:   curl -s http://127.0.0.1:8090/sth"
	@echo "witness:    curl -s http://127.0.0.1:8091/info"

# 1. watch the sample agent in observe mode (its routine work: create, list, get orders; create and search notes)
observe:
	$(RUN) agent --expect observe
	$(RUN) tools node /box/tools/check.mjs observe

# 2. learn the tightest grant for each proxy from what the agent did (a proposal only: it grants nothing)
propose:
	$(RUN) tools sh -c 'pca-proxy audit verify $(HTTP_LOG) --params $(HTTP_LOG).params.jsonl && pca-proxy audit verify $(MCP_LOG) && \
	  for n in http mcp; do \
	    log=/data/audit/$$n.audit.jsonl; params=""; [ $$n = http ] && params="--params $$log.params.jsonl"; \
	    pca autopilot observe $$log $$params --out $(AP)/$$n.traces.json && \
	    pca autopilot propose $(AP)/$$n.traces.json --out $(AP)/$$n.proposal.json && \
	    pca autopilot verify $(AP)/$$n.proposal.json $(AP)/$$n.traces.json --out $(AP)/$$n.report.json || exit 1; \
	  done'

# 3. the human reads each summary and signs. Here the dev reviewer key from the volume signs; use your own key for real.
sign:
	$(RUN) tools sh -c 'for n in http mcp; do \
	  pca autopilot review $(AP)/$$n.proposal.json $(AP)/$$n.report.json --reviewer-key @/data/keys/reviewer.key --yes \
	    --holder "$$(cat /data/keys/principal.pub)" --goal "handle customer orders" \
	    --out $(AP)/$$n.approval.json --grant-out $(AP)/$$n.grant.json || exit 1; \
	  done'

# 4. enforce the grants that were signed: the proxies load them (agent.issuedGrant) and pin the reviewer's key as the only signer.
#    Refuses until step 3 has signed.
enforce:
	$(RUN) tools sh -c 'test -s $(AP)/http.grant.json && test -s $(AP)/mcp.grant.json || { echo "not signed yet: run make sign first" >&2; exit 1; }'
	$(C) stop pca-proxy
	$(RUN) tools sh -c 'node /box/tools/enforce-config.mjs && node /box/tools/mcp-config.mjs enforce'
	$(MAKE) check

# the agent once (its routine work, then calls outside the grant), against a proxy that starts with fresh enforce-mode state (a write after relayed content waits for a human, so one run per start)
check:
	$(C) stop pca-proxy
	$(RUN) tools sh -c 'rm -rf /data/state-enforce /data/state-mcp-enforce'
	$(C) up -d --wait pca-proxy
	$(RUN) agent --expect enforce
	$(RUN) tools node /box/tools/check.mjs enforce

logs:
	$(C) logs -f --tail=50

down:
	$(C) --profile trust --profile tools down

clean:
	$(C) --profile trust --profile tools down -v

# Re-run the machine-checked evidence in this repository on a fresh Linux x86_64 machine.
#
#   make help                 list targets
#   make toolchain-check      compare installed tools with TOOLCHAIN.lock (never fails)
#   make verify               the cheap sanity pass: Dafny core + TLA+ contract models + pins (minutes)
#   make verify-all           every target below (many hours; needs every tool installed)
#
# Install tools first: verify/install-toolchain.sh <dafny|tamarin|proverif|lean|tla|easycrypt|verus|all-cheap>
# Targets that re-run a tool copy its sources to .verify-work/ first, so the committed result files under
# formal/*/results are never overwritten; compare afterwards with `diff -r formal/<x>/results .verify-work/<x>/results`.
# A timeout in Tamarin/ProVerif is NOT a proof; the run scripts print TIMEOUT explicitly.
# See docs/public/verification-index.md for what each target proves and what it does not cover.

SHELL := /bin/bash
DAFNY_DIR ?= $(HOME)/.pca-tools/dafny
export PATH := $(DAFNY_DIR):$(HOME)/tools/tamarin:$(HOME)/tools/maude:$(HOME)/.elan/bin:$(PATH)
WORK ?= $(CURDIR)/.verify-work
TAMARIN_TIMEOUT ?= 600
JOBS ?= 4

.PHONY: help toolchain-check verify verify-all verify-dafny verify-tla verify-tamarin verify-proverif \
        verify-cryptoverif verify-easycrypt verify-lean verify-leanmath verify-implverif \
        verify-conformance verify-trustbase verify-linearizability verify-audit clean-work

help:
	@sed -n '2,12p' Makefile
	@grep -E '^verify[a-z-]*:' Makefile | cut -d: -f1 | tr '\n' ' '; echo

toolchain-check:
	@bash verify/check-tools.sh

verify: toolchain-check
	bash verify/run-dafny.sh quick
	$(MAKE) verify-tla-quick

verify-all: verify-dafny verify-tla verify-tamarin verify-proverif verify-cryptoverif verify-easycrypt \
            verify-lean verify-leanmath verify-implverif verify-conformance verify-trustbase \
            verify-linearizability verify-audit

# --- Dafny: verified decision core, extension components, glue contract (Dafny 4.11.0 / z3 4.12.1, hash-pinned)
verify-dafny:
	bash verify/run-dafny.sh full

# --- TLA+/TLC: replay-store models (Postgres, Redis, in-memory, durable lock) and the ExactlyOnce contract
verify-tla-quick:
	@mkdir -p $(WORK) && rm -rf $(WORK)/tla && cp -R formal/tla $(WORK)/tla
	cd $(WORK)/tla && OUT=$(WORK)/tla/results bash run.sh contract_
verify-tla:
	@mkdir -p $(WORK) && rm -rf $(WORK)/tla && cp -R formal/tla $(WORK)/tla
	cd $(WORK)/tla && OUT=$(WORK)/tla/results bash run.sh
	@if command -v apalache-mc >/dev/null; then cd $(WORK)/tla && OUT=$(WORK)/tla/results bash run-apalache.sh; else echo "SKIPPED: apalache-mc not installed (unbounded-time ExactlyOnce proof)"; fi

# --- Tamarin 1.12.0: symbolic models of the PCA verification and protocols (heavy; per-lemma timeouts)
verify-tamarin:
	@mkdir -p $(WORK) && rm -rf $(WORK)/tamarin && cp -R formal/tamarin $(WORK)/tamarin
	cd $(WORK)/tamarin && sh ./run_all.sh $(TAMARIN_TIMEOUT)
	cd $(WORK)/tamarin && sh ./run_all_v2.sh $(TAMARIN_TIMEOUT) $(JOBS)

# --- ProVerif 2.05: the same models in a second tool; agreement table
verify-proverif:
	@mkdir -p $(WORK) && rm -rf $(WORK)/proverif && cp -R formal/proverif $(WORK)/proverif
	cd $(WORK)/proverif && bash ./run_all.sh $(JOBS) 1800 && python3 agreement.py

# --- CryptoVerif 2.13: computational proofs found automatically
verify-cryptoverif:
	@mkdir -p $(WORK) && rm -rf $(WORK)/proverif && cp -R formal/proverif $(WORK)/proverif
	cd $(WORK)/proverif/cv && bash ./run_cv.sh

# --- EasyCrypt r2026.09-29-ge7eff05 (+ Why3 1.8.2, Alt-Ergo 2.6.4, Z3, CVC5): game-hopping proofs
verify-easycrypt:
	bash formal/computational/check.sh ec

# --- Lean 4 v4.34.1: chain attenuation (core only) and formal/pca-lean
verify-lean:
	bash formal/computational/check.sh lean
	cd formal/pca-lean && lake build

# --- Lean 4 + Mathlib: forking lemma, knowledge soundness in the ROM, primality of 2^61-1
verify-leanmath:
	bash formal/computational/check.sh leanmath

# --- implementation lane that runs from this repo (Verus fragments, Lean reference model). Kani/CBMC/Miri: see script header.
verify-implverif:
	bash verify/run-implverif.sh

# --- model-to-code conformance (differential testing against packages/pca) + harness self-test; CONF=smoke|full
CONF ?= smoke
verify-conformance:
	bash verify/run-conformance.sh $(CONF)

# --- trusted-base pipeline: toolchain pin, proofs, generated-JS reproducibility, diverse compilation, SBOM
verify-trustbase:
	DAFNY_DIR=$(DAFNY_DIR) bash tools/pca-trustbase/run-all.sh

# --- replay-store linearizability checker (Go): unit tests of the checker itself; the campaigns need Postgres/Redis (see tools/pca-linearizability/)
verify-linearizability:
	cd tools/pca-linearizability && go test ./...

# --- audit program: fuzz regression gate, mutation-kill suites, traceability, static analysis, supply chain, timing self-check
verify-audit:
	bash scripts/pca-audit-all.sh

clean-work:
	rm -rf $(WORK)

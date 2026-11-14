# Attestation canary runbook

Internal. How to run the real-evidence canary for the vendor attestation verifiers, on the recorded evidence in the repository and on live hardware (owner action O-3).

## What it does

For each case in a manifest the canary builds the vendor verifier (AMD SEV-SNP, Intel TDX, Azure MAA, NVIDIA H100), verifies the evidence, then re-runs the same verifier with three negative controls. A case passes only if all of these hold:

1. the evidence verifies, is bound to the expected holder, grant, epoch and nonce, and returns a measured identity;
2. a relayed binding (other nonce), one flipped byte of the primary evidence and a wrong trust pin are each denied;
3. no certificate in the evidence, and no collateral `nextUpdate`, is within `warnDays` (default 14) of the case time.

Missing evidence files fail the case. An empty manifest fails. The process exits 0 only if every case passes.

## Recorded run (in CI)

`packages/pca/src/attest-canary.test.ts` runs `fixtures/attest-canary/manifest.json` (Azure Genoa SEV-SNP, Azure Intel TDX with PCS collateral, Azure MAA over the same TDX quote, an Azure H100 NVL) with a fixed clock. `attest-parser-fuzz.test.ts` mutates the same evidence thousands of times and requires that no mutation is accepted and none throws.

By hand: `cd packages/pca && tsx scripts/attest-canary.ts fixtures/attest-canary/manifest.json` prints the JSON report.

## Live run

1. On each machine, collect fresh evidence bound to a challenge you generate: SEV-SNP report + VCEK + ASK/ARK chain (+ runtime data on Azure), TDX quote + runtime data + current PCS collateral (TCB info, QE identity, PCK CRL, root CRL with their issuer chains), the MAA token + the instance's current signing certificates, the H100 attestation report + device chain + driver and VBIOS RIM files + current CRLs. The recorded fixtures' READMEs (`fixtures/real-*/README.md`) show each capture method.
2. Put the files and a `manifest.json` in one directory. Copy the case shape from the recorded manifest: `now` is `"now"`, `expected` is the binding you challenged with, and the pins (`measurements`, `mrtds`, `tdxMrtds`, `rootSpkiSha256`, `rimRootSpkiSha256`) are your own allowlist, not values read from the evidence.
3. Run `tsx scripts/attest-canary.ts <dir>/manifest.json` on a schedule (daily is enough for the collateral clocks; PCS TCB info and QE identity are re-issued about monthly). Alert on a non-zero exit. The report names the failing case, the control that was accepted, or the days left.

## What each failure means

| Report | Meaning |
|---|---|
| `positive verification failed: ...` | The verifier rejects the live evidence: TCB recovery (new TCB info, platform out of date), a rotated vendor or MAA signing certificate, an expired chain, a changed measurement. Read the reason. |
| `negative control accepted: <name>` | A verifier stopped denying. Treat as a security incident for the verifier, not for the machine. |
| `collateral expires in N days` | Refresh collateral or rotate the pinned root before it lapses. |
| `canary error (fail closed): evidence file ... is missing` | The collection step broke. |

## Pinned-root rotation

Vendor roots are pins in the verifier configuration (`AMD_ARK_SPKI_SHA384`, the Intel SGX Root CA SPKI, the NVIDIA device and RIM roots, the MAA signing certificates and chain roots). To rotate: where the verifier takes a list (the NVIDIA device and RIM roots, the MAA trust anchors) add the new pin next to the old one, deploy, run the canary with evidence chained to the new root, then remove the old pin. The AMD (per family) and Intel verifiers take a single pin: deploy the new pin together with the evidence that chains to it, and keep the canary on both generations of machines until the old one is retired. Never replace a pin with a value read from the evidence being verified.

## Limits

The canary shows the verifiers still behave on real evidence; it is not an audit. It does not exercise the post-quantum accountability anchoring, the hosted surface (software attestors only) or any vendor service outage. Live machines are owner action O-3.

---
title: Trusted-setup ceremony runbook
order: 41
---

# Trusted-setup ceremony runbook

The Groth16 compliance circuit and the Policy-VM circuit need a trusted setup. Whoever holds the setup randomness can forge proofs, so a key is only as good as the ceremony behind it. This runbook describes a multi-party phase-2 ceremony: the proving key stays sound if **at least one** participant destroys their randomness.

**Status.** The keys shipped for tests are single-party and are labelled `ceremony: single-party` (see "How the label works"). The tooling below is ready to run; no real ceremony has been held yet.

## Roles and inputs

- **Coordinator**: runs `init`, `accept`, `beacon`, `finalize`, `publish`. Does not need to be trusted for soundness; everything they produce is checked by `verify`.
- **Participants** (at least 3 recommended, each in a separate trust domain): run `contribute` on their own machine and return the new key.
- **Phase-1 file**: a widely contributed public powers-of-tau file of at least the circuit's size (2^18 for the Policy-VM circuit, 2^12 for the compliance circuit). Pin its SHA-256 from the publisher. BLS12-381 has no widely contributed public file; for that curve run your own phase 1 as a ceremony too (same participants rules) and publish its transcript.
- **Constraint system**: the `.r1cs` compiled from the circuit at the release commit. Publish its SHA-256 before the ceremony starts.

All commands run from `packages/pca` as `npx tsx circuits/ceremony/ceremony.ts <command> ...`. Every command stops with a non-zero exit and writes nothing on any error.

## Coordinator: start

```
circom circuits/policyvm.circom --r1cs -o build -l node_modules/circomlib/circuits
sha256sum build/policyvm.r1cs ptau/powersOfTau28_hez_final_18.ptau     # publish both hashes
ceremony.ts init --dir ceremony --circuit pca-policyvm-v1 --curve bn128 \
  --r1cs build/policyvm.r1cs --ptau ptau/powersOfTau28_hez_final_18.ptau \
  --ptau-sha256 <pinned hash> --min 3
```

`init` refuses a phase-1 file that does not match the pinned hash and refuses to overwrite a ceremony. Send `ceremony/zkeys/0000.zkey` to participant 1.

## Participant instructions

1. Use a machine you control, preferably freshly booted, offline except to receive and return the file. Have the repository at the release commit (or only `snarkjs`).
2. Run:
   ```
   ceremony.ts contribute --in 000N.zkey --out mine.zkey --name "<your name>" --entropy "<anything unpredictable you type>"
   ```
   The tool mixes 64 random bytes from the operating system with your text. Nothing is stored, so there is no secret to hand over; the only thing to protect is the machine's memory and disk during the run.
3. Publish the printed receipt (name and the two SHA-256 values) somewhere you control, such as your own site or a signed message, **before** returning the file. Return `mine.zkey` to the coordinator.
4. Power off or wipe the machine. Soundness needs only one honest, careful participant, so being thorough matters more than being quick.

## Coordinator: each contribution

```
ceremony.ts accept --dir ceremony --zkey mine.zkey --name "<participant name>"
```

`accept` checks the new key against the constraint system and phase-1 file, checks that it changed the key and extends the chain by exactly one step, and records it. Send the accepted `ceremony/zkeys/000K.zkey` to the next participant. Compare each participant's published receipt with the transcript entry.

## Beacon

After the last contribution, announce in advance a future unpredictable value (for example, the hash of a Bitcoin block at a stated height) that nobody can know when the last contribution is made. Then:

```
ceremony.ts beacon --dir ceremony --hash <64 hex characters of that value> --iterations-exp 10
ceremony.ts finalize --dir ceremony
```

`beacon` refuses to run with fewer than two contributions or fewer than `--min`. `finalize` exports the verifying key, computes its id (`vk_` followed by the SHA-256 of its canonical JSON), and verifies the whole directory. Record the printed transcript hash.

## Anyone: verify and publish

```
ceremony.ts verify --dir ceremony --min 3 --r1cs-sha256 <published hash> --transcript-sha256 <published hash>
ceremony.ts publish --dir ceremony --out release
```

`verify` fails when any of these is true: a file is missing; a key does not match its recorded hash; the constraint system or phase-1 file differs from the transcript or from the pinned hash; there are fewer than the required contributions; a contribution does not chain from the previous key or repeats a name; the beacon is missing, weak (fewer than 2^10 iterations), or not the last step; the final key is not the beacon output; the proving-key chain fails `snarkjs zkey verify` back to the phase-1 file; the beacon value is not recorded in the final key; or `verification_key.json` is not the key exported from the final proving key.

`publish` refuses an unverified ceremony and writes the transcript, the verifying key and `HASHES.json`. Publish the proving keys and every intermediate key separately (they are large) so others can re-run `verify`.

## Using the result

Pass the verifying key and the published transcript to the backend, with the transcript's SHA-256 obtained from the coordinator's announcement, not from the same download:

```ts
createPolicyVmSnarkBackend({ verificationKey, ceremony: { transcript, sha256: pinnedHash }, expectActionHash, expectPolicyHash, expectPlanHash });
```

## How the label works

The assurance report for a SNARK backend carries `ceremony`. It is `multi-party` only when the transcript's hash equals the pinned hash, the transcript is well formed (at least two distinct chained contributions, a valid beacon applied last), it names this circuit, and its key id equals the id of the verifying key in use. In every other case, including bundled keys and any error, it is `single-party`. The label states how the key was made; it does not say the circuit is correct. The check of the contributions themselves is `verify` above, which a deployer or auditor runs once on the published artifacts.

## Dev-only setup

`circuits/setup.sh`, `policyvm.setup.sh` and `policyvm.bls12381.setup.sh` make a one-person setup for tests. They refuse to run unless `PCA_DEV_SETUP=1`, print a banner, and write `circuits/build/CEREMONY.json` with `{"ceremony":"single-party","dev_only":true}`. Never ship keys from them.

## Risk-bound circuit and circuit provenance

The risk-bound Policy-VM circuit (`pca-policyvm-v2`, `circuits/policyvm_bound.circom`) is run through this ceremony exactly like the other two (compile `policyvm_bound.circom`, `--circuit pca-policyvm-v2`, power 2^18). Its dev-only counterpart, `policyvm_bound.setup.sh`, writes only under `circuits/build/` and nothing it makes is committed or shipped.

Before `init`, check that the circuit you compile is the pinned one: `node circuits/circuit-version.mjs` must print the `source_sha256` committed in `circuits/circuit-versions.json`, and two compilations must give the same `.r1cs` hash (`node circuits/r1cs-provenance.mjs <id> a.r1cs b.r1cs out.json` checks this and writes `{circuit, sourceSha256, r1csSha256}`; the circuit CI job publishes that record). The transcript's `r1csSha256` must equal the record's, and `circuitProvenance` / `checkCircuitProvenance` tie circuit version, constraint system and verifying-key id together for the verifier.


## A new setup is a new key

A change to a circuit, to the public-signal layout, or a new ceremony yields a new verifying key and so a new `vkId`. Never replace a key in place; publish the new id alongside the circuit version and retire the old one.

## Limits

The tooling does not make the circuit correct: under-constrained signals are found by circuit review and the constraint tests, not by a ceremony. It also cannot prove that a participant destroyed their randomness; it only makes a single honest participant sufficient.

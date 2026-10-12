# 03. Attestation binding: `report_data = H(binding)`, relay resistance, and the hardware assumption list

Code: `packages/pca/src/attestation.ts` (`attestationBinding` 107, `verifyAttestation` 523, `createAttestationVerifier`),
`hardware-sevsnp.ts` (`verifyGenuineSevSnpReport`, report layout, policy gates), `attest-amd-snp.ts`, `attest-intel-dcap.ts`
(`checkAzureRuntimeDataBinding` 81). Tags: **[P]** proved, **[PM]** proved in a model, **[R]** reduced to an assumption, **[O]** open.

This file separates what is *mathematics* (the binding, its injectivity, the relay argument conditional on named assumptions) from what is *physics and vendor trust* (the assumption list in section 3). Nothing in section 3 can be proved here.

---

## 1. The binding

$$
\beta=(h,g,e,n),\qquad
\mathrm{RD}(\beta)=\mathrm{SHA\text{-}512}\big(\texttt{"atlas-pca/attest-bind/v1\textbackslash0"}\ \Vert\ \mathrm{lp}(h)\ \Vert\ \mathrm{lp}(g)\ \Vert\ \mathrm{u64be}(e)\ \Vert\ \mathrm{lp}(n)\big),
$$

with $h$ = the leaf holder's encoded Ed25519 key, $g$ = `grant_ref`, $e$ = attestation epoch (non-negative safe integer), $n$ = the server-issued nonce, and $\mathrm{lp}(x)=\mathrm{u32be}(|\mathrm{utf8}(x)|)\Vert\mathrm{utf8}(x)$
(attestation.ts:107-123). The output is 64 bytes, exactly the SEV-SNP `REPORT_DATA` width.

**Lemma AT-1 (injective framing) [P; machine-checked Lean `Misc.lean` `enc_injective` for the fixed-width length-prefix model].** $\beta\mapsto$ the preimage of $\mathrm{RD}$ is injective: the prefix is a fixed constant, each $\mathrm{lp}$ field is self-delimiting (length first), and the epoch has a fixed width. A parser reading the
preimage recovers $(h,g,e,n)$ uniquely.

**Theorem AT-2 (binding) [R; the ROM collision bound is machine-checked in EasyCrypt `PcaRomCollision.ec` (`rom_collision`, generic in the output probability, `pc = 2^-512` here); the framing injectivity AT-1 is paper].** If $\beta\ne\beta'$ and $\mathrm{RD}(\beta)=\mathrm{RD}(\beta')$ then a SHA-512 collision has been found; $\Pr\le t^2/2^{513}$ for $t$ evaluations (generic birthday on a 512-bit output), which is far below the 256-bit-limited
quantities elsewhere in the system.
*Proof.* Lemma AT-1 gives distinct preimages. $\square$

The hardware verifier compares the report's `REPORT_DATA` to $\mathrm{RD}(\mathrm{expected})$ with a constant-time byte comparison (hardware-sevsnp.ts:544-546), where `expected` is the **server-supplied** tuple. In the Azure confidential-VM mode the report's `REPORT_DATA` is instead
$\mathrm{SHA\text{-}256}(\text{runtime-data JSON})\Vert 0^{32}$, and the JSON's `user-data` field (64 bytes hex) must equal $\mathrm{RD}(\mathrm{expected})$ (`attest-intel-dcap.ts:81-103`, shared with the AMD path).

## 2. Server-side checks that complete the binding (`verifyAttestation`, attestation.ts:523-650)

1. The PCActn's own `grant_ref` and `attestation.epoch` must equal `expected.grantRef`/`expected.epoch`, and `attestation.quote_digest` must equal `expected.nonce` (the PCActn *names the nonce it cites*; it is part of the body the holder signs).
2. The document nonce equals `expected.nonce`.
3. In hardware mode the nonce age is $now-\texttt{nonceIssuedAt}\in[-skew,\min(\texttt{maxNonceAgeMs},5\ \mathrm{min})+skew]$ on the **server clock**; document dates are ignored.
4. `bound: true` must be returned by the hardware verifier (a verifier that does not confirm the `REPORT_DATA` binding fails closed).
5. The measured identity is matched against the grant's `agent_binding` (model, measurement, operator, weights/system-prompt/tool allowlists; `require_hardware`; `require_measured_weights`).

**Theorem AT-3 (freshness) [P].** An accepted hardware attestation was requested for a nonce the server issued at most $5\,\mathrm{min}+skew$ before the verification instant, assuming (H4) below. *Proof:* check 3. Nothing about the document's self-asserted dates is trusted.

## 3. Named assumption list

Each item is an assumption *about the world*. They are listed so that a deployment can decide which it accepts; they are not proved.

| ID | Assumption | Where it enters |
|---|---|---|
| **H1** Quote unforgeability | The vendor signature scheme and certificate chain are unforgeable: AMD ECDSA-P384/SHA-384 report signature under the VCEK, VCEK→ASK→ARK chain (ASK and ARK RSA-4096-PSS), the ARK pinned by SPKI hash (`AMD_ARK_SPKI_SHA384`, attest-amd-snp.ts:38-42); Intel DCAP: PCK chain to the Intel SGX Root CA (pinned SPKI SHA-256) and the quoting enclave; NVIDIA: NRAS/RIM chain. All classical: **not post-quantum** (hardware-sevsnp.ts header "PQ STATUS"). | AT-4 |
| **H2** TEE isolation and measurement integrity | The hardware enforces memory confidentiality and integrity of the guest against the hypervisor and host, and the report's `MEASUREMENT` is the digest of the launched image (SEV-SNP launch digest; TDX MRTD/RTMRs). The chip is not physically compromised (side channels, fault injection and physical attacks are out of scope). | AT-4 |
| **H3** No attestation-oracle in the measured code | Software inside the measured image requests a report with `REPORT_DATA = RD(β)` **only** for a holder key $h$ whose secret key it generated inside the guest and never exports, and does not expose an API that lets an untrusted caller choose arbitrary `REPORT_DATA`. The binding proves what the *guest* asked to be signed; a guest that signs anything the host hands it proves nothing. | AT-4, AT-5 |
| **H4** Server nonce service | Nonces are unpredictable (at least 128 bits of entropy, not enforced by the library), are issued only by the server, are **consumed once** by the caller's `expectedBinding` implementation (attestation.ts:73-74 says "consumed once" but the library itself only records `nonceIssuedAt`; consumption is the integrator's job), and the server clock is correct to within the stated skew. | AT-3, AT-5 |
| **H5** Collision resistance of SHA-512 (binding) and SHA-256 (Azure runtime-data hash). | AT-2 |
| **H6** Firmware/TCB policy | The verifier's policy rejects reports from platforms with known-broken firmware or TCB (`SevSnpPolicy`: DEBUG bit rejected by default, `requireVmpl`, `chipIds`, TCB checks, `measurements` non-empty allowlist (accept-all is refused at construction, attest-amd-snp.ts:77-79)); the VCEK's `CHIP_ID` and reported-TCB extensions are bound to the report; the policy values are current. `requireVmpl` is optional: omitted means any VMPL is accepted (hardware-sevsnp.ts:682). | AT-4 |
| **H7** Azure paravisor/vTPM path | On an Azure confidential VM the VMPL0 paravisor faithfully copies the guest-supplied `user-data` into the runtime-data JSON whose SHA-256 is the report's `REPORT_DATA`, and the attested JSON identifies the vTPM attestation key (hardware-sevsnp.ts:28-31). | AT-4 (Azure mode only) |
| **H8** Verifier-side parsing | X.509/DER parsing and ASN.1 handling of the chain are correct (the strict parsers in `x509-strict.ts` are used; the RSA-PSS `trailerField` workaround routes ASK/ARK verification through node's OpenSSL, hardware-sevsnp.ts:10-14). KDS collateral freshness and certificate revocation lists are **not** analysed here. | AT-4 |
| **H9** Weights | SEV-SNP has no weights field. A `weights_digest` is hardware-measured only if the weights are inside the launched image, or the guest binds a digest into `REPORT_DATA`/a vTPM-attested token, or the GPU path (NVIDIA RIM) is used; host-asserted `HOST_DATA` never satisfies `require_measured_weights` (hardware-sevsnp.ts:34-52). | agent_binding |

## 4. Relay resistance

**Game RELAY.** An honest TEE instance $T$ (measurement $M_T$ on the verifier's allowlist, holder key pair $(h,sk_h)$ generated inside) answers $\mathrm{Quote}(\beta)$ for tuples $\beta$ requested through its legitimate protocol (H3). The server issues a fresh nonce
$n^\ast$ at time $\tau^\ast$ and sets $\beta^\ast=(h^\ast,g^\ast,e^\ast,n^\ast)$. The adversary (the host, the network, any other party; it does **not** make $T$ produce $\mathrm{RD}(\beta^\ast)$) outputs an attestation document that
`verifyAttestation` accepts for `expected = β*`.

**Theorem AT-4 (relay resistance) [R, conditional on H1-H9].** Pr[adversary wins] $\le\mathrm{Adv}^{\mathrm{forge}}_{\mathrm{quote}}+\mathrm{Adv}^{\mathrm{cr}}_{\mathrm{SHA\text{-}512}}+\Pr[\text{nonce guessed before issue}]$, where
$\mathrm{Adv}^{\mathrm{forge}}_{\mathrm{quote}}$ is the advantage against H1/H2 (a valid vendor-rooted report with an allowlisted measurement and chosen `REPORT_DATA` that no allowlisted-measurement instance requested), and the nonce term is $\le q_{\mathrm{guess}}/2^{128}$ for 128-bit nonces.

*Proof.* Acceptance implies `bound:true`, i.e. a vendor-rooted, correctly-chained report $R$ with `R.REPORT_DATA = RD(β*)`, `R.MEASUREMENT ∈ allowlist`, and the policy gates passed (H1, H6). By H2 the measurement is that of the code that ran, and by H3 that code only
requests `REPORT_DATA = RD(β)` after being handed the tuple through its legitimate protocol. If the adversary got the report from a genuine allowlisted instance, then by AT-2 that instance requested `RD(β)` for a tuple $\beta$ with $\mathrm{RD}(\beta)=\mathrm{RD}(\beta^\ast)$, hence $\beta=\beta^\ast$ except
with probability $\mathrm{Adv}^{\mathrm{cr}}$. The tuple contains $n^\ast$, which did not exist before $\tau^\ast$ and which a genuine instance learns only through the legitimate protocol. So an instance requested the report **after** $\tau^\ast$ and within 5 minutes (AT-3), for the specific holder $h^\ast$.
The only other way is that the report was produced without a genuine allowlisted instance requesting it, which is a break of H1/H2. $\square$

**What AT-4 does and does not say [P].**

* A quote captured for $(h,g,e,n)$ **cannot be reused** for any other $(h',g',e',n')$: the report data differs (AT-2), so the PCActn's `grant_ref`, `epoch`, `quote_digest`(= nonce) and leaf holder are all pinned by the single digest. Replay of the same quote with the same nonce is prevented only by nonce consumption (H4).
* The quote does **not** bind the *action* (no PCActn digest in $\beta$). The link to the action is: the PCActn is signed by $sk_h$ (C-1), $sk_h$ lives inside the attested guest (H3), and the PCActn's signed body contains `quote_digest = n`. So the action is bound to the attestation through the holder key and the nonce, not through the quote.
* A *relay* in the sense of "an attacker without access to $sk_h$ obtains a quote from some honest instance and attaches it to its own PCActn" fails: the quote names $h^\ast$, and the PCActn's `leaf_signature` must verify under $h^\ast$ (C-1).
* If H3 fails (the guest signs any `REPORT_DATA` it is given, or exports $sk_h$), the quote proves only that *some* allowlisted image is running and nothing about who holds $h^\ast$. This is the weakest and most deployment-specific assumption.

**Software mode** (`doc.mode==='software'`) replaces H1-H3 by trust in an attestor key list: the document is signed by a trusted attestor (Ed25519 or a suite; hybrid requires both and the unpinned-key caveat of `02-threshold-hybrid.md` H-4 applies if the document carries its own `pq_pk`), and `doc.binding` must equal $\mathrm{RD}(\mathrm{expected})$ in b64u. `require_hardware` rejects software documents (attestation.ts:575-579). Security is then exactly the security of the attestor key and of whatever process the attestor trusts: **no** hardware claim.

## 5. Multi-root policy

The N-of-M policy (attestation.ts:691-793, `createMultiRootVerifier`) requires corroboration from $k$ independent roots. If the roots fail independently, the forgery probability is at most the product of the per-root probabilities
$\prod_{i\in S}\mathrm{Adv}^{(i)}_{\mathrm{quote}}$ for the best $k$-subset $S$. Independence of vendors' failure modes (a shared microcode or supply-chain flaw, a shared side channel, a shared nonce service) is an assumption, not a theorem. **[O]** for correlated failures.

## 6. Summary

| ID | Statement | Status | Assumptions |
|---|---|---|---|
| AT-1 | `lp` framing is injective | P | none |
| AT-2 | $\mathrm{RD}$ binds $(h,g,e,n)$ | R | H5 |
| AT-3 | server-clock nonce freshness $\le5$ min | P | H4 |
| AT-4 | relay resistance | R | H1, H2, H3, H4, H5, H6, (H7, H8) |
| 4 | binding to the action is through $sk_h$ and the nonce, not the quote | P | AT-4 |
| 5 | multi-root independence | O | correlated-failure model |

**Gaps (after F-5).** (1) `createAttestationVerifier` now enforces a 128-bit nonce floor and consumes the nonce once when a `nonceStore` is supplied; without one only the age is checked and consumption stays the integrator's job. (2) `requireVmpl` now defaults to 0 (`'any'` opts out). (3) No analysis of certificate revocation or KDS staleness. (4) The whole chain is classical; a CRQC that breaks ECDSA-P384/RSA-4096 forges H1 for every vendor at once, so multi-root buys no PQ security unless a root uses a PQ vendor signature (none does today).

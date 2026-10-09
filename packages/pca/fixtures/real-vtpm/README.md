# Real Azure Confidential-VM vTPM Endorsement Key (hardware evidence)

`azure-cvm-ek.der` is a genuine TPM 2.0 Endorsement Key **public area** (DER), read
via `tpm2_readpublic` from the vTPM of a real Azure AMD SEV-SNP Confidential VM
(`Standard_DC4as_v5`, eastus) on 2026-10-08, SHA-256
`2f808f4e6b973c16add2fd7aaa5a9732109d83a6ddca6c9ec7ff6eade10ac5c6`.

It is evidence that the PUF root's `TpmEkPufProvider` (attest-puf.ts) reads a real,
device-unique, non-exportable EK on genuine confidential hardware. **Public key only
— no private material.** The VM was torn down after capture (credit hygiene), so this
EK is historical evidence, not a live device.

## Intel TDX CVM vTPM EK (2026-10-08)

A **genuine Azure Intel TDX Confidential VM** (`Standard_DC4es_v6`, westus3, kernel
`6.17.0-azure-fde`, confirmed TD) was provisioned after the subscription upgrade
lifted the `DCesv6` gate, and its vTPM EK was read (SHA-256
`7574e951994106792c1ee4c109b47c7888985916fb2fcb638047cc99beb36e57`). The EK `.der`
was root-owned and not exported before teardown, so only this hash is recorded — the
point it proves is that **real Intel TDX hardware is now reachable** on this sub.
NOTE: a raw Intel **DCAP TD quote** (the format our
`attest-intel-tdx` parser (`parseDcapQuote`) consumes) is NOT extractable from this Azure FDE image via
standard `tpm2`/`configfs-tsm` — Azure routes TDX attestation through its
guest-attestation client / HCL report path (an Azure-specific integration, not a PCA
gap). The DCAP verifier therefore remains synthetic-but-real-crypto tested; this EK
is the genuine-silicon evidence. Public key only; VM torn down after capture.

## Intel TDX raw-quote extraction — confirmed blocked on Azure FDE image (3 methods)

Across three genuine Azure Intel TDX CVMs (`DC4es_v6`), a raw Intel **DCAP TD quote**
(the input format of `parseDcapQuote` / `verifyGenuineTdxQuote` in `attest-intel-tdx`) could not be obtained from Azure's
`ubuntu-24_04-lts:cvm` FDE image via any standard guest interface:
 1. `configfs-tsm` (`/sys/kernel/config/tsm/report`) → ENXIO (quote provider unbound)
 2. `tpm2_nvread 0x01400001` (HCL report NV index) → TPM error
 3. `libtdx-attest` `tdx_att_get_report()` → failure (no `/dev/tdx_guest`)
Azure embeds the TD quote in the HCL report and exposes it ONLY through Microsoft's
guest-attestation client (Azure/confidential-computing-cvm-guest-attestation) + MAA.
Extracting + reformatting that into our DCAP verifier's input is a bounded Azure
integration (follow-up), NOT a PCA code gap. The Intel verifier is validated against a genuine DCAP quote
(see `fixtures/real-tdx/`); genuine Intel TDX hardware reachability is proven
(the sub upgrade lifted the gate; EK read on real TD silicon).

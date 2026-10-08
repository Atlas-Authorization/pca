# Real Azure Confidential-VM vTPM Endorsement Key (hardware evidence)

`azure-cvm-ek.der` is a genuine TPM 2.0 Endorsement Key **public area** (DER), read
via `tpm2_readpublic` from the vTPM of a real Azure AMD SEV-SNP Confidential VM
(`Standard_DC4as_v5`, eastus) on 2026-10-08, SHA-256
`2f808f4e6b973c16add2fd7aaa5a9732109d83a6ddca6c9ec7ff6eade10ac5c6`.

It is evidence that the PUF root's `TpmEkPufProvider` (attest-puf.ts) reads a real,
device-unique, non-exportable EK on genuine confidential hardware. **Public key only
— no private material.** The VM was torn down after capture (credit hygiene), so this
EK is historical evidence, not a live device.

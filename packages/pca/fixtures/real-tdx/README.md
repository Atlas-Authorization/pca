# Genuine Intel TDX hardware evidence (Azure DC4es_v6)

Captured from a real Azure Intel TDX Confidential VM (`Standard_DC4es_v6`, westus3,
kernel `6.17.0-azure-fde`, confirmed TD), 2026-10-08:

- `azure-intel-tdx-hcl.bin` — the full **HCL report** (2600 B) read from the vTPM NV
  index `0x01400001` (owner hierarchy). Magic `HCLA`, version 2, report_size 2466,
  request_type 2.
- `azure-intel-tdx-hwreport.bin` — the embedded **TD report** (2466 B, TEE type
  `0x81` = TDX) extracted from the HCL at offset 0x20: the genuine hardware
  measurements (MRTD / RTMRs) from real Intel TDX silicon.

## Honest scope — DCAP quote vs this TD report
Our `attest-intel-tdx` verification (`verifyGenuineTdxQuote`) consumes an Intel **DCAP ECDSA quote** (PCK→Intel SGX
Root chain). What Azure's FDE image exposes to the guest is the **TD report** (above),
not the DCAP-signed quote: Azure produces the signed quote **server-side via its QGS /
Microsoft Azure Attestation (MAA)** and returns an **MAA JWT**, and it does not expose
`/dev/tdx_guest` (confirmed: `CONFIG_TDX_GUEST_DRIVER=y` but no device node; configfs-tsm
provider unbound; libtdx-attest `get_report` fails). So to validate the DCAP verifier
against Azure specifically, one of: (a) a **non-FDE/generic TDX image** that exposes
`/dev/tdx_guest` → guest QGS → raw DCAP quote; or (b) an **Azure-MAA verifier adapter**
(verify the MAA JWT + its signing chain — a different attestation format than Intel
DCAP). The DCAP verification is validated against the genuine quote below;
this directory is the genuine-silicon TDX evidence (hardware reachable + real TD report).

## ✅ Real raw DCAP TDX quote (SOLVED — Azure IMDS /acc/tdquote)

`azure-intel-tdx-dcap-quote.bin` (5006 B) — a GENUINE Intel **DCAP ECDSA TDX quote**
from a real Azure TDX CVM: version 4, att_key_type 2 (ECDSA-P256), tee_type 0x81
(TDX), sig_data 4300 B (ECDSA sig + QE report + real Intel **PCK cert chain**). This
is exactly the format `parseDcapQuote` in `attest-intel-tdx.ts` parses — the "pure Intel on Azure" path.
The raw quote IS obtainable on Azure's FDE image: read the HCL report (vTPM NV
0x01400001, owner hierarchy) → extract TDREPORT[32:1056] → POST to the Azure IMDS
`http://169.254.169.254/acc/tdquote` (QGS runs server-side) → decode `{"quote"}`.
(report_data here is Azure's default = SHA-256(vTPM-AK); a PCA binding is injectable
via the 0x01400002 NV index before the read — follow-up.)

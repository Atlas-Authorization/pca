# Real Intel PCS collateral for the Azure TDX quote (FMSPC 90c06f000000)

Captured with `curl` (public, no API key) on 2026-10-08 (server Date 22:31 GMT). Used by
`src/attest-intel-collateral.test.ts` with a fixed clock (2026-10-20), inside every validity window.

| File | URL |
|---|---|
| `tdx-tcbinfo.json` | https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000 |
| `tdx-tcbinfo-issuer-chain.pem` | response header `TCB-Info-Issuer-Chain` of the above (URL-decoded) |
| `tdx-qeidentity.json` | https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity |
| `tdx-qeidentity-issuer-chain.pem` | response header `SGX-Enclave-Identity-Issuer-Chain` of the above (URL-decoded) |
| `pckcrl-platform.der` | https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der |
| `pckcrl-platform-issuer-chain.pem` | header `SGX-PCK-CRL-Issuer-Chain` of the above (URL-decoded) |
| `pckcrl-processor.der` | https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor&encoding=der |
| `pckcrl-processor-issuer-chain.pem` | header `SGX-PCK-CRL-Issuer-Chain` of the above (URL-decoded) |
| `IntelSGXRootCA.crl.der` | https://certificates.trustedservices.intel.com/IntelSGXRootCA.der (the Root CA CRL) |

Signature convention: `signature` (hex r||s, ECDSA-P256/SHA-256) covers the exact bytes of the
`tcbInfo` / `enclaveIdentity` JSON object; signing cert = Intel SGX TCB Signing -> Intel SGX Root CA.
The quote's platform PCK CA is "Intel SGX PCK Platform CA", so `pckcrl-platform.der` is the matching CRL.

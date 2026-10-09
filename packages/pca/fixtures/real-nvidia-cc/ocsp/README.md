# Real NVIDIA OCSP request/response pairs

Captured 2026-10-08 ~23:07 UTC from NVIDIA's public responder `http://ocsp.ndis.nvidia.com/` for the genuine
H100 device chain (`../h100-device-cert-chain.pem`). Companion test: `src/attest-nvidia-ocsp.test.ts`
(test clock fixed at 2026-10-08T23:08:00Z; responses are valid for 24 h).

Requests were built by `buildNvidiaOcspRequest` (CertID: SHA-384 issuerNameHash/issuerKeyHash + serial, as NVIDIA's
verifier does; the `.nonce.` variants carry the RFC 6960 nonce extension with the 16-byte nonce
`0123456789abcdef0123456789abcdef`). They parse in `openssl ocsp -reqin <f> -text`. Posted with:

    curl -sS -H 'Content-Type: application/ocsp-request' --data-binary @<name>.<variant>.req.der \
         -o <name>.<variant>.resp.der http://ocsp.ndis.nvidia.com/

| Chain cert (index) | AIA OCSP URL | HTTP | Response |
|---|---|---|---|
| 0 `GH100 A01 GSP FMC LF` (per-device leaf) | none | 200 | 5 bytes `30030a0106`: OCSPResponseStatus **unauthorized (6)** |
| 1 `GH100 A01 GSP BROM` (per-device) | none | 200 | successful, status **good**, nonce echoed |
| 2 `NVIDIA GH100 Provisioner ICA 1` | yes | 200 | successful, status **good**, nonce echoed |
| 3 `NVIDIA GH100 Identity` | yes | 200 | successful, status **good**, nonce echoed |
| 4 root | none | not asked | roots are not OCSP-checked (NVIDIA's verifier skips them) |

Without a nonce the responder still answers (smaller response, no nonce extension). Each successful response is
signed (ecdsa-with-SHA384) by a delegated responder certificate embedded in the response (`NVIDIA OCSP Responder
L3 GH100 ICA1 Identity` / `L2 GH100 Identity` / `L1-A 02`; EKU OCSP Signing + OCSP No Check), issued by the
certificate's own issuer (ICA 1, GH100 Identity, Device Identity CA respectively). thisUpdate = producedAt = request
time, nextUpdate = +24 h.

Files: `<name>.{nonce,nononce}.{req,resp}.der` for names `0-leaf-fmc`, `1-brom`, `2-provisioner-ica`, `3-identity`.

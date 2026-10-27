---
title: Mix QRNG entropy into key generation
order: 12
---

# Mix QRNG entropy into key generation

Maturity: **experimental, hardened, awaiting an independent review and a run against a real quantum source** (owner action O-3).

A quantum random number generator (QRNG) can add entropy to key generation. PCA treats it as an **add, never a dependency**: the seed is `HKDF-SHA256(local CSPRNG || quantum bytes)`, so the platform CSPRNG is always part of the key material. A source that is down, slow, malformed or fully hostile can never make a key weaker than the CSPRNG alone. This page does **not** claim post-quantum security. Post-quantum signatures come from the ML-DSA and SLH-DSA suites; QRNG only improves the entropy that feeds key derivation.

Import from `@atlasauth/pca/ext/research`.

## Use it

```ts
import { HttpQrngSource, generateKeyPairWithEntropy } from '@atlasauth/pca/ext/research';

const source = new HttpQrngSource({ url: 'https://qrng.example.com/api', apiKey: process.env.QRNG_KEY });
const { secretKey, publicKey, usedQuantum } = await generateKeyPairWithEntropy({ source });
```

`usedQuantum` tells you which path ran. For a bare seed use `secureSeed({ source, length })`.

## What happens when something is missing

| Situation | Default | With `requireQuantum: true` |
|---|---|---|
| No source configured | CSPRNG-only seed, `usedQuantum: false` | `EntropyError` code `quantum_required` |
| Source times out, errors, or answers non-2xx | CSPRNG-only seed | `EntropyError` `quantum_required` |
| Source returns the wrong number of bytes (short or long) | CSPRNG-only seed | `EntropyError` `quantum_required` |
| Source returns malformed JSON, hex, base64 or an out-of-range byte | CSPRNG-only seed | `EntropyError` `quantum_required` |
| Source returns bytes that fail the health tests (constant, long runs, heavily skewed) | CSPRNG-only seed, `onQrngError` receives `EntropyError` `health_test_failed` | `EntropyError` `quantum_required` |
| Endpoint is plain `http` (not loopback) | the fetch is refused, CSPRNG-only seed | `EntropyError` `quantum_required` |
| Endpoint answers with a redirect | refused, CSPRNG-only seed | `EntropyError` `quantum_required` |
| Local CSPRNG returns too few bytes | error, no seed (the CSPRNG is the trust anchor) | same |

Set `requireQuantum` only when your policy mandates quantum entropy and you would rather fail than generate a key without it.

## Health tests

Every quantum buffer goes through the two continuous tests of NIST SP 800-90B section 4.4: the repetition count test and the adaptive proportion test, both at a false-positive rate of 2^-20. They run on byte samples. The default assumes the source delivers 8 bits of min-entropy per byte. If your vendor's assessment says less, pass `healthTest: { h: <bits per byte> }`; a lower value loosens the cutoffs to match. `healthTest: false` disables them and is meant for tests only. A failing buffer is discarded and reported, never mixed.

## Transport

`HttpQrngSource` requires `https`. Plain `http` is accepted only for a loopback host (`localhost`, `127.0.0.1`, `[::1]`) and only with `allowInsecureLoopback: true`, for a local daemon. Redirects are never followed, the response size is capped, and the API key is sent only as a header and scrubbed from errors.

## Running against a real device (owner action O-3)

Everything above is tested against fakes and fixtures. A real run needs a QRNG endpoint or device and its vendor entropy assessment. Run `secureSeed` against it a few thousand times with `requireQuantum: true`, confirm the failure rate of the health tests is near zero, and set `h` to the assessed value.

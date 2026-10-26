# @atlasauth/pca-otel

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

OpenTelemetry instrumentation for Proof-Carrying Authority: wrap a verification guard so each decision emits a span (tier, decision, budget) and metrics, with a no-op fallback when OpenTelemetry is absent.

## Install

```sh
npm i @atlasauth/pca-otel
# peer dependency, install alongside:
npm i @opentelemetry/api
```

`@opentelemetry/api` (^1) is an optional peer dependency.

## Usage

```ts
import { instrumentGuard } from '@atlasauth/pca-otel';
import { trace, metrics } from '@opentelemetry/api';

// Wrap any verification guard (e.g. requirePCA from @atlasauth/pca).
const instrumented = instrumentGuard(guard, {
  tracer: trace.getTracer('pca'),
  meter: metrics.getMeter('pca'),
});

const result = await instrumented(req);   // same signature + result, now traced
```

Each decision emits a `pca.verify` span (decision / tier / risk / verb / resource) plus a `pca.verifications` counter and a `pca.verify.risk` histogram. With no tracer and no meter the wrapper is a transparent pass-through. It observes — it never decides; the resource server's verifier is the authority.

## What leaves your process

Every string that goes into a span attribute, a status message or a recorded exception passes through `redactSecrets` (override with the `redact` option): JWTs, `Bearer` / `Basic` credentials, URL userinfo, `token=` / `password=` style pairs and long unbroken token or digest runs are replaced with `[redacted]`, and text is cut to 256 characters. A guard that throws is recorded as a fresh error carrying only the redacted message; the original error (with its stack and `cause`) is rethrown to your caller untouched. The pattern list is a net, not a proof: keep secrets out of resources and deny reasons.

## Failure modes

| Situation | Result |
|---|---|
| The tracer, a span method, the meter or the redactor throws | ignored; the guard's result (or its exception) is returned unchanged |
| The guard returns something that is not an explicit `ok: true` | reported as `pca.decision = deny`; the value itself is returned unchanged |
| `status`, `r` or tier is not a finite number | not exported |
| `verb`, `resource` or reason is not a string | not exported |
| No tracer and no meter | transparent pass-through |

Telemetry never turns a deny into an allow or an allow into an error.

## Status

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca); see `@atlasauth/pca`.

## License

MIT - see LICENSE

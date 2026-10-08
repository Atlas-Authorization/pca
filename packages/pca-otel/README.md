# @atlasauth/pca-otel

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

// Wrap any verification guard (e.g. requirePCA from @atlasauth/backend).
const instrumented = instrumentGuard(guard, {
  tracer: trace.getTracer('pca'),
  meter: metrics.getMeter('pca'),
});

const result = await instrumented(req);   // same signature + result, now traced
```

Each decision emits a `pca.verify` span (decision / tier / risk / verb / resource) plus a `pca.verifications` counter and a `pca.verify.risk` histogram. With no tracer and no meter the wrapper is a transparent pass-through. It observes — it never decides; the resource server's verifier is the authority.

Part of Proof-Carrying Authority — see `@atlasauth/pca`.

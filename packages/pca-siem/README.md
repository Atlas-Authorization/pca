# @atlasauth/pca-siem

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

SIEM export for Proof-Carrying Authority decisions. Each verified, denied or stepped-up action becomes a security event in a schema SIEMs already ingest: OCSF (Splunk, Amazon Security Lake, Sentinel), ArcSight CEF, or Elastic Common Schema (ECS). Every event cites the cryptographic proof (the PCActn digest and the signature that verified) and carries the full delegation chain, hop by hop. It complements OpenTelemetry traces: traces are for latency and debugging, this is the security-event feed.

Export is fail-safe: a sink error is caught, reported through an optional `onError`, dropped and returned as a result value. It never throws into your authorization path.

## Install

```sh
npm i @atlasauth/pca-siem @atlasauth/pca
```

## Usage

The exported record carries the structural core verdict as evidence (and the policy decision when you have it). It
records; it does not authorize: the allow / deny decision belongs to the full server verifier (`verifyPCActn` /
`requirePCA`, with the grant from your own store).

<!-- pca-core-verify: allow the structural verdict is exported as evidence; the authorization decision is verifyPCActn / requirePCA -->
```ts
import { verifyPCActnCore } from '@atlasauth/pca';
import { httpSink, consoleSink, exportDecision, exportBatch, formatDecision } from '@atlasauth/pca-siem';

const verify = await verifyPCActnCore(pcactn, { grant, audience: 'rs', nowEpoch: Math.floor(Date.now() / 1000) });
const record = { pcactn, verify /* , decision: policyDecision (optional) */ };

const sink = httpSink('https://splunk.example.com:8088/services/collector/raw', {
  format: 'ocsf',                                   // 'ocsf' | 'cef' | 'ecs'
  headers: { authorization: `Splunk ${process.env.HEC_TOKEN}` },
});

const result = await exportDecision(record, sink, { onError: (err, ctx) => console.warn(ctx.sink, err.message) });
// { ok: true, delivered: 1, format: 'ocsf' }

await exportBatch([record /* , ... */], consoleSink({ format: 'cef' })); // one delivery for many records
formatDecision(record, 'ecs').line;                                      // serialize without sending
```

`httpSink` POSTs NDJSON for OCSF and ECS and raw lines for CEF, and accepts an injectable `fetch`. To target another destination, implement `SiemSink` (`name`, `format`, `deliver(events)`).

## API

- Exporters: `exportDecision`, `exportBatch`, `formatDecision`.
- Serializers: `toOcsfEvent`, `toCef`, `toEcs`.
- Sinks: `httpSink`, `consoleSink`, and the `SiemSink` interface.
- Input type: `PcaDecisionRecord` (`pcactn`, `verify`, optional `decision`, `now`, `session`).

## What is logged, and what is not

- The leaf signature appears as a 16-character prefix (`serialize: { signature: 'full' | 'prefix' | 'omit' }` on `exportDecision`, `exportBatch`, `httpSink` and `formatDecision`). The proof digest identifies the proof exactly; CEF carries the digest only.
- Request headers (your `authorization` or `DD-API-KEY`) never appear in a result or in `onError`. Error text that quotes the URL, a token, a bearer or Splunk credential, or URL userinfo goes through `scrubError` first.
- Values are escaped for their format: CEF header pipes and backslashes, CEF extension `=` and newlines, NDJSON by `JSON.stringify`. A newline or delimiter in a verb or resource cannot start a second record or forge a field.

## Failure modes

| Situation | Result |
|---|---|
| The sink throws, returns `ok: false`, or the HTTP status is not 2xx | `{ ok: false, delivered: 0, error }`, reported to `onError`; never thrown to the caller |
| The collector does not answer within `timeoutMs` (default 10 s) | the request is aborted; `error: 'delivery timed out'` |
| One record in a batch cannot be serialized | the others are delivered; `skipped` counts it and `onError` is told |
| No record in a batch can be serialized | nothing is delivered; `ok: false`, `skipped` set |
| `verify` is missing or not an explicit `allow: true` | the event is a `deny` |
| No `fetch` available | `{ ok: false, error: 'no fetch implementation available (pass options.fetch)' }` |

Delivery is best effort: there is no retry or queue, so a failed delivery is lost unless `onError` stores it.

## Status

Experimental. Field mappings follow OCSF, CEF and ECS conventions but should be validated against your SIEM's ingest pipeline. Delivery is best-effort (no retry or queueing); add your own buffering if you need durability.

## License

MIT - see LICENSE

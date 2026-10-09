# @atlasauth/pca-siem

SIEM export for Proof-Carrying Authority decisions. Each verified, denied or stepped-up action becomes a security event in a schema SIEMs already ingest: OCSF (Splunk, Amazon Security Lake, Sentinel), ArcSight CEF, or Elastic Common Schema (ECS). Every event cites the cryptographic proof (the PCActn digest and the signature that verified) and carries the full delegation chain, hop by hop. It complements OpenTelemetry traces: traces are for latency and debugging, this is the security-event feed.

Export is fail-safe: a sink error is caught, reported through an optional `onError`, dropped and returned as a result value. It never throws into your authorization path.

## Install

```sh
npm i @atlasauth/pca-siem @atlasauth/pca
```

## Usage

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

## Status

Experimental. Field mappings follow OCSF, CEF and ECS conventions but should be validated against your SIEM's ingest pipeline. Delivery is best-effort (no retry or queueing); add your own buffering if you need durability.

## License

MIT - see LICENSE

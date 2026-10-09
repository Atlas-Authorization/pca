# @atlasauth/pca-compliance

Turn Proof-Carrying Authority (PCA) proofs and decision records into auditor-ready compliance evidence, pre-mapped to the control language auditors already use: EU AI Act Art. 12 (record-keeping) and Art. 50 (transparency), ISO/IEC 42001 clauses, and SOC 2 CC6 (logical access).

Everything here is pure and read-only. It consumes the real shapes from `@atlasauth/pca` (a PCActn, the core verifier result, the policy decision, the capability chain, threshold co-signatures) and re-authorizes nothing. What it foregrounds:

- each log entry cites its proof (the PCActn digest and the verifying leaf signature), so the trail is tamper-evident;
- the delegation chain is explicit, hop by hop (issuer to holder, and the scope narrowed);
- human overrides are signed step-up co-signatures that name the approver, not a free-text note.

## Install

```sh
npm i @atlasauth/pca-compliance @atlasauth/pca
```

## Usage

```ts
import { agent, generateKeyPair, verifyPCActnCore } from '@atlasauth/pca';
import { toAuditEvent, toComplianceReport, renderMarkdown } from '@atlasauth/pca-compliance';

const a = agent({
  principal: generateKeyPair(),
  goal: 'reconcile refunds',
  permissions: { stripe: ['refund'] },
  limits: { refund: '$500' },
  aud: 'rs_demo',
});

const { pcactn } = a.act('stripe.refund', 'charge:ch_1', { amount: 42 });
const verify = await verifyPCActnCore(pcactn, { grant: a.grant, audience: 'rs_demo' });

// One normalized audit record per action (pass `decision` too if you have the policy decision).
const event = toAuditEvent({ pcactn, verify });

// A report for a framework: 'eu-ai-act' | 'iso-42001' | 'soc2'.
const report = toComplianceReport([event], { framework: 'eu-ai-act' });
console.log(renderMarkdown(report)); // or renderJson(report)
```

## API

- `toAuditEvent(input)` builds an `AuditEvent` from a PCActn, its verify result and optional policy decision.
- `toComplianceReport(events, { framework })` returns a `ComplianceReport` with one item per control, each `satisfied`, `partial` or `not-evidenced`, plus a coverage summary.
- `renderMarkdown(report)`, `renderJson(report)`
- `controlMappings(framework?)`, `CONTROL_MAPPINGS`, `COMPLIANCE_FRAMEWORKS`

## Status

This is an evidence mapping, not a legal certification. `satisfied` means the cryptographic evidence a control asks for is present in the records you supplied; it is not an auditor's or lawyer's sign-off. Cryptography in PCA is unaudited.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE

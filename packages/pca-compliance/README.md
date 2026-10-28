# @atlasauth/pca-compliance

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Turn Proof-Carrying Authority (PCA) proofs and decision records into auditor-ready compliance evidence, pre-mapped to the control language auditors already use: EU AI Act Art. 12 (record-keeping) and Art. 50 (transparency), ISO/IEC 42001 clauses, and SOC 2 CC6 (logical access).

Everything here is pure and read-only. It consumes the real shapes from `@atlasauth/pca` (a PCActn, the core verifier result, the policy decision, the capability chain, threshold co-signatures) and re-authorizes nothing. What it foregrounds:

- each log entry cites its proof (the PCActn digest and the verifying leaf signature), so the trail is tamper-evident;
- the delegation chain is explicit, hop by hop (issuer to holder, and the scope narrowed);
- human overrides are signed step-up co-signatures that name the approver, not a free-text note. They are reported only when the core verifier ran a threshold hook and `checks.threshold` is `pass`; shares the verifier did not check are recorded as `humanApproved: false` with no approvers (R2-13, breaking: verify with `hooks.threshold` before calling `toAuditEvent`).

## Install

```sh
npm i @atlasauth/pca-compliance @atlasauth/pca
```

## Usage

The audit record takes the structural core verdict as evidence (and the policy decision when you have it). It records;
it does not authorize: the allow / deny decision belongs to the full server verifier (`verifyPCActn` / `requirePCA`, with
the grant from your own store).

<!-- pca-core-verify: allow the structural verdict is audit evidence here; the authorization decision is verifyPCActn / requirePCA -->
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

## Fail-closed behaviour

| Missing or invalid | Result |
|---|---|
| Verifier result missing, or `allow` is not exactly `true` | The audit event is a `deny` with the verifier's reason (or "proof failed verification") |
| Policy decision absent | Outcome follows the verifier alone ("no policy decision supplied") |
| Policy decision neither admits nor releases a co-signature | `deny` (default-deny) |
| Malformed PCActn or other input to `toAuditEvent` | A best-effort record with `(unknown ...)` placeholders; nothing throws |
| Threshold hook not run, or `checks.threshold` not `pass` | `humanApproved: false` with no approvers |
| Proof that cannot be digested | Digest shown as `(undigestible)`; the event is not marked cryptographically verifiable |
| Framework name unknown, or inherited from the prototype | Throws (`controlMappings`, `toComplianceReport`) |
| No events for `toComplianceReport` | Every control is `not-evidenced` |
| No events for `frameworkReport` | Monitoring and minimisation warn |
| Policy with no predicates | Least privilege and change control warn |
| Goal commitment or erasure support not supplied | Transparency, purpose limitation and erasure warn |
| Unknown taint, or an unusable event time | Worst-case taint; the period ignores the bad time |

## Limits

- It maps records you supply onto control language. It does not collect, store or sign records, and it cannot show that the stream is complete.
- `satisfied` and `pass` mean the evidence the control asks for is present in what you passed. They are not a certification, a legal opinion or an auditor's sign-off.
- It re-verifies nothing: the audit event trusts the verifier result you hand it, so build that result from a verifier you control.
- Framework coverage is limited to the controls it lists (EU AI Act Art. 12 and 50, ISO/IEC 42001, SOC 2 CC6, plus the activity-stream report for EU AI Act, SOC 2 and GDPR); other controls and frameworks are out of scope.
-

## Status

This is an evidence mapping, not a legal certification. `satisfied` means the cryptographic evidence a control asks for is present in the records you supplied; it is not an auditor's or lawyer's sign-off.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE

## Control-status report over an activity stream

`frameworkReport(framework, { policy, events, decisions?, hasGoalCommitment?, erasureSupported? })` maps a console activity stream onto EU AI Act, SOC 2 and GDPR control language and returns pass, warn or fail per control (`frameworkReportToMarkdown` renders it). A control passes only when the supplied records evidence it: with no events, monitoring and minimisation warn; a policy with no predicates does not evidence least privilege. It is an evidence mapping, not a certification. This replaces `complianceReport` / `reportToMarkdown` from `@atlasauth/pca`, which were removed in 0.5.


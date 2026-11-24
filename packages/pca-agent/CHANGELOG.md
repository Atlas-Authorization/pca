# @atlasauth/pca-agent changelog

## 0.5.1

First 0.5 release. 0.5.0 was never published; this package is versioned in lockstep with the family and its 0.5.0 changes ship in 0.5.1.

## 0.1.0

First published release.

### Added
- `createAgent()` returns an `AgentClient` for Proof-Carrying Authority that builds the plan commitment, proof-carrying action and threshold share.
- `commitPlan()` commits the agent's plan before acting.
- `act()` returns `allowed`, `denied`, `step_up` or `error` without throwing on deny or step-up.
- `awaitStepUp()` waits for human approval of a step-up request.
- `delegate()` returns a sub-agent client with strictly lesser authority.
- `verifyReceipt()` checks a returned receipt; `PcaAgentError` for client errors; injectable `fetch`.

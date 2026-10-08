# @atlasauth/pca-mpc

PCA evolution B5 reference prototype: a multi-stakeholder Policy VM composed under secure multi-party computation (semi-honest additive secret sharing over a prime field), so user+org+regulator jointly decide allow/threshold without any party revealing its own policy.

## Install

```sh
npm i @atlasauth/pca-mpc
```

Depends on the core `@atlasauth/pca` (installed transitively).

## Usage

```ts
import { evaluateParty, composeSecure } from '@atlasauth/pca-mpc';

// Each stakeholder evaluates its OWN private policy to a tiny decision vector { allow, t, rQuant }.
const user = evaluateParty({ id: 'user', decideInput: userInput });
const org = evaluateParty({ id: 'org', decideInput: orgInput });
const regulator = evaluateParty({ id: 'regulator', decideInput: regulatorInput });

// Compose under MPC: only the joint decision is revealed, no party's own policy or vector.
const result = composeSecure([user, org, regulator]);
result.composed;         // { allow, t, rQuant } — composed allow + MAX threshold + MAX risk
result.opened;           // the Beaver openings (the only online messages)
```

`spdz` / `spdz-runner` provide the malicious-with-abort (dishonest-majority) layer. This computes a joint policy verdict; it does not authorize on its own — the resource server's verifier decides. See `docs/specs/pca-mpc-policy-vm.md` for the security model.

Part of Proof-Carrying Authority — see `@atlasauth/pca`.

# @atlasauth/pca-rotate

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Key rotation and subtree revocation for Proof-Carrying Authority capability chains. When an agent key or a principal (root) key is rotated or compromised, the chain it carried must be re-issued under a fresh key and the old key named in a revocation record. Chains are re-issued with the real `mintRoot` / `delegate` builders from `@atlasauth/pca`, carrying exactly the original caveats, so a re-issue can never widen authority. Every function returns the new chain together with a `RevocationRecord` a revocation registry (for example `@atlasauth/pca-revoke`) can consume.

## Install

```sh
npm i @atlasauth/pca-rotate @atlasauth/pca
```

## Usage

```ts
import { rotateAgentKey, rotatePrincipalKey, revokeAndReissueSubtree, compromisedKeyFlow } from '@atlasauth/pca-rotate';
import { generateKeyPair, verifyChain } from '@atlasauth/pca';

// Rotate the leaf agent's key. The leaf is re-signed by its parent holder (oldHolderSecret).
const { chain, revocation } = rotateAgentKey(oldChain, {
  oldHolderSecret: parentHolderSecret,
  newKeyPair: generateKeyPair(),
  reason: 'scheduled rotation',
});
verifyChain(chain); // { ok: true }
// revocation: { capId, holder, issuer, capIds, reason, revokedAt }

// Re-root under a new principal key (one holder secret per non-root hop).
rotatePrincipalKey({ chain: oldChain, oldPrincipalSecret, newPrincipalKeyPair: generateKeyPair(), holderSecrets });

// A holder in the middle of the chain is compromised: re-issue from its safe ancestor.
const { revocations, reissued } = compromisedKeyFlow(oldChain, compromisedHolderKey, {
  newKeyPair: generateKeyPair(),
  ancestorSecret,
});
```

`revokeAndReissueSubtree(chain, holder, opts)` is the single-record variant of `compromisedKeyFlow`. A compromised root holder cannot be fixed this way; use `rotatePrincipalKey`. Secrets passed in must match the keys in the chain or the call throws.

## Revoke what was replaced, all or nothing

`applyRotation(registry, revocation, reissuedChain?)` revokes every capability id a rotation replaced in a `RevocationRegistry` (from `@atlasauth/pca-revoke`, or anything with `revoke`, `unrevoke` and `lookup`). If one write fails, the ones this call added are removed again and the error is rethrown. It refuses a record that names no capability, and a re-issued chain that shares an id with the revoked set. It revokes capability ids only: after an agent-key rotation the old key still signs the re-issued leaf, so revoking the key itself would deny the new chain.

Rotating onto the key being rotated out, and a non-finite `now`, are refused.

## Fail-closed behaviour

| Missing or invalid | Result |
|---|---|
| An empty or non-array chain | Throws |
| `rotateAgentKey` on a root-only chain | Throws: nothing to re-issue (use `rotatePrincipalKey`) |
| A secret that does not match the key it must sign for (leaf issuer, root issuer, a hop's issuer, safe ancestor) | Throws; the message names public keys only |
| `rotatePrincipalKey` with the wrong number of `holderSecrets`, or a first element that is not a root | Throws |
| The new key pair equals the key being rotated out, or a key held inside the compromised subtree | Throws |
| `revokeAndReissueSubtree` or `compromisedKeyFlow` for a holder not in the chain, or for the root holder | Throws (use `rotatePrincipalKey` for the root) |
| A child that carries fewer caveats than its parent, or caveats that are not arrays | Throws: not an attenuation |
| `now` that is not a finite number | Throws |
| `applyRotation` with a record that names no capability, or an empty or non-string id | Throws before any write |
| `applyRotation` with a re-issued chain that shares an id with the revoked set | Throws before any write |
| A registry write that fails part-way | The ids this call added are removed again; the error is rethrown |

## Limits

- It produces new chains and revocation records. It does not publish them: nothing is revoked until you apply the records to a registry, and the agent holds the old chain until you hand over the new one.
- It needs the signing secrets for the hops it re-issues. A rotation that cannot sign cannot proceed, and it cannot recover a lost key.
- A compromised root holder is not fixed by a subtree re-issue; rotate the principal key instead.
- A subtree re-issue collapses the compromised subtree into one hop carrying the deepest leaf's caveats, so intermediate hops are not re-created.
- Rollback is best effort: if an undo write itself fails, that id stays revoked. Revocation of keys, as opposed to capability ids, is not performed.

## Status

Production. This produces new chains and revocation records only; it does not distribute them. Feed the records to a registry and hand the new chain to the agent yourself.

## License

MIT - see LICENSE

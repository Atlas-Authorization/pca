# @atlasauth/pca-rotate

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

## Status

Experimental. This produces new chains and revocation records only; it does not distribute them. Feed the records to a registry and hand the new chain to the agent yourself.

## License

MIT - see LICENSE

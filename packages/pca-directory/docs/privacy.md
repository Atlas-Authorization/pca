# Privacy: public and hashed entries

A public transparency log forces a choice between being auditable and being discreet. The directory gives each entry the choice.

## What an entry contains

Every leaf holds: the log id, the kind (register, update, revoke), the mode, a subject reference, an issuer reference, the digest of the signed passport, the passport's expiry and the time it was logged. Nothing else is in the tree.

| | `public` | `hashed` |
| --- | --- | --- |
| Subject reference | the agent's key | `SHA-256("atlas-pca/directory-ref/v1\0subject\0" + key)` |
| Issuer reference | the issuer's key | the same construction for the issuer key |
| The log serves | the entry and the signed passport (operator, model, measurements, expiry) | the entry only |
| Anyone can list who an issuer has registered | yes | no (needs the key to compute the reference) |
| A relying party finds an agent by | its key | the hash of its key, which it can compute from the key it sees |

## What hashing does and does not give you

- It removes the operator name, the model, the measurements and the keys from the public log. A reader of the log learns that some agent was listed, when, and for how long.
- It is **not secrecy**. The reference is unsalted so that a relying party can look an agent up from its key. Anyone who already knows an agent's key can confirm that it is listed, when it was registered and whether it was revoked. Anyone who has a list of candidate keys can test them. Treat a hashed entry as unlinkable to the public, not as hidden from someone who already has the key.
- Entry times, the passport's expiry and the pattern of updates remain visible.
- The log operator is not blinded. At submission the log verifies the full passport, so it sees everything the agent sends. If that is a problem, run your own log or pick a log you trust with it. A hashed entry means the log does not publish it, not that it never saw it.
- Revocation of a hashed entry is published as a bare marker (the digest of the revoked passport); the signed statement, which carries the keys, is not served.

## Choosing

- Use `public` for agents that want to be found: a published operator, a marketplace listing, a bot that identifies itself to sites.
- Use `hashed` for agents whose operator should not be read off a public list, such as internal or customer-specific agents that still need to prove to a counterpart that they are listed and current.
- A log can restrict the modes it accepts (`modes`). A relying party can restrict the modes it accepts too (`policy.modes`): requiring `public` means the passport's details were open to scrutiny when it was listed.
- The same agent can be listed in both modes; the two entries are unlinkable by the log's contents alone.

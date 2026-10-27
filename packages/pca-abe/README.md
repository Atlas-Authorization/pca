# @atlasauth/pca-abe

> Maturity: **hardened** (experimental: hardened, awaiting audit). The engineering is done and evidenced by tests, differential checks and a mutation gate; it awaits an independent review of its type-3 adaptation of the BSW07 construction, which has no published proof. It is never production until that review is done, and its API may still change. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Proof-carrying encryption for Proof-Carrying Authority (PCA). Tool payloads or results are sealed under an access policy over capability attributes (`holder:`, `verb:`, `resource:`, `scope:`, and bound `act:` verb-on-resource pairs), so they decrypt only for an agent whose PCA capability satisfies the policy. The construction is FAME ciphertext-policy ABE (Agrawal and Chase, ACM CCS 2017, ePrint 2017/807), which is proven adaptively secure for the asymmetric (type-3) pairing, here on BLS12-381, over a monotone AND/OR/threshold tree turned into a span program by Shamir sharing, with the payload sealed by AES-256-GCM. Keys issued to different holders cannot be pooled to satisfy a policy neither satisfies.

## Install

```sh
npm i @atlasauth/pca-abe
```

Depends on `@atlasauth/pca`, `@noble/curves` and `@noble/hashes` (installed transitively).

## Usage

```ts
import { generateKeyPair, mintGrant, b64u, DEFAULT_RISK_POLICY } from '@atlasauth/pca';
import {
  setup, keygenForCapability, encryptToolPayload, decryptWithCapability, Attr,
} from '@atlasauth/pca-abe';

// A capability bound to an agent, authorising `read` on /tickets/*.
const principal = generateKeyPair();
const agentPub = b64u(generateKeyPair().publicKey);
const { grant } = mintGrant({
  principalSecret: principal.secretKey,
  principalPublic: b64u(principal.publicKey),
  holder: agentPub,
  goal: 'read tickets',
  envelope: {
    predicates: [{ verb: 'read', resource: '/tickets/*' }],
    caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY,
  },
});

// The issuer holds the master key; the encryptor only needs the public half.
const { mpk, msk } = setup();
const policy = { allOf: [{ attr: Attr.holder(agentPub) }, { attr: Attr.verb('read') }] };
const { ciphertext } = encryptToolPayload(mpk, policy, { ticket: 'T-42' });

// The issuer derives a key from the capability and hands it to the agent.
const key = keygenForCapability(msk, grant);
decryptWithCapability(key, ciphertext); // { ok: true, payload: { ticket: 'T-42' } }
```

A key derived from a capability that does not satisfy the policy gets `{ ok: false, reason }`.

## API

- Keys: `setup`, `keygenForAttributes`, `keygenForCapability`.
- Raw bytes/text: `encryptForPolicy`, `decrypt`, `decryptText`, `parseCiphertext`.
- Tool payloads: `encryptToolPayload`, `decryptWithCapability`.
- Policies: `Policy` (`{ attr }`, `{ allOf }`, `{ anyOf }`, `{ threshold, of }`), `normalizePolicy`, `satisfies`, `policyAttributes`.
- Attributes: `Attr`, `capabilityAttributes`. A capability with ONE predicate yields flat `verb:`/`resource:` tokens plus `act:` pair tokens; a capability with TWO OR MORE predicates yields only `act:["verb","resource"]` pairs (plus `holder:`/`scope:`), so `read /public/*` + `write /acct/42` can never open a `read /acct/42` ciphertext (red-team RT-08; breaking: policies over flat tokens for multi-predicate capabilities must move to `Attr.act`). Predicate `where` conditions and other caveats are not encoded in any token. `scope:` tokens come only from the ROOT capability's caveats: a delegated hop's own `scope` caveats are restrictions, not grants (R2-07, breaking). For a delegated capability pass the chain, `capabilityAttributes(cap, { chain, principal })` / `keygenForCapability(msk, cap, [], { chain, principal })`; without a verified chain it gets no `scope:` tokens, and (R3-09, breaking) no `act:`/`verb:`/`resource:` tokens either, because the envelope is also read from the ROOT only (a delegatee-appended `envelope` caveat is a restriction and can no longer self-grant attributes); a chain that fails verification yields no attributes.

## Status

Hardened, awaiting audit; unaudited. The construction is FAME (Agrawal and Chase, ACM CCS 2017), a published ciphertext-policy scheme for type-3 pairings, not a design of this package. Do not make it the only control for high-value data.

What holds, and under what assumptions:

- Security of the scheme: FAME is proven adaptively secure and collusion resistant in the random-oracle model under the SXDH-family assumption the paper states, in the same asymmetric (type-3) setting this package uses. The hash-to-curve oracle is RFC 9380 SSWU on BLS12-381 with a fixed domain-separation tag and an injective input encoding.
- Collusion resistance: every key carries fresh randomisers (r1, r2), so components of different keys do not combine; pooling two holders' keys, whole or component by component, fails (tested).
- Independent check: the master key, a user key and a ciphertext for six policies (single, AND, OR, 2-of-3, 3-of-5, nested) are recomputed with py_ecc and match this implementation byte for byte; the reference also decrypts with its own Gaussian-elimination solver of the span program.

What is not covered by the paper's proof, or not established:

- The translation of the AND / OR / k-of-n tree into a span program (Shamir down the tree), the wire format and the AES-256-GCM layer are this package's own. AES-256-GCM over the whole header makes tampering detectable (integrity); that is not a CCA proof of the ABE layer.
- Attributes are single-use: a policy that names one attribute in two leaves is refused with a typed error (the scheme needs an injective row labelling).
- The policy is public in the ciphertext (no attribute hiding). No key revocation, no key delegation. Whoever holds the master secret can decrypt everything. Policies are monotone (no negation).
- Not a zero-knowledge proof: confidentiality is bound to possession of capability-derived keys. Not post-quantum (pairing based). Not constant-time (JavaScript).
- Keys and ciphertexts grow with the number of attributes (three group elements per attribute or leaf).

Failure behaviour: `decrypt` never throws and returns `null` for any malformed or unauthentic ciphertext or key, an unsatisfied policy, or a key from another master; `encryptForPolicy` and `keygenForAttributes` throw `PcaEncryptionError` on an invalid policy, a repeated attribute, or a malformed public or secret master key.

Breaking change in 0.5: the earlier adaptation of a symmetric-pairing scheme was replaced by FAME; key, public key, master key and ciphertext formats changed (old material is not readable), `rerandomizeKey` and the `KemTree` type were removed, and repeated attributes in one policy are refused.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE

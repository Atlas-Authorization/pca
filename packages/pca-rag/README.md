# @atlasauth/pca-rag

Fine-grained authorization for RAG, built on Proof-Carrying Authority (PCA). At retrieval time it filters candidate documents down to the ones a given principal may see, deciding each one with the PCA policy engine. Every filtering decision is recorded with a content-addressed digest, so you can show the model was handed only authorized data.

- Documents carry ACL metadata: a `{ relation, object }` entry, or `relation:object` tag strings.
- Policy is either raw PCA predicates or an OpenFGA / Zanzibar model plus tuples (compiled through `@atlasauth/pca-policy-bridge`, including relation closures such as "viewer from parent").
- **Fails closed**: a document is admitted only when a permit predicate matches and no deny matches. No ACL, an unresolved relation, a malformed document, or an incomplete policy translation drops the document.

## Install

```sh
npm i @atlasauth/pca-rag
```

Depends on `@atlasauth/pca` and `@atlasauth/pca-policy-bridge`.

## Usage

```ts
import { filterDocuments, withPcaFilter } from '@atlasauth/pca-rag';

const policy = { openfga: { model, tuples } }; // OpenFGA authorization model + relationship tuples

const candidates = [
  { id: 'readme', text: '...', acl: { relation: 'can_view', object: 'document:readme' } },
  { id: 'spec', text: '...', tags: ['can_view:document:spec'] },
];

const { documents, decision } = filterDocuments('user:alice', candidates, policy);
decision.allowedIds; // ids the model may see
decision.droppedIds; // ids dropped, with a reason per document in decision.decisions
decision.digest;     // b64u commitment to the decision set, bindable into a receipt or proof

// Or wrap any retriever so results are filtered before they reach the model:
const safe = withPcaFilter(retriever, 'user:alice', policy); // retriever.retrieve(query, k)
const docs = await safe.retrieve('how do I deploy?');
safe.lastDecision(); // audit trail for the last call
```

Compile once with `compilePolicy(policy)` and reuse the result to avoid recompiling per call. To derive the principal from a verified PCActn, use `principalFromPCActn(pcactn, { id })`.

## API

- `filterDocuments(principal, candidates, policy, opts?)` returns `{ documents, decision }`
- `withPcaFilter(retriever, principal, policy, opts?)` generic retriever wrapper
- `withLangChainPcaFilter(...)`, `withLlamaIndexPcaFilter(...)` structural adapters for LangChain and LlamaIndex retrievers (no dependency on either library)
- `compilePolicy`, `aclsFromMetadata`, `principalFromPCActn`

## Status

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). This filters retrieval results; it does not control what a model does with documents it is allowed to see. PCA's cryptography has not been independently audited.

## License

MIT - see LICENSE

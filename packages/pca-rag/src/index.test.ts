import { describe, expect, it } from 'vitest';
import type { Capability, Predicate } from '@atlasauth/pca';
import {
  aclsFromMetadata,
  compilePolicy,
  filterDocuments,
  principalFromPCActn,
  withLangChainPcaFilter,
  withLlamaIndexPcaFilter,
  withPcaFilter,
  type AclDocument,
  type LangChainDocumentLike,
  type LangChainRetrieverLike,
  type LlamaIndexNodeWithScoreLike,
  type LlamaIndexRetrieverLike,
  type PolicyInput,
  type RagRetriever,
} from './index';

// --- an OpenFGA/Zanzibar ReBAC model: direct `viewer` + a `can_view` that is `viewer` OR
//     "viewer from parent" (a tupleToUserset relation closure through a folder). -----------------
const model = {
  schema_version: '1.1',
  type_definitions: [
    { type: 'user' },
    { type: 'folder', relations: { viewer: { this: {} } } },
    {
      type: 'document',
      relations: {
        viewer: { this: {} },
        parent: { this: {} },
        can_view: {
          union: {
            child: [
              { computedUserset: { relation: 'viewer' } },
              { tupleToUserset: { tupleset: { relation: 'parent' }, computedUserset: { relation: 'viewer' } } },
            ],
          },
        },
      },
    },
  ],
};

const tuples = [
  // alice can view the readme DIRECTLY (direct ACL / computedUserset path)
  { user: 'user:alice', relation: 'viewer', object: 'document:readme' },
  // alice is a viewer of folder:eng, and document:spec's parent is folder:eng → alice can_view spec
  // ONLY through the relation closure (tupleToUserset), not via any direct tuple on the document.
  { user: 'user:alice', relation: 'viewer', object: 'folder:eng' },
  { user: 'folder:eng', relation: 'parent', object: 'document:spec' },
];

const fgaPolicy: PolicyInput = { openfga: { model, tuples } };

interface Doc extends AclDocument {
  text: string;
}
const docs: Doc[] = [
  { id: 'readme', text: 'readme chunk', acl: { relation: 'can_view', object: 'document:readme' } },
  { id: 'spec', text: 'spec chunk', acl: { relation: 'can_view', object: 'document:spec' } },
  { id: 'secret', text: 'secret chunk', acl: { relation: 'can_view', object: 'document:secret' } },
  { id: 'orphan', text: 'no acl chunk' }, // no ACL metadata at all
];

describe('filterDocuments (FGA-for-RAG)', () => {
  it('admits docs authorized directly AND via a relation/member_of closure; drops the rest (fail closed)', () => {
    const { documents, decision } = filterDocuments('user:alice', docs, fgaPolicy);
    const ids = documents.map((d) => d.id);

    // readme: direct viewer; spec: via tupleToUserset closure through folder:eng → BOTH admitted.
    expect(ids).toEqual(['readme', 'spec']);
    // secret: no grant; orphan: no ACL → both dropped (fail closed).
    expect(decision.allowedIds).toEqual(['readme', 'spec']);
    expect(decision.droppedIds).toEqual(['secret', 'orphan']);
  });

  it('the FilterDecision records the reason + matching permit predicate for the proof trace', () => {
    const { decision } = filterDocuments('user:alice', docs, fgaPolicy);
    const byId = new Map(decision.decisions.map((d) => [d.id, d]));

    const spec = byId.get('spec');
    expect(spec?.allowed).toBe(true);
    expect(spec?.via).toEqual({ relation: 'can_view', object: 'document:spec' });
    // the exact grant that authorized it (proof): a permit for can_view on document:spec by alice.
    expect(spec?.matched).toEqual<Predicate>({
      verb: 'can_view',
      resource: 'document:spec',
      where: [{ field: 'subject.id', op: 'eq', value: 'user:alice' }],
    });

    expect(byId.get('secret')?.allowed).toBe(false);
    expect(byId.get('secret')?.reason).toMatch(/no relation grants access|no predicate permits/);
    expect(byId.get('orphan')?.reason).toMatch(/no decidable ACL/);

    // digest is a stable content-address over the decision set (bindable into a receipt/proof).
    expect(typeof decision.digest).toBe('string');
    expect(decision.digest.length).toBeGreaterThan(0);
    expect(filterDocuments('user:alice', docs, fgaPolicy).decision.digest).toBe(decision.digest);
    expect(decision.report?.source).toBe('openfga');
  });

  it('a different principal sees only their own authorized docs (per-principal filtering)', () => {
    const { documents } = filterDocuments('user:bob', docs, fgaPolicy);
    expect(documents).toEqual([]); // bob holds no relation anywhere → nothing
  });

  it('fails closed on an incomplete policy translation (nothing reaches the model)', () => {
    const { documents, decision } = filterDocuments('user:alice', docs, { openfga: { model: 42, tuples } });
    expect(documents).toEqual([]);
    expect(decision.policyIncomplete).toBe(true);
    expect(decision.decisions.every((d) => !d.allowed)).toBe(true);
    expect(decision.decisions[0]?.reason).toMatch(/incomplete/);
  });
});

describe('core evaluator member_of relation closure', () => {
  // A hand-authored PCA predicate policy: can_view requires the subject's group to be a transitive
  // member of group:admins, resolved by the core evaluator's `member_of` op over an adjacency map.
  const memberPolicy: Predicate[] = [
    {
      verb: 'can_view',
      where: [{ field: 'subject.group', op: 'member_of', value: 'group:admins', collection: 'env.groupGraph' }],
    },
  ];
  const gatedDocs: AclDocument[] = [{ id: 'board-deck', acl: { relation: 'can_view', object: 'document:board' } }];

  it('admits when the principal reaches the authorized group through the closure', () => {
    const alice = {
      id: 'user:alice',
      attributes: { group: 'group:eng' },
      env: { groupGraph: { 'group:eng': ['group:staff'], 'group:staff': ['group:admins'] } },
    };
    const { documents } = filterDocuments(alice, gatedDocs, memberPolicy);
    expect(documents.map((d) => d.id)).toEqual(['board-deck']);
  });

  it('drops when the principal cannot reach the authorized group (fail closed)', () => {
    const bob = {
      id: 'user:bob',
      attributes: { group: 'group:contractors' },
      env: { groupGraph: { 'group:contractors': ['group:externals'] } },
    };
    const { documents, decision } = filterDocuments(bob, gatedDocs, memberPolicy);
    expect(documents).toEqual([]);
    expect(decision.droppedIds).toEqual(['board-deck']);
  });
});

describe('deny-overrides-permit + tag-based ACLs', () => {
  it('a deny predicate overrides a permit (reused bridge decide semantics)', () => {
    const policy: PolicyInput = {
      predicates: [{ verb: 'can_view', where: [{ field: 'subject.id', op: 'eq', value: 'user:alice' }] }],
      denies: [{ verb: 'can_view', resource: 'document:classified' }],
    };
    const set: AclDocument[] = [
      { id: 'ok', acl: { relation: 'can_view', object: 'document:ok' } },
      { id: 'classified', acl: { relation: 'can_view', object: 'document:classified' } },
    ];
    const { documents } = filterDocuments('user:alice', set, policy);
    expect(documents.map((d) => d.id)).toEqual(['ok']);
  });

  it('reads ACL entries from `relation:object` tags (object may itself contain ":")', () => {
    expect(aclsFromMetadata(undefined, ['can_view:document:readme'])).toEqual([
      { relation: 'can_view', object: 'document:readme' },
    ]);
    const tagged: AclDocument[] = [{ id: 'r', tags: ['can_view:document:readme'] }];
    const { documents } = filterDocuments('user:alice', tagged, fgaPolicy);
    expect(documents.map((d) => d.id)).toEqual(['r']);
  });
});

describe('retriever wrappers filter results before they reach the model', () => {
  it('generic RagRetriever wrapper', async () => {
    const underlying: RagRetriever<Doc> = {
      retrieve: (_query: string) => docs,
    };
    const guarded = withPcaFilter(underlying, 'user:alice', fgaPolicy);
    const out = await guarded.retrieve('anything');
    expect(out.map((d) => d.id)).toEqual(['readme', 'spec']);
    expect(guarded.lastDecision()?.droppedIds).toEqual(['secret', 'orphan']);
  });

  it('LangChain-shaped retriever (ACL in document metadata)', async () => {
    const lcDocs: LangChainDocumentLike[] = [
      { pageContent: 'readme', metadata: { id: 'readme', acl: { relation: 'can_view', object: 'document:readme' } } },
      { pageContent: 'secret', metadata: { id: 'secret', acl: { relation: 'can_view', object: 'document:secret' } } },
    ];
    const retriever: LangChainRetrieverLike = {
      invoke: async (_q: string) => lcDocs,
    };
    const guarded = withLangChainPcaFilter(retriever, 'user:alice', fgaPolicy);
    const viaInvoke = await guarded.invoke('q');
    expect(viaInvoke.map((d) => d.pageContent)).toEqual(['readme']);
    const viaLegacy = await guarded.getRelevantDocuments('q');
    expect(viaLegacy.map((d) => d.pageContent)).toEqual(['readme']);
    expect(guarded.lastDecision()?.allowedIds).toEqual(['readme']);
  });

  it('LlamaIndex-shaped retriever (ACL in node metadata)', async () => {
    const nodes: LlamaIndexNodeWithScoreLike[] = [
      { node: { id_: 'readme', metadata: { acl: { relation: 'can_view', object: 'document:readme' } } }, score: 0.9 },
      { node: { id_: 'secret', metadata: { acl: { relation: 'can_view', object: 'document:secret' } } }, score: 0.8 },
    ];
    const retriever: LlamaIndexRetrieverLike = {
      retrieve: async (_params) => nodes,
    };
    const guarded = withLlamaIndexPcaFilter(retriever, 'user:alice', fgaPolicy);
    const out = await guarded.retrieve({ query: 'q' });
    expect(out.map((n) => n.node.id_)).toEqual(['readme']);
    expect(guarded.lastDecision()?.droppedIds).toEqual(['secret']);
  });
});

describe('principalFromPCActn', () => {
  const cap: Capability = {
    id: 'cap-id',
    issuer: 'principal-key',
    holder: 'holder:alice-subagent',
    caveats: [],
    body_digest: 'cap-id',
    sig: 'sig',
  };

  it('derives the acting principal from the verified PCActn leaf holder', () => {
    expect(principalFromPCActn({ cap_chain: [cap] })).toEqual({ id: 'holder:alice-subagent' });
  });

  it('maps the holder to a policy user id when provided, and filters with it', () => {
    const principal = principalFromPCActn({ cap_chain: [cap] }, { id: 'user:alice' });
    expect(principal.id).toBe('user:alice');
    const { documents } = filterDocuments(principal, docs, fgaPolicy);
    expect(documents.map((d) => d.id)).toEqual(['readme', 'spec']);
  });

  it('throws on a PCActn with no capability chain (fail closed, not a silent empty principal)', () => {
    expect(() => principalFromPCActn({ cap_chain: [] })).toThrow(/no leaf capability holder/);
  });
});

describe('compilePolicy', () => {
  it('is idempotent (a CompiledPolicy passes straight through)', () => {
    const compiled = compilePolicy(fgaPolicy);
    expect(compilePolicy(compiled)).toBe(compiled);
    expect(compiled.incomplete).toBe(false);
    expect(compiled.predicates.length).toBeGreaterThan(0);
  });
});

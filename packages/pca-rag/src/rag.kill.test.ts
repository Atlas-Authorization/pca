import { describe, expect, it } from 'vitest';
import { hashCanonical, createProvenanceRecorder } from '@atlasauth/pca';
import type { Predicate } from '@atlasauth/pca';
import {
  aclsFromMetadata,
  compilePolicy,
  filterDocuments,
  principalFromPCActn,
  withLangChainPcaFilter,
  withLlamaIndexPcaFilter,
  withPcaFilter,
  type PolicyInput,
} from './index';

const P: Predicate = { verb: 'can_view', where: [{ field: 'subject.id', op: 'eq', value: 'user:alice' }] };
const POLICY: PolicyInput = [P];
const ACL = { relation: 'can_view', object: 'document:a' };
const ids = (r: { documents: Array<{ id?: string }> }) => r.documents.map((d) => d.id);

describe('principal handling', () => {
  it('a function carrying an id is not a principal', () => {
    const fn = Object.assign(() => 1, { id: 'user:alice' });
    const r = filterDocuments(fn as never, [{ id: 'a', acl: ACL }], POLICY);
    expect(r.documents).toEqual([]);
    expect(r.decision.principal).toBe('');
    expect(r.decision.decisions[0]?.reason).toBe('no principal identity (fail closed)');
  });
  it('null and non-string ids are refused with an empty principal name', () => {
    for (const p of [null, undefined, { id: 5 }, { id: '' }]) {
      const r = filterDocuments(p as never, [{ id: 'a', acl: ACL }], POLICY);
      expect(r.documents).toEqual([]);
      expect(r.decision.principal).toBe('');
      expect(r.decision.decisions[0]?.reason).toBe('no principal identity (fail closed)');
    }
  });
  it('the decision names the principal', () => {
    expect(filterDocuments('user:alice', [], POLICY).decision.principal).toBe('user:alice');
  });
});

describe('principalFromPCActn', () => {
  const msg = 'principalFromPCActn: PCActn has no leaf capability holder';
  it('refuses a missing, empty or malformed chain with the documented error', () => {
    expect(() => principalFromPCActn(undefined as never)).toThrow(msg);
    expect(() => principalFromPCActn({} as never)).toThrow(msg);
    expect(() => principalFromPCActn({ cap_chain: [] } as never)).toThrow(msg);
    expect(() => principalFromPCActn({ cap_chain: [{ holder: 5 }] } as never)).toThrow(msg);
    expect(() => principalFromPCActn({ cap_chain: [{ holder: '' }] } as never)).toThrow(msg);
  });
  it('maps the leaf holder, with optional id / attributes / env only when given', () => {
    const chain = { cap_chain: [{ holder: 'root' }, { holder: 'leaf' }] } as never;
    const bare = principalFromPCActn(chain);
    expect(bare).toStrictEqual({ id: 'leaf' });
    expect(Object.keys(bare)).toEqual(['id']);
    const full = principalFromPCActn(chain, { id: 'user:x', attributes: { a: 1 }, env: { e: 2 } });
    expect(full).toStrictEqual({ id: 'user:x', attributes: { a: 1 }, env: { e: 2 } });
  });
});

describe('ACL metadata parsing', () => {
  it('rejects empty or non-string relation / object', () => {
    for (const bad of [{ relation: '', object: 'o' }, { relation: 'r', object: '' }, { relation: ['r'], object: 'o' }, { relation: 'r', object: ['o'] }, { relation: 5, object: 'o' }, { relation: 'r', object: 5 }, null, 'x']) {
      expect(aclsFromMetadata(bad, undefined)).toEqual([]);
    }
    expect(aclsFromMetadata([{ relation: 'r', object: 'o' }, { relation: '', object: 'o' }], undefined)).toEqual([{ relation: 'r', object: 'o' }]);
  });
  it('a document with an array-valued relation has no decidable ACL', () => {
    const r = filterDocuments('user:alice', [{ id: 'a', acl: { relation: ['can_view'], object: 'o' } as never }], POLICY);
    expect(r.decision.decisions[0]?.reason).toBe('no decidable ACL metadata (fail closed)');
    const r2 = filterDocuments('user:alice', [{ id: 'a', acl: { relation: 'can_view', object: '' } }], POLICY);
    expect(r2.decision.decisions[0]?.reason).toBe('no decidable ACL metadata (fail closed)');
    const r3 = filterDocuments('user:alice', [{ id: 'a', acl: { relation: '', object: 'o' } }], POLICY);
    expect(r3.decision.decisions[0]?.reason).toBe('no decidable ACL metadata (fail closed)');
  });
  it('tags split at the first colon and need a non-empty relation and object', () => {
    expect(aclsFromMetadata(undefined, [':x', 'a:', 'nocolon', 'a:b', 'viewer:document:readme', 5, null])).toEqual([
      { relation: 'a', object: 'b' },
      { relation: 'viewer', object: 'document:readme' },
    ]);
    expect(aclsFromMetadata(undefined, 'a:b')).toEqual([]);
  });
});

describe('compilePolicy', () => {
  it('a non-object policy is incomplete', () => {
    for (const p of [null, undefined, 'x', 5]) {
      expect(compilePolicy(p as never)).toStrictEqual({ predicates: [], denies: [], incomplete: true, incompleteReason: 'no usable policy was supplied (fail closed)' });
    }
  });
  it('an object with neither predicates nor openfga is incomplete', () => {
    expect(compilePolicy({} as never)).toStrictEqual({ predicates: [], denies: [], incomplete: true, incompleteReason: 'the policy has no predicates and is not an OpenFGA policy (fail closed)' });
    expect(compilePolicy({ predicates: 'x' } as never)).toStrictEqual({ predicates: [], denies: [], incomplete: true, incompleteReason: 'the policy has no predicates and is not an OpenFGA policy (fail closed)' });
  });
  it('an openfga value that is not an object is incomplete', () => {
    for (const fga of [null, 'x', 5]) {
      expect(compilePolicy({ openfga: fga } as never)).toStrictEqual({ predicates: [], denies: [], incomplete: true, incompleteReason: 'the OpenFGA policy has no model (fail closed)' });
    }
  });
  it('an array policy is a permit list even if it carries an `incomplete` property', () => {
    const arr = Object.assign([P], { incomplete: true });
    const c = compilePolicy(arr);
    expect(c.incomplete).toBe(false);
    expect(c.predicates).toBe(arr);
    expect(c.denies).toEqual([]);
    const withFalse = compilePolicy(Object.assign([P], { incomplete: false }));
    expect(withFalse.incomplete).toBe(false);
  });
  it('an envelope whose `incomplete` is not a boolean is compiled, not passed through', () => {
    const c = compilePolicy({ incomplete: 'yes', predicates: [P] } as never);
    expect(c).toStrictEqual({ predicates: [P], denies: [], report: undefined, incomplete: false });
  });
  it('a compiled policy is passed through unchanged', () => {
    const compiled = { predicates: [P], denies: [], incomplete: true, incompleteReason: 'custom' };
    expect(compilePolicy(compiled)).toBe(compiled);
    const r = filterDocuments('user:alice', [{ id: 'a', acl: ACL }], compiled);
    expect(r.decision.decisions[0]?.reason).toBe('custom');
    const noReason = filterDocuments('user:alice', [{ id: 'a', acl: ACL }], { predicates: [P], denies: [], incomplete: true });
    expect(noReason.decision.decisions[0]?.reason).toBe('policy translation incomplete (fail closed)');
  });
  it('an envelope keeps its denies and report, and is incomplete only with report errors', () => {
    const deny: Predicate = { verb: 'can_view', resource: 'document:a' };
    const ok = { source: 'x', translated: [], skipped: [], errors: [] } as never;
    const bad = { source: 'x', translated: [], skipped: [], errors: ['boom'] } as never;
    expect(compilePolicy({ predicates: [P], denies: [deny], report: ok })).toStrictEqual({ predicates: [P], denies: [deny], report: ok, incomplete: false });
    expect(compilePolicy({ predicates: [P], report: bad })).toStrictEqual({ predicates: [P], denies: [], report: bad, incomplete: true });
    expect(compilePolicy({ predicates: [P] })).toStrictEqual({ predicates: [P], denies: [], report: undefined, incomplete: false });
  });
});

describe('decision records', () => {
  it('records the grant text, the matched predicate and the via ACL', () => {
    const d = filterDocuments('user:alice', [{ id: 'a', acl: ACL }], POLICY).decision.decisions[0];
    expect(d).toStrictEqual({ id: 'a', allowed: true, via: ACL, reason: 'granted: user:alice has can_view on document:a', matched: P });
  });
  it('a denial from the policy carries the evaluator reason', () => {
    const d = filterDocuments('user:bob', [{ id: 'a', acl: ACL }], POLICY).decision.decisions[0];
    expect(d?.allowed).toBe(false);
    // the evaluator names the unmet limit when one condition is what stands in the way
    expect(d?.reason).toBe('subject.id == "user:alice" not satisfied for can_view on document:a');
  });
  it('the last ACL entry that was evaluated decides the drop reason', () => {
    const d = filterDocuments('user:bob', [{ id: 'a', acl: [ACL, { relation: 'edit', object: 'document:a' }] }], POLICY).decision.decisions[0];
    expect(d?.reason).toBe('no predicate permits edit on document:a');
  });
  it('an evaluator that throws fails closed with its own reason, and the next ACL entry is still tried', () => {
    const broken = { predicates: [P], denies: undefined as never, incomplete: false };
    const r = filterDocuments('user:alice', [{ id: 'a', acl: [ACL, { relation: 'x', object: 'y' }] }], broken);
    expect(r.documents).toEqual([]);
    expect(r.decision.decisions[0]).toStrictEqual({ id: 'a', allowed: false, reason: 'evaluator error (fail closed)' });
  });
  it('an evaluator error on one ACL entry does not stop a later entry from granting', () => {
    let calls = 0;
    const flaky = {
      predicates: [P],
      get denies(): Predicate[] {
        calls++;
        if (calls === 1) throw new Error('first');
        return [];
      },
      incomplete: false,
    };
    const r = filterDocuments('user:alice', [{ id: 'a', acl: [{ relation: 'x', object: 'y' }, ACL] }], flaky as never);
    expect(ids(r)).toEqual(['a']);
    expect(r.decision.decisions[0]?.via).toEqual(ACL);
  });
  it('the decision digest is the content address of principal, counts and id sets', () => {
    const r = filterDocuments('user:alice', [{ id: 'a', acl: ACL }, { id: 'b' }], POLICY);
    const expected = hashCanonical({ v: 1, kind: 'pca-rag/filter', principal: 'user:alice', considered: 2, allowedIds: ['a'], allowedIndexes: [0], droppedIds: ['b'], policyIncomplete: false });
    expect(r.decision.digest).toBe(expected);
    expect('report' in r.decision).toBe(false);
    expect(r.decision.allowedIndexes).toEqual([0]);
  });
  it('a policy report appears on the decision when there is one', () => {
    const report = { source: 'x', translated: [], skipped: [], errors: [] } as never;
    expect(filterDocuments('user:alice', [], { predicates: [P], report }).decision.report).toBe(report);
  });
  it('non-array candidates are an empty set', () => {
    const r = filterDocuments('user:alice', 'nope' as never, POLICY);
    expect(r.decision.considered).toBe(0);
    expect(r.documents).toEqual([]);
  });
});

describe('document ids', () => {
  it('an empty or non-string id falls back to the position, duplicates are told apart', () => {
    const r = filterDocuments('user:alice', [{ id: '', acl: ACL }, { id: 5 as never, acl: ACL }, { id: 'x', acl: ACL }, { id: 'x', acl: ACL }], POLICY);
    expect(r.decision.allowedIds).toEqual(['doc#0', 'doc#1', 'x', 'x#dup3']);
  });
  it('a getter that throws makes that document unreadable, and it is dropped by position', () => {
    const r = filterDocuments('user:alice', [{ id: 'a', acl: ACL }, { id: 'b', acl: ACL }], POLICY, {
      getId: (d, i) => {
        if (i === 1) throw new Error('x');
        return d.id;
      },
    });
    expect(r.decision.droppedIds).toEqual(['doc#1']);
    expect(r.decision.decisions[1]).toStrictEqual({ id: 'doc#1', allowed: false, reason: 'unreadable document metadata (fail closed)' });
    expect(r.decision.allowedIds).toEqual(['a']);
    const r2 = filterDocuments('user:alice', [{ id: 'a', acl: ACL }], POLICY, {
      getAcls: () => {
        throw new Error('x');
      },
    });
    expect(r2.decision.decisions[0]).toStrictEqual({ id: 'doc#0', allowed: false, reason: 'unreadable document metadata (fail closed)' });
  });
});

describe('withPcaFilter', () => {
  it('a retriever that returns a non-array yields nothing', async () => {
    const f = withPcaFilter({ retrieve: () => null as never }, 'user:alice', POLICY);
    expect(await f.retrieve('q')).toEqual([]);
    expect(f.lastDecision()?.considered).toBe(0);
  });
});

describe('LangChain adapter', () => {
  const policy: PolicyInput = [{ verb: 'can_view' }];
  const doc = (metadata: Record<string, unknown> | null | undefined) => ({ pageContent: 'c', ...(metadata === undefined ? {} : { metadata }) }) as never;
  it('derives ids from metadata id, then source, then the position', async () => {
    const f = withLangChainPcaFilter(
      { invoke: () => [doc({ id: 'i1', acl: ACL }), doc({ source: 's1', acl: ACL }), doc({ id: '', source: 's2', acl: ACL }), doc({ id: 5, source: 's3', acl: ACL }), doc({ id: ['x'], source: 's4', acl: ACL }), doc({ acl: ACL })] },
      'user:alice',
      policy,
    );
    expect((await f.invoke('q')).length).toBe(6);
    expect(f.lastDecision()?.allowedIds).toEqual(['i1', 's1', 's2', 's3', 's4', 'doc#5']);
  });
  it('a document with no or null metadata has no ACL (dropped for that reason, not as unreadable)', async () => {
    const f = withLangChainPcaFilter({ invoke: () => [doc(undefined), doc(null)] }, 'user:alice', policy);
    expect(await f.invoke('q')).toEqual([]);
    expect(f.lastDecision()?.decisions).toStrictEqual([
      { id: 'doc#0', allowed: false, reason: 'no decidable ACL metadata (fail closed)' },
      { id: 'doc#1', allowed: false, reason: 'no decidable ACL metadata (fail closed)' },
    ]);
  });
  it('reads tags from metadata', async () => {
    const f = withLangChainPcaFilter({ invoke: () => [doc({ id: 't', tags: ['can_view:document:a'] })] }, 'user:alice', policy);
    expect((await f.invoke('q')).length).toBe(1);
  });
  it('uses invoke when present, else getRelevantDocuments, else refuses', async () => {
    const calls: string[] = [];
    const both = withLangChainPcaFilter({ invoke: () => (calls.push('invoke'), []), getRelevantDocuments: () => (calls.push('grd'), []) }, 'user:alice', policy);
    await both.invoke('q');
    await both.getRelevantDocuments('q');
    expect(calls).toEqual(['invoke', 'invoke']);
    const legacy = withLangChainPcaFilter({ getRelevantDocuments: () => [doc({ id: 'l', acl: ACL })] }, 'user:alice', policy);
    expect((await legacy.invoke('q')).length).toBe(1);
    const neither = withLangChainPcaFilter({} as never, 'user:alice', policy);
    await expect(neither.invoke('q')).rejects.toThrow('withLangChainPcaFilter: retriever has neither invoke nor getRelevantDocuments');
    const strings = withLangChainPcaFilter({ invoke: 'x' as never, getRelevantDocuments: 'y' as never }, 'user:alice', policy);
    await expect(strings.invoke('q')).rejects.toThrow('neither invoke nor getRelevantDocuments');
  });
  it('a non-array result is empty', async () => {
    const f = withLangChainPcaFilter({ invoke: () => 'x' as never }, 'user:alice', policy);
    expect(await f.invoke('q')).toEqual([]);
    expect(f.lastDecision()?.considered).toBe(0);
  });
  it('records admitted documents with their derived source', async () => {
    const rec = createProvenanceRecorder({ mediator: 'm', kid: 'k1' });
    const f = withLangChainPcaFilter({ invoke: () => [doc({ source: 'src', acl: ACL })] }, 'user:alice', policy, { recorder: rec });
    await f.invoke('q');
    expect(rec.receipts().map((r) => `${r.origin}:${r.source}`)).toEqual(['retrieval:src']);
  });
});

describe('LlamaIndex adapter', () => {
  const policy: PolicyInput = [{ verb: 'can_view' }];
  const item = (node: unknown) => ({ node, score: 1 }) as never;
  it('derives ids from node id_, then metadata id, then the position', async () => {
    const f = withLlamaIndexPcaFilter(
      {
        retrieve: () => [
          item({ id_: 'n1', metadata: { acl: ACL } }),
          item({ id_: '', metadata: { id: 'm1', acl: ACL } }),
          item({ id_: 5, metadata: { id: 'm2', acl: ACL } }),
          item({ id_: ['x'], metadata: { id: 'm3', acl: ACL } }),
          item({ metadata: { acl: ACL } }),
        ],
      },
      'user:alice',
      policy,
    );
    expect((await f.retrieve('q')).length).toBe(5);
    expect(f.lastDecision()?.allowedIds).toEqual(['n1', 'm1', 'm2', 'm3', 'node#4']);
  });
  it('an item without a node or metadata has no ACL (dropped for that reason, not as unreadable)', async () => {
    const f = withLlamaIndexPcaFilter({ retrieve: () => [item(undefined), item({}), item({ id_: 'z' })] }, 'user:alice', policy);
    expect(await f.retrieve({ query: 'q' })).toEqual([]);
    expect(f.lastDecision()?.decisions).toStrictEqual([
      { id: 'node#0', allowed: false, reason: 'no decidable ACL metadata (fail closed)' },
      { id: 'node#1', allowed: false, reason: 'no decidable ACL metadata (fail closed)' },
      { id: 'z', allowed: false, reason: 'no decidable ACL metadata (fail closed)' },
    ]);
  });
  it('reads tags from node metadata', async () => {
    const f = withLlamaIndexPcaFilter({ retrieve: () => [item({ id_: 't', metadata: { tags: ['can_view:document:a'] } })] }, 'user:alice', policy);
    expect((await f.retrieve('q')).length).toBe(1);
  });
  it('a non-array result is empty', async () => {
    const f = withLlamaIndexPcaFilter({ retrieve: () => null as never }, 'user:alice', policy);
    expect(await f.retrieve('q')).toEqual([]);
    expect(f.lastDecision()?.considered).toBe(0);
  });
});

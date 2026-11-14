import { describe, expect, it } from 'vitest';
import type { Predicate } from '@atlasauth/pca';
import { compilePolicy, filterDocuments, withLangChainPcaFilter, withLlamaIndexPcaFilter, withPcaFilter, type AclDocument } from './index';

const permit = (user: string, relation = 'viewer', object = 'doc:a'): Predicate => ({ verb: relation, resource: object, where: [{ field: 'subject.id', op: 'eq', value: user }] });
const POLICY: Predicate[] = [permit('u1', 'viewer', 'doc:a'), permit('u1', 'viewer', 'doc:b')];
const doc = (id: string, object: string, relation = 'viewer'): AclDocument => ({ id, acl: { relation, object } });
const ids = (r: { documents: AclDocument[] }) => r.documents.map((d) => d.id);

describe('fail-closed table: a missing or unusable principal', () => {
  it.each([[undefined], [null], [''], [{ id: '' }], [{ id: 5 }], [{}], [5], [true]])('principal %j sees nothing', (p) => {
    const r = filterDocuments(p as never, [doc('1', 'doc:a')], POLICY);
    expect(ids(r)).toEqual([]);
    expect(r.decision.decisions[0]).toEqual({ id: '1', allowed: false, reason: 'no principal identity (fail closed)' });
  });
  it('a real principal still sees its documents', () => {
    expect(ids(filterDocuments('u1', [doc('1', 'doc:a'), doc('2', 'doc:z')], POLICY))).toEqual(['1']);
  });
});

describe('fail-closed table: a missing or unusable policy', () => {
  it.each([[null], [undefined], ['x'], [5], [{}], [{ predicates: 'x' }], [{ openfga: null }]])('policy %j admits nothing', (policy) => {
    const r = filterDocuments('u1', [doc('1', 'doc:a')], policy as never);
    expect(ids(r)).toEqual([]);
    expect(r.decision.policyIncomplete).toBe(true);
    expect(r.decision.decisions[0]?.allowed).toBe(false);
  });
  it('the reason says which', () => {
    expect(filterDocuments('u1', [doc('1', 'doc:a')], null as never).decision.decisions[0]?.reason).toBe('no usable policy was supplied (fail closed)');
    expect(filterDocuments('u1', [doc('1', 'doc:a')], {} as never).decision.decisions[0]?.reason).toBe('the policy has no predicates and is not an OpenFGA policy (fail closed)');
    expect(filterDocuments('u1', [doc('1', 'doc:a')], { openfga: null } as never).decision.decisions[0]?.reason).toBe('the OpenFGA policy has no model (fail closed)');
  });
  it('an empty permit list admits nothing, and a translation with errors admits nothing', () => {
    expect(ids(filterDocuments('u1', [doc('1', 'doc:a')], []))).toEqual([]);
    const broken = { predicates: POLICY, report: { source: 'openfga' as const, translated: [], skipped: [], errors: ['boom'] } };
    expect(ids(filterDocuments('u1', [doc('1', 'doc:a')], broken))).toEqual([]);
  });
  it('compilePolicy is total', () => {
    for (const p of [null, undefined, 3, 'x', {}, { openfga: 1 }]) expect(compilePolicy(p as never).incomplete, JSON.stringify(p)).toBe(true);
    expect(compilePolicy(POLICY)).toEqual({ predicates: POLICY, denies: [], incomplete: false });
  });
});

describe('fail-closed table: a document with missing or malformed metadata', () => {
  it('no ACL, an empty ACL list, entries that are not {relation, object} strings', () => {
    const docs: AclDocument[] = [{ id: 'none' }, { id: 'empty', acl: [] }, { id: 'bad1', acl: { relation: 5, object: 'doc:a' } as never }, { id: 'bad2', acl: [{ relation: 'viewer' }, null, 'x'] as never }, { id: 'tags', tags: ['nocolon', ':x', 'x:', 5 as never] }];
    const r = filterDocuments('u1', docs, POLICY);
    expect(ids(r)).toEqual([]);
    expect(r.decision.decisions.every((d) => d.reason === 'no decidable ACL metadata (fail closed)')).toBe(true);
  });
  it('a custom getAcls that returns garbage or throws is dropped, not trusted', () => {
    const d = doc('1', 'doc:a');
    expect(ids(filterDocuments('u1', [d], POLICY, { getAcls: () => 'viewer:doc:a' as never }))).toEqual([]);
    expect(ids(filterDocuments('u1', [d], POLICY, { getAcls: () => [{ relation: 'viewer', object: 5 }] as never }))).toEqual([]);
    const r = filterDocuments('u1', [d], POLICY, { getAcls: () => { throw new Error('x'); } });
    expect(r.decision.decisions[0]).toEqual({ id: 'doc#0', allowed: false, reason: 'unreadable document metadata (fail closed)' });
  });
  it('a custom getId that throws or returns a non-string falls back to the position', () => {
    const r = filterDocuments('u1', [doc('1', 'doc:a')], POLICY, { getId: () => 5 as never });
    expect(r.decision.allowedIds).toEqual(['doc#0']);
  });
  it('candidates that are not an array are no candidates', () => {
    for (const c of [null, undefined, 'x', {}]) expect(filterDocuments('u1', c as never, POLICY).decision.considered).toBe(0);
  });
  it('a null candidate is dropped', () => {
    const r = filterDocuments('u1', [null as never, doc('1', 'doc:a')], POLICY);
    expect(ids(r)).toEqual(['1']);
    expect(r.decision.droppedIds).toEqual(['doc#0']);
  });
});

describe('deny overrides permit, and an evaluator that throws drops the document', () => {
  it('a matching deny wins', () => {
    const r = filterDocuments('u1', [doc('1', 'doc:a')], { predicates: POLICY, denies: [{ verb: 'viewer', resource: 'doc:a' }] });
    expect(ids(r)).toEqual([]);
    expect(r.decision.decisions[0]?.reason).toBe('forbidden by deny policy');
  });
  it('a poisoned predicate list does not admit', () => {
    const poisoned = { predicates: [{ get verb(): string { throw new Error('x'); } } as never], denies: [] };
    expect(ids(filterDocuments('u1', [doc('1', 'doc:a')], poisoned))).toEqual([]);
  });
  it('one ACL entry that grants is enough, a later one is not needed', () => {
    const d: AclDocument = { id: '1', acl: [{ relation: 'viewer', object: 'doc:zzz' }, { relation: 'viewer', object: 'doc:a' }] };
    expect(filterDocuments('u1', [d], POLICY).decision.decisions[0]?.via).toEqual({ relation: 'viewer', object: 'doc:a' });
  });
});

describe('the decision digest names exactly which candidates passed', () => {
  it('duplicate ids are told apart by position', () => {
    const r = filterDocuments('u1', [doc('x', 'doc:a'), doc('x', 'doc:z')], POLICY);
    expect(r.decision.allowedIds).toEqual(['x']);
    expect(r.decision.droppedIds).toEqual(['x#dup1']);
    expect(r.decision.allowedIndexes).toEqual([0]);
  });
  it('which duplicate was allowed changes the digest', () => {
    const a = filterDocuments('u1', [doc('x', 'doc:a'), doc('x', 'doc:z')], POLICY).decision.digest;
    const b = filterDocuments('u1', [doc('x', 'doc:z'), doc('x', 'doc:a')], POLICY).decision.digest;
    expect(a).not.toBe(b);
  });
  it('the digest is stable for the same input and changes with principal, set or order', () => {
    const docs = [doc('1', 'doc:a'), doc('2', 'doc:b')];
    const d1 = filterDocuments('u1', docs, POLICY).decision.digest;
    expect(filterDocuments('u1', docs, POLICY).decision.digest).toBe(d1);
    expect(filterDocuments('u2', docs, POLICY).decision.digest).not.toBe(d1);
    expect(filterDocuments('u1', [docs[0]!], POLICY).decision.digest).not.toBe(d1);
    expect(filterDocuments('u1', [...docs].reverse(), POLICY).decision.digest).not.toBe(d1);
  });
});

describe('wrappers fail closed', () => {
  it('a retriever that throws returns nothing and keeps the previous decision', async () => {
    let fail = false;
    const f = withPcaFilter({ retrieve: async () => { if (fail) throw new Error('down'); return [doc('1', 'doc:a')]; } }, 'u1', POLICY);
    await f.retrieve('q');
    const before = f.lastDecision();
    fail = true;
    await expect(f.retrieve('q')).rejects.toThrow('down');
    expect(f.lastDecision()).toBe(before);
  });
  it('a retriever that returns a non-array returns no documents', async () => {
    expect(await withPcaFilter({ retrieve: async () => 'oops' as never }, 'u1', POLICY).retrieve('q')).toEqual([]);
  });
  it('wrapping with an unusable policy returns no documents (it does not throw mid-retrieval)', async () => {
    expect(await withPcaFilter({ retrieve: async () => [doc('1', 'doc:a')] }, 'u1', null as never).retrieve('q')).toEqual([]);
  });
  it('the LangChain and LlamaIndex wrappers drop what has no ACL and what is not authorized', async () => {
    const lc = withLangChainPcaFilter({ invoke: async () => [{ pageContent: 'a', metadata: { id: 'a', acl: { relation: 'viewer', object: 'doc:a' } } }, { pageContent: 'b', metadata: { id: 'b' } }, { pageContent: 'c' }] }, 'u1', POLICY);
    expect((await lc.invoke('q')).map((d) => d.pageContent)).toEqual(['a']);
    const li = withLlamaIndexPcaFilter({ retrieve: async () => [{ node: { id_: 'n1', metadata: { acl: { relation: 'viewer', object: 'doc:a' } } } }, { node: { id_: 'n2', metadata: { acl: { relation: 'viewer', object: 'doc:z' } } } }, { node: undefined as never }] }, 'u1', POLICY);
    expect((await li.retrieve('q')).map((i) => i.node.id_)).toEqual(['n1']);
  });
});

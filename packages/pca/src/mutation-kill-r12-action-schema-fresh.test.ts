/**
 * 0.4.2 r12 mutation kills: action-schema.ts builds its exported constants (signing / content-address domains, document
 * kind, well-known path, the sensitivity list) and the `suiteErr` helper at module load. Under Stryker's mutant switching
 * that happens before any mutant is active, so the statically-importing schema tests never saw these mutants. Each test
 * here re-evaluates the module (vi.resetModules + dynamic import) and checks the observable behaviour.
 */
import { describe, expect, it, vi } from 'vitest';

async function fresh() {
  vi.resetModules();
  const s = await import('./action-schema');
  const hash = await import('./hash');
  const pq = await import('./pq');
  const keys = await import('./keys');
  return { s, hash, pq, keys };
}

const unsigned = () => ({
  v: 1 as const, kind: 'pca-action-schema' as const, site: 'https://s.example', aud: 's.example', version: '1',
  verbs: [{ verb: 'a.b', kind: 'write', params: { 'action.params.x': { type: 'integer', semantic: 's', sensitivity: 'free' } } }],
});

describe('published constants (fresh module)', () => {
  it('domains, kind and well-known path are the normative strings', async () => {
    const { s } = await fresh();
    expect(s.ACTION_SCHEMA_DOMAIN).toBe('atlas-pca/action-schema/v1\0');
    expect(s.ACTION_SCHEMA_REF_DOMAIN).toBe('atlas-pca/action-schema-ref/v1');
    expect(s.ACTION_SCHEMA_KIND).toBe('pca-action-schema');
    expect(s.WELL_KNOWN_PCA_ACTIONS_PATH).toBe('/.well-known/pca-actions.json');
    expect(s.SENSITIVITIES).toStrictEqual(['free', 'material', 'critical']);
  });
});

describe('document kind and the free sensitivity (fresh module)', () => {
  it("a 'pca-action-schema' document with a 'free' parameter is well-formed; another kind is refused", async () => {
    const { s } = await fresh();
    expect(s.actionSchemaShapeError(unsigned(), { signed: false })).toBeNull();
    expect(s.actionSchemaShapeError({ ...unsigned(), kind: '' }, { signed: false })).toBe("kind must be 'pca-action-schema'");
  });
  it('the MCP draft carries the normative kind', async () => {
    const { s } = await fresh();
    const d = s.draftSchemaFromMcpTools([{ name: 'list_things', annotations: { readOnlyHint: true } }] as never, { site: 'https://s.example', aud: 's.example', version: '1' });
    expect(d.schema.kind).toBe('pca-action-schema');
  });
});

describe('signing domain and content address (fresh module)', () => {
  it('the signature is over atlas-pca/action-schema/v1\\0 || strictCanonical(body)', async () => {
    const { s, hash, pq, keys } = await fresh();
    const kp = keys.generateKeyPair();
    const doc = unsigned();
    const signed = s.signActionSchema(doc as never, 'k1', kp.secretKey);
    const dom = hash.utf8('atlas-pca/action-schema/v1\0');
    const body = hash.canonicalBytesStrict(doc);
    const msg = new Uint8Array(dom.length + body.length);
    msg.set(dom);
    msg.set(body, dom.length);
    const expected = pq.signSuiteArtifact(undefined, { edSecret: kp.secretKey }, msg).sig;
    expect(signed.sig.value).toBe(expected); // Ed25519 is deterministic
    // A signature made independently over the normative message verifies.
    const key = s.actionSchemaKeyOf('k1', kp.secretKey);
    expect(s.verifyActionSchema({ ...doc, sig: { alg: 'ed25519', kid: 'k1', value: expected } }, [key])).toStrictEqual({ ok: true });
  });
  it('the digest is hashCanonical({d: atlas-pca/action-schema-ref/v1, s: doc})', async () => {
    const { s, hash, keys } = await fresh();
    const signed = s.signActionSchema(unsigned() as never, 'k1', keys.generateKeyPair().secretKey);
    expect(s.actionSchemaDigest(signed)).toBe(hash.hashCanonical({ d: 'atlas-pca/action-schema-ref/v1', s: signed }));
  });
});

describe('suite capability check (fresh module)', () => {
  it('an unknown or non-string sig.alg / key alg is refused with the suite error', async () => {
    const { s, keys } = await fresh();
    const kp = keys.generateKeyPair();
    const signed = s.signActionSchema(unsigned() as never, 'k1', kp.secretKey);
    expect(s.actionSchemaShapeError({ ...signed, sig: { ...signed.sig, alg: 'bogus' } })).toBe("sig.alg: unsupported_suite: 'bogus'");
    expect(s.actionSchemaShapeError({ ...signed, sig: { ...signed.sig, alg: 7 } })).toBe('sig.alg: alg must be a string');
    const key = s.actionSchemaKeyOf('k1', kp.secretKey);
    expect(s.verifyActionSchema(signed, [{ ...key, alg: 'bogus' } as never])).toStrictEqual({ ok: false, reason: "schema key: unsupported_suite: 'bogus'" });
    expect(s.verifyActionSchema(signed, [key])).toStrictEqual({ ok: true });
  });
});

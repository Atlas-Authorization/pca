import { describe, expect, it } from 'vitest';
import { buildDiscoveryDocument, parseDiscoveryDocument } from './discovery';

const base = { audience: 'ins_acme' };
const dir = { id: 'ins_acme', url: 'https://acme.example/v1/pca/directory', log_keys: ['k1'], witnesses: { keys: ['w1', 'w2', 'w3'], threshold: 2 }, modes: ['public', 'hashed'] as ('public' | 'hashed')[], open: false };

describe('discovery: the optional directory block', () => {
  it('absent means exactly the document it was: no `directory` member is ever added or required', () => {
    const doc = buildDiscoveryDocument(base);
    expect('directory' in doc).toBe(false);
    expect(JSON.stringify(doc)).toBe(JSON.stringify(parseDiscoveryDocument(doc)));
    expect('directory' in parseDiscoveryDocument(JSON.parse(JSON.stringify(doc)))).toBe(false);
  });

  it('a document that carries a directory block round-trips unchanged otherwise', () => {
    const plain = buildDiscoveryDocument(base);
    const withDir = buildDiscoveryDocument({ ...base, directory: dir });
    const { directory, ...rest } = withDir;
    expect(JSON.stringify(rest)).toBe(JSON.stringify(plain));
    expect(directory).toEqual(dir);
    expect(parseDiscoveryDocument(JSON.parse(JSON.stringify(withDir))).directory).toEqual(dir);
  });

  it('accepts the minimal block', () => {
    expect(parseDiscoveryDocument({ ...buildDiscoveryDocument(base), directory: { url: 'http://localhost:8080', log_keys: ['k'] } }).directory).toEqual({ url: 'http://localhost:8080', log_keys: ['k'] });
  });

  it('refuses anything malformed (fail closed)', () => {
    const doc = buildDiscoveryDocument(base);
    const bad = (d: unknown) => expect(() => parseDiscoveryDocument({ ...doc, directory: d })).toThrow(/directory/);
    bad(null);
    bad([]);
    bad('x');
    bad({ log_keys: ['k'] });
    bad({ url: 'ftp://x', log_keys: ['k'] });
    bad({ url: 'not a url', log_keys: ['k'] });
    bad({ url: 'https://x.example', log_keys: [] });
    bad({ url: 'https://x.example', log_keys: ['k', 'k'] });
    bad({ url: 'https://x.example', log_keys: [1] });
    bad({ url: 'https://x.example', log_keys: ['k'], extra: 1 });
    bad({ url: 'https://x.example', log_keys: ['k'], id: '' });
    bad({ url: 'https://x.example', log_keys: ['k'], witnesses: { keys: ['w'], threshold: 2 } });
    bad({ url: 'https://x.example', log_keys: ['k'], witnesses: { keys: ['w'], threshold: 0 } });
    bad({ url: 'https://x.example', log_keys: ['k'], witnesses: { keys: ['w'] } });
    bad({ url: 'https://x.example', log_keys: ['k'], modes: ['private'] });
    bad({ url: 'https://x.example', log_keys: ['k'], open: 'yes' });
    expect(() => buildDiscoveryDocument({ ...base, directory: { url: 'nope', log_keys: ['k'] } })).toThrow(/directory/);
  });

  it('every pre-existing member behaves as before alongside it', () => {
    const doc = buildDiscoveryDocument({ ...base, directory: dir, obligationsSupported: ['log'], intent: { versions: [2] } });
    const back = parseDiscoveryDocument(JSON.parse(JSON.stringify(doc)));
    expect(back.obligations_supported).toEqual(['log']);
    expect(back.intent).toEqual({ versions: [2] });
    expect(back.directory).toEqual(dir);
  });
});

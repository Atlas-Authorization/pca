// Duplicate members in the Sigstore entry body and the in-toto statement are refused; non-canonical numbers stay accepted.
// Bundles are minted with throwaway keys (test-support/forge-sigstore), the log/SET/proofs re-made around the edited text.
import { describe, expect, it } from 'vitest';
import { verifySigstoreBundleCore } from './sigstore';
import { defaultStatement, mint, type MintOpts } from './test-support/forge-sigstore';

const why = (o: MintOpts): string => {
  const m = mint(o);
  const r = verifySigstoreBundleCore(m.bundle, { roots: m.roots });
  return r.ok ? 'ok' : `${r.code}: ${r.detail}`;
};
const stmtText = () => JSON.stringify(defaultStatement());

describe('Sigstore duplicate members', () => {
  it('a duplicate member in the entry body is refused with the exact detail (every Rekor kind)', () => {
    for (const rekor of ['dsse', 'intoto'] as const) {
      expect(why({ rekor, rawBody: (j) => j.replace(/^\{/, '{"kind":"x",') })).toBe('tlog_body: fail closed: duplicate key "kind"');
    }
  });
  it('a duplicate member in the statement is refused with the exact detail', () => {
    expect(why({ rawPayload: stmtText().replace(/^\{/, '{"_type":"x",') })).toBe('statement: fail closed: duplicate key "_type"');
  });
  it('non-canonical numbers (8.0, 1e3) are accepted in the entry body and the statement', () => {
    expect(why({ rawBody: (j) => j.replace(/^\{/, '{"n":8.0,"e":1e3,') })).toBe('ok');
    expect(why({ rawPayload: stmtText().replace(/^\{/, '{"n":8.0,"e":1e3,') })).toBe('ok');
  });
});

/**
 * Regressions found by the audit-in-code program (fuzzing / mutation testing). Each test failed before its fix.
 */
import { createRequire } from 'node:module';
import { describe, it, expect } from 'vitest';
import { verifyNvidiaRim } from './attest-nvidia-rim';
import { detectEquivocation, TransparencyLedger, verifyWitnessedHead, type WitnessedHead } from './ledger';
import { createAllowlistAnchorLog, anchorAllowlistHead, evidenceFor, verifyAllowlistAnchored, type AnchorTrust } from './attest-allowlist-anchor';
import { signAllowlistManifest, verifyAllowlistManifest, type AllowlistIssuerKey } from './attest-allowlist';
import { generateKeyPair } from './keys';
import { evaluateCondition, isSafeRegexSource, predicateMatches } from './predicates';
import { b64u } from './hash';

describe('audit regressions', () => {
  it('verifyWitnessedHead / detectEquivocation never throw on a head with an over-nested principal (fuzz crasher)', () => {
    const w = generateKeyPair();
    const l = new TransparencyLedger('p');
    l.append({ x: 1 } as never, { salt: 's' } as never);
    const good = l.witnessHead(w.secretKey);
    let deep: unknown = 'x';
    for (let i = 0; i < 200; i++) deep = { a: deep };
    const bad = { ...good, principal: deep } as unknown as WitnessedHead;
    const pub = b64u(w.publicKey);
    expect(verifyWitnessedHead(bad, pub)).toBe(false);
    expect(detectEquivocation(bad, good, pub)).toBe(false);
    expect(verifyWitnessedHead(good, pub)).toBe(true);
  });

  it('allowlist anchor: an inclusion proof relabelled with a different size than the signed head is refused', () => {
    const keys: Record<string, ReturnType<typeof generateKeyPair>> = { ops: generateKeyPair(), ops2: generateKeyPair() };
    const guardian = generateKeyPair();
    const NOW = Date.parse('2026-10-09T00:00:00Z');
    const issuerKeys: Record<string, AllowlistIssuerKey> = Object.fromEntries(Object.entries(keys).map(([n, k]) => [n, { alg: 'ed25519', keys: { edPub: b64u(k.publicKey) } }]));
    const trust: AnchorTrust = { logKey: b64u(guardian.publicKey), instanceId: 'i', principal: 'allowlist-log' };
    const mk = (issuer: string, version: number) => {
      const m = signAllowlistManifest(
        { version, issuedAt: NOW, notBefore: NOW - 1e6, expiresAt: NOW + 1e9, entries: [{ kind: 'tdx-mrtd', value: 'ab'.repeat(48), label: `${issuer} v${version}` }] },
        { issuer, alg: 'ed25519', secrets: { edSecret: keys[issuer]!.secretKey } },
      );
      const v = verifyAllowlistManifest(m, { issuerKeys, nowMs: NOW });
      if (!v.ok) throw new Error('setup');
      return v;
    };
    const log = createAllowlistAnchorLog({ instanceId: 'i', principal: 'allowlist-log' });
    // 5 entries; leaf 0 has the same path SHAPE under tree size 5 and 6, so only the size binding distinguishes them.
    const first = mk('ops', 1);
    anchorAllowlistHead(log, first, { guardianSecret: guardian.secretKey, nowMs: NOW });
    for (let v = 1; v <= 4; v++) anchorAllowlistHead(log, mk('ops2', v), { guardianSecret: guardian.secretKey, nowMs: NOW });
    const ev = evidenceFor(log, 0);
    expect(verifyAllowlistAnchored(first, ev, { trust, nowMs: NOW }).ok).toBe(true);
    const relabelled = { ...ev, proof: { ...ev.proof, size: ev.proof.size + 1 } };
    expect(verifyAllowlistAnchored(first, relabelled, { trust, nowMs: NOW })).toMatchObject({ ok: false, code: 'bad-proof' });
  });

  describe('ReDoS: sequenced-choice regexes in signed re: patterns (found by the static-analysis pass)', () => {
    // Before the fix each of these was ACCEPTED by isSafeRegexSource and took 2^n steps in V8
    // (n=30: 54 s for `a?{30}a{30}b`; (?:a|aa){28}b: 29 s) from a <= 200-char pattern a delegatee can sign into a caveat.
    const a = (n: number) => 'a'.repeat(n);
    const evil: Array<[string, string]> = [
      ['optional chain', 'a?'.repeat(30) + a(30) + 'b'],
      ['ambiguous alternation chain', '(?:a|aa)'.repeat(24) + 'b'],
      ['capturing alternation chain (shorter, worse)', '(a|aa)'.repeat(33) + 'b'],
      ['bounded-repeat chain', 'a{0,63}'.repeat(5) + 'b'],
      ['optional-alternation mix', '(?:a|a)?'.repeat(12) + 'b'],
    ];
    it.each(evil)('refuses %s', (_n, src) => {
      expect(src.length).toBeLessThanOrEqual(200);
      expect(isSafeRegexSource(src)).toBe(false);
    });
    it.each(evil)('a re: resource pattern with %s denies promptly instead of hanging', (_n, src) => {
      const t = Date.now();
      const ok = predicateMatches({ verb: 'v', resource: 're:' + src } as never, { action: { verb: 'v', resource: a(45) } } as never);
      expect(ok).toBe(false);
      expect(Date.now() - t).toBeLessThan(1000);
    });
    it('R2-05: a long or malformed {n} quantifier is refused, not read as a literal', () => {
      for (const src of ['(a+){99999999999999999999999}b', '(a+){000000000000000000000000000002}b', 'a{', 'a{1', 'a{,5}']) {
        expect(isSafeRegexSource(src), src).toBe(false);
      }
      const t = Date.now();
      expect(predicateMatches({ verb: 'v', resource: 're:(a+){99999999999999999999999}b' } as never, { action: { verb: 'v', resource: 'a'.repeat(30) + 'c' } } as never)).toBe(false);
      expect(Date.now() - t).toBeLessThan(500);
    });
    it('ordinary patterns are unaffected', () => {
      for (const ok of ['/acct/[^/]+/items/\\d+', '(?:GET|POST) /x', 'user-[0-9]{1,8}', '(?:a|b|c)z', 'x?y?z?', '.*\\.pdf', '[a-z]+@[a-z]+\\.com']) {
        expect(isSafeRegexSource(ok), ok).toBe(true);
      }
    });
    it('the worst pattern still ACCEPTED (just under the budget) finishes well under a second', () => {
      const src = 'a?'.repeat(20) + a(20) + 'b';
      expect(isSafeRegexSource(src)).toBe(true);
      const t = Date.now();
      expect(predicateMatches({ verb: 'v', resource: 're:' + src } as never, { action: { verb: 'v', resource: a(30) } } as never)).toBe(false);
      expect(Date.now() - t).toBeLessThan(2000);
    });
  });

  describe('ReDoS: the like glob operator (found by the static-analysis pass)', () => {
    const like = (value: string, subject: string): boolean =>
      evaluateCondition({ field: 'action.resource', op: 'like', value } as never, { action: { verb: 'v', resource: subject } } as never);
    it('a pattern of k stars no longer backtracks n^k: `*a*a*a*b` on 500 a-s (was 45 s) returns immediately', () => {
      for (const k of [3, 5, 12, 60]) {
        const t = Date.now();
        expect(like('*a'.repeat(k) + '*b', 'a'.repeat(500))).toBe(false);
        expect(Date.now() - t).toBeLessThan(250);
      }
      expect(like('*a'.repeat(60) + '*', 'a'.repeat(500))).toBe(true);
    });
    // The pre-fix implementation, kept here as the oracle for small inputs where it cannot blow up.
    const oracle = (glob: string, s: string): boolean | null => {
      let out = '';
      for (let i = 0; i < glob.length; i++) {
        const ch = glob[i]!;
        if (ch === '\\') {
          const n = glob[i + 1];
          if (n === undefined) return null;
          out += /[.*+?^${}()|[\]\\]/.test(n) ? '\\' + n : n;
          i++;
        } else if (ch === '*') out += '[\\s\\S]*';
        else if (ch === '?') out += '[\\s\\S]';
        else out += /[.*+?^${}()|[\]\\]/.test(ch) ? '\\' + ch : ch;
      }
      return new RegExp('^(?:' + out + ')$').test(s);
    };
    it('agrees with the previous regex translation on 20000 random small globs and subjects (incl. escapes, newlines, astral chars)', () => {
      let seed = 12345;
      const rnd = (n: number) => {
        seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
        return (seed >>> 8) % n;
      };
      const atoms = ['a', 'b', 'a', '*', '?', '\\*', '\\?', '\\\\', '.', '\n', '\u{1F600}', '[', '(', '$'];
      const subj = ['a', 'b', 'ab', '*', '?', '\\', '.', '\n', '\u{1F600}', '\ud83d', '['];
      for (let i = 0; i < 20000; i++) {
        let g = '';
        for (let j = rnd(7); j > 0; j--) g += atoms[rnd(atoms.length)];
        let s = '';
        for (let j = rnd(9); j > 0; j--) s += subj[rnd(subj.length)];
        const want = oracle(g, s);
        const got = like(g, s);
        // a malformed glob (dangling backslash) is `unknown` => the leaf is false
        expect(got, JSON.stringify([g, s])).toBe(want === null ? false : want);
      }
    });
  });

  describe('XML parser dependency (found by the amplified fuzzer)', () => {
    const installed = (() => {
      try {
        return (createRequire(__filename)('@xmldom/xmldom/package.json') as { version: string }).version;
      } catch {
        return '0.0.0';
      }
    })();
    const [maj, min, pat] = installed.split('.').map(Number) as [number, number, number];
    const patched = maj > 0 || min > 8 || (min === 8 && pat >= 15);
    // @xmldom/xmldom < 0.8.15 parses a long whitespace run inside a malformed end tag in quadratic time (100k tabs: ~5-11 s)
    // BEFORE the RIM signature is checked. The manifest pins 0.8.15; this test is skipped only on a stale install.
    it.skipIf(!patched)(`verifyNvidiaRim refuses a 120k-tab malformed end tag promptly (installed @xmldom/xmldom ${installed})`, async () => {
      const xml = '<?xml version="1.0"?><SoftwareIdentity><ds:Signature><ds:X509Certificate>AAAA</ds:X' + '\t'.repeat(120_000) + '509Certificate></ds:Signature></SoftwareIdentity>';
      const t = Date.now();
      const r = await verifyNvidiaRim(xml, { rimRootSpkiSha256: ['00'.repeat(32)], nowMs: Date.UTC(2026, 9, 9) });
      expect(r.ok).toBe(false);
      expect(Date.now() - t).toBeLessThan(2000);
    });
  });
});

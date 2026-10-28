/**
 * Cross-check against go-spiffe v2. The accept/reject verdicts come from `crosscheck/go-spiffe` (a Go program that
 * runs go-spiffe on the same IDs, chains and JWT-SVIDs). This file only runs when PCA_GO_SPIFFE_VERDICTS names the file
 * that program wrote, so the default package test run stays offline; the CI job "pca-spiffe go-spiffe cross-check"
 * sets it. Any disagreement fails the run, except the cases in SPEC_ONLY below.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { importJWK, type JWK, type KeyLike } from 'jose';
import { describe, expect, it } from 'vitest';
import { parseSpiffeId, verifyJwtSvid, verifyX509Svid } from './index';

const VERDICTS = process.env.PCA_GO_SPIFFE_VERDICTS ?? '';

/**
 * Inputs where this package follows the SPIFFE specification and go-spiffe is documented or observed to be more
 * lenient. For these the Go verdict is recorded in the output file but not compared; this package must still refuse.
 */
const SPEC_ONLY: ReadonlySet<string> = new Set(['typ is not JWT', 'leaf violation: leaf-root-path', 'leaf violation: leaf-no-digital-signature', 'leaf violation: leaf-no-key-usage']);

interface IdRow {
  id: string;
  go_valid: boolean;
}
interface X509Row {
  name: string;
  leaf: string;
  untrusted: string[];
  roots: string[];
  at: string;
  go_valid: boolean;
  go_error?: string;
}
interface JwtRow {
  name: string;
  token: string;
  audience: string;
  alg: string;
  jwk: JWK;
  go_valid: boolean;
  go_error?: string;
}
interface Verdicts {
  ids: IdRow[];
  x509: X509Row[];
  jwt: JwtRow[];
}

function load(): Verdicts {
  const v: unknown = JSON.parse(readFileSync(VERDICTS, 'utf8'));
  const o = v as Partial<Verdicts>;
  if (!Array.isArray(o.ids) || !Array.isArray(o.x509) || !Array.isArray(o.jwt)) throw new Error('bad verdicts file');
  return o as Verdicts;
}
const gen = (name: string): string => readFileSync(resolve(__dirname, '..', 'fixtures', 'generated', name), 'utf8');

/** The standard's length limits are enforced by this package; go-spiffe is not compared on them. */
function overLimit(s: string): boolean {
  const td = /^spiffe:\/\/([^/]*)/.exec(s)?.[1] ?? '';
  return s.length > 2048 || td.length > 255;
}

describe.skipIf(VERDICTS === '')('go-spiffe v2 cross-check', () => {
  it('has verdicts for every kind of input', () => {
    const v = load();
    expect(v.ids.length).toBeGreaterThan(500);
    expect(v.x509.length).toBeGreaterThanOrEqual(19);
    expect(v.jwt.length).toBe(12);
    expect(v.ids.some((r) => r.go_valid)).toBe(true);
    expect(v.ids.some((r) => !r.go_valid)).toBe(true);
  });

  it('SPIFFE IDs: same accept/reject as go-spiffe', () => {
    const diffs: string[] = [];
    for (const r of load().ids) {
      if (overLimit(r.id)) continue;
      let ours = true;
      try {
        parseSpiffeId(r.id);
      } catch {
        ours = false;
      }
      if (ours !== r.go_valid) diffs.push(`${JSON.stringify(r.id)}: ours ${String(ours)}, go-spiffe ${String(r.go_valid)}`);
    }
    expect(diffs).toEqual([]);
  });

  it('X.509-SVID chains: same accept/reject as go-spiffe', () => {
    const diffs: string[] = [];
    for (const r of load().x509) {
      let ours = true;
      try {
        verifyX509Svid([gen(r.leaf), ...r.untrusted.map(gen)], { trustDomain: 'example.org', roots: r.roots.map(gen), now: new Date(r.at) });
      } catch {
        ours = false;
      }
      if (SPEC_ONLY.has(r.name)) {
        if (ours) diffs.push(`${r.name}: must be refused by this package`);
        continue;
      }
      if (ours !== r.go_valid) diffs.push(`${r.name}: ours ${String(ours)}, go-spiffe ${String(r.go_valid)} (${r.go_error ?? 'accepted'})`);
    }
    expect(diffs).toEqual([]);
  });

  it('JWT-SVIDs: same accept/reject as go-spiffe', async () => {
    const diffs: string[] = [];
    for (const r of load().jwt) {
      const key = (await importJWK(r.jwk, r.alg)) as KeyLike;
      let ours = true;
      try {
        await verifyJwtSvid(r.token, { audience: r.audience, key, trustDomain: 'example.org' });
      } catch {
        ours = false;
      }
      if (SPEC_ONLY.has(r.name)) {
        if (ours) diffs.push(`${r.name}: must be refused by this package`);
        continue;
      }
      if (ours !== r.go_valid) diffs.push(`${r.name}: ours ${String(ours)}, go-spiffe ${String(r.go_valid)} (${r.go_error ?? 'accepted'})`);
    }
    expect(diffs).toEqual([]);
  });
});

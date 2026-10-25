/**
 * Rule 14 (signed action schemas, closed-world conformance) 0.4.2 mutation kills: a table of targeted inputs at the exact
 * boundary of every rule, pinned as the expected output of the reference implementation. The table is the same one the
 * native SDKs replay differentially (testdata/k042-actionschema.json.gz, written by
 * tools/pca-audit/java-mutate/k042-actionschema-oracle.mts): actionSchemaShapeError / verifyActionSchema /
 * paramValueViolation / conformAction / accumulationParams / canonProjection. Every input is RAW JSON TEXT (so -0 and
 * lone-surrogate escapes round-trip); every expectation is compared exactly, reasons included. A change to a rule, a
 * reason text, a bound or an ordering fails this file by name.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { accumulationParams, actionSchemaShapeError, conformAction, paramValueViolation, verifyActionSchema } from './action-schema';
import { canonProjection } from './intent-v2';

interface Cases {
  shape: { name: string; doc: string; expect: string | null }[];
  pvv: { name: string; d: string; x: string; expect: unknown }[];
  conform: { name: string; doc: string; verb: string; params: string; expect: { ok: boolean; code?: string; path?: string | null; reason?: string } }[];
  verify: { name: string; doc: string; keys: string; expect: string | null }[];
  acc: { name: string; v: string; unit: string; expect: string[] }[];
  canon: { name: string; doc: string; verb: string; params: string; expect: { ok: boolean; out?: unknown } }[];
}
const DATA: Cases = JSON.parse(gunzipSync(readFileSync(resolve(__dirname, '..', 'testdata', 'k042-actionschema.json.gz'))).toString('utf8'));

describe('rule 14 action schema: replayed boundary table', () => {
  it('the table is the expected size (no case silently dropped)', () => {
    expect([DATA.shape.length, DATA.pvv.length, DATA.conform.length, DATA.verify.length, DATA.acc.length, DATA.canon.length]).toEqual([390, 258, 29, 40, 6, 5]);
  });
  it('actionSchemaShapeError: every shape rule, exact reason', () => {
    for (const c of DATA.shape) expect(actionSchemaShapeError(JSON.parse(c.doc)), c.name).toBe(c.expect);
  });
  it('paramValueViolation: every value-domain rule, exact code and reason', () => {
    for (const c of DATA.pvv) expect(paramValueViolation(JSON.parse(c.d), JSON.parse(c.x)), c.name).toEqual(c.expect);
  });
  it('conformAction: order of failures, code, path and reason', () => {
    for (const c of DATA.conform) {
      const r: any = conformAction(JSON.parse(c.doc), c.verb, JSON.parse(c.params));
      const got = r.ok ? { ok: true } : { ok: false, code: r.code, path: r.path ?? null, reason: r.reason };
      expect(got, c.name).toEqual(c.expect);
    }
  });
  it('verifyActionSchema: signature, key selection, alg binding (ed25519, ML-DSA-65, hybrid)', () => {
    for (const c of DATA.verify) {
      const r: any = verifyActionSchema(JSON.parse(c.doc), JSON.parse(c.keys));
      expect(r.ok ? null : r.reason, c.name).toBe(c.expect);
    }
  });
  it('accumulationParams: integer-typed params that accumulate into the unit, UTF-8 order', () => {
    for (const c of DATA.acc) expect(accumulationParams(JSON.parse(c.v), c.unit), c.name).toEqual(c.expect);
  });
  it('canonProjection: per-type canonical projection, or a refusal', () => {
    for (const c of DATA.canon) {
      let got: unknown;
      try {
        got = { ok: true, out: canonProjection(JSON.parse(c.doc), c.verb, JSON.parse(c.params)) };
      } catch {
        got = { ok: false };
      }
      expect(got, c.name).toEqual(c.expect);
    }
  });
});

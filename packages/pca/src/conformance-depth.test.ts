import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { decodeB64uStrict, MAX_JSON_DEPTH, strictParse, verifyChain, verifyPCActnCore, type Capability, type CapabilityChain, type PCActn } from './index';
import { verifyThreshold, type Signer, type ThresholdShare } from './threshold';

/**
 * Depth-limit coverage (gen-conformance-depth.mjs): the reference re-checks every primitives.depth case it wrote,
 * applying `expand` exactly as the nine language verifiers must, and asserts a clean verdict (never an exception).
 */
type Expand = { marker: string; levels: number; leaf: unknown };
type DepthCase = { name: string; api: string; depth: number; input: any; valid: boolean; expand?: Expand };
const file = JSON.parse(readFileSync(join(__dirname, '..', 'conformance', 'vectors.json'), 'utf8')) as { primitives: { depth?: DepthCase[] } };
const cases = file.primitives.depth ?? [];

const nest = (levels: number, leaf: unknown): unknown => {
  let v = leaf;
  for (let i = 0; i < levels; i++) v = [v];
  return v;
};
const subst = (v: unknown, marker: string, repl: unknown): unknown => {
  if (v === marker) return repl;
  if (Array.isArray(v)) return v.map((x) => subst(x, marker, repl));
  if (v !== null && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, subst(x, marker, repl)]));
  return v;
};
const expand = (c: DepthCase): any => {
  if (!c.expand) return c.input;
  const { marker, levels, leaf } = c.expand;
  if (c.api === 'pcactn_json' || c.api === 'json_parse') {
    expect(c.input.text.split(marker).length).toBe(2);
    return { ...c.input, text: c.input.text.replace(marker, '['.repeat(levels) + JSON.stringify(leaf) + ']'.repeat(levels)) };
  }
  return subst(c.input, marker, nest(levels, leaf));
};

async function verdict(c: DepthCase): Promise<boolean> {
  const inp = expand(c);
  switch (c.api) {
    case 'chain':
      return verifyChain(inp.chain as CapabilityChain, inp.expected_root_issuer).ok;
    case 'threshold_share': {
      const e = inp as { role: string; t: number; signer_set: Signer[]; threshold_message: string; share: ThresholdShare };
      const msg = decodeB64uStrict(e.threshold_message);
      if (msg === null) return false;
      const v = verifyThreshold({ shares: [e.share] }, msg, e.signer_set, e.t);
      return !!e.share && e.share.role === e.role && v.roles.includes(e.role as never);
    }
    case 'pcactn_json': {
      let tree: unknown;
      try {
        tree = strictParse(inp.text);
      } catch {
        return false;
      }
      return (await verifyPCActnCore(tree as PCActn, { insecureSkipPlanRootCheck: true, grant: inp.grant as Capability, nowEpoch: inp.now, audience: inp.aud })).allow;
    }
    case 'json_parse':
      try {
        strictParse(inp.text);
        return true;
      } catch {
        return false;
      }
  }
  throw new Error('unknown api ' + c.api);
}

describe('primitives.depth: nesting limits on every untrusted entry point', () => {
  it('covers limit-1, limit, limit+1 and a huge depth for every api', () => {
    expect(MAX_JSON_DEPTH).toBe(32);
    for (const api of ['chain', 'threshold_share', 'pcactn_json', 'json_parse']) {
      const ds = new Set(cases.filter((c) => c.api === api).map((c) => c.depth));
      for (const d of [31, 32, 33]) expect(ds.has(d), `${api} depth ${d}`).toBe(true);
      expect(cases.some((c) => c.api === api && c.depth >= 100_000), `${api} huge`).toBe(true);
    }
  });
  it('the reference reproduces every verdict without throwing', async () => {
    for (const c of cases) expect(await verdict(c), c.name).toBe(c.valid);
  });
});

/**
 * 0.5 (B8): the experimental extensions are subpath exports (`@atlasauth/pca/ext/*`). The root entry does not
 * re-export them, and PCA Core loads none of them.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import * as root from './index';
import * as core from './core';
import * as attestation from './ext/attestation';
import * as frost from './ext/frost';
import * as intent from './ext/intent';
import * as ledger from './ext/ledger';
import * as optimistic from './ext/optimistic';
import * as research from './ext/research';
import * as zk from './ext/zk';
import { buildPCActn } from './pcactn';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import { paramsDigest, type PlanNode } from './merkle';
import { DEFAULT_RISK_POLICY } from './risk';

const here = __dirname;
const pkgDir = join(here, '..');
const exts = { attestation, frost, intent, ledger, optimistic, research, zk } as const;
/** one name per extension that used to be on the root entry */
const SAMPLE = { frost: 'frostTrustedDealerKeygen', attestation: 'attestIntelTdx', zk: 'createZkVerifier', optimistic: 'openOptimistic', intent: 'mintSessionGrant', ledger: 'verifyLedgerConsistency', research: 'explainRisk' } as const;

describe('B8: extension subpaths', () => {
  for (const [name, mod] of Object.entries(exts)) {
    it(`@atlasauth/pca/ext/${name} exports its names and the root entry does not`, () => {
      const names = Object.keys(mod);
      expect(names.length).toBeGreaterThan(5);
      const key = SAMPLE[name as keyof typeof SAMPLE];
      expect(names).toContain(key);
      expect(Object.keys(root)).not.toContain(key);
      // nothing an extension exports is also on the root (a name moved, it was not copied)
      expect(names.filter((n) => n in root)).toEqual([]);
    });
  }
  it('the production server path stays on the root entry', () => {
    for (const n of ['verifyPCActn', 'requirePCA', 'authorize', 'createRevocationChecker', 'guardPCActnReplay', 'decide', 'threshold', 'verifyPCActnCore']) {
      expect(n in root || Object.keys(root).some((k) => k.toLowerCase().includes(n.toLowerCase()))).toBe(true);
    }
  });
  it('package.json exports ./ext/*', () => {
    const pkg = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8')) as { exports: Record<string, unknown>; typesVersions: Record<string, Record<string, string[]>> };
    expect(pkg.exports['./ext/*']).toEqual({ types: './dist/ext/*.d.ts', default: './dist/ext/*.js' });
    // consumers on classic ("node") module resolution do not read `exports`; their types come from typesVersions
    expect(pkg.typesVersions['*']!['ext/*']).toEqual(['dist/ext/*.d.ts']);
  });
});

describe('B8: Core loads no experimental module', () => {
  it('maturity.json pins an empty core_experimental_baseline', () => {
    const m = JSON.parse(readFileSync(join(pkgDir, 'maturity.json'), 'utf8')) as { core_experimental_baseline: string[] };
    expect(m.core_experimental_baseline).toEqual([]);
  });
  it("the runtime import closure of src/core.ts reaches no module of an experimental feature", () => {
    const map = JSON.parse(readFileSync(join(pkgDir, 'maturity.json'), 'utf8')) as { features: Record<string, { tier: string; modules: string[] }> };
    const experimental = new Set(Object.values(map.features).filter((f) => f.tier === 'experimental').flatMap((f) => f.modules));
    const seen = new Set<string>(['core']);
    const queue = ['core'];
    while (queue.length) {
      const m = queue.shift()!;
      const file = join(here, `${m}.ts`);
      expect(existsSync(file)).toBe(true);
      const text = readFileSync(file, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
      for (const x of text.matchAll(/(?:^|[\n;])\s*(?:import|export)\s+(?!type\s)([^;]*?)\bfrom\s+['"](\.[^'"]+)['"]/g)) {
        const clause = x[1]!.trim();
        if (/^\{[^}]*\}$/.test(clause) && clause.slice(1, -1).split(',').every((t) => !t.trim() || /^type\s/.test(t.trim()))) continue;
        const target = join(dirname(m), x[2]!.replace(/\.js$/, '')).split('\\').join('/');
        if (!seen.has(target) && existsSync(join(here, `${target}.ts`))) {
          seen.add(target);
          queue.push(target);
        }
      }
    }
    expect([...seen].filter((m) => experimental.has(m)).sort()).toEqual([]);
    expect(seen.size).toBeGreaterThan(10);
    expect(readdirSync(join(here, 'ext')).sort()).toEqual(['attestation.ts', 'frost.ts', 'intent.ts', 'ledger.ts', 'optimistic.ts', 'research.ts', 'zk.ts']);
  });
});

describe('B8: the intent layer is an extension of Core', () => {
  const principal = generateKeyPair();
  const holder = generateKeyPair();
  const pPub = encodeKey(principal.publicKey);
  const hPub = encodeKey(holder.publicKey);
  const { grant } = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: pPub,
    holder: hPub,
    goal: 'x',
    envelope: { predicates: [{ verb: 'v', resource: 'r' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  });
  const NOW = Date.UTC(2026, 9, 25, 12);
  const node: PlanNode = { id: 'n', verb: 'v', resource: 'r', params_digest: paramsDigest({}), reversibility_class: 'reversible' };
  const pcactn = buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n', params: {}, counter: 1, signerSecret: holder.secretKey, aud: 'rs', now: NOW });
  const opts = { grant, audience: 'rs', nowEpoch: NOW };

  it('Core alone is unchanged for a proof that uses no intent layer', async () => {
    const r = await core.verifyPCActnCore(pcactn, opts);
    expect({ allow: r.allow, wire: r.checks.wire }).toEqual({ allow: true, wire: 'pass' });
  });
  it('an intent policy that Core cannot enforce denies (never skipped); the root entry enforces it', async () => {
    const policy = { intent: { min_fidelity_ppm: 1 } };
    const c = await core.verifyPCActnCore(pcactn, { ...opts, ...policy });
    expect({ allow: c.allow, intent: c.checks.intent, reason: c.reason }).toEqual({
      allow: false,
      intent: 'fail',
      reason: 'intent: an intent policy is configured but this verifier does not load the intent layer (fail closed)',
    });
    const r = await root.verifyPCActnCore(pcactn, { ...opts, ...policy });
    expect({ allow: r.allow, reason: r.reason }).toEqual({ allow: false, reason: 'intent: this verifier requires an intent binding but the PCActn carries none' });
    // the extension can be handed to Core explicitly
    const e = await core.verifyPCActnCore(pcactn, { ...opts, ...policy, extensions: intent.INTENT_EXTENSIONS });
    expect(e.reason).toBe(r.reason);
  });
  it('an intent v2 context that Core cannot enforce denies', async () => {
    const c = await core.verifyPCActnCore(pcactn, { ...opts, intentV2: {} });
    expect({ allow: c.allow, check: c.checks.intent_session }).toEqual({ allow: false, check: 'fail' });
  });
  it('a proof carrying an intent slot is refused at the wire check by Core, and validated by the root entry', async () => {
    const withSlot = { ...pcactn, intent_session: { session: 'x' } } as unknown as typeof pcactn;
    const c = await core.verifyPCActnCore(withSlot, opts);
    expect(c.checks).toEqual({ wire: 'fail' });
    expect(c.reason).toMatch(/^wire: 'intent_session' is an Intent Layer extension field/);
    const r = await root.verifyPCActnCore(withSlot, opts);
    expect(r.reason).toBe("wire: missing field 'intent_session.root'");
    expect(root.validateWireV2({ ...pcactn, intent: 1 })).toBe("'intent' must be an object");
    expect(core.verifyPCActnCore).not.toBe(root.verifyPCActnCore);
  });
});

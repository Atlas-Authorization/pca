import * as nodeCrypto from 'node:crypto';
import * as nodeFs from 'node:fs';
import * as nodePath from 'node:path';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DEFAULT_RISK_POLICY, b64u, generateKeyPair, mintGrant, unb64u, verifyChain } from '@atlasauth/pca';
import { matchRoute, observedContentDigest, templateOf } from '@atlasauth/pca-proxy';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { applyPlan } from './apply';
import { runInit } from './cli';
import { makePlan, parseInitConfig } from './plan';
import { FIXTURES, fakeDeps, materialize } from './test-support/fixtures';
import type { InitOptions } from './types';

const dirs: string[] = [];
const mk = (name: string, extra: Record<string, string> = {}): string => {
  const d = materialize({ ...FIXTURES[name]!, ...extra });
  dirs.push(d);
  return d;
};
afterEach(() => {
  vi.useRealTimers();
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const rd = (root: string, rel: string): string => readFileSync(join(root, rel), 'utf8');
const opts = (cwd: string, o: Partial<InitOptions> = {}): InitOptions => ({ cwd, proxy: false, yes: true, dryRun: false, force: false, check: false, noImport: false, ...o });

const guardian = generateKeyPair();
const SIGNER = b64u(guardian.publicKey);
const grantOf = (key = guardian, predicates: object[] = [{ verb: 'fast_js.get' }]) =>
  mintGrant({ principalSecret: key.secretKey, principalPublic: b64u(key.publicKey), holder: b64u(generateKeyPair().publicKey), goal: 'test', envelope: { predicates: predicates as never, caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY } }).grant;
const TOKEN = 'pcs1.0123456789abcdefghijklmnop';

/** Connect a project (the fake control plane returns SIGNER) and return the root. */
async function connected(name = 'fastify-js', extra: Record<string, string> = {}): Promise<{ root: string; deps: ReturnType<typeof fakeDeps> }> {
  const root = mk(name, extra);
  const f = vi.fn(async () => new Response(JSON.stringify({ source: 'run-src-1', ingest_key: 'sk_ingest', instance_id: 'ins_1', kind: 'sdk', signer: SIGNER }), { status: 200 }));
  const deps = fakeDeps({ repo: false }, f as never);
  const r = await runInit(['--yes', '--connect', TOKEN], { cwd: root, deps });
  expect(r.ok).toBe(true);
  return { root, deps };
}

describe('connect keeps what the server returns', () => {
  it('reports under the source the server pinned, and keeps the signer, instance and kind', async () => {
    const { root } = await connected();
    expect(JSON.parse(rd(root, '.pca/connect.json'))).toMatchObject({ source: 'run-src-1', ingestKey: 'sk_ingest', instanceId: 'ins_1', kind: 'sdk', signer: SIGNER });
  });

  it('a lost reply is retried with the same token and the same key, and the fresh ingest key is saved', async () => {
    const root = mk('fastify-js');
    const sent: { token: string; public_key: string }[] = [];
    let n = 0;
    const f = vi.fn(async (_u: string, init: { body: string }) => {
      sent.push(JSON.parse(init.body) as never);
      if (n++ === 0) throw new Error('socket hang up'); // the server consumed the token, the reply was lost
      return new Response(JSON.stringify({ source: 'run-src-1', ingest_key: 'sk_fresh', instance_id: 'ins_1', kind: 'sdk', signer: SIGNER }), { status: 200 });
    });
    const first = await runInit(['--yes', '--connect', TOKEN], { cwd: root, deps: fakeDeps({ repo: false }, f as never) });
    expect(first.ok).toBe(false);
    expect(first.text).toContain('same command again');
    expect(existsSync(join(root, '.pca/connect.json'))).toBe(false);
    const again = await runInit(['--yes', '--connect', TOKEN], { cwd: root, deps: fakeDeps({ repo: false }, f as never) });
    expect(again.ok).toBe(true);
    expect(sent[1]).toEqual(sent[0]);
    expect(sent[0]!.public_key).toBe(rd(root, '.pca/source.key.pub').trim());
    expect(JSON.parse(rd(root, '.pca/connect.json')).ingestKey).toBe('sk_fresh');
  });
});

describe('pca init --enforce --grant', () => {
  it('verifies the grant under the pinned signer, shows a diff first, then switches and installs the grant', async () => {
    const { root, deps } = await connected();
    writeFileSync(join(root, 'issued.json'), JSON.stringify(grantOf()));
    const dry = await runInit(['--enforce', '--grant', 'issued.json'], { cwd: root, deps });
    expect(dry.ok).toBe(true);
    expect(dry.text).toContain('Dry run');
    expect(dry.text).toContain('+++ autopilot.grant.json');
    expect(dry.text).toMatch(/\+ {2}"mode": "enforce"|\+ {3}"mode": "enforce"/);
    expect(existsSync(join(root, 'autopilot.grant.json'))).toBe(false);
    const done = await runInit(['--yes', '--enforce', '--grant', 'issued.json'], { cwd: root, deps });
    expect(done.ok).toBe(true);
    expect(rd(root, 'autopilot.grant.json')).toBe(rd(root, 'issued.json'));
    expect(parseInitConfig(rd(root, 'pca.init.json'))).toMatchObject({ mode: 'enforce', signer: SIGNER, connect: true });
  });

  it('refuses a tampered grant', async () => {
    const { root, deps } = await connected();
    const g = JSON.parse(JSON.stringify(grantOf())) as { holder: string };
    g.holder = b64u(generateKeyPair().publicKey);
    writeFileSync(join(root, 'issued.json'), JSON.stringify(g));
    const r = await runInit(['--yes', '--enforce', '--grant', 'issued.json'], { cwd: root, deps });
    expect(r.ok).toBe(false);
    expect(r.text).toContain('does not verify under the pinned signer');
    expect(existsSync(join(root, 'autopilot.grant.json'))).toBe(false);
    expect(parseInitConfig(rd(root, 'pca.init.json'))).toMatchObject({ mode: 'observe' });
  });

  it('refuses the wrong signer: a grant signed by another key, or another pinned signer', async () => {
    const { root, deps } = await connected();
    writeFileSync(join(root, 'issued.json'), JSON.stringify(grantOf(generateKeyPair())));
    expect((await runInit(['--yes', '--enforce', '--grant', 'issued.json'], { cwd: root, deps })).text).toContain('does not verify under the pinned signer');
    writeFileSync(join(root, 'issued.json'), JSON.stringify(grantOf()));
    const other = b64u(generateKeyPair().publicKey);
    expect((await runInit(['--yes', '--enforce', '--grant', 'issued.json', '--signer', other], { cwd: root, deps })).text).toContain('does not verify under the pinned signer');
    expect(existsSync(join(root, 'autopilot.grant.json'))).toBe(false);
  });

  it('refuses to enforce without a grant, or with a grant and nothing to verify it under', async () => {
    const { root, deps } = await connected();
    expect((await runInit(['--enforce'], { cwd: root, deps })).text).toContain('--enforce needs --grant FILE');
    expect((await runInit(['--yes', '--mode', 'enforce'], { cwd: root, deps })).text).toContain('enforce needs a signed grant');
    const bare = mk('fastify-js');
    writeFileSync(join(bare, 'issued.json'), JSON.stringify(grantOf()));
    const r = await runInit(['--yes', '--enforce', '--grant', 'issued.json'], { cwd: bare, deps: fakeDeps({ repo: false }) });
    expect(r.ok).toBe(false);
    expect(r.text).toContain('needs the pinned signer');
    const given = await runInit(['--yes', '--enforce', '--grant', 'issued.json', '--signer', SIGNER], { cwd: bare, deps: fakeDeps({ repo: false }) });
    expect(given.ok).toBe(true);
  });

  it('switching twice changes nothing the second time', async () => {
    const { root, deps } = await connected();
    writeFileSync(join(root, 'issued.json'), JSON.stringify(grantOf()));
    await runInit(['--yes', '--enforce', '--grant', 'issued.json'], { cwd: root, deps });
    const files = ['pca.init.json', 'autopilot.grant.json', 'pca.setup.js', 'package.json'].map((f) => rd(root, f));
    const plan = await makePlan(opts(root, { mode: 'enforce', grant: join(root, 'issued.json') }), deps);
    expect(plan.changes).toEqual([]);
    const again = await runInit(['--yes', '--enforce', '--grant', 'issued.json'], { cwd: root, deps });
    expect(again.ok).toBe(true);
    expect(['pca.init.json', 'autopilot.grant.json', 'pca.setup.js', 'package.json'].map((f) => rd(root, f))).toEqual(files);
  });

  it('switches back to observe, keeping the grant and the signer for the next switch', async () => {
    const { root, deps } = await connected();
    writeFileSync(join(root, 'issued.json'), JSON.stringify(grantOf()));
    await runInit(['--yes', '--enforce', '--grant', 'issued.json'], { cwd: root, deps });
    const back = await runInit(['--yes', '--observe'], { cwd: root, deps });
    expect(back.ok).toBe(true);
    expect(parseInitConfig(rd(root, 'pca.init.json'))).toMatchObject({ mode: 'observe' });
    expect(existsSync(join(root, 'autopilot.grant.json'))).toBe(true);
    const on = await runInit(['--yes', '--mode', 'enforce'], { cwd: root, deps });
    expect(on.ok).toBe(true);
    expect(parseInitConfig(rd(root, 'pca.init.json'))).toMatchObject({ mode: 'enforce', signer: SIGNER });
  });

  it('a grant replaced by a tampered file after the switch is refused again at the next switch', async () => {
    const { root, deps } = await connected();
    writeFileSync(join(root, 'issued.json'), JSON.stringify(grantOf()));
    await runInit(['--yes', '--enforce', '--grant', 'issued.json'], { cwd: root, deps });
    await runInit(['--yes', '--observe'], { cwd: root, deps });
    const g = JSON.parse(rd(root, 'autopilot.grant.json')) as { holder: string };
    g.holder = 'AAAA';
    writeFileSync(join(root, 'autopilot.grant.json'), JSON.stringify(g));
    const r = await runInit(['--yes', '--mode', 'enforce'], { cwd: root, deps });
    expect(r.ok).toBe(false);
    expect(r.text).toContain('does not verify');
  });

  it('parses the flags', async () => {
    const root = mk('fastify-js');
    const deps = fakeDeps({ repo: false });
    expect((await runInit(['--enforce', '--observe'], { cwd: root, deps })).text).toContain('cannot be combined');
    expect((await runInit(['--grant', 'x.json'], { cwd: root, deps })).text).toContain('--grant goes with --enforce');
    expect((await runInit(['--observe', '--mode', 'enforce'], { cwd: root, deps })).text).toContain('contradicts');
  });
});

describe('the generated wiring', () => {
  const load = (root: string, env: Record<string, string>, g?: typeof fetch) => {
    const hooks: Record<string, ((...a: never[]) => unknown)[]> = {};
    const signed: { claim: { source: string; events: Record<string, unknown>[] } }[] = [];
    const stubs: Record<string, unknown> = {
      'node:fs': nodeFs,
      'node:path': nodePath,
      'node:crypto': nodeCrypto,
      '@atlasauth/pca': { protect: () => ({ options: {} }), verifyChain, unb64u },
      '@atlasauth/pca-fastify': { pcaFastify: () => async () => undefined },
      '@atlasauth/pca-proxy': { matchRoute, templateOf, observedContentDigest },
      '@atlasauth/pca-control-plane': { signIngest: (_s: unknown, claim: never) => (signed.push({ claim }), { sig: 'S' }) },
    };
    const mod = { exports: {} as { registerPca: (a: unknown) => void } };
    new Function('require', 'module', 'process', 'fetch', rd(root, 'pca.setup.js'))((n: string) => stubs[n], mod, { env: { PCA_DIR: root, ...env }, cwd: () => root }, g);
    mod.exports.registerPca({ addHook: (n: string, fn: never) => (hooks[n] ??= []).push(fn) });
    return { hooks, signed };
  };

  it('enforce refuses to start when the grant on disk no longer verifies under the pinned signer', async () => {
    const { root, deps } = await connected();
    writeFileSync(join(root, 'issued.json'), JSON.stringify(grantOf()));
    await runInit(['--yes', '--enforce', '--grant', 'issued.json'], { cwd: root, deps });
    expect(() => load(root, {})).not.toThrow();
    writeFileSync(join(root, 'autopilot.grant.json'), JSON.stringify(grantOf(generateKeyPair())));
    expect(() => load(root, {})).toThrow(/does not verify under the pinned signer/);
  });

  it('enforce reports its allowed requests with mode enforce, and writes no local observed log', async () => {
    vi.useFakeTimers();
    const { root, deps } = await connected();
    writeFileSync(join(root, 'issued.json'), JSON.stringify(grantOf()));
    await runInit(['--yes', '--enforce', '--grant', 'issued.json'], { cwd: root, deps });
    const posts: unknown[] = [];
    const { hooks, signed } = load(root, {}, (async (u: string) => (posts.push(u), { status: 202 })) as never);
    await (hooks.onResponse![0] as unknown as (a: unknown, b: unknown) => Promise<void>)({ method: 'GET', url: '/ping', body: {} }, { statusCode: 200 });
    await vi.advanceTimersByTimeAsync(5000);
    expect(signed[0]!.claim.source).toBe('run-src-1');
    expect(signed[0]!.claim.events[0]).toMatchObject({ mode: 'enforce', resource: '/ping' });
    expect(existsSync(join(root, '.pca/observed.jsonl'))).toBe(false);
  });

  it('carries only the named parameters, only as safe integers or booleans, bound by the proxy digest', async () => {
    vi.useFakeTimers();
    const { root, deps } = await connected();
    expect((await runInit(['--yes', '--connect', TOKEN, '--include-params', 'amount,express,cardNumber,note'], { cwd: root, deps })).ok).toBe(true);
    expect(parseInitConfig(rd(root, 'pca.init.json'))).toMatchObject({ includeParams: ['amount', 'express', 'cardNumber', 'note'] });
    const { hooks, signed } = load(root, { PCA_MODE: 'observe' }, (async () => ({ status: 202 })) as never);
    await (hooks.onResponse![0] as unknown as (a: unknown, b: unknown) => Promise<void>)(
      { method: 'POST', url: '/ping', body: { amount: 250, express: true, cardNumber: 4242, note: 'free text', ratio: 1.5, other: 7 } },
      { statusCode: 200 },
    );
    await vi.advanceTimersByTimeAsync(5000);
    const ev = signed[0]!.claim.events[0] as { verb: string; resource: string; observed: { seq: number; params: Record<string, unknown>; omitted: string[]; digest: string } };
    expect(ev.observed.params).toEqual({ amount: 250, express: true });
    expect([...ev.observed.omitted].sort()).toEqual(['cardNumber', 'note', 'other', 'ratio']);
    expect(ev.observed.digest).toBe(observedContentDigest({ seq: ev.observed.seq, verb: ev.verb, resource: ev.resource, params: ev.observed.params, omitted: ev.observed.omitted }));
    expect(ev.observed.digest).toHaveLength(43);
    expect(JSON.stringify(ev)).not.toMatch(/free text|4242/);
  });

  it('sends no parameters at all unless the operator named some', async () => {
    vi.useFakeTimers();
    const { root, deps } = await connected();
    void deps;
    const { hooks, signed } = load(root, { PCA_MODE: 'observe' }, (async () => ({ status: 202 })) as never);
    await (hooks.onResponse![0] as unknown as (a: unknown, b: unknown) => Promise<void>)({ method: 'POST', url: '/ping', body: { amount: 250 } }, { statusCode: 200 });
    await vi.advanceTimersByTimeAsync(5000);
    expect(signed[0]!.claim.events[0]).not.toHaveProperty('observed');
  });
});

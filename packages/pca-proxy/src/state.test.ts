import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createMemoryDurableKv } from '@atlasauth/pca/durable-state';
import { buildToolRegistry, toolDigest } from './actions';
import { Engine } from './engine';
import { openProxyState, stateFromKv } from './state';
import { cfgFor, createIssue, readIssue, rules } from './test-support/fakes';
import { setup } from './test-support/harness';

const fileState = (dir: string) => ({ state: { backend: 'file', dir } });
const dirOf = (): string => join(mkdtempSync(join(tmpdir(), 'pcap-state-')), 'state');

describe('state survives a restart', () => {
  it('the grant is the same grant: same keys, same id, and the counter carries on', async () => {
    const dir = dirOf();
    const a = setup(fileState(dir));
    await a.call('read_issue', { id: 1 });
    await a.call('read_issue', { id: 2 });
    const first = a.proxy.currentEngine!.agent.grant.id;
    const b = setup(fileState(dir));
    // a proof the old process minted with counter 2 must not be minted again by the new one: it carries on from the stored counter
    expect(b.denied(await b.call('read_issue', { id: 3 }))).toBe('');
    expect(b.proxy.currentEngine!.agent.grant.id).toBe(first);
  });

  it('the budget is spent across a restart', async () => {
    const dir = dirOf();
    const a = setup({ ...fileState(dir), budget: { max: 0.1 } });
    expect(a.denied(await a.call('read_issue', { id: 1 }))).toBe('');
    expect(a.denied(await a.call('read_issue', { id: 2 }))).toBe('');
    const b = setup({ ...fileState(dir), budget: { max: 0.1 } });
    expect(b.denied(await b.call('read_issue', { id: 3 }))).toMatch(/verify_denied/);
    expect(b.up.calls).toHaveLength(0);
  });

  it('the session taint survives a restart: a write is held again', async () => {
    const dir = dirOf();
    const a = setup(fileState(dir));
    await a.call('read_issue', { id: 1 });
    const b = setup({ ...fileState(dir), approvals: { waitSeconds: 1 } });
    expect(b.denied(await b.call('create_issue', { title: 'after restart' }))).toMatch(/approval_timeout/);
    expect(b.up.calls).toHaveLength(0);
  });

  it('a rate window survives a restart', async () => {
    const dir = dirOf();
    const limited = rules({ create_issue: { policy: 'allow', effect: 'write', pin: toolDigest(createIssue), limit: '1/hour', insecureAllowAfterUntrusted: true } });
    const a = setup(fileState(dir), limited);
    expect(a.denied(await a.call('create_issue', { title: 'one' }))).toBe('');
    const b = setup(fileState(dir), limited);
    expect(b.denied(await b.call('create_issue', { title: 'two' }))).toMatch(/rate_limited/);
  });

  it('a grant window that ended starts a new one from the same keys; before it ends the grant is the same', async () => {
    const dir = dirOf();
    let now = 1_000_000;
    const limited = rules({ read_issue: { policy: 'allow', effect: 'read', pin: toolDigest(readIssue), limit: '$5/day', amountField: 'id' } });
    const cfg = cfgFor(fileState(dir), limited);
    const candidates = buildToolRegistry([readIssue], cfg.mcp!).candidates;
    const e1 = await Engine.create({ cfg, candidates, now: () => now });
    now += 3600_000;
    const e1b = await Engine.create({ cfg, candidates, now: () => now });
    expect(e1b.agent.grant.id).toBe(e1.agent.grant.id);
    now += 2 * 86_400_000;
    const e2 = await Engine.create({ cfg, candidates, now: () => now });
    expect(e2.principal.publicKey).toEqual(e1.principal.publicKey);
    expect(e2.agent.grant.id).not.toBe(e1.agent.grant.id);
  });
});

describe('the state fails closed', () => {
  it('a corrupt journal stops the proxy from starting instead of starting empty', async () => {
    const dir = dirOf();
    // opening writes nothing: the journal exists once something was stored
    await (await openProxyState(cfgFor(fileState(dir)))).kv.update('probe', () => 1);
    const journal = join(dir, readdirSync(dir).find((f) => f.endsWith('journal'))!);
    writeFileSync(journal, `${readFileSync(journal, 'utf8').slice(0, -20)}\n`);
    await expect(openProxyState(cfgFor(fileState(dir)))).rejects.toThrow();
  });

  it('a state that stops answering refuses the call', async () => {
    const real = createMemoryDurableKv();
    let down = false;
    const kv = new Proxy(real, {
      get(target, prop) {
        const v = (target as never)[prop];
        return typeof v === 'function' ? (...a: unknown[]) => (down ? Promise.reject(new Error('disk gone')) : (v as (...x: unknown[]) => unknown).apply(target, a)) : v;
      },
    });
    const t = setup({}, rules(), undefined, (cfg, candidates) => Engine.create({ cfg, candidates, state: stateFromKv(kv, true) }));
    expect(t.denied(await t.call('read_issue', { id: 1 }))).toBe('');
    down = true;
    expect(t.denied(await t.call('read_issue', { id: 2 }))).toMatch(/denied by pca-proxy: (state_unavailable|verify_denied|internal_error)/);
    expect(t.up.calls).toHaveLength(1);
  });

  it('a result that cannot be labelled untrusted is not relayed', async () => {
    const real = createMemoryDurableKv();
    const kv = { ...real, set: () => Promise.reject(new Error('disk full')) };
    const t = setup({}, rules(), undefined, (cfg, candidates) => Engine.create({ cfg, candidates, state: stateFromKv(kv, true) }));
    expect(t.denied(await t.call('read_issue', { id: 1 }))).toMatch(/state_unavailable/);
  });
});

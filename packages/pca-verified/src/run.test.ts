import { describe, expect, it } from 'vitest';
import { loadBundledCorpus, parseCorpus, sendLine, CorpusError } from './corpus';
import { runDriver } from './driver';
import { judge } from './judge';
import { runConformance, verifyReport, type Report } from './run';
import { createStatements } from './statement';
import { generateKeyPairSync } from 'node:crypto';
import { miniCorpus, MINI_ITEMS, REGISTERED, scriptedDriver, truth } from './mini.testutil';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const impl = { name: 'demo', version: '1.0.0' };
const run = (mode = 'perfect', target = '', lie?: unknown, profiles = ['core-verifier'], timeout?: number): Promise<Report> => {
  const corpus = miniCorpus();
  const driver = scriptedDriver(corpus, mode, target, lie);
  return runConformance({ corpus, profiles, implementation: impl, driver: { ...driver, ...(timeout ? { caseTimeoutMs: timeout } : {}) } });
};
const outcome = (r: Report, id: string): string | undefined => r.cases.find((c) => c.id === id)?.outcome;

describe('a correct driver', () => {
  it('passes every profile it implements, and the report is deterministic', async () => {
    const a = await run('perfect', '', undefined, ['core-verifier', 'producer', 'stateful']);
    const b = await run('perfect', '', undefined, ['core-verifier', 'producer', 'stateful']);
    expect(a.profiles['core-verifier']!.status).toBe('pass');
    expect(a.profiles.producer!.status).toBe('pass');
    expect(a.profiles.stateful!.status).toBe('pass');
    expect(outcome(a, 'v-pq')).toBe('refused'); // a suite it does not declare is refused, which is the passing answer
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
  it('is judged over stdio framing too', async () => {
    const corpus = miniCorpus();
    const dir = mkdtempSync(join(tmpdir(), 'pcav-stdio-'));
    const answers = Object.fromEntries(corpus.items.map((i) => [i.id, truth(i)]));
    writeFileSync(join(dir, 'a.json'), JSON.stringify(answers));
    writeFileSync(join(dir, 'd.js'), `const fs=require('fs');const a=JSON.parse(fs.readFileSync(${JSON.stringify(join(dir, 'a.json'))},'utf8'));for(const l of fs.readFileSync(0,'utf8').split('\\n')){if(!l)continue;const c=JSON.parse(l);process.stdout.write(JSON.stringify({id:c.id,...a[c.id]})+'\\n');}`);
    const r = await runConformance({ corpus, profiles: ['core-verifier'], implementation: impl, driver: { command: `${JSON.stringify(process.execPath)} ${JSON.stringify(join(dir, 'd.js'))}`, io: 'stdio' } });
    expect(r.profiles['core-verifier']!.status).toBe('pass');
  });
  it('supports {in} and {out} placeholders', async () => {
    const corpus = miniCorpus();
    const d = scriptedDriver(corpus);
    const r = await runDriver({ ...d, command: d.command.replace(/ $/, '') + ' {in} {out}' }, [sendLine(corpus.items[0]!, corpus.header)], 1);
    expect(r.answers.get('suites-manifest')).toMatchObject({ suites: ['ed25519'] });
  });
});

describe('a driver that lies, hangs, crashes or garbles its output', () => {
  it('a selective liar fails exactly the item it lies about, and nothing is attested', async () => {
    const r = await run('lie', 'v-bad-aud', { allow: true, checks: { wire: true, audience: true, validity: true, chain: true, grant_ref_bound: true, plan_inclusion: true, leaf_signature: true, counter_format: true } });
    expect(outcome(r, 'v-bad-aud')).toBe('fail');
    expect(outcome(r, 'v-accept')).toBe('pass');
    expect(r.profiles['core-verifier']!.status).toBe('fail');
    expect(createStatements(r, { key: generateKeyPairSync('ed25519').privateKey, issuer: 'x' })).toEqual([]);
  });
  it('accepting a vector that needs an undeclared suite fails it', async () => {
    const r = await run('lie', 'v-pq', { allow: true, checks: { wire: true, leaf_signature: true } });
    expect(outcome(r, 'v-pq')).toBe('fail');
  });
  it('right verdict for the wrong check is a failure', async () => {
    const r = await run('lie', 'v-bad-aud', { allow: false, checks: { wire: true, audience: true, validity: false } });
    expect(outcome(r, 'v-bad-aud')).toBe('fail');
  });
  it('a hang is isolated to its item; the rest still run', async () => {
    const r = await run('hang', 'v-wire', undefined, ['core-verifier'], 1000);
    expect(outcome(r, 'v-wire')).toBe('fault');
    expect(r.cases.find((c) => c.id === 'v-wire')!.why).toBe('hang');
    expect(outcome(r, 'v-accept')).toBe('pass');
    expect(outcome(r, 'p-1')).toBe('pass');
    expect(r.profiles['core-verifier']!.status).toBe('fail');
  }, 90000);
  it('a crash is isolated to its item', async () => {
    const r = await run('crash', 'c-ok');
    expect(outcome(r, 'c-ok')).toBe('fault');
    expect(outcome(r, 'v-accept')).toBe('pass');
    expect(outcome(r, 'p-1')).toBe('pass');
    expect(r.profiles['core-verifier']!.status).toBe('fail');
  }, 90000);
  it('an item the driver silently skips is a fault', async () => {
    const r = await run('skip', 'ch-ok');
    expect(outcome(r, 'ch-ok')).toBe('fault');
    expect(r.profiles['core-verifier']!.status).toBe('fail');
  }, 90000);
  it.each(['garbage', 'unknown', 'duplicate'])('protocol violations (%s) fail every profile even when every answer is right', async (mode) => {
    const r = await run(mode, 'v-accept');
    expect(r.protocol_violations).toBeGreaterThan(0);
    expect(r.profiles['core-verifier']!.status).toBe('fail');
    expect(createStatements(r, { key: generateKeyPairSync('ed25519').privateKey, issuer: 'x' })).toEqual([]);
  });
  it('a driver that cannot start answers nothing and fails everything without bisecting forever', async () => {
    const corpus = miniCorpus();
    const r = await runConformance({ corpus, profiles: ['core-verifier'], implementation: impl, driver: { command: 'exit 3', caseTimeoutMs: 1000 } });
    expect(r.profiles['core-verifier']!.status).toBe('fail');
    expect(r.cases.every((c) => c.outcome === 'fault')).toBe(true);
  }, 60000);
  it('a driver that does not implement a kind is unsupported, not passed', async () => {
    const r = await run('perfect', '', undefined, ['stateful', 'core-verifier']);
    const corpus = miniCorpus();
    const none = await runConformance({ corpus, profiles: ['stateful'], implementation: impl, driver: scriptedDriver(corpus, 'lie', 'st-1', { error: 'unsupported' }) });
    expect(none.profiles.stateful!.status).toBe('unsupported');
    expect(r.profiles.stateful!.status).toBe('pass');
  });
  it('the pq profile needs the required suites declared', async () => {
    const r = await run('perfect', '', undefined, ['pq']);
    expect(r.profiles.pq!.status).toBe('fail');
    expect(r.profiles.pq!.reasons.join(' ')).toContain('suite manifest lacks ml-dsa-65');
  });
});

describe('a tampered report', () => {
  it('is caught: flipping a case, a profile status or the digest no longer follows from the corpus', async () => {
    const corpus = miniCorpus();
    const r = await runConformance({ corpus, profiles: ['core-verifier'], implementation: impl, driver: scriptedDriver(corpus, 'lie', 'v-accept', { allow: false, checks: { wire: false } }) });
    expect(verifyReport(r, corpus).ok).toBe(true);
    const flipCase = structuredClone(r);
    flipCase.cases.find((c) => c.id === 'v-accept')!.outcome = 'pass';
    expect(verifyReport(flipCase, corpus).ok).toBe(false);
    const flipStatus = structuredClone(r);
    flipStatus.profiles['core-verifier']!.status = 'pass';
    expect(verifyReport(flipStatus, corpus).ok).toBe(false);
    const flipDigest = structuredClone(r);
    flipDigest.profiles['core-verifier']!.results_digest = '0'.repeat(64);
    expect(verifyReport(flipDigest, corpus).ok).toBe(false);
    const dropCase = structuredClone(r);
    dropCase.cases = dropCase.cases.filter((c) => c.id !== 'v-accept');
    expect(verifyReport(dropCase, corpus).ok).toBe(false);
    const foreign = structuredClone(r);
    foreign.cases.push({ id: 'not-in-corpus', layer: 'wire', outcome: 'pass' });
    expect(verifyReport(foreign, corpus).ok).toBe(false);
  });
  it('a partial run is incomplete and cannot be attested', async () => {
    const corpus = miniCorpus();
    const r = await runConformance({ corpus, profiles: ['core-verifier'], limit: 3, implementation: impl, driver: scriptedDriver(corpus) });
    expect(r.profiles['core-verifier']!.status).toBe('incomplete');
    expect(createStatements(r, { key: generateKeyPairSync('ed25519').privateKey, issuer: 'x' })).toEqual([]);
  });
});

describe('judging', () => {
  const reg = REGISTERED;
  const item = MINI_ITEMS.find((i) => i.id === 'v-accept')!;
  it('refuses answers that are not verdicts', () => {
    for (const bad of [null, 'x', [], {}, { allow: 'yes', checks: {} }, { allow: true }, { allow: true, checks: [] }]) expect(judge(item, bad, new Set(['ed25519']), reg).outcome).toBe('fail');
  });
  it('an extra check the vector does not mention does not matter, a missing one does', () => {
    const ok = truth(item);
    expect(judge(item, { ...ok, checks: { ...ok.checks, intent: true } }, new Set(['ed25519']), reg).outcome).toBe('pass');
    const { wire: _w, ...rest } = ok.checks;
    expect(judge(item, { ...ok, checks: rest }, new Set(['ed25519']), reg).outcome).toBe('fail');
  });
  it('a canon reject must not return a canonical form', () => {
    const c = MINI_ITEMS.find((i) => i.id === 'c-bad')!;
    expect(judge(c, { canon: '{"a":1}' }, new Set(), reg).outcome).toBe('fail');
    expect(judge(c, { error: 'parse' }, new Set(), reg).outcome).toBe('pass');
  });
  it('the suites manifest must be honest', () => {
    const s = MINI_ITEMS.find((i) => i.id === 'suites-manifest')!;
    for (const bad of [{ suites: ['ml-dsa-65'] }, { suites: ['ed25519', 'ed25519'] }, { suites: ['ed25519', 'made-up'] }, { suites: [1] }]) expect(judge(s, bad, new Set(), reg).outcome).toBe('fail');
    expect(judge(s, { suites: ['ed25519'] }, new Set(), reg).outcome).toBe('pass');
  });
});

describe('the bundled corpus', () => {
  it('matches its pinned hash and never sends an expectation to the driver', () => {
    const c = loadBundledCorpus();
    expect(c.items.length).toBe(c.manifest.items);
    for (const it of c.items.slice(0, 2000)) {
      const line = sendLine(it, c.header);
      expect(line.id).toBe(it.id);
      expect('expect' in line).toBe(false);
    }
    // stateful sequences go out without their per-step expectations
    for (const it of c.items.filter((i) => i.kind === 'stateful')) expect(JSON.parse(String(sendLine(it, c.header).raw)).steps.some((s: { expect?: unknown }) => 'expect' in s)).toBe(false);
  });
  it('refuses content that does not match the manifest hash', () => {
    const c = loadBundledCorpus();
    expect(() => parseCorpus('{"corpus":{}}\n', c.manifest)).toThrow(CorpusError);
  });
  it('every profile has items and the pq and producer profiles are not empty', () => {
    const c = loadBundledCorpus();
    for (const p of ['core-verifier', 'producer', 'pq', 'stateful']) expect(c.manifest.profiles[p]!.items).toBeGreaterThan(0);
  });
});

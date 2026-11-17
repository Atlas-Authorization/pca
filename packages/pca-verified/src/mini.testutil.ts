// Test support: a tiny corpus in the real format and scripted drivers (perfect, lying, hanging, crashing, malformed).
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseCorpus, type CorpusItem, type CorpusManifest, type LoadedCorpus } from './corpus';
import type { DriverSpec } from './driver';
import { sha256hex, type Json } from './util';

export const REGISTERED = ['ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65'];
const ALL_PASS = { wire: true, version: true, audience: true, validity: true, chain: true, grant_ref_bound: true, plan_inclusion: true, leaf_signature: true, counter_format: true };

const item = (id: string, layer: CorpusItem['layer'], kind: CorpusItem['kind'], extra: Partial<CorpusItem>): CorpusItem => ({
  id, layer, kind, name: id, send: { kind, raw: '{}', grant: '{}', now: 1, aud: 'a' }, expect: {}, profiles: ['core-verifier'], ...extra,
});

export const MINI_ITEMS: CorpusItem[] = [
  item('suites-manifest', 'suites', 'suites', { send: { kind: 'suites', raw: '', grant: '', now: 0, aud: '' } }),
  item('v-accept', 'proof', 'verify', { expect: { allow: true, checks: ALL_PASS } }),
  item('v-bad-aud', 'proof', 'verify', { expect: { allow: false, checks: { ...ALL_PASS, audience: false, validity: false, chain: false, grant_ref_bound: false, plan_inclusion: false, leaf_signature: false, counter_format: false } } }),
  item('v-wire', 'wire', 'verify', { expect: { allow: false, checks: { wire: false } } }),
  item('v-pq', 'proof', 'verify', { suites: ['ml-dsa-65'], pq: true, profiles: ['core-verifier', 'pq'], expect: { allow: false, checks: { ...ALL_PASS, leaf_signature: false } } }),
  item('c-ok', 'wire', 'canon', { send: { kind: 'canon', raw: '{"b":1,"a":2}', grant: '', now: 0, aud: '' }, expect: { accept: true, canon: '{"a":2,"b":1}' } }),
  item('c-bad', 'wire', 'canon', { send: { kind: 'canon', raw: '{"a":1,"a":2}', grant: '', now: 0, aud: '' }, expect: { accept: false } }),
  item('ch-ok', 'capability', 'chain', { expect: { ok: true } }),
  item('p-1', 'policy', 'policy', { expect: { caveats: { allow: true, failed: [] }, decision: { allow: true, reasons: [] } } }),
  item('pr-1', 'producer', 'produce', { produce: { op: 'ed25519_sign', args: { m: 1 }, keyset: 'k' }, send: undefined as never, expect: { sig: 'abc' }, profiles: ['producer'] }),
  item('st-1', 'stateful', 'stateful', { expect: { steps: [{ allow: true, failed: [] }, null, { allow: false, failed: ['counter'] }] }, profiles: ['stateful'] }),
];

/** What a correct implementation answers for an item (it knows the expectation: this is the test oracle, not a real driver). */
export function truth(it: CorpusItem): Json {
  switch (it.kind) {
    case 'suites': return { suites: ['ed25519'] };
    case 'verify': return it.suites?.length ? { allow: false, checks: it.expect.checks, unsupported_suite: 'unsupported_suite: ml-dsa-65' } : { allow: it.expect.allow, checks: it.expect.checks };
    case 'canon': return it.expect.accept ? { canon: it.expect.canon, hash: 'h' } : { error: 'parse' };
    case 'chain': return { allow: it.expect.ok, checks: { chain: it.expect.ok } };
    case 'policy': return { allow: it.expect.caveats.allow, failed: it.expect.caveats.failed, decision: it.expect.decision };
    case 'produce': return { out: it.expect };
    case 'stateful': return { steps: it.expect.steps };
    default: return {};
  }
}

export function miniCorpus(items: CorpusItem[] = MINI_ITEMS): LoadedCorpus {
  const profiles: CorpusManifest['profiles'] = {};
  const defs: Record<string, { title: string; requires_suites?: string[] }> = {
    'core-verifier': { title: 'Core Verifier' }, producer: { title: 'Producer' }, pq: { title: 'Post-quantum', requires_suites: ['ml-dsa-65'] }, stateful: { title: 'Stateful' },
  };
  for (const [id, d] of Object.entries(defs)) {
    const its = items.filter((i) => i.profiles.includes(id));
    const layer_items: Record<string, number> = {};
    for (const i of its) layer_items[i.layer] = (layer_items[i.layer] ?? 0) + 1;
    profiles[id] = { title: d.title, description: id, layers: Object.keys(layer_items), items: its.length, layer_items, ...(d.requires_suites ? { requires_suites: d.requires_suites } : {}) };
  }
  const header = { corpus: { version: '9.9.9', protocol: '1', registered_suites: REGISTERED, keysets: { k: { keys: { agent: { seed: 's' } } } } } };
  const text = [JSON.stringify(header), ...items.map((i) => JSON.stringify(i))].join('\n') + '\n';
  const manifest: CorpusManifest = { format: 'pca-verified-corpus/1', corpus_version: '9.9.9', protocol_version: '1', sha256: sha256hex(text), bytes: text.length, items: items.length, layers: {}, profiles, registered_suites: REGISTERED, sources: {} };
  return parseCorpus(text, manifest);
}

const DRIVER_JS = `
const fs = require('fs');
const [inp, outp] = process.argv.slice(2);
const answers = JSON.parse(fs.readFileSync(process.env.PCAV_ANSWERS, 'utf8'));
const mode = process.env.PCAV_MODE || 'perfect';
const target = process.env.PCAV_TARGET || '';
const w = (o) => fs.appendFileSync(outp, (typeof o === 'string' ? o : JSON.stringify(o)) + '\\n');
fs.writeFileSync(outp, '');
for (const l of fs.readFileSync(inp, 'utf8').split('\\n')) {
  if (!l) continue;
  const c = JSON.parse(l);
  if (mode === 'hang' && c.id === target) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 600000);
  if (mode === 'crash' && c.id === target) process.kill(process.pid, 'SIGKILL');
  if (mode === 'skip' && c.id === target) continue;
  let a = answers[c.id] === undefined ? { error: 'unsupported' } : answers[c.id];
  if (mode === 'lie' && c.id === target) a = JSON.parse(process.env.PCAV_LIE);
  if (mode === 'garbage' && c.id === target) w('this is not json');
  if (mode === 'unknown' && c.id === target) w({ id: 'nobody-asked', allow: true });
  w({ id: c.id, ...a });
  if (mode === 'duplicate' && c.id === target) w({ id: c.id, ...a });
}
`;

/** A scripted driver over the mini corpus. `mode`: perfect | lie | hang | crash | skip | garbage | unknown | duplicate. */
export function scriptedDriver(corpus: LoadedCorpus, mode = 'perfect', target = '', lie?: Json): DriverSpec {
  const dir = mkdtempSync(join(tmpdir(), 'pcav-test-'));
  const answers: Record<string, Json> = {};
  for (const it of corpus.items) answers[it.id] = truth(it);
  writeFileSync(join(dir, 'answers.json'), JSON.stringify(answers));
  writeFileSync(join(dir, 'driver.js'), DRIVER_JS);
  return {
    command: `${JSON.stringify(process.execPath)} ${JSON.stringify(join(dir, 'driver.js'))}`,
    caseTimeoutMs: 2500,
    env: { PCAV_ANSWERS: join(dir, 'answers.json'), PCAV_MODE: mode, PCAV_TARGET: target, ...(lie !== undefined ? { PCAV_LIE: JSON.stringify(lie) } : {}) },
  };
}

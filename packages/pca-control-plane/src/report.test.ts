import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { generateKeyPair, b64u } from '@atlasauth/pca';
import { eventOfReceipt, report, reportOnce, REPORT_BATCH } from './report';
import { verifyEnvelope } from './ingest';

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const receipt = (seq: number, extra: Record<string, unknown> = {}) => ({ seq, at: 1_700_000_000_000 + seq, verb: 'gmail.draft', resource: `/drafts/${seq}`, outcome: 'allow', checks: { mode: 'observe', allowed: 'true' }, prev: '', hash: `h${seq}`, ...extra });
const setup = (lines: unknown[]) => {
  const dir = mkdtempSync(join(tmpdir(), 'pca-report-'));
  dirs.push(dir);
  const file = join(dir, 'audit.jsonl');
  writeFileSync(file, lines.map((l) => JSON.stringify(l)).join('\n') + '\n');
  const kp = generateKeyPair();
  return { file, kp };
};
const fakeFetch = (log: Array<{ url: string; headers: Record<string, string>; body: { envelope: unknown } }>, status = 202) =>
  (async (url: string, init: { headers: Record<string, string>; body: string }) => {
    log.push({ url, headers: init.headers, body: JSON.parse(init.body) });
    return { status, ok: status < 300, text: async () => 'no' } as Response;
  }) as unknown as typeof fetch;

describe('eventOfReceipt', () => {
  it('reads an allowed call as auto and a would-be refusal as deny, keeping the mode', () => {
    expect(eventOfReceipt(receipt(1), { agent: 'a' })).toMatchObject({ id: 'h1', outcome: 'auto', mode: 'observe', agent: 'a' });
    expect(eventOfReceipt(receipt(2, { checks: { allowed: 'false', mode: 'observe' } }), { agent: 'a' })).toMatchObject({ outcome: 'deny', r: 0.6 });
    expect(eventOfReceipt(receipt(3, { outcome: 'deny', checks: { mode: 'enforce' } }), { agent: 'a' })).toMatchObject({ outcome: 'deny', mode: 'enforce' });
  });
  it('skips what is not a receipt rather than guessing', () => {
    expect(eventOfReceipt(null, { agent: 'a' })).toBeNull();
    expect(eventOfReceipt({ verb: 'x' }, { agent: 'a' })).toBeNull();
    expect(eventOfReceipt(receipt(1, { at: Number.NaN }), { agent: 'a' })).toBeNull();
    expect(eventOfReceipt(receipt(1, { hash: 'x'.repeat(200) }), { agent: 'a' })).toBeNull();
  });
});

describe('reportOnce', () => {
  it('posts signed batches the control plane accepts, and never reports a line twice', async () => {
    const { file, kp } = setup(Array.from({ length: REPORT_BATCH + 5 }, (_, i) => receipt(i + 1)));
    const log: Array<{ url: string; headers: Record<string, string>; body: { envelope: unknown } }> = [];
    const o = { file, source: 'gw', secret: kp.secretKey, agent: 'agent-1', url: 'https://api.example/', apiKey: 'sk_test', fetch: fakeFetch(log), now: () => 1_700_000_100_000 };
    expect(await reportOnce(o)).toBe(REPORT_BATCH + 5);
    expect(log).toHaveLength(2);
    expect(log[0]!.url).toBe('https://api.example/v1/pca/control/events');
    expect(log[0]!.headers.authorization).toBe('Bearer sk_test');
    const seqs = log.map((l) => (l.body.envelope as { seq: number }).seq);
    expect(seqs[1]!).toBeGreaterThan(seqs[0]!);
    for (const l of log) expect(verifyEnvelope(l.body.envelope, { gw: b64u(kp.publicKey) }, 256).ok).toBe(true);
    expect(readFileSync(`${file}.report`, 'utf8').trim()).toBe(String(REPORT_BATCH + 5));
    expect(await reportOnce(o)).toBe(0);
    expect(log).toHaveLength(2);
  });
  it('stops on a refusal and does not advance the offset', async () => {
    const { file, kp } = setup([receipt(1)]);
    const log: Array<{ url: string; headers: Record<string, string>; body: { envelope: unknown } }> = [];
    await expect(report({ file, source: 'gw', secret: kp.secretKey, agent: 'a', url: 'https://x', apiKey: 'sk_x', fetch: fakeFetch(log, 403), follow: true })).rejects.toThrow(/refused the batch \(403\)/);
    expect(() => readFileSync(`${file}.report`)).toThrow();
  });
  it('retries a transient failure when following, then reports', async () => {
    const { file, kp } = setup([receipt(1)]);
    let calls = 0;
    const f = (async () => {
      calls++;
      return calls === 1 ? ({ status: 503, ok: false, text: async () => '' } as Response) : ({ status: 202, ok: true, text: async () => '' } as Response);
    }) as unknown as typeof fetch;
    let rounds = 0;
    const n = await report({ file, source: 'gw', secret: kp.secretKey, agent: 'a', url: 'https://x', apiKey: 'sk_x', fetch: f, follow: true, sleep: async () => undefined, stop: () => ++rounds >= 2 });
    expect(n).toBe(1);
    expect(calls).toBe(2);
  });
});

describe('observed parameters', () => {
  const obs = { obs1: 'a'.repeat(22), obs2: 'b'.repeat(21) };
  it('carries a receipt line with the digest the receipt holds', async () => {
    const { file, kp } = setup([receipt(1, { checks: { mode: 'observe', allowed: 'true', ...obs } })]);
    writeFileSync(`${file}.params.jsonl`, `${JSON.stringify({ v: 1, seq: 1, receipt: 'h1', verb: 'gmail.draft', resource: '/drafts/1', params: { recipients: 2 }, omitted: ['note'], prev: '', hash: 'x' })}\n`);
    const log: Array<{ url: string; headers: Record<string, string>; body: { envelope: { events: Array<{ observed?: unknown }> } } }> = [];
    await reportOnce({ file, source: 'gw', secret: kp.secretKey, agent: 'a', url: 'https://x', apiKey: 'sk_x', fetch: fakeFetch(log as never) as never });
    expect(log[0]!.body.envelope.events[0]!.observed).toEqual({ seq: 1, params: { recipients: 2 }, omitted: ['note'], digest: `${obs.obs1}${obs.obs2}` });
  });
  it('waits for a last receipt whose parameters line has not been written yet', async () => {
    const { file, kp } = setup([receipt(1), receipt(2, { checks: { mode: 'observe', allowed: 'true', ...obs } })]);
    const log: Array<{ url: string; headers: Record<string, string>; body: { envelope: unknown } }> = [];
    expect(await reportOnce({ file, source: 'gw', secret: kp.secretKey, agent: 'a', url: 'https://x', apiKey: 'sk_x', fetch: fakeFetch(log) })).toBe(1);
    expect(readFileSync(`${file}.report`, 'utf8').trim()).toBe('1');
  });
});

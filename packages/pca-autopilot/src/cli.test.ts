import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair, readEnvelope } from '@atlasauth/pca';
import { runAutopilot, type AutopilotIo } from './cli';
import { NOW, benign, jsonl, row } from './test-support/fixtures';

const mem = (files: Record<string, string>): AutopilotIo & { files: Record<string, string> } => ({
  files,
  read: (p) => { const v = files[p]; if (v === undefined) throw new Error(`no such file ${p}`); return v; },
  write: (p, d) => { files[p] = d; },
  now: () => NOW,
});

describe('pca autopilot', () => {
  it('observe -> propose -> verify -> review: a signed review writes the approval and mints the grant', async () => {
    const io = mem({ 'audit.jsonl': jsonl([...benign(), row(20, { verb: 'gmail.delete', resource: '/drafts/1', params: {} })]) });
    const o = await runAutopilot(['observe', 'audit.jsonl'], io);
    expect(o.ok).toBe(true);
    expect(o.text).toMatch(/sensitive \(need explicit confirmation/);
    const p = await runAutopilot(['propose', 'autopilot.traces.json', '--now', String(NOW)], io);
    expect(p.ok).toBe(true);
    expect(p.text).toMatch(/HELD BACK/);
    const v = await runAutopilot(['verify', 'autopilot.proposal.json', 'autopilot.traces.json'], io);
    expect(v.ok).toBe(true);
    expect(v.text).toMatch(/VERIFICATION: PASSED/);
    const dry = await runAutopilot(['review', 'autopilot.proposal.json', 'autopilot.report.json'], io);
    expect(dry.text).toMatch(/nothing signed/);
    expect(io.files['autopilot.approval.json']).toBeUndefined();
    const k = generateKeyPair();
    const holder = generateKeyPair();
    const r = await runAutopilot(['review', 'autopilot.proposal.json', 'autopilot.report.json', `--reviewer-key=${b64u(k.secretKey)}`, '--yes', '--now', String(NOW), `--holder=${b64u(holder.publicKey)}`, '--goal', 'draft mail'], io);
    expect(r.ok).toBe(true);
    const grant = JSON.parse(io.files['autopilot.grant.json']!) as Parameters<typeof readEnvelope>[0];
    expect(typeof (grant as { id?: unknown }).id).toBe('string'); // the shape http.grants loads
    expect(io.files['autopilot.grant.json.goal-salt']).toBeTruthy();
    expect(readEnvelope(grant)!.predicates).toEqual(JSON.parse(io.files['autopilot.proposal.json']!).policy.predicates);
  });

  it('review refuses to sign a proposal whose verification failed', async () => {
    const io = mem({ 'a.jsonl': jsonl(benign()) });
    await runAutopilot(['observe', 'a.jsonl'], io);
    await runAutopilot(['propose', 'autopilot.traces.json', '--now', String(NOW)], io);
    await runAutopilot(['verify', 'autopilot.proposal.json', 'autopilot.traces.json'], io);
    const rep = JSON.parse(io.files['autopilot.report.json']!);
    io.files['autopilot.report.json'] = JSON.stringify({ ...rep, ok: true, replay: { ...rep.replay, ok: false } });
    const r = await runAutopilot(['review', 'autopilot.proposal.json', 'autopilot.report.json', `--reviewer-key=${b64u(generateKeyPair().secretKey)}`, '--yes'], io);
    expect(r.ok).toBe(false);
    expect(io.files['autopilot.approval.json']).toBeUndefined();
  });

  it('turns bad input into a failed command, not a crash', async () => {
    const io = mem({});
    expect((await runAutopilot(['observe'], io)).ok).toBe(false);
    expect((await runAutopilot(['propose', 'missing.json'], io)).ok).toBe(false);
    expect((await runAutopilot(['bogus'], io)).ok).toBe(false);
    expect((await runAutopilot(['propose', 'x', '--margin', 'NaN'], mem({ x: '{}' }))).text).toMatch(/finite/);
    expect((await runAutopilot([], io)).text).toMatch(/pca autopilot/);
  });

  it('amend proposes a widening that must be verified and reviewed again', async () => {
    const io = mem({ 'a.jsonl': jsonl(benign()) });
    await runAutopilot(['observe', 'a.jsonl'], io);
    await runAutopilot(['propose', 'autopilot.traces.json', '--now', String(NOW)], io);
    io.files['b.jsonl'] = jsonl([...benign(), ...Array.from({ length: 3 }, (_, i) => row(100 + i, { resource: '/mail/x', outcome: 'deny' }))]);
    await runAutopilot(['observe', 'b.jsonl', '--out', 'b.traces.json'], io);
    const r = await runAutopilot(['amend', 'autopilot.proposal.json', 'b.traces.json', '--now', String(NOW), '--out', 'amended.json'], io);
    expect(r.ok).toBe(true);
    expect(JSON.parse(io.files['amended.json']!).amends).toBe(JSON.parse(io.files['autopilot.proposal.json']!).digest);
    expect(r.text).toMatch(/verify and review it again/);
  });
});

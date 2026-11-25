import { describe, expect, it } from 'vitest';
import { approvalChallenge, approvalChallengeB64u, approvalRenderDigest, approvalRenderShapeError, bindingWords, BINDING_WORDS, type ApprovalRender } from './approval-render';
import { lineageLines, renderLines } from './approval-channels';
import { b64u } from './hash';
import type { StepUpRequest } from './approvals';

const R: ApprovalRender = {
  v: 1, kind: 'pca-approval-render', verb: 'bank.transfer.send', def_digest: b64u(new Uint8Array(32).fill(9)), unreviewed: false,
  fields: [
    { id: 'amount', class: 'money.amount', value: 12_500, unit: { kind: 'money', ccy: 'EUR', exp: 2 } },
    { id: 'payee', class: 'party.payee', value: 'Acme ‮GmbH' },
  ],
};

describe('approval render primitives', () => {
  it('digest and challenge are pinned (a change is a wire break)', () => {
    const rd = approvalRenderDigest(R);
    const a = b64u(new Uint8Array(32).fill(1));
    expect(rd).toBe('LjQomUwTzYsTeEr-19zzjY3IFXrjFSWmqFMEDySTFG0');
    expect(approvalChallengeB64u(a, rd)).toBe('_cKOo5of1PhFvw41Z8I19YlnabGrS8Fk-Cdmv1pznAI');
    expect(approvalChallengeB64u(a, rd)).toBe(b64u(approvalChallenge(a, rd)));
    expect(approvalChallengeB64u(a, rd)).not.toBe(approvalChallengeB64u(a, approvalRenderDigest({ ...R, unreviewed: true })));
  });
  it('shape: closed members, sorted unique ids, bounded', () => {
    expect(approvalRenderShapeError(R)).toBeNull();
    expect(approvalRenderShapeError({ ...R, x: 1 })).toContain('unknown member');
    expect(approvalRenderShapeError({ ...R, fields: [...R.fields].reverse() })).toContain('sorted');
    expect(approvalRenderShapeError({ ...R, fields: [R.fields[0], R.fields[0]] })).toContain('sorted');
    expect(approvalRenderShapeError({ ...R, fields: [{ ...R.fields[0], label: 'x' }] })).toContain('unknown member');
    expect(approvalRenderShapeError({ ...R, fields: Array.from({ length: 65 }, (_, i) => ({ id: `p${String(i).padStart(3, '0')}`, class: 'param', value: 1 })) })).toContain('at most');
    expect(() => approvalRenderDigest({ ...R, unreviewed: 'no' } as unknown as ApprovalRender)).toThrow();
  });
  it('binding words: 256 distinct words, six per digest', () => {
    expect(new Set(BINDING_WORDS).size).toBe(256);
    expect(bindingWords(b64u(new Uint8Array(32).fill(0)))).toBe(Array(6).fill(BINDING_WORDS[0]).join('-'));
    expect(() => bindingWords('short')).toThrow();
  });
});

describe('channels show the whole render', () => {
  const req = (render: ApprovalRender): StepUpRequest => ({
    id: 'x', verb: render.verb, resource: 'acct', tier: 3, reason: 'r', goalCommit: '', r: 0.5, requestedAt: 0, render, renderDigest: approvalRenderDigest(render),
    lineage: { goalCommit: '', goalVerified: false, chain: [], because: 'because' },
  });
  it('lists every field, escapes bidi controls, shows the match code, and the unreviewed banner', () => {
    const lines = renderLines(req({ ...R, unreviewed: true }));
    expect(lines[0]).toContain('UNREVIEWED');
    expect(lines.some((l) => l.startsWith('amount [money.amount]: 12500 EUR'))).toBe(true);
    expect(lines.join('\n')).not.toContain('‮');
    expect(lines.join('\n')).toContain('\\u{202e}');
    expect(lines.at(-1)).toBe(`Match code: ${bindingWords(approvalRenderDigest({ ...R, unreviewed: true }))}`);
    expect(lineageLines(req(R))).toEqual(expect.arrayContaining(renderLines(req(R))));
  });
  it('a request without a render adds nothing', () => {
    const r = req(R);
    delete r.render;
    expect(renderLines(r)).toEqual([]);
  });
});

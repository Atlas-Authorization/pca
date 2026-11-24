import { describe, expect, it } from 'vitest';
import { bindingWords, type ApprovalRender } from './approval-render';
import { renderLines } from './approval-channels';
import type { StepUpRequest } from './approvals';

const DIGEST = 'A'.repeat(43);
const render = (over: Partial<ApprovalRender> = {}): ApprovalRender => ({ v: 1, kind: 'pca-approval-render', verb: 'acme.pay', def_digest: DIGEST, unreviewed: false, fields: [], ...over });
const req = (r: ApprovalRender | undefined, renderDigest: string | undefined) => ({ render: r, renderDigest }) as unknown as StepUpRequest;

describe('renderLines', () => {
  it('is empty without a render or without its digest', () => {
    expect(renderLines(req(undefined, DIGEST))).toEqual([]);
    expect(renderLines(req(render(), undefined))).toEqual([]);
  });
  it('shows no banner for a reviewed render and the match code last', () => {
    expect(renderLines(req(render(), DIGEST))).toEqual([`Match code: ${bindingWords(DIGEST)}`]);
  });
  it('shows the unreviewed banner first', () => {
    const lines = renderLines(req(render({ unreviewed: true }), DIGEST));
    expect(lines).toEqual([
      'UNREVIEWED ACTION: its definition has not been confirmed, so every value is shown raw and one-tap approval is disabled.',
      `Match code: ${bindingWords(DIGEST)}`,
    ]);
  });
  it('prints each field exactly, with a unit suffix only for money', () => {
    const lines = renderLines(req(render({
      fields: [
        { id: 'amount', class: 'money.amount', value: 4000, unit: { kind: 'money', ccy: 'USD', exp: 2 } },
        { id: 'memo', class: 'param', value: 'hi' },
        { id: 'n', class: 'param', value: 3, unit: { kind: 'count' } },
      ],
    }), DIGEST));
    expect(lines).toEqual([
      'amount [money.amount]: 4000 USD (minor units, exponent 2)',
      'memo [param]: "hi"',
      'n [param]: 3',
      `Match code: ${bindingWords(DIGEST)}`,
    ]);
  });
});

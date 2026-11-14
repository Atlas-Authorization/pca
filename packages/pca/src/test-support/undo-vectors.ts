import { b64u, sha256, utf8 } from '../hash';
import { publicKeyOf } from '../keys';
import { obligationsError } from '../obligations';
import {
  compensationDigest,
  encodeUndoToken,
  resolveUndoWindow,
  signUndoReceipt,
  signUndoToken,
  undoReceiptChainError,
  undoReceiptDigest,
  undoTokenCheck,
  undoTokenDigest,
  undoTransition,
  type UndoCompensation,
  type UndoReceipt,
  type UndoRecord,
  type UndoTransitionEvent,
} from '../undo';

/**
 * Shared vectors for undo windows (conformance/undo-vectors.json): the pure layer every language implements. Signatures are
 * deterministic Ed25519 over the domain-separated strict-canonical body, so natives reproduce them byte for byte.
 *   compensation  compensationDigest(c) == digest
 *   token         sign(record fields, signer seed) == token (and encoded, digest); checks: undoTokenCheck -> the code
 *   receipts      sign(body) == receipt (and digest); chains: undoReceiptChainError == null iff ok (error text not compared)
 *   transitions   undoTransition(record, event, now) -> outcome, plus code (refused) or the next state/ver/attempt (applied)
 *   window        resolveUndoWindow(requested, policy) == expect
 *   obligation    obligationsError([obligation]) == null iff ok
 * Regenerate: UNDO_VECTORS_WRITE=1 vitest run src/undo-vectors.test.ts
 */
const SEED = sha256(utf8('atlas-pca/undo-vectors/signer'));
const OTHER_SEED = sha256(utf8('atlas-pca/undo-vectors/other-signer'));
const T0 = 1_800_000_000_000;
const END = T0 + 900_000;

export function buildUndoVectors() {
  const signer = b64u(publicKeyOf(SEED));
  const other = b64u(publicKeyOf(OTHER_SEED));
  const C1: UndoCompensation = { verb: 'drafts.delete', resource: 'drafts:box1', params: { box: 'box1' }, undo_of: 'op_1', def_digest: 'D'.repeat(43), target_param: 'draft' };
  const C2: UndoCompensation = { verb: 'calendar.event.cancel', resource: 'calendar:primary', params: {}, undo_of: 'op_2', def_digest: 'E'.repeat(43) };
  const C3: UndoCompensation = { verb: 'drafts.delete', resource: 'drafts:box1', params: { box: 'box1', tags: ['a', 'b'], n: 3 }, undo_of: 'op_1', def_digest: 'D'.repeat(43) };
  const compensation = [
    { name: 'with-target', compensation: C1, digest: compensationDigest(C1) },
    { name: 'no-params-no-target', compensation: C2, digest: compensationDigest(C2) },
    { name: 'nested-params', compensation: C3, digest: compensationDigest(C3) },
  ];

  const record = { id: 'op_1', aud: 'drafts-rs', principal: 'P'.repeat(43), compensation_digest: compensationDigest(C1), render_digest: 'R'.repeat(43), window_end: END };
  const token = signUndoToken(record, SEED);
  const noRender = { ...record, render_digest: undefined };
  const tokenNoRender = signUndoToken(noRender, SEED);
  const forOther = signUndoToken({ ...record, id: 'op_9' }, SEED);
  const otherAud = signUndoToken({ ...record, aud: 'other-rs' }, SEED);
  const rec = (r: typeof record | typeof noRender) => ({ id: r.id, aud: r.aud, principal: r.principal, compensation_digest: r.compensation_digest, ...(r.render_digest !== undefined ? { render_digest: r.render_digest } : {}), window_end: r.window_end });
  const checks: { name: string; token: unknown; record: unknown; signer: string; now: number; expect: string }[] = [
    { name: 'valid', token, record: rec(record), signer, now: T0, expect: 'ok' },
    { name: 'valid-at-window-end', token, record: rec(record), signer, now: END, expect: 'ok' },
    { name: 'expired-one-ms-after', token, record: rec(record), signer, now: END + 1, expect: 'expired' },
    { name: 'no-render-binds-empty', token: tokenNoRender, record: rec(noRender), signer, now: T0, expect: 'ok' },
    { name: 'render-digest-mismatch', token: tokenNoRender, record: rec(record), signer, now: T0, expect: 'binding' },
    { name: 'another-signer-expected', token, record: rec(record), signer: other, now: T0, expect: 'signer' },
    { name: 'tampered-exp', token: { ...token, exp: END + 60_000 }, record: rec(record), signer, now: T0, expect: 'signature' },
    { name: 'token-for-another-record', token: forOther, record: rec(record), signer, now: T0, expect: 'record' },
    { name: 'token-for-another-audience', token: otherAud, record: rec(record), signer, now: T0, expect: 'binding' },
    { name: 'extra-member', token: { ...token, x: 1 }, record: rec(record), signer, now: T0, expect: 'malformed' },
    { name: 'wrong-kind', token: { ...token, kind: 'pca-undo-receipt' }, record: rec(record), signer, now: T0, expect: 'malformed' },
    { name: 'not-an-object', token: 'token', record: rec(record), signer, now: T0, expect: 'malformed' },
  ];

  const cd = compensationDigest(C1);
  const r0 = signUndoReceipt({ record: 'op_1', event: 'opened', state: 'open', at: T0, compensation_digest: cd, prev: '', note: 'converted' }, SEED);
  const r1 = signUndoReceipt({ record: 'op_1', event: 'effect', state: 'open', at: T0 + 1_000, compensation_digest: cd, prev: undoReceiptDigest(r0), note: '' }, SEED);
  const r2 = signUndoReceipt({ record: 'op_1', event: 'vetoed', state: 'vetoed', at: T0 + 60_000, compensation_digest: cd, prev: undoReceiptDigest(r1), note: 'token' }, SEED);
  const r3 = signUndoReceipt({ record: 'op_1', event: 'compensated', state: 'compensated', at: T0 + 61_000, compensation_digest: cd, prev: undoReceiptDigest(r2), note: '' }, SEED);
  const receipts = [r0, r1, r2, r3].map((r) => ({ receipt: r, digest: undoReceiptDigest(r) }));
  const chainRec = (state: string, rs: UndoReceipt[], id = 'op_1', c = cd) => ({ record: { id, compensation_digest: c, state }, receipts: rs });
  const back = signUndoReceipt({ record: 'op_1', event: 'effect', state: 'open', at: T0 - 1, compensation_digest: cd, prev: undoReceiptDigest(r0), note: '' }, SEED);
  const chains = [
    { name: 'sound', ...chainRec('compensated', [r0, r1, r2, r3]), signer, expect: { ok: true } },
    { name: 'sound-prefix', ...chainRec('vetoed', [r0, r1, r2]), signer, expect: { ok: true } },
    { name: 'empty', ...chainRec('open', []), signer, expect: { ok: false } },
    { name: 'state-mismatch', ...chainRec('open', [r0, r1, r2]), signer, expect: { ok: false } },
    { name: 'gap', ...chainRec('vetoed', [r0, r2]), signer, expect: { ok: false } },
    { name: 'reordered', ...chainRec('open', [r1, r0]), signer, expect: { ok: false } },
    { name: 'tampered-note', ...chainRec('vetoed', [r0, r1, { ...r2, note: 'operator' }]), signer, expect: { ok: false } },
    { name: 'another-signer', ...chainRec('compensated', [r0, r1, r2, r3]), signer: other, expect: { ok: false } },
    { name: 'another-record', ...chainRec('compensated', [r0, r1, r2, r3], 'op_2'), signer, expect: { ok: false } },
    { name: 'another-compensation', ...chainRec('compensated', [r0, r1, r2, r3], 'op_1', compensationDigest(C2)), signer, expect: { ok: false } },
    { name: 'time-goes-back', ...chainRec('open', [r0, back]), signer, expect: { ok: false } },
    { name: 'first-is-not-opened', ...chainRec('open', [r1]), signer, expect: { ok: false } },
  ];

  type Rec = { state: string; window_end: number; ver: number; attempt: number; effect?: { at: number }; outcome?: { at: number; status: string } };
  const R = (state: string, x: Partial<Rec> = {}): Rec => ({ state, window_end: END, ver: 3, attempt: 0, ...x });
  const E = { effect: { at: T0 } };
  const veto = (via = 'token'): UndoTransitionEvent => ({ kind: 'veto', veto: { at: T0, via: via as 'token', by: 'P'.repeat(43) } });
  const ap = (state: string, x: Record<string, number> = {}) => ({ outcome: 'applied', state, ver: 4, ...x });
  const rf = (code: string) => ({ outcome: 'refused', code });
  const rp = { outcome: 'replayed' };
  const transitions: { name: string; record: Rec; event: unknown; now: number; expect: Record<string, unknown> }[] = [
    { name: 'veto-open', record: R('open'), event: veto(), now: T0, expect: ap('vetoed') },
    { name: 'veto-at-window-end', record: R('open'), event: veto(), now: END, expect: ap('vetoed') },
    { name: 'veto-after-window-end', record: R('open'), event: veto(), now: END + 1, expect: rf('window_closed') },
    { name: 'veto-twice-is-a-replay', record: R('vetoed'), event: veto('operator'), now: T0, expect: rp },
    { name: 'veto-compensated-is-a-replay', record: R('compensated', E), event: veto(), now: T0, expect: rp },
    { name: 'veto-failed-is-a-replay', record: R('compensation_failed', E), event: veto(), now: T0, expect: rp },
    { name: 'veto-finalized', record: R('finalized'), event: veto(), now: T0, expect: rf('finalized') },
    { name: 'veto-unknown-via', record: R('open'), event: { kind: 'veto', veto: { at: T0, via: 'email', by: 'x' } }, now: T0, expect: rf('invalid') },
    { name: 'veto-empty-by', record: R('open'), event: { kind: 'veto', veto: { at: T0, via: 'token', by: '' } }, now: T0, expect: rf('invalid') },
    { name: 'finalize-at-window-end', record: R('open'), event: { kind: 'finalize' }, now: END, expect: rf('window_open') },
    { name: 'finalize-after-window-end', record: R('open'), event: { kind: 'finalize' }, now: END + 1, expect: ap('finalized') },
    { name: 'finalize-twice', record: R('finalized'), event: { kind: 'finalize' }, now: END + 1, expect: rp },
    { name: 'finalize-vetoed', record: R('vetoed'), event: { kind: 'finalize' }, now: END + 1, expect: rf('vetoed') },
    { name: 'abort-before-effect', record: R('open'), event: { kind: 'abort', reason: 'effect_failed' }, now: T0, expect: ap('finalized') },
    { name: 'abort-vetoed-before-effect', record: R('vetoed'), event: { kind: 'abort', reason: 'effect_failed' }, now: T0, expect: ap('finalized') },
    { name: 'abort-after-effect', record: R('open', E), event: { kind: 'abort', reason: 'x' }, now: T0, expect: rf('effect_recorded') },
    { name: 'abort-twice', record: R('finalized', { outcome: { at: T0, status: 'aborted' } }), event: { kind: 'abort', reason: 'x' }, now: T0, expect: rp },
    { name: 'abort-finalized', record: R('finalized', { outcome: { at: T0, status: 'finalized' } }), event: { kind: 'abort', reason: 'x' }, now: T0, expect: rf('finalized') },
    { name: 'effect-open', record: R('open'), event: { kind: 'effect', result: { id: 'd_1' } }, now: T0, expect: ap('open') },
    { name: 'effect-after-veto', record: R('vetoed'), event: { kind: 'effect' }, now: T0, expect: ap('vetoed') },
    { name: 'effect-twice', record: R('open', E), event: { kind: 'effect' }, now: T0, expect: rp },
    { name: 'effect-finalized', record: R('finalized'), event: { kind: 'effect' }, now: T0, expect: rf('finalized') },
    { name: 'compensated-vetoed', record: R('vetoed', E), event: { kind: 'compensated' }, now: T0, expect: ap('compensated') },
    { name: 'compensated-after-failure', record: R('compensation_failed', E), event: { kind: 'compensated' }, now: T0, expect: ap('compensated') },
    { name: 'compensated-open', record: R('open', E), event: { kind: 'compensated' }, now: T0, expect: rf('not_vetoed') },
    { name: 'compensated-twice', record: R('compensated', E), event: { kind: 'compensated' }, now: T0, expect: rp },
    { name: 'failed-vetoed', record: R('vetoed', E), event: { kind: 'compensation_failed', reason: 'x' }, now: T0, expect: ap('compensation_failed') },
    { name: 'failed-open', record: R('open', E), event: { kind: 'compensation_failed', reason: 'x' }, now: T0, expect: rf('not_vetoed') },
    { name: 'retry-failed', record: R('compensation_failed', { ...E, attempt: 2 }), event: { kind: 'retry' }, now: T0, expect: ap('vetoed', { attempt: 3 }) },
    { name: 'retry-vetoed', record: R('vetoed', E), event: { kind: 'retry' }, now: T0, expect: rf('not_failed') },
    { name: 'unknown-event', record: R('open'), event: { kind: 'explode' }, now: T0, expect: rf('invalid') },
    { name: 'unknown-state', record: R('pending'), event: veto(), now: T0, expect: rf('invalid') },
    { name: 'non-integer-now', record: R('open'), event: veto(), now: T0 + 0.5, expect: rf('invalid') },
  ];

  const window = [
    { name: 'absent-is-default', requested: null, policy: {}, expect: 900_000 },
    { name: 'below-floor', requested: 1, policy: {}, expect: 30_000 },
    { name: 'at-floor', requested: 30_000, policy: {}, expect: 30_000 },
    { name: 'in-range', requested: 120_000, policy: {}, expect: 120_000 },
    { name: 'above-ceiling', requested: 100_000_000, policy: {}, expect: 86_400_000 },
    { name: 'host-max', requested: 600_000, policy: { maxMs: 300_000 }, expect: 300_000 },
    { name: 'host-min-cannot-go-below-floor', requested: 5, policy: { minMs: 1 }, expect: 30_000 },
    { name: 'host-default', requested: null, policy: { defaultMs: 60_000 }, expect: 60_000 },
    { name: 'host-max-below-min-is-min', requested: 1, policy: { minMs: 120_000, maxMs: 60_000 }, expect: 120_000 },
  ];

  const obligation = [
    { name: 'valid', obligation: { kind: 'undo_window', params: { id: 'op_1', window_end: END }, due: END }, expect: { ok: true } },
    { name: 'missing-window-end', obligation: { kind: 'undo_window', params: { id: 'op_1' } }, expect: { ok: false } },
    { name: 'missing-id', obligation: { kind: 'undo_window', params: { window_end: END } }, expect: { ok: false } },
    { name: 'no-params', obligation: { kind: 'undo_window' }, expect: { ok: false } },
    { name: 'negative-window-end', obligation: { kind: 'undo_window', params: { id: 'op_1', window_end: -1 } }, expect: { ok: false } },
    { name: 'extra-param', obligation: { kind: 'undo_window', params: { id: 'op_1', window_end: END, by: 'x' } }, expect: { ok: false } },
  ];

  // prove the hand-written expectations against the reference, so a drifted builder cannot ship
  const same = (a: unknown, b: unknown, what: string) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${what}: ${JSON.stringify(a)} != ${JSON.stringify(b)}`); };
  for (const c of checks) same(undoTokenCheck(c.token, c.signer, c.record as never, c.now), c.expect, `token ${c.name}`);
  for (const c of chains) same({ ok: undoReceiptChainError({ ...c.record, receipts: c.receipts } as never, c.signer) === null }, c.expect, `chain ${c.name}`);
  for (const t of transitions) {
    const r = undoTransition({ ...t.record, receipts: [] } as unknown as UndoRecord, t.event as UndoTransitionEvent, t.now);
    const got = r.outcome === 'applied' ? { outcome: 'applied', state: r.record.state, ver: r.record.ver, ...(t.expect.attempt !== undefined ? { attempt: r.record.attempt } : {}) } : r.outcome === 'refused' ? { outcome: 'refused', code: r.code } : { outcome: 'replayed' };
    same(got, t.expect, `transition ${t.name}`);
  }
  for (const w of window) same(resolveUndoWindow(w.requested ?? undefined, w.policy), w.expect, `window ${w.name}`);
  for (const o of obligation) same({ ok: obligationsError([o.obligation]) === null }, o.expect, `obligation ${o.name}`);

  return {
    format: 'pca-undo-vectors',
    ver: 1,
    about: 'Conformance vectors for undo windows (the veto-window ledger). Ed25519 signer = the key whose 32-byte seed is SHA-256("atlas-pca/undo-vectors/signer"). Token: signature over UTF-8("atlas-pca/undo-token/v1" + NUL) followed by the strict-canonical body (every member but sig); encoded = base64url of the strict-canonical token; digest = hashCanonical({d:"atlas-pca/undo-token-ref/v1", t}). Receipt: signature over UTF-8("atlas-pca/undo-receipt/v1" + NUL) + strict-canonical body; digest = hashCanonical({d:"atlas-pca/undo-receipt-ref/v1", r}). Compensation digest = hashCanonical({d:"atlas-pca/undo-compensation/v1", verb, resource, params, undo_of, def_digest, target_param?}). Token checks run in order malformed, signer, signature, record, binding, expired (valid through window_end inclusive). Transitions: applied (state, ver+1, attempt for retry), refused (code) or replayed. Generated by src/test-support/undo-vectors.ts.',
    signer: { seed_label: 'atlas-pca/undo-vectors/signer', public: signer, other_public: other },
    compensation,
    token: { record: rec(record), token, encoded: encodeUndoToken(token), digest: undoTokenDigest(token), checks },
    receipts: { list: receipts, chains },
    transitions,
    window,
    obligation,
  };
}

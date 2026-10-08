import { describe, expect, it } from 'vitest';
import { appendReceipt, receiptHead, verifyReceiptChain } from './receipt';
import { agent } from './facade';
import { generateKeyPair } from './keys';
import { verifyPCActnCore } from './pcactn';

const AUD = 'ins_test';

async function build() {
  const a = agent({ principal: generateKeyPair(), goal: 'g', permissions: { gmail: ['send'] }, aud: AUD });
  let log = [] as ReturnType<typeof appendReceipt>;
  for (let i = 1; i <= 3; i++) {
    const { pcactn } = a.act('gmail.send', `msg:${i}`, {}, { counter: i });
    const v = await verifyPCActnCore(pcactn, { grant: a.grant, audience: AUD, nowEpoch: pcactn.iat });
    log = appendReceipt(log, pcactn, v);
  }
  return log;
}

describe('receipt chain', () => {
  it('builds an intact, sequential, linked hash chain', async () => {
    const log = await build();
    expect(log).toHaveLength(3);
    expect(log[0]!.prev).toBe('');
    expect(log[1]!.prev).toBe(log[0]!.hash);
    expect(log[2]!.prev).toBe(log[1]!.hash);
    expect(log.map((r) => r.seq)).toEqual([0, 1, 2]);
    expect(verifyReceiptChain(log)).toEqual({ ok: true });
    expect(receiptHead(log)).toBe(log[2]!.hash);
  });

  it('detects a tampered body', async () => {
    const log = await build();
    const tampered = [...log];
    tampered[1] = { ...tampered[1]!, resource: 'msg:evil' }; // body changed, hash not recomputed
    const r = verifyReceiptChain(tampered);
    expect(r.ok).toBe(false);
    expect(r.brokenAt).toBe(1);
    expect(r.reason).toMatch(/hash mismatch/);
  });

  it('detects a dropped entry (broken link + seq gap)', async () => {
    const log = await build();
    const dropped = [log[0]!, log[2]!]; // removed seq 1
    const r = verifyReceiptChain(dropped);
    expect(r.ok).toBe(false);
    expect(r.brokenAt).toBe(2);
  });

  it('records the verifier outcome', async () => {
    const log = await build();
    expect(log.every((r) => r.outcome === 'allow')).toBe(true);
    expect(log[0]!.checks?.leaf_signature).toBe('pass');
  });
});

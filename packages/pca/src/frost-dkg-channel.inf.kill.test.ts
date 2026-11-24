import { describe, expect, it } from 'vitest';
import { utf8 } from './hash';
import { createMemoryDkgNetwork } from './frost-dkg-channel';

const SID = utf8('dkg-channel-test-session-0001-xxxxx');

describe('a non-finite collect timeout times out instead of waiting (dkg channel)', () => {
  // old `left <= 0` was false for a NaN deadline, so the wait re-armed forever; -Infinity already timed out
  it.each([Number.NaN, Number.NEGATIVE_INFINITY])('a timeout of %s with no message is a timeout error', async (timeoutMs) => {
    const net = createMemoryDkgNetwork([1, 2], SID);
    await expect(net.channels.get(1)!.collect('round1', [2], timeoutMs)).rejects.toMatchObject({ code: 'timeout', peer: 2 });
  });
});

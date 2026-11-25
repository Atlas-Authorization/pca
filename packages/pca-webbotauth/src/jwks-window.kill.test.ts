import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import { buildKeyDirectory, jwkThumbprint, signRequest, verifySignedRequest, type KeyDirectory } from './index';

const key = generateKeyPair();
const keyid = jwkThumbprint(key.publicKey);
const NOW = 1_800_000_000;
const req = { method: 'GET', url: 'https://api.example.com/v1/x', headers: {} as Record<string, string> };

async function run(win: { nbf?: unknown; exp?: unknown }, skew: number) {
  const directory = buildKeyDirectory([{ publicKey: key.publicKey, keyid }]);
  directory.keys[0] = { ...directory.keys[0]!, ...win } as KeyDirectory['keys'][number];
  const signed = signRequest({ ...req, key, keyid, agentDirectoryUrl: 'https://agent.example.com', created: NOW });
  return verifySignedRequest({ ...req, headers: { ...signed.headers } }, { jwks: directory, now: NOW + 10, clockSkewSec: skew });
}
const NOWV = NOW + 10;

describe('jwks key validity window', () => {
  it('exp: now - skew is the last accepted instant', async () => {
    expect((await run({ exp: NOWV + 1000 }, 0)).valid).toBe(true);
    expect((await run({ exp: NOWV }, 0)).valid).toBe(true);
    expect((await run({ exp: NOWV - 1 }, 0)).valid).toBe(false);
    expect((await run({ exp: NOWV - 5 }, 5)).valid).toBe(true);
    expect((await run({ exp: NOWV - 6 }, 5)).valid).toBe(false);
  });
  it('nbf: now + skew is the first accepted instant', async () => {
    expect((await run({ nbf: NOWV }, 0)).valid).toBe(true);
    expect((await run({ nbf: NOWV + 1 }, 0)).valid).toBe(false);
    expect((await run({ nbf: NOWV + 5 }, 5)).valid).toBe(true);
    expect((await run({ nbf: NOWV + 6 }, 5)).valid).toBe(false);
  });
  it('a bound that is present but not a finite number refuses the key (an expiry is never silently skipped)', async () => {
    for (const bad of [String(NOWV - 1000), String(NOWV + 1000), NaN, Infinity, null, {}]) {
      expect((await run({ nbf: bad }, 0)).valid).toBe(false);
      expect((await run({ exp: bad }, 0)).valid).toBe(false);
    }
    expect((await run({}, 0)).valid).toBe(true); // no bound at all: no window
  });
});

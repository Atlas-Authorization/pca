/** Site kill (client.ts:288): once settled, poll() returns the settled result at once (no wait, no request). */
import { describe, expect, it } from 'vitest';
import { createCibaClient, type CibaFlow } from './client';

describe('CIBA poller: settled short-circuit', () => {
  it('a second poll after approval returns the same result without sleeping, fetching, or honouring an abort', async () => {
    const sleeps: number[] = [];
    let fetches = 0;
    let t = 1_000_000;
    const client = createCibaClient({
      backchannelAuthenticationEndpoint: 'https://idp.example/bc',
      tokenEndpoint: 'https://idp.example/token',
      clientId: 'cid',
      clientSecret: 'sec',
      now: () => t,
      sleep: async (ms: number) => { sleeps.push(ms); t += ms; },
      fetch: (async () => { fetches++; return new Response(JSON.stringify({ access_token: 'at', token_type: 'Bearer' }), { status: 200 }); }) as unknown as typeof fetch,
    });
    const flow: CibaFlow = { authReqId: 'AR1', expiresInSec: 100, intervalSec: 5, startedAt: t, delivery: 'poll', request: {} as never };
    const p = client.poller(flow);
    const first = await p.poll();
    expect(first.status).toBe('approved');
    expect(sleeps).toEqual([5000]);
    const ac = new AbortController();
    ac.abort();
    const again = await p.poll({ signal: ac.signal });
    expect(again).toBe(first);
    expect(sleeps).toEqual([5000]);
    expect(fetches).toBe(1);
  });
});

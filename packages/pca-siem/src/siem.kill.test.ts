import { afterEach, describe, expect, it, vi } from 'vitest';
import type { PCActn, VerifyResult } from '@atlasauth/pca';
import { type SiemSink, exportBatch, httpSink, scrubError, toOcsfEvent } from './index';

const CASES: Array<[string, string]> = [
  ["x://u:pw@h", "x://[redacted]@h"],
  ["x !://user:pw@h", "x !://user:pw@h"],
  ["HTTPS://u:p@h/x", "HTTPS://[redacted]@h/x"],
  ["ftp://a:b@c", "ftp://[redacted]@c"],
  ["http://u:p@h q:r@s", "http://[redacted]@h q:r@s"],
  ["ab://u@h", "ab://u@h"],
  ["a://u:p@", "a://[redacted]@"],
  ["Authorization: Basic abc", "Authorization: [redacted]"],
  ["authorization=\"xyz\" rest", "authorization=[redacted]\"xyz\" rest"],
  ["AUTHORIZATION=tok\nnext", "AUTHORIZATION=[redacted]\nnext"],
  ["authorization  :  v1", "authorization  :  [redacted]"],
  ["xauthorization: v2", "xauthorization: v2"],
  ["authorization\"x: v3", "authorization\"x: v3"],
  ["authorization'=v4'", "authorization'=[redacted]'"],
  ["authorization:\tv5 end", "authorization:\t[redacted]"],
  ["Bearer abcdef", "Bearer [redacted]"],
  ["bearer abcde", "bearer abcde"],
  ["Basic 123456 x", "Basic [redacted] x"],
  ["Splunk a.b~c+d/e=f-g", "Splunk [redacted]"],
  ["Token abcdef ok", "Token [redacted] ok"],
  ["Bearer\tabcdef", "Bearer [redacted]"],
  ["Bearer  abcdef", "Bearer [redacted]"],
  ["xBearer abcdef", "xBearer abcdef"],
  ["Bearer abcdef!", "Bearer [redacted]!"],
  ["token=abc", "token=[redacted]"],
  ["secret: abc", "secret: [redacted]"],
  ["password=abc", "password=[redacted]"],
  ["passwd=abc", "passwd=[redacted]"],
  ["pwd=abc", "pwd=[redacted]"],
  ["api_key=abc", "api_key=[redacted]"],
  ["api-key=abc", "api-key=[redacted]"],
  ["apikey=abc", "apikey=[redacted]"],
  ["dd-api-key=abc", "dd-api-key=[redacted]"],
  ["key=abc", "key=[redacted]"],
  ["signature=abc", "signature=[redacted]"],
  ["sig=abc", "sig=[redacted]"],
  ["credential=abc", "credential=[redacted]"],
  ["xtoken=abc", "xtoken=abc"],
  ["my_key=abc", "my_key=abc"],
  ["TOKEN = abc", "TOKEN = [redacted]"],
  ["token=\"a b c\" z", "token=[redacted] z"],
  ["token='a b' z", "token=[redacted] z"],
  ["token=a b", "token=[redacted] b"],
  ["token=a&b=1", "token=[redacted]&b=1"],
  ["token=a,b", "token=[redacted],b"],
  ["token=a;b", "token=[redacted];b"],
  ["token=\"x\"y", "token=[redacted]y"],
  ["token'=\"x", "token'=\"x"],
  ["token'=abc", "token'=[redacted]"],
  ["token\"=abc", "token\"=[redacted]"],
  ["token :abc", "token :[redacted]"],
  ["token=\tabc", "token=\t[redacted]"],
  ["token=", "token="],
  ["token=\"\"", "token=[redacted]"],
  ["token=''", "token=[redacted]"],
  ["token=\"abc", "token=\"abc"],
  ["token=a\"b", "token=[redacted]\"b"],
  ["token=a'b", "token=[redacted]'b"],
  ["password:\n abc", "password:\n [redacted]"],
  ["pwd = \"p q\" tail", "pwd = [redacted] tail"],
  ["tokenx=abc", "tokenx=abc"],
  ["x-api_key=abc", "x-api_key=[redacted]"],
  ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "[redacted]"],
  ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
  ["a-b_cccccccccccccccccccccccccccccccccccccccc z", "[redacted] z"],
  ["!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"],
  ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
  ["kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk", "[redacted]"],
  ["k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k ", "k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k "],
  ["k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k x", "k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k k ..."],
  ["q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q", "q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q q"],
  ["https://user:pw@h", "https://[redacted]@h"],
  ["git+ssh://usr:pw@h", "git+ssh://[redacted]@h"],
  ["ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ", "ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab "],
  ["ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab c", "ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ..."],
];

describe('scrubError exact output', () => {
  it.each(CASES)('%j', (input, out) => expect(scrubError(input)).toBe(out));
});

const verify = { allow: true, checks: { wire: 'pass', leaf_signature: 'pass' } } as unknown as VerifyResult;
const rec = (sig: string) =>
  ({
    pcactn: { ver: 2, grant_ref: 'g1', action: { verb: 'v', resource: 'r', params_digest: 'pd', reversibility_class: 'reversible' }, plan: { root: 'r', node_id: 'n' }, counter: 1, nonce: 'n1', iat: 1, exp: 2, sig, cap_chain: [{ issuer: 'P', holder: 'A', caveats: [] }] } as unknown as PCActn,
    verify,
    now: 1_800_000_000_000,
  });

describe('signature display boundary', () => {
  it('a 16-character signature is shown whole, a 17-character one is cut to its prefix', () => {
    const s16 = 'abcdefghijklmnop';
    const j16 = JSON.stringify(toOcsfEvent(rec(s16)));
    expect(j16).toContain(s16);
    expect(j16).not.toContain(`${s16}…`);
    const s17 = `${s16}q`;
    const j17 = JSON.stringify(toOcsfEvent(rec(s17)));
    expect(j17).not.toContain(s17);
    expect(j17).toContain(`${s16}…`);
  });
});

describe('httpSink timer handling', () => {
  afterEach(() => vi.useRealTimers());
  const ev = [{ format: 'ecs' as const, line: 'a' }];
  it.each([
    [0, 10_000],
    [-5, 10_000],
    [Number.NaN, 10_000],
    [Number.POSITIVE_INFINITY, 10_000],
    [1, 1],
    [50, 50],
  ])('timeoutMs %s arms a %s ms timer and clears it after delivery', async (timeoutMs, delay) => {
    vi.useFakeTimers();
    const spy = vi.spyOn(globalThis, 'setTimeout');
    const r = await httpSink('https://h/x', { format: 'ecs', timeoutMs, fetch: async () => ({ ok: true, status: 200 }) }).deliver(ev);
    expect(r).toEqual({ ok: true });
    expect(spy.mock.calls.map((c) => c[1])).toEqual([delay]);
    expect(vi.getTimerCount()).toBe(0);
  });
  it('the timer fires: result is a timeout and the request is aborted', async () => {
    vi.useFakeTimers();
    let signal: AbortSignal | undefined;
    const fetch = (_u: string, init: { signal?: AbortSignal }) => {
      signal = init.signal;
      return new Promise<never>(() => {});
    };
    const p = httpSink('https://h/x', { format: 'ecs', timeoutMs: 100, fetch: fetch as never }).deliver(ev);
    await vi.advanceTimersByTimeAsync(99);
    expect(signal?.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(await p).toEqual({ ok: false, error: 'delivery timed out' });
    expect(signal?.aborted).toBe(true);
  });
});

describe('exportBatch skipped count on a failed delivery', () => {
  it('reports skipped alongside the delivery error, and omits it when nothing was skipped', async () => {
    const sink: SiemSink = { name: 's', format: 'cef', deliver: () => ({ ok: false, error: 'boom' }) };
    const bad = await exportBatch([rec('s'), null as never], sink);
    expect(bad).toEqual({ ok: false, delivered: 0, format: 'cef', error: 'boom', skipped: 1 });
    const clean = await exportBatch([rec('s')], sink);
    expect(clean).toEqual({ ok: false, delivered: 0, format: 'cef', error: 'boom' });
  });
});

import { describe, expect, it } from 'vitest';
import { SignJWT, importJWK } from 'jose';
import { agent, b64u, generateKeyPair } from '@atlasauth/pca';
import {
  MAX_TOKEN_CHARS,
  TXN_TOKEN_TYP_DRAFT_11,
  TxnTokenError,
  fromTransactionToken,
  toTransactionToken,
  type FromTransactionTokenOptions,
} from './index';

const TD = 'trust-domain.example';
const NOW = 1_686_536_300;
const tts = generateKeyPair();
const chain = () => agent({ principal: generateKeyPair(), goal: 'g', permissions: { stripe: ['refund'] }, limits: { refund: '$5' }, aud: TD }).subAgent().chain;

async function forge(claims: Record<string, unknown>, header: Record<string, unknown> = { alg: 'EdDSA', typ: TXN_TOKEN_TYP_DRAFT_11 }) {
  const key = await importJWK({ kty: 'OKP', crv: 'Ed25519', x: b64u(tts.publicKey), d: b64u(tts.secretKey) }, 'EdDSA');
  return new SignJWT(claims).setProtectedHeader(header as never).sign(key);
}
const d11 = (over: Record<string, unknown> = {}) => ({
  iat: 1686536226, aud: TD, exp: 1686536586, txn: '97053963-771d-49cc-a4e3-20aad399c312', sub: 'd084sdrt234fsaw34tr23t',
  req_wl: 'apigateway.trust-domain.example', scope: 'trade.stocks', tctx: { action: 'BUY', ticker: 'MSFT', quantity: '100' }, ...over,
});
const opts = (more: FromTransactionTokenOptions = {}): FromTransactionTokenOptions => ({ audience: TD, now: new Date(NOW * 1000), replayCheck: 'unchecked', ...more });

type Settled = { ok: true; value: unknown } | { ok: false; name: string; message: string; code?: unknown };
async function settle(p: Promise<unknown>): Promise<Settled> {
  try {
    return { ok: true, value: await p };
  } catch (e) {
    const err = e as Error & { code?: unknown };
    return { ok: false, name: err.name, message: err.message, ...(err.code !== undefined ? { code: err.code } : {}) };
  }
}
const refused = (message: string, name?: string) => ({ ok: false, name: name ?? expect.any(String), message });

describe('draft-11 free-form tctx (Figure 4 shape)', () => {
  it('a free-form tctx is returned verbatim, with no PCA action', async () => {
    const tctx = { action: 'BUY', ticker: 'MSFT', quantity: '100', customer_type: { geo: 'US', level: 'VIP' } };
    const rctx = { authn: 'face', device: 'kiosk' };
    const r = await fromTransactionToken(await forge(d11({ tctx, rctx })), tts.publicKey, opts());
    expect(r.tctx).toEqual(tctx);
    expect(r.action).toBeUndefined();
    expect(r.claims.rctx).toEqual(rctx);
    expect(r.chain).toEqual({ sub: 'd084sdrt234fsaw34tr23t' });
  });
  it('an empty tctx object is a valid free-form context', async () => {
    const r = await fromTransactionToken(await forge(d11({ tctx: {} })), tts.publicKey, opts());
    expect(r.tctx).toEqual({});
    expect(r.action).toBeUndefined();
  });
  it('a tctx carrying the three PCA keys yields the action and keeps extra members in tctx', async () => {
    const tctx = { verb: 'stripe.refund', resource: 'charge:1', aud: TD, extra: { n: 1 } };
    const r = await fromTransactionToken(await forge(d11({ tctx })), tts.publicKey, opts());
    expect(r.action).toEqual({ verb: 'stripe.refund', resource: 'charge:1', aud: TD });
    expect(r.tctx).toEqual(tctx);
  });
  it('the PCA keys are reserved: any of them present must all be strings', async () => {
    const msg = 'transaction token: missing or malformed `tctx`';
    for (const tctx of [{ verb: 'v' }, { resource: 'r' }, { aud: 'a' }, { verb: 'v', resource: 'r' }, { verb: 1, resource: 'r', aud: 'a' }, { verb: 'v', resource: null, aud: 'a' }, { verb: 'v', resource: 'r', aud: ['a'] }]) {
      expect(await settle(fromTransactionToken(await forge(d11({ tctx })), tts.publicKey, opts()))).toEqual(refused(msg));
    }
  });
  it('a tctx that is not a JSON object is refused (missing, null, string, number, boolean, array)', async () => {
    const msg = 'transaction token: missing or malformed `tctx`';
    for (const tctx of [undefined, null, 'BUY', 7, true, [], [{ action: 'BUY' }]]) {
      expect(await settle(fromTransactionToken(await forge(d11({ tctx })), tts.publicKey, opts()))).toEqual(refused(msg));
    }
  });
  it('an rctx that is not a JSON object is refused; an object rctx is accepted', async () => {
    for (const rctx of [null, 'x', 5, true, []]) {
      expect(await settle(fromTransactionToken(await forge(d11({ rctx })), tts.publicKey, opts()))).toEqual(refused('transaction token: malformed `rctx`'));
    }
    expect((await settle(fromTransactionToken(await forge(d11({ rctx: {} })), tts.publicKey, opts()))).ok).toBe(true);
  });
  it('the legacy profile still requires the PCA action and does not read rctx', async () => {
    const legacy = (tctx: unknown) => forge({ sub: 'P', exp: NOW + 60, tctx, rctx: 'free text' }, { alg: 'EdDSA', typ: 'txn_token+jwt' });
    const o: FromTransactionTokenOptions = { profile: 'legacy', now: new Date(NOW * 1000), replayCheck: 'unchecked' };
    expect(await settle(fromTransactionToken(await legacy({ action: 'BUY' }), tts.publicKey, o))).toEqual(refused('transaction token: missing or malformed `tctx`'));
    const ok = await fromTransactionToken(await legacy({ verb: 'v', resource: 'r', aud: 'a' }), tts.publicKey, o);
    expect(ok.action).toEqual({ verb: 'v', resource: 'r', aud: 'a' });
  });
});

describe('replay store is required by default', () => {
  it('no seenTxn and no explicit opt-out throws the typed error before anything else is read', async () => {
    const jwt = await forge(d11());
    const r = await settle(fromTransactionToken(jwt, tts.publicKey, { audience: TD, now: new Date(NOW * 1000) }));
    expect(r).toEqual({
      ok: false,
      name: 'TxnTokenError',
      message: "fromTransactionToken: supply opts.seenTxn (a replay store) or set opts.replayCheck to 'unchecked'",
      code: 'replay_store_required',
    });
    const direct = await fromTransactionToken(jwt, tts.publicKey, { audience: TD }).catch((e: unknown) => e);
    expect(direct).toBeInstanceOf(TxnTokenError);
    // even a garbage token string is refused for the missing store first
    expect((await settle(fromTransactionToken('not a token', tts.publicKey, { audience: TD }))).ok).toBe(false);
    expect(await fromTransactionToken('not a token', tts.publicKey, { audience: TD }).catch((e: Error) => e.name)).toBe('TxnTokenError');
  });
  it('only the literal opt-out value disables the requirement', async () => {
    const jwt = await forge(d11());
    for (const replayCheck of ['none', 'skip', true, ''] as unknown[]) {
      const r = await settle(fromTransactionToken(jwt, tts.publicKey, { audience: TD, now: new Date(NOW * 1000), replayCheck } as never));
      expect(r.ok).toBe(false);
    }
    expect((await settle(fromTransactionToken(jwt, tts.publicKey, opts()))).ok).toBe(true);
  });
  it('a supplied seenTxn satisfies the requirement and a non-function does not', async () => {
    const jwt = await forge(d11());
    expect((await settle(fromTransactionToken(jwt, tts.publicKey, { audience: TD, now: new Date(NOW * 1000), seenTxn: () => false }))).ok).toBe(true);
    const bad = await settle(fromTransactionToken(jwt, tts.publicKey, { audience: TD, now: new Date(NOW * 1000), seenTxn: 'yes' as never }));
    expect(bad).toMatchObject({ ok: false, name: 'TxnTokenError', code: 'replay_store_required' });
  });
  it('the identifier is consumed last: a token refused for any other reason never burns its txn', async () => {
    const seen: string[] = [];
    const seenTxn = (id: string) => { seen.push(id); return false; };
    for (const over of [{ tctx: 'x' }, { sub: '' }, { act: 'x' }, { rctx: [] }]) {
      expect((await settle(fromTransactionToken(await forge(d11(over)), tts.publicKey, opts({ seenTxn })))).ok).toBe(false);
    }
    expect(seen).toEqual([]);
    expect((await settle(fromTransactionToken(await forge(d11()), tts.publicKey, opts({ seenTxn })))).ok).toBe(true);
    expect(seen).toEqual(['97053963-771d-49cc-a4e3-20aad399c312']);
  });
});

describe('draft-11 is the default profile', () => {
  it('verification with no profile reads the draft typ and requires the audience', async () => {
    expect((await settle(fromTransactionToken(await forge(d11()), tts.publicKey, opts()))).ok).toBe(true);
    expect(await settle(fromTransactionToken(await forge(d11(), { alg: 'EdDSA', typ: 'txn_token+jwt' }), tts.publicKey, opts()))).toEqual(refused('unexpected "typ" JWT header value'));
    expect(await settle(fromTransactionToken(await forge(d11()), tts.publicKey, { replayCheck: 'unchecked' }))).toEqual(
      refused('fromTransactionToken: draft-11 requires opts.audience (the trust domain this verifier serves)', 'TypeError'),
    );
  });
  it('minting with no profile emits the draft header and demands scope and reqWl', async () => {
    const base = { chain: chain(), action: { verb: 'v', resource: 'r', aud: TD }, issuerKey: tts.secretKey, issuer: 'iss' };
    expect(await settle(toTransactionToken(base))).toEqual(refused('toTransactionToken: draft-11 requires `scope`', 'TypeError'));
    const jwt = await toTransactionToken({ ...base, scope: 's', reqWl: 'w' });
    expect(JSON.parse(Buffer.from(jwt.split('.')[0]!, 'base64url').toString())).toEqual({ alg: 'EdDSA', typ: 'txntoken+jwt' });
    const lg = await toTransactionToken({ ...base, profile: 'legacy' });
    expect(JSON.parse(Buffer.from(lg.split('.')[0]!, 'base64url').toString())).toEqual({ alg: 'EdDSA', typ: 'txn_token+jwt' });
  });
});

describe('size limit', () => {
  it('a token string over MAX_TOKEN_CHARS is refused before any parsing; at the limit it reaches the next gate', async () => {
    expect(MAX_TOKEN_CHARS).toBe(16384);
    expect(await settle(fromTransactionToken('a'.repeat(MAX_TOKEN_CHARS + 1), tts.publicKey, opts()))).toEqual(refused('transaction token: token exceeds the size limit'));
    const atLimit = await settle(fromTransactionToken('a'.repeat(MAX_TOKEN_CHARS), tts.publicKey, opts()));
    expect(atLimit.ok).toBe(false);
    expect((atLimit as { message: string }).message).not.toBe('transaction token: token exceeds the size limit');
  });
  it('a validly signed oversize token is refused', async () => {
    const jwt = await forge(d11({ tctx: { blob: 'x'.repeat(MAX_TOKEN_CHARS) } }));
    expect(jwt.length).toBeGreaterThan(MAX_TOKEN_CHARS);
    expect(await settle(fromTransactionToken(jwt, tts.publicKey, opts()))).toEqual(refused('transaction token: token exceeds the size limit'));
  });
});

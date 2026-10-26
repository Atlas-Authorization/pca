import { describe, expect, it } from 'vitest';
import { SignJWT, generateKeyPair as joseKeyPair, importJWK } from 'jose';
import { agent, b64u, generateKeyPair } from '@atlasauth/pca';
import {
  TXN_TOKEN_TYP_DRAFT_11,
  actDepth,
  fromTransactionToken,
  subActChain,
  toRfc8693Act,
  toTransactionToken,
  type FromTransactionTokenOptions,
  type TxnAction,
} from './index';

const TD = 'trust-domain.example';
const ACTION: TxnAction = { verb: 'stripe.refund', resource: 'charge:ch_1', aud: TD };
const tts = generateKeyPair();

async function seedKey() {
  return importJWK({ kty: 'OKP', crv: 'Ed25519', x: b64u(tts.publicKey), d: b64u(tts.secretKey) }, 'EdDSA');
}
const chain = () => agent({ principal: generateKeyPair(), goal: 'g', permissions: { stripe: ['refund'] }, limits: { refund: '$5' }, aud: TD }).subAgent().chain;

/** Settle to a plain value so every row asserts the whole outcome. */
async function settle(p: Promise<unknown>): Promise<{ ok: true } | { ok: false; message: string }> {
  try {
    await p;
    return { ok: true };
  } catch (e) {
    return { ok: false, message: (e as Error).message };
  }
}
const fail = (message: string) => ({ ok: false, message });

/** Sign arbitrary claims/header with the TTS key (to forge off-profile tokens). */
async function forge(claims: Record<string, unknown>, header: Record<string, unknown> = { alg: 'EdDSA', typ: TXN_TOKEN_TYP_DRAFT_11 }, key?: Awaited<ReturnType<typeof seedKey>>) {
  return new SignJWT(claims).setProtectedHeader(header as never).sign(key ?? (await seedKey()));
}
const NOW = 1_686_536_300;
const d11 = (over: Record<string, unknown> = {}) => ({
  iat: 1686536226, aud: TD, exp: 1686536586, txn: '97053963-771d-49cc-a4e3-20aad399c312', sub: 'd084sdrt234fsaw34tr23t',
  req_wl: 'apigateway.trust-domain.example', scope: 'trade.stocks', tctx: { verb: 'v', resource: 'r', aud: TD }, ...over,
});
const strict = (more: FromTransactionTokenOptions = {}): FromTransactionTokenOptions => ({ profile: 'draft-11', audience: TD, now: new Date(NOW * 1000), ...more });
const verify = (jwt: string, more: FromTransactionTokenOptions = {}) => settle(fromTransactionToken(jwt, tts.publicKey, strict(more)));

describe('draft-11 profile: mint', () => {
  it('emits typ txntoken+jwt with the required claims and no jti', async () => {
    const jwt = await toTransactionToken({ chain: chain(), action: ACTION, issuerKey: tts.secretKey, issuer: 'https://tts.example', profile: 'draft-11', scope: 'refund', reqWl: 'gw.example', txn: 'tx-1' });
    const [h, p] = jwt.split('.').slice(0, 2).map((x) => JSON.parse(Buffer.from(x, 'base64url').toString()));
    expect(h).toEqual({ alg: 'EdDSA', typ: 'txntoken+jwt' });
    expect(Object.keys(p).sort()).toEqual(['act', 'aud', 'exp', 'iat', 'iss', 'req_wl', 'scope', 'sub', 'tctx', 'txn']);
    expect(p).toMatchObject({ aud: TD, txn: 'tx-1', scope: 'refund', req_wl: 'gw.example', tctx: ACTION });
    expect(p.exp - p.iat).toBe(120);
    const r = await fromTransactionToken(jwt, tts.publicKey, { profile: 'draft-11', audience: TD });
    expect(r.action).toEqual(ACTION);
    // trustDomain overrides aud; the action audience stays in tctx
    const j2 = await toTransactionToken({ chain: chain(), action: ACTION, issuerKey: tts.secretKey, issuer: 'i', profile: 'draft-11', scope: 's', reqWl: 'w', trustDomain: 'td2.example' });
    expect(JSON.parse(Buffer.from(j2.split('.')[1]!, 'base64url').toString()).aud).toBe('td2.example');
  });
  it('rows', async () => {
    const base = { chain: chain(), action: ACTION, issuerKey: tts.secretKey, issuer: 'i', profile: 'draft-11' as const };
    expect(await settle(toTransactionToken({ ...base, reqWl: 'w' }))).toEqual(fail('toTransactionToken: draft-11 requires `scope`'));
    expect(await settle(toTransactionToken({ ...base, scope: '', reqWl: 'w' }))).toEqual(fail('toTransactionToken: draft-11 requires `scope`'));
    expect(await settle(toTransactionToken({ ...base, scope: 's' }))).toEqual(fail('toTransactionToken: draft-11 requires `reqWl`'));
    expect(await settle(toTransactionToken({ ...base, scope: 's', reqWl: 'w', trustDomain: '' }))).toEqual(fail('toTransactionToken: draft-11 requires a non-empty trust domain (aud)'));
    expect(await settle(toTransactionToken({ ...base, profile: 'draft-99' as never, scope: 's', reqWl: 'w' }))).toEqual(fail('toTransactionToken: profile must be legacy or draft-11'));
  });
  it('the unique txn is generated when not given', async () => {
    const mk = () => toTransactionToken({ chain: chain(), action: ACTION, issuerKey: tts.secretKey, issuer: 'i', profile: 'draft-11', scope: 's', reqWl: 'w' });
    const [a, b] = await Promise.all([mk(), mk()]);
    const txn = (j: string) => JSON.parse(Buffer.from(j.split('.')[1]!, 'base64url').toString()).txn as string;
    expect(txn(a)).toMatch(/^[0-9a-f-]{36}$/);
    expect(txn(a)).not.toBe(txn(b));
  });
});

describe('draft-11 profile: verify rows (whole outcome)', () => {
  it('the draft Figure 3/4 header and payload (with the PCA tctx) verify', async () => {
    expect(await verify(await forge(d11()))).toEqual({ ok: true });
  });
  it('the draft Figure 4 payload with its own free-form tctx is refused by the PCA profile', async () => {
    const figure4 = d11({ tctx: { action: 'BUY', ticker: 'MSFT', quantity: '100', customer_type: { geo: 'US', level: 'VIP' } }, rctx: { req_ip: '69.151.72.123', authn: 'face' } });
    expect(await verify(await forge(figure4))).toEqual(fail('transaction token: missing or malformed `tctx`'));
  });
  it('required claims: each one missing is refused', async () => {
    for (const k of ['iat', 'aud', 'exp', 'txn', 'sub', 'scope', 'req_wl']) {
      const claims: Record<string, unknown> = d11();
      delete claims[k];
      const r = await verify(await forge(claims));
      expect(r).toEqual(fail(`missing required "${k}" claim`));
    }
  });
  it('empty or non-string txn / scope / req_wl are refused', async () => {
    for (const k of ['txn', 'scope', 'req_wl']) {
      for (const v of ['', 7]) {
        expect(await verify(await forge(d11({ [k]: v })))).toEqual(fail(`transaction token: \`${k}\` must be a non-empty string`));
      }
    }
  });
  it('audience: a different trust domain, or the option omitted', async () => {
    expect(await verify(await forge(d11({ aud: 'other.example' })))).toEqual(fail('unexpected "aud" claim value'));
    expect(await verify(await forge(d11()), { audience: 'other.example' })).toEqual(fail('unexpected "aud" claim value'));
    expect(await settle(fromTransactionToken(await forge(d11()), tts.publicKey, { profile: 'draft-11' }))).toEqual(
      fail('fromTransactionToken: draft-11 requires opts.audience (the trust domain this verifier serves)'),
    );
    expect(await verify(await forge(d11({ aud: [TD, 'other.example'] })))).toEqual({ ok: true });
  });
  it('time: expired, not yet valid, tolerance', async () => {
    expect(await verify(await forge(d11()), { now: new Date((1686536586 + 1) * 1000) })).toEqual(fail('"exp" claim timestamp check failed'));
    expect(await verify(await forge(d11({ nbf: NOW + 100 })))).toEqual(fail('"nbf" claim timestamp check failed'));
    expect(await verify(await forge(d11()), { now: new Date((1686536586 + 5) * 1000), clockToleranceSec: 10 })).toEqual({ ok: true });
  });
  it('header typ: legacy typ, JWT and none are refused; each profile refuses the other', async () => {
    expect(await verify(await forge(d11(), { alg: 'EdDSA', typ: 'txn_token+jwt' }))).toEqual(fail('unexpected "typ" JWT header value'));
    expect(await verify(await forge(d11(), { alg: 'EdDSA', typ: 'JWT' }))).toEqual(fail('unexpected "typ" JWT header value'));
    expect(await verify(await forge(d11(), { alg: 'EdDSA' }))).toEqual(fail('unexpected "typ" JWT header value'));
    const legacy = await toTransactionToken({ chain: chain(), action: ACTION, issuerKey: tts.secretKey, issuer: 'i' });
    expect(await settle(fromTransactionToken(legacy, tts.publicKey, strict()))).toEqual(fail('unexpected "typ" JWT header value'));
    const draft = await toTransactionToken({ chain: chain(), action: ACTION, issuerKey: tts.secretKey, issuer: 'i', profile: 'draft-11', scope: 's', reqWl: 'w' });
    expect(await settle(fromTransactionToken(draft, tts.publicKey))).toEqual(fail('unexpected "typ" JWT header value'));
  });
  it('signature: tampered payload and wrong key', async () => {
    const jwt = await forge(d11());
    const [h, , s] = jwt.split('.');
    const p = Buffer.from(JSON.stringify(d11({ scope: 'admin' }))).toString('base64url');
    expect(await verify(`${h}.${p}.${s}`)).toEqual(fail('signature verification failed'));
    expect(await settle(fromTransactionToken(jwt, generateKeyPair().publicKey, strict()))).toEqual(fail('signature verification failed'));
  });
  it('replay hook: first sight passes, a repeat is refused, the hook sees txn and exp', async () => {
    const seen = new Set<string>();
    const calls: Array<[string, number]> = [];
    const seenTxn = (id: string, exp: number) => { calls.push([id, exp]); return seen.has(id) ? true : (seen.add(id), false); };
    const jwt = await forge(d11());
    expect(await verify(jwt, { seenTxn })).toEqual({ ok: true });
    expect(await verify(jwt, { seenTxn })).toEqual(fail('transaction token: replayed (transaction identifier already seen)'));
    expect(calls[0]).toEqual(['97053963-771d-49cc-a4e3-20aad399c312', 1686536586]);
    // an async hook that throws fails closed
    expect(await verify(jwt, { seenTxn: async () => { throw new Error('store down'); } })).toEqual(fail('store down'));
  });
  it('non-canonical spelling is refused before verification', async () => {
    const jwt = await forge(d11());
    expect((await verify(jwt + '=')).ok).toBe(false);
  });
});

describe('legacy profile hardening (additive)', () => {
  it('a token with no exp is refused; algorithms are pinned to EdDSA', async () => {
    const noExp = await forge({ sub: 'P', tctx: { verb: 'v', resource: 'r', aud: 'a' } }, { alg: 'EdDSA', typ: 'txn_token+jwt' });
    expect(await settle(fromTransactionToken(noExp, tts.publicKey))).toEqual(fail('missing required "exp" claim'));
    const ec = await joseKeyPair('ES256');
    const es = await new SignJWT({ sub: 'P', exp: Math.floor(Date.now() / 1000) + 60, tctx: { verb: 'v', resource: 'r', aud: 'a' } })
      .setProtectedHeader({ alg: 'ES256', typ: 'txn_token+jwt' })
      .sign(ec.privateKey);
    expect(await settle(fromTransactionToken(es, ec.publicKey))).toEqual(fail('"alg" (Algorithm) Header Parameter value not allowed'));
  });
  it('opts.audience and the replay hook (jti) work in legacy mode too', async () => {
    const jwt = await toTransactionToken({ chain: chain(), action: ACTION, issuerKey: tts.secretKey, issuer: 'i' });
    expect(await settle(fromTransactionToken(jwt, tts.publicKey, { audience: 'nope' }))).toEqual(fail('unexpected "aud" claim value'));
    expect(await settle(fromTransactionToken(jwt, tts.publicKey, { audience: TD }))).toEqual({ ok: true });
    const seen = new Set<string>();
    const seenTxn = (id: string) => (seen.has(id) ? true : (seen.add(id), false));
    expect(await settle(fromTransactionToken(jwt, tts.publicKey, { seenTxn }))).toEqual({ ok: true });
    expect(await settle(fromTransactionToken(jwt, tts.publicKey, { seenTxn }))).toEqual(fail('transaction token: replayed (transaction identifier already seen)'));
    const noJti = await forge({ sub: 'P', exp: Math.floor(Date.now() / 1000) + 60, tctx: { verb: 'v', resource: 'r', aud: 'a' } }, { alg: 'EdDSA', typ: 'txn_token+jwt' });
    expect(await settle(fromTransactionToken(noJti, tts.publicKey, { seenTxn }))).toEqual(fail('transaction token: no transaction identifier to check for replay'));
    expect(await settle(fromTransactionToken(jwt, tts.publicKey, { profile: 'x' as never }))).toEqual(fail('fromTransactionToken: profile must be legacy or draft-11'));
  });
});

describe('RFC 8693 chains', () => {
  // RFC 8693 section 4.1 nested actor example: the most recent actor is outermost.
  const RFC_ACT = { sub: 'https://service16.example.com', act: { sub: 'https://service77.example.com' } };
  it('a token carrying the RFC nested act round-trips unchanged', async () => {
    const jwt = await forge({ ...d11(), sub: 'user@example.com', act: RFC_ACT });
    const r = await fromTransactionToken(jwt, tts.publicKey, strict());
    expect(r.chain).toEqual({ sub: 'user@example.com', act: RFC_ACT });
    expect(actDepth(r.chain)).toBe(2);
  });
  it('toRfc8693Act reverses this profile order (root holder outermost) into the RFC order (latest outermost)', () => {
    const ours = { sub: 'P', act: { sub: 'h0', act: { sub: 'h1', act: { sub: 'h2' } } } };
    expect(toRfc8693Act(ours)).toEqual({ sub: 'P', act: { sub: 'h2', act: { sub: 'h1', act: { sub: 'h0' } } } });
    expect(toRfc8693Act({ sub: 'P' })).toEqual({ sub: 'P' });
    expect(toRfc8693Act(toRfc8693Act(ours))).toEqual(ours);
    const c = chain();
    const out = toRfc8693Act(subActChain(c));
    expect(out.act?.sub).toBe(c[c.length - 1]!.holder);
  });
  it('malformed act in a verified token is refused', async () => {
    for (const act of [null, 'x', [], { sub: '' }, { sub: 'a', act: { sub: 5 } }]) {
      expect((await verify(await forge(d11({ act })))).ok).toBe(false);
    }
  });
});

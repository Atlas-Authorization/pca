import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import { buildKeyDirectory, jwkThumbprint, signRequest } from '@atlasauth/pca-webbotauth';
import { absoluteUrl, pcaSiteExpress, pcaSiteFastify, pcaSiteHono, withSite, withSiteRoute, type SiteDecision } from './index';

const key = generateKeyPair();
const keyid = jwkThumbprint(key.publicKey);
const opts = {
  audience: 'ins_shop',
  policy: { tiers: { 'cat.list': { tier: 1 }, 'site.page': { tier: 0 } }, web_bot_auth: { accept: true } },
  verbOf: (r: { url: string }) => (new URL(r.url).pathname === '/catalog' ? 'cat.list' : new URL(r.url).pathname === '/' ? 'site.page' : null),
  webBotAuth: { jwks: buildKeyDirectory([{ publicKey: key.publicKey, keyid }]) },
};
const URL_CAT = 'https://shop.example/catalog';
const signed = () => signRequest({ method: 'GET', url: URL_CAT, key, keyid }).headers;
const lower = (h: Record<string, string>) => Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), v]));

function fakeExpressRes() {
  const r = { code: 0, headers: {} as Record<string, string>, body: undefined as unknown,
    status(c: number) { r.code = c; return r; }, set(k: string, v: string) { r.headers[k] = v; return r; }, json(b: unknown) { r.body = b; return b; } };
  return r;
}

describe('absoluteUrl', () => {
  it('rebuilds the client URL from Host + originalUrl, or uses publicOrigin', () => {
    expect(absoluteUrl({ headers: { host: 'shop.example' }, originalUrl: '/catalog?x=1', protocol: 'https' })).toBe('https://shop.example/catalog?x=1');
    expect(absoluteUrl({ headers: { host: 'internal:8080' }, url: '/catalog' }, 'https://shop.example')).toBe('https://shop.example/catalog');
    expect(() => absoluteUrl({ headers: {}, url: '/' })).toThrow(/publicOrigin/);
  });
});

describe('Express adapter', () => {
  it('allows a signed request and attaches the decision', async () => {
    const mw = pcaSiteExpress(opts);
    const req: Record<string, unknown> & { headers: Record<string, string> } = { method: 'GET', headers: { host: 'shop.example', ...lower(signed()) }, originalUrl: '/catalog', protocol: 'https' };
    let nexted = false;
    await mw(req, fakeExpressRes(), () => { nexted = true; });
    expect(nexted).toBe(true);
    expect((req.pcaSite as SiteDecision).presentedTier).toBe(1);
  });
  it('answers the problem with status and headers', async () => {
    const mw = pcaSiteExpress(opts);
    const res = fakeExpressRes();
    await mw({ method: 'GET', headers: { host: 'shop.example' }, originalUrl: '/catalog' }, res, () => { throw new Error('must not run'); });
    expect(res.code).toBe(401);
    expect(res.headers['WWW-Authenticate']).toMatch(/insufficient_tier/);
    expect(res.headers['Content-Type']).toBe('application/problem+json');
  });
});

describe('Fastify adapter', () => {
  it('passes or replies', async () => {
    const hook = pcaSiteFastify({ ...opts, publicOrigin: 'https://shop.example' });
    const reply = { c: 0, h: {} as Record<string, string>, b: undefined as unknown,
      code(n: number) { reply.c = n; return reply; }, header(k: string, v: string) { reply.h[k] = v; return reply; }, send(b: unknown) { reply.b = b; return b; } };
    const ok: Record<string, unknown> & { headers: Record<string, string> } = { method: 'GET', url: '/catalog', headers: lower(signed()) };
    await hook(ok, reply);
    expect(reply.c).toBe(0);
    expect((ok.pcaSite as SiteDecision).allow).toBe(true);
    await hook({ method: 'GET', url: '/catalog', headers: {} }, reply);
    expect(reply.c).toBe(401);
  });
});

describe('web adapters (Fetch, Next.js, Hono)', () => {
  it('withSite runs the handler only when allowed', async () => {
    const h = withSite(opts, async (_req, { pcaSite }) => new Response(String(pcaSite.presentedTier)));
    expect(await (await h(new Request(URL_CAT, { headers: signed() }))).text()).toBe('1');
    const denied = await h(new Request(URL_CAT));
    expect(denied.status).toBe(401);
    expect(denied.headers.get('content-type')).toBe('application/problem+json');
    expect(denied.headers.get('www-authenticate')).toMatch(/insufficient_tier/);
  });
  it('withSiteRoute supports onDeny', async () => {
    const h = withSiteRoute({ ...opts, onDeny: (d) => new Response('nope', { status: d.status }) }, async () => new Response('ok'));
    expect((await h(new Request(URL_CAT))).status).toBe(401);
    expect(await (await h(new Request('https://shop.example/'))).text()).toBe('ok');
  });
  it('Hono middleware sets the decision and short-circuits a deny', async () => {
    const mw = pcaSiteHono(opts);
    const store: Record<string, unknown> = {};
    let nexted = false;
    const c = (req: Request) => ({ req: { raw: req }, set: (k: string, v: unknown) => void (store[k] = v) });
    expect(await mw(c(new Request(URL_CAT, { headers: signed() })), async () => { nexted = true; })).toBeUndefined();
    expect(nexted).toBe(true);
    expect((store.pcaSite as SiteDecision).allow).toBe(true);
    const r = await mw(c(new Request(URL_CAT)), async () => { throw new Error('must not run'); });
    expect((r as Response).status).toBe(401);
  });
});

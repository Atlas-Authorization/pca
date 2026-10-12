/** Mutation-kill tests for Web Bot Auth: independent RFC 9421 known answers (forged signatures), parser reasons, freshness boundaries, resolver and replay paths. */
import { sign as nodeSign, createHash, createPrivateKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair, type PCActn } from '@atlasauth/pca';
import {
  DIRECTORY_CONTENT_TYPE,
  PCA_HEADER,
  WELL_KNOWN_DIRECTORY_PATH,
  buildKeyDirectory,
  decodeProofHeader,
  directoryHandler,
  jwkThumbprint,
  memoryReplayCache,
  resolveFromDirectory,
  signRequest,
  signRequestWithProof,
  verifySignedRequest,
  verifySignedRequestWithProof,
  type ReplayCache,
  type VerifyOptions,
} from './index';

const kp = generateKeyPair();
const KID = 'k1';
const NOW = 1_800_000_000;
const URL1 = 'https://example.com/a/b';
const resolveKey = (id: string) => (id === KID ? kp.publicKey : null);
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64');
const b64url = (u: Uint8Array) => Buffer.from(u).toString('base64url');

function rawSign(base: string): string {
  const jwk = { kty: 'OKP', crv: 'Ed25519', x: b64url(kp.publicKey), d: b64url(kp.secretKey) };
  return b64(nodeSign(null, Buffer.from(base), createPrivateKey({ key: jwk, format: 'jwk' })));
}

const STD = ['"@authority": example.com', '"@method": GET', '"@path": /a/b'];
const STD_LIST = '("@authority" "@method" "@path")';
const GOOD_TAIL = `;created=${NOW};keyid="${KID}";alg="ed25519";expires=${NOW + 100};tag="web-bot-auth"`;

/** Sign an arbitrary signature-params string over explicitly listed base lines (independent of the library's base builder). */
type SigHeaders = { 'signature-input': string; signature: string };
function forge(paramsRaw: string, lines: string[] = STD, label = 'sig1'): SigHeaders {
  const sig = rawSign([...lines, `"@signature-params": ${paramsRaw.trim()}`].join('\n'));
  return { 'signature-input': `${label}=${paramsRaw}`, signature: `${label}=:${sig}:` };
}
const forged = (tail = GOOD_TAIL, list = STD_LIST, lines = STD) => forge(`${list}${tail}`, lines);

const vr = (headers: Record<string, string>, opts: Partial<VerifyOptions> = {}, url = URL1, method = 'GET') =>
  verifySignedRequest({ method, url, headers }, { resolveKey, now: NOW, ...opts });
const reason = async (headers: Record<string, string>, opts: Partial<VerifyOptions> = {}, url = URL1, method = 'GET') => {
  const r = await vr(headers, opts, url, method);
  expect(r.valid).toBe(false);
  return r.reason;
};
const sign = (over: Partial<Parameters<typeof signRequest>[0]> = {}) =>
  signRequest({ method: 'GET', url: URL1, key: kp, keyid: KID, created: NOW, ...over });

describe('memoryReplayCache', () => {
  it('claims once per key until the expiry (inclusive), then again', () => {
    const c = memoryReplayCache();
    expect(c.claim('a', 10, 5)).toBe(true);
    expect(c.claim('a', 10, 5)).toBe(false);
    expect(c.claim('a', 10, 10)).toBe(false); // existing >= now: still claimed at the boundary
    expect(c.claim('a', 20, 11)).toBe(true); // expired: claimable again
    expect(c.claim('b', 10, 5)).toBe(true);
  });
  it('is bounded: throws when full, prunes only strictly expired claims', () => {
    const one = memoryReplayCache(1);
    expect(one.claim('a', 10, 5)).toBe(true);
    expect(() => one.claim('b', 10, 5)).toThrow('replay cache full');
    const c = memoryReplayCache(2);
    expect(c.claim('a', 5, 3)).toBe(true);
    expect(c.claim('b', 20, 3)).toBe(true); // size 1 < 2: no pruning, no throw
    expect(() => c.claim('c', 30, 5)).toThrow('replay cache full'); // a expires AT 5: not yet pruned
    const d = memoryReplayCache(3);
    expect(d.claim('a', 5, 3)).toBe(true);
    expect(d.claim('b', 20, 3)).toBe(true);
    expect(d.claim('c', 30, 3)).toBe(true);
    expect(d.claim('d', 40, 6)).toBe(true); // only a (5 < 6) was pruned
    expect(() => d.claim('e', 50, 6)).toThrow('replay cache full'); // b, c, d are all live
  });
});

describe('memoryReplayCache with a non-monotonic clock', () => {
  it('does not forget a claim just because a later call saw a later time (pruning happens only when full)', () => {
    const c = memoryReplayCache(5);
    expect(c.claim('a', 5, 3)).toBe(true);
    expect(c.claim('b', 9, 10)).toBe(true);
    expect(c.claim('a', 9, 3)).toBe(false);
  });
});

describe('sf-string serialisation and top-level splitting', () => {
  it('round-trips awkward keyids and nonces through signRequest and verifySignedRequest', async () => {
    for (const odd of ['a,b', 'a;b', 'a b', 'a(b', 'a)b', 'q"r,s;t u(v)w', 'tail\\', 'x\\"y', 'a=b']) {
      const seen: string[] = [];
      const s = sign({ keyid: odd, nonce: odd });
      expect(s.signatureInput).toContain(`keyid="${odd.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`);
      const r = await verifySignedRequest(
        { method: 'GET', url: URL1, headers: s.headers },
        { resolveKey: (k) => (seen.push(k), kp.publicKey), now: NOW },
      );
      expect(seen).toEqual([odd]);
      expect(r).toMatchObject({ valid: true, keyid: odd, nonce: odd });
    }
  });
  it('splits Signature-Input members at top-level commas only (nested parentheses respected)', async () => {
    expect(await reason(forge(`((x),y)${GOOD_TAIL}`, STD))).toBe('verification failed (fail closed): expected a quoted string');
    expect(await reason(forge(`(("@authority")${GOOD_TAIL}`, STD))).toBe('verification failed (fail closed): unterminated inner list');
    expect(await reason(forge(`("@authority",)${GOOD_TAIL}`, STD))).toBe('verification failed (fail closed): unsupported component parameters on "@authority"');
    // a stray ")" in one member's parameters must not swallow the next member
    const a = forge(`${STD_LIST}${GOOD_TAIL};zz=1)`, STD, 'sig1');
    const b = forge(`${STD_LIST}${GOOD_TAIL}`, STD, 'sig2');
    const h = { 'signature-input': `${a['signature-input']}, ${b['signature-input']}`, signature: `${a.signature}, ${b.signature}` };
    expect(await vr(h, { label: 'sig2' })).toMatchObject({ valid: true, label: 'sig2' });
    expect(await vr(h, { label: 'sig1' })).toMatchObject({ valid: true, label: 'sig1' });
    // two well-formed members
    const c = { 'signature-input': `${b['signature-input'].replace('sig2', 'sigA')}, ${b['signature-input']}`, signature: `${b.signature.replace('sig2', 'sigA')}, ${b.signature}` };
    expect(await vr(c, { label: 'sig2' })).toMatchObject({ valid: true, label: 'sig2' });
    expect(await vr(c, { label: 'sigA' })).toMatchObject({ valid: true, label: 'sigA' });
  });
});

describe('Signature-Input / Signature grammar errors', () => {
  const ok = forged();
  it('malformed members and values', async () => {
    expect(await reason({ ...ok, 'signature-input': 'garbage' })).toBe('verification failed (fail closed): malformed Signature-Input member');
    expect(await reason({ ...ok, 'signature-input': 'sig1=5' })).toBe('verification failed (fail closed): Signature-Input value must be an inner list');
    expect(await reason({ ...ok, 'signature-input': 'sig1=("@authority"' })).toBe('verification failed (fail closed): unterminated inner list');
    expect(await reason({ ...ok, 'signature-input': 'sig1=(@authority)' })).toBe('verification failed (fail closed): expected a quoted string');
    expect(await reason({ ...ok, signature: 'garbage' })).toBe('verification failed (fail closed): malformed Signature member');
    for (const v of ['sig1=abc', 'sig1=:', 'sig1=:abc', 'sig1=abc:', 'sig1=']) {
      expect(await reason({ ...ok, signature: v })).toBe('verification failed (fail closed): Signature value must be a byte sequence (:base64:)');
    }
  });
  it('an empty byte sequence is a well-formed signature that fails to verify', async () => {
    expect(await reason({ ...ok, signature: 'sig1=::' })).toBe('signature does not verify under the resolved key');
  });
  it('tolerates whitespace around members, labels, values and empty members', async () => {
    const sig = ok.signature.slice('sig1='.length);
    const inp = ok['signature-input'].slice('sig1='.length);
    expect((await vr({ 'signature-input': `sig1= ${inp}`, signature: `sig1= ${sig}` })).valid).toBe(true);
    expect((await vr({ 'signature-input': `${ok['signature-input']}, `, signature: `${ok.signature} , ` })).valid).toBe(true);
    expect((await vr({ 'signature-input': `, ${ok['signature-input']},,`, signature: `,${ok.signature},, ` })).valid).toBe(true);
    expect((await vr({ 'signature-input': ` sig1 = ${inp}`, signature: ` sig1 = ${sig}` })).valid).toBe(true);
    expect((await vr({ 'signature-input': `sig1=${inp}`, signature: `sig1 = ${sig}` })).valid).toBe(true);
  });
  it('whitespace between components: blank chunks skipped, trailing chunk whitespace trimmed', async () => {
    const list = '("@authority" \t "@method"\t "@path")';
    expect((await vr(forge(`${list}${GOOD_TAIL}`, STD))).valid).toBe(true);
  });
  it('component parameters: only key= on header components, exactly', async () => {
    const hdr = { 'x-h': 'v' };
    const lines = (extra: string) => [...STD, extra];
    const bad = async (comp: string) => reason({ ...forge(`("@authority" "@method" "@path" ${comp})${GOOD_TAIL}`, lines(`${comp}: v`)), ...hdr });
    expect(await bad('"@method";key="a"')).toBe('verification failed (fail closed): unsupported component parameters on "@method"');
    expect(await bad('"x-h";sf')).toBe('verification failed (fail closed): unsupported component parameters on "x-h"');
    expect(await bad('"x-h"junk;key="a"')).toBe('verification failed (fail closed): unsupported component parameters on "x-h"');
    expect(await bad('"x-h";key="a"junk')).toBe('verification failed (fail closed): unsupported component parameters on "x-h"');
    expect(await bad('"x-h";key=a')).toBe('verification failed (fail closed): unsupported component parameters on "x-h"');
  });
});

describe('parameters', () => {
  const tailWith = (extra: string) => `;created=${NOW};keyid="${KID}";alg="ed25519";expires=${NOW + 100}${extra};tag="web-bot-auth"`;
  it('no parameters at all: reaches the keyid check (everything else relaxed)', async () => {
    const h = forge(STD_LIST);
    expect(await reason(h, { requireExpires: false, maxLifetimeSec: Infinity, requiredTag: null })).toBe('missing keyid parameter');
    expect(await reason(forge(`${STD_LIST} `), { requireExpires: false, maxLifetimeSec: Infinity, requiredTag: null })).toBe('missing keyid parameter');
  });
  it('parameters must start with ";"', async () => {
    expect(await reason(forge(`${STD_LIST}x${GOOD_TAIL}`))).toBe('verification failed (fail closed): expected parameters to start with ";"');
  });
  it('leading whitespace before the parameter list and around names/values is ignored', async () => {
    expect((await vr(forge(`${STD_LIST}  ${GOOD_TAIL}`))).valid).toBe(true);
    expect((await vr(forge(`${STD_LIST}${GOOD_TAIL.replace('created=', 'created = ').replace(';keyid', '; keyid')}`))).valid).toBe(true);
  });
  it('integer, decimal, token and boolean values', async () => {
    expect(await vr(forge(`${STD_LIST}${GOOD_TAIL.replace(`created=${NOW}`, `created=${NOW - 10}.25`)}`))).toMatchObject({ valid: true, created: NOW - 10 + 0.25 });
    expect(await vr(forge(`${STD_LIST}${GOOD_TAIL.replace(`created=${NOW}`, `created=${NOW - 10}.255`)}`))).toMatchObject({ created: NOW - 10 + 0.255 });
    expect(await vr(forge(`${STD_LIST}${GOOD_TAIL.replace(`created=${NOW}`, `created=${NOW - 10}.25.5`)}`))).toMatchObject({ valid: false, reason: 'missing created parameter (needed to bound the signature lifetime)' });
    for (const bad of ['1x', 'x1', '12.5x', 'x12.5', '1.', '.5', '12.5.1', '-', '1 2']) {
      expect(await reason(forge(`${STD_LIST}${GOOD_TAIL.replace(`created=${NOW}`, `created=${bad}`)}`))).toBe('missing created parameter (needed to bound the signature lifetime)');
    }
    expect(await reason(forge(`${STD_LIST}${GOOD_TAIL.replace(`expires=${NOW + 100}`, 'expires=abc')}`))).toBe('missing expires parameter');
    expect(await vr(forge(`${STD_LIST}${GOOD_TAIL.replace(`keyid="${KID}"`, 'keyid=k1')}`))).toMatchObject({ valid: true, keyid: 'k1' });
    expect(await vr(forge(`${STD_LIST}${GOOD_TAIL.replace(`keyid="${KID}"`, 'keyid=5')}`))).toMatchObject({ valid: false, reason: 'missing keyid parameter' });
    const r = await vr(forge(`${STD_LIST}${GOOD_TAIL.replace('tag="web-bot-auth"', 'tag=?1')}`), { requiredTag: null });
    expect(r.valid).toBe(true);
    expect(r.tag).toBeUndefined();
    const r0 = await vr(forge(`${STD_LIST}${GOOD_TAIL.replace('tag="web-bot-auth"', 'tag=?0')}`), { requiredTag: null });
    expect(r0.tag).toBeUndefined();
    const rn = await vr(forge(`${STD_LIST}${GOOD_TAIL.replace('tag="web-bot-auth"', 'tag=5')}`), { requiredTag: null });
    expect(rn.tag).toBeUndefined();
    const e = await vr(forge(`${STD_LIST}${tailWith(';nonce=')}`));
    expect(e.valid).toBe(true);
    expect(e.nonce).toBeUndefined();
    expect((await vr(forge(`${STD_LIST}${tailWith(';nonce= x')}`))).nonce).toBe('x');
    expect((await vr(forge(`${STD_LIST}${tailWith(';nonce=tok')}`))).nonce).toBe('tok');
  });
  it('a valueless parameter does not clobber a real one (name is the whole text)', async () => {
    const r = await vr(forge(`${STD_LIST}${GOOD_TAIL};tagx`));
    expect(r).toMatchObject({ valid: true, tag: 'web-bot-auth' });
    const r2 = await vr(forge(`${STD_LIST}${GOOD_TAIL};a=1;b;c`));
    expect(r2.valid).toBe(true);
  });
  it('quoted strings: escapes decoded; bad escapes, trailing text and unterminated strings fail closed', async () => {
    expect((await vr(forge(`${STD_LIST}${tailWith(';nonce="a\\"b\\\\c"')}`))).nonce).toBe('a"b\\c');
    expect(await reason(forge(`${STD_LIST}${tailWith(';nonce="a\\qb"')}`))).toBe('verification failed (fail closed): invalid escape in string');
    expect(await reason(forge(`${STD_LIST}${tailWith(';nonce="ab\\')}`))).toBe('verification failed (fail closed): invalid escape in string');
    expect(await reason(forge(`${STD_LIST}${tailWith(';nonce="abc"x')}`))).toBe('verification failed (fail closed): trailing characters after string parameter');
    expect(await reason(forge(`${STD_LIST}${GOOD_TAIL};nonce="abc`))).toBe('verification failed (fail closed): unterminated string');
  });
  it('signature-agent dictionary-member components', async () => {
    const hdr = (v: string) => ({ 'signature-agent': v });
    const comp = '"signature-agent";key="k"';
    const list = `("@authority" "@method" "@path" ${comp})`;
    const run = (v: string, line = v) => vr({ ...forge(`${list}${GOOD_TAIL}`, [...STD, `${comp}: ${line}`]), ...hdr(v) });
    expect((await run('k="https://u"', '"https://u"')).valid).toBe(true);
    expect((await run('a="1", k="https://u", j="2"', '"https://u"')).valid).toBe(true);
    expect((await run('a="1" , k="https://u" , j="2"', '"https://u"')).valid).toBe(true);
    expect((await run('k= "https://u"', '"https://u"')).valid).toBe(true);
    expect((await run('k="u";p1=abc;p2="q\\"r";p3;*s=a_Z.9:/*+%-', '"u";p1=abc;p2="q\\"r";p3;*s=a_Z.9:/*+%-')).valid).toBe(true);
    expect((await run('bare, k="u"', '"u"')).valid).toBe(true);
    const lastReason = async (v: string) => (await run(v, '"x"')).reason;
    expect(await lastReason('kk')).toBe('verification failed (fail closed): "signature-agent" has no dictionary member "k"');
    expect(await lastReason('j="1"')).toBe('verification failed (fail closed): "signature-agent" has no dictionary member "k"');
    expect(await lastReason('k=5')).toBe('verification failed (fail closed): expected a quoted string');
    for (const junk of ['k="u" x', 'k="u";Bad', 'k="u";1a', 'k="u";a=b c', 'k="u";a="x', 'k="u";a=', 'k="u"x', 'k="u"=', 'k="u";a="b"c']) {
      expect(await lastReason(junk)).toBe('verification failed (fail closed): member "k" of "signature-agent" is not in canonical form');
    }
    expect((await run('k="u";a="abc"', '"u";a="abc"')).valid).toBe(true);
    expect((await run('k="u";a=Z', '"u";a=Z')).valid).toBe(true);
    expect((await run('k="u";a-b.c_d*1=1', '"u";a-b.c_d*1=1')).valid).toBe(true);
  });
});

describe('structured-field scanning corner cases', () => {
  it('a valueless parameter replaces an earlier value of the same name', async () => {
    expect(await vr(forge(`${STD_LIST}${GOOD_TAIL};tag`))).toEqual({ valid: false, reason: 'tag "undefined" does not match required "web-bot-auth"' });
    const r = await vr(forge(`${STD_LIST}${GOOD_TAIL};nonce="x";nonce`));
    expect(r.valid).toBe(true);
    expect(r.nonce).toBeUndefined();
  });
  it('whitespace-only members between real ones are skipped', async () => {
    const a = forge(`${STD_LIST}${GOOD_TAIL}`, STD, 'sigA');
    const b = forge(`${STD_LIST}${GOOD_TAIL}`, STD, 'sigB');
    const h = { 'signature-input': `${a['signature-input']},  , ${b['signature-input']}`, signature: `${a.signature},  , ${b.signature}` };
    expect(await vr(h, { label: 'sigB' })).toMatchObject({ valid: true, label: 'sigB' });
  });
  it('whitespace between a component and its key parameter is ignored', async () => {
    const comp = '"x-h"\t;key="k"';
    const h = forge(`("@authority" "@method" "@path" ${comp})${GOOD_TAIL}`, [...STD, '"x-h";key="k": "v"']);
    expect((await vr({ ...h, 'x-h': 'k="v"' })).valid).toBe(true);
  });
  it('component names may hold parentheses and escaped quotes (string-aware list matching)', async () => {
    for (const [id, enc] of [['x)h', 'x)h'], ['x(h', 'x(h'], ['x")h', 'x\\")h']] as const) {
      const h = forge(`("@authority" "@method" "@path" "${enc}")${GOOD_TAIL}`, [...STD, `"${id}": v`]);
      const r = await verifySignedRequest({ method: 'GET', url: URL1, headers: { ...h, [id]: 'v' } }, { resolveKey, now: NOW });
      expect(r).toMatchObject({ valid: true, covered: ['@authority', '@method', '@path', id] });
    }
  });
  it('dictionary member names are matched at top level only (strings and parentheses respected)', async () => {
    const run = async (key: string, header: string) => {
      const comp = `"signature-agent";key="${key.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
      const h = forge(`("@authority" "@method" "@path" ${comp})${GOOD_TAIL}`, [...STD, `${comp}: "v"`]);
      return vr({ ...h, 'signature-agent': header });
    };
    expect((await run('p(q=r)', 'p(q=r)="v"')).valid).toBe(true);
    expect((await run('p((q)=r)', 'p((q)=r)="v"')).valid).toBe(true);
    expect((await run('p(q)', 'p(q)="v"')).valid).toBe(true);
    expect((await run('a)b', 'a)b="v"')).valid).toBe(true);
    expect((await run('k', 'k ="v"')).valid).toBe(true);
    expect((await run('a"b\\"=c"', 'a"b\\"=c"="v"')).valid).toBe(true);
    expect(await run('q"r', 'q"r="v"')).toEqual({ valid: false, reason: 'verification failed (fail closed): "signature-agent" has no dictionary member "q"r"' });
  });
});

describe('derived components against independent known answers', () => {
  it('@method uppercases, @authority lowercases and keeps the port, @path/@query/@scheme/@target-uri', async () => {
    const url = 'https://Example.COM:8443/p/q?x=1&y=2';
    const inner = ['"@authority"', '"@method"', '"@path"', '"@query"', '"@scheme"', '"@target-uri"'];
    const lines = [
      '"@authority": example.com:8443',
      '"@method": POST',
      '"@path": /p/q',
      '"@query": ?x=1&y=2',
      '"@scheme": https',
      '"@target-uri": https://example.com:8443/p/q?x=1&y=2',
    ];
    const h = forge(`(${inner.join(' ')})${GOOD_TAIL}`, lines);
    expect((await vr(h, {}, url, 'post')).valid).toBe(true);
    expect((await vr(h, {}, url, 'POST')).valid).toBe(true);
  });
  it('empty query is "?"; non-special URL with no path has path "/"', async () => {
    const lines = ['"@authority": example.com', '"@method": GET', '"@path": /', '"@query": ?', '"@scheme": foo'];
    const h = forge(`("@authority" "@method" "@path" "@query" "@scheme")${GOOD_TAIL}`, lines);
    expect((await vr(h, {}, 'foo://Example.com')).valid).toBe(true);
    expect((await vr(h, {}, 'foo://Example.com', 'get')).valid).toBe(true);
  });
  it('unsupported derived components and absent headers fail closed', async () => {
    const h = forge(`("@authority" "@method" "@path" "@bogus")${GOOD_TAIL}`, [...STD, '"@bogus": x']);
    expect(await reason(h)).toBe('verification failed (fail closed): unsupported derived component "@bogus"');
    const h2 = forge(`("@authority" "@method" "@path" "x-h")${GOOD_TAIL}`, [...STD, '"x-h": v']);
    expect(await reason(h2)).toBe('verification failed (fail closed): covered header "x-h" is absent from the request');
  });
  it('header values: trimmed, arrays joined with ", ", repeated names merged in order', async () => {
    const list = '("@authority" "@method" "@path" "x-h")';
    const forgeH = (v: string) => forge(`${list}${GOOD_TAIL}`, [...STD, `"x-h": ${v}`]);
    expect((await vr({ ...forgeH('v'), 'X-H': '  v  ' })).valid).toBe(true);
    const r = await verifySignedRequest({ method: 'GET', url: URL1, headers: { ...forgeH('a, b'), 'X-H': [' a ', 'b '] } }, { resolveKey, now: NOW });
    expect(r.valid).toBe(true);
    const r2 = await verifySignedRequest({ method: 'GET', url: URL1, headers: { ...forgeH('a, b, c'), 'x-h': 'a', 'X-H': ['b', 'c'] } }, { resolveKey, now: NOW });
    expect(r2.valid).toBe(true);
    const r3 = await verifySignedRequest({ method: 'GET', url: URL1, headers: { ...forgeH('a'), 'x-h': ' a ' } }, { resolveKey, now: NOW });
    expect(r3.valid).toBe(true);
  });
});

describe('verifySignedRequest decisions', () => {
  const good = forged();
  it('requires a key source and both headers', async () => {
    expect(await verifySignedRequest({ method: 'GET', url: URL1, headers: good }, {})).toEqual({ valid: false, reason: 'verifySignedRequest: provide resolveKey or jwks' });
    const only = { jwks: buildKeyDirectory([{ publicKey: kp.publicKey, keyid: KID }]), now: NOW };
    expect((await verifySignedRequest({ method: 'GET', url: URL1, headers: good }, only)).valid).toBe(true);
    const m = { valid: false, reason: 'missing Signature-Input or Signature header' };
    expect(await vr({ signature: good.signature })).toEqual(m);
    expect(await vr({ 'signature-input': good['signature-input'] })).toEqual(m);
    expect(await vr({})).toEqual(m);
  });
  it('success result carries every verified field', async () => {
    const s = sign({ nonce: 'n1', agentDirectoryUrl: 'https://agent.example' });
    expect(await vr(s.headers)).toEqual({
      valid: true,
      label: 'sig1',
      keyid: KID,
      covered: ['@authority', '@method', '@path', 'signature-agent'],
      created: NOW,
      expires: NOW + 300,
      tag: 'web-bot-auth',
      nonce: 'n1',
    });
  });
  it('label and tag based selection', async () => {
    const a = forge(`${STD_LIST}${GOOD_TAIL.replace('tag="web-bot-auth"', 'tag="other"')}`, STD, 'A');
    const b = forge(`${STD_LIST}${GOOD_TAIL}`, STD, 'B');
    const h = { 'signature-input': `${a['signature-input']}, ${b['signature-input']}`, signature: `${a.signature}, ${b.signature}` };
    expect(await vr(h)).toMatchObject({ valid: true, label: 'B' });
    expect(await vr(h, { requiredTag: 'other' })).toMatchObject({ valid: true, label: 'A', tag: 'other' });
    expect(await vr(h, { requiredTag: null })).toMatchObject({ valid: true, label: 'A', tag: 'other' });
    expect(await vr(h, { label: 'A', requiredTag: null })).toMatchObject({ valid: true, label: 'A' });
    expect(await vr(h, { label: 'B' })).toMatchObject({ valid: true, label: 'B' });
    expect(await vr(h, { label: 'A' })).toEqual({ valid: false, reason: 'tag "other" does not match required "web-bot-auth"' });
    expect(await vr(h, { label: 'Z' })).toEqual({ valid: false, reason: 'no matching signature in Signature-Input' });
    expect(await vr(h, { requiredTag: 'nomatch' })).toEqual({ valid: false, reason: 'tag "other" does not match required "nomatch"' });
    expect(await vr({ 'signature-input': '', signature: '' })).toEqual({ valid: false, reason: 'no matching signature in Signature-Input' });
    const noSig = { 'signature-input': a['signature-input'], signature: b.signature };
    expect(await vr(noSig, { requiredTag: null })).toEqual({ valid: false, reason: 'no Signature entry for label "A"' });
    const untagged = forge(`${STD_LIST}${GOOD_TAIL.replace(';tag="web-bot-auth"', '')}`);
    expect(await vr(untagged)).toEqual({ valid: false, reason: 'tag "undefined" does not match required "web-bot-auth"' });
    expect((await vr(untagged, { requiredTag: null })).valid).toBe(true);
  });
  it('required components', async () => {
    const without = (drop: string) => forge(`(${['"@authority"', '"@method"', '"@path"'].filter((c) => !c.includes(drop)).join(' ')})${GOOD_TAIL}`, STD.filter((l) => !l.includes(drop)));
    for (const id of ['@authority', '@method', '@path']) expect(await vr(without(id))).toEqual({ valid: false, reason: `${id} is not a covered component` });
    const q = 'https://example.com/a/b?x=1';
    expect(await vr(good, {}, q)).toEqual({ valid: false, reason: '@query is not a covered component' });
    expect(await vr(good, {}, '?x=1')).toEqual({ valid: false, reason: '@query is not a covered component' });
    for (const u of ['https://example.com/a/b?', 'https://example.com/a/b?#frag']) expect((await vr(good, {}, u)).valid).toBe(true);
    expect((await vr(good, { requiredComponents: ['@authority'] }, q)).valid).toBe(true);
    expect(await vr(good, { requiredComponents: ['@scheme'] })).toEqual({ valid: false, reason: '@scheme is not a covered component' });
    expect((await vr(good, { requiredComponents: [] })).valid).toBe(true);
  });
  it('alg', async () => {
    expect(await vr(forge(`${STD_LIST}${GOOD_TAIL.replace('alg="ed25519"', 'alg="rsa-pss-sha512"')}`))).toEqual({ valid: false, reason: 'unsupported alg "rsa-pss-sha512"' });
    expect((await vr(forge(`${STD_LIST}${GOOD_TAIL.replace(';alg="ed25519"', '')}`))).valid).toBe(true);
  });
  it('freshness boundaries and clock skew', async () => {
    const at = (created: number | undefined, expires: number | undefined) =>
      forge(`${STD_LIST}${created === undefined ? '' : `;created=${created}`};keyid="${KID}"${expires === undefined ? '' : `;expires=${expires}`};tag="web-bot-auth"`);
    expect((await vr(at(NOW - 10, NOW))).valid).toBe(true); // now == expires
    expect(await vr(at(NOW - 10, NOW - 1))).toEqual({ valid: false, reason: 'signature has expired' });
    expect((await vr(at(NOW - 10, NOW - 5), { clockSkewSec: 5 })).valid).toBe(true);
    expect((await vr(at(NOW - 10, NOW - 6), { clockSkewSec: 5 })).reason).toBe('signature has expired');
    expect((await vr(at(NOW, NOW + 10))).valid).toBe(true); // created == now
    expect(await vr(at(NOW + 1, NOW + 10))).toEqual({ valid: false, reason: 'signature created-time is in the future' });
    expect((await vr(at(NOW + 5, NOW + 10), { clockSkewSec: 5 })).valid).toBe(true);
    expect((await vr(at(NOW + 6, NOW + 10), { clockSkewSec: 5 })).reason).toBe('signature created-time is in the future');
    // maxAgeSec: now - created <= maxAge + skew
    expect((await vr(at(NOW - 100, NOW + 100), { maxAgeSec: 100, maxLifetimeSec: 1000 })).valid).toBe(true);
    expect((await vr(at(NOW - 101, NOW + 100), { maxAgeSec: 100, maxLifetimeSec: 1000 })).reason).toBe('signature is older than maxAgeSec');
    expect((await vr(at(NOW - 105, NOW + 100), { maxAgeSec: 100, clockSkewSec: 5, maxLifetimeSec: 1000 })).valid).toBe(true);
    expect((await vr(at(NOW - 106, NOW + 100), { maxAgeSec: 100, clockSkewSec: 5, maxLifetimeSec: 1000 })).reason).toBe('signature is older than maxAgeSec');
    expect((await vr(at(NOW - 5, NOW + 100), { maxAgeSec: 10 })).valid).toBe(true);
    // expires is mandatory unless relaxed
    expect(await vr(at(NOW, undefined))).toEqual({ valid: false, reason: 'missing expires parameter' });
    expect((await vr(at(NOW, undefined), { requireExpires: false })).valid).toBe(true);
    expect((await vr(at(NOW, undefined), { requireExpires: true })).reason).toBe('missing expires parameter');
  });
  it('lifetime cap needs created', async () => {
    const at = (created: number | undefined, expires: number) =>
      forge(`${STD_LIST}${created === undefined ? '' : `;created=${created}`};keyid="${KID}";expires=${expires};tag="web-bot-auth"`);
    expect((await vr(at(NOW, NOW + 300))).valid).toBe(true);
    expect(await vr(at(NOW, NOW + 301))).toEqual({ valid: false, reason: 'signature lifetime exceeds maxLifetimeSec' });
    expect((await vr(at(NOW, NOW + 301), { maxLifetimeSec: 301 })).valid).toBe(true);
    expect((await vr(at(NOW, NOW + 301), { maxLifetimeSec: Infinity })).valid).toBe(true);
    expect(await vr(at(undefined, NOW + 10))).toEqual({ valid: false, reason: 'missing created parameter (needed to bound the signature lifetime)' });
    expect((await vr(at(undefined, NOW + 10), { maxLifetimeSec: Infinity })).valid).toBe(true);
    expect((await vr(at(NOW, NOW + 3000), { maxLifetimeSec: Infinity })).valid).toBe(true);
  });
  it('keyid and key resolution', async () => {
    const noKey = forge(`${STD_LIST};created=${NOW};expires=${NOW + 10};tag="web-bot-auth"`);
    expect(await vr(noKey)).toEqual({ valid: false, reason: 'missing keyid parameter' });
    expect(await vr(forged(), { resolveKey: () => null })).toEqual({ valid: false, reason: `could not resolve key "${KID}"` });
    expect(await vr(forged(), { resolveKey: () => undefined })).toEqual({ valid: false, reason: `could not resolve key "${KID}"` });
    expect(await vr(forged(), { resolveKey: () => new Uint8Array(31) })).toEqual({ valid: false, reason: `could not resolve key "${KID}"` });
    expect(await vr(forged(), { resolveKey: () => new Uint8Array(33) })).toEqual({ valid: false, reason: `could not resolve key "${KID}"` });
    const x = b64url(kp.publicKey);
    expect((await vr(forged(), { resolveKey: () => ({ kty: 'OKP', crv: 'Ed25519', x }) })).valid).toBe(true);
    for (const bad of [{ kty: 'OKP', crv: 'X25519', x }, { kty: 'EC', crv: 'Ed25519', x }, { kty: 'OKP', crv: 'Ed25519', x: 5 }, { kty: 'OKP', crv: 'Ed25519' }, 'str', 5]) {
      expect(await vr(forged(), { resolveKey: () => bad as never })).toEqual({ valid: false, reason: `could not resolve key "${KID}"` });
    }
    expect(await vr(forged(), { resolveKey: () => ({ kty: 'OKP', crv: 'Ed25519', x: 'AAAA' }) })).toEqual({ valid: false, reason: 'signature does not verify under the resolved key' });
    expect(await vr(forged(), { resolveKey: () => generateKeyPair().publicKey })).toEqual({ valid: false, reason: 'signature does not verify under the resolved key' });
    const other = generateKeyPair();
    const dir = buildKeyDirectory([{ publicKey: other.publicKey, keyid: 'zz' }, { publicKey: kp.publicKey, keyid: KID }]);
    expect((await vr(forged(), { resolveKey: undefined, jwks: dir })).valid).toBe(true);
    expect(await vr(forged(), { resolveKey: undefined, jwks: buildKeyDirectory([{ publicKey: other.publicKey, keyid: 'zz' }]) })).toEqual({ valid: false, reason: `could not resolve key "${KID}"` });
    // resolveKey takes precedence over jwks
    expect(await vr(forged(), { resolveKey: () => null, jwks: dir })).toEqual({ valid: false, reason: `could not resolve key "${KID}"` });
    // a 64-byte signature of the wrong content
    const bad = forged();
    expect(await reason({ ...bad, signature: `sig1=:${Buffer.alloc(64).toString('base64')}:` })).toBe('signature does not verify under the resolved key');
  });
  it('replay cache keys, expiry and refusal', async () => {
    const calls: Array<[string, number, number]> = [];
    const spy: ReplayCache = { claim: (k, e, n) => (calls.push([k, e, n]), true) };
    const withNonce = forge(`${STD_LIST}${GOOD_TAIL};nonce="n1"`);
    await vr(withNonce, { replayCache: spy, clockSkewSec: 7 });
    expect(calls[0]).toEqual([`${KID}|n1`, NOW + 100 + 7, NOW]);
    const plain = forged();
    await vr(plain, { replayCache: spy });
    const sigBytes = Buffer.from(plain.signature.slice('sig1=:'.length, -1), 'base64');
    expect(calls[1]).toEqual([`${KID}|${b64url(sigBytes)}`, NOW + 100, NOW]);
    const noExp = forge(`${STD_LIST};created=${NOW - 10};keyid="${KID}";tag="web-bot-auth"`);
    await vr(noExp, { replayCache: spy, requireExpires: false });
    expect(calls[2]![1]).toBe(NOW - 10 + 300);
    await vr(noExp, { replayCache: spy, requireExpires: false, maxLifetimeSec: Infinity });
    expect(calls[3]![1]).toBe(NOW - 10 + 3600);
    await vr(noExp, { replayCache: spy, requireExpires: false, maxLifetimeSec: 50, clockSkewSec: 2 });
    expect(calls[4]![1]).toBe(NOW - 10 + 50 + 2);
    const noCreated = forge(`${STD_LIST};keyid="${KID}";tag="web-bot-auth"`);
    await vr(noCreated, { replayCache: spy, requireExpires: false, maxLifetimeSec: Infinity });
    expect(calls[5]![1]).toBe(NOW + 3600);

    const cache = memoryReplayCache();
    expect((await vr(plain, { replayCache: cache })).valid).toBe(true);
    expect(await vr(plain, { replayCache: cache })).toEqual({ valid: false, reason: 'replayed signature' });
    const asyncCache: ReplayCache = { claim: async () => false };
    expect(await vr(plain, { replayCache: asyncCache })).toEqual({ valid: false, reason: 'replayed signature' });
    const full = memoryReplayCache(1);
    await vr(plain, { replayCache: full });
    expect((await vr(withNonce, { replayCache: full })).reason).toBe('verification failed (fail closed): replay cache full');
  });
});

describe('signRequest', () => {
  it('rejects bad component configurations and missing covered headers', () => {
    expect(() => sign({ components: ['@method'] })).toThrow('signRequest: the web-bot-auth profile requires @authority to be covered');
    expect(() => sign({ components: ['@authority', 'x-h'] })).toThrow('signRequest: components must be derived components, got "x-h" (use coverHeaders for headers)');
    expect(() => sign({ agentDirectoryKey: 'k' })).toThrow('signRequest: agentDirectoryKey requires agentDirectoryUrl');
    expect(() => sign({ coverHeaders: ['X-Missing'] })).toThrow('signRequest: covered header "X-Missing" is not present in headers');
    expect(() => sign({ coverHeaders: ['x-h'], headers: { 'X-H': 'v' } })).not.toThrow();
  });
  it('covers each header once, in order; the signature agent is not duplicated', () => {
    const s = sign({ headers: { 'X-H': 'v', 'x-g': 'w' }, coverHeaders: ['x-h', 'X-H', 'x-g'] });
    expect(s.covered).toEqual(['@authority', '@method', '@path', 'x-h', 'x-g']);
    const t = sign({ agentDirectoryUrl: 'https://a', headers: { 'Signature-Agent': 'zzz' }, coverHeaders: ['signature-agent', 'Signature-Agent'] });
    expect(t.covered).toEqual(['@authority', '@method', '@path', 'signature-agent']);
    expect(t.signatureAgent).toBe('"https://a"');
    expect(t.headers['Signature-Agent']).toBe('"https://a"');
    const d = sign({ agentDirectoryUrl: 'https://a', agentDirectoryKey: 'k' });
    expect(d.signatureAgent).toBe('k="https://a"');
    expect(d.signatureInput).toContain('"signature-agent";key="k"');
  });
  it('default parameters, params order and input defaults', () => {
    const s = signRequest({ method: 'get', url: 'https://example.com/a?q=1', key: kp, keyid: 'id"x', created: 1000, nonce: 'n' });
    expect(s.signatureInput).toBe('sig1=("@authority" "@method" "@path" "@query");created=1000;keyid="id\\"x";alg="ed25519";expires=1300;nonce="n";tag="web-bot-auth"');
    expect(s.covered).toEqual(['@authority', '@method', '@path', '@query']);
    expect(Object.keys(s.headers).sort()).toEqual(['Signature', 'Signature-Input']);
    expect(s.signature.startsWith('sig1=:')).toBe(true);
    const t = signRequest({ method: 'GET', url: 'https://example.com/a', key: kp, keyid: 'k', created: 10, expiresInSec: 5, label: 'L1' });
    expect(t.signatureInput).toBe('L1=("@authority" "@method" "@path");created=10;keyid="k";alg="ed25519";expires=15;tag="web-bot-auth"');
    expect(t.signature.startsWith('L1=:')).toBe(true);
    const u = signRequest({ method: 'GET', url: 'https://example.com/a?#f', key: kp, keyid: 'k', created: 10 });
    expect(u.covered).toEqual(['@authority', '@method', '@path']);
    const custom = signRequest({ method: 'GET', url: 'https://example.com/a?q=1', key: kp, keyid: 'k', created: 10, components: ['@authority', '@Scheme'] });
    expect(custom.covered).toEqual(['@authority', '@scheme']);
    expect(() => signRequest({ method: 'GET', url: 'https://example.com/a', key: kp, keyid: 'k', components: ['@AUTHORITY'] })).toThrow('requires @authority');
    const now = Math.floor(Date.now() / 1000);
    const dflt = signRequest({ method: 'GET', url: 'https://example.com/a', key: kp, keyid: 'k' });
    const m = /created=(\d+);.*expires=(\d+)/.exec(dflt.signatureInput)!;
    expect(Math.abs(Number(m[1]) - now)).toBeLessThanOrEqual(2);
    expect(Number(m[2]) - Number(m[1])).toBe(300);
  });
  it('signs exactly the independent RFC 9421 base', async () => {
    const s = sign({ components: ['@authority', '@method', '@path', '@scheme'] });
    const lines = ['"@authority": example.com', '"@method": GET', '"@path": /a/b', '"@scheme": https'];
    const params = s.signatureInput.slice('sig1='.length);
    const expected = rawSign([...lines, `"@signature-params": ${params}`].join('\n'));
    expect(s.signature).toBe(`sig1=:${expected}:`);
  });
});

describe('key directory', () => {
  it('buildKeyDirectory publishes optional members only when given', () => {
    const k = kp.publicKey;
    const d = buildKeyDirectory([{ publicKey: k }, { publicKey: k, keyid: 'kid2', use: 'sig', nbf: 5, exp: 9 }, { publicKey: k, nbf: 0, exp: 0 }]);
    expect(d.keys[0]).toEqual({ kty: 'OKP', crv: 'Ed25519', x: b64url(k), kid: jwkThumbprint(k) });
    expect(Object.keys(d.keys[0]!).sort()).toEqual(['crv', 'kid', 'kty', 'x']);
    expect(Object.keys(d.keys[1]!).sort()).toEqual(['crv', 'exp', 'kid', 'kty', 'nbf', 'use', 'x']);
    expect(d.keys[1]).toMatchObject({ kid: 'kid2', use: 'sig', nbf: 5, exp: 9 });
    expect(d.keys[2]).toMatchObject({ nbf: 0, exp: 0 });
    expect(Object.keys(d.keys[2]!)).not.toContain('use');
    const only = buildKeyDirectory([{ publicKey: k, use: 'enc' }]).keys[0]!;
    expect(Object.keys(only).sort()).toEqual(['crv', 'kid', 'kty', 'use', 'x']);
    expect(Object.keys(buildKeyDirectory([{ publicKey: k, nbf: 1 }]).keys[0]!)).toContain('nbf');
    expect(Object.keys(buildKeyDirectory([{ publicKey: k, nbf: 1 }]).keys[0]!)).not.toContain('exp');
    expect(Object.keys(buildKeyDirectory([{ publicKey: k, exp: 1 }]).keys[0]!)).not.toContain('nbf');
  });
  it('jwkThumbprint is the RFC 7638 SHA-256 thumbprint', () => {
    const k = new Uint8Array(32);
    // base64url(sha256('{"crv":"Ed25519","kty":"OKP","x":"AAAA...A"}'))
    const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${b64url(k)}"}`;
    expect(jwkThumbprint(k)).toBe(createHash('sha256').update(canonical).digest('base64url'));
  });
  it('resolveFromDirectory finds by kid only', () => {
    const dir = buildKeyDirectory([{ publicKey: new Uint8Array(32), keyid: 'a' }, { publicKey: kp.publicKey, keyid: 'b' }]);
    expect(resolveFromDirectory(dir, 'b')?.x).toBe(b64url(kp.publicKey));
    expect(resolveFromDirectory(dir, 'c')).toBeUndefined();
  });
  it('directoryHandler serves the exact response on the well-known path (query ignored)', () => {
    const h = directoryHandler([{ publicKey: kp.publicKey, keyid: KID }]);
    const body = JSON.stringify(buildKeyDirectory([{ publicKey: kp.publicKey, keyid: KID }]));
    const expected = { status: 200, headers: { 'content-type': DIRECTORY_CONTENT_TYPE, 'cache-control': 'max-age=86400' }, body };
    expect(h(WELL_KNOWN_DIRECTORY_PATH)).toEqual(expected);
    expect(h(`${WELL_KNOWN_DIRECTORY_PATH}?x=1`)).toEqual(expected);
    expect(h('/other')).toBeNull();
    expect(h('')).toBeNull();
    expect(h(`${WELL_KNOWN_DIRECTORY_PATH}/x`)).toBeNull();
  });
});

describe('proof binding', () => {
  function pcactn(): PCActn {
    const a = agent({ principal: generateKeyPair(), holder: kp, goal: 'issue refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500' }, aud: 'https://api.example.com' });
    return a.act('stripe.refund', 'charge_123', { amount: 100 }).pcactn;
  }
  const send = (s: { headers: Record<string, string> }, extra: Record<string, string> = {}) => ({ method: 'GET', url: URL1, headers: { ...s.headers, ...extra } });
  it('signRequestWithProof works without caller headers and merges the proof header', async () => {
    const p = pcactn();
    const s = signRequestWithProof({ method: 'GET', url: URL1, key: kp, keyid: KID, created: NOW, pcactn: p });
    expect(s.covered).toEqual(['@authority', '@method', '@path', 'pca-action']);
    expect(Object.keys(s.proofHeader)).toEqual([PCA_HEADER]);
    expect(s.headers[PCA_HEADER]).toBe(s.proofHeader[PCA_HEADER]);
    expect(decodeProofHeader(s.proofHeader[PCA_HEADER]!)).toEqual(p);
    const r = await verifySignedRequestWithProof(send(s), { resolveKey, now: NOW });
    expect(r.valid).toBe(true);
    expect(r.pcactn).toEqual(p);
    const e = await verifySignedRequestWithProof(send(s), { resolveKey, now: NOW, expectedPCActn: p });
    expect(e.valid).toBe(true);
  });
  it('refuses when the base signature is invalid, the proof is not covered, undecodable, or not the expected one', async () => {
    const p = pcactn();
    const s = signRequestWithProof({ method: 'GET', url: URL1, key: kp, keyid: KID, created: NOW, pcactn: p });
    expect(await verifySignedRequestWithProof(send(s), { resolveKey: () => null, now: NOW })).toEqual({ valid: false, reason: `could not resolve key "${KID}"` });
    const plain = sign({ headers: { [PCA_HEADER]: s.proofHeader[PCA_HEADER]! } });
    expect(await verifySignedRequestWithProof(send(plain, { [PCA_HEADER]: s.proofHeader[PCA_HEADER]! }), { resolveKey, now: NOW })).toEqual({
      valid: false,
      reason: `the ${PCA_HEADER} proof header is not covered by the signature`,
    });
    const garbage = sign({ headers: { [PCA_HEADER]: 'not-a-pcactn' }, coverHeaders: [PCA_HEADER] });
    const g = await verifySignedRequestWithProof(send(garbage, { [PCA_HEADER]: 'not-a-pcactn' }), { resolveKey, now: NOW });
    expect(g.valid).toBe(false);
    expect(g.reason!.startsWith(`invalid PCActn in ${PCA_HEADER}: `)).toBe(true);
    expect(g.reason!.length).toBeGreaterThan(`invalid PCActn in ${PCA_HEADER}: `.length);
    const other = pcactn();
    expect(await verifySignedRequestWithProof(send(s), { resolveKey, now: NOW, expectedPCActn: other })).toEqual({ valid: false, reason: 'carried PCActn does not match the expected proof' });
  });
});

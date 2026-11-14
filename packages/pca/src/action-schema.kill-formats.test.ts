/**
 * The v2 string formats, the object_ref / datetime / duration value domains, and the format-checked string values:
 * every syntactic rule on its own, with accepted and refused inputs at each boundary. The module is re-evaluated per
 * test because the format table and its patterns are built at load.
 */
import { describe, expect, it, vi } from 'vitest';
import type { ActionParamDecl } from './action-schema';

async function fresh() {
  vi.resetModules();
  return import('./action-schema');
}

const decl = (o: Partial<ActionParamDecl> & { type: ActionParamDecl['type'] }): ActionParamDecl => ({ semantic: 's', sensitivity: 'free', ...o });
const verdicts = (check: (s: string) => boolean, good: string[], bad: string[]) => {
  for (const g of good) expect(check(g), `accept ${JSON.stringify(g)}`).toBe(true);
  for (const b of bad) expect(check(b), `refuse ${JSON.stringify(b)}`).toBe(false);
};

describe('formatCheck: the format table', () => {
  it('knows exactly the documented names; id:<type> is a grammar, anything else is null', async () => {
    const { formatCheck } = await fresh();
    for (const f of ['email', 'url', 'uri_https', 'uuid', 'iban', 'phone_e164', 'cidr', 'iso_country', 'iso_currency', 'semver', 'sha256', 'id:user', 'id:a.b.c.d']) expect(typeof formatCheck(f), f).toBe('function');
    for (const f of ['', 'bogus', 'Email', 'id:', 'id:Upper', 'id:a.b.c.d.e', 'id:a..b', 'id:a-b', 'xid:a', 'id:a!', ' id:a', 'id:a\n', 'constructor', 'toString', '__proto__', 'hasOwnProperty', 'valueOf']) expect(formatCheck(f), JSON.stringify(f)).toBeNull();
  });
  it('id:<type> accepts a 1..128 character safe id', async () => {
    const { formatCheck } = await fresh();
    const ck = formatCheck('id:user')!;
    verdicts(ck, ['a', 'abc', 'A-b_c.d:e', 'user_1', '0', 'a'.repeat(128)], ['', 'a'.repeat(129), 'a b', 'a/b', 'a@b', ' a', 'a ', 'a\n', 'é', 'a,b']);
    expect(formatCheck('id:a.b.c.d')!('x1')).toBe(true);
    expect(formatCheck('id:account')!('Zz9')).toBe(true);
  });
});

describe('email', () => {
  it('accepts an address with a 1..64 local part, dotted labels of 1..63 characters and at most 254 characters', async () => {
    const { formatCheck } = await fresh();
    const ck = formatCheck('email')!;
    const label = (n: number) => 'b'.repeat(n);
    const at254 = `${'a'.repeat(64)}@${label(63)}.${label(63)}.${label(61)}`;
    const at255 = `${'a'.repeat(64)}@${label(63)}.${label(63)}.${label(62)}`;
    expect(at254.length).toBe(254);
    expect(at255.length).toBe(255);
    verdicts(
      ck,
      ['a@b.co', 'a@b.c.d.e', 'a.b+c%d_e-f@sub.example.com', 'a@b-c.d', 'A@B.CO', '1@2.3', `${'a'.repeat(64)}@b.co`, `a@${label(63)}.co`, `a@b.${label(63)}`, at254],
      ['', 'a@b', 'a@', '@b.co', 'a@.co', 'a@b.', 'a b@c.d', 'a@b c.d', 'a@b..c', ' a@b.co', 'a@b.co ', 'a@b.co\n', 'a@@b.co', 'a@b@c.d', `${'a'.repeat(65)}@b.co`, `a@${label(64)}.co`, `a@b.${label(64)}`, at255, 'a@b_c.d', 'a@b.c_d', 'a(b)@c.d', 'é@b.co'],
    );
  });
});

describe('url and uri_https', () => {
  it('url: a scheme of 1..32 characters, ://, a non-empty authority, then any non-space tail', async () => {
    const { formatCheck } = await fresh();
    const ck = formatCheck('url')!;
    verdicts(
      ck,
      ['https://example.com', 'http://a', 'ftp://h', 'a://b', 'a+b.c-d://h', `a${'b'.repeat(31)}://h`, 'https://a.b/c?d#e', 'http://a:80/x', 'https://u@h/p', 'x://y/z/w'],
      ['', 'http://', 'http:///x', 'http://?x', 'http://#x', '1http://x', '+http://x', ' http://x', 'x http://a.b', 'http://a b', 'http://a.b x', 'http://a.b\n', '://x', 'http:/x', 'http//x', `a${'b'.repeat(32)}://h`, 'a_b://h', 'http://\nx', 'mailto:a@b'],
    );
  });
  it('uri_https: https only, same authority and tail rule', async () => {
    const { formatCheck } = await fresh();
    const ck = formatCheck('uri_https')!;
    verdicts(
      ck,
      ['https://a', 'https://a.b', 'https://a.b/c?d#e', 'https://h:8443/x'],
      ['', 'http://a.b', 'ftp://a.b', 'https://', 'https:///x', 'https://?x', 'https://#x', ' https://a', 'x https://a', 'https://a b', 'https://a.b x', 'https://a.b\n', 'HTTPS://a', 'https:/a', 'xhttps://a'],
    );
  });
});

describe('uuid, sha256, phone, country, currency', () => {
  it('uuid: 8-4-4-4-12 lowercase hex', async () => {
    const { formatCheck } = await fresh();
    const ck = formatCheck('uuid')!;
    verdicts(
      ck,
      ['123e4567-e89b-12d3-a456-426614174000', '00000000-0000-0000-0000-000000000000', 'ffffffff-ffff-ffff-ffff-ffffffffffff'],
      ['', '123E4567-E89B-12D3-A456-426614174000', '123e4567-e89b-12d3-a456-42661417400', '123e4567-e89b-12d3-a456-4266141740000', '123e456-e89b-12d3-a456-426614174000', '123e45678-e89b-12d3-a456-426614174000', '123e4567-e89-12d3-a456-426614174000', '123e4567-e89bb-12d3-a456-426614174000', '123e4567-e89b-12d-a456-426614174000', '123e4567-e89b-12d3a-a456-426614174000', '123e4567-e89b-12d3-a45-426614174000', '123e4567-e89b-12d3-a4566-426614174000', 'g23e4567-e89b-12d3-a456-426614174000', '123e4567e89b12d3a456426614174000', 'x123e4567-e89b-12d3-a456-426614174000', '123e4567-e89b-12d3-a456-426614174000x', ' 123e4567-e89b-12d3-a456-426614174000', '123e4567-e89b-12d3-a456-426614174000\n'],
    );
  });
  it('sha256: 64 lowercase hex characters', async () => {
    const { formatCheck } = await fresh();
    const ck = formatCheck('sha256')!;
    verdicts(ck, ['0123456789abcdef'.repeat(4), 'a'.repeat(64), '0'.repeat(64)], ['', 'a'.repeat(63), 'a'.repeat(65), 'A'.repeat(64), 'g'.repeat(64), `x${'a'.repeat(64)}`, `${'a'.repeat(64)}x`, ` ${'a'.repeat(63)}`, `${'a'.repeat(64)}\n`]);
  });
  it('phone_e164: + then a non-zero digit and 6..14 more digits', async () => {
    const { formatCheck } = await fresh();
    const ck = formatCheck('phone_e164')!;
    verdicts(
      ck,
      ['+14155552671', '+1234567', '+123456789012345', '+9999999'],
      ['', '+123456', '+1234567890123456', '+0123456789', '14155552671', '++14155552671', ' +14155552671', '+14155552671 ', '+1415555267a', '+1-415-555-2671', 'x+14155552671', '+', '+1', '+14155552671\n'],
    );
  });
  it('iso_country is two capitals and iso_currency three', async () => {
    const { formatCheck } = await fresh();
    verdicts(formatCheck('iso_country')!, ['US', 'ZZ', 'AA'], ['', 'U', 'USA', 'us', 'Us', 'U1', '11', 'xUS', 'USx', ' US', 'US ', 'US\n']);
    verdicts(formatCheck('iso_currency')!, ['USD', 'EUR', 'ZZZ'], ['', 'US', 'USDD', 'usd', 'Usd', 'U5D', '111', 'xUSD', 'USDx', ' USD', 'USD ', 'USD\n']);
  });
});

describe('semver', () => {
  it('accepts a semantic version with optional pre-release and build parts', async () => {
    const { formatCheck } = await fresh();
    const ck = formatCheck('semver')!;
    verdicts(
      ck,
      ['0.0.0', '1.2.3', '10.20.30', '1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-0.3.7', '1.0.0-x.7.z.92', '1.0.0+20130313144700', '1.0.0-beta+exp.sha.5114f85', '1.0.0-a-b', '1.0.0+a-b.c', '1.0.0-rc.1+build.1', '100.200.300', '1.0.0-A', '1.0.0+a.b.c'],
      ['', '1', '1.2', '1.2.3.4', '01.2.3', '1.02.3', '1.2.03', '-1.2.3', '1.2.3-', '1.2.3+', '1.2.3-+x', '1.2.3-a..b', '1.2.3-a.', '1.2.3+a..b', '1.2.3+a.', '1.2.3-a+', 'v1.2.3', ' 1.2.3', '1.2.3 ', '1.2.3-a b', '1.2.3/x', 'a.b.c', '1.2.x', '1.2.3-a_b', '1.2.3\n', '1..3', '1.2.3-a.b..c', '1.2.3-a+b+c'],
    );
  });
});

describe('iban', () => {
  it('accepts a valid mod-97 checksum and refuses others', async () => {
    const { formatCheck } = await fresh();
    const ck = formatCheck('iban')!;
    verdicts(
      ck,
      ['GB82WEST12345698765432', 'DE89370400440532013000', 'FR1420041010050500013M02606', 'ZA64Z9A8Z7A6Z5A4Z3', 'DE29AZ900000000', 'XX86ABCDEFGHIJK', `XX88${'A'.repeat(30)}`],
      ['', 'GB82WEST12345698765433', 'GB83WEST12345698765432', 'GB82WEST12345698765431', 'DE89370400440532013001', 'ZA65Z9A8Z7A6Z5A4Z3', 'ZA64Z9A8Z7A6Z5A4Z4', 'ZA64Z9A8Z7A6Z5B4Z3'],
    );
  });
  it('the shape comes first: two capitals, two digits, 11..30 alphanumerics, upper case, anchored', async () => {
    const { formatCheck } = await fresh();
    const ck = formatCheck('iban')!;
    verdicts(ck, [], [
      'XX70AAAAAAAAAA', // 14 characters: checksum is right, the length is not
      `XX08${'A'.repeat(31)}`, // 35 characters: checksum is right, the length is not
      'gb82west12345698765432',
      'GB82west12345698765432',
      'G182WEST12345698765432',
      'GBXXWEST12345698765432',
      'GB8WEST12345698765432',
      ' GB82WEST12345698765432',
      'GB82WEST12345698765432 ',
      'GB82-WEST-1234-5698-7654-32',
      'nzGB82WEST12345698765432', // right checksum with a prefix
      'GB82WEST12345698765432by', // right checksum with a suffix
    ]);
  });
});

describe('cidr', () => {
  it('IPv4: four decimal octets without leading zeros and a prefix of 0..32', async () => {
    const { formatCheck } = await fresh();
    const ck = formatCheck('cidr')!;
    verdicts(
      ck,
      ['10.0.0.0/8', '0.0.0.0/0', '255.255.255.255/32', '192.168.1.0/24', '1.2.3.4/1', '9.9.9.9/9', '100.200.250.255/31'],
      ['', '10.0.0.0', '256.0.0.0/8', '0.256.0.0/8', '0.0.256.0/8', '0.0.0.256/8', '999.0.0.0/8', '1.2.3.4/33', '1.2.3.4/99', '1.2.3.4/08', '1.2.3.4/00', '01.2.3.4/8', '1.02.3.4/8', '1.2.03.4/8', '1.2.3.04/8', '1.2.3/8', '1.2.3.4.5/8', '1.2.3.4/', '1.2.3.4/-1', '1.2.3.4/8x', 'x1.2.3.4/8', ' 1.2.3.4/8', '1.2.3.4/8 ', '1.2.3.1234/8', '1234.2.3.4/8', 'a.b.c.d/8', '1.2.3.4/a', '1.2.3.4//8', '1.2.3.4/8\n', '::/0x'],
    );
  });
  it('IPv6: hex groups with at least two colons, no :::, and a prefix of 0..128', async () => {
    const { formatCheck } = await fresh();
    const ck = formatCheck('cidr')!;
    verdicts(
      ck,
      ['2001:db8::/32', '::/0', '::1/128', '1:2:3/8', 'fe80::1/64', 'FE80::/10', 'a::b/1', '2001:0db8:85a3:0000:0000:8a2e:0370:7334/128', '::/128'],
      ['', '::/129', '::1/129', '::1/999', '::1/0128', '::1/08', '::1/00', 'fe80:1/64', 'abcd/8', 'ab/8', ':::/1', '1:::2/8', '::1', '::1/', '::1/x', 'g::1/8', 'x::/0', '::/0x', ' ::/0', '::/0 ', 'a/8', '/8', '::1/8\n', `${'a:'.repeat(20)}/8`, '1.2.3.4::/8'],
    );
  });
});

describe('paramValueViolation: format-checked strings', () => {
  it('a string with a format is checked after its length and values; an unknown declared format refuses every value', async () => {
    const { paramValueViolation } = await fresh();
    expect(paramValueViolation(decl({ type: 'string', format: 'email' }), 'a@b.co')).toBeNull();
    expect(paramValueViolation(decl({ type: 'string', format: 'email' }), 'nope')).toStrictEqual({ code: 'out_of_domain', reason: 'not a valid email' });
    expect(paramValueViolation(decl({ type: 'string', format: 'uuid' }), '123e4567-e89b-12d3-a456-426614174000')).toBeNull();
    expect(paramValueViolation(decl({ type: 'string', format: 'id:user' }), 'u_1')).toBeNull();
    expect(paramValueViolation(decl({ type: 'string', format: 'id:user' }), 'not ok')).toStrictEqual({ code: 'out_of_domain', reason: 'not a valid id:user' });
    expect(paramValueViolation(decl({ type: 'string', format: 'bogus' }), 'anything')).toStrictEqual({ code: 'out_of_domain', reason: 'not a valid bogus' });
    expect(paramValueViolation(decl({ type: 'string' }), 'anything at all')).toBeNull();
    expect(paramValueViolation(decl({ type: 'string', format: 'email', max_len: 3 }), 'a@b.co')).toStrictEqual({ code: 'out_of_domain', reason: 'longer than 3 UTF-8 bytes' });
    expect(paramValueViolation(decl({ type: 'string', format: 'email', values: ['x@y.zz'] }), 'a@b.co')).toStrictEqual({ code: 'out_of_domain', reason: 'not one of the declared values' });
  });
});

describe('paramValueViolation: object_ref', () => {
  it('is a non-empty id string within max_len UTF-8 bytes and, when declared, its format', async () => {
    const { paramValueViolation } = await fresh();
    const bad = { code: 'bad_type', reason: 'expected a non-empty id string' };
    const d = decl({ type: 'object_ref' });
    expect(paramValueViolation(d, 'obj_1')).toBeNull();
    expect(paramValueViolation(d, 'a')).toBeNull();
    for (const x of ['', 5, null, undefined, {}, ['a'], true, '\ud800', 'a\udc00b']) expect(paramValueViolation(d, x), String(x)).toStrictEqual(bad);
    expect(paramValueViolation(d, 'a'.repeat(1024))).toBeNull();
    expect(paramValueViolation(d, 'a'.repeat(1025))).toStrictEqual({ code: 'out_of_domain', reason: 'longer than 1024 UTF-8 bytes' });
    expect(paramValueViolation(decl({ type: 'object_ref', max_len: 4 }), 'abcd')).toBeNull();
    expect(paramValueViolation(decl({ type: 'object_ref', max_len: 4 }), 'abcde')).toStrictEqual({ code: 'out_of_domain', reason: 'longer than 4 UTF-8 bytes' });
    expect(paramValueViolation(decl({ type: 'object_ref', max_len: 5 }), '\u00e9\u00e9\u00e9')).toStrictEqual({ code: 'out_of_domain', reason: 'longer than 5 UTF-8 bytes' });
    expect(paramValueViolation(decl({ type: 'object_ref', max_len: 6 }), '\u00e9\u00e9\u00e9')).toBeNull();
    expect(paramValueViolation(decl({ type: 'object_ref', format: 'uuid' }), '123e4567-e89b-12d3-a456-426614174000')).toBeNull();
    expect(paramValueViolation(decl({ type: 'object_ref', format: 'uuid' }), 'obj_1')).toStrictEqual({ code: 'out_of_domain', reason: 'not a valid uuid' });
  });
  it('is not the string type: no declared values apply and a number is a type error, not a domain error', async () => {
    const { paramValueViolation } = await fresh();
    expect(paramValueViolation(decl({ type: 'object_ref', values: ['x'] }), 'y')).toBeNull();
    expect(paramValueViolation(decl({ type: 'string' }), '')).toBeNull();
    expect(paramValueViolation(decl({ type: 'string' }), 5)).toStrictEqual({ code: 'bad_type', reason: 'expected a string' });
  });
});

describe('paramValueViolation: datetime', () => {
  const NOT = { code: 'out_of_domain', reason: 'not an RFC 3339 UTC datetime YYYY-MM-DDTHH:MM:SS[.fff]Z' };
  it('accepts a real UTC instant with optional 1..3 fractional digits', async () => {
    const { paramValueViolation } = await fresh();
    const d = decl({ type: 'datetime' });
    for (const x of [
      '2024-02-29T12:00:00Z', '2023-12-31T23:59:59Z', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00.1Z', '2024-01-01T00:00:00.12Z', '2024-01-01T00:00:00.123Z',
      '2000-02-29T00:00:00Z', '1999-12-31T09:09:09Z', '2024-06-30T10:19:20Z', '2024-06-30T19:30:30Z', '2024-06-30T20:45:45Z', '2024-01-31T13:14:15Z', '0001-01-01T00:00:00Z',
    ]) expect(paramValueViolation(d, x), x).toBeNull();
  });
  it('refuses a malformed instant or a day that is not on the calendar', async () => {
    const { paramValueViolation } = await fresh();
    const d = decl({ type: 'datetime' });
    for (const x of [
      '2023-02-29T12:00:00Z', '2100-02-29T12:00:00Z', '2024-02-30T12:00:00Z', '2024-13-01T12:00:00Z', '2024-00-10T12:00:00Z', '2024-04-31T12:00:00Z', '2024-01-00T12:00:00Z', '0000-01-01T00:00:00Z',
      '2024-01-01T24:00:00Z', '2024-01-01T25:00:00Z', '2024-01-01T12:60:00Z', '2024-01-01T12:00:60Z', '2024-01-01T12:00:00+00:00', '2024-01-01 12:00:00Z', '2024-01-01T12:00:00',
      '2024-01-01T12:00:00.1234Z', '2024-01-01T12:00:00.Z', '2024-01-01T12:00Z', '24-01-01T12:00:00Z', '2024-1-01T12:00:00Z', '2024-01-1T12:00:00Z', '2024-01-01t12:00:00Z', '2024-01-01T12:00:00z',
      ' 2024-01-01T12:00:00Z', '2024-01-01T12:00:00Z ', '2024-01-01T12:00:00Zx', 'x2024-01-01T12:00:00Z', '2024-01-01T12:00:00Z\n', '2024-01-01T7:00:00Z', '', 'now', '2024-01-01',
      'a024-01-01T12:00:00Z', '2024-0a-01T12:00:00Z', '2024-01-0aT12:00:00Z', '2024-01-01T1a:00:00Z', '2024-01-01T12:0a:00Z', '2024-01-01T12:00:0aZ', '2024-01-01T12:00:00.aZ', '2024-01-01T30:00:00Z', '2024-01-01T12:70:00Z', '2024-01-01T12:00:70Z',
    ]) expect(paramValueViolation(d, x), JSON.stringify(x)).toStrictEqual(NOT);
  });
  it('a non-string is a type error', async () => {
    const { paramValueViolation } = await fresh();
    const d = decl({ type: 'datetime' });
    for (const x of [5, null, undefined, {}, [], true, new Date(0)]) expect(paramValueViolation(d, x), String(x)).toStrictEqual({ code: 'bad_type', reason: 'expected an RFC 3339 UTC string' });
  });
});

describe('paramValueViolation: duration and integer bounds', () => {
  it('a duration is a non-negative safe integer within its optional bounds', async () => {
    const { paramValueViolation } = await fresh();
    const d = decl({ type: 'duration' });
    expect(paramValueViolation(d, 0)).toBeNull();
    expect(paramValueViolation(d, 1)).toBeNull();
    expect(paramValueViolation(d, Number.MAX_SAFE_INTEGER)).toBeNull();
    for (const x of [1.5, '5', null, undefined, NaN, Infinity, -0, Number.MAX_SAFE_INTEGER + 1, true]) expect(paramValueViolation(d, x), String(x)).toStrictEqual({ code: 'bad_type', reason: 'expected a safe integer (milliseconds)' });
    for (const x of [-1, -1000]) expect(paramValueViolation(d, x), String(x)).toStrictEqual({ code: 'out_of_domain', reason: 'a duration is not negative' });
    const b = decl({ type: 'duration', min: 5, max: 10 });
    expect(paramValueViolation(b, 5)).toBeNull();
    expect(paramValueViolation(b, 10)).toBeNull();
    expect(paramValueViolation(b, 7)).toBeNull();
    expect(paramValueViolation(b, 4)).toStrictEqual({ code: 'out_of_domain', reason: 'below min 5' });
    expect(paramValueViolation(b, 11)).toStrictEqual({ code: 'out_of_domain', reason: 'above max 10' });
    expect(paramValueViolation(decl({ type: 'duration', min: 5 }), 4)).toStrictEqual({ code: 'out_of_domain', reason: 'below min 5' });
    expect(paramValueViolation(decl({ type: 'duration', min: 5 }), 1_000_000)).toBeNull();
    expect(paramValueViolation(decl({ type: 'duration', max: 5 }), 6)).toStrictEqual({ code: 'out_of_domain', reason: 'above max 5' });
    expect(paramValueViolation(decl({ type: 'duration', max: 5 }), 0)).toBeNull();
    expect(paramValueViolation(decl({ type: 'duration', min: 0 }), 0)).toBeNull();
    expect(paramValueViolation(decl({ type: 'duration', max: 0 }), 0)).toBeNull();
    expect(paramValueViolation(decl({ type: 'duration', max: 0 }), 1)).toStrictEqual({ code: 'out_of_domain', reason: 'above max 0' });
  });
  it('an integer without bounds takes any safe integer; with bounds both ends are inclusive', async () => {
    const { paramValueViolation } = await fresh();
    const d = decl({ type: 'integer' });
    expect(paramValueViolation(d, -5)).toBeNull();
    expect(paramValueViolation(d, 0)).toBeNull();
    expect(paramValueViolation(d, 1.5)).toStrictEqual({ code: 'bad_type', reason: 'expected a safe integer' });
    const b = decl({ type: 'integer', min: -2, max: 2 });
    for (const x of [-2, -1, 0, 2]) expect(paramValueViolation(b, x), String(x)).toBeNull();
    expect(paramValueViolation(b, -3)).toStrictEqual({ code: 'out_of_domain', reason: 'below min -2' });
    expect(paramValueViolation(b, 3)).toStrictEqual({ code: 'out_of_domain', reason: 'above max 2' });
    expect(paramValueViolation(decl({ type: 'integer', min: 0 }), -1)).toStrictEqual({ code: 'out_of_domain', reason: 'below min 0' });
    expect(paramValueViolation(decl({ type: 'integer', max: 0 }), 1)).toStrictEqual({ code: 'out_of_domain', reason: 'above max 0' });
  });
});

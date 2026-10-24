/** 0.4.2 mutation kills: the ASCII form of a payee (every branch and the \u fallback), lookalike refusal texts, other-script payees. */
import { describe, expect, it } from 'vitest';
import { asciiForm, cibaActionFromStepUp } from './index';

const step = (payee: string): never =>
  ({ id: 's1', verb: 'wire.send', resource: 'acct:a', params: { amount: '10', currency: 'USD', payee }, tier: 3, reason: 'r', goalCommit: 'G'.repeat(43), lineage: {}, r: 0.9, requestedAt: 0 }) as never;

describe('asciiForm', () => {
  it('ASCII (any length, any case) is returned untouched, word by word and whole', () => {
    expect(asciiForm('Bob Smith')).toBe('Bob Smith');
    expect(asciiForm('Bob')).toBe('Bob');
    expect(asciiForm('')).toBe('');
  });
  it('only the non-ASCII words are converted; ASCII words keep their case', () => {
    expect(asciiForm('Bob bücher')).toBe('Bob xn--bcher-kva');
  });
  it('a word IDNA refuses falls back to \\u{hex} for every character above 0x7e, ASCII (0x7e included) kept, joined with no separator', () => {
    expect(asciiForm('é<')).toBe('\\u{e9}<');
    expect(asciiForm('é~<')).toBe('\\u{e9}~<');
    expect(asciiForm('é<é')).toBe('\\u{e9}<\\u{e9}');
    expect(asciiForm('日<')).toBe('\\u{65e5}<');
  });
});

describe('payee look-alike refusals: exact reasons', () => {
  it('combining marks', () => {
    expect(() => cibaActionFromStepUp(step('bo̸b'))).toThrow('ciba: the payee contains combining marks and cannot be shown unambiguously');
  });
  it('compatibility / fullwidth characters', () => {
    expect(() => cibaActionFromStepUp(step('ｂｏｂ'))).toThrow('ciba: the payee contains compatibility/fullwidth characters that imitate plain ones');
  });
  it('mixed writing systems', () => {
    expect(() => cibaActionFromStepUp(step('Pаypal'))).toThrow('ciba: the payee mixes writing systems (a homograph risk); refusing so the person never approves a look-alike');
  });
  it('letters of two scripts outside the known groups are two different systems; a single repeated one is one', () => {
    expect(() => cibaActionFromStepUp(step('አበ'))).toThrow('ciba: the payee mixes writing systems');
    expect(cibaActionFromStepUp(step('አአ')).payee).toBe('አአ');
  });
});

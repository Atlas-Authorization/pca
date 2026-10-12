import { describe, expect, it } from 'vitest';
import { asciiForm, toCibaAuthRequest } from './index';

// R4-13: confusable / mixed-script / combining / compatibility payees must not be shown as the text they imitate.
const mk = (payee: string): never =>
  ({ id: 's1', verb: 'wire.send', resource: 'acct:a', params: { amount: '10', currency: 'USD', payee }, tier: 3, reason: 'r', goalCommit: 'G'.repeat(43), lineage: {}, r: 0.9, requestedAt: 0 }) as never;

describe('R4-13 payee lookalikes', () => {
  it.each([
    ['Cyrillic a inside a Latin word', 'Pаypal'],
    ['Greek omicron inside a Latin word', 'Gοοgle'],
    ['Latin + Cyrillic + Greek mixture', 'abаο'],
    ['combining marks left after NFC', 'bo̸b'],
    ['fullwidth Latin', 'ｂｏｂ'],
    ['ligature (NFKC differs)', 'oﬃce'],
    ['circled letters', 'ⓑⓞⓑ'],
  ])('refuses %s', (_n, payee) => {
    expect(() => toCibaAuthRequest(mk(payee))).toThrow(RangeError);
  });

  it('plain ASCII payees render exactly as before (no extra annotation)', () => {
    const m = toCibaAuthRequest(mk('Acme Corp')).binding_message;
    expect(m).toContain('10 USD to "Acme Corp" on acct:a');
    expect(m).not.toMatch(/non-ASCII/);
  });

  it('single-script Latin with diacritics (NFC-composed) is allowed and shown with its ASCII form', () => {
    const m = toCibaAuthRequest(mk('José Müller')).binding_message;
    expect(m).toContain('to "José Müller" [non-ASCII name; ASCII form: ');
    expect(m).toContain('xn--');
  });

  it('a WHOLE-script look-alike (all Cyrillic "apple") is allowed only with its punycode form beside it', () => {
    const fake = 'аррӏе'; // а р р ӏ е
    const m = toCibaAuthRequest(mk(fake)).binding_message;
    expect(m).toContain(`"${fake}"`);
    expect(m).toContain('xn--');
  });

  it('asciiForm: ASCII passes through; non-ASCII words become punycode', () => {
    expect(asciiForm('bob')).toBe('bob');
    expect(asciiForm('bücher shop')).toMatch(/^xn--bcher-kva shop$/);
  });
});

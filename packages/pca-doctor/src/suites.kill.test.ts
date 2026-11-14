import { SIG_SUITES } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { PQ_REMEDIATION, SUITES_REMEDIATION, checkAllowedSuites, checkPqBinding } from './suites';

const SKIP_DETAIL = 'no verifier configuration given (config verifier.*)';
const ID = 'A'.repeat(43);
const known = Object.keys(SIG_SUITES);
const pqSuites = known.filter((k) => (SIG_SUITES as Record<string, { needsPqPk: boolean }>)[k]!.needsPqPk);

describe('checkAllowedSuites', () => {
  it('skips without verifier configuration', () => {
    expect(checkAllowedSuites({})).toStrictEqual({ id: 'suites.allowed', status: 'skip', detail: SKIP_DETAIL });
  });

  it('warns on an unset list, naming every registered suite', () => {
    expect(checkAllowedSuites({ verifier: {} })).toStrictEqual({
      id: 'suites.allowed',
      status: 'warn',
      detail: `allowedSuites is unset: every registered suite is accepted (${known.length}: ${known.join(', ')})`,
      remediation: SUITES_REMEDIATION,
    });
  });

  it('fails on an empty or non-list value', () => {
    for (const l of [[], 'ed25519', 5]) {
      expect(checkAllowedSuites({ verifier: { allowedSuites: l as never } })).toStrictEqual({
        id: 'suites.allowed',
        status: 'fail',
        detail: 'allowedSuites is empty or not a list: no PCActn can verify',
        remediation: SUITES_REMEDIATION,
      });
    }
  });

  it('fails on names outside the registry (including non-strings), listing them and the known ones', () => {
    expect(checkAllowedSuites({ verifier: { allowedSuites: ['ed25519', 'rsa', 'dsa'] } })).toStrictEqual({
      id: 'suites.allowed',
      status: 'fail',
      detail: `allowedSuites names suite(s) outside the registry: rsa, dsa (known: ${known.join(', ')})`,
      remediation: SUITES_REMEDIATION,
    });
    // a number that would coerce to a registry key is still not a suite name
    const r = checkAllowedSuites({ verifier: { allowedSuites: [5 as never] } }, { '5': {} });
    expect(r).toMatchObject({ status: 'fail', detail: 'allowedSuites names suite(s) outside the registry: 5 (known: 5)' });
    // inherited properties are not suites
    expect(checkAllowedSuites({ verifier: { allowedSuites: ['toString'] } }).status).toBe('fail');
  });

  it('passes with the list in the detail', () => {
    expect(checkAllowedSuites({ verifier: { allowedSuites: ['ed25519', known[known.length - 1]!] } })).toStrictEqual({
      id: 'suites.allowed',
      status: 'pass',
      detail: `allowedSuites = ed25519, ${known[known.length - 1]!}`,
    });
  });
});

describe('checkPqBinding', () => {
  const fail = (detail: string) => ({ id: 'suites.pq-binding', status: 'fail', detail, remediation: PQ_REMEDIATION });

  it('skips without verifier configuration', () => {
    expect(checkPqBinding({})).toStrictEqual({ id: 'suites.pq-binding', status: 'skip', detail: SKIP_DETAIL });
  });

  it('fails on allowUnboundPq', () => {
    expect(checkPqBinding({ verifier: { allowUnboundPq: true } })).toStrictEqual(
      fail('allowUnboundPq is set: PQ keys are read from the artifact, so a hybrid gives no protection against an Ed25519 forger and a pure-PQ hop can be signed by any key'),
    );
  });

  it('fails on a pqPins value that is not an object', () => {
    const msg = 'pqPins is not an object of { ed25519 identity: pq public key }';
    for (const p of [null, 'abc', 5, [], ['x']]) {
      expect(checkPqBinding({ verifier: { pqPins: p as never } })).toStrictEqual(fail(msg));
    }
  });

  it('fails on malformed pin entries, naming the keys', () => {
    const bad = (pins: Record<string, unknown>, keys: string) =>
      expect(checkPqBinding({ verifier: { pqPins: pins as never } })).toStrictEqual(
        fail(`pqPins has malformed entries (key must be a 43-char base64url Ed25519 identity, value a base64url PQ key): ${keys}`),
      );
    bad({ short: 'AbC' }, 'short');
    bad({ [ID]: 5 }, ID); // a number would pass the base64url test once coerced
    bad({ [ID]: 'not base64!' }, ID);
    bad({ ['B'.repeat(43)]: 'ok', k1: 'x', k2: 'y' }, 'k1, k2');
  });

  it('passes with no PQ suite accepted, even if pins are missing', () => {
    expect(checkPqBinding({ verifier: { allowedSuites: ['ed25519', 'not-a-suite'] } })).toStrictEqual({
      id: 'suites.pq-binding',
      status: 'pass',
      detail: 'no post-quantum suite is accepted (Ed25519 only: no PQ binding needed, and no PQ protection)',
    });
  });

  it('warns on PQ suites without pins or stored root; an empty pins object counts as no pins', () => {
    const detail = `post-quantum suite(s) accepted (${pqSuites.join(', ')}) with neither pqPins nor a stored trustedRoot: a non-Ed25519 root is refused (fail closed) or its PQ key is not pinned`;
    const w = { id: 'suites.pq-binding', status: 'warn', detail, remediation: PQ_REMEDIATION };
    expect(checkPqBinding({ verifier: {} })).toStrictEqual(w);
    expect(checkPqBinding({ verifier: { pqPins: {} } })).toStrictEqual(w);
    expect(checkPqBinding({ verifier: { trustedRoot: false } })).toStrictEqual(w);
  });

  it('passes when bound by pins or by the stored root', () => {
    const one = pqSuites[0]!;
    expect(checkPqBinding({ verifier: { allowedSuites: [one, one], pqPins: { [ID]: 'AbC_-1', ['C'.repeat(43)]: 'zz' } } })).toStrictEqual({
      id: 'suites.pq-binding',
      status: 'pass',
      detail: `PQ suites (${one}, ${one}) are bound: 2 pin(s); allowUnboundPq off`,
    });
    expect(checkPqBinding({ verifier: { allowedSuites: [one], trustedRoot: true } })).toStrictEqual({
      id: 'suites.pq-binding',
      status: 'pass',
      detail: `PQ suites (${one}) are bound: stored trustedRoot; allowUnboundPq off`,
    });
  });
});

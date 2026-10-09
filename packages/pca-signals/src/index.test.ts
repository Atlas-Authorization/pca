import { describe, it, expect } from 'vitest';
import { generateKeyPair } from 'jose';
import {
  EVENT_TYPES,
  buildSET,
  verifySET,
  createRevocationState,
  applySET,
  isRevoked,
  streamProcessor,
  type GrantRevokedEvent,
  type SetEvents,
} from './index';

const ISS = 'https://transmitter.atlasauth.net';
const AUD = 'https://rs.acme.com';

async function keys() {
  // EdDSA default curve is Ed25519.
  return generateKeyPair('EdDSA');
}

function grantRevoked(grantRef: string, ts: number, agent?: string): SetEvents {
  const ev: GrantRevokedEvent = { grant_ref: grantRef, reason: 'policy_violation', event_timestamp: ts };
  if (agent !== undefined) {
    ev.agent = agent;
  }
  return { [EVENT_TYPES.grantRevoked]: ev };
}

function killSwitch(agent: string, ts: number): SetEvents {
  return { [EVENT_TYPES.killSwitch]: { agent, reason: 'compromised', event_timestamp: ts } };
}

describe('buildSET -> verifySET round-trip', () => {
  it('round-trips a grant-revoked event (RFC 8417 SET + CAEP-style payload)', async () => {
    const { publicKey, privateKey } = await keys();
    const set = await buildSET({
      issuer: ISS,
      audience: AUD,
      subject: 'user_123',
      key: privateKey,
      events: grantRevoked('grant_1', 1000, 'bot_a'),
    });
    expect(set.split('.')).toHaveLength(3);

    const parsed = await verifySET(set, publicKey, { issuer: ISS, audience: AUD });
    expect(parsed.iss).toBe(ISS);
    expect(typeof parsed.jti).toBe('string');
    expect(parsed.jti.length).toBeGreaterThan(0);
    expect(parsed.sub).toBe('user_123');

    const ev = parsed.events[EVENT_TYPES.grantRevoked];
    expect(ev).toBeDefined();
    expect(ev?.grant_ref).toBe('grant_1');
    expect(ev?.agent).toBe('bot_a');
    expect(ev?.reason).toBe('policy_violation');
    expect(ev?.event_timestamp).toBe(1000);
  });

  it('carries the RFC 8417 secevent+jwt header typ and a numeric iat', async () => {
    const { publicKey, privateKey } = await keys();
    const set = await buildSET({ issuer: ISS, audience: AUD, key: privateKey, events: grantRevoked('g', 1) });
    const parsed = await verifySET(set, publicKey);
    expect(typeof parsed.payload.iat).toBe('number');
    // default verify enforces the typ; disabling it also succeeds
    await expect(verifySET(set, publicKey, { requireTyp: false })).resolves.toBeDefined();
  });

  it('round-trips a CAEP session-revoked event', async () => {
    const { publicKey, privateKey } = await keys();
    const set = await buildSET({
      issuer: ISS,
      audience: AUD,
      key: privateKey,
      events: {
        [EVENT_TYPES.sessionRevoked]: {
          subject: { format: 'opaque', id: 'sess_9' },
          event_timestamp: 42,
          reason_admin: 'token theft',
        },
      },
    });
    const parsed = await verifySET(set, publicKey);
    expect(parsed.events[EVENT_TYPES.sessionRevoked]?.event_timestamp).toBe(42);
  });
});

describe('verifySET rejects invalid tokens', () => {
  it('rejects a tampered SET', async () => {
    const { publicKey, privateKey } = await keys();
    const set = await buildSET({ issuer: ISS, audience: AUD, key: privateKey, events: grantRevoked('g', 1) });
    const dot = set.indexOf('.');
    // flip a byte in the signed payload segment (header.<here>.sig) — breaks the signature
    const i = dot + 3;
    const flipped = set[i] === 'A' ? 'B' : 'A';
    const tampered = `${set.slice(0, i)}${flipped}${set.slice(i + 1)}`;
    await expect(verifySET(tampered, publicKey)).rejects.toThrow();
  });

  it('rejects a SET verified with the wrong key', async () => {
    const { privateKey } = await keys();
    const { publicKey: otherPublic } = await keys();
    const set = await buildSET({ issuer: ISS, audience: AUD, key: privateKey, events: grantRevoked('g', 1) });
    await expect(verifySET(set, otherPublic)).rejects.toThrow();
  });

  it('rejects a wrong-audience SET when audience is required', async () => {
    const { publicKey, privateKey } = await keys();
    const set = await buildSET({ issuer: ISS, audience: AUD, key: privateKey, events: grantRevoked('g', 1) });
    await expect(verifySET(set, publicKey, { audience: 'https://evil.example' })).rejects.toThrow();
  });
});

describe('subscriber revocation state', () => {
  it('applySET makes isRevoked(grantRef) true', async () => {
    const { publicKey, privateKey } = await keys();
    const parsed = await verifySET(
      await buildSET({ issuer: ISS, audience: AUD, key: privateKey, events: grantRevoked('g-42', 500) }),
      publicKey,
    );
    const state = createRevocationState();
    expect(isRevoked(state, 'g-42')).toBe(false);
    applySET(state, parsed);
    expect(isRevoked(state, 'g-42')).toBe(true);
    // an unrelated grant is still live
    expect(isRevoked(state, 'g-99')).toBe(false);
  });

  it('a kill-switch revokes every grant for that agent', async () => {
    const { publicKey, privateKey } = await keys();
    const parsed = await verifySET(
      await buildSET({ issuer: ISS, audience: AUD, key: privateKey, events: killSwitch('agent_x', 900) }),
      publicKey,
    );
    const state = createRevocationState();
    applySET(state, parsed);
    expect(isRevoked(state, 'any-grant', 'agent_x')).toBe(true);
    expect(isRevoked(state, 'another-grant', 'agent_x')).toBe(true);
    // a different agent is untouched
    expect(isRevoked(state, 'some-grant', 'other_agent')).toBe(false);
    // and without naming the agent, an unknown grant is still live
    expect(isRevoked(state, 'some-grant')).toBe(false);
  });

  it('an out-of-order older event does not un-revoke (respects event_timestamp)', async () => {
    const { publicKey, privateKey } = await keys();
    const newer = await verifySET(
      await buildSET({ issuer: ISS, audience: AUD, key: privateKey, events: killSwitch('bot', 1000) }),
      publicKey,
    );
    const older = await verifySET(
      await buildSET({ issuer: ISS, audience: AUD, key: privateKey, events: killSwitch('bot', 10) }),
      publicKey,
    );

    // apply out of order: newer first, then the stale older event
    const state = createRevocationState();
    applySET(state, newer);
    applySET(state, older);
    expect(isRevoked(state, 'g', 'bot')).toBe(true);
    // the stored timestamp must NOT have regressed to the stale value
    expect(state.killedAgents.get('bot')).toBe(1000);

    // streamProcessor folds by event_timestamp order and yields the same monotone result
    const folded = streamProcessor([older, newer]);
    expect(isRevoked(folded, 'g', 'bot')).toBe(true);
    expect(folded.killedAgents.get('bot')).toBe(1000);
  });

  it('streamProcessor folds a mixed sequence into one state', async () => {
    const { publicKey, privateKey } = await keys();
    const sets = await Promise.all([
      buildSET({ issuer: ISS, audience: AUD, key: privateKey, events: grantRevoked('g-1', 100) }),
      buildSET({ issuer: ISS, audience: AUD, key: privateKey, events: killSwitch('bot_b', 200) }),
      buildSET({ issuer: ISS, audience: AUD, key: privateKey, events: grantRevoked('g-2', 300) }),
    ]);
    const parsed = await Promise.all(sets.map((s) => verifySET(s, publicKey)));
    const state = streamProcessor(parsed);
    expect(isRevoked(state, 'g-1')).toBe(true);
    expect(isRevoked(state, 'g-2')).toBe(true);
    expect(isRevoked(state, 'x', 'bot_b')).toBe(true);
    expect(isRevoked(state, 'g-3')).toBe(false);
  });
});

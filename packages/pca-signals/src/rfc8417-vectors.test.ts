import { generateKeyPair, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';
import { createInMemorySetReplayStore, createRevocationState, receiveSET } from './index';

// Examples reproduced verbatim from RFC 8417 (July 2018): Figures 1, 2, 5 (claim sets) and Figure 6 (the unsecured SET).
const FIG1 = {
  iss: 'https://scim.example.com',
  iat: 1458496025,
  jti: '3d0c3cf797584bd193bd0fb1bd4e7d30',
  aud: ['https://jhub.example.com/Feeds/98d52461fa5bbc879593b7754', 'https://jhub.example.com/Feeds/5d7604516b1d08641d7676ee7'],
  sub: 'https://scim.example.com/Users/44f6142df96bd6ab61e7521d9',
  events: {
    'urn:ietf:params:scim:event:passwordReset': { id: '44f6142df96bd6ab61e7521d9' },
    'https://example.com/scim/event/passwordResetExt': { resetAttempts: 5 },
  },
};
const FIG2 = {
  iss: 'https://server.example.com',
  sub: '248289761001',
  aud: 's6BhdRkqt3',
  iat: 1471566154,
  jti: 'bWJq',
  sid: '08a5019c-17e1-4977-8f42-65a12843ea02',
  events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
};
const FIG5 = {
  iss: 'https://scim.example.com',
  iat: 1458496404,
  jti: '4d3559ec67504aaba65d40b0363faad8',
  aud: ['https://scim.example.com/Feeds/98d52461fa5bbc879593b7754', 'https://scim.example.com/Feeds/5d7604516b1d08641d7676ee7'],
  events: {
    'urn:ietf:params:scim:event:create': {
      ref: 'https://scim.example.com/Users/44f6142df96bd6ab61e7521d9',
      attributes: ['id', 'name', 'userName', 'password', 'emails'],
    },
  },
};
const FIG6_HEADER = 'eyJ0eXAiOiJzZWNldmVudCtqd3QiLCJhbGciOiJub25lIn0';
const FIG6_PAYLOAD =
  'eyJpc3MiOiJodHRwczovL3NjaW0uZXhhbXBsZS5jb20iLCJpYXQiOjE0NTg0OTY0MDQsImp0aSI6IjRkMzU1OWVjNjc1MDRhYWJhNjVkNDBiMDM2M2ZhYWQ4IiwiYXVkIjpbImh0dHBzOi8vc2NpbS5leGFtcGxlLmNvbS9GZWVkcy85OGQ1MjQ2MWZhNWJiYzg3OTU5M2I3NzU0IiwiaHR0cHM6Ly9zY2ltLmV4YW1wbGUuY29tL0ZlZWRzLzVkNzYwNDUxNmIxZDA4NjQxZDc2NzZlZTciXSwiZXZlbnRzIjp7InVybjppZXRmOnBhcmFtczpzY2ltOmV2ZW50OmNyZWF0ZSI6eyJyZWYiOiJodHRwczovL3NjaW0uZXhhbXBsZS5jb20vVXNlcnMvNDRmNjE0MmRmOTZiZDZhYjYxZTc1MjFkOSIsImF0dHJpYnV0ZXMiOlsiaWQiLCJuYW1lIiwidXNlck5hbWUiLCJwYXNzd29yZCIsImVtYWlscyJdfX19';

describe('RFC 8417 examples', () => {
  it('Figure 6 payload decodes to the Figure 5 claim set; the header is the documented one', () => {
    expect(JSON.parse(Buffer.from(FIG6_PAYLOAD, 'base64url').toString())).toEqual(FIG5);
    expect(Buffer.from(FIG6_HEADER, 'base64url').toString()).toBe('{"typ":"secevent+jwt","alg":"none"}');
  });

  it('Figure 6 (the unsecured SET) is refused (empty signature fails the canonical-spelling gate, alg none is never accepted)', async () => {
    const { publicKey } = await generateKeyPair('EdDSA');
    const r = await receiveSET(`${FIG6_HEADER}.${FIG6_PAYLOAD}.`, publicKey, {
      issuer: FIG5.iss,
      audience: FIG5.aud[0] as string,
      replayStore: createInMemorySetReplayStore(),
      state: createRevocationState(),
      maxAgeSec: 3600,
      nowSec: FIG5.iat + 1,
    });
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.code).toBe('malformed');
  });

  it.each([
    ['Figure 1 (SCIM password reset)', FIG1, 'https://jhub.example.com/Feeds/5d7604516b1d08641d7676ee7'],
    ['Figure 2 (back-channel logout, empty event object)', FIG2, 's6BhdRkqt3'],
    ['Figure 5 (SCIM create)', FIG5, 'https://scim.example.com/Feeds/98d52461fa5bbc879593b7754'],
  ])('%s: the claim set, signed EdDSA, is accepted; unknown event types are carried', async (_n, claims, aud) => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA');
    const jws = await new SignJWT(claims).setProtectedHeader({ alg: 'EdDSA', typ: 'secevent+jwt' }).sign(privateKey);
    const r = await receiveSET(jws, publicKey, {
      issuer: claims.iss,
      audience: aud,
      replayStore: createInMemorySetReplayStore(),
      state: createRevocationState(),
      maxAgeSec: 3600,
      nowSec: claims.iat + 1,
    });
    expect(r.ok).toBe(true);
    expect(r.ok && r.parsed.events).toEqual(claims.events);
    expect(r.ok && r.parsed.jti).toBe(claims.jti);
  });
});

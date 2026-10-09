import { hexToBytes } from '@noble/curves/abstract/utils';
import { describe, expect, it } from 'vitest';
import {
  API_ID,
  CIPHERSUITE_ID,
  createGenerators,
  generateKeyPair,
  mapMessageToScalarAsHash,
  messagesToScalars,
  proofGen,
  proofVerify,
  R,
  sign,
  skFromBytes,
  skToPk,
  verify,
} from './bbs';

const TEXT = new TextEncoder();
const msg = (s: string): Uint8Array => TEXT.encode(s);
function nn<T>(v: T | undefined): T {
  if (v === undefined) throw new Error('unexpected undefined');
  return v;
}

function fourMessages(): Uint8Array[] {
  return [msg('issuer=plat_forumulate'), msg('holder=agent-7'), msg('scope=search:read'), msg('budget<=100')];
}

describe('BBS core (BLS12-381-SHA-256)', () => {
  it('exposes the chosen ciphersuite identifier', () => {
    expect(CIPHERSUITE_ID).toBe('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_');
    expect(API_ID).toBe('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_');
  });

  it('signs a 4-message credential and Verify passes', () => {
    const { sk, pk } = generateKeyPair();
    const messages = fourMessages();
    const header = msg('ctx:atlas-pca');
    const signature = sign(sk, pk, header, messages);
    expect(signature.length).toBe(80); // 48-byte G1 point + 32-byte scalar
    expect(verify(pk, signature, header, messages)).toBe(true);
  });

  it('Verify fails when a message is tampered', () => {
    const { sk, pk } = generateKeyPair();
    const messages = fourMessages();
    const header = msg('ctx:atlas-pca');
    const signature = sign(sk, pk, header, messages);

    const tampered = [...messages];
    tampered[2] = msg('scope=search:write'); // widen the scope
    expect(verify(pk, signature, header, tampered)).toBe(false);
  });

  it('Verify fails under the wrong header or wrong key', () => {
    const { sk, pk } = generateKeyPair();
    const other = generateKeyPair();
    const messages = fourMessages();
    const signature = sign(sk, pk, msg('h1'), messages);
    expect(verify(pk, signature, msg('h2'), messages)).toBe(false);
    expect(verify(other.pk, signature, msg('h1'), messages)).toBe(false);
  });

  it('ProofGen discloses a subset and ProofVerify passes with only the disclosed messages', () => {
    const { sk, pk } = generateKeyPair();
    const messages = fourMessages();
    const header = msg('ctx:atlas-pca');
    const ph = msg('nonce:action-123');
    const signature = sign(sk, pk, header, messages);

    // Disclose indexes 0 and 2 (issuer + scope); hide holder and budget.
    const disclosedIndexes = [0, 2];
    const proof = proofGen(pk, signature, header, ph, messages, disclosedIndexes);
    const disclosedMessages = disclosedIndexes.map((i) => nn(messages[i]));

    expect(proofVerify(pk, proof, header, ph, disclosedMessages, disclosedIndexes)).toBe(true);
  });

  it('ProofVerify fails if a disclosed message is altered', () => {
    const { sk, pk } = generateKeyPair();
    const messages = fourMessages();
    const header = msg('ctx');
    const ph = msg('nonce');
    const signature = sign(sk, pk, header, messages);
    const disclosedIndexes = [0, 2];
    const proof = proofGen(pk, signature, header, ph, messages, disclosedIndexes);

    const altered = [nn(messages[0]), msg('scope=admin:*')];
    expect(proofVerify(pk, proof, header, ph, altered, disclosedIndexes)).toBe(false);
  });

  it('ProofVerify fails if an index is lied about', () => {
    const { sk, pk } = generateKeyPair();
    const messages = fourMessages();
    const header = msg('ctx');
    const ph = msg('nonce');
    const signature = sign(sk, pk, header, messages);
    const disclosedIndexes = [0, 2];
    const disclosedMessages = disclosedIndexes.map((i) => nn(messages[i]));
    const proof = proofGen(pk, signature, header, ph, messages, disclosedIndexes);

    // Claim the same disclosed messages sit at different indexes.
    expect(proofVerify(pk, proof, header, ph, disclosedMessages, [1, 3])).toBe(false);
  });

  it('ProofVerify fails under a different presentation header (binding)', () => {
    const { sk, pk } = generateKeyPair();
    const messages = fourMessages();
    const header = msg('ctx');
    const signature = sign(sk, pk, header, messages);
    const disclosedIndexes = [0];
    const disclosedMessages = [nn(messages[0])];
    const proof = proofGen(pk, signature, header, msg('nonce:A'), messages, disclosedIndexes);
    expect(proofVerify(pk, proof, header, msg('nonce:B'), disclosedMessages, disclosedIndexes)).toBe(false);
  });

  it('UNLINKABILITY: two proofs of the same credential/disclosure differ but both verify', () => {
    const { sk, pk } = generateKeyPair();
    const messages = fourMessages();
    const header = msg('ctx');
    const ph = msg('nonce');
    const signature = sign(sk, pk, header, messages);
    const disclosedIndexes = [2];
    const disclosedMessages = [nn(messages[2])];

    const p1 = proofGen(pk, signature, header, ph, messages, disclosedIndexes);
    const p2 = proofGen(pk, signature, header, ph, messages, disclosedIndexes);

    expect(Buffer.from(p1).equals(Buffer.from(p2))).toBe(false); // re-randomized
    expect(proofVerify(pk, p1, header, ph, disclosedMessages, disclosedIndexes)).toBe(true);
    expect(proofVerify(pk, p2, header, ph, disclosedMessages, disclosedIndexes)).toBe(true);
  });

  it('full disclosure (reveal all) still proves and verifies', () => {
    const { sk, pk } = generateKeyPair();
    const messages = fourMessages();
    const header = msg('ctx');
    const ph = msg('nonce');
    const signature = sign(sk, pk, header, messages);
    const idx = [0, 1, 2, 3];
    const proof = proofGen(pk, signature, header, ph, messages, idx);
    expect(proofVerify(pk, proof, header, ph, messages, idx)).toBe(true);
  });

  it('messages_to_scalars and MapMessageToScalarAsHash agree and land in [0, r)', () => {
    const messages = fourMessages();
    const scalars = messagesToScalars(messages);
    expect(scalars).toHaveLength(4);
    for (let i = 0; i < messages.length; i++) {
      const s = nn(scalars[i]);
      expect(s).toBe(mapMessageToScalarAsHash(nn(messages[i])));
      expect(s >= 0n && s < R).toBe(true);
    }
  });

  it('create_generators is deterministic and returns distinct points', () => {
    const a = createGenerators(5);
    const b = createGenerators(5);
    expect(a).toHaveLength(5);
    for (let i = 0; i < 5; i++) expect(nn(a[i]).equals(nn(b[i]))).toBe(true);
    // distinct
    expect(nn(a[0]).equals(nn(a[1]))).toBe(false);
  });
});

// Draft test vector (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256, single-message signature).
describe('BBS draft conformance vector', () => {
  const SK = skFromBytes(hexToBytes('60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc'));
  const PK = hexToBytes(
    'a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c',
  );
  const HEADER = hexToBytes('11223344556677889900aabbccddeeff');
  const M1 = hexToBytes('9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02');
  const EXPECTED_SIG =
    '84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0';

  it('derives the published public key from the secret key', () => {
    expect(Buffer.from(skToPk(SK)).toString('hex')).toBe(Buffer.from(PK).toString('hex'));
  });

  it('produces the published single-message signature and verifies it', () => {
    const signature = sign(SK, PK, HEADER, [M1]);
    expect(Buffer.from(signature).toString('hex')).toBe(EXPECTED_SIG);
    expect(verify(PK, signature, HEADER, [M1])).toBe(true);
  });
});

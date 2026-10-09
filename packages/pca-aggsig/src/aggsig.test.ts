import { bls12_381 } from '@noble/curves/bls12-381';
import { bytesToHex } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';
import {
  type BlsKeyPair,
  PUBLIC_KEY_LENGTH,
  SIGNATURE_LENGTH,
  aggregate,
  aggregateVerify,
  fastAggregateVerify,
  keyGen,
  popProve,
  popVerify,
  publicKeyOf,
  sign,
  verify,
} from './bls';
import {
  type BlsCapability,
  aggregateChainSignatures,
  blsDelegate,
  blsPublicKey,
  mintBlsRoot,
  verifyAggregatedChain,
} from './chain';
import {
  aggregateWitnessCosignatures,
  cosignTreeHead,
  verifyAggregatedWitnessCosignatures,
  verifyWitnessCosignature,
} from './witness';

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

describe('BLS core: sign + verify', () => {
  it('keyGen produces a 48-byte G1 key and signatures verify', () => {
    const kp = keyGen();
    expect(kp.publicKey.length).toBe(PUBLIC_KEY_LENGTH);
    const msg = enc('authorize payment of 100 USD');
    const sig = sign(kp.secretKey, msg);
    expect(sig.length).toBe(SIGNATURE_LENGTH);
    expect(verify(kp.publicKey, msg, sig)).toBe(true);
  });

  it('rejects a wrong message, a wrong key and a tampered signature', () => {
    const kp = keyGen();
    const other = keyGen();
    const msg = enc('the real message');
    const sig = sign(kp.secretKey, msg);
    expect(verify(kp.publicKey, enc('a different message'), sig)).toBe(false);
    expect(verify(other.publicKey, msg, sig)).toBe(false);
    const bad = Uint8Array.from(sig);
    bad[0] = ((bad[0] ?? 0) ^ 0x01) & 0xff;
    expect(verify(kp.publicKey, msg, bad)).toBe(false);
  });
});

describe('aggregate over distinct messages', () => {
  const kps: BlsKeyPair[] = [keyGen(), keyGen(), keyGen()];
  const msgs = [enc('alpha'), enc('beta'), enc('gamma')];
  const sigs = kps.map((kp, i) => sign(kp.secretKey, msgs[i]!));
  const agg = aggregate(sigs);
  const pks = kps.map((kp) => kp.publicKey);

  it('aggregates 3 signatures into one 96-byte aggregate that verifies', () => {
    expect(agg.length).toBe(SIGNATURE_LENGTH);
    expect(aggregateVerify(pks, msgs, agg)).toBe(true);
  });

  it('fails if a message is altered', () => {
    const tampered = [msgs[0]!, enc('BETA'), msgs[2]!];
    expect(aggregateVerify(pks, tampered, agg)).toBe(false);
  });

  it('fails if a public key is altered', () => {
    const tampered = [pks[1]!, pks[1]!, pks[2]!];
    expect(aggregateVerify(tampered, msgs, agg)).toBe(false);
  });

  it('fails if a signature in the aggregate is altered', () => {
    const forgedSig = sign(kps[0]!.secretKey, enc('a forged message'));
    const badAgg = aggregate([forgedSig, sigs[1]!, sigs[2]!]);
    expect(aggregateVerify(pks, msgs, badAgg)).toBe(false);
  });

  it('refuses a repeated message (distinct-message requirement)', () => {
    const dupMsgs = [enc('same'), enc('same'), enc('other')];
    const dupSigs = kps.map((kp, i) => sign(kp.secretKey, dupMsgs[i]!));
    expect(aggregateVerify(pks, dupMsgs, aggregate(dupSigs))).toBe(false);
  });

  it('fails on a length mismatch', () => {
    expect(aggregateVerify(pks, [msgs[0]!, msgs[1]!], agg)).toBe(false);
  });
});

describe('proof-of-possession (rogue-key defence)', () => {
  it('accepts a PoP from the true key holder', () => {
    const kp = keyGen();
    const pop = popProve(kp.secretKey);
    expect(popVerify(kp.publicKey, pop)).toBe(true);
  });

  it('rejects a PoP checked against a different (rogue) key', () => {
    const honest = keyGen();
    const rogue = keyGen();
    const pop = popProve(honest.secretKey);
    // The rogue cannot present a PoP for a key it does not hold the secret for.
    expect(popVerify(rogue.publicKey, pop)).toBe(false);
  });

  it('rejects a rogue key crafted as a function of an honest key', () => {
    // Classic rogue-key construction: pk_rogue = g^a - pk_honest, so pk_honest + pk_rogue = g^a and
    // the attacker can forge an aggregate over the SAME message for {honest, rogue}. FastAggregateVerify
    // would accept it — which is exactly why admission REQUIRES a PoP, and the rogue has none.
    const honest = keyGen();
    const a = bls12_381.utils.randomPrivateKey();
    const honestPt = bls12_381.G1.ProjectivePoint.fromHex(honest.publicKey);
    const roguePt = bls12_381.G1.ProjectivePoint.fromHex(publicKeyOf(a)).subtract(honestPt);
    const roguePk = roguePt.toRawBytes(true);

    const msg = enc('transfer everything');
    // Attacker forges the aggregate as g^a over H(msg): sig = a * H(msg).
    const forgedAgg = sign(a, msg);
    // The forged aggregate DOES pass same-message aggregate verification over {honest, rogue}...
    expect(fastAggregateVerify([honest.publicKey, roguePk], msg, forgedAgg)).toBe(true);
    // ...but the rogue key cannot produce a valid proof-of-possession, so it is never admitted.
    expect(popVerify(roguePk, popProve(a))).toBe(false);
    expect(popVerify(honest.publicKey, popProve(honest.secretKey))).toBe(true);
  });
});

describe('fastAggregateVerify over a shared message', () => {
  const kps = [keyGen(), keyGen(), keyGen(), keyGen()];
  const msg = enc('one shared statement');
  const agg = aggregate(kps.map((kp) => sign(kp.secretKey, msg)));
  const pks = kps.map((kp) => kp.publicKey);

  it('accepts the full signer set', () => {
    expect(fastAggregateVerify(pks, msg, agg)).toBe(true);
  });

  it('rejects a missing signer, an extra signer and a wrong message', () => {
    expect(fastAggregateVerify([pks[0]!, pks[1]!, pks[2]!], msg, agg)).toBe(false);
    expect(fastAggregateVerify([...pks, keyGen().publicKey], msg, agg)).toBe(false);
    expect(fastAggregateVerify(pks, enc('a different statement'), agg)).toBe(false);
  });
});

describe('PCA: BLS-suite aggregated capability chain', () => {
  function buildChain(): { chain: BlsCapability[]; principal: string } {
    const principal = keyGen();
    const agentA = keyGen();
    const agentB = keyGen();
    const principalPub = blsPublicKey(principal.secretKey);

    const root = mintBlsRoot({
      principalSecret: principal.secretKey,
      principalPublic: principalPub,
      holder: blsPublicKey(agentA.secretKey),
      caveats: [{ type: 'scope', value: 'payments:write' }],
    });
    // hop 1: agentA delegates to agentB, attenuating with an amount cap.
    const hop1 = blsDelegate(root, blsPublicKey(agentB.secretKey), [{ type: 'max_amount', limit: 100 }], agentA.secretKey);
    // hop 2: agentB attenuates further (same holder), adding a recipient allow-list.
    const hop2 = blsDelegate(hop1, blsPublicKey(agentB.secretKey), [{ type: 'recipient', allow: ['acct_42'] }], agentB.secretKey);
    return { chain: [root, hop1, hop2], principal: principalPub };
  }

  it('round-trips a 3-hop chain through one aggregate signature', () => {
    const { chain, principal } = buildChain();
    const agg = aggregateChainSignatures(chain);
    expect(agg.length).toBe(SIGNATURE_LENGTH);
    expect(verifyAggregatedChain(chain, agg, principal)).toEqual({ ok: true });
  });

  it('rejects an unexpected root principal', () => {
    const { chain } = buildChain();
    const agg = aggregateChainSignatures(chain);
    const res = verifyAggregatedChain(chain, agg, blsPublicKey(keyGen().secretKey));
    expect(res.ok).toBe(false);
  });

  it('fails when a hop body is tampered (caveat altered)', () => {
    const { chain, principal } = buildChain();
    const agg = aggregateChainSignatures(chain);
    const leaf = chain[2]!;
    const tamperedLeaf: BlsCapability = {
      ...leaf,
      caveats: [...leaf.caveats.slice(0, 2), { type: 'recipient', allow: ['acct_99'] }],
    };
    const tamperedChain = [chain[0]!, chain[1]!, tamperedLeaf];
    const res = verifyAggregatedChain(tamperedChain, agg, principal);
    expect(res.ok).toBe(false);
  });

  it('fails when the aggregate signature is swapped out', () => {
    const { chain, principal } = buildChain();
    const bogus = aggregateChainSignatures(buildChain().chain);
    expect(verifyAggregatedChain(chain, bogus, principal).ok).toBe(false);
  });

  it('fails on a broken holder->issuer continuity', () => {
    const { chain, principal } = buildChain();
    const agg = aggregateChainSignatures(chain);
    const forgedMiddle: BlsCapability = { ...chain[1]!, issuer: blsPublicKey(keyGen().secretKey) };
    expect(verifyAggregatedChain([chain[0]!, forgedMiddle, chain[2]!], agg, principal).ok).toBe(false);
  });
});

describe('PCA: transparency-ledger witness cosignature aggregation', () => {
  const statement = { size: 1024, root: 'cm9vdEA=', prev_root: 'cHJldg==', guardian_epoch: 3 };
  const witnesses = [keyGen(), keyGen(), keyGen()];

  it('verifies an aggregate of a witness quorum over one STH statement', () => {
    const cosigs = witnesses.map((w) => cosignTreeHead(statement, w.secretKey));
    cosigs.forEach((c) => expect(verifyWitnessCosignature(statement, c)).toBe(true));
    const agg = aggregateWitnessCosignatures(cosigs);
    const keys = cosigs.map((c) => c.key);
    expect(verifyAggregatedWitnessCosignatures(statement, keys, agg)).toBe(true);
  });

  it('fails if the tree-head statement is altered', () => {
    const cosigs = witnesses.map((w) => cosignTreeHead(statement, w.secretKey));
    const agg = aggregateWitnessCosignatures(cosigs);
    const keys = cosigs.map((c) => c.key);
    const forged = { ...statement, root: 'Zm9yZ2VkUm9vdA==' };
    expect(verifyAggregatedWitnessCosignatures(forged, keys, agg)).toBe(false);
  });

  it('fails if a witness key in the quorum is swapped for a non-signer', () => {
    const cosigs = witnesses.map((w) => cosignTreeHead(statement, w.secretKey));
    const agg = aggregateWitnessCosignatures(cosigs);
    const keys = [cosigs[0]!.key, cosigs[1]!.key, blsPublicKey(keyGen().secretKey)];
    expect(verifyAggregatedWitnessCosignatures(statement, keys, agg)).toBe(false);
  });
});

describe('BLS12-381 spec vector', () => {
  it('getPublicKey(scalar 1) is the standard compressed G1 generator', () => {
    // The BLS12-381 G1 generator, compressed (draft-irtf-cfrg-pairing-friendly-curves / zkcrypto).
    const G1_GENERATOR_COMPRESSED =
      '97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb';
    const scalarOne = new Uint8Array(32);
    scalarOne[31] = 1;
    expect(bytesToHex(publicKeyOf(scalarOne))).toBe(G1_GENERATOR_COMPRESSED);
  });
});

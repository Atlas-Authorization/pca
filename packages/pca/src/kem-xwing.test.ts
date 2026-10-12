import { describe, expect, it } from 'vitest';
import {
  XWING_CIPHERTEXT_LEN,
  XWING_ESEED_LEN,
  XWING_LABEL,
  XWING_PUBLIC_KEY_LEN,
  XWING_SECRET_KEY_LEN,
  XWING_SEED_LEN,
  XWING_SHARED_SECRET_LEN,
  XWING_SUITE,
  decodeXWingCiphertext,
  decodeXWingPublicKey,
  encodeXWingCiphertext,
  encodeXWingPublicKey,
  xwingDecapsulate,
  xwingEncapsulate,
  xwingEncapsulateDerand,
  xwingKeygen,
} from './kem';

const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

function hex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function toHex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

/**
 * Known-answer vectors from draft-connolly-cfrg-xwing-kem-09, Appendix C. Each gives the 32-byte seed
 * (which IS both the X-Wing secret/decapsulation key), the 64-byte derandomized encapsulation seed
 * (ML-KEM message m ‖ X25519 ephemeral secret), and the resulting 32-byte shared secret. Reproducing
 * `ss` from `seed`+`eseed` transitively proves keygen (pk_M, pk_X, sk_X), encapsulation, and the SHA3-256
 * combiner + label are all byte-exact — a single modified bit anywhere changes `ss`.
 */
const KAT = [
  {
    seed: '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26',
    eseed:
      '3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2',
    ss: 'd2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384',
  },
  {
    seed: 'badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea',
    eseed:
      '17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d',
    ss: 'f2e86241c64d60f6649fbc6c5b7d17180b780a3f34355e64a85749949c45f150',
  },
  {
    seed: 'ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9',
    eseed:
      '22a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b',
    ss: '953f7f4e8c5b5049bdc771d1dffada0dd961477d1a2ae0988baa7ea6898d893f',
  },
];

// The full public key and ciphertext for KAT vector 1 (Appendix C), to assert byte-exact ENCODING order
// (pk = pk_M ‖ pk_X ; ct = ct_M ‖ ct_X), not just the shared secret.
const KAT1_PK =
  'e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3da5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a5253401bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced40769923610034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da063bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2aea10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545eae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17ed55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a487e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc090544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c952151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae4065ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb57b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e317346e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d13698a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da969e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff7349042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534';
const KAT1_CT =
  'b83aa828d4d62b9a83ceffe1d3d3bb1ef31264643c070c5798927e41fb07914a273f8f96e7826cd5375a283d7da885304c5de0516a0f0654243dc5b97f8bfeb831f68251219aabdd723bc6512041acbaef8af44265524942b902e68ffd23221cda70b1b55d776a92d1143ea3a0c475f63ee6890157c7116dae3f62bf72f60acd2bb8cc31ce2ba0de364f52b8ed38c79d719715963a5dd3842d8e8b43ab704e4759b5327bf027c63c8fa857c4908d5a8a7b88ac7f2be394d93c3706ddd4e698cc6ce370101f4d0213254238b4a2e8821b6e414a1cf20f6c1244b699046f5a01caa0a1a55516300b40d2048c77cc73afba79afeea9d2c0118bdf2adb8870dc328c5516cc45b1a2058141039e2c90a110a9e16b318dfb53bd49a126d6b73f215787517b8917cc01cabd107d06859854ee8b4f9861c226d3764c87339ab16c3667d2f49384e55456dd40414b70a6af841585f4c90c68725d57704ee8ee7ce6e2f9be582dbee985e038ffc346ebfb4e22158b6c84374a9ab4a44e1f91de5aac5197f89bc5e5442f51f9a5937b102ba3beaebf6e1c58380a4a5fedce4a4e5026f88f528f59ffd2db41752b3a3d90efabe463899b7d40870c530c8841e8712b733668ed033adbfafb2d49d37a44d4064e5863eb0af0a08d47b3cc888373bc05f7a33b841bc2587c57eb69554e8a3767b7506917b6b70498727f16eac1a36ec8d8cfaf751549f2277db277e8a55a9a5106b23a0206b4721fa9b3048552c5bd5b594d6e247f38c18c591aea7f56249c72ce7b117afcc3a8621582f9cf71787e183dee09367976e98409ad9217a497df888042384d7707a6b78f5f7fb8409e3b535175373461b776002d799cbad62860be70573ecbe13b246e0da7e93a52168e0fb6a9756b895ef7f0147a0dc81bfa644b088a9228160c0f9acf1379a2941cd28c06ebc80e44e17aa2f8177010afd78a97ce0868d1629ebb294c5151812c583daeb88685220f4da9118112e07041fcc24d5564a99fdbde28869fe0722387d7a9a4d16e1cc8555917e09944aa5ebaaaec2cf62693afad42a3f518fce67d273cc6c9fb5472b380e8573ec7de06a3ba2fd5f931d725b493026cb0acbd3fe62d00e4c790d965d7a03a3c0b4222ba8c2a9a16e2ac658f572ae0e746eafc4feba023576f08942278a041fb82a70a595d5bacbf297ce2029898a71e5c3b0d1c6228b485b1ade509b35fbca7eca97b2132e7cb6bc465375146b7dceac969308ac0c2ac89e7863eb8943015b24314cafb9c7c0e85fe543d56658c213632599efabfc1ec49dd8c88547bb2cc40c9d38cbd3099b4547840560531d0188cd1e9c23a0ebee0a03d5577d66b1d2bcb4baaf21cc7fef1e03806ca96299df0dfbc56e1b2b43e4fc20c37f834c4af62127e7dae86c3c25a2f696ac8b589dec71d595bfbe94b5ed4bc07d800b330796fda89edb77be0294136139354eb8cd37591578f9c600dd9be8ec6219fdd507adf3397ed4d68707b8d13b24ce4cd8fb22851bfe9d632407f31ed6f7cb1600de56f17576740ce2a32fc5145030145cfb97e63e0e41d354274a079d3e6fb2e15';

describe('X-Wing KEM (draft-connolly-cfrg-xwing-kem-09)', () => {
  it('exports the suite id and the correct draft-09 sizes', () => {
    expect(XWING_SUITE).toBe('xwing');
    expect(XWING_SEED_LEN).toBe(32);
    expect(XWING_SECRET_KEY_LEN).toBe(32);
    expect(XWING_PUBLIC_KEY_LEN).toBe(1216);
    expect(XWING_CIPHERTEXT_LEN).toBe(1120);
    expect(XWING_SHARED_SECRET_LEN).toBe(32);
    expect(XWING_ESEED_LEN).toBe(64);
  });

  it('the combiner label is exactly the 6 bytes `\\.//^\\` (hex 5c2e2f2f5e5c)', () => {
    expect(Array.from(XWING_LABEL)).toEqual([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);
    expect(toHex(XWING_LABEL)).toBe('5c2e2f2f5e5c');
  });

  it('keygen → encapsulate → decapsulate recovers the same 32-byte secret, with the right sizes', () => {
    const kp = xwingKeygen();
    expect(kp.secretKey.length).toBe(XWING_SECRET_KEY_LEN);
    expect(kp.publicKey.length).toBe(XWING_PUBLIC_KEY_LEN);
    const { ciphertext, sharedSecret } = xwingEncapsulate(kp.publicKey);
    expect(ciphertext.length).toBe(XWING_CIPHERTEXT_LEN);
    expect(sharedSecret.length).toBe(XWING_SHARED_SECRET_LEN);
    const recovered = xwingDecapsulate(ciphertext, kp.secretKey);
    expect(eq(recovered, sharedSecret)).toBe(true);
  });

  it('keygen from a fixed seed is deterministic', () => {
    const seed = new Uint8Array(32).fill(7);
    const a = xwingKeygen(seed);
    const b = xwingKeygen(seed);
    expect(eq(a.publicKey, b.publicKey)).toBe(true);
    expect(eq(a.secretKey, b.secretKey)).toBe(true);
    // the stored secret is a COPY of the seed (mutating the input must not corrupt the key pair)
    const before = a.secretKey[0];
    seed[0] = (seed[0] ?? 0) ^ 0xff;
    expect(a.secretKey[0]).toBe(before);
    expect(a.secretKey[0]).not.toBe(seed[0]);
  });

  it('a different recipient key recovers a different secret', () => {
    const a = xwingKeygen();
    const b = xwingKeygen();
    const { ciphertext, sharedSecret } = xwingEncapsulate(a.publicKey);
    expect(eq(xwingDecapsulate(ciphertext, b.secretKey), sharedSecret)).toBe(false);
  });

  it('fresh encapsulations to the same key differ (ephemeral)', () => {
    const kp = xwingKeygen();
    const e1 = xwingEncapsulate(kp.publicKey);
    const e2 = xwingEncapsulate(kp.publicKey);
    expect(eq(e1.ciphertext, e2.ciphertext)).toBe(false);
    expect(eq(e1.sharedSecret, e2.sharedSecret)).toBe(false);
  });

  it('corrupting EITHER the ML-KEM half OR the X25519 half breaks the shared secret', () => {
    const kp = xwingKeygen();
    const { ciphertext, sharedSecret } = xwingEncapsulate(kp.publicKey);

    // flip a byte in ct_M (the first 1088 bytes — ML-KEM FO transform binds ss_M to ct_M)
    const tamperM = Uint8Array.from(ciphertext);
    tamperM[100] = tamperM[100]! ^ 0xff;
    expect(eq(xwingDecapsulate(tamperM, kp.secretKey), sharedSecret)).toBe(false);

    // flip a byte in ct_X (the trailing 32 bytes — the ephemeral X25519 public key, bound via the combiner)
    const tamperX = Uint8Array.from(ciphertext);
    tamperX[XWING_CIPHERTEXT_LEN - 1] = tamperX[XWING_CIPHERTEXT_LEN - 1]! ^ 0xff;
    expect(eq(xwingDecapsulate(tamperX, kp.secretKey), sharedSecret)).toBe(false);
  });

  it('fails closed on malformed sizes', () => {
    const kp = xwingKeygen();
    expect(() => xwingEncapsulate(new Uint8Array(10))).toThrow(/public key must be/);
    expect(() => xwingEncapsulateDerand(kp.publicKey, new Uint8Array(10))).toThrow(/eseed must be/);
    expect(() => xwingDecapsulate(new Uint8Array(10), kp.secretKey)).toThrow(/ciphertext must be/);
    const { ciphertext } = xwingEncapsulate(kp.publicKey);
    expect(() => xwingDecapsulate(ciphertext, new Uint8Array(8))).toThrow(/seed must be/);
  });

  it('b64u wire helpers round-trip', () => {
    const kp = xwingKeygen();
    expect(eq(decodeXWingPublicKey(encodeXWingPublicKey(kp.publicKey)), kp.publicKey)).toBe(true);
    const { ciphertext } = xwingEncapsulate(kp.publicKey);
    expect(eq(decodeXWingCiphertext(encodeXWingCiphertext(ciphertext)), ciphertext)).toBe(true);
  });

  describe('byte-exact against the draft-09 Appendix C known-answer vectors', () => {
    it('all three vectors: derandomized encaps and decaps both reproduce the published shared secret', () => {
      for (const v of KAT) {
        const kp = xwingKeygen(hex(v.seed));
        const { ciphertext, sharedSecret } = xwingEncapsulateDerand(kp.publicKey, hex(v.eseed));
        expect(toHex(sharedSecret)).toBe(v.ss);
        // decapsulation with the seed key recovers the identical secret
        expect(toHex(xwingDecapsulate(ciphertext, kp.secretKey))).toBe(v.ss);
      }
    });

    it('vector 1: the public key and ciphertext are byte-exact (pk = pk_M‖pk_X, ct = ct_M‖ct_X)', () => {
      const kp = xwingKeygen(hex(KAT[0]!.seed));
      expect(toHex(kp.publicKey)).toBe(KAT1_PK);
      const { ciphertext } = xwingEncapsulateDerand(kp.publicKey, hex(KAT[0]!.eseed));
      expect(toHex(ciphertext)).toBe(KAT1_CT);
    });
  });
});

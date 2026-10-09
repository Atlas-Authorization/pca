// node_modules/.pnpm/@noble+hashes@1.8.0/node_modules/@noble/hashes/esm/crypto.js
var crypto = typeof globalThis === "object" && "crypto" in globalThis ? globalThis.crypto : void 0;

// node_modules/.pnpm/@noble+hashes@1.8.0/node_modules/@noble/hashes/esm/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function anumber(n) {
  if (!Number.isSafeInteger(n) || n < 0)
    throw new Error("positive integer expected, got " + n);
}
function abytes(b, ...lengths) {
  if (!isBytes(b))
    throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
}
function ahash(h) {
  if (typeof h !== "function" || typeof h.create !== "function")
    throw new Error("Hash should be wrapped by utils.createHasher");
  anumber(h.outputLen);
  anumber(h.blockLen);
}
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput(out, instance) {
  abytes(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error("digestInto() expects output buffer of length at least " + min);
  }
}
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function rotr(word, shift) {
  return word << 32 - shift | word >>> shift;
}
var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
function byteSwap(word) {
  return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
function byteSwap32(arr) {
  for (let i = 0; i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
  return arr;
}
var swap32IfBE = isLE ? (u) => u : byteSwap32;
var hasHexBuiltin = /* @__PURE__ */ (() => (
  // @ts-ignore
  typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
))();
var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
function bytesToHex(bytes) {
  abytes(bytes);
  if (hasHexBuiltin)
    return bytes.toHex();
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += hexes[bytes[i]];
  }
  return hex;
}
var asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
function asciiToBase16(ch) {
  if (ch >= asciis._0 && ch <= asciis._9)
    return ch - asciis._0;
  if (ch >= asciis.A && ch <= asciis.F)
    return ch - (asciis.A - 10);
  if (ch >= asciis.a && ch <= asciis.f)
    return ch - (asciis.a - 10);
  return;
}
function hexToBytes(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  if (hasHexBuiltin)
    return Uint8Array.fromHex(hex);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    throw new Error("hex string expected, got unpadded hex of length " + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === void 0 || n2 === void 0) {
      const char = hex[hi] + hex[hi + 1];
      throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2;
  }
  return array;
}
function utf8ToBytes(str) {
  if (typeof str !== "string")
    throw new Error("string expected");
  return new Uint8Array(new TextEncoder().encode(str));
}
function toBytes(data) {
  if (typeof data === "string")
    data = utf8ToBytes(data);
  abytes(data);
  return data;
}
function concatBytes(...arrays) {
  let sum = 0;
  for (let i = 0; i < arrays.length; i++) {
    const a = arrays[i];
    abytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}
var Hash = class {
};
function createHasher(hashCons) {
  const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}
function createXOFer(hashCons) {
  const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
  const tmp = hashCons({});
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = (opts) => hashCons(opts);
  return hashC;
}
function randomBytes(bytesLength = 32) {
  if (crypto && typeof crypto.getRandomValues === "function") {
    return crypto.getRandomValues(new Uint8Array(bytesLength));
  }
  if (crypto && typeof crypto.randomBytes === "function") {
    return Uint8Array.from(crypto.randomBytes(bytesLength));
  }
  throw new Error("crypto.getRandomValues must be defined");
}

// node_modules/.pnpm/@noble+hashes@1.8.0/node_modules/@noble/hashes/esm/_md.js
function setBigUint64(view, byteOffset, value, isLE2) {
  if (typeof view.setBigUint64 === "function")
    return view.setBigUint64(byteOffset, value, isLE2);
  const _32n2 = BigInt(32);
  const _u32_max = BigInt(4294967295);
  const wh = Number(value >> _32n2 & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE2 ? 4 : 0;
  const l = isLE2 ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE2);
  view.setUint32(byteOffset + l, wl, isLE2);
}
function Chi(a, b, c) {
  return a & b ^ ~a & c;
}
function Maj(a, b, c) {
  return a & b ^ a & c ^ b & c;
}
var HashMD = class extends Hash {
  constructor(blockLen, outputLen, padOffset, isLE2) {
    super();
    this.finished = false;
    this.length = 0;
    this.pos = 0;
    this.destroyed = false;
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE2;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    aexists(this);
    data = toBytes(data);
    abytes(data);
    const { view, buffer, blockLen } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
      }
    }
    this.length += data.length;
    this.roundClean();
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE: isLE2 } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    clean(this.buffer.subarray(pos));
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    for (let i = pos; i < blockLen; i++)
      buffer[i] = 0;
    setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE2);
    this.process(view, 0);
    const oview = createView(out);
    const len = this.outputLen;
    if (len % 4)
      throw new Error("_sha2: outputLen should be aligned to 32bit");
    const outLen = len / 4;
    const state = this.get();
    if (outLen > state.length)
      throw new Error("_sha2: outputLen bigger than state");
    for (let i = 0; i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE2);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to) {
    to || (to = new this.constructor());
    to.set(...this.get());
    const { blockLen, buffer, length, finished, destroyed, pos } = this;
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    if (length % blockLen)
      to.buffer.set(buffer);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
};
var SHA256_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);
var SHA224_IV = /* @__PURE__ */ Uint32Array.from([
  3238371032,
  914150663,
  812702999,
  4144912697,
  4290775857,
  1750603025,
  1694076839,
  3204075428
]);
var SHA384_IV = /* @__PURE__ */ Uint32Array.from([
  3418070365,
  3238371032,
  1654270250,
  914150663,
  2438529370,
  812702999,
  355462360,
  4144912697,
  1731405415,
  4290775857,
  2394180231,
  1750603025,
  3675008525,
  1694076839,
  1203062813,
  3204075428
]);
var SHA512_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  4089235720,
  3144134277,
  2227873595,
  1013904242,
  4271175723,
  2773480762,
  1595750129,
  1359893119,
  2917565137,
  2600822924,
  725511199,
  528734635,
  4215389547,
  1541459225,
  327033209
]);

// node_modules/.pnpm/@noble+hashes@1.8.0/node_modules/@noble/hashes/esm/_u64.js
var U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
var _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
  const len = lst.length;
  let Ah = new Uint32Array(len);
  let Al = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    const { h, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h, l];
  }
  return [Ah, Al];
}
var shrSH = (h, _l, s) => h >>> s;
var shrSL = (h, l, s) => h << 32 - s | l >>> s;
var rotrSH = (h, l, s) => h >>> s | l << 32 - s;
var rotrSL = (h, l, s) => h << 32 - s | l >>> s;
var rotrBH = (h, l, s) => h << 64 - s | l >>> s - 32;
var rotrBL = (h, l, s) => h >>> s - 32 | l << 64 - s;
var rotlSH = (h, l, s) => h << s | l >>> 32 - s;
var rotlSL = (h, l, s) => l << s | h >>> 32 - s;
var rotlBH = (h, l, s) => l << s - 32 | h >>> 64 - s;
var rotlBL = (h, l, s) => h << s - 32 | l >>> 64 - s;
function add(Ah, Al, Bh, Bl) {
  const l = (Al >>> 0) + (Bl >>> 0);
  return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
}
var add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
var add3H = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
var add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
var add4H = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
var add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
var add5H = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;

// node_modules/.pnpm/@noble+hashes@1.8.0/node_modules/@noble/hashes/esm/sha2.js
var SHA256_K = /* @__PURE__ */ Uint32Array.from([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
var SHA256 = class extends HashMD {
  constructor(outputLen = 32) {
    super(64, outputLen, 8, false);
    this.A = SHA256_IV[0] | 0;
    this.B = SHA256_IV[1] | 0;
    this.C = SHA256_IV[2] | 0;
    this.D = SHA256_IV[3] | 0;
    this.E = SHA256_IV[4] | 0;
    this.F = SHA256_IV[5] | 0;
    this.G = SHA256_IV[6] | 0;
    this.H = SHA256_IV[7] | 0;
  }
  get() {
    const { A, B, C, D: D2, E, F: F2, G, H } = this;
    return [A, B, C, D2, E, F2, G, H];
  }
  // prettier-ignore
  set(A, B, C, D2, E, F2, G, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D2 | 0;
    this.E = E | 0;
    this.F = F2 | 0;
    this.G = G | 0;
    this.H = H | 0;
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4)
      SHA256_W[i] = view.getUint32(offset, false);
    for (let i = 16; i < 64; i++) {
      const W15 = SHA256_W[i - 15];
      const W2 = SHA256_W[i - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
      SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
    }
    let { A, B, C, D: D2, E, F: F2, G, H } = this;
    for (let i = 0; i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F2, G) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B, C) | 0;
      H = G;
      G = F2;
      F2 = E;
      E = D2 + T1 | 0;
      D2 = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D2 = D2 + this.D | 0;
    E = E + this.E | 0;
    F2 = F2 + this.F | 0;
    G = G + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D2, E, F2, G, H);
  }
  roundClean() {
    clean(SHA256_W);
  }
  destroy() {
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    clean(this.buffer);
  }
};
var SHA224 = class extends SHA256 {
  constructor() {
    super(28);
    this.A = SHA224_IV[0] | 0;
    this.B = SHA224_IV[1] | 0;
    this.C = SHA224_IV[2] | 0;
    this.D = SHA224_IV[3] | 0;
    this.E = SHA224_IV[4] | 0;
    this.F = SHA224_IV[5] | 0;
    this.G = SHA224_IV[6] | 0;
    this.H = SHA224_IV[7] | 0;
  }
};
var K512 = /* @__PURE__ */ (() => split([
  "0x428a2f98d728ae22",
  "0x7137449123ef65cd",
  "0xb5c0fbcfec4d3b2f",
  "0xe9b5dba58189dbbc",
  "0x3956c25bf348b538",
  "0x59f111f1b605d019",
  "0x923f82a4af194f9b",
  "0xab1c5ed5da6d8118",
  "0xd807aa98a3030242",
  "0x12835b0145706fbe",
  "0x243185be4ee4b28c",
  "0x550c7dc3d5ffb4e2",
  "0x72be5d74f27b896f",
  "0x80deb1fe3b1696b1",
  "0x9bdc06a725c71235",
  "0xc19bf174cf692694",
  "0xe49b69c19ef14ad2",
  "0xefbe4786384f25e3",
  "0x0fc19dc68b8cd5b5",
  "0x240ca1cc77ac9c65",
  "0x2de92c6f592b0275",
  "0x4a7484aa6ea6e483",
  "0x5cb0a9dcbd41fbd4",
  "0x76f988da831153b5",
  "0x983e5152ee66dfab",
  "0xa831c66d2db43210",
  "0xb00327c898fb213f",
  "0xbf597fc7beef0ee4",
  "0xc6e00bf33da88fc2",
  "0xd5a79147930aa725",
  "0x06ca6351e003826f",
  "0x142929670a0e6e70",
  "0x27b70a8546d22ffc",
  "0x2e1b21385c26c926",
  "0x4d2c6dfc5ac42aed",
  "0x53380d139d95b3df",
  "0x650a73548baf63de",
  "0x766a0abb3c77b2a8",
  "0x81c2c92e47edaee6",
  "0x92722c851482353b",
  "0xa2bfe8a14cf10364",
  "0xa81a664bbc423001",
  "0xc24b8b70d0f89791",
  "0xc76c51a30654be30",
  "0xd192e819d6ef5218",
  "0xd69906245565a910",
  "0xf40e35855771202a",
  "0x106aa07032bbd1b8",
  "0x19a4c116b8d2d0c8",
  "0x1e376c085141ab53",
  "0x2748774cdf8eeb99",
  "0x34b0bcb5e19b48a8",
  "0x391c0cb3c5c95a63",
  "0x4ed8aa4ae3418acb",
  "0x5b9cca4f7763e373",
  "0x682e6ff3d6b2b8a3",
  "0x748f82ee5defb2fc",
  "0x78a5636f43172f60",
  "0x84c87814a1f0ab72",
  "0x8cc702081a6439ec",
  "0x90befffa23631e28",
  "0xa4506cebde82bde9",
  "0xbef9a3f7b2c67915",
  "0xc67178f2e372532b",
  "0xca273eceea26619c",
  "0xd186b8c721c0c207",
  "0xeada7dd6cde0eb1e",
  "0xf57d4f7fee6ed178",
  "0x06f067aa72176fba",
  "0x0a637dc5a2c898a6",
  "0x113f9804bef90dae",
  "0x1b710b35131c471b",
  "0x28db77f523047d84",
  "0x32caab7b40c72493",
  "0x3c9ebe0a15c9bebc",
  "0x431d67c49c100d4c",
  "0x4cc5d4becb3e42b6",
  "0x597f299cfc657e2a",
  "0x5fcb6fab3ad6faec",
  "0x6c44198c4a475817"
].map((n) => BigInt(n))))();
var SHA512_Kh = /* @__PURE__ */ (() => K512[0])();
var SHA512_Kl = /* @__PURE__ */ (() => K512[1])();
var SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
var SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
var SHA512 = class extends HashMD {
  constructor(outputLen = 64) {
    super(128, outputLen, 16, false);
    this.Ah = SHA512_IV[0] | 0;
    this.Al = SHA512_IV[1] | 0;
    this.Bh = SHA512_IV[2] | 0;
    this.Bl = SHA512_IV[3] | 0;
    this.Ch = SHA512_IV[4] | 0;
    this.Cl = SHA512_IV[5] | 0;
    this.Dh = SHA512_IV[6] | 0;
    this.Dl = SHA512_IV[7] | 0;
    this.Eh = SHA512_IV[8] | 0;
    this.El = SHA512_IV[9] | 0;
    this.Fh = SHA512_IV[10] | 0;
    this.Fl = SHA512_IV[11] | 0;
    this.Gh = SHA512_IV[12] | 0;
    this.Gl = SHA512_IV[13] | 0;
    this.Hh = SHA512_IV[14] | 0;
    this.Hl = SHA512_IV[15] | 0;
  }
  // prettier-ignore
  get() {
    const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
  }
  // prettier-ignore
  set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
    this.Ah = Ah | 0;
    this.Al = Al | 0;
    this.Bh = Bh | 0;
    this.Bl = Bl | 0;
    this.Ch = Ch | 0;
    this.Cl = Cl | 0;
    this.Dh = Dh | 0;
    this.Dl = Dl | 0;
    this.Eh = Eh | 0;
    this.El = El | 0;
    this.Fh = Fh | 0;
    this.Fl = Fl | 0;
    this.Gh = Gh | 0;
    this.Gl = Gl | 0;
    this.Hh = Hh | 0;
    this.Hl = Hl | 0;
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4) {
      SHA512_W_H[i] = view.getUint32(offset);
      SHA512_W_L[i] = view.getUint32(offset += 4);
    }
    for (let i = 16; i < 80; i++) {
      const W15h = SHA512_W_H[i - 15] | 0;
      const W15l = SHA512_W_L[i - 15] | 0;
      const s0h = rotrSH(W15h, W15l, 1) ^ rotrSH(W15h, W15l, 8) ^ shrSH(W15h, W15l, 7);
      const s0l = rotrSL(W15h, W15l, 1) ^ rotrSL(W15h, W15l, 8) ^ shrSL(W15h, W15l, 7);
      const W2h = SHA512_W_H[i - 2] | 0;
      const W2l = SHA512_W_L[i - 2] | 0;
      const s1h = rotrSH(W2h, W2l, 19) ^ rotrBH(W2h, W2l, 61) ^ shrSH(W2h, W2l, 6);
      const s1l = rotrSL(W2h, W2l, 19) ^ rotrBL(W2h, W2l, 61) ^ shrSL(W2h, W2l, 6);
      const SUMl = add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
      const SUMh = add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
      SHA512_W_H[i] = SUMh | 0;
      SHA512_W_L[i] = SUMl | 0;
    }
    let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    for (let i = 0; i < 80; i++) {
      const sigma1h = rotrSH(Eh, El, 14) ^ rotrSH(Eh, El, 18) ^ rotrBH(Eh, El, 41);
      const sigma1l = rotrSL(Eh, El, 14) ^ rotrSL(Eh, El, 18) ^ rotrBL(Eh, El, 41);
      const CHIh = Eh & Fh ^ ~Eh & Gh;
      const CHIl = El & Fl ^ ~El & Gl;
      const T1ll = add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
      const T1h = add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
      const T1l = T1ll | 0;
      const sigma0h = rotrSH(Ah, Al, 28) ^ rotrBH(Ah, Al, 34) ^ rotrBH(Ah, Al, 39);
      const sigma0l = rotrSL(Ah, Al, 28) ^ rotrBL(Ah, Al, 34) ^ rotrBL(Ah, Al, 39);
      const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
      const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
      Hh = Gh | 0;
      Hl = Gl | 0;
      Gh = Fh | 0;
      Gl = Fl | 0;
      Fh = Eh | 0;
      Fl = El | 0;
      ({ h: Eh, l: El } = add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
      Dh = Ch | 0;
      Dl = Cl | 0;
      Ch = Bh | 0;
      Cl = Bl | 0;
      Bh = Ah | 0;
      Bl = Al | 0;
      const All = add3L(T1l, sigma0l, MAJl);
      Ah = add3H(All, T1h, sigma0h, MAJh);
      Al = All | 0;
    }
    ({ h: Ah, l: Al } = add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
    ({ h: Bh, l: Bl } = add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
    ({ h: Ch, l: Cl } = add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
    ({ h: Dh, l: Dl } = add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
    ({ h: Eh, l: El } = add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
    ({ h: Fh, l: Fl } = add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
    ({ h: Gh, l: Gl } = add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
    ({ h: Hh, l: Hl } = add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
    this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
  }
  roundClean() {
    clean(SHA512_W_H, SHA512_W_L);
  }
  destroy() {
    clean(this.buffer);
    this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  }
};
var SHA384 = class extends SHA512 {
  constructor() {
    super(48);
    this.Ah = SHA384_IV[0] | 0;
    this.Al = SHA384_IV[1] | 0;
    this.Bh = SHA384_IV[2] | 0;
    this.Bl = SHA384_IV[3] | 0;
    this.Ch = SHA384_IV[4] | 0;
    this.Cl = SHA384_IV[5] | 0;
    this.Dh = SHA384_IV[6] | 0;
    this.Dl = SHA384_IV[7] | 0;
    this.Eh = SHA384_IV[8] | 0;
    this.El = SHA384_IV[9] | 0;
    this.Fh = SHA384_IV[10] | 0;
    this.Fl = SHA384_IV[11] | 0;
    this.Gh = SHA384_IV[12] | 0;
    this.Gl = SHA384_IV[13] | 0;
    this.Hh = SHA384_IV[14] | 0;
    this.Hl = SHA384_IV[15] | 0;
  }
};
var T224_IV = /* @__PURE__ */ Uint32Array.from([
  2352822216,
  424955298,
  1944164710,
  2312950998,
  502970286,
  855612546,
  1738396948,
  1479516111,
  258812777,
  2077511080,
  2011393907,
  79989058,
  1067287976,
  1780299464,
  286451373,
  2446758561
]);
var T256_IV = /* @__PURE__ */ Uint32Array.from([
  573645204,
  4230739756,
  2673172387,
  3360449730,
  596883563,
  1867755857,
  2520282905,
  1497426621,
  2519219938,
  2827943907,
  3193839141,
  1401305490,
  721525244,
  746961066,
  246885852,
  2177182882
]);
var SHA512_224 = class extends SHA512 {
  constructor() {
    super(28);
    this.Ah = T224_IV[0] | 0;
    this.Al = T224_IV[1] | 0;
    this.Bh = T224_IV[2] | 0;
    this.Bl = T224_IV[3] | 0;
    this.Ch = T224_IV[4] | 0;
    this.Cl = T224_IV[5] | 0;
    this.Dh = T224_IV[6] | 0;
    this.Dl = T224_IV[7] | 0;
    this.Eh = T224_IV[8] | 0;
    this.El = T224_IV[9] | 0;
    this.Fh = T224_IV[10] | 0;
    this.Fl = T224_IV[11] | 0;
    this.Gh = T224_IV[12] | 0;
    this.Gl = T224_IV[13] | 0;
    this.Hh = T224_IV[14] | 0;
    this.Hl = T224_IV[15] | 0;
  }
};
var SHA512_256 = class extends SHA512 {
  constructor() {
    super(32);
    this.Ah = T256_IV[0] | 0;
    this.Al = T256_IV[1] | 0;
    this.Bh = T256_IV[2] | 0;
    this.Bl = T256_IV[3] | 0;
    this.Ch = T256_IV[4] | 0;
    this.Cl = T256_IV[5] | 0;
    this.Dh = T256_IV[6] | 0;
    this.Dl = T256_IV[7] | 0;
    this.Eh = T256_IV[8] | 0;
    this.El = T256_IV[9] | 0;
    this.Fh = T256_IV[10] | 0;
    this.Fl = T256_IV[11] | 0;
    this.Gh = T256_IV[12] | 0;
    this.Gl = T256_IV[13] | 0;
    this.Hh = T256_IV[14] | 0;
    this.Hl = T256_IV[15] | 0;
  }
};
var sha256 = /* @__PURE__ */ createHasher(() => new SHA256());
var sha224 = /* @__PURE__ */ createHasher(() => new SHA224());
var sha512 = /* @__PURE__ */ createHasher(() => new SHA512());
var sha384 = /* @__PURE__ */ createHasher(() => new SHA384());
var sha512_256 = /* @__PURE__ */ createHasher(() => new SHA512_256());
var sha512_224 = /* @__PURE__ */ createHasher(() => new SHA512_224());

// node_modules/.pnpm/@noble+hashes@1.8.0/node_modules/@noble/hashes/esm/sha256.js
var sha2562 = sha256;

// node_modules/.pnpm/@noble+hashes@1.8.0/node_modules/@noble/hashes/esm/sha512.js
var sha3842 = sha384;

// node_modules/.pnpm/@scure+base@1.2.6/node_modules/@scure/base/lib/esm/index.js
function isBytes2(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function isArrayOf(isString, arr) {
  if (!Array.isArray(arr))
    return false;
  if (arr.length === 0)
    return true;
  if (isString) {
    return arr.every((item) => typeof item === "string");
  } else {
    return arr.every((item) => Number.isSafeInteger(item));
  }
}
function astr(label, input) {
  if (typeof input !== "string")
    throw new Error(`${label}: string expected`);
  return true;
}
function anumber2(n) {
  if (!Number.isSafeInteger(n))
    throw new Error(`invalid integer: ${n}`);
}
function aArr(input) {
  if (!Array.isArray(input))
    throw new Error("array expected");
}
function astrArr(label, input) {
  if (!isArrayOf(true, input))
    throw new Error(`${label}: array of strings expected`);
}
function anumArr(label, input) {
  if (!isArrayOf(false, input))
    throw new Error(`${label}: array of numbers expected`);
}
// @__NO_SIDE_EFFECTS__
function chain(...args) {
  const id2 = (a) => a;
  const wrap = (a, b) => (c) => a(b(c));
  const encode = args.map((x) => x.encode).reduceRight(wrap, id2);
  const decode = args.map((x) => x.decode).reduce(wrap, id2);
  return { encode, decode };
}
// @__NO_SIDE_EFFECTS__
function alphabet(letters) {
  const lettersA = typeof letters === "string" ? letters.split("") : letters;
  const len = lettersA.length;
  astrArr("alphabet", lettersA);
  const indexes = new Map(lettersA.map((l, i) => [l, i]));
  return {
    encode: (digits) => {
      aArr(digits);
      return digits.map((i) => {
        if (!Number.isSafeInteger(i) || i < 0 || i >= len)
          throw new Error(`alphabet.encode: digit index outside alphabet "${i}". Allowed: ${letters}`);
        return lettersA[i];
      });
    },
    decode: (input) => {
      aArr(input);
      return input.map((letter) => {
        astr("alphabet.decode", letter);
        const i = indexes.get(letter);
        if (i === void 0)
          throw new Error(`Unknown letter: "${letter}". Allowed: ${letters}`);
        return i;
      });
    }
  };
}
// @__NO_SIDE_EFFECTS__
function join(separator = "") {
  astr("join", separator);
  return {
    encode: (from) => {
      astrArr("join.decode", from);
      return from.join(separator);
    },
    decode: (to) => {
      astr("join.decode", to);
      return to.split(separator);
    }
  };
}
var gcd = (a, b) => b === 0 ? a : gcd(b, a % b);
var radix2carry = /* @__NO_SIDE_EFFECTS__ */ (from, to) => from + (to - gcd(from, to));
var powers = /* @__PURE__ */ (() => {
  let res = [];
  for (let i = 0; i < 40; i++)
    res.push(2 ** i);
  return res;
})();
function convertRadix2(data, from, to, padding) {
  aArr(data);
  if (from <= 0 || from > 32)
    throw new Error(`convertRadix2: wrong from=${from}`);
  if (to <= 0 || to > 32)
    throw new Error(`convertRadix2: wrong to=${to}`);
  if (/* @__PURE__ */ radix2carry(from, to) > 32) {
    throw new Error(`convertRadix2: carry overflow from=${from} to=${to} carryBits=${/* @__PURE__ */ radix2carry(from, to)}`);
  }
  let carry = 0;
  let pos = 0;
  const max = powers[from];
  const mask = powers[to] - 1;
  const res = [];
  for (const n of data) {
    anumber2(n);
    if (n >= max)
      throw new Error(`convertRadix2: invalid data word=${n} from=${from}`);
    carry = carry << from | n;
    if (pos + from > 32)
      throw new Error(`convertRadix2: carry overflow pos=${pos} from=${from}`);
    pos += from;
    for (; pos >= to; pos -= to)
      res.push((carry >> pos - to & mask) >>> 0);
    const pow = powers[pos];
    if (pow === void 0)
      throw new Error("invalid carry");
    carry &= pow - 1;
  }
  carry = carry << to - pos & mask;
  if (!padding && pos >= from)
    throw new Error("Excess padding");
  if (!padding && carry > 0)
    throw new Error(`Non-zero padding: ${carry}`);
  if (padding && pos > 0)
    res.push(carry >>> 0);
  return res;
}
// @__NO_SIDE_EFFECTS__
function radix2(bits, revPadding = false) {
  anumber2(bits);
  if (bits <= 0 || bits > 32)
    throw new Error("radix2: bits should be in (0..32]");
  if (/* @__PURE__ */ radix2carry(8, bits) > 32 || /* @__PURE__ */ radix2carry(bits, 8) > 32)
    throw new Error("radix2: carry overflow");
  return {
    encode: (bytes) => {
      if (!isBytes2(bytes))
        throw new Error("radix2.encode input should be Uint8Array");
      return convertRadix2(Array.from(bytes), 8, bits, !revPadding);
    },
    decode: (digits) => {
      anumArr("radix2.decode", digits);
      return Uint8Array.from(convertRadix2(digits, bits, 8, revPadding));
    }
  };
}
var base64urlnopad = /* @__PURE__ */ chain(/* @__PURE__ */ radix2(6), /* @__PURE__ */ alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"), /* @__PURE__ */ join(""));

// packages/pca/src/hash.ts
var enc = new TextEncoder();
function utf8(s) {
  return enc.encode(s);
}
function sha2563(bytes) {
  return sha2562(bytes);
}
function sha3843(bytes) {
  return sha3842(bytes);
}
var DEFAULT_HASH_SUITE = "sha256";
var HASH_LEN = { sha256: 32, sha384: 48 };
function isHashSuite(s) {
  return s === "sha256" || s === "sha384";
}
function hashWithSuite(bytes, suite = DEFAULT_HASH_SUITE) {
  return suite === "sha384" ? sha3843(bytes) : sha2563(bytes);
}
function b64u(bytes) {
  return base64urlnopad.encode(bytes);
}
function unb64u(s) {
  return base64urlnopad.decode(s);
}
var B64U_ALPHABET = /^[A-Za-z0-9_-]*$/;
function decodeB64uStrict(s, len) {
  if (typeof s !== "string" || !B64U_ALPHABET.test(s) || s.length % 4 === 1) return null;
  if (len !== void 0 && s.length !== b64uLen(len)) return null;
  try {
    const bytes = unb64u(s);
    if (b64u(bytes) !== s) return null;
    if (len !== void 0 && bytes.length !== len) return null;
    return bytes;
  } catch {
    return null;
  }
}
function b64uLen(n) {
  return Math.ceil(n * 4 / 3);
}
function compareUtf8(a, b) {
  if (a === b) return 0;
  const x = enc.encode(a);
  const y = enc.encode(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) {
    const d = x[i] - y[i];
    if (d !== 0) return d;
  }
  return x.length - y.length;
}
var LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
var hasLoneSurrogate = (s) => LONE_SURROGATE.test(s);
var MAX_DECIMAL_DIGITS = 15;
function canonicalizeStrict(value) {
  return ser(value, /* @__PURE__ */ new Set(), true, 1);
}
var MAX_JSON_DEPTH = 32;
function strictNumberError(v) {
  if (!Number.isFinite(v)) return "non-finite number";
  if (Object.is(v, -0)) return "negative zero";
  if (Number.isInteger(v)) return Number.isSafeInteger(v) ? null : "integer outside the safe range (|n| > 2^53-1)";
  if (Math.abs(v) < 1e-6) return "non-integer magnitude below 1e-6 (needs an exponent form; not representable in the canonical decimal form)";
  const s = String(v);
  if (/e/i.test(s)) return "non-integer number needs an exponent form (not representable in the canonical decimal form)";
  const digits = s.replace("-", "").replace(".", "").replace(/^0+/, "");
  if (digits.length > MAX_DECIMAL_DIGITS) return `non-integer number has more than ${MAX_DECIMAL_DIGITS} significant digits`;
  return null;
}
function ser(v, seen, strict, depth = 1) {
  if (v === null) return "null";
  switch (typeof v) {
    case "string":
      if (strict && hasLoneSurrogate(v)) throw new TypeError("canonicalize: lone surrogate in string");
      return JSON.stringify(v);
    case "boolean":
      return v ? "true" : "false";
    case "number": {
      if (!Number.isFinite(v)) throw new TypeError("canonicalize: non-finite number");
      if (strict) {
        const e = strictNumberError(v);
        if (e) throw new TypeError(`canonicalize: ${e}`);
        return String(v);
      }
      return Object.is(v, -0) ? "0" : JSON.stringify(v);
    }
    case "object":
      break;
    default:
      throw new TypeError(`canonicalize: unsupported type ${typeof v}`);
  }
  const o = v;
  if (strict && depth > MAX_JSON_DEPTH) throw new TypeError("canonicalize: nesting too deep");
  if (seen.has(o)) throw new TypeError("canonicalize: cycle");
  seen.add(o);
  try {
    if (Array.isArray(o)) {
      return "[" + o.map((x) => ser(x, seen, strict, depth + 1)).join(",") + "]";
    }
    const proto = Object.getPrototypeOf(o);
    if (proto !== Object.prototype && proto !== null) {
      throw new TypeError("canonicalize: non-plain object");
    }
    const rec = o;
    const keys = Object.keys(rec).sort(compareUtf8);
    return "{" + keys.map((k) => {
      if (strict && hasLoneSurrogate(k)) throw new TypeError("canonicalize: lone surrogate in key");
      return JSON.stringify(k) + ":" + ser(rec[k], seen, strict, depth + 1);
    }).join(",") + "}";
  } finally {
    seen.delete(o);
  }
}
function canonicalBytes(value) {
  return utf8(canonicalizeStrict(value));
}
function canonicalBytesStrict(value) {
  return utf8(canonicalizeStrict(value));
}
function hashCanonical(value, suite = DEFAULT_HASH_SUITE) {
  return b64u(hashWithSuite(canonicalBytes(value), suite));
}

// node_modules/.pnpm/@noble+curves@1.9.1/node_modules/@noble/curves/esm/abstract/utils.js
var _0n = /* @__PURE__ */ BigInt(0);
var _1n = /* @__PURE__ */ BigInt(1);
function isBytes3(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function abytes2(item) {
  if (!isBytes3(item))
    throw new Error("Uint8Array expected");
}
function abool(title, value) {
  if (typeof value !== "boolean")
    throw new Error(title + " boolean expected, got " + value);
}
function hexToNumber(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  return hex === "" ? _0n : BigInt("0x" + hex);
}
var hasHexBuiltin2 = (
  // @ts-ignore
  typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
);
var hexes2 = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
function bytesToHex2(bytes) {
  abytes2(bytes);
  if (hasHexBuiltin2)
    return bytes.toHex();
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += hexes2[bytes[i]];
  }
  return hex;
}
var asciis2 = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
function asciiToBase162(ch) {
  if (ch >= asciis2._0 && ch <= asciis2._9)
    return ch - asciis2._0;
  if (ch >= asciis2.A && ch <= asciis2.F)
    return ch - (asciis2.A - 10);
  if (ch >= asciis2.a && ch <= asciis2.f)
    return ch - (asciis2.a - 10);
  return;
}
function hexToBytes2(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  if (hasHexBuiltin2)
    return Uint8Array.fromHex(hex);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    throw new Error("hex string expected, got unpadded hex of length " + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase162(hex.charCodeAt(hi));
    const n2 = asciiToBase162(hex.charCodeAt(hi + 1));
    if (n1 === void 0 || n2 === void 0) {
      const char = hex[hi] + hex[hi + 1];
      throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2;
  }
  return array;
}
function bytesToNumberBE(bytes) {
  return hexToNumber(bytesToHex2(bytes));
}
function bytesToNumberLE(bytes) {
  abytes2(bytes);
  return hexToNumber(bytesToHex2(Uint8Array.from(bytes).reverse()));
}
function numberToBytesBE(n, len) {
  return hexToBytes2(n.toString(16).padStart(len * 2, "0"));
}
function numberToBytesLE(n, len) {
  return numberToBytesBE(n, len).reverse();
}
function ensureBytes(title, hex, expectedLength) {
  let res;
  if (typeof hex === "string") {
    try {
      res = hexToBytes2(hex);
    } catch (e) {
      throw new Error(title + " must be hex string or Uint8Array, cause: " + e);
    }
  } else if (isBytes3(hex)) {
    res = Uint8Array.from(hex);
  } else {
    throw new Error(title + " must be hex string or Uint8Array");
  }
  const len = res.length;
  if (typeof expectedLength === "number" && len !== expectedLength)
    throw new Error(title + " of length " + expectedLength + " expected, got " + len);
  return res;
}
function concatBytes2(...arrays) {
  let sum = 0;
  for (let i = 0; i < arrays.length; i++) {
    const a = arrays[i];
    abytes2(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}
var isPosBig = (n) => typeof n === "bigint" && _0n <= n;
function inRange(n, min, max) {
  return isPosBig(n) && isPosBig(min) && isPosBig(max) && min <= n && n < max;
}
function aInRange(title, n, min, max) {
  if (!inRange(n, min, max))
    throw new Error("expected valid " + title + ": " + min + " <= n < " + max + ", got " + n);
}
function bitLen(n) {
  let len;
  for (len = 0; n > _0n; n >>= _1n, len += 1)
    ;
  return len;
}
var bitMask = (n) => (_1n << BigInt(n)) - _1n;
var validatorFns = {
  bigint: (val) => typeof val === "bigint",
  function: (val) => typeof val === "function",
  boolean: (val) => typeof val === "boolean",
  string: (val) => typeof val === "string",
  stringOrUint8Array: (val) => typeof val === "string" || isBytes3(val),
  isSafeInteger: (val) => Number.isSafeInteger(val),
  array: (val) => Array.isArray(val),
  field: (val, object) => object.Fp.isValid(val),
  hash: (val) => typeof val === "function" && Number.isSafeInteger(val.outputLen)
};
function validateObject(object, validators, optValidators = {}) {
  const checkField = (fieldName, type, isOptional) => {
    const checkVal = validatorFns[type];
    if (typeof checkVal !== "function")
      throw new Error("invalid validator function");
    const val = object[fieldName];
    if (isOptional && val === void 0)
      return;
    if (!checkVal(val, object)) {
      throw new Error("param " + String(fieldName) + " is invalid. Expected " + type + ", got " + val);
    }
  };
  for (const [fieldName, type] of Object.entries(validators))
    checkField(fieldName, type, false);
  for (const [fieldName, type] of Object.entries(optValidators))
    checkField(fieldName, type, true);
  return object;
}
function memoized(fn) {
  const map = /* @__PURE__ */ new WeakMap();
  return (arg, ...args) => {
    const val = map.get(arg);
    if (val !== void 0)
      return val;
    const computed = fn(arg, ...args);
    map.set(arg, computed);
    return computed;
  };
}

// node_modules/.pnpm/@noble+curves@1.9.1/node_modules/@noble/curves/esm/abstract/modular.js
var _0n2 = BigInt(0);
var _1n2 = BigInt(1);
var _2n = /* @__PURE__ */ BigInt(2);
var _3n = /* @__PURE__ */ BigInt(3);
var _4n = /* @__PURE__ */ BigInt(4);
var _5n = /* @__PURE__ */ BigInt(5);
var _8n = /* @__PURE__ */ BigInt(8);
function mod(a, b) {
  const result = a % b;
  return result >= _0n2 ? result : b + result;
}
function pow2(x, power, modulo) {
  let res = x;
  while (power-- > _0n2) {
    res *= res;
    res %= modulo;
  }
  return res;
}
function invert(number, modulo) {
  if (number === _0n2)
    throw new Error("invert: expected non-zero number");
  if (modulo <= _0n2)
    throw new Error("invert: expected positive modulus, got " + modulo);
  let a = mod(number, modulo);
  let b = modulo;
  let x = _0n2, y = _1n2, u = _1n2, v = _0n2;
  while (a !== _0n2) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd2 = b;
  if (gcd2 !== _1n2)
    throw new Error("invert: does not exist");
  return mod(x, modulo);
}
function sqrt3mod4(Fp2, n) {
  const p1div4 = (Fp2.ORDER + _1n2) / _4n;
  const root = Fp2.pow(n, p1div4);
  if (!Fp2.eql(Fp2.sqr(root), n))
    throw new Error("Cannot find square root");
  return root;
}
function sqrt5mod8(Fp2, n) {
  const p5div8 = (Fp2.ORDER - _5n) / _8n;
  const n2 = Fp2.mul(n, _2n);
  const v = Fp2.pow(n2, p5div8);
  const nv = Fp2.mul(n, v);
  const i = Fp2.mul(Fp2.mul(nv, _2n), v);
  const root = Fp2.mul(nv, Fp2.sub(i, Fp2.ONE));
  if (!Fp2.eql(Fp2.sqr(root), n))
    throw new Error("Cannot find square root");
  return root;
}
function tonelliShanks(P) {
  if (P < BigInt(3))
    throw new Error("sqrt is not defined for small field");
  let Q2 = P - _1n2;
  let S = 0;
  while (Q2 % _2n === _0n2) {
    Q2 /= _2n;
    S++;
  }
  let Z = _2n;
  const _Fp = Field(P);
  while (FpLegendre(_Fp, Z) === 1) {
    if (Z++ > 1e3)
      throw new Error("Cannot find square root: probably non-prime P");
  }
  if (S === 1)
    return sqrt3mod4;
  let cc = _Fp.pow(Z, Q2);
  const Q1div2 = (Q2 + _1n2) / _2n;
  return function tonelliSlow(Fp2, n) {
    if (Fp2.is0(n))
      return n;
    if (FpLegendre(Fp2, n) !== 1)
      throw new Error("Cannot find square root");
    let M = S;
    let c = Fp2.mul(Fp2.ONE, cc);
    let t = Fp2.pow(n, Q2);
    let R = Fp2.pow(n, Q1div2);
    while (!Fp2.eql(t, Fp2.ONE)) {
      if (Fp2.is0(t))
        return Fp2.ZERO;
      let i = 1;
      let t_tmp = Fp2.sqr(t);
      while (!Fp2.eql(t_tmp, Fp2.ONE)) {
        i++;
        t_tmp = Fp2.sqr(t_tmp);
        if (i === M)
          throw new Error("Cannot find square root");
      }
      const exponent = _1n2 << BigInt(M - i - 1);
      const b = Fp2.pow(c, exponent);
      M = i;
      c = Fp2.sqr(b);
      t = Fp2.mul(t, c);
      R = Fp2.mul(R, b);
    }
    return R;
  };
}
function FpSqrt(P) {
  if (P % _4n === _3n)
    return sqrt3mod4;
  if (P % _8n === _5n)
    return sqrt5mod8;
  return tonelliShanks(P);
}
var isNegativeLE = (num, modulo) => (mod(num, modulo) & _1n2) === _1n2;
var FIELD_FIELDS = [
  "create",
  "isValid",
  "is0",
  "neg",
  "inv",
  "sqrt",
  "sqr",
  "eql",
  "add",
  "sub",
  "mul",
  "pow",
  "div",
  "addN",
  "subN",
  "mulN",
  "sqrN"
];
function validateField(field) {
  const initial = {
    ORDER: "bigint",
    MASK: "bigint",
    BYTES: "isSafeInteger",
    BITS: "isSafeInteger"
  };
  const opts = FIELD_FIELDS.reduce((map, val) => {
    map[val] = "function";
    return map;
  }, initial);
  return validateObject(field, opts);
}
function FpPow(Fp2, num, power) {
  if (power < _0n2)
    throw new Error("invalid exponent, negatives unsupported");
  if (power === _0n2)
    return Fp2.ONE;
  if (power === _1n2)
    return num;
  let p = Fp2.ONE;
  let d = num;
  while (power > _0n2) {
    if (power & _1n2)
      p = Fp2.mul(p, d);
    d = Fp2.sqr(d);
    power >>= _1n2;
  }
  return p;
}
function FpInvertBatch(Fp2, nums, passZero = false) {
  const inverted = new Array(nums.length).fill(passZero ? Fp2.ZERO : void 0);
  const multipliedAcc = nums.reduce((acc, num, i) => {
    if (Fp2.is0(num))
      return acc;
    inverted[i] = acc;
    return Fp2.mul(acc, num);
  }, Fp2.ONE);
  const invertedAcc = Fp2.inv(multipliedAcc);
  nums.reduceRight((acc, num, i) => {
    if (Fp2.is0(num))
      return acc;
    inverted[i] = Fp2.mul(acc, inverted[i]);
    return Fp2.mul(acc, num);
  }, invertedAcc);
  return inverted;
}
function FpLegendre(Fp2, n) {
  const p1mod2 = (Fp2.ORDER - _1n2) / _2n;
  const powered = Fp2.pow(n, p1mod2);
  const yes = Fp2.eql(powered, Fp2.ONE);
  const zero = Fp2.eql(powered, Fp2.ZERO);
  const no = Fp2.eql(powered, Fp2.neg(Fp2.ONE));
  if (!yes && !zero && !no)
    throw new Error("invalid Legendre symbol result");
  return yes ? 1 : zero ? 0 : -1;
}
function nLength(n, nBitLength) {
  if (nBitLength !== void 0)
    anumber(nBitLength);
  const _nBitLength = nBitLength !== void 0 ? nBitLength : n.toString(2).length;
  const nByteLength = Math.ceil(_nBitLength / 8);
  return { nBitLength: _nBitLength, nByteLength };
}
function Field(ORDER, bitLen2, isLE2 = false, redef = {}) {
  if (ORDER <= _0n2)
    throw new Error("invalid field: expected ORDER > 0, got " + ORDER);
  const { nBitLength: BITS, nByteLength: BYTES } = nLength(ORDER, bitLen2);
  if (BYTES > 2048)
    throw new Error("invalid field: expected ORDER of <= 2048 bytes");
  let sqrtP;
  const f = Object.freeze({
    ORDER,
    isLE: isLE2,
    BITS,
    BYTES,
    MASK: bitMask(BITS),
    ZERO: _0n2,
    ONE: _1n2,
    create: (num) => mod(num, ORDER),
    isValid: (num) => {
      if (typeof num !== "bigint")
        throw new Error("invalid field element: expected bigint, got " + typeof num);
      return _0n2 <= num && num < ORDER;
    },
    is0: (num) => num === _0n2,
    isOdd: (num) => (num & _1n2) === _1n2,
    neg: (num) => mod(-num, ORDER),
    eql: (lhs, rhs) => lhs === rhs,
    sqr: (num) => mod(num * num, ORDER),
    add: (lhs, rhs) => mod(lhs + rhs, ORDER),
    sub: (lhs, rhs) => mod(lhs - rhs, ORDER),
    mul: (lhs, rhs) => mod(lhs * rhs, ORDER),
    pow: (num, power) => FpPow(f, num, power),
    div: (lhs, rhs) => mod(lhs * invert(rhs, ORDER), ORDER),
    // Same as above, but doesn't normalize
    sqrN: (num) => num * num,
    addN: (lhs, rhs) => lhs + rhs,
    subN: (lhs, rhs) => lhs - rhs,
    mulN: (lhs, rhs) => lhs * rhs,
    inv: (num) => invert(num, ORDER),
    sqrt: redef.sqrt || ((n) => {
      if (!sqrtP)
        sqrtP = FpSqrt(ORDER);
      return sqrtP(f, n);
    }),
    toBytes: (num) => isLE2 ? numberToBytesLE(num, BYTES) : numberToBytesBE(num, BYTES),
    fromBytes: (bytes) => {
      if (bytes.length !== BYTES)
        throw new Error("Field.fromBytes: expected " + BYTES + " bytes, got " + bytes.length);
      return isLE2 ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
    },
    // TODO: we don't need it here, move out to separate fn
    invertBatch: (lst) => FpInvertBatch(f, lst),
    // We can't move this out because Fp6, Fp12 implement it
    // and it's unclear what to return in there.
    cmov: (a, b, c) => c ? b : a
  });
  return Object.freeze(f);
}

// node_modules/.pnpm/@noble+curves@1.9.1/node_modules/@noble/curves/esm/abstract/curve.js
var _0n3 = BigInt(0);
var _1n3 = BigInt(1);
function constTimeNegate(condition, item) {
  const neg = item.negate();
  return condition ? neg : item;
}
function validateW(W, bits) {
  if (!Number.isSafeInteger(W) || W <= 0 || W > bits)
    throw new Error("invalid window size, expected [1.." + bits + "], got W=" + W);
}
function calcWOpts(W, scalarBits) {
  validateW(W, scalarBits);
  const windows = Math.ceil(scalarBits / W) + 1;
  const windowSize = 2 ** (W - 1);
  const maxNumber = 2 ** W;
  const mask = bitMask(W);
  const shiftBy = BigInt(W);
  return { windows, windowSize, mask, maxNumber, shiftBy };
}
function calcOffsets(n, window, wOpts) {
  const { windowSize, mask, maxNumber, shiftBy } = wOpts;
  let wbits = Number(n & mask);
  let nextN = n >> shiftBy;
  if (wbits > windowSize) {
    wbits -= maxNumber;
    nextN += _1n3;
  }
  const offsetStart = window * windowSize;
  const offset = offsetStart + Math.abs(wbits) - 1;
  const isZero = wbits === 0;
  const isNeg = wbits < 0;
  const isNegF = window % 2 !== 0;
  const offsetF = offsetStart;
  return { nextN, offset, isZero, isNeg, isNegF, offsetF };
}
function validateMSMPoints(points, c) {
  if (!Array.isArray(points))
    throw new Error("array expected");
  points.forEach((p, i) => {
    if (!(p instanceof c))
      throw new Error("invalid point at index " + i);
  });
}
function validateMSMScalars(scalars, field) {
  if (!Array.isArray(scalars))
    throw new Error("array of scalars expected");
  scalars.forEach((s, i) => {
    if (!field.isValid(s))
      throw new Error("invalid scalar at index " + i);
  });
}
var pointPrecomputes = /* @__PURE__ */ new WeakMap();
var pointWindowSizes = /* @__PURE__ */ new WeakMap();
function getW(P) {
  return pointWindowSizes.get(P) || 1;
}
function wNAF(c, bits) {
  return {
    constTimeNegate,
    hasPrecomputes(elm) {
      return getW(elm) !== 1;
    },
    // non-const time multiplication ladder
    unsafeLadder(elm, n, p = c.ZERO) {
      let d = elm;
      while (n > _0n3) {
        if (n & _1n3)
          p = p.add(d);
        d = d.double();
        n >>= _1n3;
      }
      return p;
    },
    /**
     * Creates a wNAF precomputation window. Used for caching.
     * Default window size is set by `utils.precompute()` and is equal to 8.
     * Number of precomputed points depends on the curve size:
     * 2^(𝑊−1) * (Math.ceil(𝑛 / 𝑊) + 1), where:
     * - 𝑊 is the window size
     * - 𝑛 is the bitlength of the curve order.
     * For a 256-bit curve and window size 8, the number of precomputed points is 128 * 33 = 4224.
     * @param elm Point instance
     * @param W window size
     * @returns precomputed point tables flattened to a single array
     */
    precomputeWindow(elm, W) {
      const { windows, windowSize } = calcWOpts(W, bits);
      const points = [];
      let p = elm;
      let base = p;
      for (let window = 0; window < windows; window++) {
        base = p;
        points.push(base);
        for (let i = 1; i < windowSize; i++) {
          base = base.add(p);
          points.push(base);
        }
        p = base.double();
      }
      return points;
    },
    /**
     * Implements ec multiplication using precomputed tables and w-ary non-adjacent form.
     * @param W window size
     * @param precomputes precomputed tables
     * @param n scalar (we don't check here, but should be less than curve order)
     * @returns real and fake (for const-time) points
     */
    wNAF(W, precomputes, n) {
      let p = c.ZERO;
      let f = c.BASE;
      const wo = calcWOpts(W, bits);
      for (let window = 0; window < wo.windows; window++) {
        const { nextN, offset, isZero, isNeg, isNegF, offsetF } = calcOffsets(n, window, wo);
        n = nextN;
        if (isZero) {
          f = f.add(constTimeNegate(isNegF, precomputes[offsetF]));
        } else {
          p = p.add(constTimeNegate(isNeg, precomputes[offset]));
        }
      }
      return { p, f };
    },
    /**
     * Implements ec unsafe (non const-time) multiplication using precomputed tables and w-ary non-adjacent form.
     * @param W window size
     * @param precomputes precomputed tables
     * @param n scalar (we don't check here, but should be less than curve order)
     * @param acc accumulator point to add result of multiplication
     * @returns point
     */
    wNAFUnsafe(W, precomputes, n, acc = c.ZERO) {
      const wo = calcWOpts(W, bits);
      for (let window = 0; window < wo.windows; window++) {
        if (n === _0n3)
          break;
        const { nextN, offset, isZero, isNeg } = calcOffsets(n, window, wo);
        n = nextN;
        if (isZero) {
          continue;
        } else {
          const item = precomputes[offset];
          acc = acc.add(isNeg ? item.negate() : item);
        }
      }
      return acc;
    },
    getPrecomputes(W, P, transform) {
      let comp = pointPrecomputes.get(P);
      if (!comp) {
        comp = this.precomputeWindow(P, W);
        if (W !== 1)
          pointPrecomputes.set(P, transform(comp));
      }
      return comp;
    },
    wNAFCached(P, n, transform) {
      const W = getW(P);
      return this.wNAF(W, this.getPrecomputes(W, P, transform), n);
    },
    wNAFCachedUnsafe(P, n, transform, prev) {
      const W = getW(P);
      if (W === 1)
        return this.unsafeLadder(P, n, prev);
      return this.wNAFUnsafe(W, this.getPrecomputes(W, P, transform), n, prev);
    },
    // We calculate precomputes for elliptic curve point multiplication
    // using windowed method. This specifies window size and
    // stores precomputed values. Usually only base point would be precomputed.
    setWindowSize(P, W) {
      validateW(W, bits);
      pointWindowSizes.set(P, W);
      pointPrecomputes.delete(P);
    }
  };
}
function pippenger(c, fieldN, points, scalars) {
  validateMSMPoints(points, c);
  validateMSMScalars(scalars, fieldN);
  const plength = points.length;
  const slength = scalars.length;
  if (plength !== slength)
    throw new Error("arrays of points and scalars must have equal length");
  const zero = c.ZERO;
  const wbits = bitLen(BigInt(plength));
  let windowSize = 1;
  if (wbits > 12)
    windowSize = wbits - 3;
  else if (wbits > 4)
    windowSize = wbits - 2;
  else if (wbits > 0)
    windowSize = 2;
  const MASK = bitMask(windowSize);
  const buckets = new Array(Number(MASK) + 1).fill(zero);
  const lastBits = Math.floor((fieldN.BITS - 1) / windowSize) * windowSize;
  let sum = zero;
  for (let i = lastBits; i >= 0; i -= windowSize) {
    buckets.fill(zero);
    for (let j = 0; j < slength; j++) {
      const scalar = scalars[j];
      const wbits2 = Number(scalar >> BigInt(i) & MASK);
      buckets[wbits2] = buckets[wbits2].add(points[j]);
    }
    let resI = zero;
    for (let j = buckets.length - 1, sumI = zero; j > 0; j--) {
      sumI = sumI.add(buckets[j]);
      resI = resI.add(sumI);
    }
    sum = sum.add(resI);
    if (i !== 0)
      for (let j = 0; j < windowSize; j++)
        sum = sum.double();
  }
  return sum;
}
function validateBasic(curve) {
  validateField(curve.Fp);
  validateObject(curve, {
    n: "bigint",
    h: "bigint",
    Gx: "field",
    Gy: "field"
  }, {
    nBitLength: "isSafeInteger",
    nByteLength: "isSafeInteger"
  });
  return Object.freeze({
    ...nLength(curve.n, curve.nBitLength),
    ...curve,
    ...{ p: curve.Fp.ORDER }
  });
}

// node_modules/.pnpm/@noble+curves@1.9.1/node_modules/@noble/curves/esm/abstract/edwards.js
var _0n4 = BigInt(0);
var _1n4 = BigInt(1);
var _2n2 = BigInt(2);
var _8n2 = BigInt(8);
var VERIFY_DEFAULT = { zip215: true };
function validateOpts(curve) {
  const opts = validateBasic(curve);
  validateObject(curve, {
    hash: "function",
    a: "bigint",
    d: "bigint",
    randomBytes: "function"
  }, {
    adjustScalarBytes: "function",
    domain: "function",
    uvRatio: "function",
    mapToCurve: "function"
  });
  return Object.freeze({ ...opts });
}
function twistedEdwards(curveDef) {
  const CURVE = validateOpts(curveDef);
  const { Fp: Fp2, n: CURVE_ORDER, prehash, hash: cHash, randomBytes: randomBytes3, nByteLength, h: cofactor } = CURVE;
  const MASK = _2n2 << BigInt(nByteLength * 8) - _1n4;
  const modP = Fp2.create;
  const Fn = Field(CURVE.n, CURVE.nBitLength);
  function isEdValidXY(x, y) {
    const x2 = Fp2.sqr(x);
    const y2 = Fp2.sqr(y);
    const left = Fp2.add(Fp2.mul(CURVE.a, x2), y2);
    const right = Fp2.add(Fp2.ONE, Fp2.mul(CURVE.d, Fp2.mul(x2, y2)));
    return Fp2.eql(left, right);
  }
  if (!isEdValidXY(CURVE.Gx, CURVE.Gy))
    throw new Error("bad curve params: generator point");
  const uvRatio2 = CURVE.uvRatio || ((u, v) => {
    try {
      return { isValid: true, value: Fp2.sqrt(u * Fp2.inv(v)) };
    } catch (e) {
      return { isValid: false, value: _0n4 };
    }
  });
  const adjustScalarBytes2 = CURVE.adjustScalarBytes || ((bytes) => bytes);
  const domain = CURVE.domain || ((data, ctx, phflag) => {
    abool("phflag", phflag);
    if (ctx.length || phflag)
      throw new Error("Contexts/pre-hash are not supported");
    return data;
  });
  function aCoordinate(title, n, banZero = false) {
    const min = banZero ? _1n4 : _0n4;
    aInRange("coordinate " + title, n, min, MASK);
  }
  function aextpoint(other) {
    if (!(other instanceof Point))
      throw new Error("ExtendedPoint expected");
  }
  const toAffineMemo = memoized((p, iz) => {
    const { ex: x, ey: y, ez: z } = p;
    const is0 = p.is0();
    if (iz == null)
      iz = is0 ? _8n2 : Fp2.inv(z);
    const ax = modP(x * iz);
    const ay = modP(y * iz);
    const zz = modP(z * iz);
    if (is0)
      return { x: _0n4, y: _1n4 };
    if (zz !== _1n4)
      throw new Error("invZ was invalid");
    return { x: ax, y: ay };
  });
  const assertValidMemo = memoized((p) => {
    const { a, d } = CURVE;
    if (p.is0())
      throw new Error("bad point: ZERO");
    const { ex: X, ey: Y, ez: Z, et: T } = p;
    const X2 = modP(X * X);
    const Y2 = modP(Y * Y);
    const Z2 = modP(Z * Z);
    const Z4 = modP(Z2 * Z2);
    const aX2 = modP(X2 * a);
    const left = modP(Z2 * modP(aX2 + Y2));
    const right = modP(Z4 + modP(d * modP(X2 * Y2)));
    if (left !== right)
      throw new Error("bad point: equation left != right (1)");
    const XY = modP(X * Y);
    const ZT = modP(Z * T);
    if (XY !== ZT)
      throw new Error("bad point: equation left != right (2)");
    return true;
  });
  class Point {
    constructor(ex, ey, ez, et) {
      aCoordinate("x", ex);
      aCoordinate("y", ey);
      aCoordinate("z", ez, true);
      aCoordinate("t", et);
      this.ex = ex;
      this.ey = ey;
      this.ez = ez;
      this.et = et;
      Object.freeze(this);
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    static fromAffine(p) {
      if (p instanceof Point)
        throw new Error("extended point not allowed");
      const { x, y } = p || {};
      aCoordinate("x", x);
      aCoordinate("y", y);
      return new Point(x, y, _1n4, modP(x * y));
    }
    static normalizeZ(points) {
      const toInv = FpInvertBatch(Fp2, points.map((p) => p.ez));
      return points.map((p, i) => p.toAffine(toInv[i])).map(Point.fromAffine);
    }
    // Multiscalar Multiplication
    static msm(points, scalars) {
      return pippenger(Point, Fn, points, scalars);
    }
    // "Private method", don't use it directly
    _setWindowSize(windowSize) {
      wnaf.setWindowSize(this, windowSize);
    }
    // Not required for fromHex(), which always creates valid points.
    // Could be useful for fromAffine().
    assertValidity() {
      assertValidMemo(this);
    }
    // Compare one point to another.
    equals(other) {
      aextpoint(other);
      const { ex: X1, ey: Y1, ez: Z1 } = this;
      const { ex: X2, ey: Y2, ez: Z2 } = other;
      const X1Z2 = modP(X1 * Z2);
      const X2Z1 = modP(X2 * Z1);
      const Y1Z2 = modP(Y1 * Z2);
      const Y2Z1 = modP(Y2 * Z1);
      return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
    }
    is0() {
      return this.equals(Point.ZERO);
    }
    negate() {
      return new Point(modP(-this.ex), this.ey, this.ez, modP(-this.et));
    }
    // Fast algo for doubling Extended Point.
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
    // Cost: 4M + 4S + 1*a + 6add + 1*2.
    double() {
      const { a } = CURVE;
      const { ex: X1, ey: Y1, ez: Z1 } = this;
      const A = modP(X1 * X1);
      const B = modP(Y1 * Y1);
      const C = modP(_2n2 * modP(Z1 * Z1));
      const D2 = modP(a * A);
      const x1y1 = X1 + Y1;
      const E = modP(modP(x1y1 * x1y1) - A - B);
      const G2 = D2 + B;
      const F2 = G2 - C;
      const H = D2 - B;
      const X3 = modP(E * F2);
      const Y3 = modP(G2 * H);
      const T3 = modP(E * H);
      const Z3 = modP(F2 * G2);
      return new Point(X3, Y3, Z3, T3);
    }
    // Fast algo for adding 2 Extended Points.
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-add-2008-hwcd
    // Cost: 9M + 1*a + 1*d + 7add.
    add(other) {
      aextpoint(other);
      const { a, d } = CURVE;
      const { ex: X1, ey: Y1, ez: Z1, et: T1 } = this;
      const { ex: X2, ey: Y2, ez: Z2, et: T2 } = other;
      const A = modP(X1 * X2);
      const B = modP(Y1 * Y2);
      const C = modP(T1 * d * T2);
      const D2 = modP(Z1 * Z2);
      const E = modP((X1 + Y1) * (X2 + Y2) - A - B);
      const F2 = D2 - C;
      const G2 = D2 + C;
      const H = modP(B - a * A);
      const X3 = modP(E * F2);
      const Y3 = modP(G2 * H);
      const T3 = modP(E * H);
      const Z3 = modP(F2 * G2);
      return new Point(X3, Y3, Z3, T3);
    }
    subtract(other) {
      return this.add(other.negate());
    }
    wNAF(n) {
      return wnaf.wNAFCached(this, n, Point.normalizeZ);
    }
    // Constant-time multiplication.
    multiply(scalar) {
      const n = scalar;
      aInRange("scalar", n, _1n4, CURVE_ORDER);
      const { p, f } = this.wNAF(n);
      return Point.normalizeZ([p, f])[0];
    }
    // Non-constant-time multiplication. Uses double-and-add algorithm.
    // It's faster, but should only be used when you don't care about
    // an exposed private key e.g. sig verification.
    // Does NOT allow scalars higher than CURVE.n.
    // Accepts optional accumulator to merge with multiply (important for sparse scalars)
    multiplyUnsafe(scalar, acc = Point.ZERO) {
      const n = scalar;
      aInRange("scalar", n, _0n4, CURVE_ORDER);
      if (n === _0n4)
        return I;
      if (this.is0() || n === _1n4)
        return this;
      return wnaf.wNAFCachedUnsafe(this, n, Point.normalizeZ, acc);
    }
    // Checks if point is of small order.
    // If you add something to small order point, you will have "dirty"
    // point with torsion component.
    // Multiplies point by cofactor and checks if the result is 0.
    isSmallOrder() {
      return this.multiplyUnsafe(cofactor).is0();
    }
    // Multiplies point by curve order and checks if the result is 0.
    // Returns `false` is the point is dirty.
    isTorsionFree() {
      return wnaf.unsafeLadder(this, CURVE_ORDER).is0();
    }
    // Converts Extended point to default (x, y) coordinates.
    // Can accept precomputed Z^-1 - for example, from invertBatch.
    toAffine(iz) {
      return toAffineMemo(this, iz);
    }
    clearCofactor() {
      const { h: cofactor2 } = CURVE;
      if (cofactor2 === _1n4)
        return this;
      return this.multiplyUnsafe(cofactor2);
    }
    // Converts hash string or Uint8Array to Point.
    // Uses algo from RFC8032 5.1.3.
    static fromHex(hex, zip215 = false) {
      const { d, a } = CURVE;
      const len = Fp2.BYTES;
      hex = ensureBytes("pointHex", hex, len);
      abool("zip215", zip215);
      const normed = hex.slice();
      const lastByte = hex[len - 1];
      normed[len - 1] = lastByte & ~128;
      const y = bytesToNumberLE(normed);
      const max = zip215 ? MASK : Fp2.ORDER;
      aInRange("pointHex.y", y, _0n4, max);
      const y2 = modP(y * y);
      const u = modP(y2 - _1n4);
      const v = modP(d * y2 - a);
      let { isValid, value: x } = uvRatio2(u, v);
      if (!isValid)
        throw new Error("Point.fromHex: invalid y coordinate");
      const isXOdd = (x & _1n4) === _1n4;
      const isLastByteOdd = (lastByte & 128) !== 0;
      if (!zip215 && x === _0n4 && isLastByteOdd)
        throw new Error("Point.fromHex: x=0 and x_0=1");
      if (isLastByteOdd !== isXOdd)
        x = modP(-x);
      return Point.fromAffine({ x, y });
    }
    static fromPrivateKey(privKey) {
      const { scalar } = getPrivateScalar(privKey);
      return G.multiply(scalar);
    }
    toRawBytes() {
      const { x, y } = this.toAffine();
      const bytes = numberToBytesLE(y, Fp2.BYTES);
      bytes[bytes.length - 1] |= x & _1n4 ? 128 : 0;
      return bytes;
    }
    toHex() {
      return bytesToHex2(this.toRawBytes());
    }
  }
  Point.BASE = new Point(CURVE.Gx, CURVE.Gy, _1n4, modP(CURVE.Gx * CURVE.Gy));
  Point.ZERO = new Point(_0n4, _1n4, _1n4, _0n4);
  const { BASE: G, ZERO: I } = Point;
  const wnaf = wNAF(Point, nByteLength * 8);
  function modN(a) {
    return mod(a, CURVE_ORDER);
  }
  function modN_LE(hash) {
    return modN(bytesToNumberLE(hash));
  }
  function getPrivateScalar(key) {
    const len = Fp2.BYTES;
    key = ensureBytes("private key", key, len);
    const hashed = ensureBytes("hashed private key", cHash(key), 2 * len);
    const head = adjustScalarBytes2(hashed.slice(0, len));
    const prefix = hashed.slice(len, 2 * len);
    const scalar = modN_LE(head);
    return { head, prefix, scalar };
  }
  function getExtendedPublicKey(key) {
    const { head, prefix, scalar } = getPrivateScalar(key);
    const point = G.multiply(scalar);
    const pointBytes = point.toRawBytes();
    return { head, prefix, scalar, point, pointBytes };
  }
  function getPublicKey(privKey) {
    return getExtendedPublicKey(privKey).pointBytes;
  }
  function hashDomainToScalar(context = Uint8Array.of(), ...msgs) {
    const msg = concatBytes2(...msgs);
    return modN_LE(cHash(domain(msg, ensureBytes("context", context), !!prehash)));
  }
  function sign2(msg, privKey, options = {}) {
    msg = ensureBytes("message", msg);
    if (prehash)
      msg = prehash(msg);
    const { prefix, scalar, pointBytes } = getExtendedPublicKey(privKey);
    const r = hashDomainToScalar(options.context, prefix, msg);
    const R = G.multiply(r).toRawBytes();
    const k = hashDomainToScalar(options.context, R, pointBytes, msg);
    const s = modN(r + k * scalar);
    aInRange("signature.s", s, _0n4, CURVE_ORDER);
    const res = concatBytes2(R, numberToBytesLE(s, Fp2.BYTES));
    return ensureBytes("result", res, Fp2.BYTES * 2);
  }
  const verifyOpts = VERIFY_DEFAULT;
  function verify2(sig, msg, publicKey, options = verifyOpts) {
    const { context, zip215 } = options;
    const len = Fp2.BYTES;
    sig = ensureBytes("signature", sig, 2 * len);
    msg = ensureBytes("message", msg);
    publicKey = ensureBytes("publicKey", publicKey, len);
    if (zip215 !== void 0)
      abool("zip215", zip215);
    if (prehash)
      msg = prehash(msg);
    const s = bytesToNumberLE(sig.slice(len, 2 * len));
    let A, R, SB;
    try {
      A = Point.fromHex(publicKey, zip215);
      R = Point.fromHex(sig.slice(0, len), zip215);
      SB = G.multiplyUnsafe(s);
    } catch (error) {
      return false;
    }
    if (!zip215 && A.isSmallOrder())
      return false;
    const k = hashDomainToScalar(context, R.toRawBytes(), A.toRawBytes(), msg);
    const RkA = R.add(A.multiplyUnsafe(k));
    return RkA.subtract(SB).clearCofactor().equals(Point.ZERO);
  }
  G._setWindowSize(8);
  const utils = {
    getExtendedPublicKey,
    /** ed25519 priv keys are uniform 32b. No need to check for modulo bias, like in secp256k1. */
    randomPrivateKey: () => randomBytes3(Fp2.BYTES),
    /**
     * We're doing scalar multiplication (used in getPublicKey etc) with precomputed BASE_POINT
     * values. This slows down first getPublicKey() by milliseconds (see Speed section),
     * but allows to speed-up subsequent getPublicKey() calls up to 20x.
     * @param windowSize 2, 4, 8, 16
     */
    precompute(windowSize = 8, point = Point.BASE) {
      point._setWindowSize(windowSize);
      point.multiply(BigInt(3));
      return point;
    }
  };
  return {
    CURVE,
    getPublicKey,
    sign: sign2,
    verify: verify2,
    ExtendedPoint: Point,
    utils
  };
}

// node_modules/.pnpm/@noble+curves@1.9.1/node_modules/@noble/curves/esm/ed25519.js
var ED25519_P = BigInt("57896044618658097711785492504343953926634992332820282019728792003956564819949");
var ED25519_SQRT_M1 = /* @__PURE__ */ BigInt("19681161376707505956807079304988542015446066515923890162744021073123829784752");
var _0n5 = BigInt(0);
var _1n5 = BigInt(1);
var _2n3 = BigInt(2);
var _3n2 = BigInt(3);
var _5n2 = BigInt(5);
var _8n3 = BigInt(8);
function ed25519_pow_2_252_3(x) {
  const _10n = BigInt(10), _20n = BigInt(20), _40n = BigInt(40), _80n = BigInt(80);
  const P = ED25519_P;
  const x2 = x * x % P;
  const b2 = x2 * x % P;
  const b4 = pow2(b2, _2n3, P) * b2 % P;
  const b5 = pow2(b4, _1n5, P) * x % P;
  const b10 = pow2(b5, _5n2, P) * b5 % P;
  const b20 = pow2(b10, _10n, P) * b10 % P;
  const b40 = pow2(b20, _20n, P) * b20 % P;
  const b80 = pow2(b40, _40n, P) * b40 % P;
  const b160 = pow2(b80, _80n, P) * b80 % P;
  const b240 = pow2(b160, _80n, P) * b80 % P;
  const b250 = pow2(b240, _10n, P) * b10 % P;
  const pow_p_5_8 = pow2(b250, _2n3, P) * x % P;
  return { pow_p_5_8, b2 };
}
function adjustScalarBytes(bytes) {
  bytes[0] &= 248;
  bytes[31] &= 127;
  bytes[31] |= 64;
  return bytes;
}
function uvRatio(u, v) {
  const P = ED25519_P;
  const v3 = mod(v * v * v, P);
  const v7 = mod(v3 * v3 * v, P);
  const pow = ed25519_pow_2_252_3(u * v7).pow_p_5_8;
  let x = mod(u * v3 * pow, P);
  const vx2 = mod(v * x * x, P);
  const root1 = x;
  const root2 = mod(x * ED25519_SQRT_M1, P);
  const useRoot1 = vx2 === u;
  const useRoot2 = vx2 === mod(-u, P);
  const noRoot = vx2 === mod(-u * ED25519_SQRT_M1, P);
  if (useRoot1)
    x = root1;
  if (useRoot2 || noRoot)
    x = root2;
  if (isNegativeLE(x, P))
    x = mod(-x, P);
  return { isValid: useRoot1 || useRoot2, value: x };
}
var Fp = /* @__PURE__ */ (() => Field(ED25519_P, void 0, true))();
var ed25519Defaults = /* @__PURE__ */ (() => ({
  // Removing Fp.create() will still work, and is 10% faster on sign
  a: Fp.create(BigInt(-1)),
  // d is -121665/121666 a.k.a. Fp.neg(121665 * Fp.inv(121666))
  d: BigInt("37095705934669439343138083508754565189542113879843219016388785533085940283555"),
  // Finite field 2n**255n - 19n
  Fp,
  // Subgroup order 2n**252n + 27742317777372353535851937790883648493n;
  n: BigInt("7237005577332262213973186563042994240857116359379907606001950938285454250989"),
  h: _8n3,
  Gx: BigInt("15112221349535400772501151409588531511454012693041857206046113283949847762202"),
  Gy: BigInt("46316835694926478169428394003475163141307993866256225615783033603165251855960"),
  hash: sha512,
  randomBytes,
  adjustScalarBytes,
  // dom2
  // Ratio of u to v. Allows us to combine inversion and square root. Uses algo from RFC8032 5.1.3.
  // Constant-time, u/√v
  uvRatio
}))();
var ed25519 = /* @__PURE__ */ (() => twistedEdwards(ed25519Defaults))();

// packages/pca/src/keys.ts
var EdPoint = ed25519.ExtendedPoint;
function generateKeyPair() {
  const secretKey = ed25519.utils.randomPrivateKey();
  return { secretKey, publicKey: ed25519.getPublicKey(secretKey) };
}
function publicKeyOf(secretKey) {
  return ed25519.getPublicKey(secretKey);
}
function sign(secretKey, msg) {
  return ed25519.sign(msg, secretKey);
}
function verify(publicKey, msg, sig) {
  try {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) return false;
    if (!(sig instanceof Uint8Array) || sig.length !== 64) return false;
    if (!ed25519.verify(sig, msg, publicKey, { zip215: false })) return false;
    const A = EdPoint.fromHex(publicKey);
    const R = EdPoint.fromHex(sig.subarray(0, 32));
    if (A.isSmallOrder() || R.isSmallOrder()) return false;
    if (!A.isTorsionFree() || !R.isTorsionFree()) return false;
    return true;
  } catch {
    return false;
  }
}
var encodeKey = b64u;
function verifyB64u(publicKeyB64u, msg, sigB64u) {
  try {
    const pk = decodeB64uStrict(publicKeyB64u, 32);
    const sg = decodeB64uStrict(sigB64u, 64);
    if (!pk || !sg) return false;
    return verify(pk, msg, sg);
  } catch {
    return false;
  }
}

// tools/pca-playground/shims/node-module.js
function createRequire() {
  throw new Error("node:module is not available in the browser");
}

// tools/pca-playground/shims/node-path.js
function join2(...parts) {
  return parts.join("/");
}

// node_modules/.pnpm/@noble+hashes@1.8.0/node_modules/@noble/hashes/esm/sha3.js
var _0n6 = BigInt(0);
var _1n6 = BigInt(1);
var _2n4 = BigInt(2);
var _7n = BigInt(7);
var _256n = BigInt(256);
var _0x71n = BigInt(113);
var SHA3_PI = [];
var SHA3_ROTL = [];
var _SHA3_IOTA = [];
for (let round = 0, R = _1n6, x = 1, y = 0; round < 24; round++) {
  [x, y] = [y, (2 * x + 3 * y) % 5];
  SHA3_PI.push(2 * (5 * y + x));
  SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
  let t = _0n6;
  for (let j = 0; j < 7; j++) {
    R = (R << _1n6 ^ (R >> _7n) * _0x71n) % _256n;
    if (R & _2n4)
      t ^= _1n6 << (_1n6 << /* @__PURE__ */ BigInt(j)) - _1n6;
  }
  _SHA3_IOTA.push(t);
}
var IOTAS = split(_SHA3_IOTA, true);
var SHA3_IOTA_H = IOTAS[0];
var SHA3_IOTA_L = IOTAS[1];
var rotlH = (h, l, s) => s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s);
var rotlL = (h, l, s) => s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s);
function keccakP(s, rounds = 24) {
  const B = new Uint32Array(5 * 2);
  for (let round = 24 - rounds; round < 24; round++) {
    for (let x = 0; x < 10; x++)
      B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
    for (let x = 0; x < 10; x += 2) {
      const idx1 = (x + 8) % 10;
      const idx0 = (x + 2) % 10;
      const B0 = B[idx0];
      const B1 = B[idx0 + 1];
      const Th = rotlH(B0, B1, 1) ^ B[idx1];
      const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
      for (let y = 0; y < 50; y += 10) {
        s[x + y] ^= Th;
        s[x + y + 1] ^= Tl;
      }
    }
    let curH = s[2];
    let curL = s[3];
    for (let t = 0; t < 24; t++) {
      const shift = SHA3_ROTL[t];
      const Th = rotlH(curH, curL, shift);
      const Tl = rotlL(curH, curL, shift);
      const PI = SHA3_PI[t];
      curH = s[PI];
      curL = s[PI + 1];
      s[PI] = Th;
      s[PI + 1] = Tl;
    }
    for (let y = 0; y < 50; y += 10) {
      for (let x = 0; x < 10; x++)
        B[x] = s[y + x];
      for (let x = 0; x < 10; x++)
        s[y + x] ^= ~B[(x + 2) % 10] & B[(x + 4) % 10];
    }
    s[0] ^= SHA3_IOTA_H[round];
    s[1] ^= SHA3_IOTA_L[round];
  }
  clean(B);
}
var Keccak = class _Keccak extends Hash {
  // NOTE: we accept arguments in bytes instead of bits here.
  constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
    super();
    this.pos = 0;
    this.posOut = 0;
    this.finished = false;
    this.destroyed = false;
    this.enableXOF = false;
    this.blockLen = blockLen;
    this.suffix = suffix;
    this.outputLen = outputLen;
    this.enableXOF = enableXOF;
    this.rounds = rounds;
    anumber(outputLen);
    if (!(0 < blockLen && blockLen < 200))
      throw new Error("only keccak-f1600 function is supported");
    this.state = new Uint8Array(200);
    this.state32 = u32(this.state);
  }
  clone() {
    return this._cloneInto();
  }
  keccak() {
    swap32IfBE(this.state32);
    keccakP(this.state32, this.rounds);
    swap32IfBE(this.state32);
    this.posOut = 0;
    this.pos = 0;
  }
  update(data) {
    aexists(this);
    data = toBytes(data);
    abytes(data);
    const { blockLen, state } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      for (let i = 0; i < take; i++)
        state[this.pos++] ^= data[pos++];
      if (this.pos === blockLen)
        this.keccak();
    }
    return this;
  }
  finish() {
    if (this.finished)
      return;
    this.finished = true;
    const { state, suffix, pos, blockLen } = this;
    state[pos] ^= suffix;
    if ((suffix & 128) !== 0 && pos === blockLen - 1)
      this.keccak();
    state[blockLen - 1] ^= 128;
    this.keccak();
  }
  writeInto(out) {
    aexists(this, false);
    abytes(out);
    this.finish();
    const bufferOut = this.state;
    const { blockLen } = this;
    for (let pos = 0, len = out.length; pos < len; ) {
      if (this.posOut >= blockLen)
        this.keccak();
      const take = Math.min(blockLen - this.posOut, len - pos);
      out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
      this.posOut += take;
      pos += take;
    }
    return out;
  }
  xofInto(out) {
    if (!this.enableXOF)
      throw new Error("XOF is not possible for this instance");
    return this.writeInto(out);
  }
  xof(bytes) {
    anumber(bytes);
    return this.xofInto(new Uint8Array(bytes));
  }
  digestInto(out) {
    aoutput(out, this);
    if (this.finished)
      throw new Error("digest() was already called");
    this.writeInto(out);
    this.destroy();
    return out;
  }
  digest() {
    return this.digestInto(new Uint8Array(this.outputLen));
  }
  destroy() {
    this.destroyed = true;
    clean(this.state);
  }
  _cloneInto(to) {
    const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
    to || (to = new _Keccak(blockLen, suffix, outputLen, enableXOF, rounds));
    to.state32.set(this.state32);
    to.pos = this.pos;
    to.posOut = this.posOut;
    to.finished = this.finished;
    to.rounds = rounds;
    to.suffix = suffix;
    to.outputLen = outputLen;
    to.enableXOF = enableXOF;
    to.destroyed = this.destroyed;
    return to;
  }
};
var gen = (suffix, blockLen, outputLen) => createHasher(() => new Keccak(blockLen, suffix, outputLen));
var sha3_224 = /* @__PURE__ */ (() => gen(6, 144, 224 / 8))();
var sha3_256 = /* @__PURE__ */ (() => gen(6, 136, 256 / 8))();
var sha3_384 = /* @__PURE__ */ (() => gen(6, 104, 384 / 8))();
var sha3_512 = /* @__PURE__ */ (() => gen(6, 72, 512 / 8))();
var genShake = (suffix, blockLen, outputLen) => createXOFer((opts = {}) => new Keccak(blockLen, suffix, opts.dkLen === void 0 ? outputLen : opts.dkLen, true));
var shake128 = /* @__PURE__ */ (() => genShake(31, 168, 128 / 8))();
var shake256 = /* @__PURE__ */ (() => genShake(31, 136, 256 / 8))();

// node_modules/.pnpm/@noble+post-quantum@0.4.1/node_modules/@noble/post-quantum/esm/utils.js
var ensureBytes2 = abytes;
var randomBytes2 = randomBytes;
function equalBytes(a, b) {
  if (a.length !== b.length)
    return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++)
    diff |= a[i] ^ b[i];
  return diff === 0;
}
function splitCoder(...lengths) {
  const getLength = (c) => typeof c === "number" ? c : c.bytesLen;
  const bytesLen = lengths.reduce((sum, a) => sum + getLength(a), 0);
  return {
    bytesLen,
    encode: (bufs) => {
      const res = new Uint8Array(bytesLen);
      for (let i = 0, pos = 0; i < lengths.length; i++) {
        const c = lengths[i];
        const l = getLength(c);
        const b = typeof c === "number" ? bufs[i] : c.encode(bufs[i]);
        ensureBytes2(b, l);
        res.set(b, pos);
        if (typeof c !== "number")
          b.fill(0);
        pos += l;
      }
      return res;
    },
    decode: (buf) => {
      ensureBytes2(buf, bytesLen);
      const res = [];
      for (const c of lengths) {
        const l = getLength(c);
        const b = buf.subarray(0, l);
        res.push(typeof c === "number" ? b : c.decode(b));
        buf = buf.subarray(l);
      }
      return res;
    }
  };
}
function vecCoder(c, vecLen) {
  const bytesLen = vecLen * c.bytesLen;
  return {
    bytesLen,
    encode: (u) => {
      if (u.length !== vecLen)
        throw new Error(`vecCoder.encode: wrong length=${u.length}. Expected: ${vecLen}`);
      const res = new Uint8Array(bytesLen);
      for (let i = 0, pos = 0; i < u.length; i++) {
        const b = c.encode(u[i]);
        res.set(b, pos);
        b.fill(0);
        pos += b.length;
      }
      return res;
    },
    decode: (a) => {
      ensureBytes2(a, bytesLen);
      const r = [];
      for (let i = 0; i < a.length; i += c.bytesLen)
        r.push(c.decode(a.subarray(i, i + c.bytesLen)));
      return r;
    }
  };
}
function cleanBytes(...list) {
  for (const t of list) {
    if (Array.isArray(t))
      for (const b of t)
        b.fill(0);
    else
      t.fill(0);
  }
}
function getMask(bits) {
  return (1 << bits) - 1;
}
var EMPTY = new Uint8Array(0);
function getMessage(msg, ctx = EMPTY) {
  ensureBytes2(msg);
  ensureBytes2(ctx);
  if (ctx.length > 255)
    throw new Error("context should be less than 255 bytes");
  return concatBytes(new Uint8Array([0, ctx.length]), ctx, msg);
}
var HASHES = {
  "SHA2-256": { oid: hexToBytes("0609608648016503040201"), hash: sha256 },
  "SHA2-384": { oid: hexToBytes("0609608648016503040202"), hash: sha384 },
  "SHA2-512": { oid: hexToBytes("0609608648016503040203"), hash: sha512 },
  "SHA2-224": { oid: hexToBytes("0609608648016503040204"), hash: sha224 },
  "SHA2-512/224": { oid: hexToBytes("0609608648016503040205"), hash: sha512_224 },
  "SHA2-512/256": { oid: hexToBytes("0609608648016503040206"), hash: sha512_256 },
  "SHA3-224": { oid: hexToBytes("0609608648016503040207"), hash: sha3_224 },
  "SHA3-256": { oid: hexToBytes("0609608648016503040208"), hash: sha3_256 },
  "SHA3-384": { oid: hexToBytes("0609608648016503040209"), hash: sha3_384 },
  "SHA3-512": { oid: hexToBytes("060960864801650304020A"), hash: sha3_512 },
  "SHAKE-128": {
    oid: hexToBytes("060960864801650304020B"),
    hash: (msg) => shake128(msg, { dkLen: 32 })
  },
  "SHAKE-256": {
    oid: hexToBytes("060960864801650304020C"),
    hash: (msg) => shake256(msg, { dkLen: 64 })
  }
};
function getMessagePrehash(hashName, msg, ctx = EMPTY) {
  ensureBytes2(msg);
  ensureBytes2(ctx);
  if (ctx.length > 255)
    throw new Error("context should be less than 255 bytes");
  if (!HASHES[hashName])
    throw new Error("unknown hash: " + hashName);
  const { oid, hash } = HASHES[hashName];
  const hashed = hash(msg);
  return concatBytes(new Uint8Array([1, ctx.length]), ctx, oid, hashed);
}

// node_modules/.pnpm/@noble+post-quantum@0.4.1/node_modules/@noble/post-quantum/esm/_crystals.js
function bitReversal(n, bits = 8) {
  const padded = n.toString(2).padStart(8, "0");
  const sliced = padded.slice(-bits).padStart(7, "0");
  const revrsd = sliced.split("").reverse().join("");
  return Number.parseInt(revrsd, 2);
}
var genCrystals = (opts) => {
  const { newPoly: newPoly2, N: N2, Q: Q2, F: F2, ROOT_OF_UNITY: ROOT_OF_UNITY2, brvBits, isKyber } = opts;
  const mod3 = (a, modulo = Q2) => {
    const result = a % modulo | 0;
    return (result >= 0 ? result | 0 : modulo + result | 0) | 0;
  };
  const smod2 = (a, modulo = Q2) => {
    const r = mod3(a, modulo) | 0;
    return (r > modulo >> 1 ? r - modulo | 0 : r) | 0;
  };
  function getZettas() {
    const out = newPoly2(N2);
    for (let i = 0; i < N2; i++) {
      const b = bitReversal(i, brvBits);
      const p = BigInt(ROOT_OF_UNITY2) ** BigInt(b) % BigInt(Q2);
      out[i] = Number(p) | 0;
    }
    return out;
  }
  const nttZetas = getZettas();
  const LEN1 = isKyber ? 128 : N2;
  const LEN2 = isKyber ? 1 : 0;
  const NTT2 = {
    encode: (r) => {
      for (let k = 1, len = 128; len > LEN2; len >>= 1) {
        for (let start = 0; start < N2; start += 2 * len) {
          const zeta = nttZetas[k++];
          for (let j = start; j < start + len; j++) {
            const t = mod3(zeta * r[j + len]);
            r[j + len] = mod3(r[j] - t) | 0;
            r[j] = mod3(r[j] + t) | 0;
          }
        }
      }
      return r;
    },
    decode: (r) => {
      for (let k = LEN1 - 1, len = 1 + LEN2; len < LEN1 + LEN2; len <<= 1) {
        for (let start = 0; start < N2; start += 2 * len) {
          const zeta = nttZetas[k--];
          for (let j = start; j < start + len; j++) {
            const t = r[j];
            r[j] = mod3(t + r[j + len]);
            r[j + len] = mod3(zeta * (r[j + len] - t));
          }
        }
      }
      for (let i = 0; i < r.length; i++)
        r[i] = mod3(F2 * r[i]);
      return r;
    }
  };
  const bitsCoder2 = (d, c) => {
    const mask = getMask(d);
    const bytesLen = d * (N2 / 8);
    return {
      bytesLen,
      encode: (poly) => {
        const r = new Uint8Array(bytesLen);
        for (let i = 0, buf = 0, bufLen = 0, pos = 0; i < poly.length; i++) {
          buf |= (c.encode(poly[i]) & mask) << bufLen;
          bufLen += d;
          for (; bufLen >= 8; bufLen -= 8, buf >>= 8)
            r[pos++] = buf & getMask(bufLen);
        }
        return r;
      },
      decode: (bytes) => {
        const r = newPoly2(N2);
        for (let i = 0, buf = 0, bufLen = 0, pos = 0; i < bytes.length; i++) {
          buf |= bytes[i] << bufLen;
          bufLen += 8;
          for (; bufLen >= d; bufLen -= d, buf >>= d)
            r[pos++] = c.decode(buf & mask);
        }
        return r;
      }
    };
  };
  return { mod: mod3, smod: smod2, nttZetas, NTT: NTT2, bitsCoder: bitsCoder2 };
};
var createXofShake = (shake) => (seed, blockLen) => {
  if (!blockLen)
    blockLen = shake.blockLen;
  const _seed = new Uint8Array(seed.length + 2);
  _seed.set(seed);
  const seedLen = seed.length;
  const buf = new Uint8Array(blockLen);
  let h = shake.create({});
  let calls = 0;
  let xofs = 0;
  return {
    stats: () => ({ calls, xofs }),
    get: (x, y) => {
      _seed[seedLen + 0] = x;
      _seed[seedLen + 1] = y;
      h.destroy();
      h = shake.create({}).update(_seed);
      calls++;
      return () => {
        xofs++;
        return h.xofInto(buf);
      };
    },
    clean: () => {
      h.destroy();
      buf.fill(0);
      _seed.fill(0);
    }
  };
};
var XOF128 = /* @__PURE__ */ createXofShake(shake128);
var XOF256 = /* @__PURE__ */ createXofShake(shake256);

// node_modules/.pnpm/@noble+post-quantum@0.4.1/node_modules/@noble/post-quantum/esm/ml-dsa.js
var N = 256;
var Q = 8380417;
var ROOT_OF_UNITY = 1753;
var F = 8347681;
var D = 13;
var GAMMA2_1 = Math.floor((Q - 1) / 88) | 0;
var GAMMA2_2 = Math.floor((Q - 1) / 32) | 0;
var PARAMS = {
  2: { K: 4, L: 4, D, GAMMA1: 2 ** 17, GAMMA2: GAMMA2_1, TAU: 39, ETA: 2, OMEGA: 80 },
  3: { K: 6, L: 5, D, GAMMA1: 2 ** 19, GAMMA2: GAMMA2_2, TAU: 49, ETA: 4, OMEGA: 55 },
  5: { K: 8, L: 7, D, GAMMA1: 2 ** 19, GAMMA2: GAMMA2_2, TAU: 60, ETA: 2, OMEGA: 75 }
};
var newPoly = (n) => new Int32Array(n);
var { mod: mod2, smod, NTT, bitsCoder } = genCrystals({
  N,
  Q,
  F,
  ROOT_OF_UNITY,
  newPoly,
  isKyber: false,
  brvBits: 8
});
var id = (n) => n;
var polyCoder = (d, compress = id, verify2 = id) => bitsCoder(d, {
  encode: (i) => compress(verify2(i)),
  decode: (i) => verify2(compress(i))
});
var polyAdd = (a, b) => {
  for (let i = 0; i < a.length; i++)
    a[i] = mod2(a[i] + b[i]);
  return a;
};
var polySub = (a, b) => {
  for (let i = 0; i < a.length; i++)
    a[i] = mod2(a[i] - b[i]);
  return a;
};
var polyShiftl = (p) => {
  for (let i = 0; i < N; i++)
    p[i] <<= D;
  return p;
};
var polyChknorm = (p, B) => {
  for (let i = 0; i < N; i++)
    if (Math.abs(smod(p[i])) >= B)
      return true;
  return false;
};
var MultiplyNTTs = (a, b) => {
  const c = newPoly(N);
  for (let i = 0; i < a.length; i++)
    c[i] = mod2(a[i] * b[i]);
  return c;
};
function RejNTTPoly(xof) {
  const r = newPoly(N);
  for (let j = 0; j < N; ) {
    const b = xof();
    if (b.length % 3)
      throw new Error("RejNTTPoly: unaligned block");
    for (let i = 0; j < N && i <= b.length - 3; i += 3) {
      const t = (b[i + 0] | b[i + 1] << 8 | b[i + 2] << 16) & 8388607;
      if (t < Q)
        r[j++] = t;
    }
  }
  return r;
}
function getDilithium(opts) {
  const { K, L, GAMMA1, GAMMA2, TAU, ETA, OMEGA } = opts;
  const { CRH_BYTES, TR_BYTES, C_TILDE_BYTES, XOF128: XOF1282, XOF256: XOF2562 } = opts;
  if (![2, 4].includes(ETA))
    throw new Error("Wrong ETA");
  if (![1 << 17, 1 << 19].includes(GAMMA1))
    throw new Error("Wrong GAMMA1");
  if (![GAMMA2_1, GAMMA2_2].includes(GAMMA2))
    throw new Error("Wrong GAMMA2");
  const BETA = TAU * ETA;
  const decompose = (r) => {
    const rPlus = mod2(r);
    const r0 = smod(rPlus, 2 * GAMMA2) | 0;
    if (rPlus - r0 === Q - 1)
      return { r1: 0 | 0, r0: r0 - 1 | 0 };
    const r1 = Math.floor((rPlus - r0) / (2 * GAMMA2)) | 0;
    return { r1, r0 };
  };
  const HighBits = (r) => decompose(r).r1;
  const LowBits = (r) => decompose(r).r0;
  const MakeHint = (z, r) => {
    const res0 = z <= GAMMA2 || z > Q - GAMMA2 || z === Q - GAMMA2 && r === 0 ? 0 : 1;
    return res0;
  };
  const UseHint = (h, r) => {
    const m = Math.floor((Q - 1) / (2 * GAMMA2));
    const { r1, r0 } = decompose(r);
    if (h === 1)
      return r0 > 0 ? mod2(r1 + 1, m) | 0 : mod2(r1 - 1, m) | 0;
    return r1 | 0;
  };
  const Power2Round = (r) => {
    const rPlus = mod2(r);
    const r0 = smod(rPlus, 2 ** D) | 0;
    return { r1: Math.floor((rPlus - r0) / 2 ** D) | 0, r0 };
  };
  const hintCoder = {
    bytesLen: OMEGA + K,
    encode: (h) => {
      if (h === false)
        throw new Error("hint.encode: hint is false");
      const res = new Uint8Array(OMEGA + K);
      for (let i = 0, k = 0; i < K; i++) {
        for (let j = 0; j < N; j++)
          if (h[i][j] !== 0)
            res[k++] = j;
        res[OMEGA + i] = k;
      }
      return res;
    },
    decode: (buf) => {
      const h = [];
      let k = 0;
      for (let i = 0; i < K; i++) {
        const hi = newPoly(N);
        if (buf[OMEGA + i] < k || buf[OMEGA + i] > OMEGA)
          return false;
        for (let j = k; j < buf[OMEGA + i]; j++) {
          if (j > k && buf[j] <= buf[j - 1])
            return false;
          hi[buf[j]] = 1;
        }
        k = buf[OMEGA + i];
        h.push(hi);
      }
      for (let j = k; j < OMEGA; j++)
        if (buf[j] !== 0)
          return false;
      return h;
    }
  };
  const ETACoder = polyCoder(ETA === 2 ? 3 : 4, (i) => ETA - i, (i) => {
    if (!(-ETA <= i && i <= ETA))
      throw new Error(`malformed key s1/s3 ${i} outside of ETA range [${-ETA}, ${ETA}]`);
    return i;
  });
  const T0Coder = polyCoder(13, (i) => (1 << D - 1) - i);
  const T1Coder = polyCoder(10);
  const ZCoder = polyCoder(GAMMA1 === 1 << 17 ? 18 : 20, (i) => smod(GAMMA1 - i));
  const W1Coder = polyCoder(GAMMA2 === GAMMA2_1 ? 6 : 4);
  const W1Vec = vecCoder(W1Coder, K);
  const publicCoder = splitCoder(32, vecCoder(T1Coder, K));
  const secretCoder = splitCoder(32, 32, TR_BYTES, vecCoder(ETACoder, L), vecCoder(ETACoder, K), vecCoder(T0Coder, K));
  const sigCoder = splitCoder(C_TILDE_BYTES, vecCoder(ZCoder, L), hintCoder);
  const CoefFromHalfByte = ETA === 2 ? (n) => n < 15 ? 2 - n % 5 : false : (n) => n < 9 ? 4 - n : false;
  function RejBoundedPoly(xof) {
    const r = newPoly(N);
    for (let j = 0; j < N; ) {
      const b = xof();
      for (let i = 0; j < N && i < b.length; i += 1) {
        const d1 = CoefFromHalfByte(b[i] & 15);
        const d2 = CoefFromHalfByte(b[i] >> 4 & 15);
        if (d1 !== false)
          r[j++] = d1;
        if (j < N && d2 !== false)
          r[j++] = d2;
      }
    }
    return r;
  }
  const SampleInBall = (seed) => {
    const pre = newPoly(N);
    const s = shake256.create({}).update(seed);
    const buf = new Uint8Array(shake256.blockLen);
    s.xofInto(buf);
    const masks = buf.slice(0, 8);
    for (let i = N - TAU, pos = 8, maskPos = 0, maskBit = 0; i < N; i++) {
      let b = i + 1;
      for (; b > i; ) {
        b = buf[pos++];
        if (pos < shake256.blockLen)
          continue;
        s.xofInto(buf);
        pos = 0;
      }
      pre[i] = pre[b];
      pre[b] = 1 - ((masks[maskPos] >> maskBit++ & 1) << 1);
      if (maskBit >= 8) {
        maskPos++;
        maskBit = 0;
      }
    }
    return pre;
  };
  const polyPowerRound = (p) => {
    const res0 = newPoly(N);
    const res1 = newPoly(N);
    for (let i = 0; i < p.length; i++) {
      const { r0, r1 } = Power2Round(p[i]);
      res0[i] = r0;
      res1[i] = r1;
    }
    return { r0: res0, r1: res1 };
  };
  const polyUseHint = (u, h) => {
    for (let i = 0; i < N; i++)
      u[i] = UseHint(h[i], u[i]);
    return u;
  };
  const polyMakeHint = (a, b) => {
    const v = newPoly(N);
    let cnt = 0;
    for (let i = 0; i < N; i++) {
      const h = MakeHint(a[i], b[i]);
      v[i] = h;
      cnt += h;
    }
    return { v, cnt };
  };
  const signRandBytes = 32;
  const seedCoder = splitCoder(32, 64, 32);
  const internal = {
    signRandBytes,
    keygen: (seed) => {
      const seedDst = new Uint8Array(32 + 2);
      const randSeed = seed === void 0;
      if (randSeed)
        seed = randomBytes2(32);
      ensureBytes2(seed, 32);
      seedDst.set(seed);
      if (randSeed)
        seed.fill(0);
      seedDst[32] = K;
      seedDst[33] = L;
      const [rho, rhoPrime, K_] = seedCoder.decode(shake256(seedDst, { dkLen: seedCoder.bytesLen }));
      const xofPrime = XOF2562(rhoPrime);
      const s1 = [];
      for (let i = 0; i < L; i++)
        s1.push(RejBoundedPoly(xofPrime.get(i & 255, i >> 8 & 255)));
      const s2 = [];
      for (let i = L; i < L + K; i++)
        s2.push(RejBoundedPoly(xofPrime.get(i & 255, i >> 8 & 255)));
      const s1Hat = s1.map((i) => NTT.encode(i.slice()));
      const t0 = [];
      const t1 = [];
      const xof = XOF1282(rho);
      const t = newPoly(N);
      for (let i = 0; i < K; i++) {
        t.fill(0);
        for (let j = 0; j < L; j++) {
          const aij = RejNTTPoly(xof.get(j, i));
          polyAdd(t, MultiplyNTTs(aij, s1Hat[j]));
        }
        NTT.decode(t);
        const { r0, r1 } = polyPowerRound(polyAdd(t, s2[i]));
        t0.push(r0);
        t1.push(r1);
      }
      const publicKey = publicCoder.encode([rho, t1]);
      const tr = shake256(publicKey, { dkLen: TR_BYTES });
      const secretKey = secretCoder.encode([rho, K_, tr, s1, s2, t0]);
      xof.clean();
      xofPrime.clean();
      cleanBytes(rho, rhoPrime, K_, s1, s2, s1Hat, t, t0, t1, tr, seedDst);
      return { publicKey, secretKey };
    },
    // NOTE: random is optional.
    sign: (secretKey, msg, random, externalMu = false) => {
      const [rho, _K, tr, s1, s2, t0] = secretCoder.decode(secretKey);
      const A = [];
      const xof = XOF1282(rho);
      for (let i = 0; i < K; i++) {
        const pv = [];
        for (let j = 0; j < L; j++)
          pv.push(RejNTTPoly(xof.get(j, i)));
        A.push(pv);
      }
      xof.clean();
      for (let i = 0; i < L; i++)
        NTT.encode(s1[i]);
      for (let i = 0; i < K; i++) {
        NTT.encode(s2[i]);
        NTT.encode(t0[i]);
      }
      const mu = externalMu ? msg : shake256.create({ dkLen: CRH_BYTES }).update(tr).update(msg).digest();
      const rnd = random ? random : new Uint8Array(32);
      ensureBytes2(rnd);
      const rhoprime = shake256.create({ dkLen: CRH_BYTES }).update(_K).update(rnd).update(mu).digest();
      ensureBytes2(rhoprime, CRH_BYTES);
      const x256 = XOF2562(rhoprime, ZCoder.bytesLen);
      main_loop: for (let kappa = 0; ; ) {
        const y = [];
        for (let i = 0; i < L; i++, kappa++)
          y.push(ZCoder.decode(x256.get(kappa & 255, kappa >> 8)()));
        const z = y.map((i) => NTT.encode(i.slice()));
        const w = [];
        for (let i = 0; i < K; i++) {
          const wi = newPoly(N);
          for (let j = 0; j < L; j++)
            polyAdd(wi, MultiplyNTTs(A[i][j], z[j]));
          NTT.decode(wi);
          w.push(wi);
        }
        const w1 = w.map((j) => j.map(HighBits));
        const cTilde = shake256.create({ dkLen: C_TILDE_BYTES }).update(mu).update(W1Vec.encode(w1)).digest();
        const cHat = NTT.encode(SampleInBall(cTilde));
        const cs1 = s1.map((i) => MultiplyNTTs(i, cHat));
        for (let i = 0; i < L; i++) {
          polyAdd(NTT.decode(cs1[i]), y[i]);
          if (polyChknorm(cs1[i], GAMMA1 - BETA))
            continue main_loop;
        }
        let cnt = 0;
        const h = [];
        for (let i = 0; i < K; i++) {
          const cs2 = NTT.decode(MultiplyNTTs(s2[i], cHat));
          const r0 = polySub(w[i], cs2).map(LowBits);
          if (polyChknorm(r0, GAMMA2 - BETA))
            continue main_loop;
          const ct0 = NTT.decode(MultiplyNTTs(t0[i], cHat));
          if (polyChknorm(ct0, GAMMA2))
            continue main_loop;
          polyAdd(r0, ct0);
          const hint = polyMakeHint(r0, w1[i]);
          h.push(hint.v);
          cnt += hint.cnt;
        }
        if (cnt > OMEGA)
          continue;
        x256.clean();
        const res = sigCoder.encode([cTilde, cs1, h]);
        cleanBytes(cTilde, cs1, h, cHat, w1, w, z, y, rhoprime, mu, s1, s2, t0, ...A);
        return res;
      }
      throw new Error("Unreachable code path reached, report this error");
    },
    verify: (publicKey, msg, sig, externalMu = false) => {
      const [rho, t1] = publicCoder.decode(publicKey);
      const tr = shake256(publicKey, { dkLen: TR_BYTES });
      if (sig.length !== sigCoder.bytesLen)
        return false;
      const [cTilde, z, h] = sigCoder.decode(sig);
      if (h === false)
        return false;
      for (let i = 0; i < L; i++)
        if (polyChknorm(z[i], GAMMA1 - BETA))
          return false;
      const mu = externalMu ? msg : shake256.create({ dkLen: CRH_BYTES }).update(tr).update(msg).digest();
      const c = NTT.encode(SampleInBall(cTilde));
      const zNtt = z.map((i) => i.slice());
      for (let i = 0; i < L; i++)
        NTT.encode(zNtt[i]);
      const wTick1 = [];
      const xof = XOF1282(rho);
      for (let i = 0; i < K; i++) {
        const ct12d = MultiplyNTTs(NTT.encode(polyShiftl(t1[i])), c);
        const Az = newPoly(N);
        for (let j = 0; j < L; j++) {
          const aij = RejNTTPoly(xof.get(j, i));
          polyAdd(Az, MultiplyNTTs(aij, zNtt[j]));
        }
        const wApprox = NTT.decode(polySub(Az, ct12d));
        wTick1.push(polyUseHint(wApprox, h[i]));
      }
      xof.clean();
      const c2 = shake256.create({ dkLen: C_TILDE_BYTES }).update(mu).update(W1Vec.encode(wTick1)).digest();
      for (const t of h) {
        const sum = t.reduce((acc, i) => acc + i, 0);
        if (!(sum <= OMEGA))
          return false;
      }
      for (const t of z)
        if (polyChknorm(t, GAMMA1 - BETA))
          return false;
      return equalBytes(cTilde, c2);
    }
  };
  return {
    internal,
    keygen: internal.keygen,
    signRandBytes: internal.signRandBytes,
    sign: (secretKey, msg, ctx = EMPTY, random) => {
      const M = getMessage(msg, ctx);
      const res = internal.sign(secretKey, M, random);
      M.fill(0);
      return res;
    },
    verify: (publicKey, msg, sig, ctx = EMPTY) => {
      return internal.verify(publicKey, getMessage(msg, ctx), sig);
    },
    prehash: (hashName) => ({
      sign: (secretKey, msg, ctx = EMPTY, random) => {
        const M = getMessagePrehash(hashName, msg, ctx);
        const res = internal.sign(secretKey, M, random);
        M.fill(0);
        return res;
      },
      verify: (publicKey, msg, sig, ctx = EMPTY) => {
        return internal.verify(publicKey, getMessagePrehash(hashName, msg, ctx), sig);
      }
    })
  };
}
var ml_dsa44 = /* @__PURE__ */ getDilithium({
  ...PARAMS[2],
  CRH_BYTES: 64,
  TR_BYTES: 64,
  C_TILDE_BYTES: 32,
  XOF128,
  XOF256
});
var ml_dsa65 = /* @__PURE__ */ getDilithium({
  ...PARAMS[3],
  CRH_BYTES: 64,
  TR_BYTES: 64,
  C_TILDE_BYTES: 48,
  XOF128,
  XOF256
});
var ml_dsa87 = /* @__PURE__ */ getDilithium({
  ...PARAMS[5],
  CRH_BYTES: 64,
  TR_BYTES: 64,
  C_TILDE_BYTES: 64,
  XOF128,
  XOF256
});

// node_modules/.pnpm/@noble+hashes@1.8.0/node_modules/@noble/hashes/esm/hmac.js
var HMAC = class extends Hash {
  constructor(hash, _key) {
    super();
    this.finished = false;
    this.destroyed = false;
    ahash(hash);
    const key = toBytes(_key);
    this.iHash = hash.create();
    if (typeof this.iHash.update !== "function")
      throw new Error("Expected instance of class which extends utils.Hash");
    this.blockLen = this.iHash.blockLen;
    this.outputLen = this.iHash.outputLen;
    const blockLen = this.blockLen;
    const pad = new Uint8Array(blockLen);
    pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
    for (let i = 0; i < pad.length; i++)
      pad[i] ^= 54;
    this.iHash.update(pad);
    this.oHash = hash.create();
    for (let i = 0; i < pad.length; i++)
      pad[i] ^= 54 ^ 92;
    this.oHash.update(pad);
    clean(pad);
  }
  update(buf) {
    aexists(this);
    this.iHash.update(buf);
    return this;
  }
  digestInto(out) {
    aexists(this);
    abytes(out, this.outputLen);
    this.finished = true;
    this.iHash.digestInto(out);
    this.oHash.update(out);
    this.oHash.digestInto(out);
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to) {
    to || (to = Object.create(Object.getPrototypeOf(this), {}));
    const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
    to = to;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.oHash = oHash._cloneInto(to.oHash);
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
  destroy() {
    this.destroyed = true;
    this.oHash.destroy();
    this.iHash.destroy();
  }
};
var hmac = (hash, key, message) => new HMAC(hash, key).update(message).digest();
hmac.create = (hash, key) => new HMAC(hash, key);

// node_modules/.pnpm/@noble+post-quantum@0.4.1/node_modules/@noble/post-quantum/esm/slh-dsa.js
var PARAMS2 = {
  "128f": { W: 16, N: 16, H: 66, D: 22, K: 33, A: 6 },
  "128s": { W: 16, N: 16, H: 63, D: 7, K: 14, A: 12 },
  "192f": { W: 16, N: 24, H: 66, D: 22, K: 33, A: 8 },
  "192s": { W: 16, N: 24, H: 63, D: 7, K: 17, A: 14 },
  "256f": { W: 16, N: 32, H: 68, D: 17, K: 35, A: 9 },
  "256s": { W: 16, N: 32, H: 64, D: 8, K: 22, A: 14 }
};
var AddressType = {
  WOTS: 0,
  WOTSPK: 1,
  HASHTREE: 2,
  FORSTREE: 3,
  FORSPK: 4,
  WOTSPRF: 5,
  FORSPRF: 6
};
function hexToNumber2(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  return BigInt(hex === "" ? "0" : "0x" + hex);
}
function bytesToNumberBE2(bytes) {
  return hexToNumber2(bytesToHex(bytes));
}
function numberToBytesBE2(n, len) {
  return hexToBytes(n.toString(16).padStart(len * 2, "0"));
}
var base2b = (outLen, b) => {
  const mask = getMask(b);
  return (bytes) => {
    const baseB = new Uint32Array(outLen);
    for (let out = 0, pos = 0, bits = 0, total = 0; out < outLen; out++) {
      while (bits < b) {
        total = total << 8 | bytes[pos++];
        bits += 8;
      }
      bits -= b;
      baseB[out] = total >>> bits & mask;
    }
    return baseB;
  };
};
function getMaskBig(bits) {
  return (1n << BigInt(bits)) - 1n;
}
function gen2(opts, hashOpts) {
  const { N: N2, W, H, D: D2, K, A } = opts;
  const getContext = hashOpts.getContext(opts);
  if (W !== 16)
    throw new Error("Unsupported Winternitz parameter");
  const WOTS_LOGW = 4;
  const WOTS_LEN1 = Math.floor(8 * N2 / WOTS_LOGW);
  const WOTS_LEN2 = N2 <= 8 ? 2 : N2 <= 136 ? 3 : 4;
  const TREE_HEIGHT = Math.floor(H / D2);
  const WOTS_LEN = WOTS_LEN1 + WOTS_LEN2;
  let ADDR_BYTES = 22;
  let OFFSET_LAYER = 0;
  let OFFSET_TREE = 1;
  let OFFSET_TYPE = 9;
  let OFFSET_KP_ADDR2 = 12;
  let OFFSET_KP_ADDR1 = 13;
  let OFFSET_CHAIN_ADDR = 17;
  let OFFSET_TREE_INDEX = 18;
  let OFFSET_HASH_ADDR = 21;
  if (!hashOpts.isCompressed) {
    ADDR_BYTES = 32;
    OFFSET_LAYER += 3;
    OFFSET_TREE += 7;
    OFFSET_TYPE += 10;
    OFFSET_KP_ADDR2 += 10;
    OFFSET_KP_ADDR1 += 10;
    OFFSET_CHAIN_ADDR += 10;
    OFFSET_TREE_INDEX += 10;
    OFFSET_HASH_ADDR += 10;
  }
  const setAddr = (opts2, addr = new Uint8Array(ADDR_BYTES)) => {
    const { type, height, tree, layer, index, chain: chain2, hash, keypair } = opts2;
    const { subtreeAddr, keypairAddr } = opts2;
    const v = createView(addr);
    if (height !== void 0)
      addr[OFFSET_CHAIN_ADDR] = height;
    if (layer !== void 0)
      addr[OFFSET_LAYER] = layer;
    if (type !== void 0)
      addr[OFFSET_TYPE] = type;
    if (chain2 !== void 0)
      addr[OFFSET_CHAIN_ADDR] = chain2;
    if (hash !== void 0)
      addr[OFFSET_HASH_ADDR] = hash;
    if (index !== void 0)
      v.setUint32(OFFSET_TREE_INDEX, index, false);
    if (subtreeAddr)
      addr.set(subtreeAddr.subarray(0, OFFSET_TREE + 8));
    if (tree !== void 0)
      setBigUint64(v, OFFSET_TREE, tree, false);
    if (keypair !== void 0) {
      addr[OFFSET_KP_ADDR1] = keypair;
      if (TREE_HEIGHT > 8)
        addr[OFFSET_KP_ADDR2] = keypair >>> 8;
    }
    if (keypairAddr) {
      addr.set(keypairAddr.subarray(0, OFFSET_TREE + 8));
      addr[OFFSET_KP_ADDR1] = keypairAddr[OFFSET_KP_ADDR1];
      if (TREE_HEIGHT > 8)
        addr[OFFSET_KP_ADDR2] = keypairAddr[OFFSET_KP_ADDR2];
    }
    return addr;
  };
  const chainCoder = base2b(WOTS_LEN2, WOTS_LOGW);
  const chainLengths = (msg) => {
    const W1 = base2b(WOTS_LEN1, WOTS_LOGW)(msg);
    let csum = 0;
    for (let i = 0; i < W1.length; i++)
      csum += W - 1 - W1[i];
    csum <<= (8 - WOTS_LEN2 * WOTS_LOGW % 8) % 8;
    const W2 = chainCoder(numberToBytesBE2(csum, Math.ceil(WOTS_LEN2 * WOTS_LOGW / 8)));
    const lengths = new Uint32Array(WOTS_LEN);
    lengths.set(W1);
    lengths.set(W2, W1.length);
    return lengths;
  };
  const messageToIndices = base2b(K, A);
  const TREE_BITS = TREE_HEIGHT * (D2 - 1);
  const LEAF_BITS = TREE_HEIGHT;
  const hashMsgCoder = splitCoder(Math.ceil(A * K / 8), Math.ceil(TREE_BITS / 8), Math.ceil(TREE_HEIGHT / 8));
  const hashMessage = (R, pkSeed, msg, context) => {
    const digest = context.Hmsg(R, pkSeed, msg, hashMsgCoder.bytesLen);
    const [md, tmpIdxTree, tmpIdxLeaf] = hashMsgCoder.decode(digest);
    const tree = bytesToNumberBE2(tmpIdxTree) & getMaskBig(TREE_BITS);
    const leafIdx = Number(bytesToNumberBE2(tmpIdxLeaf)) & getMask(LEAF_BITS);
    return { tree, leafIdx, md };
  };
  const treehash = (height, fn) => function treehash_i(context, leafIdx, idxOffset, treeAddr, info) {
    const maxIdx = (1 << height) - 1;
    const stack = new Uint8Array(height * N2);
    const authPath = new Uint8Array(height * N2);
    for (let idx = 0; ; idx++) {
      const current = new Uint8Array(2 * N2);
      const cur0 = current.subarray(0, N2);
      const cur1 = current.subarray(N2);
      const addrOffset = idx + idxOffset;
      cur1.set(fn(leafIdx, addrOffset, context, info));
      let h = 0;
      for (let i = idx, o = idxOffset, l = leafIdx; ; h++, i >>>= 1, l >>>= 1, o >>>= 1) {
        if (h === height)
          return { root: cur1, authPath };
        if ((i ^ l) === 1)
          authPath.subarray(h * N2).set(cur1);
        if ((i & 1) === 0 && idx < maxIdx)
          break;
        setAddr({ height: h + 1, index: (i >> 1) + (o >> 1) }, treeAddr);
        cur0.set(stack.subarray(h * N2).subarray(0, N2));
        cur1.set(context.thashN(2, current, treeAddr));
      }
      stack.subarray(h * N2).set(cur1);
    }
    throw new Error("Unreachable code path reached, report this error");
  };
  const wotsTreehash = treehash(TREE_HEIGHT, (leafIdx, addrOffset, context, info) => {
    const wotsPk = new Uint8Array(WOTS_LEN * N2);
    const wotsKmask = addrOffset === leafIdx ? 0 : ~0 >>> 0;
    setAddr({ keypair: addrOffset }, info.leafAddr);
    setAddr({ keypair: addrOffset }, info.pkAddr);
    for (let i = 0; i < WOTS_LEN; i++) {
      const wotsK = info.wotsSteps[i] | wotsKmask;
      const pk = wotsPk.subarray(i * N2, (i + 1) * N2);
      setAddr({ chain: i, hash: 0, type: AddressType.WOTSPRF }, info.leafAddr);
      pk.set(context.PRFaddr(info.leafAddr));
      setAddr({ type: AddressType.WOTS }, info.leafAddr);
      for (let k = 0; ; k++) {
        if (k === wotsK)
          info.wotsSig.subarray(i * N2).set(pk);
        if (k === W - 1)
          break;
        setAddr({ hash: k }, info.leafAddr);
        pk.set(context.thash1(pk, info.leafAddr));
      }
    }
    return context.thashN(WOTS_LEN, wotsPk, info.pkAddr);
  });
  const forsTreehash = treehash(A, (_, addrOffset, context, forsLeafAddr) => {
    setAddr({ type: AddressType.FORSPRF, index: addrOffset }, forsLeafAddr);
    const prf = context.PRFaddr(forsLeafAddr);
    setAddr({ type: AddressType.FORSTREE }, forsLeafAddr);
    return context.thash1(prf, forsLeafAddr);
  });
  const merkleSign = (context, wotsAddr, treeAddr, leafIdx, prevRoot = new Uint8Array(N2)) => {
    setAddr({ type: AddressType.HASHTREE }, treeAddr);
    const info = {
      wotsSig: new Uint8Array(wotsCoder.bytesLen),
      wotsSteps: chainLengths(prevRoot),
      leafAddr: setAddr({ subtreeAddr: wotsAddr }),
      pkAddr: setAddr({ type: AddressType.WOTSPK, subtreeAddr: wotsAddr })
    };
    const { root, authPath } = wotsTreehash(context, leafIdx, 0, treeAddr, info);
    return {
      root,
      sigWots: info.wotsSig.subarray(0, WOTS_LEN * N2),
      sigAuth: authPath
    };
  };
  const computeRoot = (leaf, leafIdx, idxOffset, authPath, treeHeight, context, addr) => {
    const buffer = new Uint8Array(2 * N2);
    const b0 = buffer.subarray(0, N2);
    const b1 = buffer.subarray(N2, 2 * N2);
    if ((leafIdx & 1) !== 0) {
      b1.set(leaf.subarray(0, N2));
      b0.set(authPath.subarray(0, N2));
    } else {
      b0.set(leaf.subarray(0, N2));
      b1.set(authPath.subarray(0, N2));
    }
    leafIdx >>>= 1;
    idxOffset >>>= 1;
    for (let i = 0; i < treeHeight - 1; i++, leafIdx >>= 1, idxOffset >>= 1) {
      setAddr({ height: i + 1, index: leafIdx + idxOffset }, addr);
      const a = authPath.subarray((i + 1) * N2, (i + 2) * N2);
      if ((leafIdx & 1) !== 0) {
        b1.set(context.thashN(2, buffer, addr));
        b0.set(a);
      } else {
        buffer.set(context.thashN(2, buffer, addr));
        b1.set(a);
      }
    }
    setAddr({ height: treeHeight, index: leafIdx + idxOffset }, addr);
    return context.thashN(2, buffer, addr);
  };
  const seedCoder = splitCoder(N2, N2, N2);
  const publicCoder = splitCoder(N2, N2);
  const secretCoder = splitCoder(N2, N2, publicCoder.bytesLen);
  const forsCoder = vecCoder(splitCoder(N2, N2 * A), K);
  const wotsCoder = vecCoder(splitCoder(WOTS_LEN * N2, TREE_HEIGHT * N2), D2);
  const sigCoder = splitCoder(N2, forsCoder, wotsCoder);
  const internal = {
    signRandBytes: N2,
    keygen(seed) {
      seed = seed === void 0 ? randomBytes2(seedCoder.bytesLen) : seed.slice();
      const [secretSeed, secretPRF, publicSeed] = seedCoder.decode(seed);
      const context = getContext(publicSeed, secretSeed);
      const topTreeAddr = setAddr({ layer: D2 - 1 });
      const wotsAddr = setAddr({ layer: D2 - 1 });
      const { root } = merkleSign(context, wotsAddr, topTreeAddr, ~0 >>> 0);
      const publicKey = publicCoder.encode([publicSeed, root]);
      const secretKey = secretCoder.encode([secretSeed, secretPRF, publicKey]);
      context.clean();
      cleanBytes(secretSeed, secretPRF, root, wotsAddr, topTreeAddr);
      return { publicKey, secretKey };
    },
    sign: (sk, msg, random) => {
      const [skSeed, skPRF, pk] = secretCoder.decode(sk);
      const [pkSeed, _] = publicCoder.decode(pk);
      if (!random)
        random = pkSeed.slice();
      ensureBytes2(random, N2);
      const context = getContext(pkSeed, skSeed);
      const R = context.PRFmsg(skPRF, random, msg);
      let { tree, leafIdx, md } = hashMessage(R, pk, msg, context);
      const wotsAddr = setAddr({
        type: AddressType.WOTS,
        tree,
        keypair: leafIdx
      });
      const roots = [];
      const forsLeaf = setAddr({ keypairAddr: wotsAddr });
      const forsTreeAddr = setAddr({ keypairAddr: wotsAddr });
      const indices = messageToIndices(md);
      const fors = [];
      for (let i = 0; i < indices.length; i++) {
        const idxOffset = i << A;
        setAddr({
          type: AddressType.FORSPRF,
          height: 0,
          index: indices[i] + idxOffset
        }, forsTreeAddr);
        const prf = context.PRFaddr(forsTreeAddr);
        setAddr({ type: AddressType.FORSTREE }, forsTreeAddr);
        const { root: root2, authPath } = forsTreehash(context, indices[i], idxOffset, forsTreeAddr, forsLeaf);
        roots.push(root2);
        fors.push([prf, authPath]);
      }
      const forsPkAddr = setAddr({
        type: AddressType.FORSPK,
        keypairAddr: wotsAddr
      });
      const root = context.thashN(K, concatBytes(...roots), forsPkAddr);
      const treeAddr = setAddr({ type: AddressType.HASHTREE });
      const wots = [];
      for (let i = 0; i < D2; i++, tree >>= BigInt(TREE_HEIGHT)) {
        setAddr({ tree, layer: i }, treeAddr);
        setAddr({ subtreeAddr: treeAddr, keypair: leafIdx }, wotsAddr);
        const { sigWots, sigAuth, root: r } = merkleSign(context, wotsAddr, treeAddr, leafIdx, root);
        root.set(r);
        r.fill(0);
        wots.push([sigWots, sigAuth]);
        leafIdx = Number(tree & getMaskBig(TREE_HEIGHT));
      }
      context.clean();
      const SIG2 = sigCoder.encode([R, fors, wots]);
      cleanBytes(R, random, treeAddr, wotsAddr, forsLeaf, forsTreeAddr, indices, roots);
      return SIG2;
    },
    verify: (publicKey, msg, sig) => {
      const [pkSeed, pubRoot] = publicCoder.decode(publicKey);
      const [random, forsVec, wotsVec] = sigCoder.decode(sig);
      const pk = publicKey;
      if (sig.length !== sigCoder.bytesLen)
        return false;
      const context = getContext(pkSeed);
      let { tree, leafIdx, md } = hashMessage(random, pk, msg, context);
      const wotsAddr = setAddr({
        type: AddressType.WOTS,
        tree,
        keypair: leafIdx
      });
      const roots = [];
      const forsTreeAddr = setAddr({
        type: AddressType.FORSTREE,
        keypairAddr: wotsAddr
      });
      const indices = messageToIndices(md);
      for (let i = 0; i < forsVec.length; i++) {
        const [prf, authPath] = forsVec[i];
        const idxOffset = i << A;
        setAddr({ height: 0, index: indices[i] + idxOffset }, forsTreeAddr);
        const leaf = context.thash1(prf, forsTreeAddr);
        roots.push(computeRoot(leaf, indices[i], idxOffset, authPath, A, context, forsTreeAddr));
      }
      const forsPkAddr = setAddr({
        type: AddressType.FORSPK,
        keypairAddr: wotsAddr
      });
      let root = context.thashN(K, concatBytes(...roots), forsPkAddr);
      const treeAddr = setAddr({ type: AddressType.HASHTREE });
      const wotsPkAddr = setAddr({ type: AddressType.WOTSPK });
      const wotsPk = new Uint8Array(WOTS_LEN * N2);
      for (let i = 0; i < wotsVec.length; i++, tree >>= BigInt(TREE_HEIGHT)) {
        const [wots, sigAuth] = wotsVec[i];
        setAddr({ tree, layer: i }, treeAddr);
        setAddr({ subtreeAddr: treeAddr, keypair: leafIdx }, wotsAddr);
        setAddr({ keypairAddr: wotsAddr }, wotsPkAddr);
        const lengths = chainLengths(root);
        for (let i2 = 0; i2 < WOTS_LEN; i2++) {
          setAddr({ chain: i2 }, wotsAddr);
          const steps = W - 1 - lengths[i2];
          const start = lengths[i2];
          const out = wotsPk.subarray(i2 * N2);
          out.set(wots.subarray(i2 * N2, (i2 + 1) * N2));
          for (let j = start; j < start + steps && j < W; j++) {
            setAddr({ hash: j }, wotsAddr);
            out.set(context.thash1(out, wotsAddr));
          }
        }
        const leaf = context.thashN(WOTS_LEN, wotsPk, wotsPkAddr);
        root = computeRoot(leaf, leafIdx, 0, sigAuth, TREE_HEIGHT, context, treeAddr);
        leafIdx = Number(tree & getMaskBig(TREE_HEIGHT));
      }
      return equalBytes(root, pubRoot);
    }
  };
  return {
    internal,
    seedLen: seedCoder.bytesLen,
    keygen: internal.keygen,
    signRandBytes: internal.signRandBytes,
    sign: (secretKey, msg, ctx = EMPTY, random) => {
      const M = getMessage(msg, ctx);
      const res = internal.sign(secretKey, M, random);
      M.fill(0);
      return res;
    },
    verify: (publicKey, msg, sig, ctx = EMPTY) => {
      return internal.verify(publicKey, getMessage(msg, ctx), sig);
    },
    prehash: (hashName) => ({
      seedLen: seedCoder.bytesLen,
      keygen: internal.keygen,
      signRandBytes: internal.signRandBytes,
      sign: (secretKey, msg, ctx = EMPTY, random) => {
        const M = getMessagePrehash(hashName, msg, ctx);
        const res = internal.sign(secretKey, M, random);
        M.fill(0);
        return res;
      },
      verify: (publicKey, msg, sig, ctx = EMPTY) => {
        return internal.verify(publicKey, getMessagePrehash(hashName, msg, ctx), sig);
      }
    })
  };
}
var genShake2 = () => (opts) => (pubSeed, skSeed) => {
  const { N: N2 } = opts;
  const stats = { prf: 0, thash: 0, hmsg: 0, gen_message_random: 0 };
  const h0 = shake256.create({}).update(pubSeed);
  const h0tmp = h0.clone();
  const thash = (blocks, input, addr) => {
    stats.thash++;
    return h0._cloneInto(h0tmp).update(addr).update(input.subarray(0, blocks * N2)).xof(N2);
  };
  return {
    PRFaddr: (addr) => {
      if (!skSeed)
        throw new Error("no sk seed");
      stats.prf++;
      const res = h0._cloneInto(h0tmp).update(addr).update(skSeed).xof(N2);
      return res;
    },
    PRFmsg: (skPRF, random, msg) => {
      stats.gen_message_random++;
      return shake256.create({}).update(skPRF).update(random).update(msg).digest().subarray(0, N2);
    },
    Hmsg: (R, pk, m, outLen) => {
      stats.hmsg++;
      return shake256.create({}).update(R.subarray(0, N2)).update(pk).update(m).xof(outLen);
    },
    thash1: thash.bind(null, 1),
    thashN: thash,
    clean: () => {
      h0.destroy();
      h0tmp.destroy();
    }
  };
};
var SHAKE_SIMPLE = { getContext: genShake2() };
var slh_dsa_shake_128f = /* @__PURE__ */ gen2(PARAMS2["128f"], SHAKE_SIMPLE);
var slh_dsa_shake_128s = /* @__PURE__ */ gen2(PARAMS2["128s"], SHAKE_SIMPLE);
var slh_dsa_shake_192f = /* @__PURE__ */ gen2(PARAMS2["192f"], SHAKE_SIMPLE);
var slh_dsa_shake_192s = /* @__PURE__ */ gen2(PARAMS2["192s"], SHAKE_SIMPLE);
var slh_dsa_shake_256f = /* @__PURE__ */ gen2(PARAMS2["256f"], SHAKE_SIMPLE);
var slh_dsa_shake_256s = /* @__PURE__ */ gen2(PARAMS2["256s"], SHAKE_SIMPLE);
var genSha = (h0, h1) => (opts) => (pub_seed, sk_seed) => {
  const { N: N2 } = opts;
  const stats = { prf: 0, thash: 0, hmsg: 0, gen_message_random: 0, mgf1: 0 };
  const counterB = new Uint8Array(4);
  const counterV = createView(counterB);
  const h0ps = h0.create().update(pub_seed).update(new Uint8Array(h0.blockLen - N2));
  const h1ps = h1.create().update(pub_seed).update(new Uint8Array(h1.blockLen - N2));
  const h0tmp = h0ps.clone();
  const h1tmp = h1ps.clone();
  function mgf1(seed, length, hash) {
    stats.mgf1++;
    const out = new Uint8Array(Math.ceil(length / hash.outputLen) * hash.outputLen);
    if (length > 2 ** 32)
      throw new Error("mask too long");
    for (let counter = 0, o = out; o.length; counter++) {
      counterV.setUint32(0, counter, false);
      hash.create().update(seed).update(counterB).digestInto(o);
      o = o.subarray(hash.outputLen);
    }
    out.subarray(length).fill(0);
    return out.subarray(0, length);
  }
  const thash = (_, h, hTmp) => (blocks, input, addr) => {
    stats.thash++;
    const d = h._cloneInto(hTmp).update(addr).update(input.subarray(0, blocks * N2)).digest();
    return d.subarray(0, N2);
  };
  return {
    PRFaddr: (addr) => {
      if (!sk_seed)
        throw new Error("No sk seed");
      stats.prf++;
      const res = h0ps._cloneInto(h0tmp).update(addr).update(sk_seed).digest().subarray(0, N2);
      return res;
    },
    PRFmsg: (skPRF, random, msg) => {
      stats.gen_message_random++;
      return new HMAC(h1, skPRF).update(random).update(msg).digest().subarray(0, N2);
    },
    Hmsg: (R, pk, m, outLen) => {
      stats.hmsg++;
      const seed = concatBytes(R.subarray(0, N2), pk.subarray(0, N2), h1.create().update(R.subarray(0, N2)).update(pk).update(m).digest());
      return mgf1(seed, outLen, h1);
    },
    thash1: thash(h0, h0ps, h0tmp).bind(null, 1),
    thashN: thash(h1, h1ps, h1tmp),
    clean: () => {
      h0ps.destroy();
      h1ps.destroy();
      h0tmp.destroy();
      h1tmp.destroy();
    }
  };
};
var SHA256_SIMPLE = {
  isCompressed: true,
  getContext: genSha(sha256, sha256)
};
var SHA512_SIMPLE = {
  isCompressed: true,
  getContext: genSha(sha256, sha512)
};
var slh_dsa_sha2_128f = /* @__PURE__ */ gen2(PARAMS2["128f"], SHA256_SIMPLE);
var slh_dsa_sha2_128s = /* @__PURE__ */ gen2(PARAMS2["128s"], SHA256_SIMPLE);
var slh_dsa_sha2_192f = /* @__PURE__ */ gen2(PARAMS2["192f"], SHA512_SIMPLE);
var slh_dsa_sha2_192s = /* @__PURE__ */ gen2(PARAMS2["192s"], SHA512_SIMPLE);
var slh_dsa_sha2_256f = /* @__PURE__ */ gen2(PARAMS2["256f"], SHA512_SIMPLE);
var slh_dsa_sha2_256s = /* @__PURE__ */ gen2(PARAMS2["256s"], SHA512_SIMPLE);

// packages/pca/src/pq.ts
var ML_DSA_65_PUBLIC_KEY_BYTES = 1952;
var ML_DSA_65_SIGNATURE_BYTES = 3309;
var SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES = 32;
var SLH_DSA_SHA2_128F_SIGNATURE_BYTES = 17088;
var ED25519_SIGNATURE_BYTES = 64;
var ML_DSA_87_PUBLIC_KEY_BYTES = 2592;
var ML_DSA_87_SIGNATURE_BYTES = 4627;
var SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES = 64;
var SLH_DSA_SHA2_256S_SIGNATURE_BYTES = 29792;
var FN_DSA_512_PUBLIC_KEY_BYTES = 897;
var FN_DSA_512_SIGNATURE_BYTES = 666;
var FN_DSA_1024_PUBLIC_KEY_BYTES = 1793;
var FN_DSA_1024_SIGNATURE_BYTES = 1280;
var DEFAULT_SIG_ALG = "ed25519";
var SIG_SUITES = Object.freeze({
  ed25519: { alg: "ed25519", sigBytes: ED25519_SIGNATURE_BYTES, hasEd25519: true, hasMlDsa: false, hasSlhDsa: false, hasMlDsa87: false, hasSlhDsa256s: false, needsPqPk: false, needsPqSig: false, pqPkBytes: 0, pqSigBytes: 0 },
  "ml-dsa-65": { alg: "ml-dsa-65", sigBytes: ML_DSA_65_SIGNATURE_BYTES, hasEd25519: false, hasMlDsa: true, hasSlhDsa: false, hasMlDsa87: false, hasSlhDsa256s: false, needsPqPk: true, needsPqSig: false, pqPkBytes: ML_DSA_65_PUBLIC_KEY_BYTES, pqSigBytes: 0 },
  "hybrid-ed25519-ml-dsa-65": { alg: "hybrid-ed25519-ml-dsa-65", sigBytes: ED25519_SIGNATURE_BYTES, hasEd25519: true, hasMlDsa: true, hasSlhDsa: false, hasMlDsa87: false, hasSlhDsa256s: false, needsPqPk: true, needsPqSig: true, pqPkBytes: ML_DSA_65_PUBLIC_KEY_BYTES, pqSigBytes: ML_DSA_65_SIGNATURE_BYTES },
  // SUF-CMA nested variant: wire shape is byte-identical to the plain hybrid above (same sig/pq_pk/pq_sig
  // lengths), but the ML-DSA component signs `message ‖ sig_ed25519` (nested), not `message`. See the
  // `hybrid-nested-ed25519-ml-dsa-65` case in signWithSuite/verifyWithSuite and the SUF-CMA note below.
  "hybrid-nested-ed25519-ml-dsa-65": { alg: "hybrid-nested-ed25519-ml-dsa-65", sigBytes: ED25519_SIGNATURE_BYTES, hasEd25519: true, hasMlDsa: true, hasSlhDsa: false, hasMlDsa87: false, hasSlhDsa256s: false, needsPqPk: true, needsPqSig: true, pqPkBytes: ML_DSA_65_PUBLIC_KEY_BYTES, pqSigBytes: ML_DSA_65_SIGNATURE_BYTES },
  "slh-dsa-sha2-128f": { alg: "slh-dsa-sha2-128f", sigBytes: SLH_DSA_SHA2_128F_SIGNATURE_BYTES, hasEd25519: false, hasMlDsa: false, hasSlhDsa: true, hasMlDsa87: false, hasSlhDsa256s: false, needsPqPk: true, needsPqSig: false, pqPkBytes: SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES, pqSigBytes: 0 },
  "hybrid-ed25519-slh-dsa-sha2-128f": { alg: "hybrid-ed25519-slh-dsa-sha2-128f", sigBytes: ED25519_SIGNATURE_BYTES, hasEd25519: true, hasMlDsa: false, hasSlhDsa: true, hasMlDsa87: false, hasSlhDsa256s: false, needsPqPk: true, needsPqSig: true, pqPkBytes: SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES, pqSigBytes: SLH_DSA_SHA2_128F_SIGNATURE_BYTES },
  // ---- Level-5 / long-lived (CNSA 2.0) — opt-in, additive. ----
  "ml-dsa-87": { alg: "ml-dsa-87", sigBytes: ML_DSA_87_SIGNATURE_BYTES, hasEd25519: false, hasMlDsa: false, hasSlhDsa: false, hasMlDsa87: true, hasSlhDsa256s: false, needsPqPk: true, needsPqSig: false, pqPkBytes: ML_DSA_87_PUBLIC_KEY_BYTES, pqSigBytes: 0 },
  "hybrid-ed25519-ml-dsa-87": { alg: "hybrid-ed25519-ml-dsa-87", sigBytes: ED25519_SIGNATURE_BYTES, hasEd25519: true, hasMlDsa: false, hasSlhDsa: false, hasMlDsa87: true, hasSlhDsa256s: false, needsPqPk: true, needsPqSig: true, pqPkBytes: ML_DSA_87_PUBLIC_KEY_BYTES, pqSigBytes: ML_DSA_87_SIGNATURE_BYTES },
  "slh-dsa-sha2-256s": { alg: "slh-dsa-sha2-256s", sigBytes: SLH_DSA_SHA2_256S_SIGNATURE_BYTES, hasEd25519: false, hasMlDsa: false, hasSlhDsa: false, hasMlDsa87: false, hasSlhDsa256s: true, needsPqPk: true, needsPqSig: false, pqPkBytes: SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES, pqSigBytes: 0 },
  "hybrid-ed25519-slh-dsa-sha2-256s": { alg: "hybrid-ed25519-slh-dsa-sha2-256s", sigBytes: ED25519_SIGNATURE_BYTES, hasEd25519: true, hasMlDsa: false, hasSlhDsa: false, hasMlDsa87: false, hasSlhDsa256s: true, needsPqPk: true, needsPqSig: true, pqPkBytes: SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES, pqSigBytes: SLH_DSA_SHA2_256S_SIGNATURE_BYTES },
  // ---- FN-DSA (Falcon, FIPS 206) — pure-PQ lattice, opt-in, additive. Verify routes through pca-fndsa-wasm. ----
  // `sig` carries the FN-DSA signature; `pq_pk` carries the FN-DSA verifying key; no `pq_sig` (non-hybrid).
  "fn-dsa-512": { alg: "fn-dsa-512", sigBytes: FN_DSA_512_SIGNATURE_BYTES, hasEd25519: false, hasMlDsa: false, hasSlhDsa: false, hasMlDsa87: false, hasSlhDsa256s: false, hasFnDsa512: true, needsPqPk: true, needsPqSig: false, pqPkBytes: FN_DSA_512_PUBLIC_KEY_BYTES, pqSigBytes: 0 },
  "fn-dsa-1024": { alg: "fn-dsa-1024", sigBytes: FN_DSA_1024_SIGNATURE_BYTES, hasEd25519: false, hasMlDsa: false, hasSlhDsa: false, hasMlDsa87: false, hasSlhDsa256s: false, hasFnDsa1024: true, needsPqPk: true, needsPqSig: false, pqPkBytes: FN_DSA_1024_PUBLIC_KEY_BYTES, pqSigBytes: 0 }
});
function isKnownSigAlg(x) {
  return typeof x === "string" && Object.prototype.hasOwnProperty.call(SIG_SUITES, x);
}
function resolveSigAlg(alg) {
  if (alg === void 0) return SIG_SUITES[DEFAULT_SIG_ALG];
  if (isKnownSigAlg(alg)) return SIG_SUITES[alg];
  return null;
}
function mlDsa65Sign(secretKey, msg) {
  return ml_dsa65.sign(secretKey, msg);
}
function mlDsa65Verify(publicKey, msg, sig) {
  try {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== ML_DSA_65_PUBLIC_KEY_BYTES) return false;
    if (!(sig instanceof Uint8Array) || sig.length !== ML_DSA_65_SIGNATURE_BYTES) return false;
    return ml_dsa65.verify(publicKey, msg, sig);
  } catch {
    return false;
  }
}
function mlDsa65VerifyB64u(publicKeyB64u, msg, sigB64u) {
  try {
    const pk = decodeB64uStrict(publicKeyB64u, ML_DSA_65_PUBLIC_KEY_BYTES);
    const sg = decodeB64uStrict(sigB64u, ML_DSA_65_SIGNATURE_BYTES);
    if (!pk || !sg) return false;
    return mlDsa65Verify(pk, msg, sg);
  } catch {
    return false;
  }
}
function encodeMlDsaPublicKey(publicKey) {
  return b64u(publicKey);
}
function slhDsa128fSign(secretKey, msg) {
  return slh_dsa_sha2_128f.sign(secretKey, msg);
}
function slhDsa128fVerify(publicKey, msg, sig) {
  try {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES) return false;
    if (!(sig instanceof Uint8Array) || sig.length !== SLH_DSA_SHA2_128F_SIGNATURE_BYTES) return false;
    return slh_dsa_sha2_128f.verify(publicKey, msg, sig);
  } catch {
    return false;
  }
}
function slhDsa128fVerifyB64u(publicKeyB64u, msg, sigB64u) {
  try {
    const pk = decodeB64uStrict(publicKeyB64u, SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES);
    const sg = decodeB64uStrict(sigB64u, SLH_DSA_SHA2_128F_SIGNATURE_BYTES);
    if (!pk || !sg) return false;
    return slhDsa128fVerify(pk, msg, sg);
  } catch {
    return false;
  }
}
function encodeSlhDsaPublicKey(publicKey) {
  return b64u(publicKey);
}
function mlDsa87Sign(secretKey, msg) {
  return ml_dsa87.sign(secretKey, msg);
}
function mlDsa87Verify(publicKey, msg, sig) {
  try {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== ML_DSA_87_PUBLIC_KEY_BYTES) return false;
    if (!(sig instanceof Uint8Array) || sig.length !== ML_DSA_87_SIGNATURE_BYTES) return false;
    return ml_dsa87.verify(publicKey, msg, sig);
  } catch {
    return false;
  }
}
function mlDsa87VerifyB64u(publicKeyB64u, msg, sigB64u) {
  try {
    const pk = decodeB64uStrict(publicKeyB64u, ML_DSA_87_PUBLIC_KEY_BYTES);
    const sg = decodeB64uStrict(sigB64u, ML_DSA_87_SIGNATURE_BYTES);
    if (!pk || !sg) return false;
    return mlDsa87Verify(pk, msg, sg);
  } catch {
    return false;
  }
}
function encodeMlDsa87PublicKey(publicKey) {
  return b64u(publicKey);
}
function slhDsa256sSign(secretKey, msg) {
  return slh_dsa_sha2_256s.sign(secretKey, msg);
}
function slhDsa256sVerify(publicKey, msg, sig) {
  try {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES) return false;
    if (!(sig instanceof Uint8Array) || sig.length !== SLH_DSA_SHA2_256S_SIGNATURE_BYTES) return false;
    return slh_dsa_sha2_256s.verify(publicKey, msg, sig);
  } catch {
    return false;
  }
}
function slhDsa256sVerifyB64u(publicKeyB64u, msg, sigB64u) {
  try {
    const pk = decodeB64uStrict(publicKeyB64u, SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES);
    const sg = decodeB64uStrict(sigB64u, SLH_DSA_SHA2_256S_SIGNATURE_BYTES);
    if (!pk || !sg) return false;
    return slhDsa256sVerify(pk, msg, sg);
  } catch {
    return false;
  }
}
function encodeSlhDsa256sPublicKey(publicKey) {
  return b64u(publicKey);
}
var fnDsaBackend;
function asFnDsaBinding(mod3) {
  if (typeof mod3 !== "object" || mod3 === null) return null;
  const m = mod3;
  for (const name of ["verify", "sign", "keygen"]) {
    if (typeof m[name] !== "function") return null;
  }
  return mod3;
}
function fnDsaWasm() {
  if (fnDsaBackend !== void 0) return fnDsaBackend;
  fnDsaBackend = null;
  try {
    const req = createRequire(__filename);
    const candidates = [
      "@atlasauth/pca-fndsa-wasm",
      join2(__dirname, "..", "..", "pca-fndsa-wasm", "dist", "index.js")
    ];
    for (const spec of candidates) {
      try {
        const loaded = asFnDsaBinding(req(spec));
        if (loaded !== null) {
          fnDsaBackend = loaded;
          break;
        }
      } catch {
      }
    }
  } catch {
    fnDsaBackend = null;
  }
  return fnDsaBackend;
}
function fnDsa512Sign(signingKey, msg, seed) {
  const w = fnDsaWasm();
  if (w === null) throw new Error("fnDsa512Sign: FN-DSA wasm backend unavailable");
  return w.sign("fn-dsa-512", signingKey, msg, seed);
}
function fnDsa1024Sign(signingKey, msg, seed) {
  const w = fnDsaWasm();
  if (w === null) throw new Error("fnDsa1024Sign: FN-DSA wasm backend unavailable");
  return w.sign("fn-dsa-1024", signingKey, msg, seed);
}
function fnDsaVerify(variant, pkBytes, sigBytes, publicKey, msg, sig) {
  try {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== pkBytes) return false;
    if (!(sig instanceof Uint8Array) || sig.length !== sigBytes) return false;
    const w = fnDsaWasm();
    if (w === null) return false;
    return w.verify(variant, publicKey, msg, sig) === true;
  } catch {
    return false;
  }
}
function fnDsa512Verify(publicKey, msg, sig) {
  return fnDsaVerify("fn-dsa-512", FN_DSA_512_PUBLIC_KEY_BYTES, FN_DSA_512_SIGNATURE_BYTES, publicKey, msg, sig);
}
function fnDsa1024Verify(publicKey, msg, sig) {
  return fnDsaVerify("fn-dsa-1024", FN_DSA_1024_PUBLIC_KEY_BYTES, FN_DSA_1024_SIGNATURE_BYTES, publicKey, msg, sig);
}
function fnDsa512VerifyB64u(publicKeyB64u, msg, sigB64u) {
  try {
    const pk = decodeB64uStrict(publicKeyB64u, FN_DSA_512_PUBLIC_KEY_BYTES);
    const sg = decodeB64uStrict(sigB64u, FN_DSA_512_SIGNATURE_BYTES);
    if (!pk || !sg) return false;
    return fnDsa512Verify(pk, msg, sg);
  } catch {
    return false;
  }
}
function fnDsa1024VerifyB64u(publicKeyB64u, msg, sigB64u) {
  try {
    const pk = decodeB64uStrict(publicKeyB64u, FN_DSA_1024_PUBLIC_KEY_BYTES);
    const sg = decodeB64uStrict(sigB64u, FN_DSA_1024_SIGNATURE_BYTES);
    if (!pk || !sg) return false;
    return fnDsa1024Verify(pk, msg, sg);
  } catch {
    return false;
  }
}
function signWithSuite(alg, keys, msg) {
  const suite = resolveSigAlg(alg);
  if (suite === null) throw new RangeError(`signWithSuite: unknown signature alg '${String(alg)}'`);
  if (suite.hasEd25519 && !(keys.edSecret instanceof Uint8Array)) throw new TypeError(`signWithSuite: '${suite.alg}' requires edSecret`);
  if (suite.hasMlDsa && !(keys.mlDsa && keys.mlDsa.secretKey instanceof Uint8Array)) throw new TypeError(`signWithSuite: '${suite.alg}' requires mlDsa key material`);
  if (suite.hasSlhDsa && !(keys.slhDsa && keys.slhDsa.secretKey instanceof Uint8Array)) throw new TypeError(`signWithSuite: '${suite.alg}' requires slhDsa key material`);
  if (suite.hasMlDsa87 && !(keys.mlDsa87 && keys.mlDsa87.secretKey instanceof Uint8Array)) throw new TypeError(`signWithSuite: '${suite.alg}' requires mlDsa87 key material`);
  if (suite.hasSlhDsa256s && !(keys.slhDsa256s && keys.slhDsa256s.secretKey instanceof Uint8Array)) throw new TypeError(`signWithSuite: '${suite.alg}' requires slhDsa256s key material`);
  if (suite.hasFnDsa512 && !(keys.fnDsa512 && keys.fnDsa512.signingKey instanceof Uint8Array && keys.fnDsa512.signSeed instanceof Uint8Array)) throw new TypeError(`signWithSuite: '${suite.alg}' requires fnDsa512 key material (signingKey + signSeed)`);
  if (suite.hasFnDsa1024 && !(keys.fnDsa1024 && keys.fnDsa1024.signingKey instanceof Uint8Array && keys.fnDsa1024.signSeed instanceof Uint8Array)) throw new TypeError(`signWithSuite: '${suite.alg}' requires fnDsa1024 key material (signingKey + signSeed)`);
  switch (suite.alg) {
    case "ed25519":
      return { sig: b64u(sign(keys.edSecret, msg)) };
    case "ml-dsa-65":
      return { sig: b64u(mlDsa65Sign(keys.mlDsa.secretKey, msg)) };
    case "hybrid-ed25519-ml-dsa-65":
      return { sig: b64u(sign(keys.edSecret, msg)), pq_sig: b64u(mlDsa65Sign(keys.mlDsa.secretKey, msg)) };
    case "hybrid-nested-ed25519-ml-dsa-65": {
      const edSig = sign(keys.edSecret, msg);
      return { sig: b64u(edSig), pq_sig: b64u(mlDsa65Sign(keys.mlDsa.secretKey, concatBytes3(msg, edSig))) };
    }
    case "slh-dsa-sha2-128f":
      return { sig: b64u(slhDsa128fSign(keys.slhDsa.secretKey, msg)) };
    case "hybrid-ed25519-slh-dsa-sha2-128f":
      return { sig: b64u(sign(keys.edSecret, msg)), pq_sig: b64u(slhDsa128fSign(keys.slhDsa.secretKey, msg)) };
    case "ml-dsa-87":
      return { sig: b64u(mlDsa87Sign(keys.mlDsa87.secretKey, msg)) };
    case "hybrid-ed25519-ml-dsa-87":
      return { sig: b64u(sign(keys.edSecret, msg)), pq_sig: b64u(mlDsa87Sign(keys.mlDsa87.secretKey, msg)) };
    case "slh-dsa-sha2-256s":
      return { sig: b64u(slhDsa256sSign(keys.slhDsa256s.secretKey, msg)) };
    case "hybrid-ed25519-slh-dsa-sha2-256s":
      return { sig: b64u(sign(keys.edSecret, msg)), pq_sig: b64u(slhDsa256sSign(keys.slhDsa256s.secretKey, msg)) };
    case "fn-dsa-512":
      return { sig: b64u(fnDsa512Sign(keys.fnDsa512.signingKey, msg, keys.fnDsa512.signSeed)) };
    case "fn-dsa-1024":
      return { sig: b64u(fnDsa1024Sign(keys.fnDsa1024.signingKey, msg, keys.fnDsa1024.signSeed)) };
  }
}
function verifyWithSuite(alg, keys, msg, s) {
  const suite = resolveSigAlg(alg);
  if (suite === null) return false;
  const sig = s?.sig;
  switch (suite.alg) {
    case "ed25519":
      return typeof sig === "string" && typeof keys.edPub === "string" && verifyB64u(keys.edPub, msg, sig);
    case "ml-dsa-65":
      return typeof sig === "string" && mlDsa65VerifyB64u(keys.mlDsaPub, msg, sig);
    case "hybrid-ed25519-ml-dsa-65": {
      const edOk = typeof sig === "string" && typeof keys.edPub === "string" && verifyB64u(keys.edPub, msg, sig);
      const pqOk = typeof s?.pq_sig === "string" && mlDsa65VerifyB64u(keys.mlDsaPub, msg, s.pq_sig);
      return edOk && pqOk;
    }
    case "hybrid-nested-ed25519-ml-dsa-65": {
      const edOk = typeof sig === "string" && typeof keys.edPub === "string" && verifyB64u(keys.edPub, msg, sig);
      const edSigBytes = typeof sig === "string" ? decodeB64uStrict(sig, ED25519_SIGNATURE_BYTES) : null;
      const pqOk = edSigBytes !== null && typeof s?.pq_sig === "string" && mlDsa65VerifyB64u(keys.mlDsaPub, concatBytes3(msg, edSigBytes), s.pq_sig);
      return edOk && pqOk;
    }
    case "slh-dsa-sha2-128f":
      return typeof sig === "string" && slhDsa128fVerifyB64u(keys.slhDsaPub, msg, sig);
    case "hybrid-ed25519-slh-dsa-sha2-128f": {
      const edOk = typeof sig === "string" && typeof keys.edPub === "string" && verifyB64u(keys.edPub, msg, sig);
      const pqOk = typeof s?.pq_sig === "string" && slhDsa128fVerifyB64u(keys.slhDsaPub, msg, s.pq_sig);
      return edOk && pqOk;
    }
    case "ml-dsa-87":
      return typeof sig === "string" && mlDsa87VerifyB64u(keys.mlDsa87Pub, msg, sig);
    case "hybrid-ed25519-ml-dsa-87": {
      const edOk = typeof sig === "string" && typeof keys.edPub === "string" && verifyB64u(keys.edPub, msg, sig);
      const pqOk = typeof s?.pq_sig === "string" && mlDsa87VerifyB64u(keys.mlDsa87Pub, msg, s.pq_sig);
      return edOk && pqOk;
    }
    case "slh-dsa-sha2-256s":
      return typeof sig === "string" && slhDsa256sVerifyB64u(keys.slhDsa256sPub, msg, sig);
    case "hybrid-ed25519-slh-dsa-sha2-256s": {
      const edOk = typeof sig === "string" && typeof keys.edPub === "string" && verifyB64u(keys.edPub, msg, sig);
      const pqOk = typeof s?.pq_sig === "string" && slhDsa256sVerifyB64u(keys.slhDsa256sPub, msg, s.pq_sig);
      return edOk && pqOk;
    }
    case "fn-dsa-512":
      return typeof sig === "string" && fnDsa512VerifyB64u(keys.fnDsa512Pub, msg, sig);
    case "fn-dsa-1024":
      return typeof sig === "string" && fnDsa1024VerifyB64u(keys.fnDsa1024Pub, msg, sig);
  }
}
function bindSuiteFields(base, alg, pqPublicKey) {
  const suite = resolveSigAlg(alg);
  if (suite === null || suite.alg === "ed25519") return base;
  const out = { ...base, alg: suite.alg };
  if (suite.needsPqPk) out.pq_pk = pqPublicKey;
  return out;
}
function verifyLeafSuite(i) {
  const pqPub = typeof i.pqPublicKey === "string" ? i.pqPublicKey : void 0;
  return verifyWithSuite(
    i.alg,
    { edPub: i.holder, mlDsaPub: pqPub, slhDsaPub: pqPub, mlDsa87Pub: pqPub, slhDsa256sPub: pqPub, fnDsa512Pub: pqPub, fnDsa1024Pub: pqPub },
    i.message,
    { sig: i.sig, pq_sig: i.pqSig }
  );
}
function validateSignatureWire(p, decode = decodeB64uStrict) {
  const alg = p.alg;
  if (alg !== void 0 && typeof alg !== "string") return "'alg' must be a string";
  const suite = resolveSigAlg(alg);
  if (suite === null) return `unknown signature alg '${String(alg)}'`;
  if (decode(p.sig, suite.sigBytes) === null) {
    return `'sig' is not canonical base64url (${suite.sigBytes} bytes) for alg '${suite.alg}'`;
  }
  if (suite.needsPqPk) {
    if (decode(p.pq_pk, suite.pqPkBytes) === null) {
      return `'pq_pk' is not canonical base64url (${suite.pqPkBytes} bytes) for alg '${suite.alg}'`;
    }
  } else if (p.pq_pk !== void 0) {
    return `'pq_pk' must be absent for alg '${suite.alg}'`;
  }
  if (suite.needsPqSig) {
    if (decode(p.pq_sig, suite.pqSigBytes) === null) {
      return `'pq_sig' is not canonical base64url (${suite.pqSigBytes} bytes) for alg '${suite.alg}'`;
    }
  } else if (p.pq_sig !== void 0) {
    return `'pq_sig' must be absent for alg '${suite.alg}'`;
  }
  return null;
}
function concatBytes3(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}
var COMPOSITE_SIGNATURE_BYTES = ML_DSA_65_SIGNATURE_BYTES + ED25519_SIGNATURE_BYTES;

// packages/pca/src/capability.ts
var CAP_DOMAIN = "atlas-pca/cap/v1\0";
var BUDGET_ALLOC_CAVEAT = "budget_alloc";
function allocationsMonotone(caveats) {
  if (!Array.isArray(caveats)) return { ok: false, reason: "malformed caveats" };
  let prev = Infinity;
  for (let i = 0; i < caveats.length; i++) {
    const cv = caveats[i];
    if (cv === null || typeof cv !== "object" || cv.type !== BUDGET_ALLOC_CAVEAT) continue;
    const lim = cv.limit;
    if (typeof lim !== "number" || !Number.isFinite(lim) || lim < 0) {
      return { ok: false, reason: `budget_alloc caveat ${i}: limit must be a finite number >= 0` };
    }
    if (lim > prev) {
      return {
        ok: false,
        reason: `budget_alloc caveat ${i}: allocation ${lim} widens the parent's carried allocation ${prev} (monotone: a child can only allocate <= its parent)`
      };
    }
    prev = lim;
  }
  return { ok: true };
}
function bodyOf(c) {
  return {
    issuer: c.issuer,
    holder: c.holder,
    caveats: c.caveats,
    parent: c.parent ?? null
  };
}
function sigMessage(bodyDigest) {
  const d = unb64u(bodyDigest);
  const p = utf8(CAP_DOMAIN);
  const m = new Uint8Array(p.length + d.length);
  m.set(p);
  m.set(d, p.length);
  return m;
}
function capHash(c) {
  return hashCanonical(c);
}
function signableBody(body, alg, pqPk) {
  return bindSuiteFields(bodyOf(body), alg, pqPk);
}
function capPqPublicKey(resolved, suite) {
  if (!resolved.needsPqPk) return void 0;
  if (resolved.hasMlDsa) {
    if (!(suite?.mlDsa && suite.mlDsa.secretKey instanceof Uint8Array)) throw new TypeError(`capability: '${resolved.alg}' requires an mlDsa key pair`);
    return encodeMlDsaPublicKey(suite.mlDsa.publicKey);
  }
  if (resolved.hasSlhDsa) {
    if (!(suite?.slhDsa && suite.slhDsa.secretKey instanceof Uint8Array)) throw new TypeError(`capability: '${resolved.alg}' requires an slhDsa key pair`);
    return encodeSlhDsaPublicKey(suite.slhDsa.publicKey);
  }
  if (resolved.hasMlDsa87) {
    if (!(suite?.mlDsa87 && suite.mlDsa87.secretKey instanceof Uint8Array)) throw new TypeError(`capability: '${resolved.alg}' requires an mlDsa87 key pair`);
    return encodeMlDsa87PublicKey(suite.mlDsa87.publicKey);
  }
  if (resolved.hasSlhDsa256s) {
    if (!(suite?.slhDsa256s && suite.slhDsa256s.secretKey instanceof Uint8Array)) throw new TypeError(`capability: '${resolved.alg}' requires an slhDsa256s key pair`);
    return encodeSlhDsa256sPublicKey(suite.slhDsa256s.publicKey);
  }
  return void 0;
}
function seal(body, signerSecret, suite) {
  const resolved = resolveSigAlg(suite?.alg);
  if (resolved === null) throw new RangeError(`capability: unknown signature alg '${String(suite?.alg)}'`);
  const pqPk = capPqPublicKey(resolved, suite);
  const body_digest = hashCanonical(signableBody(body, suite?.alg, pqPk));
  const parts = signWithSuite(
    suite?.alg,
    { edSecret: signerSecret, mlDsa: suite?.mlDsa, slhDsa: suite?.slhDsa, mlDsa87: suite?.mlDsa87, slhDsa256s: suite?.slhDsa256s },
    sigMessage(body_digest)
  );
  const cap = {
    id: body_digest,
    issuer: body.issuer,
    holder: body.holder,
    caveats: body.caveats,
    body_digest,
    sig: parts.sig
  };
  if (body.parent !== void 0) cap.parent = body.parent;
  if (resolved.alg !== "ed25519") {
    cap.alg = resolved.alg;
    if (pqPk !== void 0) cap.pq_pk = pqPk;
    if (parts.pq_sig !== void 0) cap.pq_sig = parts.pq_sig;
  }
  return cap;
}
function cloneCaveats(cs) {
  return JSON.parse(new TextDecoder().decode(canonicalBytes(cs)));
}
function mintRoot(args) {
  return seal(
    { issuer: args.principalPublic, holder: args.holder, caveats: cloneCaveats(args.caveats) },
    args.principalSecret,
    args.suite
  );
}
function checkSig(c, signer, label) {
  if (resolveSigAlg(c.alg) === null) return `${label}: unknown signature alg '${String(c.alg)}'`;
  let digest;
  try {
    digest = hashCanonical(signableBody(c, c.alg, c.pq_pk));
  } catch {
    return `${label}: malformed body`;
  }
  if (digest !== c.body_digest || c.id !== c.body_digest) return `${label}: body digest mismatch`;
  if (!verifyWithSuite(
    c.alg,
    { edPub: signer, mlDsaPub: c.pq_pk, slhDsaPub: c.pq_pk, mlDsa87Pub: c.pq_pk, slhDsa256sPub: c.pq_pk },
    sigMessage(c.body_digest),
    { sig: c.sig, pq_sig: c.pq_sig }
  )) {
    return `${label}: bad signature (not signed by expected key)`;
  }
  return void 0;
}
var MAX_CHAIN_DEPTH = 16;
function wellTyped(c) {
  if (c === null || typeof c !== "object") return false;
  const x = c;
  return typeof x.id === "string" && typeof x.issuer === "string" && typeof x.holder === "string" && typeof x.body_digest === "string" && typeof x.sig === "string" && (x.alg === void 0 || typeof x.alg === "string") && (x.pq_pk === void 0 || typeof x.pq_pk === "string") && (x.pq_sig === void 0 || typeof x.pq_sig === "string") && (x.parent === void 0 || typeof x.parent === "string") && Array.isArray(x.caveats) && x.caveats.every((cv) => cv !== null && typeof cv === "object" && !Array.isArray(cv) && typeof cv.type === "string");
}
function verifyChain(chain2, expectedRootIssuer) {
  if (!Array.isArray(chain2) || chain2.length === 0) return { ok: false, reason: "empty chain" };
  if (chain2.length > MAX_CHAIN_DEPTH) return { ok: false, reason: `chain too long (max ${MAX_CHAIN_DEPTH} hops)` };
  for (let i = 0; i < chain2.length; i++) {
    if (!wellTyped(chain2[i])) return { ok: false, reason: `hop ${i}: malformed capability` };
  }
  const root = chain2[0];
  if (root.parent !== void 0) return { ok: false, reason: "hop 0: root must not have a parent" };
  if (expectedRootIssuer !== void 0 && root.issuer !== expectedRootIssuer) {
    return { ok: false, reason: "hop 0: root issuer is not the expected principal" };
  }
  const rootErr = checkSig(root, root.issuer, "hop 0");
  if (rootErr) return { ok: false, reason: rootErr };
  for (let i = 1; i < chain2.length; i++) {
    const parent = chain2[i - 1];
    const c = chain2[i];
    const label = `hop ${i}`;
    if (c.parent !== capHash(parent)) return { ok: false, reason: `${label}: broken parent link` };
    if (c.issuer !== parent.holder) {
      return { ok: false, reason: `${label}: issuer is not the parent's bound holder` };
    }
    const err = checkSig(c, parent.holder, label);
    if (err) return { ok: false, reason: err };
    if (c.caveats.length < parent.caveats.length) {
      return { ok: false, reason: `${label}: drops parent caveat(s)` };
    }
    for (let j = 0; j < parent.caveats.length; j++) {
      if (hashCanonical(c.caveats[j]) !== hashCanonical(parent.caveats[j])) {
        return { ok: false, reason: `${label}: caveat ${j} altered or reordered` };
      }
    }
  }
  const alloc = allocationsMonotone(chain2[chain2.length - 1].caveats);
  if (!alloc.ok) return alloc;
  return { ok: true };
}

// packages/pca/src/merkle.ts
var LEAF = 0;
var NODE = 1;
function cat(prefix, ...parts) {
  const out = new Uint8Array(1 + parts.reduce((n, p) => n + p.length, 0));
  out[0] = prefix;
  let o = 1;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
function leafHashSuite(leaf, suite) {
  return hashWithSuite(cat(LEAF, canonicalBytes(leaf)), suite);
}
function nodeHash(l, r, suite = DEFAULT_HASH_SUITE) {
  return hashWithSuite(cat(NODE, l, r), suite);
}
function split2(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}
function build(hs, suite) {
  if (hs.length === 1) return hs[0];
  const k = split2(hs.length);
  return nodeHash(build(hs.slice(0, k), suite), build(hs.slice(k), suite), suite);
}
function prove(hs, idx, out, suite) {
  if (hs.length === 1) return;
  const k = split2(hs.length);
  if (idx < k) {
    prove(hs.slice(0, k), idx, out, suite);
    out.push({ side: "R", hash: b64u(build(hs.slice(k), suite)) });
  } else {
    prove(hs.slice(k), idx - k, out, suite);
    out.push({ side: "L", hash: b64u(build(hs.slice(0, k), suite)) });
  }
}
function merkleRoot(leaves, suite = DEFAULT_HASH_SUITE) {
  if (leaves.length === 0) throw new RangeError("merkleRoot: empty leaf set");
  return b64u(build(leaves.map((l) => leafHashSuite(l, suite)), suite));
}
function merkleProof(leaves, index, suite = DEFAULT_HASH_SUITE) {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new RangeError("merkleProof: index out of range");
  }
  const path = [];
  prove(leaves.map((l) => leafHashSuite(l, suite)), index, path, suite);
  const proof = { index, size: leaves.length, path };
  if (suite !== DEFAULT_HASH_SUITE) proof.hash_suite = suite;
  return proof;
}
function pathShape(index, size) {
  const out = [];
  let idx = index;
  let n = size;
  while (n > 1) {
    const k = split2(n);
    if (idx < k) {
      out.push("R");
      n = k;
    } else {
      out.push("L");
      idx -= k;
      n -= k;
    }
  }
  return out.reverse();
}
function verifyInclusion(root, proof, leaf) {
  try {
    if (!proof || !Array.isArray(proof.path)) return false;
    const rawSuite = proof.hash_suite;
    if (rawSuite !== void 0 && !isHashSuite(rawSuite)) return false;
    const suite = rawSuite === void 0 ? DEFAULT_HASH_SUITE : rawSuite;
    const sibLen = HASH_LEN[suite];
    if (!Number.isSafeInteger(proof.index) || !Number.isSafeInteger(proof.size)) return false;
    if (proof.size < 1 || proof.index < 0 || proof.index >= proof.size) return false;
    const shape = pathShape(proof.index, proof.size);
    if (shape.length !== proof.path.length) return false;
    let h = leafHashSuite(leaf, suite);
    for (let i = 0; i < proof.path.length; i++) {
      const step = proof.path[i];
      if (step.side !== shape[i]) return false;
      const sib = decodeB64uStrict(step.hash, sibLen);
      if (!sib) return false;
      h = step.side === "L" ? nodeHash(sib, h, suite) : nodeHash(h, sib, suite);
    }
    return b64u(h) === root;
  } catch {
    return false;
  }
}
function paramsDigest(params) {
  return hashCanonical(params ?? {});
}
var DEFAULT_REVERSIBILITY_CLASS = "reversible";
var EMPTY_PARAMS_DIGEST = paramsDigest();
function conditionsDigest(pre, post) {
  return b64u(sha2563(canonicalBytes({ pre: pre ?? null, post: post ?? null })));
}
function planLeaf(nodeId, action, conditions) {
  return {
    node_id: nodeId,
    verb: action.verb,
    resource: action.resource,
    params_digest: action.params_digest ?? EMPTY_PARAMS_DIGEST,
    reversibility_class: action.reversibility_class ?? DEFAULT_REVERSIBILITY_CLASS,
    conditions
  };
}
function planNodeLeaf(n) {
  return planLeaf(n.id, n, conditionsDigest(n.pre, n.post));
}
function commitPlan(nodes) {
  const ids = /* @__PURE__ */ new Set();
  for (const n of nodes) {
    if (ids.has(n.id)) throw new Error(`commitPlan: duplicate node id ${n.id}`);
    ids.add(n.id);
  }
  const leaves = nodes.map(planNodeLeaf);
  const root = merkleRoot(leaves);
  return {
    root,
    proofFor(nodeId) {
      const i = nodes.findIndex((n) => n.id === nodeId);
      if (i < 0) throw new Error(`commitPlan: unknown node ${nodeId}`);
      return merkleProof(leaves, i);
    }
  };
}

// packages/pca/src/wire.ts
var PCACTN_WIRE_VERSION = 2;
var PCACTN_REQUIRED_FIELDS = [
  "ver",
  "action",
  "grant_ref",
  "cap_chain",
  "plan",
  "attestation",
  "provenance",
  "freshness",
  "counter",
  "risk_claim",
  "aud",
  "iat",
  "exp",
  "sig"
];
var PCACTN_OPTIONAL_FIELDS = [
  "nonce",
  "caution",
  "rationale_commitment",
  "progress_step",
  "prohibition_evidence",
  "tool_binding",
  "threshold",
  "zk_compliance",
  "bond_ref",
  // B4 crypto-agility (additive): absent `alg` == "ed25519" and validates exactly as today.
  "alg",
  "pq_pk",
  "pq_sig"
];
var KNOWN = /* @__PURE__ */ new Set([...PCACTN_REQUIRED_FIELDS, ...PCACTN_OPTIONAL_FIELDS]);
var isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
var isStr = (v) => typeof v === "string";
var isInt = (v) => typeof v === "number" && Number.isSafeInteger(v) && !Object.is(v, -0);
var isNum = (v) => typeof v === "number" && Number.isFinite(v);
var B32 = 32;
var SIG = 64;
var u8len = (s) => new TextEncoder().encode(s).length;
var MAX_AUD_LEN = 256;
var MAX_NONCE_LEN = 128;
var HOP_KEYS = /* @__PURE__ */ new Set(["id", "issuer", "holder", "body_digest", "caveats", "sig", "parent", "alg", "pq_pk", "pq_sig"]);
function validateWireV2(p) {
  try {
    if (!isObj(p)) return "PCActn is not an object";
    for (const k of Object.keys(p)) if (!KNOWN.has(k)) return `unknown field '${k}'`;
    for (const k of PCACTN_REQUIRED_FIELDS) if (!(k in p)) return `missing field '${k}'`;
    const { sig, threshold, pq_sig, ...body } = p;
    void sig;
    void threshold;
    void pq_sig;
    try {
      canonicalizeStrict(body);
    } catch (e) {
      return e.message;
    }
    if (!isInt(p.ver)) return "'ver' must be a safe integer";
    if (!isInt(p.counter)) return "'counter' must be a safe integer";
    if (!isInt(p.iat)) return "'iat' must be a safe integer";
    if (!isInt(p.exp)) return "'exp' must be a safe integer";
    if (!isStr(p.aud) || p.aud.length === 0 || u8len(p.aud) > MAX_AUD_LEN) return "'aud' must be a non-empty string (<= 256 UTF-8 bytes)";
    if (p.nonce !== void 0 && (!isStr(p.nonce) || p.nonce.length === 0 || u8len(p.nonce) > MAX_NONCE_LEN)) {
      return "'nonce' must be a non-empty string (<= 128 UTF-8 bytes)";
    }
    const sigErr = validateSignatureWire(p, decodeB64uStrict);
    if (sigErr !== null) return sigErr;
    if (decodeB64uStrict(p.grant_ref, B32) === null) return "'grant_ref' is not canonical base64url (32 bytes)";
    const a = p.action;
    if (!isObj(a)) return "'action' must be an object";
    for (const k of Object.keys(a)) if (!["verb", "resource", "params_digest", "reversibility_class"].includes(k)) return `unknown field 'action.${k}'`;
    if (!isStr(a.verb) || !isStr(a.resource) || !isStr(a.reversibility_class)) return "action.verb/resource/reversibility_class must be strings";
    if (decodeB64uStrict(a.params_digest, B32) === null) return "'action.params_digest' is not canonical base64url (32 bytes)";
    const pl = p.plan;
    if (!isObj(pl)) return "'plan' must be an object";
    for (const k of Object.keys(pl)) if (!["root", "inclusion_proof", "node_id", "conditions_digest"].includes(k)) return `unknown field 'plan.${k}'`;
    if (decodeB64uStrict(pl.root, B32) === null) return "'plan.root' is not canonical base64url (32 bytes)";
    if (!isStr(pl.node_id)) return "'plan.node_id' must be a string";
    if (pl.conditions_digest !== void 0 && decodeB64uStrict(pl.conditions_digest, B32) === null) {
      return "'plan.conditions_digest' must be a canonical base64url string (32 bytes)";
    }
    const ip = pl.inclusion_proof;
    if (!isObj(ip)) return "'plan.inclusion_proof' must be an object";
    for (const k of Object.keys(ip)) if (!["index", "size", "path"].includes(k)) return `unknown field 'plan.inclusion_proof.${k}'`;
    if (!isInt(ip.index)) return "'plan.inclusion_proof.index' must be a safe integer";
    if (!isInt(ip.size)) return "'plan.inclusion_proof.size' must be a safe integer";
    if (!Array.isArray(ip.path)) return "'plan.inclusion_proof.path' must be an array";
    for (const [i, st] of ip.path.entries()) {
      if (!isObj(st)) return `proof step ${i} must be an object`;
      for (const k of Object.keys(st)) if (k !== "side" && k !== "hash") return `unknown field 'path[${i}].${k}'`;
      if (st.side !== "L" && st.side !== "R") return `proof step ${i}: side must be 'L' or 'R'`;
      if (decodeB64uStrict(st.hash, B32) === null) return `proof step ${i}: hash is not canonical base64url (32 bytes)`;
    }
    if (!Array.isArray(p.cap_chain)) return "'cap_chain' must be an array";
    for (const [i, c] of p.cap_chain.entries()) {
      if (!isObj(c)) return `cap_chain[${i}] must be an object`;
      for (const k of Object.keys(c)) if (!HOP_KEYS.has(k)) return `unknown field 'cap_chain[${i}].${k}'`;
      for (const k of ["id", "issuer", "holder", "body_digest"]) {
        if (decodeB64uStrict(c[k], B32) === null) return `cap_chain[${i}].${k} is not canonical base64url (32 bytes)`;
      }
      const hopSigErr = validateSignatureWire(c, decodeB64uStrict);
      if (hopSigErr !== null) return `cap_chain[${i}]: ${hopSigErr}`;
      if (c.parent !== void 0 && decodeB64uStrict(c.parent, B32) === null) return `cap_chain[${i}].parent is not canonical base64url (32 bytes)`;
      if (!Array.isArray(c.caveats) || !c.caveats.every((cv) => isObj(cv) && isStr(cv.type))) return `cap_chain[${i}].caveats must be an array of {type,...} objects`;
    }
    const at = p.attestation;
    if (!isObj(at) || !isInt(at.epoch)) return "'attestation' must be an object with an integer 'epoch'";
    if (!isStr(at.quote_digest) || !isStr(at.model_id) || !isStr(at.measurement) || !isStr(at.operator)) return "attestation string fields must be strings";
    const pv = p.provenance;
    if (!isObj(pv) || !isStr(pv.causal_hash) || !isNum(pv.taint_level) || !Array.isArray(pv.trusted_refs) || !pv.trusted_refs.every(isStr)) {
      return "'provenance' is malformed";
    }
    const fr = p.freshness;
    if (!isObj(fr) || !isInt(fr.epoch) || !isStr(fr.beacon_ref) || !isStr(fr.accumulator_witness)) return "'freshness' is malformed";
    const rc = p.risk_claim;
    if (!isObj(rc) || !isNum(rc.r) || !isObj(rc.inputs)) return "'risk_claim' is malformed";
    if (p.caution !== void 0 && !(isNum(p.caution) && p.caution >= 0 && p.caution <= 1)) return "'caution' must be a number in [0,1]";
    if (p.rationale_commitment !== void 0 && decodeB64uStrict(p.rationale_commitment, B32) === null) {
      return "'rationale_commitment' is not canonical base64url (32 bytes)";
    }
    if (p.tool_binding !== void 0 && decodeB64uStrict(p.tool_binding, B32) === null) return "'tool_binding' is not canonical base64url (32 bytes)";
    if (p.progress_step !== void 0 && !isObj(p.progress_step)) return "'progress_step' must be an object";
    if (p.prohibition_evidence !== void 0 && !isObj(p.prohibition_evidence) && !Array.isArray(p.prohibition_evidence)) {
      return "'prohibition_evidence' must be an object or array";
    }
    if (p.threshold !== void 0) {
      const th = p.threshold;
      if (!isObj(th) || !Array.isArray(th.shares)) return "'threshold' must be {shares:[...]}";
      for (const [i, s] of th.shares.entries()) {
        if (!isObj(s) || !isStr(s.role)) return `threshold.shares[${i}] is malformed`;
        if (decodeB64uStrict(s.publicKey, B32) === null) return `threshold.shares[${i}].publicKey is not canonical base64url (32 bytes)`;
        if (decodeB64uStrict(s.sig, SIG) === null) return `threshold.shares[${i}].sig is not canonical base64url (64 bytes)`;
      }
    }
    return null;
  } catch (e) {
    return `malformed: ${e.message}`;
  }
}

// packages/pca/src/beacons.ts
var BEACON_EPOCH_MS = 6e4;
var BEACON_MAX_VALIDITY_MS = 60 * 6e4;

// packages/pca/src/taint.ts
var TAINT_LEVELS = ["trusted", "first_party", "tool", "web", "agent"];
var RANK = { trusted: 0, first_party: 1, tool: 2, web: 3, agent: 4 };
var MAX_RANK = TAINT_LEVELS.length - 1;
var TOP = { kind: "agent" };
var labelRank = (l) => RANK[l.kind];
var taintValue = (l) => labelRank(l) / MAX_RANK;
var labelId = (l) => "id" in l ? l.id : void 0;
function joinLabel(a, b) {
  const ra = labelRank(a);
  const rb = labelRank(b);
  if (ra > rb) return a;
  if (rb > ra) return b;
  const ida = labelId(a);
  const idb = labelId(b);
  if (ida === idb) return a;
  return { kind: a.kind };
}
function joinLabels(labels) {
  if (labels.length === 0) return { ...TOP };
  return labels.reduce((acc, l) => joinLabel(acc, l));
}
function classifyRef(ref, ctx) {
  if (typeof ref !== "string" || ref.length === 0) return { kind: "agent" };
  const vouched = ctx.registry.lookup(ref);
  if (vouched && RANK[vouched.kind] !== void 0) return vouched;
  try {
    if (ctx.resourceGraph?.node(ref)) return { kind: "first_party" };
  } catch {
  }
  return { kind: "agent", id: ref.length <= 128 ? ref : void 0 };
}
function computeTaint(provenance, ctx) {
  const fail = (reason) => ({ taint: 1, label: { ...TOP }, refs: [], valid: false, reason });
  if (!ctx || !ctx.registry || typeof ctx.registry.lookup !== "function") return fail("taint: no trusted-input registry");
  if (provenance === null || typeof provenance !== "object" || Array.isArray(provenance)) {
    return fail("taint: provenance is absent or malformed");
  }
  const refsRaw = provenance.trusted_refs;
  if (refsRaw !== void 0 && !Array.isArray(refsRaw)) return fail("taint: trusted_refs must be an array");
  const list = Array.isArray(refsRaw) ? refsRaw : [];
  if (list.some((r) => typeof r !== "string" || r.length === 0)) return fail("taint: trusted_refs must be non-empty strings");
  const refs = list.map((ref) => ({ ref, label: classifyRef(ref, ctx) }));
  const label = joinLabels(refs.map((r) => r.label));
  return { taint: taintValue(label), label, refs, valid: true };
}

// packages/pca/src/pcactn.ts
var PCACTN_VERSION = PCACTN_WIRE_VERSION;
var SIG_DOMAIN = "atlas-pca/actn/v2\0";
var PCACTN_MAX_LIFETIME_MS = 36e5;
var PCACTN_MAX_SKEW_MS = 6e4;
var PCACTN_DEFAULT_TTL_MS = 20 * 6e4;
function thresholdMessage(p) {
  const { sig: _sig, threshold: _th, pq_sig: _pq, ...body } = p;
  void _sig;
  void _th;
  void _pq;
  const d = sha2563(canonicalBytesStrict(body));
  const pre = utf8(SIG_DOMAIN);
  const m = new Uint8Array(pre.length + d.length);
  m.set(pre);
  m.set(d, pre.length);
  return m;
}
function signPCActn(body, leafHolderSecret) {
  return { ...body, sig: b64u(sign(leafHolderSecret, thresholdMessage(body))) };
}
function pcactnDigest(p) {
  return hashCanonical(p);
}
function buildPCActn(input) {
  if (typeof input.aud !== "string" || input.aud.length === 0) throw new Error("buildPCActn: aud (audience) is required");
  const node = input.plan.find((n) => n.id === input.nodeId);
  if (!node) throw new Error(`buildPCActn: unknown plan node ${input.nodeId}`);
  const digest = paramsDigest(input.params);
  if (node.params_digest !== void 0 && node.params_digest !== digest) {
    throw new Error(`buildPCActn: params do not match plan node ${node.id}'s params_digest`);
  }
  const committed = commitPlan(input.plan);
  const iat = input.iat ?? input.now ?? Date.now();
  const body = {
    ver: PCACTN_VERSION,
    action: {
      verb: node.verb,
      resource: node.resource,
      params_digest: digest,
      reversibility_class: node.reversibility_class ?? DEFAULT_REVERSIBILITY_CLASS
    },
    grant_ref: input.grant.id,
    cap_chain: input.chain,
    plan: {
      root: committed.root,
      inclusion_proof: committed.proofFor(node.id),
      node_id: node.id,
      conditions_digest: conditionsDigest(node.pre, node.post)
    },
    // Empty STRUCTURE stubs when the caller supplies none (wire stays well-formed). Enforcement is REAL
    // and opt-in on the verifier: M5 attestation (enforce.attestation), M3 freshness (enforce.freshness),
    // M1 taint gate (enforce.taint). A stub fails those gates closed; a real action carries real blocks.
    attestation: input.attestation ?? { quote_digest: "", epoch: 0, model_id: "unattested", measurement: "", operator: "unattested" },
    provenance: input.provenance ?? { causal_hash: "", taint_level: 0, trusted_refs: [] },
    freshness: input.freshness ?? { beacon_ref: "", epoch: 0, accumulator_witness: "" },
    counter: input.counter,
    risk_claim: input.riskClaim ?? { r: 0, inputs: {} },
    aud: input.aud,
    iat,
    exp: input.exp ?? iat + (input.ttlMs ?? PCACTN_DEFAULT_TTL_MS),
    ...input.nonce !== void 0 ? { nonce: input.nonce } : {},
    ...input.caution !== void 0 ? { caution: input.caution } : {},
    ...input.rationaleCommitment !== void 0 ? { rationale_commitment: input.rationaleCommitment } : {},
    ...input.progressStep !== void 0 ? { progress_step: input.progressStep } : {},
    ...input.prohibitionEvidence !== void 0 ? { prohibition_evidence: input.prohibitionEvidence } : {},
    ...input.toolBinding !== void 0 ? { tool_binding: input.toolBinding } : {}
  };
  return signPCActn(body, input.signerSecret);
}
var notEnforced = () => ({ enforced: false });
async function verifyPCActnCore(p, opts) {
  const checks = {};
  let reason;
  const fail = (name, why) => {
    checks[name] = "fail";
    reason ??= `${name}: ${why}`;
  };
  const now = opts.nowEpoch ?? Date.now();
  const ctx = { pcactn: p, grant: opts.grant, nowEpoch: now };
  try {
    const wire = validateWireV2(p);
    if (wire !== null) {
      checks.wire = "fail";
      return { allow: false, checks, reason: `wire: ${wire}` };
    }
    checks.wire = "pass";
    if (p.ver === PCACTN_VERSION) checks.version = "pass";
    else fail("version", `unsupported ver ${String(p.ver)} (this verifier requires ${PCACTN_VERSION})`);
    const hasAud = typeof p.aud === "string" && p.aud.length > 0;
    if (opts.audience === null) checks.audience = "not-enforced";
    else if (opts.audience === void 0) {
      if (hasAud) fail("audience", "PCActn carries a signed aud but this verifier supplied no audience (pass your audience, or audience: null to accept any)");
      else checks.audience = "not-enforced";
    } else if (p.aud === opts.audience) checks.audience = "pass";
    else fail("audience", "aud does not match this resource server / instance");
    if (!(p.exp > p.iat)) fail("validity", "exp must be greater than iat");
    else if (p.exp - p.iat > PCACTN_MAX_LIFETIME_MS) fail("validity", `lifetime exceeds ${PCACTN_MAX_LIFETIME_MS} ms`);
    else if (p.iat > now + PCACTN_MAX_SKEW_MS) fail("validity", "iat is in the future (clock skew)");
    else if (now > p.exp) fail("validity", "the PCActn has expired");
    else checks.validity = "pass";
    const chain2 = p.cap_chain;
    if (!Array.isArray(chain2) || chain2.length === 0) {
      fail("cap_chain", "empty chain");
    } else if (capHash(chain2[0]) !== capHash(opts.grant)) {
      fail("cap_chain", "chain root is not the grant");
    } else {
      const r = verifyChain(chain2, opts.grant.issuer);
      if (r.ok) checks.cap_chain = "pass";
      else fail("cap_chain", r.reason ?? "invalid");
    }
    const chainRoot = Array.isArray(chain2) && chain2.length > 0 ? chain2[0] : void 0;
    const rootId = typeof chainRoot === "object" && chainRoot !== null ? chainRoot.id : void 0;
    if (typeof p.grant_ref === "string" && p.grant_ref.length > 0 && typeof rootId === "string" && p.grant_ref === rootId) {
      checks.grant_ref_bound = "pass";
    } else {
      fail("grant_ref_bound", "grant_ref is not the id of the root capability in cap_chain");
    }
    const cond = p.plan.conditions_digest ?? conditionsDigest();
    const leaf = planLeaf(p.plan.node_id, p.action, cond);
    if (verifyInclusion(p.plan.root, p.plan.inclusion_proof, leaf)) checks.plan_inclusion = "pass";
    else fail("plan_inclusion", "action is not a node of the committed plan");
    checks.plan_root_authorized = "not-enforced";
    const leafCap = Array.isArray(chain2) ? chain2[chain2.length - 1] : void 0;
    if (leafCap && typeof p.sig === "string" && verifyLeafSuite({ alg: p.alg, holder: leafCap.holder, pqPublicKey: p.pq_pk, message: thresholdMessage(p), sig: p.sig, pqSig: p.pq_sig })) {
      checks.leaf_signature = "pass";
    } else {
      fail("leaf_signature", "signature does not verify under the leaf holder key / suite");
    }
    if (typeof p.counter === "number" && Number.isSafeInteger(p.counter) && p.counter >= 0) checks.counter = "pass";
    else fail("counter", "missing or not a non-negative safe integer");
    if (opts.enforce?.taint) {
      const g = opts.enforce.taint;
      try {
        const t = computeTaint(p.provenance, g.ctx);
        if (!t.valid) fail("taint_gate", t.reason ?? "provenance lineage is not server-verifiable (fail closed)");
        else if (!(g.maxTaint >= 0)) fail("taint_gate", "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)");
        else if (t.taint > g.maxTaint) fail("taint_gate", `information-flow taint ${t.taint} exceeds policy max ${g.maxTaint}`);
        else checks.taint_gate = "pass";
      } catch (e) {
        fail("taint_gate", `taint gate error (fail closed): ${e.message}`);
      }
    } else {
      checks.taint_gate = "not-enforced";
    }
    if (opts.enforce?.freshness) {
      const g = opts.enforce.freshness;
      const epochMs = g.epochMs ?? BEACON_EPOCH_MS;
      const fnow = g.now ?? now;
      const skew = Number.isFinite(g.clockSkewMs) ? Math.max(0, g.clockSkewMs) : 0;
      const fr = p.freshness;
      if (!(epochMs > 0) || !Number.isFinite(g.maxAgeMs) || g.maxAgeMs < 0) {
        fail("freshness", "freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)");
      } else if (typeof fr?.beacon_ref !== "string" || fr.beacon_ref.length === 0 || !Number.isSafeInteger(fr.epoch) || fr.epoch <= 0) {
        fail("freshness", "freshness anchor is missing (empty beacon_ref or non-positive epoch stub)");
      } else {
        const anchor = fr.epoch * epochMs;
        if (anchor > fnow + skew) fail("freshness", "freshness anchor is in the future");
        else if (fnow - anchor > g.maxAgeMs) fail("freshness", `freshness anchor is stale (older than ${g.maxAgeMs} ms)`);
        else checks.freshness = "pass";
      }
    }
    const run = async (name, hook, applicable = true) => {
      if (!applicable) return;
      const res = await (hook ?? notEnforced)(ctx);
      if (!res.enforced) checks[name] = "not-enforced";
      else if (res.ok) checks[name] = "pass";
      else fail(name, res.reason ?? "rejected");
    };
    const attGate = opts.enforce?.attestation;
    await run("attestation", attGate?.verifier ?? opts.hooks?.attestation);
    if (attGate && (attGate.required ?? true) && checks.attestation === "not-enforced") {
      fail("attestation", "attestation required but the verifier reported not-enforced / no document (fail closed)");
    }
    await run("threshold", opts.hooks?.threshold);
    await run("revocation", opts.hooks?.revocation);
    if (p.zk_compliance !== void 0) {
      await run("zk_compliance", opts.hooks?.zk);
      if (checks.zk_compliance !== "pass" && checks.zk_compliance !== "fail") {
        fail("zk_compliance", "PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof");
      }
    }
    if (p.bond_ref !== void 0) checks.bond = "not-enforced";
  } catch (e) {
    reason ??= `malformed PCActn: ${e.message}`;
    checks.malformed = "fail";
  }
  const allow = !Object.values(checks).includes("fail");
  return allow ? { allow, checks } : { allow, checks, reason };
}

// packages/pca/src/risk.ts
var clamp01 = (x) => x < 0 ? 0 : x > 1 ? 1 : x;
var unit = (x, worst) => Number.isFinite(x) ? clamp01(x) : worst;
var wt = (x) => Number.isFinite(x) && x > 0 ? x : 0;
function riskScore(i, w) {
  const r = wt(w.alpha) * unit(i.semanticDistance, 1) + wt(w.beta) * (1 - unit(i.reversibility, 0)) + wt(w.gamma) * unit(i.blastRadius, 1) + wt(w.delta) * unit(i.taint, 1) + wt(w.epsilon) * (1 - unit(i.confidence, 0)) + wt(w.zeta) * unit(i.age, 1);
  return clamp01(r);
}
function requiredThreshold(r, p, opts = {}) {
  const x = Number.isFinite(r) ? r : 1;
  if (x <= p.theta1) return { t: 1, proof: "claim", optimisticAllowed: !opts.irreversible };
  if (x <= p.theta2) return { t: 2, proof: "standard", optimisticAllowed: false };
  return { t: 3, proof: "strong", optimisticAllowed: false };
}
var nz = (x) => Number.isFinite(x) && x > 0 ? x : 0;
function cost(r, kappa) {
  return nz(kappa) * clamp01(Number.isFinite(r) ? r : 1);
}
function leak(b, now, lambda) {
  const from = b.asOf ?? b.tau;
  const dt = Number.isFinite(now) && Number.isFinite(from) ? Math.max(0, now - from) : 0;
  const B = Math.max(0, b.B - nz(lambda) * (dt / 1e3));
  return { B, tau: b.tau, asOf: Number.isFinite(now) ? Math.max(now, from) : from };
}
function debit(b, c) {
  return { ...b, B: Math.max(0, b.B - nz(c)) };
}
function recharge(b, rho, bMax, now) {
  return { B: Math.min(nz(bMax), b.B + nz(rho)), tau: now, asOf: now };
}
function admit(r, b, p) {
  const { t } = requiredThreshold(r, p);
  const c = cost(r, p.kappa);
  if (t < 3 && !(b.B >= c)) return { admit: false, needStepUp: true, t: 3, metered: false };
  if (t === 1) return { admit: true, needStepUp: false, t: 1, metered: true };
  if (t === 2) return { admit: false, needStepUp: true, t: 2, metered: true };
  return { admit: false, needStepUp: true, t: 3, metered: false };
}
function safetyBound(p) {
  return p.kappa > 0 ? Math.max(0, p.bMax) / p.kappa : 0;
}

// packages/pca/src/threshold.ts
var isValidT = (t) => t === 1 || t === 2 || t === 3;
var SIGNER_SET_DOMAIN = "atlas-pca/signerset/v1\0";
function signerSetHash(signerSet) {
  const rows = (Array.isArray(signerSet) ? signerSet : []).map((s) => {
    const row = { publicKey: String(s?.publicKey), role: String(s?.role) };
    if (typeof s?.pq_pk === "string") row.pq_pk = s.pq_pk;
    return row;
  }).sort((a, b) => compareUtf8(a.role, b.role) || compareUtf8(a.publicKey, b.publicKey));
  return sha2563(concat(utf8(SIGNER_SET_DOMAIN), canonicalBytes(rows)));
}
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
var SHARE_SUITE_TAG = "\0atlas-pca/share-suite/v1\0";
function shareSuiteTag(alg) {
  const suite = resolveSigAlg(alg);
  if (suite === null || suite.alg === "ed25519") return new Uint8Array(0);
  return utf8(SHARE_SUITE_TAG + suite.alg);
}
function shareMessage(role, message, signerSet, t, alg) {
  if (!isValidT(t)) throw new RangeError("shareMessage: t must be 1, 2 or 3");
  return concat(utf8(`atlas-pca/share/${role}\0`), sha2563(message), signerSetHash(signerSet), new Uint8Array([t]), shareSuiteTag(alg));
}
function signShare(role, secretKey, message, bind, suite) {
  if (!bind) throw new TypeError(`signShare: a '${role}' share must bind {signerSet, t}`);
  return signPreparedShare(role, secretKey, shareMessage(role, message, bind.signerSet, bind.t, suite?.alg), suite);
}
function signPreparedShare(role, secretKey, preparedShareMessage, suite) {
  const resolved = resolveSigAlg(suite?.alg);
  if (resolved === null) throw new RangeError(`signPreparedShare: unknown signature alg '${String(suite?.alg)}'`);
  const publicKey = b64u(publicKeyOf(secretKey));
  if (resolved.alg === "ed25519") {
    return { role, publicKey, sig: b64u(sign(secretKey, preparedShareMessage)) };
  }
  const parts = signWithSuite(suite.alg, { edSecret: secretKey, mlDsa: suite.mlDsa }, preparedShareMessage);
  const share = { role, publicKey, sig: parts.sig, alg: resolved.alg };
  if (parts.pq_sig !== void 0) share.pq_sig = parts.pq_sig;
  return share;
}
function assembleThreshold(shares) {
  return { shares: Array.isArray(shares) ? [...shares] : [] };
}
var ROLES = ["agent", "guardian", "principal"];
function verifyThreshold(sig, message, signerSet, t, baseline) {
  const fail = (reason2) => ({ ok: false, count: 0, roles: [], reason: reason2 });
  if (!isValidT(t)) return fail(`invalid threshold t=${String(t)} (must be 1, 2 or 3)`);
  const keyOfRole = /* @__PURE__ */ new Map();
  const pqKeyOfRole = /* @__PURE__ */ new Map();
  const roleOfKey = /* @__PURE__ */ new Map();
  for (const s of Array.isArray(signerSet) ? signerSet : []) {
    if (!s || !ROLES.includes(s.role) || decodeB64uStrict(s.publicKey, 32) === null) return fail("malformed signer set");
    if (s.pq_pk !== void 0 && decodeB64uStrict(s.pq_pk, ML_DSA_65_PUBLIC_KEY_BYTES) === null) return fail("malformed signer set (pq_pk)");
    const prevKey = keyOfRole.get(s.role);
    if (prevKey !== void 0 && prevKey !== s.publicKey) return fail(`signer set registers more than one key for role ${s.role}`);
    const prevRole = roleOfKey.get(s.publicKey);
    if (prevRole !== void 0 && prevRole !== s.role) return fail("signer set registers one key under two roles");
    keyOfRole.set(s.role, s.publicKey);
    pqKeyOfRole.set(s.role, typeof s.pq_pk === "string" ? s.pq_pk : void 0);
    roleOfKey.set(s.publicKey, s.role);
  }
  const validKeys = /* @__PURE__ */ new Set();
  const validRoles = [];
  let reason;
  for (const share of sig && Array.isArray(sig.shares) ? sig.shares : []) {
    if (!share || typeof share.role !== "string" || typeof share.publicKey !== "string") {
      reason ??= "malformed share";
      continue;
    }
    if (validKeys.has(share.publicKey)) continue;
    const registeredKey = keyOfRole.get(share.role);
    if (registeredKey === void 0) {
      reason ??= `role ${share.role} is not in the signer set`;
      continue;
    }
    if (share.publicKey !== registeredKey) {
      reason ??= `share for role ${share.role} uses a key not registered for that role`;
      continue;
    }
    if (resolveSigAlg(share.alg) === null) {
      reason ??= `share for role ${share.role} declares an unknown signature alg`;
      continue;
    }
    const signed = shareMessage(share.role, message, signerSet, t, share.alg);
    const mlDsaPub = pqKeyOfRole.get(share.role);
    if (typeof share.sig !== "string" || !verifyWithSuite(share.alg, { edPub: share.publicKey, mlDsaPub }, signed, { sig: share.sig, pq_sig: share.pq_sig })) {
      reason ??= `invalid signature for role ${share.role}`;
      continue;
    }
    validKeys.add(share.publicKey);
    validRoles.push(share.role);
  }
  if (baseline) {
    const agentKey = keyOfRole.get("agent");
    if (typeof baseline.holder === "string" && agentKey !== void 0 && baseline.holder === agentKey && !validKeys.has(agentKey) && verifyLeafSuite({ alg: baseline.alg, holder: agentKey, pqPublicKey: baseline.pqPk, message, sig: baseline.sig, pqSig: baseline.pqSig })) {
      validKeys.add(agentKey);
      validRoles.push("agent");
    }
  }
  const count = validKeys.size;
  const ok = count >= t;
  if (ok) return { ok, count, roles: validRoles };
  return { ok, count, roles: validRoles, reason: reason ?? `only ${count} distinct valid key(s), need ${t}` };
}
export {
  admit,
  assembleThreshold,
  b64u,
  buildPCActn,
  commitPlan,
  cost,
  debit,
  encodeKey,
  generateKeyPair,
  hashCanonical,
  leak,
  mintRoot,
  pcactnDigest,
  recharge,
  requiredThreshold,
  riskScore,
  safetyBound,
  signShare,
  thresholdMessage,
  verifyPCActnCore,
  verifyThreshold
};
/*! Bundled license information:

@noble/hashes/esm/utils.js:
  (*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@scure/base/lib/esm/index.js:
  (*! scure-base - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/curves/esm/abstract/utils.js:
@noble/curves/esm/abstract/modular.js:
@noble/curves/esm/abstract/curve.js:
@noble/curves/esm/abstract/edwards.js:
@noble/curves/esm/ed25519.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/post-quantum/esm/utils.js:
@noble/post-quantum/esm/_crystals.js:
@noble/post-quantum/esm/ml-dsa.js:
@noble/post-quantum/esm/slh-dsa.js:
  (*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) *)
*/

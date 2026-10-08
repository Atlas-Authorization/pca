var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

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
  const hashC = (msg3) => hashCons().update(toBytes(msg3)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
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
function setBigUint64(view, byteOffset, value, isLE) {
  if (typeof view.setBigUint64 === "function")
    return view.setBigUint64(byteOffset, value, isLE);
  const _32n2 = BigInt(32);
  const _u32_max = BigInt(4294967295);
  const wh = Number(value >> _32n2 & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE ? 4 : 0;
  const l = isLE ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE);
  view.setUint32(byteOffset + l, wl, isLE);
}
function Chi(a, b, c) {
  return a & b ^ ~a & c;
}
function Maj(a, b, c) {
  return a & b ^ a & c ^ b & c;
}
var HashMD = class extends Hash {
  constructor(blockLen, outputLen, padOffset, isLE) {
    super();
    this.finished = false;
    this.length = 0;
    this.pos = 0;
    this.destroyed = false;
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE;
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
    const { buffer, view, blockLen, isLE } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    clean(this.buffer.subarray(pos));
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    for (let i = pos; i < blockLen; i++)
      buffer[i] = 0;
    setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
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
      oview.setUint32(4 * i, state[i], isLE);
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
    const { A, B, C, D, E, F, G, H } = this;
    return [A, B, C, D, E, F, G, H];
  }
  // prettier-ignore
  set(A, B, C, D, E, F, G, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
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
    let { A, B, C, D, E, F, G, H } = this;
    for (let i = 0; i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B, C) | 0;
      H = G;
      G = F;
      F = E;
      E = D + T1 | 0;
      D = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D = D + this.D | 0;
    E = E + this.E | 0;
    F = F + this.F | 0;
    G = G + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D, E, F, G, H);
  }
  roundClean() {
    clean(SHA256_W);
  }
  destroy() {
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    clean(this.buffer);
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
var sha256 = /* @__PURE__ */ createHasher(() => new SHA256());
var sha512 = /* @__PURE__ */ createHasher(() => new SHA512());
var sha384 = /* @__PURE__ */ createHasher(() => new SHA384());

// node_modules/.pnpm/@noble+hashes@1.8.0/node_modules/@noble/hashes/esm/sha256.js
var sha2562 = sha256;

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
  const id = (a) => a;
  const wrap = (a, b) => (c) => a(b(c));
  const encode = args.map((x) => x.encode).reduceRight(wrap, id);
  const decode = args.map((x) => x.decode).reduce(wrap, id);
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
    encode: (bytes2) => {
      if (!isBytes2(bytes2))
        throw new Error("radix2.encode input should be Uint8Array");
      return convertRadix2(Array.from(bytes2), 8, bits, !revPadding);
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
function sha2563(bytes2) {
  return sha2562(bytes2);
}
function b64u(bytes2) {
  return base64urlnopad.encode(bytes2);
}
function unb64u(s) {
  return base64urlnopad.decode(s);
}
var B64U_ALPHABET = /^[A-Za-z0-9_-]*$/;
function decodeB64uStrict(s, len) {
  if (typeof s !== "string" || !B64U_ALPHABET.test(s) || s.length % 4 === 1) return null;
  if (len !== void 0 && s.length !== b64uLen(len)) return null;
  try {
    const bytes2 = unb64u(s);
    if (b64u(bytes2) !== s) return null;
    if (len !== void 0 && bytes2.length !== len) return null;
    return bytes2;
  } catch {
    return null;
  }
}
function b64uLen(n) {
  return Math.ceil(n * 4 / 3);
}
function isCanonicalB64u(s, len) {
  return decodeB64uStrict(s, len) !== null;
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
function canonicalize(value) {
  return ser(value, /* @__PURE__ */ new Set(), false);
}
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
function hashCanonical(value) {
  return b64u(sha2563(canonicalBytes(value)));
}
function canonicalBytesLenient(value) {
  return utf8(canonicalize(value));
}
function hashCanonicalLenient(value) {
  return b64u(sha2563(canonicalBytesLenient(value)));
}

// packages/pca/src/strict-json.ts
var MAX_JSON_BYTES = 1 << 20;
var StrictJsonError = class extends Error {
  constructor(message, offset) {
    super(`strict JSON: ${message} (at offset ${offset})`);
    this.offset = offset;
    this.name = "StrictJsonError";
  }
};
var NUM = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
function strictParse(text) {
  if (typeof text !== "string") throw new StrictJsonError("input is not a string", 0);
  if (new TextEncoder().encode(text).length > MAX_JSON_BYTES) throw new StrictJsonError("input too large", 0);
  let i = 0;
  const err = (m) => {
    throw new StrictJsonError(m, i);
  };
  const ws = () => {
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c === 32 || c === 9 || c === 10 || c === 13) i++;
      else break;
    }
  };
  const parseString = () => {
    i++;
    let out = "";
    let start = i;
    for (; ; ) {
      if (i >= text.length) err("unterminated string");
      const c = text.charCodeAt(i);
      if (c === 34) {
        out += text.slice(start, i);
        i++;
        break;
      }
      if (c < 32) err("raw control character in string");
      if (c === 92) {
        out += text.slice(start, i);
        i++;
        const e = text[i];
        switch (e) {
          case '"':
            out += '"';
            break;
          case "\\":
            out += "\\";
            break;
          case "/":
            out += "/";
            break;
          case "b":
            out += "\b";
            break;
          case "f":
            out += "\f";
            break;
          case "n":
            out += "\n";
            break;
          case "r":
            out += "\r";
            break;
          case "t":
            out += "	";
            break;
          case "u": {
            const h = text.slice(i + 1, i + 5);
            if (!/^[0-9a-fA-F]{4}$/.test(h)) err("bad \\u escape");
            out += String.fromCharCode(parseInt(h, 16));
            i += 4;
            break;
          }
          default:
            err("unknown escape");
        }
        i++;
        start = i;
        continue;
      }
      i++;
    }
    if (hasLoneSurrogate(out)) err("lone surrogate in string");
    return out;
  };
  const parseNumber = () => {
    NUM.lastIndex = i;
    const m = NUM.exec(text);
    if (!m) return err("bad number");
    const lex = m[0];
    i += lex.length;
    if (/[eE]/.test(lex)) err("exponent form is not allowed (use a plain decimal)");
    if (lex === "-0") err("negative zero is not allowed");
    if (lex.includes(".")) {
      if (lex.endsWith("0")) err("trailing fractional zero is not canonical");
      const digits = lex.replace("-", "").replace(".", "").replace(/^0+/, "");
      if (digits.length > MAX_DECIMAL_DIGITS) err(`more than ${MAX_DECIMAL_DIGITS} significant digits`);
      const v2 = Number(lex);
      if (v2 !== 0 && Math.abs(v2) < 1e-6) err("non-integer magnitude below 1e-6 is not allowed");
      return v2;
    }
    const abs = lex.startsWith("-") ? lex.slice(1) : lex;
    if (abs.length > 16 || BigInt(abs) > 9007199254740991n) err("integer outside the safe range (|n| > 2^53-1)");
    return Number(lex);
  };
  const parseValue = (depth) => {
    ws();
    if (i >= text.length) err("unexpected end of input");
    const ch = text[i];
    if (ch === "{") {
      if (depth > MAX_JSON_DEPTH) err("nesting too deep");
      i++;
      const o = {};
      const seen = /* @__PURE__ */ new Set();
      ws();
      if (text[i] === "}") {
        i++;
        return o;
      }
      for (; ; ) {
        ws();
        if (text[i] !== '"') err("expected a string key");
        const k = parseString();
        if (seen.has(k)) err(`duplicate key ${JSON.stringify(k)}`);
        seen.add(k);
        ws();
        if (text[i] !== ":") err('expected ":"');
        i++;
        const v2 = parseValue(depth + 1);
        Object.defineProperty(o, k, { value: v2, enumerable: true, writable: true, configurable: true });
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "}") {
          i++;
          return o;
        }
        err('expected "," or "}"');
      }
    }
    if (ch === "[") {
      if (depth > MAX_JSON_DEPTH) err("nesting too deep");
      i++;
      const a = [];
      ws();
      if (text[i] === "]") {
        i++;
        return a;
      }
      for (; ; ) {
        a.push(parseValue(depth + 1));
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "]") {
          i++;
          return a;
        }
        err('expected "," or "]"');
      }
    }
    if (ch === '"') return parseString();
    if (ch === "-" || ch >= "0" && ch <= "9") return parseNumber();
    if (text.startsWith("true", i)) {
      i += 4;
      return true;
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return false;
    }
    if (text.startsWith("null", i)) {
      i += 4;
      return null;
    }
    return err("unexpected token");
  };
  const v = parseValue(1);
  ws();
  if (i < text.length) err("trailing characters after the JSON value");
  return v;
}
function strictParseBytes(bytes2) {
  const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes2);
  return strictParse(text);
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
  "bond_ref"
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
var HOP_KEYS = /* @__PURE__ */ new Set(["id", "issuer", "holder", "body_digest", "caveats", "sig", "parent"]);
function validateWireV2(p) {
  try {
    if (!isObj(p)) return "PCActn is not an object";
    for (const k of Object.keys(p)) if (!KNOWN.has(k)) return `unknown field '${k}'`;
    for (const k of PCACTN_REQUIRED_FIELDS) if (!(k in p)) return `missing field '${k}'`;
    const { sig, threshold, ...body2 } = p;
    try {
      canonicalizeStrict(body2);
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
    if (decodeB64uStrict(p.sig, SIG) === null) return "'sig' is not canonical base64url (64 bytes)";
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
      if (decodeB64uStrict(c.sig, SIG) === null) return `cap_chain[${i}].sig is not canonical base64url (64 bytes)`;
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
function numberToHexUnpadded(num) {
  const hex = num.toString(16);
  return hex.length & 1 ? "0" + hex : hex;
}
function hexToNumber(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  return hex === "" ? _0n : BigInt("0x" + hex);
}
var hasHexBuiltin = (
  // @ts-ignore
  typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
);
var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
function bytesToHex(bytes2) {
  abytes2(bytes2);
  if (hasHexBuiltin)
    return bytes2.toHex();
  let hex = "";
  for (let i = 0; i < bytes2.length; i++) {
    hex += hexes[bytes2[i]];
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
function bytesToNumberBE(bytes2) {
  return hexToNumber(bytesToHex(bytes2));
}
function bytesToNumberLE(bytes2) {
  abytes2(bytes2);
  return hexToNumber(bytesToHex(Uint8Array.from(bytes2).reverse()));
}
function numberToBytesBE(n, len) {
  return hexToBytes(n.toString(16).padStart(len * 2, "0"));
}
function numberToBytesLE(n, len) {
  return numberToBytesBE(n, len).reverse();
}
function ensureBytes(title, hex, expectedLength) {
  let res;
  if (typeof hex === "string") {
    try {
      res = hexToBytes(hex);
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
var u8n = (len) => new Uint8Array(len);
var u8fr = (arr) => Uint8Array.from(arr);
function createHmacDrbg(hashLen, qByteLen, hmacFn) {
  if (typeof hashLen !== "number" || hashLen < 2)
    throw new Error("hashLen must be a number");
  if (typeof qByteLen !== "number" || qByteLen < 2)
    throw new Error("qByteLen must be a number");
  if (typeof hmacFn !== "function")
    throw new Error("hmacFn must be a function");
  let v = u8n(hashLen);
  let k = u8n(hashLen);
  let i = 0;
  const reset = () => {
    v.fill(1);
    k.fill(0);
    i = 0;
  };
  const h = (...b) => hmacFn(k, v, ...b);
  const reseed = (seed = u8n(0)) => {
    k = h(u8fr([0]), seed);
    v = h();
    if (seed.length === 0)
      return;
    k = h(u8fr([1]), seed);
    v = h();
  };
  const gen = () => {
    if (i++ >= 1e3)
      throw new Error("drbg: tried 1000 values");
    let len = 0;
    const out = [];
    while (len < qByteLen) {
      v = h();
      const sl = v.slice();
      out.push(sl);
      len += v.length;
    }
    return concatBytes2(...out);
  };
  const genUntil = (seed, pred) => {
    reset();
    reseed(seed);
    let res = void 0;
    while (!(res = pred(gen())))
      reseed();
    reset();
    return res;
  };
  return genUntil;
}
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
function tonelliShanks(P3) {
  if (P3 < BigInt(3))
    throw new Error("sqrt is not defined for small field");
  let Q = P3 - _1n2;
  let S = 0;
  while (Q % _2n === _0n2) {
    Q /= _2n;
    S++;
  }
  let Z = _2n;
  const _Fp = Field(P3);
  while (FpLegendre(_Fp, Z) === 1) {
    if (Z++ > 1e3)
      throw new Error("Cannot find square root: probably non-prime P");
  }
  if (S === 1)
    return sqrt3mod4;
  let cc = _Fp.pow(Z, Q);
  const Q1div2 = (Q + _1n2) / _2n;
  return function tonelliSlow(Fp2, n) {
    if (Fp2.is0(n))
      return n;
    if (FpLegendre(Fp2, n) !== 1)
      throw new Error("Cannot find square root");
    let M = S;
    let c = Fp2.mul(Fp2.ONE, cc);
    let t = Fp2.pow(n, Q);
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
function FpSqrt(P3) {
  if (P3 % _4n === _3n)
    return sqrt3mod4;
  if (P3 % _8n === _5n)
    return sqrt5mod8;
  return tonelliShanks(P3);
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
function Field(ORDER, bitLen2, isLE = false, redef = {}) {
  if (ORDER <= _0n2)
    throw new Error("invalid field: expected ORDER > 0, got " + ORDER);
  const { nBitLength: BITS, nByteLength: BYTES } = nLength(ORDER, bitLen2);
  if (BYTES > 2048)
    throw new Error("invalid field: expected ORDER of <= 2048 bytes");
  let sqrtP;
  const f = Object.freeze({
    ORDER,
    isLE,
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
    toBytes: (num) => isLE ? numberToBytesLE(num, BYTES) : numberToBytesBE(num, BYTES),
    fromBytes: (bytes2) => {
      if (bytes2.length !== BYTES)
        throw new Error("Field.fromBytes: expected " + BYTES + " bytes, got " + bytes2.length);
      return isLE ? bytesToNumberLE(bytes2) : bytesToNumberBE(bytes2);
    },
    // TODO: we don't need it here, move out to separate fn
    invertBatch: (lst) => FpInvertBatch(f, lst),
    // We can't move this out because Fp6, Fp12 implement it
    // and it's unclear what to return in there.
    cmov: (a, b, c) => c ? b : a
  });
  return Object.freeze(f);
}
function getFieldBytesLength(fieldOrder) {
  if (typeof fieldOrder !== "bigint")
    throw new Error("field order must be bigint");
  const bitLength = fieldOrder.toString(2).length;
  return Math.ceil(bitLength / 8);
}
function getMinHashLength(fieldOrder) {
  const length = getFieldBytesLength(fieldOrder);
  return length + Math.ceil(length / 2);
}
function mapHashToField(key, fieldOrder, isLE = false) {
  const len = key.length;
  const fieldLen = getFieldBytesLength(fieldOrder);
  const minLen = getMinHashLength(fieldOrder);
  if (len < 16 || len < minLen || len > 1024)
    throw new Error("expected " + minLen + "-1024 bytes of input, got " + len);
  const num = isLE ? bytesToNumberLE(key) : bytesToNumberBE(key);
  const reduced = mod(num, fieldOrder - _1n2) + _1n2;
  return isLE ? numberToBytesLE(reduced, fieldLen) : numberToBytesBE(reduced, fieldLen);
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
  const isZero2 = wbits === 0;
  const isNeg = wbits < 0;
  const isNegF = window % 2 !== 0;
  const offsetF = offsetStart;
  return { nextN, offset, isZero: isZero2, isNeg, isNegF, offsetF };
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
function getW(P3) {
  return pointWindowSizes.get(P3) || 1;
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
        const { nextN, offset, isZero: isZero2, isNeg, isNegF, offsetF } = calcOffsets(n, window, wo);
        n = nextN;
        if (isZero2) {
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
        const { nextN, offset, isZero: isZero2, isNeg } = calcOffsets(n, window, wo);
        n = nextN;
        if (isZero2) {
          continue;
        } else {
          const item = precomputes[offset];
          acc = acc.add(isNeg ? item.negate() : item);
        }
      }
      return acc;
    },
    getPrecomputes(W, P3, transform) {
      let comp = pointPrecomputes.get(P3);
      if (!comp) {
        comp = this.precomputeWindow(P3, W);
        if (W !== 1)
          pointPrecomputes.set(P3, transform(comp));
      }
      return comp;
    },
    wNAFCached(P3, n, transform) {
      const W = getW(P3);
      return this.wNAF(W, this.getPrecomputes(W, P3, transform), n);
    },
    wNAFCachedUnsafe(P3, n, transform, prev) {
      const W = getW(P3);
      if (W === 1)
        return this.unsafeLadder(P3, n, prev);
      return this.wNAFUnsafe(W, this.getPrecomputes(W, P3, transform), n, prev);
    },
    // We calculate precomputes for elliptic curve point multiplication
    // using windowed method. This specifies window size and
    // stores precomputed values. Usually only base point would be precomputed.
    setWindowSize(P3, W) {
      validateW(W, bits);
      pointWindowSizes.set(P3, W);
      pointPrecomputes.delete(P3);
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
  const { Fp: Fp2, n: CURVE_ORDER, prehash, hash: cHash, randomBytes: randomBytes2, nByteLength, h: cofactor } = CURVE;
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
  const adjustScalarBytes2 = CURVE.adjustScalarBytes || ((bytes2) => bytes2);
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
      const D = modP(a * A);
      const x1y1 = X1 + Y1;
      const E = modP(modP(x1y1 * x1y1) - A - B);
      const G2 = D + B;
      const F = G2 - C;
      const H = D - B;
      const X3 = modP(E * F);
      const Y3 = modP(G2 * H);
      const T3 = modP(E * H);
      const Z3 = modP(F * G2);
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
      const D = modP(Z1 * Z2);
      const E = modP((X1 + Y1) * (X2 + Y2) - A - B);
      const F = D - C;
      const G2 = D + C;
      const H = modP(B - a * A);
      const X3 = modP(E * F);
      const Y3 = modP(G2 * H);
      const T3 = modP(E * H);
      const Z3 = modP(F * G2);
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
      const bytes2 = numberToBytesLE(y, Fp2.BYTES);
      bytes2[bytes2.length - 1] |= x & _1n4 ? 128 : 0;
      return bytes2;
    }
    toHex() {
      return bytesToHex(this.toRawBytes());
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
    const msg3 = concatBytes2(...msgs);
    return modN_LE(cHash(domain(msg3, ensureBytes("context", context), !!prehash)));
  }
  function sign2(msg3, privKey, options = {}) {
    msg3 = ensureBytes("message", msg3);
    if (prehash)
      msg3 = prehash(msg3);
    const { prefix, scalar, pointBytes } = getExtendedPublicKey(privKey);
    const r = hashDomainToScalar(options.context, prefix, msg3);
    const R = G.multiply(r).toRawBytes();
    const k = hashDomainToScalar(options.context, R, pointBytes, msg3);
    const s = modN(r + k * scalar);
    aInRange("signature.s", s, _0n4, CURVE_ORDER);
    const res = concatBytes2(R, numberToBytesLE(s, Fp2.BYTES));
    return ensureBytes("result", res, Fp2.BYTES * 2);
  }
  const verifyOpts = VERIFY_DEFAULT;
  function verify2(sig, msg3, publicKey, options = verifyOpts) {
    const { context, zip215 } = options;
    const len = Fp2.BYTES;
    sig = ensureBytes("signature", sig, 2 * len);
    msg3 = ensureBytes("message", msg3);
    publicKey = ensureBytes("publicKey", publicKey, len);
    if (zip215 !== void 0)
      abool("zip215", zip215);
    if (prehash)
      msg3 = prehash(msg3);
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
    const k = hashDomainToScalar(context, R.toRawBytes(), A.toRawBytes(), msg3);
    const RkA = R.add(A.multiplyUnsafe(k));
    return RkA.subtract(SB).clearCofactor().equals(Point.ZERO);
  }
  G._setWindowSize(8);
  const utils = {
    getExtendedPublicKey,
    /** ed25519 priv keys are uniform 32b. No need to check for modulo bias, like in secp256k1. */
    randomPrivateKey: () => randomBytes2(Fp2.BYTES),
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
  const P3 = ED25519_P;
  const x2 = x * x % P3;
  const b2 = x2 * x % P3;
  const b4 = pow2(b2, _2n3, P3) * b2 % P3;
  const b5 = pow2(b4, _1n5, P3) * x % P3;
  const b10 = pow2(b5, _5n2, P3) * b5 % P3;
  const b20 = pow2(b10, _10n, P3) * b10 % P3;
  const b40 = pow2(b20, _20n, P3) * b20 % P3;
  const b80 = pow2(b40, _40n, P3) * b40 % P3;
  const b160 = pow2(b80, _80n, P3) * b80 % P3;
  const b240 = pow2(b160, _80n, P3) * b80 % P3;
  const b250 = pow2(b240, _10n, P3) * b10 % P3;
  const pow_p_5_8 = pow2(b250, _2n3, P3) * x % P3;
  return { pow_p_5_8, b2 };
}
function adjustScalarBytes(bytes2) {
  bytes2[0] &= 248;
  bytes2[31] &= 127;
  bytes2[31] |= 64;
  return bytes2;
}
function uvRatio(u, v) {
  const P3 = ED25519_P;
  const v3 = mod(v * v * v, P3);
  const v7 = mod(v3 * v3 * v, P3);
  const pow = ed25519_pow_2_252_3(u * v7).pow_p_5_8;
  let x = mod(u * v3 * pow, P3);
  const vx2 = mod(v * x * x, P3);
  const root1 = x;
  const root2 = mod(x * ED25519_SQRT_M1, P3);
  const useRoot1 = vx2 === u;
  const useRoot2 = vx2 === mod(-u, P3);
  const noRoot = vx2 === mod(-u * ED25519_SQRT_M1, P3);
  if (useRoot1)
    x = root1;
  if (useRoot2 || noRoot)
    x = root2;
  if (isNegativeLE(x, P3))
    x = mod(-x, P3);
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
function sign(secretKey, msg3) {
  return ed25519.sign(msg3, secretKey);
}
function verify(publicKey, msg3, sig) {
  try {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) return false;
    if (!(sig instanceof Uint8Array) || sig.length !== 64) return false;
    if (!ed25519.verify(sig, msg3, publicKey, { zip215: false })) return false;
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
var decodeKey = unb64u;
var encodeSig = b64u;
var decodeSig = unb64u;
function verifyB64u(publicKeyB64u, msg3, sigB64u) {
  try {
    const pk = decodeB64uStrict(publicKeyB64u, 32);
    const sg = decodeB64uStrict(sigB64u, 64);
    if (!pk || !sg) return false;
    return verify(pk, msg3, sg);
  } catch {
    return false;
  }
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
function leafHash(leaf) {
  return sha2563(cat(LEAF, canonicalBytes(leaf)));
}
function nodeHash(l, r) {
  return sha2563(cat(NODE, l, r));
}
function split2(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}
function build(hs) {
  if (hs.length === 1) return hs[0];
  const k = split2(hs.length);
  return nodeHash(build(hs.slice(0, k)), build(hs.slice(k)));
}
function prove(hs, idx, out) {
  if (hs.length === 1) return;
  const k = split2(hs.length);
  if (idx < k) {
    prove(hs.slice(0, k), idx, out);
    out.push({ side: "R", hash: b64u(build(hs.slice(k))) });
  } else {
    prove(hs.slice(k), idx - k, out);
    out.push({ side: "L", hash: b64u(build(hs.slice(0, k))) });
  }
}
function merkleRoot(leaves) {
  if (leaves.length === 0) throw new RangeError("merkleRoot: empty leaf set");
  return b64u(build(leaves.map(leafHash)));
}
function merkleProof(leaves, index) {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new RangeError("merkleProof: index out of range");
  }
  const path = [];
  prove(leaves.map(leafHash), index, path);
  return { index, size: leaves.length, path };
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
    if (!Number.isSafeInteger(proof.index) || !Number.isSafeInteger(proof.size)) return false;
    if (proof.size < 1 || proof.index < 0 || proof.index >= proof.size) return false;
    const shape = pathShape(proof.index, proof.size);
    if (shape.length !== proof.path.length) return false;
    let h = leafHash(leaf);
    for (let i = 0; i < proof.path.length; i++) {
      const step = proof.path[i];
      if (step.side !== shape[i]) return false;
      const sib = decodeB64uStrict(step.hash, 32);
      if (!sib) return false;
      h = step.side === "L" ? nodeHash(sib, h) : nodeHash(h, sib);
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

// packages/pca/src/capability.ts
var CAP_DOMAIN = "atlas-pca/cap/v1\0";
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
function seal(body2, signerSecret) {
  const body_digest = hashCanonical(bodyOf(body2));
  const sig = b64u(sign(signerSecret, sigMessage(body_digest)));
  const cap = {
    id: body_digest,
    issuer: body2.issuer,
    holder: body2.holder,
    caveats: body2.caveats,
    body_digest,
    sig
  };
  if (body2.parent !== void 0) cap.parent = body2.parent;
  return cap;
}
function cloneCaveats(cs) {
  return JSON.parse(new TextDecoder().decode(canonicalBytes(cs)));
}
function mintRoot(args) {
  return seal(
    { issuer: args.principalPublic, holder: args.holder, caveats: cloneCaveats(args.caveats) },
    args.principalSecret
  );
}
function attenuate(parent, addedCaveats, signerSecret) {
  return delegate(parent, parent.holder, addedCaveats, signerSecret);
}
function delegate(parent, toHolder, addedCaveats, signerSecret) {
  return seal(
    {
      issuer: parent.holder,
      holder: toHolder,
      caveats: [...cloneCaveats(parent.caveats), ...cloneCaveats(addedCaveats)],
      parent: capHash(parent)
    },
    signerSecret
  );
}
function checkSig(c, signer, label) {
  let digest;
  try {
    digest = hashCanonical(bodyOf(c));
  } catch {
    return `${label}: malformed body`;
  }
  if (digest !== c.body_digest || c.id !== c.body_digest) return `${label}: body digest mismatch`;
  if (!verifyB64u(signer, sigMessage(c.body_digest), c.sig)) {
    return `${label}: bad signature (not signed by expected key)`;
  }
  return void 0;
}
var MAX_CHAIN_DEPTH = 16;
function wellTyped(c) {
  if (c === null || typeof c !== "object") return false;
  const x = c;
  return typeof x.id === "string" && typeof x.issuer === "string" && typeof x.holder === "string" && typeof x.body_digest === "string" && typeof x.sig === "string" && (x.parent === void 0 || typeof x.parent === "string") && Array.isArray(x.caveats) && x.caveats.every((cv) => cv !== null && typeof cv === "object" && !Array.isArray(cv) && typeof cv.type === "string");
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
  return { ok: true };
}

// packages/pca/src/pcactn.ts
var PCACTN_VERSION = PCACTN_WIRE_VERSION;
var SIG_DOMAIN = "atlas-pca/actn/v2\0";
var PCACTN_MAX_LIFETIME_MS = 36e5;
var PCACTN_MAX_SKEW_MS = 6e4;
var PCACTN_DEFAULT_TTL_MS = 20 * 6e4;
function thresholdMessage(p) {
  const { sig: _sig, threshold: _th, ...body2 } = p;
  const d = sha2563(canonicalBytesStrict(body2));
  const pre = utf8(SIG_DOMAIN);
  const m = new Uint8Array(pre.length + d.length);
  m.set(pre);
  m.set(d, pre.length);
  return m;
}
function signPCActn(body2, leafHolderSecret) {
  return { ...body2, sig: b64u(sign(leafHolderSecret, thresholdMessage(body2))) };
}
function encodePCActn(p) {
  return canonicalize(p);
}
function decodePCActn(s) {
  const v = strictParse(s);
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new TypeError("decodePCActn: not an object");
  return v;
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
  const body2 = {
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
    // NOT-YET-ENFORCED stub defaults (M5 attestation / M3 freshness / M1 taint gate).
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
  return signPCActn(body2, input.signerSecret);
}
var notEnforced = () => ({ enforced: false });
async function verifyPCActnCore(p, opts) {
  const checks = {};
  let reason;
  const fail2 = (name, why) => {
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
    else fail2("version", `unsupported ver ${String(p.ver)} (this verifier requires ${PCACTN_VERSION})`);
    if (opts.audience === void 0) checks.audience = "not-enforced";
    else if (p.aud === opts.audience) checks.audience = "pass";
    else fail2("audience", "aud does not match this resource server / instance");
    if (!(p.exp > p.iat)) fail2("validity", "exp must be greater than iat");
    else if (p.exp - p.iat > PCACTN_MAX_LIFETIME_MS) fail2("validity", `lifetime exceeds ${PCACTN_MAX_LIFETIME_MS} ms`);
    else if (p.iat > now + PCACTN_MAX_SKEW_MS) fail2("validity", "iat is in the future (clock skew)");
    else if (now > p.exp) fail2("validity", "the PCActn has expired");
    else checks.validity = "pass";
    const chain2 = p.cap_chain;
    if (!Array.isArray(chain2) || chain2.length === 0) {
      fail2("cap_chain", "empty chain");
    } else if (capHash(chain2[0]) !== capHash(opts.grant)) {
      fail2("cap_chain", "chain root is not the grant");
    } else {
      const r = verifyChain(chain2, opts.grant.issuer);
      if (r.ok) checks.cap_chain = "pass";
      else fail2("cap_chain", r.reason ?? "invalid");
    }
    const cond = p.plan.conditions_digest ?? conditionsDigest();
    const leaf = planLeaf(p.plan.node_id, p.action, cond);
    if (verifyInclusion(p.plan.root, p.plan.inclusion_proof, leaf)) checks.plan_inclusion = "pass";
    else fail2("plan_inclusion", "action is not a node of the committed plan");
    checks.plan_root_authorized = "not-enforced";
    const leafCap = Array.isArray(chain2) ? chain2[chain2.length - 1] : void 0;
    if (leafCap && typeof p.sig === "string" && verifyB64u(leafCap.holder, thresholdMessage(p), p.sig)) {
      checks.leaf_signature = "pass";
    } else {
      fail2("leaf_signature", "signature does not verify under the leaf holder key");
    }
    if (typeof p.counter === "number" && Number.isSafeInteger(p.counter) && p.counter >= 0) checks.counter = "pass";
    else fail2("counter", "missing or not a non-negative safe integer");
    checks.taint_gate = "not-enforced";
    const run = async (name, hook, applicable = true) => {
      if (!applicable) return;
      const res = await (hook ?? notEnforced)(ctx);
      if (!res.enforced) checks[name] = "not-enforced";
      else if (res.ok) checks[name] = "pass";
      else fail2(name, res.reason ?? "rejected");
    };
    await run("attestation", opts.hooks?.attestation);
    await run("threshold", opts.hooks?.threshold);
    await run("revocation", opts.hooks?.revocation);
    await run("zk_compliance", opts.hooks?.zk, p.zk_compliance !== void 0);
    if (p.bond_ref !== void 0) checks.bond = "not-enforced";
  } catch (e) {
    reason ??= `malformed PCActn: ${e.message}`;
    checks.malformed = "fail";
  }
  const allow = !Object.values(checks).includes("fail");
  return allow ? { allow, checks } : { allow, checks, reason };
}

// packages/pca/src/risk.ts
var DEFAULT_RISK_POLICY = {
  weights: { alpha: 0.25, beta: 0.2, gamma: 0.2, delta: 0.2, epsilon: 0.1, zeta: 0.05 },
  theta1: 0.25,
  theta2: 0.6,
  kappa: 1,
  lambda: 5e-4,
  rho: 0.5,
  bMax: 1
};
function validateRiskPolicy(p) {
  if (p === null || typeof p !== "object") return "risk_policy must be an object";
  const r = p;
  const w = r.weights;
  if (!w || typeof w !== "object") return "risk_policy.weights missing";
  for (const k of ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"]) {
    if (!Number.isFinite(w[k]) || w[k] < 0) return `risk_policy.weights.${k} must be finite and >= 0`;
  }
  for (const k of ["theta1", "theta2", "kappa", "lambda", "rho", "bMax"]) {
    if (!Number.isFinite(r[k])) return `risk_policy.${k} must be finite`;
  }
  if (r.theta1 < 0 || r.theta2 < r.theta1) return "risk_policy requires 0 <= theta1 <= theta2";
  if (r.kappa <= 0) return "risk_policy.kappa must be > 0";
  if (r.lambda < 0 || r.rho < 0 || r.bMax < 0) return "risk_policy lambda/rho/bMax must be >= 0";
  return null;
}
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
var PROOF_FOR_T = { 1: "claim", 2: "standard", 3: "strong" };
var PROOF_RANK = { claim: 0, standard: 1, strong: 2 };
function escalateThreshold(rt, minT) {
  const t = minT > rt.t ? minT : rt.t;
  const floor = PROOF_FOR_T[t];
  const proof = PROOF_RANK[rt.proof] >= PROOF_RANK[floor] ? rt.proof : floor;
  return { t, proof, optimisticAllowed: t > 1 ? false : rt.optimisticAllowed };
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
function rechargeFull(b, bMax, now) {
  return { B: nz(bMax), tau: now, asOf: now };
}
function ageSinceTouch(b, now, horizonMs = 36e5) {
  if (!Number.isFinite(now) || !Number.isFinite(b.tau) || !(horizonMs > 0)) return 1;
  return clamp01((now - b.tau) / horizonMs);
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
function subBudget(parent, alloc) {
  if (!Number.isFinite(alloc) || alloc < 0) return { ok: false, reason: "allocation must be finite and >= 0" };
  if (alloc > parent.B) return { ok: false, reason: "allocation exceeds parent remaining budget" };
  return { ok: true, sub: { B: alloc, tau: parent.tau, asOf: parent.asOf ?? parent.tau } };
}
function debitConsolidated(parent, sub, c) {
  const x = nz(c);
  if (sub.B < x) return { ok: false, reason: "sub-agent budget insufficient" };
  if (parent.B < x) return { ok: false, reason: "parent budget insufficient" };
  return { ok: true, parent: debit(parent, x), sub: debit(sub, x) };
}
var PRE_KEYS = ["after", "depends_on", "requires", "nodes"];
var POST_KEYS = ["before", "enables", "then", "next"];
function refsOf(x, keys) {
  const out = [];
  const add2 = (v) => {
    if (typeof v === "string") out.push(v);
    else if (Array.isArray(v)) {
      for (const s of v) if (typeof s === "string") out.push(s);
    }
  };
  add2(x);
  if (x !== null && typeof x === "object" && !Array.isArray(x)) {
    for (const k of keys) add2(x[k]);
  }
  return out;
}
function planGeodesic(plan, fromNodeId, toGoalNodeId) {
  if (!Array.isArray(plan)) return 1;
  const idx = /* @__PURE__ */ new Map();
  plan.forEach((n2, i) => idx.set(n2.id, i));
  const a = idx.get(fromNodeId);
  const b = idx.get(toGoalNodeId);
  if (a === void 0 || b === void 0) return 1;
  if (a === b) return 0;
  const n = plan.length;
  const adj = plan.map(() => /* @__PURE__ */ new Set());
  let edges = 0;
  const link = (i, j) => {
    if (i === j) return;
    if (!adj[i].has(j)) edges++;
    adj[i].add(j);
    adj[j].add(i);
  };
  plan.forEach((node, i) => {
    for (const id of refsOf(node.pre, PRE_KEYS)) {
      const j = idx.get(id);
      if (j !== void 0) link(j, i);
    }
    for (const id of refsOf(node.post, POST_KEYS)) {
      const j = idx.get(id);
      if (j !== void 0) link(i, j);
    }
  });
  if (edges === 0) return clamp01(Math.abs(a - b) / (n - 1));
  const dist = new Array(n).fill(-1);
  dist[a] = 0;
  const q = [a];
  for (let h = 0; h < q.length; h++) {
    const u = q[h];
    for (const v of [...adj[u]].sort((x, y) => x - y)) {
      if (dist[v] === -1) {
        dist[v] = dist[u] + 1;
        q.push(v);
      }
    }
  }
  return dist[b] < 0 ? 1 : clamp01(dist[b] / (n - 1));
}

// packages/pca/src/envelope.ts
var ENVELOPE_CAVEAT = "envelope";
var GOAL_DOMAIN = "atlas-pca/goal/v1\0";
function goalCommitOf(goal, salt) {
  return hashCanonical({ d: GOAL_DOMAIN, goal, salt });
}
function verifyGoalCommit(commit, goal, salt) {
  return goalCommitOf(goal, salt) === commit;
}
function plain(v) {
  return JSON.parse(JSON.stringify(v));
}
function mintGrant(args) {
  if (typeof args.goal !== "string" || args.goal.length === 0) throw new Error("mintGrant: goal required");
  const bad = validateRiskPolicy(args.envelope.risk_policy);
  if (bad) throw new Error(`mintGrant: ${bad}`);
  const goalSalt = args.salt ?? b64u(randomBytes(16));
  const goalCommit = goalCommitOf(args.goal, goalSalt);
  const env = plain({
    goal_commit: goalCommit,
    predicates: args.envelope.predicates,
    caveats: args.envelope.caveats,
    agent_binding: args.envelope.agent_binding ?? {},
    risk_policy: args.envelope.risk_policy,
    ...args.envelope.objective_risk !== void 0 ? { objective_risk: args.envelope.objective_risk } : {},
    ...args.envelope.progress !== void 0 ? { progress: args.envelope.progress } : {}
  });
  canonicalizeStrict(env);
  const grant = mintRoot({
    principalSecret: args.principalSecret,
    principalPublic: args.principalPublic,
    holder: args.holder,
    caveats: [{ type: ENVELOPE_CAVEAT, ...env }]
  });
  return { grant, goalCommit, goalSalt };
}
function readEnvelope(grant) {
  try {
    const cv = grant?.caveats?.find((c) => c?.type === ENVELOPE_CAVEAT);
    if (!cv) return null;
    const { type: _t, ...rest } = cv;
    const e = rest;
    if (typeof e.goal_commit !== "string") return null;
    if (!Array.isArray(e.predicates) || !Array.isArray(e.caveats)) return null;
    if (e.agent_binding === null || typeof e.agent_binding !== "object") return null;
    if (validateRiskPolicy(e.risk_policy)) return null;
    return e;
  } catch {
    return null;
  }
}

// packages/pca/src/threshold.ts
var VALID_THRESHOLDS = [1, 2, 3];
var isValidT = (t) => t === 1 || t === 2 || t === 3;
var SIGNER_SET_DOMAIN = "atlas-pca/signerset/v1\0";
function signerSetHash(signerSet) {
  const rows = (Array.isArray(signerSet) ? signerSet : []).map((s) => ({ publicKey: String(s?.publicKey), role: String(s?.role) })).sort((a, b) => compareUtf8(a.role, b.role) || compareUtf8(a.publicKey, b.publicKey));
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
function shareMessage(role, message, signerSet, t) {
  if (!isValidT(t)) throw new RangeError("shareMessage: t must be 1, 2 or 3");
  return concat(utf8(`atlas-pca/share/${role}\0`), sha2563(message), signerSetHash(signerSet), new Uint8Array([t]));
}
function signShare(role, secretKey, message, bind) {
  if (role === "agent") return { role, publicKey: b64u(publicKeyOf(secretKey)), sig: b64u(sign(secretKey, message)) };
  if (!bind) throw new TypeError(`signShare: a '${role}' share must bind {signerSet, t}`);
  return signPreparedShare(role, secretKey, shareMessage(role, message, bind.signerSet, bind.t));
}
function signPreparedShare(role, secretKey, preparedShareMessage) {
  return { role, publicKey: b64u(publicKeyOf(secretKey)), sig: b64u(sign(secretKey, preparedShareMessage)) };
}
function assembleThreshold(shares) {
  return { shares: Array.isArray(shares) ? [...shares] : [] };
}
var ROLES = ["agent", "guardian", "principal"];
function verifyThreshold(sig, message, signerSet, t) {
  const fail2 = (reason2) => ({ ok: false, count: 0, roles: [], reason: reason2 });
  if (!isValidT(t)) return fail2(`invalid threshold t=${String(t)} (must be 1, 2 or 3)`);
  const keyOfRole = /* @__PURE__ */ new Map();
  const roleOfKey = /* @__PURE__ */ new Map();
  for (const s of Array.isArray(signerSet) ? signerSet : []) {
    if (!s || !ROLES.includes(s.role) || decodeB64uStrict(s.publicKey, 32) === null) return fail2("malformed signer set");
    const prevKey = keyOfRole.get(s.role);
    if (prevKey !== void 0 && prevKey !== s.publicKey) return fail2(`signer set registers more than one key for role ${s.role}`);
    const prevRole = roleOfKey.get(s.publicKey);
    if (prevRole !== void 0 && prevRole !== s.role) return fail2("signer set registers one key under two roles");
    keyOfRole.set(s.role, s.publicKey);
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
    const signed = share.role === "agent" ? message : shareMessage(share.role, message, signerSet, t);
    if (typeof share.sig !== "string" || !verifyB64u(share.publicKey, signed, share.sig)) {
      reason ??= `invalid signature for role ${share.role}`;
      continue;
    }
    validKeys.add(share.publicKey);
    validRoles.push(share.role);
  }
  const count = validKeys.size;
  const ok = count >= t;
  if (ok) return { ok, count, roles: validRoles };
  return { ok, count, roles: validRoles, reason: reason ?? `only ${count} distinct valid key(s), need ${t}` };
}
function riskDerivedT(ctx) {
  const env = readEnvelope(ctx.grant);
  if (!env) return 1;
  const r = ctx.pcactn?.risk_claim?.r;
  return requiredThreshold(typeof r === "number" ? r : 1, env.risk_policy).t;
}
function createThresholdVerifier(opts) {
  const resolveT = opts.requiredT ?? (opts.t !== void 0 ? () => opts.t : riskDerivedT);
  return (ctx) => {
    const p = ctx.pcactn;
    const message = thresholdMessage(p);
    const shares = [];
    const chain2 = p.cap_chain;
    const leaf = Array.isArray(chain2) ? chain2[chain2.length - 1] : void 0;
    if (leaf && typeof leaf.holder === "string" && typeof p.sig === "string") {
      shares.push({ role: "agent", publicKey: leaf.holder, sig: p.sig });
    }
    if (p.threshold && Array.isArray(p.threshold.shares)) shares.push(...p.threshold.shares);
    const t = resolveT(ctx);
    const verdict = verifyThreshold({ shares }, message, opts.signerSet, t);
    return verdict.ok ? { enforced: true, ok: true } : { enforced: true, ok: false, reason: verdict.reason ?? "threshold not met" };
  };
}

// node_modules/.pnpm/@noble+hashes@1.8.0/node_modules/@noble/hashes/esm/sha512.js
var sha5122 = sha512;
var sha3842 = sha384;

// packages/pca/src/frost.ts
var P = ed25519.ExtendedPoint;
var L = ed25519.CURVE.n;
var CONTEXT_STRING = "FROST-ED25519-SHA512-v1";
var CTX = utf8(CONTEXT_STRING);
function mod2(a) {
  const r = a % L;
  return r >= 0n ? r : r + L;
}
function scalarToBytes(s) {
  let v = mod2(s);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}
function bytesToScalar(b) {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = x << 8n | BigInt(b[i]);
  return mod2(x);
}
function concat2(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
}
function hashToScalar(msg3) {
  return mod2(bytesToScalar(sha5122(msg3)));
}
function mulBase(s) {
  const v = mod2(s);
  return v === 0n ? P.ZERO : P.BASE.multiply(v);
}
function mulPoint(pt, s) {
  const v = mod2(s);
  return v === 0n ? P.ZERO : pt.multiply(v);
}
function decodeSafePoint(b) {
  if (!(b instanceof Uint8Array) || b.length !== 32) throw new Error("frost: point must be 32 bytes");
  const pt = P.fromHex(b);
  pt.assertValidity();
  if (pt.isSmallOrder()) throw new Error("frost: small-order point rejected");
  if (!pt.isTorsionFree()) throw new Error("frost: point is not in the prime-order subgroup");
  const re = pt.toRawBytes();
  for (let i = 0; i < 32; i++) if (re[i] !== b[i]) throw new Error("frost: non-canonical point encoding");
  return pt;
}
var decodePoint = decodeSafePoint;
function assertValidId(id) {
  if (typeof id !== "number" || !Number.isSafeInteger(id) || id <= 0) {
    throw new Error("frost: participant identifier must be a positive safe integer");
  }
}
function validateCommitments(list, threshold) {
  if (!Array.isArray(list) || list.length === 0) throw new Error("frost: empty commitment list");
  if (threshold !== void 0) {
    if (!Number.isSafeInteger(threshold) || threshold < 1) throw new Error("frost: invalid threshold");
    if (list.length < threshold) throw new Error(`frost: need at least t=${threshold} commitments (got ${list.length})`);
  }
  const seen = /* @__PURE__ */ new Set();
  for (const c of list) {
    if (!c || typeof c !== "object") throw new Error("frost: malformed commitment");
    assertValidId(c.identifier);
    if (seen.has(c.identifier)) throw new Error(`frost: duplicate commitment identifier ${c.identifier}`);
    seen.add(c.identifier);
    decodeSafePoint(c.hiding);
    decodeSafePoint(c.binding);
  }
}
function H1(m) {
  return hashToScalar(concat2(CTX, utf8("rho"), m));
}
function H2(m) {
  return hashToScalar(m);
}
function H3(m) {
  return hashToScalar(concat2(CTX, utf8("nonce"), m));
}
function H4(m) {
  return sha5122(concat2(CTX, utf8("msg"), m));
}
function H5(m) {
  return sha5122(concat2(CTX, utf8("com"), m));
}
function frostTrustedDealerKeygen(t, n, opts = {}) {
  if (!Number.isInteger(t) || !Number.isInteger(n) || t < 1 || n < t) {
    throw new Error(`frostTrustedDealerKeygen: need 1 <= t <= n (got t=${t}, n=${n})`);
  }
  const ids = opts.identifiers ?? Array.from({ length: n }, (_, i) => i + 1);
  if (ids.length !== n) throw new Error("frostTrustedDealerKeygen: identifiers.length must equal n");
  if (new Set(ids).size !== n) throw new Error("frostTrustedDealerKeygen: identifiers must be distinct");
  if (ids.some((x) => !Number.isInteger(x) || x <= 0)) {
    throw new Error("frostTrustedDealerKeygen: identifiers must be positive integers");
  }
  const secret = opts.secret ? bytesToScalar(opts.secret) : bytesToScalar(ed25519.utils.randomPrivateKey());
  const coeffs = [secret];
  for (let i = 1; i < t; i++) {
    const c = opts.coefficients?.[i - 1];
    coeffs.push(c ? bytesToScalar(c) : bytesToScalar(ed25519.utils.randomPrivateKey()));
  }
  const evalPoly2 = (x) => {
    let acc = 0n;
    for (let j = coeffs.length - 1; j >= 0; j--) acc = mod2(acc * x + coeffs[j]);
    return acc;
  };
  const participantShares = ids.map((id) => {
    const s = evalPoly2(BigInt(id));
    return { identifier: id, share: scalarToBytes(s), publicKey: mulBase(s).toRawBytes() };
  });
  const groupCommitment = coeffs.map((a) => mulBase(a).toRawBytes());
  return { groupPublicKey: groupCommitment[0], participantShares, groupCommitment };
}
function nonceGenerate(randomness, secretShare) {
  if (randomness.length !== 32) throw new Error("frostCommit: nonce randomness must be 32 bytes");
  return H3(concat2(randomness, scalarToBytes(bytesToScalar(secretShare))));
}
function frostCommit(participantShare, opts = {}) {
  const hr = opts.hidingRandomness ?? ed25519.utils.randomPrivateKey();
  const br = opts.bindingRandomness ?? ed25519.utils.randomPrivateKey();
  const hidingNonce = nonceGenerate(hr, participantShare.share);
  const bindingNonce = nonceGenerate(br, participantShare.share);
  return {
    hidingNonce: scalarToBytes(hidingNonce),
    bindingNonce: scalarToBytes(bindingNonce),
    commitment: {
      identifier: participantShare.identifier,
      hiding: mulBase(hidingNonce).toRawBytes(),
      binding: mulBase(bindingNonce).toRawBytes()
    }
  };
}
function sortCommitments(list) {
  return [...list].sort((a, b) => a.identifier - b.identifier);
}
function encodeCommitmentList(list) {
  const parts = [];
  for (const c of list) {
    parts.push(scalarToBytes(BigInt(c.identifier)), c.hiding, c.binding);
  }
  return concat2(...parts);
}
function computeBindingFactors(groupPublicKey, list, msg3) {
  const msgHash = H4(msg3);
  const encHash = H5(encodeCommitmentList(list));
  const prefix = concat2(groupPublicKey, msgHash, encHash);
  const out = /* @__PURE__ */ new Map();
  for (const c of list) {
    out.set(c.identifier, H1(concat2(prefix, scalarToBytes(BigInt(c.identifier)))));
  }
  return out;
}
function computeGroupCommitment(list, bindingFactors) {
  let R = P.ZERO;
  for (const c of list) {
    const bf = bindingFactors.get(c.identifier);
    R = R.add(decodePoint(c.hiding)).add(mulPoint(decodePoint(c.binding), bf));
  }
  return R;
}
function computeChallenge(R, groupPublicKey, msg3) {
  return H2(concat2(R, groupPublicKey, msg3));
}
function deriveInterpolatingValue(participants, i) {
  if (!participants.includes(i)) throw new Error("frost: identifier not in participant list");
  let num = 1n;
  let den = 1n;
  const xi = BigInt(i);
  for (const j of participants) {
    if (j === i) continue;
    const xj = BigInt(j);
    num = mod2(num * xj);
    den = mod2(den * (xj - xi));
  }
  const lam = mod2(num * modInverse(den));
  if (lam === 0n) throw new Error("frost: zero Lagrange coefficient");
  return lam;
}
function modInverse(a) {
  const v = mod2(a);
  if (v === 0n) throw new Error("frost: modular inverse of zero");
  return modPow(v, L - 2n);
}
function modPow(base, exp) {
  let b = mod2(base);
  let e = exp;
  let r = 1n;
  while (e > 0n) {
    if (e & 1n) r = mod2(r * b);
    b = mod2(b * b);
    e >>= 1n;
  }
  return r;
}
var SPENT_NONCES = /* @__PURE__ */ new WeakSet();
function isZero(b) {
  let acc = 0;
  for (const x of b) acc |= x;
  return acc === 0;
}
function frostSign(identifier, share, groupPublicKey, nonces, message, signingCommitments, opts = {}) {
  assertValidId(identifier);
  validateCommitments(signingCommitments, opts.threshold);
  decodeSafePoint(groupPublicKey);
  if (!nonces || !(nonces.hiding instanceof Uint8Array) || !(nonces.binding instanceof Uint8Array)) {
    throw new Error("frostSign: malformed nonces");
  }
  if (SPENT_NONCES.has(nonces.hiding) || SPENT_NONCES.has(nonces.binding)) {
    throw new Error("frostSign: nonces already used (one-shot; reuse would leak the signing share)");
  }
  if (isZero(nonces.hiding) || isZero(nonces.binding)) throw new Error("frostSign: zero/zeroized nonce");
  if (nonces.hiding === nonces.binding) throw new Error("frostSign: hiding and binding nonce must differ");
  const list = sortCommitments(signingCommitments);
  const mine = list.find((c2) => c2.identifier === identifier);
  if (!mine) throw new Error("frostSign: this identifier has no commitment in the set");
  const hiding = bytesToScalar(nonces.hiding);
  const binding = bytesToScalar(nonces.binding);
  const sk = bytesToScalar(share);
  if (!mulBase(hiding).equals(decodePoint(mine.hiding)) || !mulBase(binding).equals(decodePoint(mine.binding))) {
    throw new Error("frostSign: own commitment does not match nonces");
  }
  if (opts.verificationShare !== void 0) {
    if (!mulBase(sk).equals(decodePoint(opts.verificationShare))) {
      throw new Error("frostSign: share does not match verification share");
    }
  }
  const participants = list.map((c2) => c2.identifier);
  if (opts.verificationShares !== void 0) {
    let acc = P.ZERO;
    for (const id of participants) {
      const vs = opts.verificationShares.find((v) => v.identifier === id);
      if (!vs) throw new Error(`frostSign: missing verification share for ${id}`);
      acc = acc.add(mulPoint(decodePoint(vs.publicKey), deriveInterpolatingValue(participants, id)));
    }
    if (!acc.equals(decodePoint(groupPublicKey))) {
      throw new Error("frostSign: group public key does not match the verification shares");
    }
  }
  const bindingFactors = computeBindingFactors(groupPublicKey, list, message);
  const bf = bindingFactors.get(identifier);
  const R = computeGroupCommitment(list, bindingFactors);
  const lambda = deriveInterpolatingValue(participants, identifier);
  const c = computeChallenge(R.toRawBytes(), groupPublicKey, message);
  const z = mod2(hiding + mod2(binding * bf) + mod2(mod2(lambda * sk) * c));
  SPENT_NONCES.add(nonces.hiding);
  SPENT_NONCES.add(nonces.binding);
  nonces.hiding.fill(0);
  nonces.binding.fill(0);
  return { identifier, sigShare: scalarToBytes(z) };
}
function frostAggregate(message, signingCommitments, sigShares, groupPublicKey, opts = {}) {
  validateCommitments(signingCommitments, opts.threshold);
  decodeSafePoint(groupPublicKey);
  const list = sortCommitments(signingCommitments);
  if (!Array.isArray(sigShares) || sigShares.length !== list.length) {
    throw new Error("frostAggregate: need exactly one signature share per commitment");
  }
  const shareIds = /* @__PURE__ */ new Set();
  for (const s of sigShares) {
    if (!list.some((c) => c.identifier === s.identifier)) throw new Error("frostAggregate: share from non-signer");
    if (shareIds.has(s.identifier)) throw new Error("frostAggregate: duplicate signature share");
    shareIds.add(s.identifier);
  }
  if (opts.verificationShares) {
    for (const s of sigShares) {
      const vs = opts.verificationShares.find((v) => v.identifier === s.identifier);
      const commitment = list.find((c) => c.identifier === s.identifier);
      if (!vs || !frostVerifySigShare({
        identifier: s.identifier,
        publicKey: vs.publicKey,
        commitment,
        sigShare: s,
        signingCommitments: list,
        groupPublicKey,
        message
      })) {
        throw new Error(`frostAggregate: invalid signature share from participant ${s.identifier}`);
      }
    }
  }
  const bindingFactors = computeBindingFactors(groupPublicKey, list, message);
  const R = computeGroupCommitment(list, bindingFactors);
  let z = 0n;
  for (const s of sigShares) z = mod2(z + bytesToScalar(s.sigShare));
  const sig = concat2(R.toRawBytes(), scalarToBytes(z));
  if (!ed25519.verify(sig, message, groupPublicKey, { zip215: false })) {
    throw new Error("frostAggregate: aggregate signature does not verify (a share is invalid)");
  }
  return sig;
}
function frostVerifySigShare(params) {
  try {
    validateCommitments(params.signingCommitments);
    const list = sortCommitments(params.signingCommitments);
    const bindingFactors = computeBindingFactors(params.groupPublicKey, list, params.message);
    const bf = bindingFactors.get(params.identifier);
    if (bf === void 0) return false;
    const R = computeGroupCommitment(list, bindingFactors);
    const commShare = decodePoint(params.commitment.hiding).add(mulPoint(decodePoint(params.commitment.binding), bf));
    const c = computeChallenge(R.toRawBytes(), params.groupPublicKey, params.message);
    const participants = list.map((x) => x.identifier);
    const lambda = deriveInterpolatingValue(participants, params.identifier);
    const lhs = mulBase(bytesToScalar(params.sigShare.sigShare));
    const rhs = commShare.add(mulPoint(decodePoint(params.publicKey), mod2(c * lambda)));
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}

// packages/pca/src/frost-dkg.ts
var P2 = ed25519.ExtendedPoint;
function mod3(a) {
  const r = a % L;
  return r >= 0n ? r : r + L;
}
function concat3(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
}
function hashToScalar2(msg3) {
  return bytesToScalar(sha5122(msg3));
}
function mulBase2(s) {
  const v = mod3(s);
  return v === 0n ? P2.ZERO : P2.BASE.multiply(v);
}
function mulPoint2(pt, s) {
  const v = mod3(s);
  return v === 0n ? P2.ZERO : pt.multiply(v);
}
var decodePoint2 = decodeSafePoint;
function commitVecOf(commitments) {
  if (!Array.isArray(commitments) || commitments.length === 0) throw new Error("dkg: empty commitment vector");
  const pts = commitments.map((c) => decodePoint2(unb64u(c)));
  const hdr = new Uint8Array(4);
  new DataView(hdr.buffer).setUint32(0, pts.length, false);
  return { c0: pts[0], bytes: concat3(hdr, ...pts.map((p) => p.toRawBytes())) };
}
function randomScalar() {
  return bytesToScalar(ed25519.utils.randomPrivateKey());
}
function evalPoly(coeffs, x) {
  let acc = 0n;
  for (let j = coeffs.length - 1; j >= 0; j--) acc = mod3(acc * x + coeffs[j]);
  return acc;
}
function vssCheck(share, commitments, atId) {
  if (commitments.length === 0) return false;
  const lhs = mulBase2(share);
  let rhs = P2.ZERO;
  const x = BigInt(atId);
  let xk = 1n;
  for (const cB of commitments) {
    rhs = rhs.add(mulPoint2(decodePoint2(unb64u(cB)), xk));
    xk = mod3(xk * x);
  }
  return lhs.equals(rhs);
}
var DKG_POP_DST = utf8("dkg-pop");
var CTX2 = utf8(CONTEXT_STRING);
function dkgPopChallenge(sessionId, identifier, cv, R) {
  return hashToScalar2(
    concat3(
      CTX2,
      DKG_POP_DST,
      sessionId,
      scalarToBytes(BigInt(identifier)),
      cv.bytes,
      R.toRawBytes()
    )
  );
}
var DKG_SHARE_DST = utf8("dkg-share");
var DKG_SHARE_NONCE_DST = utf8("dkg-share-nonce");
function dkgShareChallenge(sessionId, from, to, shareBytes, cv, Rs) {
  return hashToScalar2(
    concat3(
      CTX2,
      DKG_SHARE_DST,
      sessionId,
      scalarToBytes(BigInt(from)),
      scalarToBytes(BigInt(to)),
      shareBytes,
      cv.bytes,
      Rs.toRawBytes()
    )
  );
}
function dkgShareNonce(a0, sessionId, from, to, shareBytes, cv) {
  return hashToScalar2(
    concat3(
      CTX2,
      DKG_SHARE_NONCE_DST,
      scalarToBytes(a0),
      sessionId,
      scalarToBytes(BigInt(from)),
      scalarToBytes(BigInt(to)),
      shareBytes,
      cv.bytes
    )
  );
}
function signShareScalar(a0, cv, sessionId, from, to, shareBytes) {
  const k = dkgShareNonce(a0, sessionId, from, to, shareBytes, cv);
  const Rs = mulBase2(k);
  const e = dkgShareChallenge(sessionId, from, to, shareBytes, cv, Rs);
  const s = mod3(k + mod3(a0 * e));
  return b64u(concat3(Rs.toRawBytes(), scalarToBytes(s)));
}
function verifyShareSig(sig, sessionId, from, to, shareBytes, cv) {
  try {
    const raw = unb64u(sig);
    if (raw.length !== 64) return false;
    const Rs = decodePoint2(raw.subarray(0, 32));
    const s = bytesToScalar(raw.subarray(32, 64));
    const e = dkgShareChallenge(sessionId, from, to, shareBytes, cv, Rs);
    return mulBase2(s).equals(Rs.add(mulPoint2(cv.c0, e)));
  } catch {
    return false;
  }
}
function verifyShareSigAgainstPackage(sig, sessionId, from, to, shareBytes, senderPackage) {
  try {
    if (typeof sig !== "string" || senderPackage.coefficientCommitments.length === 0) return false;
    const cv = commitVecOf(senderPackage.coefficientCommitments);
    return verifyShareSig(sig, sessionId, from, to, shareBytes, cv);
  } catch {
    return false;
  }
}
function dkgSignShare(state, to, shareBytes) {
  const a0 = bytesToScalar(state.coefficients[0]);
  const cv = commitVecOf(state.package.coefficientCommitments);
  return signShareScalar(a0, cv, state.sessionId, state.identifier, to, shareBytes);
}
function dkgRound1(identifier, t, n, sessionId, opts = {}) {
  if (!Number.isInteger(identifier) || identifier <= 0) {
    throw new Error("dkgRound1: identifier must be a positive integer");
  }
  if (!Number.isInteger(t) || !Number.isInteger(n) || t < 1 || n < t) {
    throw new Error(`dkgRound1: need 1 <= t <= n (got t=${t}, n=${n})`);
  }
  if (!(sessionId instanceof Uint8Array) || sessionId.length === 0) {
    throw new Error("dkgRound1: sessionId must be a non-empty byte string");
  }
  const coeffBytes = [];
  const coeffs = [];
  if (opts.coefficients) {
    if (opts.coefficients.length !== t) {
      throw new Error(`dkgRound1: coefficients.length must equal t (${t})`);
    }
    for (const c2 of opts.coefficients) {
      const s = bytesToScalar(c2);
      coeffs.push(s);
      coeffBytes.push(scalarToBytes(s));
    }
  } else {
    for (let j = 0; j < t; j++) {
      const s = randomScalar();
      coeffs.push(s);
      coeffBytes.push(scalarToBytes(s));
    }
  }
  const commitmentPoints = coeffs.map((a) => mulBase2(a));
  const coefficientCommitments = commitmentPoints.map((pt) => b64u(pt.toRawBytes()));
  const a0 = coeffs[0];
  const cv = commitVecOf(coefficientCommitments);
  const k = opts.popNonce ? bytesToScalar(opts.popNonce) : randomScalar();
  const R = mulBase2(k);
  const c = dkgPopChallenge(sessionId, identifier, cv, R);
  const mu = mod3(k + mod3(a0 * c));
  const pkg = {
    identifier,
    sessionId: b64u(sessionId),
    coefficientCommitments,
    proofOfKnowledge: { R: b64u(R.toRawBytes()), mu: b64u(scalarToBytes(mu)) }
  };
  return {
    package: pkg,
    state: { identifier, t, n, sessionId: Uint8Array.from(sessionId), coefficients: coeffBytes, package: pkg }
  };
}
function dkgVerifyRound1(fromIdentifier, pkg, sessionId) {
  try {
    if (pkg.sessionId !== b64u(sessionId)) return false;
    if (pkg.coefficientCommitments.length === 0) return false;
    const cv = commitVecOf(pkg.coefficientCommitments);
    const commit0 = cv.c0;
    const R = decodePoint2(unb64u(pkg.proofOfKnowledge.R));
    const mu = bytesToScalar(unb64u(pkg.proofOfKnowledge.mu));
    const c = dkgPopChallenge(sessionId, fromIdentifier, cv, R);
    const lhs = mulBase2(mu);
    const rhs = R.add(mulPoint2(commit0, c));
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}
function dkgRound2(state, allRound1Packages) {
  const ids = allRound1Packages.map((p) => p.identifier);
  if (new Set(ids).size !== ids.length) throw new Error("dkgRound2: duplicate identifiers in round-1 packages");
  if (!ids.includes(state.identifier)) throw new Error("dkgRound2: my own round-1 package is missing");
  const sidB64 = b64u(state.sessionId);
  for (const p of allRound1Packages) {
    if (p.sessionId !== sidB64) {
      throw new Error(`dkgRound2: participant ${p.identifier} round-1 package is from a different session`);
    }
  }
  const coeffs = state.coefficients.map((c) => bytesToScalar(c));
  const a0 = coeffs[0];
  const cv = commitVecOf(state.package.coefficientCommitments);
  const out = [];
  for (const j of ids) {
    if (j === state.identifier) continue;
    const share = scalarToBytes(evalPoly(coeffs, BigInt(j)));
    const sig = signShareScalar(a0, cv, state.sessionId, state.identifier, j, share);
    out.push({ from: state.identifier, to: j, sessionId: sidB64, share, sig });
  }
  return out;
}
function dkgVerifyShare(received, senderPackage, myIdentifier, sessionId) {
  try {
    if (!received || !(received.share instanceof Uint8Array)) return false;
    if (!dkgVerifyRound1(senderPackage.identifier, senderPackage, sessionId)) return false;
    if (!verifyShareSigAgainstPackage(received.sig, sessionId, received.from, myIdentifier, received.share, senderPackage)) {
      return false;
    }
    return vssCheck(bytesToScalar(received.share), senderPackage.coefficientCommitments, myIdentifier);
  } catch {
    return false;
  }
}
function dkgFileComplaint(params) {
  const { accused, accuser, receivedShare, shareSig, sessionId } = params;
  void params.senderCommitments;
  if (!Number.isInteger(accused) || accused <= 0) throw new Error("dkgFileComplaint: accused must be a positive integer");
  if (!Number.isInteger(accuser) || accuser <= 0) throw new Error("dkgFileComplaint: accuser must be a positive integer");
  if (accused === accuser) throw new Error("dkgFileComplaint: cannot file a complaint against yourself");
  if (typeof shareSig !== "string" || shareSig.length === 0) {
    throw new Error("dkgFileComplaint: shareSig (the accused-signed share) is required");
  }
  if (!(sessionId instanceof Uint8Array) || sessionId.length === 0) {
    throw new Error("dkgFileComplaint: sessionId must be a non-empty byte string");
  }
  return {
    accused,
    accuser,
    sessionId: b64u(sessionId),
    revealedShare: b64u(scalarToBytes(bytesToScalar(receivedShare))),
    shareSig
  };
}
function dkgVerifyComplaint(complaint, round1Packages) {
  try {
    const accusedPkg = round1Packages.find((p) => p.identifier === complaint.accused);
    if (!accusedPkg) {
      return { justified: false, reason: `accused ${complaint.accused} has no round-1 package to adjudicate against` };
    }
    if (accusedPkg.sessionId !== complaint.sessionId) {
      return { justified: false, reason: "complaint sessionId does not match the accused round-1 package session" };
    }
    const sidBytes = unb64u(complaint.sessionId);
    const shareBytes = unb64u(complaint.revealedShare);
    if (!verifyShareSigAgainstPackage(complaint.shareSig, sidBytes, complaint.accused, complaint.accuser, shareBytes, accusedPkg)) {
      return {
        justified: false,
        atFault: complaint.accuser,
        reason: "revealed share is not validly signed by the accused \u2014 inadmissible (cannot frame an honest party)"
      };
    }
    const valid = vssCheck(bytesToScalar(shareBytes), accusedPkg.coefficientCommitments, complaint.accuser);
    if (valid) {
      return {
        justified: false,
        atFault: complaint.accuser,
        reason: "accused-signed share is VALID against the accused commitments \u2014 false accusation"
      };
    }
    return {
      justified: true,
      disqualify: complaint.accused,
      reason: "accused non-repudiably signed a share that FAILS VSS against its broadcast commitments"
    };
  } catch {
    return { justified: false, reason: "malformed complaint" };
  }
}
function dkgRebut(accused, complaint, myRound2State) {
  if (myRound2State.identifier !== accused) throw new Error("dkgRebut: myRound2State is not the accused");
  if (complaint.accused !== accused) throw new Error("dkgRebut: complaint does not name this accused");
  if (b64u(myRound2State.sessionId) !== complaint.sessionId) {
    throw new Error("dkgRebut: complaint is scoped to a different session than my state");
  }
  const coeffs = myRound2State.coefficients.map((c) => bytesToScalar(c));
  const share = scalarToBytes(evalPoly(coeffs, BigInt(complaint.accuser)));
  const shareSig = dkgSignShare(myRound2State, complaint.accuser, share);
  return {
    accused,
    accuser: complaint.accuser,
    sessionId: complaint.sessionId,
    presentedShare: b64u(share),
    shareSig
  };
}
function dkgResolveBlame(complaint, rebuttal, round1Packages) {
  try {
    const accusedPkg = round1Packages.find((p) => p.identifier === complaint.accused);
    if (!accusedPkg) {
      return { guilty: complaint.accused, reason: `accused ${complaint.accused} has no round-1 package to defend with` };
    }
    if (accusedPkg.sessionId !== complaint.sessionId) {
      return { guilty: complaint.accuser, reason: "complaint names a session the accused did not run \u2014 inadmissible" };
    }
    const sidBytes = unb64u(complaint.sessionId);
    const shareBytes = unb64u(complaint.revealedShare);
    const admissible = verifyShareSigAgainstPackage(
      complaint.shareSig,
      sidBytes,
      complaint.accused,
      complaint.accuser,
      shareBytes,
      accusedPkg
    );
    if (admissible) {
      const valid = vssCheck(bytesToScalar(shareBytes), accusedPkg.coefficientCommitments, complaint.accuser);
      if (!valid) {
        return { guilty: complaint.accused, reason: "accused non-repudiably signed a share that fails VSS" };
      }
      return { guilty: complaint.accuser, reason: "accused-signed share is valid against its commitments \u2014 false accusation" };
    }
    if (rebuttal && rebuttal.accused === complaint.accused && rebuttal.accuser === complaint.accuser && rebuttal.sessionId === complaint.sessionId) {
      const rShare = unb64u(rebuttal.presentedShare);
      const rebuttalValid = verifyShareSigAgainstPackage(rebuttal.shareSig, sidBytes, complaint.accused, complaint.accuser, rShare, accusedPkg) && vssCheck(bytesToScalar(rShare), accusedPkg.coefficientCommitments, complaint.accuser);
      if (rebuttalValid) {
        return {
          guilty: complaint.accuser,
          reason: "accused produced a validly-signed, VSS-correct share for the recipient \u2014 the non-receipt/fabrication complaint is refuted"
        };
      }
      return {
        guilty: complaint.accused,
        reason: "accused could not present a validly-signed, VSS-correct share on rebuttal"
      };
    }
    return {
      guilty: complaint.accuser,
      reason: "complaint carries no accused-signed share and the accused offered no rebuttal \u2014 inadmissible, cannot frame the accused"
    };
  } catch {
    return { guilty: complaint.accuser, reason: "malformed complaint \u2014 inadmissible" };
  }
}
function dkgQualifiedSet(participants, complaints, round1Packages, rebuttals = []) {
  const pkgById = new Map(round1Packages.map((p) => [p.identifier, p]));
  const sessionCounts = /* @__PURE__ */ new Map();
  for (const p of round1Packages) sessionCounts.set(p.sessionId, (sessionCounts.get(p.sessionId) ?? 0) + 1);
  let runSession = "";
  let best = -1;
  for (const [s, c] of sessionCounts) {
    if (c > best) {
      best = c;
      runSession = s;
    }
  }
  const qualified = /* @__PURE__ */ new Set();
  for (const p of participants) {
    const pkg = pkgById.get(p);
    if (!pkg) continue;
    if (pkg.sessionId !== runSession) continue;
    let sid;
    try {
      sid = unb64u(pkg.sessionId);
    } catch {
      continue;
    }
    if (dkgVerifyRound1(p, pkg, sid)) qualified.add(p);
  }
  for (const c of complaints) {
    const reb = rebuttals.find((r) => r.accused === c.accused && r.accuser === c.accuser && r.sessionId === c.sessionId);
    const res = dkgResolveBlame(c, reb, round1Packages);
    if (res.guilty === c.accused) qualified.delete(res.guilty);
  }
  return [...qualified].sort((a, b) => a - b);
}
function dkgFinalize(myIdentifier, myState, receivedShares, allCommitments, qualified) {
  if (myState.identifier !== myIdentifier) throw new Error("dkgFinalize: myState.identifier != myIdentifier");
  const ids = allCommitments.map((p) => p.identifier);
  if (new Set(ids).size !== ids.length) throw new Error("dkgFinalize: duplicate identifiers in commitments");
  if (!ids.includes(myIdentifier)) throw new Error("dkgFinalize: my own package is missing from allCommitments");
  const sidB64 = b64u(myState.sessionId);
  for (const p of allCommitments) {
    if (p.sessionId !== sidB64) {
      throw new Error(`dkgFinalize: participant ${p.identifier} round-1 package is from a different session`);
    }
  }
  const qset = (qualified ?? ids).filter((id) => ids.includes(id));
  const qSet = new Set(qset);
  if (!qSet.has(myIdentifier)) throw new Error("dkgFinalize: myIdentifier is not in the qualified set");
  if (qSet.size < myState.t) {
    throw new Error(`dkgFinalize: qualified set (${qSet.size}) is smaller than the threshold t=${myState.t}`);
  }
  const t = myState.t;
  for (const p of allCommitments) {
    if (!qSet.has(p.identifier)) continue;
    if (p.coefficientCommitments.length !== t) {
      throw new Error(
        `dkgFinalize: participant ${p.identifier} committed to ${p.coefficientCommitments.length} coefficients, expected t=${t}`
      );
    }
  }
  const recvBy = /* @__PURE__ */ new Map();
  for (const r of receivedShares) {
    if (r.from === myIdentifier) continue;
    if (!qSet.has(r.from)) continue;
    if (r.sessionId !== sidB64) {
      throw new Error(`dkgFinalize: received share from ${r.from} is from a different session`);
    }
    if (recvBy.has(r.from)) throw new Error(`dkgFinalize: duplicate received share from ${r.from}`);
    recvBy.set(r.from, r.share);
  }
  for (const j of qset) {
    if (j === myIdentifier) continue;
    if (!recvBy.has(j)) throw new Error(`dkgFinalize: missing received share from qualified participant ${j}`);
  }
  const myCoeffs = myState.coefficients.map((c) => bytesToScalar(c));
  let s = evalPoly(myCoeffs, BigInt(myIdentifier));
  for (const [, share] of recvBy) s = mod3(s + bytesToScalar(share));
  const signingShare = scalarToBytes(s);
  const groupCoeffPoints = [];
  for (let kIdx = 0; kIdx < t; kIdx++) {
    let acc = P2.ZERO;
    for (const p of allCommitments) {
      if (!qSet.has(p.identifier)) continue;
      acc = acc.add(decodePoint2(unb64u(p.coefficientCommitments[kIdx])));
    }
    groupCoeffPoints.push(acc);
  }
  const groupPublicKey = groupCoeffPoints[0].toRawBytes();
  const groupCommitment = groupCoeffPoints.map((pt) => pt.toRawBytes());
  const verifyingShares = qset.map((j) => {
    let acc = P2.ZERO;
    const x = BigInt(j);
    let xk = 1n;
    for (const phi of groupCoeffPoints) {
      acc = acc.add(mulPoint2(phi, xk));
      xk = mod3(xk * x);
    }
    return { identifier: j, publicKey: acc.toRawBytes() };
  });
  const verifyingShare = mulBase2(s).toRawBytes();
  const mine = verifyingShares.find((v) => v.identifier === myIdentifier);
  if (!mine || !mulBase2(s).equals(decodePoint2(mine.publicKey))) {
    throw new Error("dkgFinalize: signing share is inconsistent with the group verifying share (bad dealer share)");
  }
  return {
    identifier: myIdentifier,
    signingShare,
    groupPublicKey,
    verifyingShare,
    publicKeyPackage: { groupPublicKey, groupCommitment, verifyingShares }
  };
}
function frostDkgSimulate(t, n, opts = {}) {
  if (!Number.isInteger(t) || !Number.isInteger(n) || t < 1 || n < t) {
    throw new Error(`frostDkgSimulate: need 1 <= t <= n (got t=${t}, n=${n})`);
  }
  const ids = opts.identifiers ?? Array.from({ length: n }, (_, i) => i + 1);
  if (ids.length !== n) throw new Error("frostDkgSimulate: identifiers.length must equal n");
  if (new Set(ids).size !== n) throw new Error("frostDkgSimulate: identifiers must be distinct");
  if (ids.some((x) => !Number.isInteger(x) || x <= 0)) {
    throw new Error("frostDkgSimulate: identifiers must be positive integers");
  }
  const sessionId = opts.sessionId ?? ed25519.utils.randomPrivateKey();
  const cheaters = new Set(opts.cheaters ?? []);
  const states = ids.map(
    (id, idx) => dkgRound1(id, t, n, sessionId, { coefficients: opts.coefficientsByParticipant?.[idx] }).state
  );
  const round1Packages = states.map((st) => st.package);
  for (const pkg of round1Packages) {
    if (!dkgVerifyRound1(pkg.identifier, pkg, sessionId)) {
      throw new Error(`frostDkgSimulate: PoP verification failed for participant ${pkg.identifier}`);
    }
  }
  const inbox = new Map(ids.map((id) => [id, []]));
  const complaints = [];
  const stateById = new Map(states.map((st) => [st.identifier, st]));
  for (const st of states) {
    for (const outgoing of dkgRound2(st, round1Packages)) {
      let shareBytes = outgoing.share;
      let shareSig = outgoing.sig;
      if (cheaters.has(outgoing.from)) {
        const bad = Uint8Array.from(outgoing.share);
        bad[0] = bad[0] ^ 1;
        shareBytes = bad;
        shareSig = dkgSignShare(st, outgoing.to, bad);
      }
      const senderPkg = round1Packages.find((p) => p.identifier === outgoing.from);
      if (dkgVerifyShare({ from: outgoing.from, share: shareBytes, sig: shareSig }, senderPkg, outgoing.to, sessionId)) {
        inbox.get(outgoing.to).push({ from: outgoing.from, sessionId: outgoing.sessionId, share: shareBytes, sig: shareSig });
      } else {
        complaints.push(
          dkgFileComplaint({
            accused: outgoing.from,
            accuser: outgoing.to,
            receivedShare: shareBytes,
            shareSig,
            senderCommitments: senderPkg.coefficientCommitments,
            sessionId
          })
        );
      }
    }
  }
  const rebuttals = complaints.map((c) => dkgRebut(c.accused, c, stateById.get(c.accused)));
  const qualified = dkgQualifiedSet(ids, complaints, round1Packages, rebuttals);
  if (qualified.length < t) {
    throw new Error(`frostDkgSimulate: only ${qualified.length} qualified participants (< t=${t}) after the blame round`);
  }
  const qualifiedStates = states.filter((st) => qualified.includes(st.identifier));
  const keyPackages = qualifiedStates.map(
    (st) => dkgFinalize(st.identifier, st, inbox.get(st.identifier), round1Packages, qualified)
  );
  const groupPublicKey = keyPackages[0].groupPublicKey;
  const gpkHex = b64u(groupPublicKey);
  for (const kp of keyPackages) {
    if (b64u(kp.groupPublicKey) !== gpkHex) {
      throw new Error("frostDkgSimulate: participants disagree on the group public key");
    }
  }
  const participantShares = keyPackages.map((kp) => ({
    identifier: kp.identifier,
    share: kp.signingShare,
    publicKey: kp.verifyingShare
  }));
  return {
    groupPublicKey,
    participantShares,
    groupCommitment: keyPackages[0].publicKeyPackage.groupCommitment,
    keyPackages,
    round1Packages,
    qualified,
    complaints,
    rebuttals,
    sessionId
  };
}

// packages/pca/src/predicates.ts
var ROOTS = /* @__PURE__ */ new Set(["action", "subject", "env"]);
var FORBIDDEN = /* @__PURE__ */ new Set(["__proto__", "constructor", "prototype"]);
var has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
function resolvePath(ctx, path) {
  if (typeof path !== "string" || path.length === 0) return { found: false };
  const segs = path.split(".");
  if (!ROOTS.has(segs[0])) return { found: false };
  let cur = ctx?.[segs[0]];
  if (cur === void 0) return { found: false };
  for (let i = 1; i < segs.length; i++) {
    const s = segs[i];
    if (FORBIDDEN.has(s) || cur === null || typeof cur !== "object") return { found: false };
    if (Array.isArray(cur)) {
      if (!/^(0|[1-9]\d*)$/.test(s)) return { found: false };
      const idx = Number(s);
      if (idx >= cur.length) return { found: false };
      cur = cur[idx];
    } else {
      if (!has(cur, s)) return { found: false };
      cur = cur[s];
    }
    if (cur === void 0) return { found: false };
  }
  return { found: true, value: cur };
}
function deepEq(a, b) {
  try {
    return canonicalize(a) === canonicalize(b);
  } catch {
    return false;
  }
}
function ordered(a, b) {
  if (typeof a === "number" && typeof b === "number" && Number.isFinite(a) && Number.isFinite(b)) {
    return a < b ? -1 : a > b ? 1 : 0;
  }
  if (typeof a === "string" && typeof b === "string") return a < b ? -1 : a > b ? 1 : 0;
  return null;
}
function evaluateCondition(c, ctx) {
  try {
    if (c === null || typeof c !== "object") return false;
    if (typeof c.field === "string" && (c.field === "action.params" || c.field.startsWith("action.params."))) {
      const p = ctx?.action?.params;
      if (p === void 0 || p === null || typeof p !== "object") return false;
    }
    if (typeof c.ref === "string" && (c.ref === "action.params" || c.ref.startsWith("action.params."))) {
      const p = ctx?.action?.params;
      if (p === void 0 || p === null || typeof p !== "object") return false;
    }
    const f = resolvePath(ctx, c.field);
    if (c.op === "exists") return c.value === false ? !f.found : f.found;
    if (!f.found) return false;
    let operand;
    if (c.ref !== void 0) {
      const r = resolvePath(ctx, c.ref);
      if (!r.found) return false;
      operand = r.value;
    } else {
      if (!has(c, "value") || c.value === void 0) return false;
      operand = c.value;
    }
    const v = f.value;
    switch (c.op) {
      case "eq":
        return deepEq(v, operand);
      case "ne":
        return !deepEq(v, operand);
      case "in":
        return Array.isArray(operand) && operand.some((x) => deepEq(v, x));
      case "nin":
        return Array.isArray(operand) && !operand.some((x) => deepEq(v, x));
      case "lt": {
        const o = ordered(v, operand);
        return o !== null && o < 0;
      }
      case "lte": {
        const o = ordered(v, operand);
        return o !== null && o <= 0;
      }
      case "gt": {
        const o = ordered(v, operand);
        return o !== null && o > 0;
      }
      case "gte": {
        const o = ordered(v, operand);
        return o !== null && o >= 0;
      }
      case "prefix":
        return typeof v === "string" && typeof operand === "string" && v.startsWith(operand);
      default:
        return false;
    }
  } catch {
    return false;
  }
}
function verbMatches(p, verb) {
  if (typeof p === "string") return p === "*" || p === verb;
  if (Array.isArray(p)) return p.some((x) => typeof x === "string" && (x === "*" || x === verb));
  return false;
}
var MAX_RE_RESOURCE_LEN = 512;
var MAX_UNBOUNDED_QUANTIFIERS = 3;
var MAX_BOUNDED_REPEAT = 64;
function isSafeRegexSource(src) {
  const stack = [{ hasQuant: false, hasAlt: false }];
  let prev = "none";
  let unbounded = 0;
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (ch === "\\") {
      const n = src[i + 1];
      if (n === void 0) return false;
      if (n >= "1" && n <= "9" || n === "k") return false;
      i += 2;
      prev = "atom";
      continue;
    }
    if (ch === "[") {
      let j = i + 1;
      if (src[j] === "^") j++;
      if (src[j] === "]") j++;
      for (; j < src.length && src[j] !== "]"; j++) if (src[j] === "\\") j++;
      if (j >= src.length) return false;
      i = j + 1;
      prev = "atom";
      continue;
    }
    if (ch === "(") {
      if (src[i + 1] === "?") {
        if (src[i + 2] !== ":") return false;
        i += 3;
      } else i += 1;
      stack.push({ hasQuant: false, hasAlt: false });
      prev = "none";
      continue;
    }
    if (ch === ")") {
      if (stack.length < 2) return false;
      const f = stack.pop();
      const parent = stack[stack.length - 1];
      parent.hasQuant ||= f.hasQuant;
      parent.hasAlt ||= f.hasAlt;
      prev = f;
      i++;
      continue;
    }
    if (ch === "|") {
      stack[stack.length - 1].hasAlt = true;
      prev = "none";
      i++;
      continue;
    }
    let q = null;
    if (ch === "*" || ch === "+") q = { len: 1, unbounded: true, max: Infinity };
    else if (ch === "?") q = { len: 1, unbounded: false, max: 1 };
    else if (ch === "{") {
      const m = /^\{(\d+)(?:(,)(\d*))?\}/.exec(src.slice(i, i + 24));
      if (m) {
        const lo = Number(m[1]);
        const hasComma = m[2] !== void 0;
        const hi = !hasComma ? lo : m[3] === "" ? Infinity : Number(m[3]);
        if (hi < lo) return false;
        q = { len: m[0].length, unbounded: hi === Infinity, max: hi };
      }
    }
    if (q) {
      if (prev === "none") return false;
      if (typeof prev === "object" && (prev.hasQuant || prev.hasAlt)) return false;
      if (q.unbounded && ++unbounded > MAX_UNBOUNDED_QUANTIFIERS) return false;
      if (!q.unbounded && q.max !== Infinity && q.max > MAX_BOUNDED_REPEAT) return false;
      stack[stack.length - 1].hasQuant = true;
      i += q.len;
      if (src[i] === "?") i++;
      prev = "none";
      continue;
    }
    i++;
    prev = "atom";
  }
  return stack.length === 1;
}
function resourceMatches(pattern, resource) {
  if (pattern === void 0) return true;
  if (typeof pattern !== "string") return false;
  if (pattern === "*") return true;
  if (pattern.startsWith("re:")) {
    const src = pattern.slice(3);
    if (src.length > 200) return false;
    if (resource.length > MAX_RE_RESOURCE_LEN) return false;
    if (!isSafeRegexSource(src)) return false;
    try {
      return new RegExp("^(?:" + src + ")$").test(resource);
    } catch {
      return false;
    }
  }
  if (pattern.endsWith("*")) return resource.startsWith(pattern.slice(0, -1));
  return pattern === resource;
}
function predicateMatches(p, ctx) {
  try {
    if (p === null || typeof p !== "object") return false;
    const a = ctx?.action;
    if (!a || typeof a.verb !== "string" || typeof a.resource !== "string") return false;
    if (!verbMatches(p.verb, a.verb)) return false;
    if (!resourceMatches(p.resource, a.resource)) return false;
    if (p.where !== void 0) {
      if (!Array.isArray(p.where)) return false;
      for (const c of p.where) if (!evaluateCondition(c, ctx)) return false;
    }
    return true;
  } catch {
    return false;
  }
}
function evaluatePredicates(predicates, ctx) {
  try {
    if (!Array.isArray(predicates) || predicates.length === 0) {
      return { allowed: false, reason: "envelope grants no predicates" };
    }
    for (const p of predicates) {
      if (predicateMatches(p, ctx)) return { allowed: true, matched: p };
    }
    const a = ctx?.action;
    return { allowed: false, reason: `no predicate permits ${String(a?.verb)} on ${String(a?.resource)}` };
  } catch {
    return { allowed: false, reason: "predicate evaluation error (fail closed)" };
  }
}
var REVERSIBILITY_ORDER = ["reversible", "rate_limited", "irreversible"];
var fin = (x) => typeof x === "number" && Number.isFinite(x);
var envelopeCaveatEvaluator = (caveat, ctx) => {
  try {
    if (caveat === null || typeof caveat !== "object" || ctx === null || typeof ctx !== "object") return false;
    const c = ctx;
    if (!fin(c.now)) return false;
    switch (caveat.type) {
      case "expires":
        return fin(caveat.at) && c.now < caveat.at;
      case "not_before":
        return fin(caveat.at) && c.now >= caveat.at;
      case "rate": {
        if (!fin(caveat.max) || !fin(caveat.per_secs) || caveat.per_secs <= 0) return false;
        if (!Array.isArray(c.recentActionTimes)) return false;
        const lo = c.now - caveat.per_secs * 1e3;
        const n = c.recentActionTimes.filter((t) => fin(t) && t > lo && t <= c.now).length;
        return n < caveat.max;
      }
      case "max_blast_radius":
        return fin(caveat.max) && fin(c.blastRadius) && c.blastRadius <= caveat.max;
      case "reversibility_max": {
        const lim = REVERSIBILITY_ORDER.indexOf(String(caveat.class));
        const cur = REVERSIBILITY_ORDER.indexOf(String(c.reversibilityClass));
        return lim >= 0 && cur >= 0 && cur <= lim;
      }
      case "delegation_depth":
        return fin(caveat.max) && fin(c.delegationDepth) && c.delegationDepth <= caveat.max;
      default:
        return false;
    }
  } catch {
    return false;
  }
};
function evaluateCaveats(caveats, ctx, evaluator = envelopeCaveatEvaluator) {
  const failed = [];
  if (!Array.isArray(caveats)) return { ok: false, failed: ["<malformed caveats>"] };
  for (const cv of caveats) {
    let ok = false;
    try {
      ok = evaluator(cv, ctx);
    } catch {
      ok = false;
    }
    if (!ok) failed.push(typeof cv?.type === "string" ? cv.type : "<malformed>");
  }
  return { ok: failed.length === 0, failed };
}

// packages/pca/src/agent-native.ts
var agent_native_exports = {};
__export(agent_native_exports, {
  ABSOLUTE_MAX_ARRAY_ITEMS: () => ABSOLUTE_MAX_ARRAY_ITEMS,
  ABSOLUTE_MAX_STRING_LEN: () => ABSOLUTE_MAX_STRING_LEN,
  CAVEAT_DELEGATION_DEPTH: () => CAVEAT_DELEGATION_DEPTH,
  CAVEAT_ENVELOPE: () => CAVEAT_ENVELOPE,
  CAVEAT_EXPIRES: () => CAVEAT_EXPIRES,
  CAVEAT_MAX_BLAST_RADIUS: () => CAVEAT_MAX_BLAST_RADIUS,
  CAVEAT_NOT_BEFORE: () => CAVEAT_NOT_BEFORE,
  CAVEAT_PREDICATES: () => CAVEAT_PREDICATES,
  CAVEAT_RATE: () => CAVEAT_RATE,
  CAVEAT_REVERSIBILITY_MAX: () => CAVEAT_REVERSIBILITY_MAX,
  CAVEAT_TOOL_SCHEMA: () => CAVEAT_TOOL_SCHEMA,
  DEFAULT_MAX_ARRAY_ITEMS: () => DEFAULT_MAX_ARRAY_ITEMS,
  DEFAULT_MAX_STRING_LEN: () => DEFAULT_MAX_STRING_LEN,
  HEARTBEAT_SKEW_MS: () => HEARTBEAT_SKEW_MS,
  MAX_CAUTION_REASON_LEN: () => MAX_CAUTION_REASON_LEN,
  MAX_ENUM_VALUES: () => MAX_ENUM_VALUES,
  MAX_LEASE_TTL_MS: () => MAX_LEASE_TTL_MS,
  MAX_OBJECT_PROPS: () => MAX_OBJECT_PROPS,
  MAX_RATIONALE_LEN: () => MAX_RATIONALE_LEN,
  MAX_SCHEMA_DEPTH: () => MAX_SCHEMA_DEPTH,
  MAX_SCHEMA_NODES: () => MAX_SCHEMA_NODES,
  MAX_VALUE_NODES: () => MAX_VALUE_NODES,
  MIN_SALT_BYTES: () => MIN_SALT_BYTES,
  MIN_SALT_DISTINCT_BYTES: () => MIN_SALT_DISTINCT_BYTES,
  agentNativeCaveatEvaluator: () => agentNativeCaveatEvaluator,
  auditRationale: () => auditRationale,
  bindRationale: () => bindRationale,
  checkCautionMonotone: () => checkCautionMonotone,
  combineCaution: () => combineCaution,
  combineSignedCaution: () => combineSignedCaution,
  describeEnvelope: () => describeEnvelope,
  envelopePermits: () => envelopePermits,
  envelopePermitsToolCall: () => envelopePermitsToolCall,
  evaluateToolSchema: () => evaluateToolSchema,
  grantLease: () => grantLease,
  isStrongSalt: () => isStrongSalt,
  leaseState: () => leaseState,
  predicatesCaveat: () => predicatesCaveat,
  renewLease: () => renewLease,
  signCaution: () => signCaution,
  signHeartbeat: () => signHeartbeat,
  toolSchemaCaveat: () => toolSchemaCaveat,
  toolSchemaEvaluator: () => toolSchemaEvaluator,
  validateArgSchema: () => validateArgSchema,
  verifyCaution: () => verifyCaution,
  verifyRationale: () => verifyRationale
});
var CAVEAT_ENVELOPE = ENVELOPE_CAVEAT;
var CAVEAT_EXPIRES = "expires";
var CAVEAT_NOT_BEFORE = "not_before";
var CAVEAT_RATE = "rate";
var CAVEAT_MAX_BLAST_RADIUS = "max_blast_radius";
var CAVEAT_REVERSIBILITY_MAX = "reversibility_max";
var CAVEAT_DELEGATION_DEPTH = "delegation_depth";
var CAVEAT_PREDICATES = "predicates";
var CAVEAT_TOOL_SCHEMA = "tool_schema";
var fin2 = (x) => typeof x === "number" && Number.isFinite(x);
var isObj2 = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
var isPlain = (x) => {
  if (!isObj2(x)) return false;
  const p = Object.getPrototypeOf(x);
  return p === Object.prototype || p === null;
};
var has2 = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
var isStr2 = (x) => typeof x === "string";
var nonEmpty = (x) => typeof x === "string" && x.length > 0;
var msgOf = (domain, body2) => canonicalBytes({ d: domain, b: body2 });
var onlyKeys = (o, allowed) => Object.keys(o).every((k) => allowed.includes(k));
var clamp012 = (x) => Math.min(1, Math.max(0, x));
var MAX_CAUTION_REASON_LEN = 64;
var REASON_RE = /^[A-Za-z0-9_.:-]+$/;
var CAUTION_KEYS = ["action_digest", "caution", "reason", "holder", "sig"];
function cautionBodyError(b) {
  if (!isPlain(b)) return "not an object";
  if (!nonEmpty(b.action_digest)) return "action_digest required";
  if (!nonEmpty(b.holder)) return "holder required";
  if (!fin2(b.caution) || b.caution < 0 || b.caution > 1) return "caution must be a finite number in [0,1]";
  if (b.reason !== void 0 && (!isStr2(b.reason) || b.reason.length > MAX_CAUTION_REASON_LEN || !REASON_RE.test(b.reason))) {
    return "invalid reason";
  }
  return null;
}
function signCaution(body2, holderSecret) {
  const err = cautionBodyError(body2);
  if (err) throw new RangeError(`signCaution: ${err}`);
  const clean2 = { action_digest: body2.action_digest, caution: body2.caution, holder: body2.holder };
  if (body2.reason !== void 0) clean2.reason = body2.reason;
  return { ...clean2, sig: b64u(sign(holderSecret, msgOf("atlas-pca/caution/v1", clean2))) };
}
function verifyCaution(claim, expectedActionDigest, expectedHolder) {
  try {
    if (!isPlain(claim) || !isStr2(claim.sig) || !onlyKeys(claim, CAUTION_KEYS)) return false;
    if (cautionBodyError(claim) !== null) return false;
    if (expectedActionDigest !== void 0 && claim.action_digest !== expectedActionDigest) return false;
    if (expectedHolder !== void 0 && claim.holder !== expectedHolder) return false;
    const { sig, ...body2 } = claim;
    return verifyB64u(claim.holder, msgOf("atlas-pca/caution/v1", body2), sig);
  } catch {
    return false;
  }
}
function combineCaution(agentDeclaredCaution, serverRisk) {
  const s = fin2(serverRisk) ? clamp012(serverRisk) : 1;
  if (!fin2(agentDeclaredCaution)) return s;
  return Math.max(clamp012(agentDeclaredCaution), s);
}
function combineSignedCaution(claim, actionDigest, serverRisk, expectedHolder) {
  const s = fin2(serverRisk) ? clamp012(serverRisk) : 1;
  const ok = claim !== void 0 && verifyCaution(claim, actionDigest, expectedHolder);
  const effectiveRisk = combineCaution(ok ? claim.caution : void 0, s);
  return { effectiveRisk, honoured: ok, escalated: effectiveRisk > s };
}
function checkCautionMonotone(grid) {
  const g = grid.filter(fin2);
  for (const s of g) {
    for (const d of g) {
      const e = combineCaution(d, s);
      if (e < clamp012(s)) return { ok: false, counterexample: [d, s] };
      for (const d2 of g) if (d2 >= d && combineCaution(d2, s) < e) return { ok: false, counterexample: [d2, s] };
    }
  }
  return { ok: true };
}
var MIN_SALT_BYTES = 16;
var MIN_SALT_DISTINCT_BYTES = 8;
var MAX_RATIONALE_LEN = 8192;
function isStrongSalt(salt) {
  if (!isStr2(salt) || salt.length > 256 || !/^[A-Za-z0-9_-]+$/.test(salt)) return false;
  try {
    const b = unb64u(salt);
    return b.length >= MIN_SALT_BYTES && new Set(b).size >= MIN_SALT_DISTINCT_BYTES;
  } catch {
    return false;
  }
}
function randomSalt() {
  const b = new Uint8Array(32);
  globalThis.crypto.getRandomValues(b);
  return b64u(b);
}
var commitDigest = (actionDigest, salt, rationale) => hashCanonical({ d: "atlas-pca/rationale/v1", a: actionDigest, s: salt, r: rationale });
function bindRationale(action, rationaleText, salt = randomSalt()) {
  if (!isStr2(rationaleText)) throw new TypeError("bindRationale: rationale must be a string");
  if (rationaleText.length > MAX_RATIONALE_LEN) throw new RangeError("bindRationale: rationale too long");
  if (!isStrongSalt(salt)) throw new RangeError(`bindRationale: salt must be b64u of >=${MIN_SALT_BYTES} bytes with >=${MIN_SALT_DISTINCT_BYTES} distinct values`);
  const action_digest = hashCanonical(action);
  return {
    commitment: { v: 1, action_digest, commitment: commitDigest(action_digest, salt, rationaleText) },
    reveal: { rationale: rationaleText, salt }
  };
}
function verifyRationale(commitment, reveal, action) {
  try {
    if (!isPlain(commitment) || !isPlain(reveal)) return false;
    if (commitment.v !== 1 || !nonEmpty(commitment.action_digest) || !nonEmpty(commitment.commitment)) return false;
    if (!isStr2(reveal.rationale) || reveal.rationale.length > MAX_RATIONALE_LEN || !isStrongSalt(reveal.salt)) return false;
    if (action !== void 0 && hashCanonical(action) !== commitment.action_digest) return false;
    return commitDigest(commitment.action_digest, reveal.salt, reveal.rationale) === commitment.commitment;
  } catch {
    return false;
  }
}
function auditRationale(commitment, action, reveal, judge) {
  const evidence = {
    commitment: isPlain(commitment) && isStr2(commitment.commitment) ? commitment.commitment : "",
    action_digest: isPlain(commitment) && isStr2(commitment.action_digest) ? commitment.action_digest : ""
  };
  try {
    if (!isPlain(commitment) || commitment.v !== 1 || !nonEmpty(commitment.action_digest) || !nonEmpty(commitment.commitment)) {
      return { verdict: "malformed", slashable: false, evidence };
    }
    if (hashCanonical(action) !== commitment.action_digest) return { verdict: "wrong_action", slashable: false, evidence };
    if (!reveal || !verifyRationale(commitment, reveal, action)) return { verdict: "unopened", slashable: true, evidence };
    let ok;
    try {
      ok = judge(reveal.rationale, action) === true;
    } catch {
      return { verdict: "judge_error", slashable: false, evidence: { ...evidence, rationale: reveal.rationale } };
    }
    return {
      verdict: ok ? "consistent" : "false_rationale",
      slashable: !ok,
      evidence: { ...evidence, rationale: reveal.rationale }
    };
  } catch {
    return { verdict: "malformed", slashable: false, evidence };
  }
}
var MAX_SCHEMA_DEPTH = 8;
var MAX_SCHEMA_NODES = 256;
var MAX_OBJECT_PROPS = 64;
var MAX_ENUM_VALUES = 256;
var DEFAULT_MAX_ARRAY_ITEMS = 256;
var ABSOLUTE_MAX_ARRAY_ITEMS = 4096;
var DEFAULT_MAX_STRING_LEN = 65536;
var ABSOLUTE_MAX_STRING_LEN = 1048576;
var MAX_VALUE_NODES = 1e4;
var SAFE_NAME = /^[A-Za-z0-9_]{1,64}$/;
var SPEC_KEYS = {
  string: ["type", "enum", "const", "minLength", "maxLength", "prefix"],
  number: ["type", "enum", "const", "min", "max"],
  integer: ["type", "enum", "const", "min", "max"],
  boolean: ["type", "enum", "const"],
  object: ["type", "props", "required"],
  array: ["type", "items", "minItems", "maxItems"]
};
var nonNegInt = (x, max) => fin2(x) && Number.isInteger(x) && x >= 0 && x <= max;
function validateArgSchema(schema) {
  if (!isPlain(schema)) return "schema must be an object";
  if (!onlyKeys(schema, ["props", "required"])) return "unknown schema key";
  const budget = { nodes: 0 };
  return objectSchemaError(schema.props, schema.required, 1, budget);
}
function objectSchemaError(props, required, depth, budget) {
  if (depth > MAX_SCHEMA_DEPTH) return "schema too deep";
  if (++budget.nodes > MAX_SCHEMA_NODES) return "schema too large";
  if (!isPlain(props)) return "props must be an object";
  const names = Object.keys(props);
  if (names.length > MAX_OBJECT_PROPS) return "too many props";
  for (const n of names) {
    if (!SAFE_NAME.test(n)) return `invalid property name '${n.slice(0, 32)}'`;
    const e = specError(props[n], depth + 1, budget);
    if (e) return `${n}: ${e}`;
  }
  if (required !== void 0) {
    if (!Array.isArray(required) || required.length > MAX_OBJECT_PROPS) return "required must be a short array";
    for (const r of required) if (!isStr2(r) || !has2(props, r)) return "required names an undeclared property";
  }
  return null;
}
function specError(spec, depth, budget) {
  if (depth > MAX_SCHEMA_DEPTH) return "schema too deep";
  if (++budget.nodes > MAX_SCHEMA_NODES) return "schema too large";
  if (!isPlain(spec) || !isStr2(spec.type) || !has2(SPEC_KEYS, spec.type)) return "unknown type";
  const t = spec.type;
  if (!onlyKeys(spec, SPEC_KEYS[t])) return "unknown spec key";
  if (t === "object") {
    budget.nodes--;
    return objectSchemaError(spec.props, spec.required, depth, budget);
  }
  if (t === "array") {
    if (spec.minItems !== void 0 && !nonNegInt(spec.minItems, ABSOLUTE_MAX_ARRAY_ITEMS)) return "bad minItems";
    if (spec.maxItems !== void 0 && !nonNegInt(spec.maxItems, ABSOLUTE_MAX_ARRAY_ITEMS)) return "bad maxItems";
    if (fin2(spec.minItems) && fin2(spec.maxItems) && spec.minItems > spec.maxItems) return "minItems > maxItems";
    return specError(spec.items, depth + 1, budget);
  }
  const ok = (v) => t === "string" ? isStr2(v) && v.length <= 1024 : t === "boolean" ? typeof v === "boolean" : fin2(v) && (t === "number" || Number.isInteger(v));
  if (has2(spec, "const") && !ok(spec.const)) return "bad const";
  if (spec.enum !== void 0) {
    if (!Array.isArray(spec.enum) || spec.enum.length === 0 || spec.enum.length > MAX_ENUM_VALUES || !spec.enum.every(ok)) return "bad enum";
  }
  if (t === "string") {
    if (spec.minLength !== void 0 && !nonNegInt(spec.minLength, ABSOLUTE_MAX_STRING_LEN)) return "bad minLength";
    if (spec.maxLength !== void 0 && !nonNegInt(spec.maxLength, ABSOLUTE_MAX_STRING_LEN)) return "bad maxLength";
    if (fin2(spec.minLength) && fin2(spec.maxLength) && spec.minLength > spec.maxLength) return "minLength > maxLength";
    if (spec.prefix !== void 0 && (!isStr2(spec.prefix) || spec.prefix.length > 512)) return "bad prefix";
  } else if (t === "number" || t === "integer") {
    if (spec.min !== void 0 && !fin2(spec.min)) return "bad min";
    if (spec.max !== void 0 && !fin2(spec.max)) return "bad max";
    if (fin2(spec.min) && fin2(spec.max) && spec.min > spec.max) return "min > max";
  }
  return null;
}
var bindingOf = (tool, signature_digest, schema) => hashCanonical({ tool, signature_digest, schema });
function toolSchemaCaveat(toolSignature, argSchema) {
  const sig = toolSignature;
  const tool = typeof sig === "string" ? sig : isObj2(sig) && isStr2(sig.name) ? sig.name : "";
  if (!tool) throw new TypeError("toolSchemaCaveat: tool name required");
  const err = validateArgSchema(argSchema);
  if (err) throw new TypeError(`toolSchemaCaveat: ${err}`);
  const schema = JSON.parse(canonicalize(argSchema));
  const signature_digest = hashCanonical(toolSignature);
  return {
    type: "tool_schema",
    tool,
    signature_digest,
    schema,
    schema_digest: hashCanonical(schema),
    binding_digest: bindingOf(tool, signature_digest, schema)
  };
}
var show = (k) => JSON.stringify(k.length > 48 ? k.slice(0, 48) + "\u2026" : k);
function checkValue(spec, v, path, depth, budget) {
  if (depth > MAX_SCHEMA_DEPTH + 1) return `${path}: too deep`;
  if (++budget.n > MAX_VALUE_NODES) return `${path}: too many values`;
  switch (spec.type) {
    case "object": {
      if (!isPlain(v)) return `${path}: expected object`;
      return checkObject(spec.props, spec.required, v, path, depth, budget);
    }
    case "array": {
      if (!Array.isArray(v)) return `${path}: expected array`;
      const max = Math.min(spec.maxItems ?? DEFAULT_MAX_ARRAY_ITEMS, ABSOLUTE_MAX_ARRAY_ITEMS);
      if (v.length > max) return `${path}: exceeds maxItems`;
      if (spec.minItems !== void 0 && v.length < spec.minItems) return `${path}: below minItems`;
      for (let i = 0; i < v.length; i++) {
        if (!(i in v)) return `${path}[${i}]: hole in array`;
        const e = checkValue(spec.items, v[i], `${path}[${i}]`, depth + 1, budget);
        if (e) return e;
      }
      return null;
    }
    case "string": {
      if (!isStr2(v)) return `${path}: wrong type (expected string)`;
      if (v.length > Math.min(spec.maxLength ?? DEFAULT_MAX_STRING_LEN, ABSOLUTE_MAX_STRING_LEN)) return `${path}: exceeds maxLength`;
      if (spec.minLength !== void 0 && v.length < spec.minLength) return `${path}: below minLength`;
      if (spec.prefix !== void 0 && !v.startsWith(spec.prefix)) return `${path}: violates prefix`;
      break;
    }
    case "number":
    case "integer": {
      if (!fin2(v) || spec.type === "integer" && !Number.isInteger(v)) return `${path}: wrong type (expected ${spec.type})`;
      if (spec.min !== void 0 && v < spec.min) return `${path}: below min`;
      if (spec.max !== void 0 && v > spec.max) return `${path}: above max`;
      break;
    }
    case "boolean":
      if (typeof v !== "boolean") return `${path}: wrong type (expected boolean)`;
      break;
    default:
      return `${path}: unknown type`;
  }
  const sc = spec;
  if (has2(sc, "const") && sc.const !== v) return `${path}: violates const`;
  if (sc.enum !== void 0 && !sc.enum.some((e) => e === v)) return `${path}: violates enum`;
  return null;
}
function checkObject(props, required, obj, path, depth, budget) {
  const keys = Object.keys(obj);
  for (const k of keys) if (!has2(props, k)) return `${path}: unexpected argument ${show(k)}`;
  for (const r of required ?? []) if (!has2(obj, r)) return `${path}: missing required argument '${r}'`;
  for (const k of keys) {
    const e = checkValue(props[k], obj[k], `${path}.${k}`, depth + 1, budget);
    if (e) return e;
  }
  return null;
}
function evaluateToolSchema(caveat, call) {
  try {
    if (!isObj2(caveat) || caveat.type !== "tool_schema" || !nonEmpty(caveat.tool)) {
      return { ok: false, reason: "malformed tool_schema caveat" };
    }
    const verr = validateArgSchema(caveat.schema);
    if (verr) return { ok: false, reason: `malformed tool_schema caveat: ${verr}` };
    if (hashCanonical(caveat.schema) !== caveat.schema_digest) return { ok: false, reason: "schema digest mismatch" };
    if (bindingOf(caveat.tool, String(caveat.signature_digest), caveat.schema) !== caveat.binding_digest) {
      return { ok: false, reason: "binding digest mismatch" };
    }
    if (!isObj2(call) || !isStr2(call.tool) || !isPlain(call.args)) return { ok: false, reason: "malformed call" };
    if (call.tool !== caveat.tool) return { ok: false, reason: `tool ${show(call.tool)} not authorized` };
    if (call.toolSignature !== void 0 && hashCanonical(call.toolSignature) !== caveat.signature_digest) {
      return { ok: false, reason: "tool signature differs from the authorized signature" };
    }
    if (call.toolSignatureDigest !== void 0 && call.toolSignatureDigest !== caveat.signature_digest) {
      return { ok: false, reason: "signed tool_binding differs from the authorized tool signature" };
    }
    const e = checkObject(caveat.schema.props, caveat.schema.required, call.args, "args", 1, { n: 0 });
    return e ? { ok: false, reason: e } : { ok: true };
  } catch {
    return { ok: false, reason: "evaluation error (fail closed)" };
  }
}
function toolSchemaEvaluator(caveat, ctx) {
  if (!isObj2(ctx) || !isObj2(ctx.toolCall)) return false;
  return evaluateToolSchema(caveat, ctx.toolCall).ok;
}
function predicatesCaveat(allow) {
  return { type: CAVEAT_PREDICATES, allow: JSON.parse(canonicalize(allow)) };
}
function agentNativeCaveatEvaluator(caveat, ctx) {
  try {
    if (!isObj2(caveat) || !isObj2(ctx)) return false;
    if (caveat.type === CAVEAT_TOOL_SCHEMA) return toolSchemaEvaluator(caveat, ctx);
    if (caveat.type === CAVEAT_PREDICATES) {
      const a = ctx.action;
      if (!isObj2(a) || !Array.isArray(caveat.allow)) return false;
      return caveat.allow.some((p) => predicateMatches(p, a));
    }
    return envelopeCaveatEvaluator(caveat, ctx);
  } catch {
    return false;
  }
}
function intersectVerbs(a, b) {
  if (a.includes("*")) return [...new Set(b)].sort();
  if (b.includes("*")) return [...new Set(a)].sort();
  return [...new Set(a.filter((x) => b.includes(x)))].sort();
}
function interRes(a, b) {
  if (a === b) return a;
  if (a.startsWith("re:") || b.startsWith("re:")) return void 0;
  if (a === "*") return b;
  if (b === "*") return a;
  const ap = a.endsWith("*"), bp = b.endsWith("*");
  if (ap && bp) {
    const pa = a.slice(0, -1), pb = b.slice(0, -1);
    return pb.startsWith(pa) ? b : pa.startsWith(pb) ? a : null;
  }
  if (ap) return b.startsWith(a.slice(0, -1)) ? b : null;
  if (bp) return a.startsWith(b.slice(0, -1)) ? a : null;
  return null;
}
function collapseResources(list) {
  let lit;
  const res = /* @__PURE__ */ new Set();
  for (const p of list) {
    if (p.startsWith("re:")) {
      res.add(p);
      continue;
    }
    if (lit === void 0) lit = p;
    else {
      const r = interRes(lit, p);
      if (r === null || r === void 0) return null;
      lit = r;
    }
  }
  const out = [...lit !== void 0 && lit !== "*" ? [lit] : [], ...[...res].sort()];
  return out.length ? out : ["*"];
}
function scopeOfPredicate(p) {
  if (!isObj2(p)) return null;
  const verbs = typeof p.verb === "string" ? [p.verb] : Array.isArray(p.verb) && p.verb.every(isStr2) ? [...p.verb] : null;
  if (!verbs) return null;
  if (p.resource !== void 0 && !isStr2(p.resource)) return null;
  const where = p.where === void 0 ? [] : Array.isArray(p.where) ? p.where : null;
  if (!where) return null;
  return { verbs: [...new Set(verbs)].sort(), resources: [p.resource ?? "*"], where };
}
function intersectScopes(a, b) {
  const out = /* @__PURE__ */ new Map();
  for (const x of a) {
    for (const y of b) {
      const verbs = intersectVerbs(x.verbs, y.verbs);
      if (!verbs.length) continue;
      const resources = collapseResources([...x.resources, ...y.resources]);
      if (!resources) continue;
      const s = { verbs, resources, where: [...x.where, ...y.where] };
      out.set(hashCanonical(s), s);
    }
  }
  return [...out.entries()].sort(([p], [q]) => p < q ? -1 : p > q ? 1 : 0).map(([, s]) => s);
}
function scopeMatches(s, verb, resource, params) {
  if (!s.verbs.includes("*") && !s.verbs.includes(verb)) return false;
  const ctx = { action: { verb, resource, ...params ? { params } : {} } };
  for (const r of s.resources) if (!predicateMatches({ verb: "*", resource: r }, ctx)) return false;
  if (params !== void 0 && s.where.length) return predicateMatches({ verb: "*", where: s.where }, ctx);
  return true;
}
var REV = REVERSIBILITY_ORDER;
function wellFormedCaveat(cv) {
  switch (cv.type) {
    case CAVEAT_EXPIRES:
    case CAVEAT_NOT_BEFORE:
      return fin2(cv.at);
    case CAVEAT_RATE:
      return fin2(cv.max) && fin2(cv.per_secs) && cv.per_secs > 0;
    case CAVEAT_MAX_BLAST_RADIUS:
    case CAVEAT_DELEGATION_DEPTH:
      return fin2(cv.max);
    case CAVEAT_REVERSIBILITY_MAX:
      return REV.includes(String(cv.class));
    case CAVEAT_PREDICATES:
      return Array.isArray(cv.allow) && cv.allow.every((p) => scopeOfPredicate(p) !== null);
    case CAVEAT_TOOL_SCHEMA:
      return nonEmpty(cv.tool);
    default:
      return false;
  }
}
function describeEnvelope(chain2, now, expectedRootIssuer) {
  const empty = {
    ok: false,
    hasEnvelope: false,
    scopes: [],
    verbs: [],
    resources: [],
    opaqueResourceConstraints: [],
    tools: [],
    toolSchemas: [],
    unsatisfiable: [],
    caveats: [],
    remainingBudgetHints: {}
  };
  try {
    const v = verifyChain(chain2, expectedRootIssuer);
    if (!v.ok) return { ...empty, reason: v.reason };
    const root = chain2[0];
    const leaf = chain2[chain2.length - 1];
    const env0 = readEnvelope(root);
    const env = { ...empty, ok: true, hasEnvelope: env0 !== null, caveats: leaf.caveats };
    const h = env.remainingBudgetHints;
    const bad = /* @__PURE__ */ new Set();
    let scopes = null;
    if (env0) {
      const base = env0.predicates.map(scopeOfPredicate);
      if (base.some((s) => s === null)) bad.add("envelope.predicates");
      scopes = intersectScopes(base.filter((s) => s !== null), [{ verbs: ["*"], resources: ["*"], where: [] }]);
    }
    let tools = null;
    let seenEnvelope = false;
    const fold = (cv, inEnvelope) => {
      if (!isObj2(cv) || !isStr2(cv.type)) {
        bad.add("<malformed>");
        return;
      }
      if (cv.type === CAVEAT_ENVELOPE) {
        if (seenEnvelope || inEnvelope) bad.add(CAVEAT_ENVELOPE);
        seenEnvelope = true;
        return;
      }
      if (!wellFormedCaveat(cv)) {
        bad.add(cv.type);
        return;
      }
      switch (cv.type) {
        case CAVEAT_PREDICATES: {
          const next = cv.allow.map((p) => scopeOfPredicate(p));
          scopes = intersectScopes(scopes ?? [{ verbs: ["*"], resources: ["*"], where: [] }], next);
          break;
        }
        case CAVEAT_TOOL_SCHEMA: {
          const tc = cv;
          env.toolSchemas.push(tc);
          const consistent = validateArgSchema(tc.schema) === null && hashCanonical(tc.schema) === tc.schema_digest && bindingOf(tc.tool, String(tc.signature_digest), tc.schema) === tc.binding_digest;
          if (!consistent) {
            tools = [];
            bad.add(CAVEAT_TOOL_SCHEMA);
          } else tools = tools === null ? [tc.tool] : tools.filter((t) => t === tc.tool);
          break;
        }
        case CAVEAT_EXPIRES:
          h.expiresAt = h.expiresAt === void 0 ? cv.at : Math.min(h.expiresAt, cv.at);
          break;
        case CAVEAT_NOT_BEFORE:
          h.notBefore = h.notBefore === void 0 ? cv.at : Math.max(h.notBefore, cv.at);
          break;
        case CAVEAT_RATE: {
          const cur = h.maxRate;
          const m = cv.max, p = cv.per_secs;
          if (!cur || m / p < cur.max / cur.per_secs || m / p === cur.max / cur.per_secs && m < cur.max) h.maxRate = { max: m, per_secs: p };
          break;
        }
        case CAVEAT_MAX_BLAST_RADIUS:
          h.maxBlastRadius = h.maxBlastRadius === void 0 ? cv.max : Math.min(h.maxBlastRadius, cv.max);
          break;
        case CAVEAT_REVERSIBILITY_MAX: {
          const i = REV.indexOf(String(cv.class));
          const j = h.reversibilityMax === void 0 ? REV.length : REV.indexOf(h.reversibilityMax);
          if (i < j) h.reversibilityMax = REV[i];
          break;
        }
        case CAVEAT_DELEGATION_DEPTH: {
          const rem = cv.max - (chain2.length - 1);
          h.delegationDepthRemaining = h.delegationDepthRemaining === void 0 ? rem : Math.min(h.delegationDepthRemaining, rem);
          break;
        }
      }
    };
    if (env0) for (const cv of env0.caveats) fold(cv, true);
    for (const cv of leaf.caveats) fold(cv, false);
    env.scopes = scopes;
    const opaque = /* @__PURE__ */ new Set();
    if (scopes) {
      const vs = /* @__PURE__ */ new Set(), rs = /* @__PURE__ */ new Set();
      for (const s of scopes) {
        s.verbs.forEach((x) => vs.add(x));
        s.resources.forEach((r) => {
          rs.add(r);
          if (r.startsWith("re:")) opaque.add(r);
        });
      }
      env.verbs = [...vs].sort();
      env.resources = [...rs].sort();
    } else {
      env.verbs = null;
      env.resources = null;
    }
    env.opaqueResourceConstraints = [...opaque].sort();
    env.tools = tools === null ? null : [...new Set(tools)].sort();
    env.unsatisfiable = [...bad].sort();
    if (env.unsatisfiable.length) {
      env.scopes = [];
      env.verbs = [];
      env.resources = [];
      env.tools = [];
      env.reason = `unsatisfiable caveat(s): ${env.unsatisfiable.join(", ")}`;
    }
    if (h.expiresAt !== void 0 && fin2(now)) h.expiresIn = h.expiresAt - now;
    return env;
  } catch {
    return { ...empty, reason: "introspection error (fail closed)" };
  }
}
function envelopePermits(env, verb, resource, now, params) {
  try {
    if (!env.ok || env.unsatisfiable.length) return false;
    if (env.scopes !== null && !env.scopes.some((s) => scopeMatches(s, verb, resource, params))) return false;
    const h = env.remainingBudgetHints;
    if (h.delegationDepthRemaining !== void 0 && h.delegationDepthRemaining < 0) return false;
    if (now !== void 0) {
      if (!fin2(now)) return false;
      if (h.expiresAt !== void 0 && now >= h.expiresAt) return false;
      if (h.notBefore !== void 0 && now < h.notBefore) return false;
    }
    return true;
  } catch {
    return false;
  }
}
function envelopePermitsToolCall(env, call) {
  try {
    if (!env.ok || env.unsatisfiable.length) return { ok: false, reason: env.reason ?? "envelope not usable" };
    if (env.tools !== null && !env.tools.includes(call.tool)) return { ok: false, reason: `tool ${show(String(call.tool))} not authorized` };
    for (const tc of env.toolSchemas) {
      const r = evaluateToolSchema(tc, call);
      if (!r.ok) return r;
    }
    return { ok: true };
  } catch {
    return { ok: false, reason: "evaluation error (fail closed)" };
  }
}
var HEARTBEAT_SKEW_MS = 3e4;
var MAX_LEASE_TTL_MS = 7 * 24 * 36e5;
function grantLease(args) {
  if (!nonEmpty(args.cap_id) || !nonEmpty(args.holder)) throw new TypeError("grantLease: cap_id and holder required");
  if (!fin2(args.now) || !fin2(args.ttl_ms) || args.ttl_ms <= 0 || args.ttl_ms > MAX_LEASE_TTL_MS) throw new RangeError("grantLease: invalid now/ttl_ms");
  if (args.hard_expires_at !== void 0 && (!fin2(args.hard_expires_at) || args.hard_expires_at <= args.now)) throw new RangeError("grantLease: hard_expires_at must be finite and in the future");
  if (args.max_renewals !== void 0 && !(Number.isInteger(args.max_renewals) && args.max_renewals >= 0)) throw new RangeError("grantLease: invalid max_renewals");
  const exp = args.hard_expires_at === void 0 ? args.now + args.ttl_ms : Math.min(args.now + args.ttl_ms, args.hard_expires_at);
  const l = {
    cap_id: args.cap_id,
    holder: args.holder,
    issued_at: args.now,
    renewed_at: args.now,
    ttl_ms: args.ttl_ms,
    renewals: 0,
    last_seq: 0,
    expires_at: exp
  };
  if (args.hard_expires_at !== void 0) l.hard_expires_at = args.hard_expires_at;
  if (args.max_renewals !== void 0) l.max_renewals = args.max_renewals;
  return l;
}
function leaseError(l) {
  if (!isPlain(l)) return "malformed lease";
  if (!nonEmpty(l.cap_id) || !nonEmpty(l.holder)) return "malformed lease";
  if (![l.issued_at, l.renewed_at, l.ttl_ms, l.expires_at].every(fin2)) return "malformed lease";
  const ttl = l.ttl_ms;
  if (ttl <= 0 || ttl > MAX_LEASE_TTL_MS) return "malformed lease";
  if (!(Number.isInteger(l.renewals) && l.renewals >= 0) || !(Number.isInteger(l.last_seq) && l.last_seq >= 0)) return "malformed lease";
  if (l.max_renewals !== void 0 && !(Number.isInteger(l.max_renewals) && l.max_renewals >= 0)) return "malformed lease";
  if (l.hard_expires_at !== void 0) {
    if (!fin2(l.hard_expires_at)) return "malformed lease";
    if (l.expires_at > l.hard_expires_at) return "lease exceeds hard expiry";
  }
  if (l.expires_at > l.renewed_at + ttl) return "malformed lease";
  return null;
}
function leaseState(lease, now) {
  const dead = (reason) => ({ live: false, expiresIn: 0, reason });
  if (!fin2(now)) return dead("invalid clock");
  const e = leaseError(lease);
  if (e) return dead(e);
  if (now < lease.renewed_at - HEARTBEAT_SKEW_MS) return dead("clock before last renewal");
  const expiresIn = lease.expires_at - now;
  if (expiresIn <= 0) return dead("lease lapsed");
  return { live: true, expiresIn };
}
var HB_KEYS = ["cap_id", "seq", "at", "holder", "lease_issued_at", "sig"];
function signHeartbeat(body2, holderSecret) {
  const clean2 = { cap_id: body2.cap_id, seq: body2.seq, at: body2.at, holder: body2.holder, lease_issued_at: body2.lease_issued_at };
  return { ...clean2, sig: b64u(sign(holderSecret, msgOf("atlas-pca/lease-hb/v2", clean2))) };
}
function renewLease(lease, hb, now) {
  try {
    const st = leaseState(lease, now);
    if (!st.live) return { ok: false, reason: st.reason === "lease lapsed" ? "lease lapsed" : `lease not live: ${st.reason}` };
    if (!isPlain(hb) || !onlyKeys(hb, HB_KEYS) || !isStr2(hb.sig)) return { ok: false, reason: "malformed heartbeat" };
    if (hb.cap_id !== lease.cap_id || hb.holder !== lease.holder || hb.lease_issued_at !== lease.issued_at) {
      return { ok: false, reason: "heartbeat not for this lease" };
    }
    if (!Number.isSafeInteger(hb.seq) || hb.seq <= lease.last_seq) return { ok: false, reason: "stale or replayed heartbeat" };
    if (!fin2(hb.at) || Math.abs(hb.at - now) > HEARTBEAT_SKEW_MS) return { ok: false, reason: "heartbeat outside skew window" };
    const { sig, ...body2 } = hb;
    if (!verifyB64u(lease.holder, msgOf("atlas-pca/lease-hb/v2", body2), sig)) return { ok: false, reason: "bad heartbeat signature" };
    if (lease.max_renewals !== void 0 && lease.renewals >= lease.max_renewals) return { ok: false, reason: "renewal budget exhausted" };
    let exp = now + lease.ttl_ms;
    if (lease.hard_expires_at !== void 0) exp = Math.min(exp, lease.hard_expires_at);
    if (!fin2(exp)) return { ok: false, reason: "malformed lease" };
    return {
      ok: true,
      lease: { ...lease, renewals: lease.renewals + 1, last_seq: hb.seq, renewed_at: Math.max(now, lease.renewed_at), expires_at: Math.max(exp, lease.expires_at) }
    };
  } catch {
    return { ok: false, reason: "malformed heartbeat" };
  }
}

// packages/pca/src/policy-vm.ts
function toolCallOf(action) {
  const a = action?.action;
  const params = a?.params;
  return {
    tool: typeof a?.verb === "string" ? a.verb : "",
    args: params !== null && typeof params === "object" && !Array.isArray(params) ? params : {},
    ...typeof action?.toolBinding === "string" ? { toolSignatureDigest: action.toolBinding } : {}
  };
}
function agentCaveatContext(base, action) {
  return { ...base, action, toolCall: toolCallOf(action) };
}
function evaluateAgentCaveats(caveats, base, action) {
  return evaluateCaveats(caveats, agentCaveatContext(base, action), agentNativeCaveatEvaluator);
}
var WORST = {
  semanticDistance: 1,
  reversibility: 0,
  blastRadius: 1,
  taint: 1,
  confidence: 0,
  age: 1
};
function denied(reason, budget) {
  return {
    releaseGuardianShare: false,
    requiredThreshold: { t: 3, proof: "strong", optimisticAllowed: false },
    r: 1,
    admit: false,
    needStepUp: true,
    reasons: [reason],
    budget
  };
}
function decide(input) {
  const fallbackBudget = input?.budget ?? { B: 0, tau: 0 };
  try {
    const { grant, action, plan, risk, budget, now } = input;
    const env = readEnvelope(grant);
    if (!env) return denied("grant carries no valid envelope", budget);
    if (!Number.isFinite(now)) return denied("invalid decision time", budget);
    const pol = env.risk_policy;
    const reasons = [];
    const pr = evaluatePredicates(env.predicates, action);
    if (!pr.allowed) reasons.push(pr.reason ?? "action not permitted by envelope predicates");
    let nodeId = input.nodeId;
    if (plan && nodeId === void 0) {
      nodeId = plan.find((n) => n.verb === action?.action?.verb && n.resource === action?.action?.resource)?.id;
    }
    const node = plan?.find((n) => n.id === nodeId);
    const chain2 = input.chain;
    const cctx = {
      now,
      blastRadius: risk?.blastRadius,
      reversibilityClass: action?.action?.reversibility_class ?? node?.reversibility_class,
      ...input.caveatContext
    };
    let chainOk = true;
    let extra = [];
    if (chain2 !== void 0) {
      if (!Array.isArray(chain2) || chain2.length === 0) {
        chainOk = false;
        reasons.push("delegation chain is empty or malformed");
      } else {
        cctx.delegationDepth = chain2.length - 1;
        extra = chain2[chain2.length - 1].caveats.slice(grant.caveats.length);
      }
    }
    const cv = evaluateAgentCaveats(env.caveats, cctx, action);
    if (!cv.ok) reasons.push(`caveat(s) not satisfied: ${cv.failed.join(", ")}`);
    const dcv = evaluateAgentCaveats(extra, cctx, action);
    if (!dcv.ok) reasons.push(`delegated caveat(s) not satisfied: ${dcv.failed.join(", ")}`);
    const leaked = leak(budget, now, pol.lambda);
    const inputs = { ...WORST, ...stripUndef(risk) };
    const missing = Object.keys(WORST).filter(
      (k) => k !== "age" && (risk?.[k] === void 0 || !Number.isFinite(risk[k]))
    );
    if (plan && risk?.semanticDistance === void 0) {
      const goal = input.goalNodeId ?? plan[plan.length - 1]?.id;
      inputs.semanticDistance = nodeId !== void 0 && goal !== void 0 ? planGeodesic(plan, nodeId, goal) : 1;
      const i = missing.indexOf("semanticDistance");
      if (i >= 0) missing.splice(i, 1);
    }
    if (risk?.age === void 0) inputs.age = ageSinceTouch(leaked, now, input.ageHorizonMs);
    if (missing.length) reasons.push(`risk input(s) missing, assumed worst case: ${missing.join(", ")}`);
    const rFloor = typeof input.rFloor === "number" && Number.isFinite(input.rFloor) ? Math.min(1, Math.max(0, input.rFloor)) : 0;
    const r = Math.max(riskScore(inputs, pol.weights), rFloor);
    const irreversible = cctx.reversibilityClass === "irreversible";
    const rt = requiredThreshold(r, pol, { irreversible });
    const adm = admit(r, leaked, pol);
    if (adm.needStepUp) {
      reasons.push(
        rt.t < 3 && adm.t === 3 ? "trust budget depleted: human recharge required" : `risk ${r.toFixed(3)} exceeds auto threshold: step-up to t=${adm.t}`
      );
    }
    const policyOk = pr.allowed && cv.ok && dcv.ok && chainOk;
    const release = policyOk;
    const autoAdmit = release && adm.admit;
    const outBudget = release && adm.metered ? debit(leaked, cost(r, pol.kappa)) : leaked;
    return {
      releaseGuardianShare: release,
      requiredThreshold: escalateThreshold(rt, adm.t),
      r,
      admit: autoAdmit,
      needStepUp: release ? adm.needStepUp : true,
      reasons,
      budget: outBudget
    };
  } catch (e) {
    return denied(`policy evaluation error (fail closed): ${e instanceof Error ? e.message : "unknown"}`, fallbackBudget);
  }
}
function stripUndef(r) {
  const out = {};
  if (!r) return out;
  for (const k of Object.keys(WORST)) {
    if (typeof r[k] === "number" && Number.isFinite(r[k])) out[k] = r[k];
  }
  return out;
}
function deriveDecideInput(p, ctx) {
  const chain2 = ctx.chain ?? p.cap_chain;
  const grant = ctx.grant ?? chain2?.[0];
  return {
    grant,
    chain: chain2,
    action: {
      action: {
        verb: p.action?.verb,
        resource: p.action?.resource,
        params: ctx.params ?? {},
        reversibility_class: p.action?.reversibility_class
      },
      ...ctx.subject ? { subject: ctx.subject } : {},
      ...ctx.env ? { env: ctx.env } : {}
    },
    plan: ctx.plan,
    nodeId: p.plan?.node_id,
    goalNodeId: ctx.goalNodeId,
    risk: ctx.risk,
    budget: ctx.budget,
    now: ctx.now,
    caveatContext: ctx.caveatContext,
    ageHorizonMs: ctx.ageHorizonMs
  };
}

// packages/pca/src/ledger.ts
var NODE2 = 1;
function nodeHash2(l, r) {
  const out = new Uint8Array(1 + l.length + r.length);
  out[0] = NODE2;
  out.set(l, 1);
  out.set(r, 1 + l.length);
  return sha2563(out);
}
function split3(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}
function mth(hs) {
  if (hs.length === 0) return sha2563(new Uint8Array(0));
  if (hs.length === 1) return hs[0];
  const k = split3(hs.length);
  return nodeHash2(mth(hs.slice(0, k)), mth(hs.slice(k)));
}
function entryCommit(salt, pcactn) {
  return hashCanonical({ salt, pcactn_digest: pcactnDigest(pcactn) });
}
function verifyOpening(commit, opening) {
  try {
    return entryCommit(opening.salt, opening.pcactn) === commit;
  } catch {
    return false;
  }
}
function ledgerRootOf(commits) {
  return b64u(mth(commits.map(leafHash)));
}
function verifyLedgerInclusion(root, proof, commit) {
  return verifyInclusion(root, proof, commit);
}
function verifyLedgerConsistency(oldRoot, newRoot, proof) {
  try {
    const first = proof.oldSize;
    const second = proof.newSize;
    if (!Number.isInteger(first) || !Number.isInteger(second) || first < 0 || first > second) return false;
    if (!Array.isArray(proof.path)) return false;
    if (first === 0) return proof.path.length === 0;
    if (first === second) return proof.path.length === 0 && oldRoot === newRoot;
    const path = proof.path.map(unb64u);
    if ((first & first - 1) === 0) path.unshift(unb64u(oldRoot));
    if (path.length === 0) return false;
    let fn = first - 1;
    let sn = second - 1;
    while (fn & 1) {
      fn >>= 1;
      sn >>= 1;
    }
    let fr = path[0];
    let sr = path[0];
    for (const c of path.slice(1)) {
      if (sn === 0) return false;
      if (fn & 1 || fn === sn) {
        fr = nodeHash2(c, fr);
        sr = nodeHash2(c, sr);
        while (!(fn & 1) && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      } else {
        sr = nodeHash2(sr, c);
      }
      fn >>= 1;
      sn >>= 1;
    }
    return sn === 0 && b64u(fr) === oldRoot && b64u(sr) === newRoot;
  } catch {
    return false;
  }
}
var WITNESS_DOMAIN = "atlas-pca/ledger-head/v1\0";
function headMessage(principal, size, root) {
  const body2 = canonicalBytes({ principal, size, root });
  const p = utf8(WITNESS_DOMAIN);
  const m = new Uint8Array(p.length + body2.length);
  m.set(p);
  m.set(body2, p.length);
  return m;
}
function verifyWitnessedHead(wh, witnessPublic) {
  return wh.witness === witnessPublic && verifyB64u(witnessPublic, headMessage(wh.principal, wh.size, wh.root), wh.sig);
}
function detectEquivocation(a, b, witnessPublic) {
  return verifyWitnessedHead(a, witnessPublic) && verifyWitnessedHead(b, witnessPublic) && a.principal === b.principal && a.size === b.size && a.root !== b.root;
}
var TransparencyLedger = class _TransparencyLedger {
  constructor(principal = "") {
    this.principal = principal;
  }
  _entries = [];
  _hashes = [];
  /** Rebuild from stored entries (e.g. after persistence, or to model tampering). */
  static fromEntries(entries, principal = "") {
    const l = new _TransparencyLedger(principal);
    for (const e of entries) {
      l._entries.push({ commit: e.commit, ...e.opening ? { opening: e.opening } : {} });
      l._hashes.push(leafHash(e.commit));
    }
    return l;
  }
  get size() {
    return this._entries.length;
  }
  /** Append a PCActn as a salted commitment. Pass `opts.salt` for deterministic output. */
  append(pcactn, opts = {}) {
    const salt = opts.salt ?? b64u(randomBytes(16));
    const commit = entryCommit(salt, pcactn);
    const index = this._entries.length;
    this._entries.push({ commit, opening: { salt, pcactn } });
    this._hashes.push(leafHash(commit));
    return { index, commit };
  }
  head() {
    return { size: this.size, root: b64u(mth(this._hashes)) };
  }
  /** Root the log had when it contained only the first `size` entries. */
  rootAt(size) {
    if (!Number.isInteger(size) || size < 0 || size > this.size) throw new RangeError("rootAt: size out of range");
    return b64u(mth(this._hashes.slice(0, size)));
  }
  commits() {
    return this._entries.map((e) => e.commit);
  }
  entry(index) {
    const e = this._entries[index];
    if (!e) throw new RangeError("entry: index out of range");
    return { commit: e.commit, ...e.opening ? { opening: e.opening } : {} };
  }
  /** Indices whose stored opening no longer matches its commit (storage tamper detection). */
  auditOpenings() {
    const bad = [];
    this._entries.forEach((e, i) => {
      if (e.opening && !verifyOpening(e.commit, e.opening)) bad.push(i);
    });
    return bad;
  }
  inclusionProof(index) {
    return merkleProof(this.commits(), index);
  }
  verifyInclusion(root, proof, commit) {
    return verifyLedgerInclusion(root, proof, commit);
  }
  /** RFC 6962 SUBPROOF(m, D[n], true). */
  consistencyProof(oldSize, newSize = this.size) {
    if (!Number.isInteger(oldSize) || !Number.isInteger(newSize) || oldSize < 0 || oldSize > newSize || newSize > this.size) {
      throw new RangeError("consistencyProof: invalid sizes");
    }
    const out = [];
    const sub = (m, hs, b) => {
      const n = hs.length;
      if (m === n) {
        if (!b) out.push(mth(hs));
        return;
      }
      const k = split3(n);
      if (m <= k) {
        sub(m, hs.slice(0, k), b);
        out.push(mth(hs.slice(k)));
      } else {
        sub(m - k, hs.slice(k), false);
        out.push(mth(hs.slice(0, k)));
      }
    };
    if (oldSize > 0 && oldSize < newSize) sub(oldSize, this._hashes.slice(0, newSize), true);
    return { oldSize, newSize, path: out.map(b64u) };
  }
  verifyConsistency(oldRoot, newRoot, proof) {
    return verifyLedgerConsistency(oldRoot, newRoot, proof);
  }
  /**
   * Crypto-shred: destroy the opening (salt + PCActn), keep the commit. The leaf, the root and every
   * inclusion/consistency proof are unchanged. Returns whether an opening was actually removed.
   */
  shred(index) {
    const e = this._entries[index];
    if (!e) throw new RangeError("shred: index out of range");
    const had = e.opening !== void 0;
    delete e.opening;
    return had;
  }
  /** Sign the current head for third-party witnessing / anti-equivocation (co-sign hook). */
  witnessHead(guardianSecret) {
    const { size, root } = this.head();
    const sig = sign(guardianSecret, headMessage(this.principal, size, root));
    return { principal: this.principal, size, root, witness: b64u(publicKeyOf(guardianSecret)), sig: b64u(sig) };
  }
};
var STH_DOMAIN = "atlas-pca/sth/v1\0";
function sthMessage(h) {
  const body2 = canonicalBytes({
    instance_id: h.instance_id,
    principal: h.principal,
    size: h.size,
    root: h.root,
    prev_root: h.prev_root,
    timestamp: h.timestamp
  });
  const p = utf8(STH_DOMAIN);
  const m = new Uint8Array(p.length + body2.length);
  m.set(p);
  m.set(body2, p.length);
  return m;
}
function signTreeHead(guardianSecret, head) {
  return {
    instance_id: head.instance_id,
    principal: head.principal,
    size: head.size,
    root: head.root,
    prev_root: head.prev_root,
    timestamp: head.timestamp,
    guardian: b64u(publicKeyOf(guardianSecret)),
    sig: b64u(sign(guardianSecret, sthMessage(head)))
  };
}
function verifyTreeHead(sth, guardianPublic) {
  try {
    if (!sth || sth.guardian !== guardianPublic) return false;
    if (!Number.isSafeInteger(sth.size) || sth.size < 0) return false;
    return verifyB64u(guardianPublic, sthMessage(sth), sth.sig);
  } catch {
    return false;
  }
}
function verifyHeadConsistency(older, newer, proof, guardianPublic) {
  try {
    if (!verifyTreeHead(older, guardianPublic) || !verifyTreeHead(newer, guardianPublic)) return false;
    if (older.instance_id !== newer.instance_id || older.principal !== newer.principal) return false;
    if (proof.oldSize !== older.size || proof.newSize !== newer.size) return false;
    return verifyLedgerConsistency(older.root, newer.root, proof);
  } catch {
    return false;
  }
}

// packages/pca/src/revocation.ts
var NODE3 = 1;
function nodeHash3(l, r) {
  const out = new Uint8Array(1 + l.length + r.length);
  out[0] = NODE3;
  out.set(l, 1);
  out.set(r, 1 + l.length);
  return sha2563(out);
}
function bindRoot(size, treeRoot) {
  const prefix = utf8("pca-revset/v1\0");
  const tail = canonicalBytes({ size, tree: treeRoot });
  const m = new Uint8Array(prefix.length + tail.length);
  m.set(prefix);
  m.set(tail, prefix.length);
  return b64u(sha2563(m));
}
var EMPTY_TREE = b64u(sha2563(new Uint8Array(0)));
function split4(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}
function expectedSides(index, size) {
  const out = [];
  const go = (i, n) => {
    if (n === 1) return;
    const k = split4(n);
    if (i < k) {
      go(i, k);
      out.push("R");
    } else {
      go(i - k, n - k);
      out.push("L");
    }
  };
  go(index, size);
  return out;
}
function leafOk(root, size, id, proof) {
  try {
    if (!proof || proof.size !== size || !Number.isInteger(proof.index) || proof.index < 0 || proof.index >= size) return false;
    const sides = expectedSides(proof.index, size);
    if (!Array.isArray(proof.path) || proof.path.length !== sides.length) return false;
    let h = leafHash(id);
    for (let i = 0; i < sides.length; i++) {
      const step = proof.path[i];
      if (step.side !== sides[i]) return false;
      const sib = unb64u(step.hash);
      h = step.side === "L" ? nodeHash3(sib, h) : nodeHash3(h, sib);
    }
    return bindRoot(size, b64u(h)) === root;
  } catch {
    return false;
  }
}
var RevocationSet = class {
  ids = [];
  constructor(initial = []) {
    for (const id of initial) this.revoke(id);
  }
  get size() {
    return this.ids.length;
  }
  /** Idempotent. Returns true when newly revoked. */
  revoke(id) {
    if (typeof id !== "string") throw new TypeError("revoke: id must be a string");
    let lo = 0;
    let hi = this.ids.length;
    while (lo < hi) {
      const mid = lo + hi >> 1;
      if (this.ids[mid] < id) lo = mid + 1;
      else hi = mid;
    }
    if (this.ids[lo] === id) return false;
    this.ids.splice(lo, 0, id);
    return true;
  }
  has(id) {
    return this.indexOf(id) >= 0;
  }
  indexOf(id) {
    let lo = 0;
    let hi = this.ids.length;
    while (lo < hi) {
      const mid = lo + hi >> 1;
      if (this.ids[mid] < id) lo = mid + 1;
      else hi = mid;
    }
    return this.ids[lo] === id ? lo : -1;
  }
  /** Sorted revoked ids (copy). */
  list() {
    return [...this.ids];
  }
  get root() {
    return bindRoot(this.ids.length, this.ids.length === 0 ? EMPTY_TREE : merkleRoot(this.ids));
  }
  membershipProof(id) {
    const i = this.indexOf(id);
    if (i < 0) throw new Error("membershipProof: id is not revoked");
    return merkleProof(this.ids, i);
  }
  /** Throws when the id IS revoked (no such proof can exist). */
  nonMembershipProof(id) {
    if (this.has(id)) throw new Error("nonMembershipProof: id is revoked");
    const n = this.ids.length;
    let lo = 0;
    let hi = n;
    while (lo < hi) {
      const mid = lo + hi >> 1;
      if (this.ids[mid] < id) lo = mid + 1;
      else hi = mid;
    }
    const leaf = (i) => ({ id: this.ids[i], proof: merkleProof(this.ids, i) });
    const p = { size: n };
    if (lo > 0) p.lo = leaf(lo - 1);
    if (lo < n) p.hi = leaf(lo);
    return p;
  }
};
function verifyMembership(root, proof, id) {
  return !!proof && leafOk(root, proof.size, id, proof);
}
function verifyNonMembership(root, proof, id) {
  try {
    if (!proof || !Number.isInteger(proof.size) || proof.size < 0) return false;
    const { size, lo, hi } = proof;
    if (size === 0) return !lo && !hi && root === bindRoot(0, EMPTY_TREE);
    if (!lo && !hi) return false;
    if (lo) {
      if (!(lo.id < id) || !leafOk(root, size, lo.id, lo.proof)) return false;
      if (!hi && lo.proof.index !== size - 1) return false;
    }
    if (hi) {
      if (!(id < hi.id) || !leafOk(root, size, hi.id, hi.proof)) return false;
      if (!lo && hi.proof.index !== 0) return false;
    }
    if (lo && hi && hi.proof.index !== lo.proof.index + 1) return false;
    return true;
  } catch {
    return false;
  }
}
var REVEPOCH_DOMAIN = "atlas-pca/revepoch/v1\0";
var REVOCATION_EPOCH_REFRESH_MS = 6e4;
var REVOCATION_EPOCH_VALIDITY_MS = 5 * 6e4;
function epochMessage(e) {
  const body2 = canonicalBytes({
    instance_id: e.instance_id,
    grant_ref: e.grant_ref,
    epoch: e.epoch,
    set_size: e.set_size,
    root: e.root,
    issued_at: e.issued_at,
    not_after: e.not_after
  });
  const p = utf8(REVEPOCH_DOMAIN);
  const m = new Uint8Array(p.length + body2.length);
  m.set(p);
  m.set(body2, p.length);
  return m;
}
function signRevocationEpoch(guardianSecret, body2) {
  return {
    instance_id: body2.instance_id,
    grant_ref: body2.grant_ref,
    epoch: body2.epoch,
    set_size: body2.set_size,
    root: body2.root,
    issued_at: body2.issued_at,
    not_after: body2.not_after,
    guardian: b64u(publicKeyOf(guardianSecret)),
    sig: b64u(sign(guardianSecret, epochMessage(body2)))
  };
}
function checkRevocationEpoch(ep, o) {
  try {
    if (!ep || ep.guardian !== o.guardianPublic) return { ok: false, reason: "revocation epoch not signed by the pinned guardian" };
    if (!Number.isSafeInteger(ep.epoch) || ep.epoch < 0 || !Number.isSafeInteger(ep.set_size) || ep.set_size < 0) {
      return { ok: false, reason: "malformed revocation epoch" };
    }
    if (!verifyB64u(o.guardianPublic, epochMessage(ep), ep.sig)) return { ok: false, reason: "revocation epoch signature invalid" };
    if (o.grantRef !== void 0 && ep.grant_ref !== o.grantRef) return { ok: false, reason: "revocation epoch is for a different grant" };
    if (!(o.now <= ep.not_after)) return { ok: false, reason: "revocation epoch expired (stale revocation root)" };
    if (!(ep.issued_at <= o.now + 6e4)) return { ok: false, reason: "revocation epoch issued in the future" };
    if (o.lastAcceptedEpoch !== void 0 && ep.epoch < o.lastAcceptedEpoch) {
      return { ok: false, reason: `revocation epoch ${ep.epoch} is older than the last accepted ${o.lastAcceptedEpoch} (rollback)` };
    }
    if (o.pcactnEpoch !== void 0 && !(o.pcactnEpoch >= ep.epoch)) {
      return { ok: false, reason: `PCActn freshness.epoch ${o.pcactnEpoch} predates the revocation epoch ${ep.epoch}` };
    }
    return { ok: true };
  } catch {
    return { ok: false, reason: "revocation epoch check error" };
  }
}
function revokeMessage(grantRef, revokedCapId) {
  const body2 = canonicalBytes({ grant_ref: grantRef, revoked_cap_id: revokedCapId });
  const p = utf8("atlas-pca/revoke/v1\0");
  const m = new Uint8Array(p.length + body2.length);
  m.set(p);
  m.set(body2, p.length);
  return m;
}
function createRevocationChecker(opts) {
  return (ctx) => {
    let root = opts.root?.(ctx);
    let accepted;
    if (opts.epoch) {
      const ep = opts.epoch(ctx);
      if (!ep || !opts.guardianPublic) return { enforced: true, ok: false, reason: "no signed revocation epoch" };
      const chk = checkRevocationEpoch(ep, {
        guardianPublic: opts.guardianPublic,
        now: ctx.nowEpoch ?? Date.now(),
        grantRef: ctx.pcactn.grant_ref,
        lastAcceptedEpoch: opts.lastAcceptedEpoch?.(ctx),
        pcactnEpoch: ctx.pcactn.freshness?.epoch
      });
      if (!chk.ok) return { enforced: true, ok: false, reason: chk.reason };
      if (root !== void 0 && root !== ep.root) return { enforced: true, ok: false, reason: "revocation root does not match the signed epoch" };
      root = ep.root;
      accepted = ep;
    }
    if (!root) return { enforced: true, ok: false, reason: "no revocation root" };
    const ids = opts.ids ? opts.ids(ctx) : ctx.pcactn.cap_chain.map((c) => c.id);
    for (const id of ids) {
      const proof = opts.proofFor(id, ctx);
      if (!proof) return { enforced: true, ok: false, reason: `no non-membership proof for ${id}` };
      if (!verifyNonMembership(root, proof, id)) {
        return { enforced: true, ok: false, reason: `capability ${id} is revoked or proof invalid` };
      }
    }
    if (accepted) opts.onEpochAccepted?.(accepted, ctx);
    return { enforced: true, ok: true };
  };
}

// packages/pca/src/beacons.ts
var GLOBAL_SCOPE = "*";
var DOMAIN = "atlas-pca/beacon/v1\0";
function msg(b) {
  const body2 = canonicalBytes({ v: b.v, scope: b.scope, epoch: b.epoch, not_after: b.not_after, guardian: b.guardian });
  const p = utf8(DOMAIN);
  const m = new Uint8Array(p.length + body2.length);
  m.set(p);
  m.set(body2, p.length);
  return m;
}
function issueBeacon(args) {
  const { guardianSecret, epoch, notAfter } = args;
  if (!Number.isInteger(epoch) || !Number.isInteger(notAfter) || notAfter < epoch) {
    throw new RangeError("issueBeacon: need integer epoch <= notAfter");
  }
  const body2 = { v: 1, scope: args.scope ?? GLOBAL_SCOPE, epoch, not_after: notAfter, guardian: b64u(publicKeyOf(guardianSecret)) };
  return { ...body2, sig: b64u(sign(guardianSecret, msg(body2))) };
}
function verifyBeacon(beacon, guardianPublic, nowEpoch, scope) {
  try {
    const pub = typeof guardianPublic === "string" ? guardianPublic : b64u(guardianPublic);
    if (beacon.v !== 1 || beacon.guardian !== pub) return { ok: false, reason: "wrong guardian key" };
    if (!verifyB64u(pub, msg(beacon), beacon.sig)) return { ok: false, reason: "bad signature" };
    if (!Number.isInteger(beacon.epoch) || !Number.isInteger(beacon.not_after) || beacon.not_after < beacon.epoch) {
      return { ok: false, reason: "malformed window" };
    }
    if (nowEpoch < beacon.epoch) return { ok: false, reason: "not yet valid" };
    if (nowEpoch > beacon.not_after) return { ok: false, reason: "expired" };
    if (scope !== void 0 && beacon.scope !== GLOBAL_SCOPE && beacon.scope !== scope) {
      return { ok: false, reason: "scope not covered" };
    }
    return { ok: true };
  } catch {
    return { ok: false, reason: "malformed beacon" };
  }
}
function isFrozen(beacons, nowEpoch, guardianPublic, scope) {
  return !beacons.some((b) => verifyBeacon(b, guardianPublic, nowEpoch, scope).ok);
}
var LIVENESS_DOMAIN = "atlas-pca/beacon/v2\0";
var BEACON_EPOCH_MS = 6e4;
var BEACON_MAX_VALIDITY_MS = 60 * 6e4;
var BEACON_CLOCK_SKEW_MS = 3e4;
function livenessMsg(b) {
  const body2 = canonicalBytes({
    v: b.v,
    instance: b.instance,
    scope: b.scope,
    epoch: b.epoch,
    seq: b.seq,
    issued_at: b.issued_at,
    not_after: b.not_after,
    issuer: b.issuer
  });
  const p = utf8(LIVENESS_DOMAIN);
  const m = new Uint8Array(p.length + body2.length);
  m.set(p);
  m.set(body2, p.length);
  return m;
}
function livenessBeaconMessage(b) {
  return livenessMsg(b);
}
function issueLivenessBeacon(args) {
  const validity = args.validityMs ?? 5 * BEACON_EPOCH_MS;
  if (!Number.isInteger(args.seq) || args.seq < 0) throw new RangeError("issueLivenessBeacon: seq must be a non-negative integer");
  if (!Number.isInteger(args.issuedAt) || args.issuedAt < 0) throw new RangeError("issueLivenessBeacon: issuedAt must be an integer");
  if (!Number.isInteger(validity) || validity <= 0 || validity > BEACON_MAX_VALIDITY_MS) {
    throw new RangeError(`issueLivenessBeacon: validity must be in (0, ${BEACON_MAX_VALIDITY_MS}] ms`);
  }
  const body2 = {
    v: 2,
    instance: args.instance,
    scope: args.scope ?? GLOBAL_SCOPE,
    epoch: Math.floor(args.issuedAt / BEACON_EPOCH_MS),
    seq: args.seq,
    issued_at: args.issuedAt,
    not_after: args.issuedAt + validity,
    issuer: b64u(publicKeyOf(args.issuerSecret))
  };
  return { ...body2, sig: b64u(sign(args.issuerSecret, livenessMsg(body2))) };
}
function beaconRef(b) {
  return b64u(sha2563(canonicalBytes({ ...b })));
}
function verifyLivenessBeacon(b, o) {
  try {
    if (!b || b.v !== 2) return { ok: false, reason: "malformed beacon" };
    if (b.instance !== o.instance) return { ok: false, reason: "wrong instance" };
    if (!o.issuers.includes(b.issuer)) return { ok: false, reason: "issuer not pinned" };
    if (!verifyB64u(b.issuer, livenessMsg(b), b.sig)) return { ok: false, reason: "bad signature" };
    if (![b.epoch, b.seq, b.issued_at, b.not_after].every(Number.isInteger) || b.seq < 0) {
      return { ok: false, reason: "malformed window" };
    }
    if (b.not_after <= b.issued_at || b.not_after - b.issued_at > BEACON_MAX_VALIDITY_MS) {
      return { ok: false, reason: "validity exceeds the hard maximum" };
    }
    if (b.epoch !== Math.floor(b.issued_at / BEACON_EPOCH_MS)) return { ok: false, reason: "epoch does not match issued_at" };
    if (o.now + BEACON_CLOCK_SKEW_MS < b.issued_at) return { ok: false, reason: "not yet valid" };
    if (o.now > b.not_after) return { ok: false, reason: "expired" };
    if (o.scope !== void 0 && b.scope !== GLOBAL_SCOPE && b.scope !== o.scope) {
      return { ok: false, reason: "scope not covered" };
    }
    return { ok: true };
  } catch {
    return { ok: false, reason: "malformed beacon" };
  }
}
function acceptBeacon(prev, next) {
  if (prev && !(next.seq > prev.seq)) return { ok: false, reason: `replayed beacon: seq ${next.seq} <= ${prev.seq}` };
  return { ok: true };
}
function isFrozenLiveness(beacons, o) {
  return !beacons.some((b) => verifyLivenessBeacon(b, o).ok);
}

// packages/pca/src/attestation.ts
var DOMAIN2 = "atlas-pca/attest/v1\0";
var ATTEST_BIND_DOMAIN = "atlas-pca/attest-bind/v1\0";
var MAX_ATTESTATION_AGE_MS = 5 * 6e4;
function lp(s) {
  const b = utf8(s);
  const out = new Uint8Array(4 + b.length);
  new DataView(out.buffer).setUint32(0, b.length, false);
  out.set(b, 4);
  return out;
}
function attestationBinding(exp) {
  if (!exp || typeof exp.holderPub !== "string" || exp.holderPub.length === 0) throw new TypeError("binding: holderPub required");
  if (typeof exp.grantRef !== "string" || exp.grantRef.length === 0) throw new TypeError("binding: grantRef required");
  if (typeof exp.nonce !== "string" || exp.nonce.length === 0) throw new TypeError("binding: nonce required");
  if (!Number.isSafeInteger(exp.epoch) || exp.epoch < 0) throw new TypeError("binding: epoch must be a non-negative safe integer");
  const parts = [utf8(ATTEST_BIND_DOMAIN), lp(exp.holderPub), lp(exp.grantRef), new Uint8Array(8), lp(exp.nonce)];
  new DataView(parts[3].buffer).setBigUint64(0, BigInt(exp.epoch), false);
  let n = 0;
  for (const p of parts) n += p.length;
  const buf = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    buf.set(p, o);
    o += p.length;
  }
  return sha5122(buf);
}
function attestationBindingB64u(exp) {
  return b64u(attestationBinding(exp));
}
function attestMessage(body2) {
  const d = canonicalBytes(body2);
  const p = utf8(DOMAIN2);
  const m = new Uint8Array(p.length + d.length);
  m.set(p);
  m.set(d, p.length);
  return m;
}
function attestationDigest(doc) {
  return hashCanonical(doc);
}
function createDevAttestor(secret) {
  const publicKey = b64u(publicKeyOf(secret));
  return {
    publicKey,
    attest(claims) {
      const body2 = {
        model_id: claims.model_id,
        weights_digest: claims.weights_digest,
        runtime_measurement: claims.runtime_measurement,
        operator: claims.operator,
        nonce: claims.nonce,
        issued_at: claims.issued_at,
        expires_at: claims.expires_at,
        attestor: publicKey,
        mode: "software"
      };
      if (claims.holder_pub !== void 0 && claims.grant_ref !== void 0 && claims.epoch !== void 0) {
        body2.binding = attestationBindingB64u({
          holderPub: claims.holder_pub,
          grantRef: claims.grant_ref,
          epoch: claims.epoch,
          nonce: claims.nonce
        });
      }
      return { ...body2, sig: b64u(sign(secret, attestMessage(body2))) };
    }
  };
}
function attestationRegistry(docs) {
  const byNonce = /* @__PURE__ */ new Map();
  for (const d of Array.isArray(docs) ? docs : []) {
    if (d && typeof d.nonce === "string") byNonce.set(d.nonce, d);
  }
  return (ctx) => {
    const key = ctx?.pcactn?.attestation?.quote_digest;
    return typeof key === "string" ? byNonce.get(key) : void 0;
  };
}
function requiresAttestation(binding) {
  const b = binding ?? {};
  return Array.isArray(b.model_allowlist) && b.model_allowlist.length > 0 || typeof b.min_measurement === "string" && b.min_measurement.length > 0 || typeof b.operator === "string" && b.operator.length > 0 || Array.isArray(b.weights_allowlist) && b.weights_allowlist.length > 0;
}
function nonceBinds(doc, ctx) {
  return typeof doc?.nonce === "string" && doc.nonce === ctx?.pcactn?.attestation?.quote_digest;
}
function matchAgentBinding(id, binding) {
  const b = binding ?? {};
  if (Array.isArray(b.model_allowlist) && b.model_allowlist.length > 0 && !b.model_allowlist.includes(id.model_id)) {
    return `model_id ${id.model_id} not in model_allowlist`;
  }
  if (typeof b.min_measurement === "string" && b.min_measurement.length > 0 && id.runtime_measurement !== b.min_measurement) {
    return `runtime_measurement does not match required min_measurement`;
  }
  if (typeof b.operator === "string" && b.operator.length > 0 && id.operator !== b.operator) {
    return `operator ${id.operator} is not the bound operator`;
  }
  if (Array.isArray(b.weights_allowlist) && b.weights_allowlist.length > 0 && !b.weights_allowlist.includes(id.weights_digest)) {
    return `weights_digest not in weights_allowlist (model swap / fine-tune?)`;
  }
  return null;
}
async function verifyAttestation(input) {
  const doc = input.document;
  const present = !!doc && typeof doc === "object";
  const fail2 = (reason) => ({ ok: false, present, bound: false, reason });
  try {
    if (!present || !doc) return fail2("no attestation document for this action");
    const { ctx, expected, nowMs } = input;
    const trusted = new Set(input.trustedAttestorKeys);
    const skew = Number.isFinite(input.clockSkewMs) ? Math.max(0, input.clockSkewMs) : 0;
    const maxAge = Math.min(
      Number.isFinite(input.maxNonceAgeMs) && input.maxNonceAgeMs > 0 ? input.maxNonceAgeMs : MAX_ATTESTATION_AGE_MS,
      MAX_ATTESTATION_AGE_MS
    );
    let expectedBinding;
    try {
      expectedBinding = attestationBindingB64u(expected);
    } catch (e) {
      return fail2(`attestation binding not constructible: ${e instanceof Error ? e.message : "invalid"}`);
    }
    if (ctx?.pcactn?.grant_ref !== expected.grantRef) return fail2("attestation binding: PCActn grant_ref differs from expected grant");
    if (ctx?.pcactn?.attestation?.epoch !== expected.epoch) return fail2("attestation binding: PCActn attestation epoch differs from expected epoch");
    if (ctx?.pcactn?.attestation?.quote_digest !== expected.nonce) return fail2("attestation nonce does not bind to this PCActn");
    if (doc.nonce !== expected.nonce) return fail2("attestation nonce does not match the server-issued nonce");
    const nonceAgeCheck = () => {
      if (typeof expected.nonceIssuedAt !== "number" || !Number.isFinite(expected.nonceIssuedAt)) {
        return "server nonce issue time unknown (cannot establish freshness)";
      }
      if (nowMs + skew < expected.nonceIssuedAt) return "nonce issued in the future";
      if (nowMs - expected.nonceIssuedAt > maxAge + skew) return "attestation nonce expired (stale quote)";
      return null;
    };
    let identity;
    if (input.hardwareVerifier) {
      const nErr = nonceAgeCheck();
      if (nErr) return fail2(nErr);
      const hw = await input.hardwareVerifier.verify({ document: doc, ctx, nowMs, expected });
      if (!hw.ok) return fail2(`hardware attestation rejected: ${hw.reason ?? "invalid"}`);
      if (hw.bound !== true) return fail2("hardware verifier did not confirm report_data binding");
      if (!hw.measured) return fail2("hardware verifier returned no measured identity");
      identity = hw.measured;
    } else {
      if (doc.mode !== "software") return fail2(`document mode ${String(doc.mode)} needs a hardwareVerifier`);
      if (typeof doc.attestor !== "string" || !trusted.has(doc.attestor)) return fail2("attestor key is not trusted");
      const { sig, ...body2 } = doc;
      if (typeof sig !== "string" || !verifyB64u(doc.attestor, attestMessage(body2), sig)) {
        return fail2("attestation signature does not verify");
      }
      if (typeof doc.binding !== "string" || doc.binding.length === 0) return fail2("attestation is not bound (binding absent)");
      if (doc.binding !== expectedBinding) return fail2("attestation binding mismatch (holder/grant/epoch/nonce)");
      if (!Number.isFinite(doc.issued_at) || !Number.isFinite(doc.expires_at) || doc.expires_at < doc.issued_at) {
        return fail2("malformed attestation validity window");
      }
      if (nowMs + skew < doc.issued_at) return fail2("attestation not yet valid");
      if (nowMs - skew > doc.expires_at) return fail2("attestation expired");
      if (typeof expected.nonceIssuedAt === "number") {
        const nErr = nonceAgeCheck();
        if (nErr) return fail2(nErr);
      }
      identity = {
        model_id: doc.model_id,
        weights_digest: doc.weights_digest,
        runtime_measurement: doc.runtime_measurement,
        operator: doc.operator
      };
    }
    const env = readEnvelope(ctx.grant);
    const bindErr = matchAgentBinding(identity, env?.agent_binding);
    if (bindErr) return fail2(bindErr);
    return { ok: true, present: true, bound: true, identity };
  } catch (e) {
    return fail2(`attestation verification error (fail closed): ${e instanceof Error ? e.message : "unknown"}`);
  }
}
function createAttestationVerifier(opts) {
  const trusted = Array.isArray(opts.trustedAttestorKeys) ? opts.trustedAttestorKeys : [];
  const resolve2 = opts.resolveDocument ?? attestationRegistry([]);
  const clock = opts.now ?? (() => Date.now());
  return async (ctx) => {
    const fin4 = (v) => ({
      enforced: true,
      ok: v.ok,
      ...v.reason ? { reason: v.reason } : {},
      present: v.present,
      bound: v.bound
    });
    try {
      const document = resolve2(ctx);
      let expected;
      if (opts.expectedBinding) {
        expected = await opts.expectedBinding(ctx);
      } else if (opts.insecure_selfDeclaredNonce === true) {
        const chain2 = ctx?.pcactn?.cap_chain;
        const leaf = Array.isArray(chain2) && chain2.length > 0 ? chain2[chain2.length - 1] : ctx?.grant;
        expected = {
          holderPub: typeof leaf?.holder === "string" ? leaf.holder : "",
          grantRef: ctx?.pcactn?.grant_ref,
          epoch: ctx?.pcactn?.attestation?.epoch,
          nonce: ctx?.pcactn?.attestation?.quote_digest
        };
      }
      if (!expected) {
        return fin4({ ok: false, present: !!document, bound: false, reason: "no server-issued attestation nonce/binding available (fail closed)" });
      }
      return fin4(
        await verifyAttestation({
          document,
          ctx,
          expected,
          nowMs: clock(),
          trustedAttestorKeys: trusted,
          hardwareVerifier: opts.hardwareVerifier,
          maxNonceAgeMs: opts.maxNonceAgeMs,
          clockSkewMs: opts.clockSkewMs
        })
      );
    } catch (e) {
      return fin4({ ok: false, present: false, bound: false, reason: `attestation verification error (fail closed): ${e instanceof Error ? e.message : "unknown"}` });
    }
  };
}

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

// node_modules/.pnpm/@noble+curves@1.9.1/node_modules/@noble/curves/esm/abstract/weierstrass.js
function validateSigVerOpts(opts) {
  if (opts.lowS !== void 0)
    abool("lowS", opts.lowS);
  if (opts.prehash !== void 0)
    abool("prehash", opts.prehash);
}
function validatePointOpts(curve) {
  const opts = validateBasic(curve);
  validateObject(opts, {
    a: "field",
    b: "field"
  }, {
    allowInfinityPoint: "boolean",
    allowedPrivateKeyLengths: "array",
    clearCofactor: "function",
    fromBytes: "function",
    isTorsionFree: "function",
    toBytes: "function",
    wrapPrivateKey: "boolean"
  });
  const { endo, Fp: Fp2, a } = opts;
  if (endo) {
    if (!Fp2.eql(a, Fp2.ZERO)) {
      throw new Error("invalid endo: CURVE.a must be 0");
    }
    if (typeof endo !== "object" || typeof endo.beta !== "bigint" || typeof endo.splitScalar !== "function") {
      throw new Error('invalid endo: expected "beta": bigint and "splitScalar": function');
    }
  }
  return Object.freeze({ ...opts });
}
var DERErr = class extends Error {
  constructor(m = "") {
    super(m);
  }
};
var DER = {
  // asn.1 DER encoding utils
  Err: DERErr,
  // Basic building block is TLV (Tag-Length-Value)
  _tlv: {
    encode: (tag, data) => {
      const { Err: E } = DER;
      if (tag < 0 || tag > 256)
        throw new E("tlv.encode: wrong tag");
      if (data.length & 1)
        throw new E("tlv.encode: unpadded data");
      const dataLen = data.length / 2;
      const len = numberToHexUnpadded(dataLen);
      if (len.length / 2 & 128)
        throw new E("tlv.encode: long form length too big");
      const lenLen = dataLen > 127 ? numberToHexUnpadded(len.length / 2 | 128) : "";
      const t = numberToHexUnpadded(tag);
      return t + lenLen + len + data;
    },
    // v - value, l - left bytes (unparsed)
    decode(tag, data) {
      const { Err: E } = DER;
      let pos = 0;
      if (tag < 0 || tag > 256)
        throw new E("tlv.encode: wrong tag");
      if (data.length < 2 || data[pos++] !== tag)
        throw new E("tlv.decode: wrong tlv");
      const first = data[pos++];
      const isLong = !!(first & 128);
      let length = 0;
      if (!isLong)
        length = first;
      else {
        const lenLen = first & 127;
        if (!lenLen)
          throw new E("tlv.decode(long): indefinite length not supported");
        if (lenLen > 4)
          throw new E("tlv.decode(long): byte length is too big");
        const lengthBytes = data.subarray(pos, pos + lenLen);
        if (lengthBytes.length !== lenLen)
          throw new E("tlv.decode: length bytes not complete");
        if (lengthBytes[0] === 0)
          throw new E("tlv.decode(long): zero leftmost byte");
        for (const b of lengthBytes)
          length = length << 8 | b;
        pos += lenLen;
        if (length < 128)
          throw new E("tlv.decode(long): not minimal encoding");
      }
      const v = data.subarray(pos, pos + length);
      if (v.length !== length)
        throw new E("tlv.decode: wrong value length");
      return { v, l: data.subarray(pos + length) };
    }
  },
  // https://crypto.stackexchange.com/a/57734 Leftmost bit of first byte is 'negative' flag,
  // since we always use positive integers here. It must always be empty:
  // - add zero byte if exists
  // - if next byte doesn't have a flag, leading zero is not allowed (minimal encoding)
  _int: {
    encode(num) {
      const { Err: E } = DER;
      if (num < _0n6)
        throw new E("integer: negative integers are not allowed");
      let hex = numberToHexUnpadded(num);
      if (Number.parseInt(hex[0], 16) & 8)
        hex = "00" + hex;
      if (hex.length & 1)
        throw new E("unexpected DER parsing assertion: unpadded hex");
      return hex;
    },
    decode(data) {
      const { Err: E } = DER;
      if (data[0] & 128)
        throw new E("invalid signature integer: negative");
      if (data[0] === 0 && !(data[1] & 128))
        throw new E("invalid signature integer: unnecessary leading zero");
      return bytesToNumberBE(data);
    }
  },
  toSig(hex) {
    const { Err: E, _int: int, _tlv: tlv } = DER;
    const data = ensureBytes("signature", hex);
    const { v: seqBytes, l: seqLeftBytes } = tlv.decode(48, data);
    if (seqLeftBytes.length)
      throw new E("invalid signature: left bytes after parsing");
    const { v: rBytes, l: rLeftBytes } = tlv.decode(2, seqBytes);
    const { v: sBytes, l: sLeftBytes } = tlv.decode(2, rLeftBytes);
    if (sLeftBytes.length)
      throw new E("invalid signature: left bytes after parsing");
    return { r: int.decode(rBytes), s: int.decode(sBytes) };
  },
  hexFromSig(sig) {
    const { _tlv: tlv, _int: int } = DER;
    const rs = tlv.encode(2, int.encode(sig.r));
    const ss = tlv.encode(2, int.encode(sig.s));
    const seq = rs + ss;
    return tlv.encode(48, seq);
  }
};
function numToSizedHex(num, size) {
  return bytesToHex(numberToBytesBE(num, size));
}
var _0n6 = BigInt(0);
var _1n6 = BigInt(1);
var _2n4 = BigInt(2);
var _3n3 = BigInt(3);
var _4n2 = BigInt(4);
function weierstrassPoints(opts) {
  const CURVE = validatePointOpts(opts);
  const { Fp: Fp2 } = CURVE;
  const Fn = Field(CURVE.n, CURVE.nBitLength);
  const toBytes2 = CURVE.toBytes || ((_c, point, _isCompressed) => {
    const a = point.toAffine();
    return concatBytes2(Uint8Array.from([4]), Fp2.toBytes(a.x), Fp2.toBytes(a.y));
  });
  const fromBytes = CURVE.fromBytes || ((bytes2) => {
    const tail = bytes2.subarray(1);
    const x = Fp2.fromBytes(tail.subarray(0, Fp2.BYTES));
    const y = Fp2.fromBytes(tail.subarray(Fp2.BYTES, 2 * Fp2.BYTES));
    return { x, y };
  });
  function weierstrassEquation(x) {
    const { a, b } = CURVE;
    const x2 = Fp2.sqr(x);
    const x3 = Fp2.mul(x2, x);
    return Fp2.add(Fp2.add(x3, Fp2.mul(x, a)), b);
  }
  function isValidXY(x, y) {
    const left = Fp2.sqr(y);
    const right = weierstrassEquation(x);
    return Fp2.eql(left, right);
  }
  if (!isValidXY(CURVE.Gx, CURVE.Gy))
    throw new Error("bad curve params: generator point");
  const _4a3 = Fp2.mul(Fp2.pow(CURVE.a, _3n3), _4n2);
  const _27b2 = Fp2.mul(Fp2.sqr(CURVE.b), BigInt(27));
  if (Fp2.is0(Fp2.add(_4a3, _27b2)))
    throw new Error("bad curve params: a or b");
  function isWithinCurveOrder(num) {
    return inRange(num, _1n6, CURVE.n);
  }
  function normPrivateKeyToScalar(key) {
    const { allowedPrivateKeyLengths: lengths, nByteLength, wrapPrivateKey, n: N } = CURVE;
    if (lengths && typeof key !== "bigint") {
      if (isBytes3(key))
        key = bytesToHex(key);
      if (typeof key !== "string" || !lengths.includes(key.length))
        throw new Error("invalid private key");
      key = key.padStart(nByteLength * 2, "0");
    }
    let num;
    try {
      num = typeof key === "bigint" ? key : bytesToNumberBE(ensureBytes("private key", key, nByteLength));
    } catch (error) {
      throw new Error("invalid private key, expected hex or " + nByteLength + " bytes, got " + typeof key);
    }
    if (wrapPrivateKey)
      num = mod(num, N);
    aInRange("private key", num, _1n6, N);
    return num;
  }
  function aprjpoint(other) {
    if (!(other instanceof Point))
      throw new Error("ProjectivePoint expected");
  }
  const toAffineMemo = memoized((p, iz) => {
    const { px: x, py: y, pz: z } = p;
    if (Fp2.eql(z, Fp2.ONE))
      return { x, y };
    const is0 = p.is0();
    if (iz == null)
      iz = is0 ? Fp2.ONE : Fp2.inv(z);
    const ax = Fp2.mul(x, iz);
    const ay = Fp2.mul(y, iz);
    const zz = Fp2.mul(z, iz);
    if (is0)
      return { x: Fp2.ZERO, y: Fp2.ZERO };
    if (!Fp2.eql(zz, Fp2.ONE))
      throw new Error("invZ was invalid");
    return { x: ax, y: ay };
  });
  const assertValidMemo = memoized((p) => {
    if (p.is0()) {
      if (CURVE.allowInfinityPoint && !Fp2.is0(p.py))
        return;
      throw new Error("bad point: ZERO");
    }
    const { x, y } = p.toAffine();
    if (!Fp2.isValid(x) || !Fp2.isValid(y))
      throw new Error("bad point: x or y not FE");
    if (!isValidXY(x, y))
      throw new Error("bad point: equation left != right");
    if (!p.isTorsionFree())
      throw new Error("bad point: not in prime-order subgroup");
    return true;
  });
  class Point {
    constructor(px, py, pz) {
      if (px == null || !Fp2.isValid(px))
        throw new Error("x required");
      if (py == null || !Fp2.isValid(py) || Fp2.is0(py))
        throw new Error("y required");
      if (pz == null || !Fp2.isValid(pz))
        throw new Error("z required");
      this.px = px;
      this.py = py;
      this.pz = pz;
      Object.freeze(this);
    }
    // Does not validate if the point is on-curve.
    // Use fromHex instead, or call assertValidity() later.
    static fromAffine(p) {
      const { x, y } = p || {};
      if (!p || !Fp2.isValid(x) || !Fp2.isValid(y))
        throw new Error("invalid affine point");
      if (p instanceof Point)
        throw new Error("projective point not allowed");
      const is0 = (i) => Fp2.eql(i, Fp2.ZERO);
      if (is0(x) && is0(y))
        return Point.ZERO;
      return new Point(x, y, Fp2.ONE);
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    /**
     * Takes a bunch of Projective Points but executes only one
     * inversion on all of them. Inversion is very slow operation,
     * so this improves performance massively.
     * Optimization: converts a list of projective points to a list of identical points with Z=1.
     */
    static normalizeZ(points) {
      const toInv = FpInvertBatch(Fp2, points.map((p) => p.pz));
      return points.map((p, i) => p.toAffine(toInv[i])).map(Point.fromAffine);
    }
    /**
     * Converts hash string or Uint8Array to Point.
     * @param hex short/long ECDSA hex
     */
    static fromHex(hex) {
      const P3 = Point.fromAffine(fromBytes(ensureBytes("pointHex", hex)));
      P3.assertValidity();
      return P3;
    }
    // Multiplies generator point by privateKey.
    static fromPrivateKey(privateKey) {
      return Point.BASE.multiply(normPrivateKeyToScalar(privateKey));
    }
    // Multiscalar Multiplication
    static msm(points, scalars) {
      return pippenger(Point, Fn, points, scalars);
    }
    // "Private method", don't use it directly
    _setWindowSize(windowSize) {
      wnaf.setWindowSize(this, windowSize);
    }
    // A point on curve is valid if it conforms to equation.
    assertValidity() {
      assertValidMemo(this);
    }
    hasEvenY() {
      const { y } = this.toAffine();
      if (Fp2.isOdd)
        return !Fp2.isOdd(y);
      throw new Error("Field doesn't support isOdd");
    }
    /**
     * Compare one point to another.
     */
    equals(other) {
      aprjpoint(other);
      const { px: X1, py: Y1, pz: Z1 } = this;
      const { px: X2, py: Y2, pz: Z2 } = other;
      const U1 = Fp2.eql(Fp2.mul(X1, Z2), Fp2.mul(X2, Z1));
      const U2 = Fp2.eql(Fp2.mul(Y1, Z2), Fp2.mul(Y2, Z1));
      return U1 && U2;
    }
    /**
     * Flips point to one corresponding to (x, -y) in Affine coordinates.
     */
    negate() {
      return new Point(this.px, Fp2.neg(this.py), this.pz);
    }
    // Renes-Costello-Batina exception-free doubling formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 3
    // Cost: 8M + 3S + 3*a + 2*b3 + 15add.
    double() {
      const { a, b } = CURVE;
      const b3 = Fp2.mul(b, _3n3);
      const { px: X1, py: Y1, pz: Z1 } = this;
      let X3 = Fp2.ZERO, Y3 = Fp2.ZERO, Z3 = Fp2.ZERO;
      let t0 = Fp2.mul(X1, X1);
      let t1 = Fp2.mul(Y1, Y1);
      let t2 = Fp2.mul(Z1, Z1);
      let t3 = Fp2.mul(X1, Y1);
      t3 = Fp2.add(t3, t3);
      Z3 = Fp2.mul(X1, Z1);
      Z3 = Fp2.add(Z3, Z3);
      X3 = Fp2.mul(a, Z3);
      Y3 = Fp2.mul(b3, t2);
      Y3 = Fp2.add(X3, Y3);
      X3 = Fp2.sub(t1, Y3);
      Y3 = Fp2.add(t1, Y3);
      Y3 = Fp2.mul(X3, Y3);
      X3 = Fp2.mul(t3, X3);
      Z3 = Fp2.mul(b3, Z3);
      t2 = Fp2.mul(a, t2);
      t3 = Fp2.sub(t0, t2);
      t3 = Fp2.mul(a, t3);
      t3 = Fp2.add(t3, Z3);
      Z3 = Fp2.add(t0, t0);
      t0 = Fp2.add(Z3, t0);
      t0 = Fp2.add(t0, t2);
      t0 = Fp2.mul(t0, t3);
      Y3 = Fp2.add(Y3, t0);
      t2 = Fp2.mul(Y1, Z1);
      t2 = Fp2.add(t2, t2);
      t0 = Fp2.mul(t2, t3);
      X3 = Fp2.sub(X3, t0);
      Z3 = Fp2.mul(t2, t1);
      Z3 = Fp2.add(Z3, Z3);
      Z3 = Fp2.add(Z3, Z3);
      return new Point(X3, Y3, Z3);
    }
    // Renes-Costello-Batina exception-free addition formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 1
    // Cost: 12M + 0S + 3*a + 3*b3 + 23add.
    add(other) {
      aprjpoint(other);
      const { px: X1, py: Y1, pz: Z1 } = this;
      const { px: X2, py: Y2, pz: Z2 } = other;
      let X3 = Fp2.ZERO, Y3 = Fp2.ZERO, Z3 = Fp2.ZERO;
      const a = CURVE.a;
      const b3 = Fp2.mul(CURVE.b, _3n3);
      let t0 = Fp2.mul(X1, X2);
      let t1 = Fp2.mul(Y1, Y2);
      let t2 = Fp2.mul(Z1, Z2);
      let t3 = Fp2.add(X1, Y1);
      let t4 = Fp2.add(X2, Y2);
      t3 = Fp2.mul(t3, t4);
      t4 = Fp2.add(t0, t1);
      t3 = Fp2.sub(t3, t4);
      t4 = Fp2.add(X1, Z1);
      let t5 = Fp2.add(X2, Z2);
      t4 = Fp2.mul(t4, t5);
      t5 = Fp2.add(t0, t2);
      t4 = Fp2.sub(t4, t5);
      t5 = Fp2.add(Y1, Z1);
      X3 = Fp2.add(Y2, Z2);
      t5 = Fp2.mul(t5, X3);
      X3 = Fp2.add(t1, t2);
      t5 = Fp2.sub(t5, X3);
      Z3 = Fp2.mul(a, t4);
      X3 = Fp2.mul(b3, t2);
      Z3 = Fp2.add(X3, Z3);
      X3 = Fp2.sub(t1, Z3);
      Z3 = Fp2.add(t1, Z3);
      Y3 = Fp2.mul(X3, Z3);
      t1 = Fp2.add(t0, t0);
      t1 = Fp2.add(t1, t0);
      t2 = Fp2.mul(a, t2);
      t4 = Fp2.mul(b3, t4);
      t1 = Fp2.add(t1, t2);
      t2 = Fp2.sub(t0, t2);
      t2 = Fp2.mul(a, t2);
      t4 = Fp2.add(t4, t2);
      t0 = Fp2.mul(t1, t4);
      Y3 = Fp2.add(Y3, t0);
      t0 = Fp2.mul(t5, t4);
      X3 = Fp2.mul(t3, X3);
      X3 = Fp2.sub(X3, t0);
      t0 = Fp2.mul(t3, t1);
      Z3 = Fp2.mul(t5, Z3);
      Z3 = Fp2.add(Z3, t0);
      return new Point(X3, Y3, Z3);
    }
    subtract(other) {
      return this.add(other.negate());
    }
    is0() {
      return this.equals(Point.ZERO);
    }
    wNAF(n) {
      return wnaf.wNAFCached(this, n, Point.normalizeZ);
    }
    /**
     * Non-constant-time multiplication. Uses double-and-add algorithm.
     * It's faster, but should only be used when you don't care about
     * an exposed private key e.g. sig verification, which works over *public* keys.
     */
    multiplyUnsafe(sc) {
      const { endo: endo2, n: N } = CURVE;
      aInRange("scalar", sc, _0n6, N);
      const I = Point.ZERO;
      if (sc === _0n6)
        return I;
      if (this.is0() || sc === _1n6)
        return this;
      if (!endo2 || wnaf.hasPrecomputes(this))
        return wnaf.wNAFCachedUnsafe(this, sc, Point.normalizeZ);
      let { k1neg, k1, k2neg, k2 } = endo2.splitScalar(sc);
      let k1p = I;
      let k2p = I;
      let d = this;
      while (k1 > _0n6 || k2 > _0n6) {
        if (k1 & _1n6)
          k1p = k1p.add(d);
        if (k2 & _1n6)
          k2p = k2p.add(d);
        d = d.double();
        k1 >>= _1n6;
        k2 >>= _1n6;
      }
      if (k1neg)
        k1p = k1p.negate();
      if (k2neg)
        k2p = k2p.negate();
      k2p = new Point(Fp2.mul(k2p.px, endo2.beta), k2p.py, k2p.pz);
      return k1p.add(k2p);
    }
    /**
     * Constant time multiplication.
     * Uses wNAF method. Windowed method may be 10% faster,
     * but takes 2x longer to generate and consumes 2x memory.
     * Uses precomputes when available.
     * Uses endomorphism for Koblitz curves.
     * @param scalar by which the point would be multiplied
     * @returns New point
     */
    multiply(scalar) {
      const { endo: endo2, n: N } = CURVE;
      aInRange("scalar", scalar, _1n6, N);
      let point, fake;
      if (endo2) {
        const { k1neg, k1, k2neg, k2 } = endo2.splitScalar(scalar);
        let { p: k1p, f: f1p } = this.wNAF(k1);
        let { p: k2p, f: f2p } = this.wNAF(k2);
        k1p = wnaf.constTimeNegate(k1neg, k1p);
        k2p = wnaf.constTimeNegate(k2neg, k2p);
        k2p = new Point(Fp2.mul(k2p.px, endo2.beta), k2p.py, k2p.pz);
        point = k1p.add(k2p);
        fake = f1p.add(f2p);
      } else {
        const { p, f } = this.wNAF(scalar);
        point = p;
        fake = f;
      }
      return Point.normalizeZ([point, fake])[0];
    }
    /**
     * Efficiently calculate `aP + bQ`. Unsafe, can expose private key, if used incorrectly.
     * Not using Strauss-Shamir trick: precomputation tables are faster.
     * The trick could be useful if both P and Q are not G (not in our case).
     * @returns non-zero affine point
     */
    multiplyAndAddUnsafe(Q, a, b) {
      const G = Point.BASE;
      const mul = (P3, a2) => a2 === _0n6 || a2 === _1n6 || !P3.equals(G) ? P3.multiplyUnsafe(a2) : P3.multiply(a2);
      const sum = mul(this, a).add(mul(Q, b));
      return sum.is0() ? void 0 : sum;
    }
    // Converts Projective point to affine (x, y) coordinates.
    // Can accept precomputed Z^-1 - for example, from invertBatch.
    // (x, y, z) ∋ (x=x/z, y=y/z)
    toAffine(iz) {
      return toAffineMemo(this, iz);
    }
    isTorsionFree() {
      const { h: cofactor, isTorsionFree } = CURVE;
      if (cofactor === _1n6)
        return true;
      if (isTorsionFree)
        return isTorsionFree(Point, this);
      throw new Error("isTorsionFree() has not been declared for the elliptic curve");
    }
    clearCofactor() {
      const { h: cofactor, clearCofactor } = CURVE;
      if (cofactor === _1n6)
        return this;
      if (clearCofactor)
        return clearCofactor(Point, this);
      return this.multiplyUnsafe(CURVE.h);
    }
    toRawBytes(isCompressed = true) {
      abool("isCompressed", isCompressed);
      this.assertValidity();
      return toBytes2(Point, this, isCompressed);
    }
    toHex(isCompressed = true) {
      abool("isCompressed", isCompressed);
      return bytesToHex(this.toRawBytes(isCompressed));
    }
  }
  Point.BASE = new Point(CURVE.Gx, CURVE.Gy, Fp2.ONE);
  Point.ZERO = new Point(Fp2.ZERO, Fp2.ONE, Fp2.ZERO);
  const { endo, nBitLength } = CURVE;
  const wnaf = wNAF(Point, endo ? Math.ceil(nBitLength / 2) : nBitLength);
  return {
    CURVE,
    ProjectivePoint: Point,
    normPrivateKeyToScalar,
    weierstrassEquation,
    isWithinCurveOrder
  };
}
function validateOpts2(curve) {
  const opts = validateBasic(curve);
  validateObject(opts, {
    hash: "hash",
    hmac: "function",
    randomBytes: "function"
  }, {
    bits2int: "function",
    bits2int_modN: "function",
    lowS: "boolean"
  });
  return Object.freeze({ lowS: true, ...opts });
}
function weierstrass(curveDef) {
  const CURVE = validateOpts2(curveDef);
  const { Fp: Fp2, n: CURVE_ORDER, nByteLength, nBitLength } = CURVE;
  const compressedLen = Fp2.BYTES + 1;
  const uncompressedLen = 2 * Fp2.BYTES + 1;
  function modN(a) {
    return mod(a, CURVE_ORDER);
  }
  function invN(a) {
    return invert(a, CURVE_ORDER);
  }
  const { ProjectivePoint: Point, normPrivateKeyToScalar, weierstrassEquation, isWithinCurveOrder } = weierstrassPoints({
    ...CURVE,
    toBytes(_c, point, isCompressed) {
      const a = point.toAffine();
      const x = Fp2.toBytes(a.x);
      const cat2 = concatBytes2;
      abool("isCompressed", isCompressed);
      if (isCompressed) {
        return cat2(Uint8Array.from([point.hasEvenY() ? 2 : 3]), x);
      } else {
        return cat2(Uint8Array.from([4]), x, Fp2.toBytes(a.y));
      }
    },
    fromBytes(bytes2) {
      const len = bytes2.length;
      const head = bytes2[0];
      const tail = bytes2.subarray(1);
      if (len === compressedLen && (head === 2 || head === 3)) {
        const x = bytesToNumberBE(tail);
        if (!inRange(x, _1n6, Fp2.ORDER))
          throw new Error("Point is not on curve");
        const y2 = weierstrassEquation(x);
        let y;
        try {
          y = Fp2.sqrt(y2);
        } catch (sqrtError) {
          const suffix = sqrtError instanceof Error ? ": " + sqrtError.message : "";
          throw new Error("Point is not on curve" + suffix);
        }
        const isYOdd = (y & _1n6) === _1n6;
        const isHeadOdd = (head & 1) === 1;
        if (isHeadOdd !== isYOdd)
          y = Fp2.neg(y);
        return { x, y };
      } else if (len === uncompressedLen && head === 4) {
        const x = Fp2.fromBytes(tail.subarray(0, Fp2.BYTES));
        const y = Fp2.fromBytes(tail.subarray(Fp2.BYTES, 2 * Fp2.BYTES));
        return { x, y };
      } else {
        const cl = compressedLen;
        const ul = uncompressedLen;
        throw new Error("invalid Point, expected length of " + cl + ", or uncompressed " + ul + ", got " + len);
      }
    }
  });
  function isBiggerThanHalfOrder(number) {
    const HALF = CURVE_ORDER >> _1n6;
    return number > HALF;
  }
  function normalizeS(s) {
    return isBiggerThanHalfOrder(s) ? modN(-s) : s;
  }
  const slcNum = (b, from, to) => bytesToNumberBE(b.slice(from, to));
  class Signature {
    constructor(r, s, recovery) {
      aInRange("r", r, _1n6, CURVE_ORDER);
      aInRange("s", s, _1n6, CURVE_ORDER);
      this.r = r;
      this.s = s;
      if (recovery != null)
        this.recovery = recovery;
      Object.freeze(this);
    }
    // pair (bytes of r, bytes of s)
    static fromCompact(hex) {
      const l = nByteLength;
      hex = ensureBytes("compactSignature", hex, l * 2);
      return new Signature(slcNum(hex, 0, l), slcNum(hex, l, 2 * l));
    }
    // DER encoded ECDSA signature
    // https://bitcoin.stackexchange.com/questions/57644/what-are-the-parts-of-a-bitcoin-transaction-input-script
    static fromDER(hex) {
      const { r, s } = DER.toSig(ensureBytes("DER", hex));
      return new Signature(r, s);
    }
    /**
     * @todo remove
     * @deprecated
     */
    assertValidity() {
    }
    addRecoveryBit(recovery) {
      return new Signature(this.r, this.s, recovery);
    }
    recoverPublicKey(msgHash) {
      const { r, s, recovery: rec } = this;
      const h = bits2int_modN(ensureBytes("msgHash", msgHash));
      if (rec == null || ![0, 1, 2, 3].includes(rec))
        throw new Error("recovery id invalid");
      const radj = rec === 2 || rec === 3 ? r + CURVE.n : r;
      if (radj >= Fp2.ORDER)
        throw new Error("recovery id 2 or 3 invalid");
      const prefix = (rec & 1) === 0 ? "02" : "03";
      const R = Point.fromHex(prefix + numToSizedHex(radj, Fp2.BYTES));
      const ir = invN(radj);
      const u1 = modN(-h * ir);
      const u2 = modN(s * ir);
      const Q = Point.BASE.multiplyAndAddUnsafe(R, u1, u2);
      if (!Q)
        throw new Error("point at infinify");
      Q.assertValidity();
      return Q;
    }
    // Signatures should be low-s, to prevent malleability.
    hasHighS() {
      return isBiggerThanHalfOrder(this.s);
    }
    normalizeS() {
      return this.hasHighS() ? new Signature(this.r, modN(-this.s), this.recovery) : this;
    }
    // DER-encoded
    toDERRawBytes() {
      return hexToBytes(this.toDERHex());
    }
    toDERHex() {
      return DER.hexFromSig(this);
    }
    // padded bytes of r, then padded bytes of s
    toCompactRawBytes() {
      return hexToBytes(this.toCompactHex());
    }
    toCompactHex() {
      const l = nByteLength;
      return numToSizedHex(this.r, l) + numToSizedHex(this.s, l);
    }
  }
  const utils = {
    isValidPrivateKey(privateKey) {
      try {
        normPrivateKeyToScalar(privateKey);
        return true;
      } catch (error) {
        return false;
      }
    },
    normPrivateKeyToScalar,
    /**
     * Produces cryptographically secure private key from random of size
     * (groupLen + ceil(groupLen / 2)) with modulo bias being negligible.
     */
    randomPrivateKey: () => {
      const length = getMinHashLength(CURVE.n);
      return mapHashToField(CURVE.randomBytes(length), CURVE.n);
    },
    /**
     * Creates precompute table for an arbitrary EC point. Makes point "cached".
     * Allows to massively speed-up `point.multiply(scalar)`.
     * @returns cached point
     * @example
     * const fast = utils.precompute(8, ProjectivePoint.fromHex(someonesPubKey));
     * fast.multiply(privKey); // much faster ECDH now
     */
    precompute(windowSize = 8, point = Point.BASE) {
      point._setWindowSize(windowSize);
      point.multiply(BigInt(3));
      return point;
    }
  };
  function getPublicKey(privateKey, isCompressed = true) {
    return Point.fromPrivateKey(privateKey).toRawBytes(isCompressed);
  }
  function isProbPub(item) {
    if (typeof item === "bigint")
      return false;
    if (item instanceof Point)
      return true;
    const arr = ensureBytes("key", item);
    const len = arr.length;
    const fpl = Fp2.BYTES;
    const compLen = fpl + 1;
    const uncompLen = 2 * fpl + 1;
    if (CURVE.allowedPrivateKeyLengths || nByteLength === compLen) {
      return void 0;
    } else {
      return len === compLen || len === uncompLen;
    }
  }
  function getSharedSecret(privateA, publicB, isCompressed = true) {
    if (isProbPub(privateA) === true)
      throw new Error("first arg must be private key");
    if (isProbPub(publicB) === false)
      throw new Error("second arg must be public key");
    const b = Point.fromHex(publicB);
    return b.multiply(normPrivateKeyToScalar(privateA)).toRawBytes(isCompressed);
  }
  const bits2int = CURVE.bits2int || function(bytes2) {
    if (bytes2.length > 8192)
      throw new Error("input is too large");
    const num = bytesToNumberBE(bytes2);
    const delta = bytes2.length * 8 - nBitLength;
    return delta > 0 ? num >> BigInt(delta) : num;
  };
  const bits2int_modN = CURVE.bits2int_modN || function(bytes2) {
    return modN(bits2int(bytes2));
  };
  const ORDER_MASK = bitMask(nBitLength);
  function int2octets(num) {
    aInRange("num < 2^" + nBitLength, num, _0n6, ORDER_MASK);
    return numberToBytesBE(num, nByteLength);
  }
  function prepSig(msgHash, privateKey, opts = defaultSigOpts) {
    if (["recovered", "canonical"].some((k) => k in opts))
      throw new Error("sign() legacy options not supported");
    const { hash, randomBytes: randomBytes2 } = CURVE;
    let { lowS, prehash, extraEntropy: ent } = opts;
    if (lowS == null)
      lowS = true;
    msgHash = ensureBytes("msgHash", msgHash);
    validateSigVerOpts(opts);
    if (prehash)
      msgHash = ensureBytes("prehashed msgHash", hash(msgHash));
    const h1int = bits2int_modN(msgHash);
    const d = normPrivateKeyToScalar(privateKey);
    const seedArgs = [int2octets(d), int2octets(h1int)];
    if (ent != null && ent !== false) {
      const e = ent === true ? randomBytes2(Fp2.BYTES) : ent;
      seedArgs.push(ensureBytes("extraEntropy", e));
    }
    const seed = concatBytes2(...seedArgs);
    const m = h1int;
    function k2sig(kBytes) {
      const k = bits2int(kBytes);
      if (!isWithinCurveOrder(k))
        return;
      const ik = invN(k);
      const q = Point.BASE.multiply(k).toAffine();
      const r = modN(q.x);
      if (r === _0n6)
        return;
      const s = modN(ik * modN(m + r * d));
      if (s === _0n6)
        return;
      let recovery = (q.x === r ? 0 : 2) | Number(q.y & _1n6);
      let normS = s;
      if (lowS && isBiggerThanHalfOrder(s)) {
        normS = normalizeS(s);
        recovery ^= 1;
      }
      return new Signature(r, normS, recovery);
    }
    return { seed, k2sig };
  }
  const defaultSigOpts = { lowS: CURVE.lowS, prehash: false };
  const defaultVerOpts = { lowS: CURVE.lowS, prehash: false };
  function sign2(msgHash, privKey, opts = defaultSigOpts) {
    const { seed, k2sig } = prepSig(msgHash, privKey, opts);
    const C = CURVE;
    const drbg = createHmacDrbg(C.hash.outputLen, C.nByteLength, C.hmac);
    return drbg(seed, k2sig);
  }
  Point.BASE._setWindowSize(8);
  function verify2(signature, msgHash, publicKey, opts = defaultVerOpts) {
    const sg = signature;
    msgHash = ensureBytes("msgHash", msgHash);
    publicKey = ensureBytes("publicKey", publicKey);
    const { lowS, prehash, format } = opts;
    validateSigVerOpts(opts);
    if ("strict" in opts)
      throw new Error("options.strict was renamed to lowS");
    if (format !== void 0 && format !== "compact" && format !== "der")
      throw new Error("format must be compact or der");
    const isHex = typeof sg === "string" || isBytes3(sg);
    const isObj6 = !isHex && !format && typeof sg === "object" && sg !== null && typeof sg.r === "bigint" && typeof sg.s === "bigint";
    if (!isHex && !isObj6)
      throw new Error("invalid signature, expected Uint8Array, hex string or Signature instance");
    let _sig = void 0;
    let P3;
    try {
      if (isObj6)
        _sig = new Signature(sg.r, sg.s);
      if (isHex) {
        try {
          if (format !== "compact")
            _sig = Signature.fromDER(sg);
        } catch (derError) {
          if (!(derError instanceof DER.Err))
            throw derError;
        }
        if (!_sig && format !== "der")
          _sig = Signature.fromCompact(sg);
      }
      P3 = Point.fromHex(publicKey);
    } catch (error) {
      return false;
    }
    if (!_sig)
      return false;
    if (lowS && _sig.hasHighS())
      return false;
    if (prehash)
      msgHash = CURVE.hash(msgHash);
    const { r, s } = _sig;
    const h = bits2int_modN(msgHash);
    const is = invN(s);
    const u1 = modN(h * is);
    const u2 = modN(r * is);
    const R = Point.BASE.multiplyAndAddUnsafe(P3, u1, u2)?.toAffine();
    if (!R)
      return false;
    const v = modN(R.x);
    return v === r;
  }
  return {
    CURVE,
    getPublicKey,
    getSharedSecret,
    sign: sign2,
    verify: verify2,
    ProjectivePoint: Point,
    Signature,
    utils
  };
}

// node_modules/.pnpm/@noble+curves@1.9.1/node_modules/@noble/curves/esm/_shortw_utils.js
function getHash(hash) {
  return {
    hash,
    hmac: (key, ...msgs) => hmac(hash, key, concatBytes(...msgs)),
    randomBytes
  };
}
function createCurve(curveDef, defHash) {
  const create = (hash) => weierstrass({ ...curveDef, ...getHash(hash) });
  return { ...create(defHash), create };
}

// node_modules/.pnpm/@noble+curves@1.9.1/node_modules/@noble/curves/esm/nist.js
var Fp256 = Field(BigInt("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"));
var p256_a = Fp256.create(BigInt("-3"));
var p256_b = BigInt("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
var p256 = createCurve({
  a: p256_a,
  b: p256_b,
  Fp: Fp256,
  n: BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
  Gx: BigInt("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
  Gy: BigInt("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
  h: BigInt(1),
  lowS: false
}, sha256);
var Fp384 = Field(BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"));
var p384_a = Fp384.create(BigInt("-3"));
var p384_b = BigInt("0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef");
var p384 = createCurve({
  a: p384_a,
  b: p384_b,
  Fp: Fp384,
  n: BigInt("0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
  Gx: BigInt("0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"),
  Gy: BigInt("0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),
  h: BigInt(1),
  lowS: false
}, sha384);
var Fp521 = Field(BigInt("0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
var p521_a = Fp521.create(BigInt("-3"));
var p521_b = BigInt("0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00");
var p521 = createCurve({
  a: p521_a,
  b: p521_b,
  Fp: Fp521,
  n: BigInt("0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"),
  Gx: BigInt("0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66"),
  Gy: BigInt("0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"),
  h: BigInt(1),
  lowS: false,
  allowedPrivateKeyLengths: [130, 131, 132]
  // P521 keys are variable-length. Normalize to 132b
}, sha512);

// node_modules/.pnpm/@noble+curves@1.9.1/node_modules/@noble/curves/esm/p384.js
var p3842 = p384;

// packages/pca/src/hardware-sevsnp.ts
var OFF = {
  VERSION: 0,
  //            u32   report format version (>= 2 for the layout below)
  GUEST_SVN: 4,
  //          u32   guest security version
  POLICY: 8,
  //             u64   guest policy
  FAMILY_ID: 16,
  //          16 B  guest family id
  IMAGE_ID: 32,
  //           16 B  guest image id
  VMPL: 48,
  //               u32   VMPL the report was requested at
  SIGNATURE_ALGO: 52,
  //     u32   1 = ECDSA_P384_SHA384
  CURRENT_TCB: 56,
  //        u64   current TCB version
  PLATFORM_INFO: 64,
  //      u64   platform info (SMT / TSME ...)
  // 0x048 u32 flags (AUTHOR_KEY_EN bit0, MASK_CHIP_KEY bit1, SIGNING_KEY bits4:2); 0x04C u32 reserved
  REPORT_DATA: 80,
  //        64 B  guest-supplied data — the nonce binding lives here
  MEASUREMENT: 144,
  //        48 B  launch measurement (hardware-authoritative)
  HOST_DATA: 192,
  //          32 B  data the host/owner supplied at launch
  ID_KEY_DIGEST: 224,
  //      48 B  SHA-384 of the ID key
  AUTHOR_KEY_DIGEST: 272,
  //  48 B  SHA-384 of the author key (zero if AUTHOR_KEY_EN=0)
  REPORT_ID: 320,
  //          32 B  report id
  REPORT_ID_MA: 352,
  //       32 B  report id of the migration agent
  REPORTED_TCB: 384,
  //       u64   reported TCB version
  // 0x188 reserved (24 B)
  CHIP_ID: 416,
  //            64 B  unique chip id (hardware operator identity)
  // ... reserved / build fields ...
  SIGNED_END: 672,
  //         signed region is [0x000, 0x2A0)
  SIG_R: 672,
  //              72 B  signature r, LITTLE-ENDIAN (P-384 uses the low 48 B)
  SIG_S: 744,
  //              72 B  signature s, LITTLE-ENDIAN
  REPORT_LEN: 1184
  //         1184  canonical report size (signature block is 0x2A0..0x4A0)
};
var SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384 = 1;
function u32le(dv, off) {
  return dv.getUint32(off, true);
}
function u64le(dv, off) {
  return dv.getBigUint64(off, true);
}
function slice(bytes2, off, len) {
  return bytes2.slice(off, off + len);
}
function leToBigInt(le) {
  let n = 0n;
  for (let i = le.length - 1; i >= 0; i--) n = n << 8n | BigInt(le[i]);
  return n;
}
function toHex(bytes2) {
  let s = "";
  for (let i = 0; i < bytes2.length; i++) s += bytes2[i].toString(16).padStart(2, "0");
  return s;
}
function parseSevSnpReport(bytes2) {
  if (!(bytes2 instanceof Uint8Array)) throw new TypeError("parseSevSnpReport: expected Uint8Array");
  const minLen = OFF.SIG_S + 72;
  if (bytes2.length < minLen) {
    throw new RangeError(`parseSevSnpReport: report too short (${bytes2.length} < ${minLen})`);
  }
  const dv = new DataView(bytes2.buffer, bytes2.byteOffset, bytes2.byteLength);
  return {
    version: u32le(dv, OFF.VERSION),
    guest_svn: u32le(dv, OFF.GUEST_SVN),
    policy: u64le(dv, OFF.POLICY),
    family_id: slice(bytes2, OFF.FAMILY_ID, 16),
    image_id: slice(bytes2, OFF.IMAGE_ID, 16),
    vmpl: u32le(dv, OFF.VMPL),
    signature_algo: u32le(dv, OFF.SIGNATURE_ALGO),
    current_tcb: u64le(dv, OFF.CURRENT_TCB),
    platform_info: u64le(dv, OFF.PLATFORM_INFO),
    report_data: slice(bytes2, OFF.REPORT_DATA, 64),
    measurement: slice(bytes2, OFF.MEASUREMENT, 48),
    host_data: slice(bytes2, OFF.HOST_DATA, 32),
    id_key_digest: slice(bytes2, OFF.ID_KEY_DIGEST, 48),
    author_key_digest: slice(bytes2, OFF.AUTHOR_KEY_DIGEST, 48),
    report_id: slice(bytes2, OFF.REPORT_ID, 32),
    report_id_ma: slice(bytes2, OFF.REPORT_ID_MA, 32),
    reported_tcb: u64le(dv, OFF.REPORTED_TCB),
    chip_id: slice(bytes2, OFF.CHIP_ID, 64),
    signature: { r: slice(bytes2, OFF.SIG_R, 72), s: slice(bytes2, OFF.SIG_S, 72) },
    signed: slice(bytes2, 0, OFF.SIGNED_END),
    raw: bytes2.slice()
  };
}
function serializeSevSnpReport(fields) {
  const out = new Uint8Array(OFF.REPORT_LEN);
  const dv = new DataView(out.buffer);
  const put = (off, len, src) => {
    if (!src) return;
    out.set(src.subarray(0, len), off);
  };
  dv.setUint32(OFF.VERSION, fields.version ?? 2, true);
  dv.setUint32(OFF.GUEST_SVN, fields.guest_svn ?? 0, true);
  dv.setBigUint64(OFF.POLICY, fields.policy ?? 0n, true);
  put(OFF.FAMILY_ID, 16, fields.family_id);
  put(OFF.IMAGE_ID, 16, fields.image_id);
  dv.setUint32(OFF.VMPL, fields.vmpl ?? 0, true);
  dv.setUint32(OFF.SIGNATURE_ALGO, fields.signature_algo ?? SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384, true);
  dv.setBigUint64(OFF.CURRENT_TCB, fields.current_tcb ?? 0n, true);
  dv.setBigUint64(OFF.PLATFORM_INFO, fields.platform_info ?? 0n, true);
  put(OFF.REPORT_DATA, 64, fields.report_data);
  put(OFF.MEASUREMENT, 48, fields.measurement);
  put(OFF.HOST_DATA, 32, fields.host_data);
  put(OFF.ID_KEY_DIGEST, 48, fields.id_key_digest);
  put(OFF.AUTHOR_KEY_DIGEST, 48, fields.author_key_digest);
  put(OFF.REPORT_ID, 32, fields.report_id);
  put(OFF.REPORT_ID_MA, 32, fields.report_id_ma);
  dv.setBigUint64(OFF.REPORTED_TCB, fields.reported_tcb ?? 0n, true);
  put(OFF.CHIP_ID, 64, fields.chip_id);
  if (fields.signature) {
    put(OFF.SIG_R, 72, fields.signature.r);
    put(OFF.SIG_S, 72, fields.signature.s);
  }
  return out;
}
function ecdsaP384PublicKey(sec1) {
  const pt = p3842.ProjectivePoint.fromHex(sec1);
  return { point: pt.toRawBytes(false) };
}
function sevSnpSignatureToCompact(sig) {
  const n = p3842.CURVE.n;
  const r = leToBigInt(sig.r);
  const s = leToBigInt(sig.s);
  if (r <= 0n || r >= n) throw new RangeError("sev-snp signature: r out of range");
  if (s <= 0n || s >= n) throw new RangeError("sev-snp signature: s out of range");
  return new p3842.Signature(r, s).toCompactRawBytes();
}
function verifySevSnpReportSignature(report, vcek) {
  try {
    const digest = sha3842(report.signed);
    const compact = sevSnpSignatureToCompact(report.signature);
    return p3842.verify(compact, digest, vcek.point, { lowS: false });
  } catch {
    return false;
  }
}
function pubEq(a, b) {
  if (a.point.length !== b.point.length) return false;
  let diff = 0;
  for (let i = 0; i < a.point.length; i++) diff |= a.point[i] ^ b.point[i];
  return diff === 0;
}
function verifyTbsSig(tbs, sig, signer) {
  try {
    return p3842.verify(sig, sha3842(tbs), signer.point, { lowS: false });
  } catch {
    return false;
  }
}
function indexOfBytes(hay, needle, from = 0) {
  outer: for (let i = from; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}
function tbsContainsSubjectKey(tbs, key) {
  const framed = new Uint8Array(3 + key.point.length);
  framed.set([3, 98, 0], 0);
  framed.set(key.point, 3);
  const first = indexOfBytes(tbs, framed);
  if (first < 0) return false;
  return indexOfBytes(tbs, framed, first + 1) < 0;
}
function readTlv(b, off) {
  if (off + 2 > b.length) return null;
  const tag = b[off];
  let len = b[off + 1];
  let start = off + 2;
  if (len & 128) {
    const n = len & 127;
    if (n < 1 || n > 2 || off + 2 + n > b.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len << 8 | b[off + 2 + i];
    start = off + 2 + n;
  }
  const end = start + len;
  return end <= b.length ? { tag, start, end } : null;
}
function oidDer(dotted) {
  const arcs = dotted.split(".").map(Number);
  const body2 = [arcs[0] * 40 + arcs[1]];
  for (const a of arcs.slice(2)) {
    const stack = [a & 127];
    for (let v = a >>> 7; v > 0; v >>>= 7) stack.unshift(v & 127 | 128);
    body2.push(...stack);
  }
  return Uint8Array.from([6, body2.length, ...body2]);
}
function extensionValue(tbs, dotted) {
  const oid = oidDer(dotted);
  const at = indexOfBytes(tbs, oid);
  if (at < 0 || indexOfBytes(tbs, oid, at + 1) >= 0) return void 0;
  let off = at + oid.length;
  const maybeBool = readTlv(tbs, off);
  if (maybeBool && maybeBool.tag === 1) off = maybeBool.end;
  const oct = readTlv(tbs, off);
  if (!oct || oct.tag !== 4) return void 0;
  return tbs.slice(oct.start, oct.end);
}
var OID_HWID = "1.3.6.1.4.1.3704.1.4";
var OID_BL_SPL = "1.3.6.1.4.1.3704.1.3.1";
var OID_TEE_SPL = "1.3.6.1.4.1.3704.1.3.2";
var OID_SNP_SPL = "1.3.6.1.4.1.3704.1.3.3";
var OID_UCODE_SPL = "1.3.6.1.4.1.3704.1.3.8";
function spl(tbs, dotted) {
  const v = extensionValue(tbs, dotted);
  if (!v) return void 0;
  if (v.length >= 3 && v[0] === 2) {
    const t = readTlv(v, 0);
    if (!t || t.end !== v.length || t.end - t.start < 1 || t.end - t.start > 2) return void 0;
    let n = 0;
    for (let i = t.start; i < t.end; i++) n = n << 8 | v[i];
    return n;
  }
  return v.length === 1 ? v[0] : void 0;
}
function checkVcekReportBinding(vcekTbs, report) {
  const hw = extensionValue(vcekTbs, OID_HWID);
  if (!hw) return "VCEK certificate has no CHIP_ID (hwID) extension";
  const chip = hw.length === 66 && hw[0] === 4 && hw[1] === 64 ? hw.subarray(2) : hw;
  if (chip.length !== 64 || !timingSafeEq(chip, report.chip_id)) return "VCEK CHIP_ID does not match report chip_id";
  const t = report.reported_tcb;
  const byteAt = (i) => Number(t >> BigInt(8 * i) & 0xffn);
  const pairs = [
    [OID_BL_SPL, "bootloader", byteAt(0)],
    [OID_TEE_SPL, "tee", byteAt(1)],
    [OID_SNP_SPL, "snp", byteAt(6)],
    [OID_UCODE_SPL, "microcode", byteAt(7)]
  ];
  for (const [oid, name, want] of pairs) {
    const got = spl(vcekTbs, oid);
    if (got === void 0) return `VCEK certificate has no ${name} SPL extension`;
    if (got !== want) return `VCEK ${name} SPL ${got} does not match report reported_tcb (${want}) \u2014 TCB downgrade?`;
  }
  return null;
}
function verifyVcekChain(input) {
  const { chain: chain2, trustAnchorArk } = input;
  try {
    if (!pubEq(chain2.ark, trustAnchorArk)) return { ok: false, reason: "ARK does not match the configured trust anchor" };
    if (!tbsContainsSubjectKey(chain2.ask_tbs, chain2.ask)) return { ok: false, reason: "ASK key is not the subject key of the ASK certificate body" };
    if (!verifyTbsSig(chain2.ask_tbs, chain2.ask_sig, chain2.ark)) return { ok: false, reason: "ASK is not signed by ARK" };
    if (!tbsContainsSubjectKey(chain2.vcek_tbs, chain2.vcek)) return { ok: false, reason: "VCEK key is not the subject key of the VCEK certificate body" };
    if (!verifyTbsSig(chain2.vcek_tbs, chain2.vcek_sig, chain2.ask)) return { ok: false, reason: "VCEK is not signed by ASK" };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `chain verification error: ${e instanceof Error ? e.message : "unknown"}` };
  }
}
function makeDefaultDeriveIdentity(weightsFromHostData) {
  return (report) => ({
    model_id: "",
    weights_digest: weightsFromHostData ? toHex(report.host_data) : "",
    runtime_measurement: toHex(report.measurement),
    operator: toHex(report.chip_id)
  });
}
var SEV_SNP_POLICY_DEBUG_BIT = 1n << 19n;
function checkSevSnpPolicy(report, policy) {
  if (policy.requireEcdsaP384 !== false && report.signature_algo !== SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384) {
    return `unexpected signature_algo ${report.signature_algo}`;
  }
  if (policy.allowDebug !== true && (report.policy & SEV_SNP_POLICY_DEBUG_BIT) !== 0n) {
    return "guest policy has the DEBUG bit set (host can inspect the guest)";
  }
  if (typeof policy.minGuestSvn === "number" && report.guest_svn < policy.minGuestSvn) {
    return `guest_svn ${report.guest_svn} below minimum ${policy.minGuestSvn}`;
  }
  if (typeof policy.minReportedTcb === "bigint" && report.reported_tcb < policy.minReportedTcb) {
    return `reported_tcb below minimum (rollback?)`;
  }
  if (typeof policy.requireVmpl === "number" && report.vmpl !== policy.requireVmpl) {
    return `vmpl ${report.vmpl} is not the required ${policy.requireVmpl}`;
  }
  if (Array.isArray(policy.measurements) && policy.measurements.length > 0) {
    const m = toHex(report.measurement);
    if (!policy.measurements.map((x) => x.toLowerCase()).includes(m)) {
      return "measurement not in policy allowlist";
    }
  }
  if (Array.isArray(policy.hostData) && policy.hostData.length > 0) {
    const h = toHex(report.host_data);
    if (!policy.hostData.map((x) => x.toLowerCase()).includes(h)) return "host_data not in policy allowlist";
  }
  if (Array.isArray(policy.chipIds) && policy.chipIds.length > 0) {
    const c = toHex(report.chip_id);
    if (!policy.chipIds.map((x) => x.toLowerCase()).includes(c)) {
      return "chip_id not in policy allowlist";
    }
  }
  return null;
}
function createSevSnpVerifier(opts) {
  if (!opts?.policy || !Array.isArray(opts.policy.measurements) || opts.policy.measurements.length === 0) {
    throw new TypeError("createSevSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)");
  }
  const deriveIdentity = opts.policy.deriveIdentity ?? makeDefaultDeriveIdentity(opts.policy.weightsFromHostData === true);
  return {
    async verify(input) {
      const fail2 = (reason) => ({ ok: false, reason });
      try {
        if (!opts.resolveEvidence) return fail2("no SEV-SNP evidence resolver configured (fail closed)");
        const evidence = await opts.resolveEvidence(input.document, input.ctx);
        if (!evidence || !(evidence.report instanceof Uint8Array) || !evidence.chain) {
          return fail2("no SEV-SNP evidence for this action");
        }
        let report;
        try {
          report = parseSevSnpReport(evidence.report);
        } catch (e) {
          return fail2(`report parse failed: ${e instanceof Error ? e.message : "unknown"}`);
        }
        const chain2 = verifyVcekChain({ chain: evidence.chain, trustAnchorArk: opts.trustAnchorArk });
        if (!chain2.ok) return fail2(`cert chain invalid: ${chain2.reason}`);
        if (!verifySevSnpReportSignature(report, evidence.chain.vcek)) {
          return fail2("report signature does not verify under VCEK");
        }
        const vErr = checkVcekReportBinding(evidence.chain.vcek_tbs, report);
        if (vErr) return fail2(vErr);
        if (!input.expected) return fail2("no expected attestation binding supplied");
        let expectedData;
        try {
          expectedData = attestationBinding(input.expected);
        } catch (e) {
          return fail2(`binding not constructible: ${e instanceof Error ? e.message : "invalid"}`);
        }
        if (!timingSafeEq(expectedData, report.report_data)) {
          return fail2("report_data does not bind holder/grant/epoch/nonce (relayed or unbound quote)");
        }
        const polErr = checkSevSnpPolicy(report, opts.policy);
        if (polErr) return fail2(polErr);
        const measured = deriveIdentity(report);
        return { ok: true, bound: true, measured, hostAsserted: { host_data: toHex(report.host_data) } };
      } catch (e) {
        return fail2(`sev-snp verification error (fail closed): ${e instanceof Error ? e.message : "unknown"}`);
      }
    }
  };
}
function timingSafeEq(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
function fingerprintPublicKey(pk) {
  return b64u(sha3842(pk.point)).slice(0, 16);
}

// packages/pca/src/optimistic.ts
var DOMAIN3 = "atlas-pca/optimistic/v1\0";
var IRREVERSIBLE_CLASS = "irreversible";
function claimMessage(body2) {
  const d = canonicalBytesLenient(body2);
  const p = utf8(DOMAIN3);
  const m = new Uint8Array(p.length + d.length);
  m.set(p);
  m.set(d, p.length);
  return m;
}
var DEFAULT_WINDOW_POLICY = {
  minWindowMs: 1e3,
  maxWindowMs: 24 * 60 * 60 * 1e3,
  defaultWindowMs: 5 * 60 * 1e3,
  maxSkewMs: 5e3
};
function resolveWindow(policy, serverNow, requestedMs) {
  if (!Number.isFinite(serverNow)) throw new Error("resolveWindow: serverNow must be finite");
  const want = Number.isFinite(requestedMs) ? requestedMs : policy.defaultWindowMs;
  const challenge_window_ms = Math.min(policy.maxWindowMs, Math.max(policy.minWindowMs, want));
  return { issued_at: serverNow, challenge_window_ms };
}
function validateWindow(issuedAt, windowMs, serverNow, policy = DEFAULT_WINDOW_POLICY) {
  if (!Number.isFinite(serverNow)) return "server time is not finite";
  if (!Number.isFinite(issuedAt) || !Number.isFinite(windowMs)) return "malformed challenge window";
  if (Math.abs(issuedAt - serverNow) > policy.maxSkewMs) return "issued_at is outside the allowed skew of server time";
  if (windowMs < policy.minWindowMs) return "challenge window is below the minimum";
  if (windowMs > policy.maxWindowMs) return "challenge window exceeds the maximum";
  return null;
}
function openOptimistic(pcactn, opts, signerSecret) {
  const rc = pcactn?.action?.reversibility_class;
  if (rc === IRREVERSIBLE_CLASS) {
    throw new Error("openOptimistic: irreversible actions cannot use the optimistic fast-path (\xA79A)");
  }
  if (!Number.isFinite(opts.claimedR)) throw new Error("openOptimistic: claimedR must be finite");
  const policy = opts.windowPolicy ?? DEFAULT_WINDOW_POLICY;
  const serverNow = Number.isFinite(opts.serverNow) ? opts.serverNow : Date.now();
  const issuedAt = Number.isFinite(opts.issuedAt) ? opts.issuedAt : serverNow;
  const windowMs = opts.challengeWindowMs === void 0 ? policy.defaultWindowMs : opts.challengeWindowMs;
  const bad = validateWindow(issuedAt, windowMs, serverNow, policy);
  if (bad) throw new Error(`openOptimistic: ${bad}`);
  const body2 = {
    pcactn_digest: pcactnDigest(pcactn),
    bond_ref: opts.bondRef,
    claimed_r: opts.claimedR,
    reversibility_class: typeof rc === "string" ? rc : "unknown",
    issued_at: issuedAt,
    challenge_window_ms: windowMs
  };
  return { ...body2, sig: b64u(sign(signerSecret, claimMessage(body2))) };
}
function verifyClaim(claim, pcactn, signerPublic, opts = {}) {
  try {
    if (!claim || typeof claim !== "object") return { ok: false, reason: "malformed claim" };
    if (claim.reversibility_class === IRREVERSIBLE_CLASS) {
      return { ok: false, reason: "irreversible action is ineligible for the optimistic path" };
    }
    if (claim.pcactn_digest !== pcactnDigest(pcactn)) {
      return { ok: false, reason: "claim does not cover this PCActn" };
    }
    if (!Number.isFinite(claim.claimed_r)) return { ok: false, reason: "claimed_r is not finite" };
    const serverNow = Number.isFinite(opts.serverNow) ? opts.serverNow : Date.now();
    const bad = validateWindow(claim.issued_at, claim.challenge_window_ms, serverNow, opts.windowPolicy ?? DEFAULT_WINDOW_POLICY);
    if (bad) return { ok: false, reason: bad };
    const { sig, ...body2 } = claim;
    if (typeof sig !== "string" || !verifyB64u(signerPublic, claimMessage(body2), sig)) {
      return { ok: false, reason: "claim signature does not verify" };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `claim verification error: ${e instanceof Error ? e.message : "unknown"}` };
  }
}
function challengeWindowEnd(claim) {
  return claim.issued_at + claim.challenge_window_ms;
}
function withinChallengeWindow(claim, now) {
  if (!Number.isFinite(now)) return false;
  return now <= challengeWindowEnd(claim);
}
function claimStatus(claim, now) {
  return withinChallengeWindow(claim, now) ? "open" : "finalized";
}
var DEFAULT_R_MARGIN = 1e-9;
function fileFraudProof(args) {
  const { claim, pcactn } = args;
  const decideInput = args.openSnapshot ?? args.decideInput;
  if (!decideInput) return null;
  const actualDecision = decide({ ...decideInput, grant: args.grant });
  if (claim.pcactn_digest !== pcactnDigest(pcactn)) return null;
  const margin = Number.isFinite(args.rMargin) ? Math.max(0, args.rMargin) : DEFAULT_R_MARGIN;
  const decision = {
    releaseGuardianShare: actualDecision.releaseGuardianShare,
    r: actualDecision.r,
    optimisticAllowed: actualDecision.requiredThreshold.optimisticAllowed
  };
  const { grant: _g, ...evidence } = decideInput;
  const base = {
    pcactn_digest: claim.pcactn_digest,
    bond_ref: claim.bond_ref,
    claimed_r: claim.claimed_r,
    decision,
    evidence,
    r_margin: margin
  };
  let kind = null;
  let reason = "";
  if (claim.reversibility_class === IRREVERSIBLE_CLASS || pcactn.action?.reversibility_class === IRREVERSIBLE_CLASS) {
    kind = "irreversible";
    reason = "irreversible action took the optimistic path";
  } else if (!actualDecision.releaseGuardianShare) {
    kind = "policy-denied";
    reason = `Policy VM denied the action: ${actualDecision.reasons.join("; ") || "not compliant"}`;
  } else if (!actualDecision.requiredThreshold.optimisticAllowed) {
    kind = "optimistic-not-allowed";
    reason = `optimistic path not allowed at real r=${actualDecision.r.toFixed(3)} (t=${actualDecision.requiredThreshold.t})`;
  } else if (actualDecision.r > claim.claimed_r + margin) {
    kind = "risk-understated";
    reason = `claimed r=${claim.claimed_r} but real r=${actualDecision.r.toFixed(3)}`;
  }
  if (kind === null) return null;
  return { ...base, kind, reason };
}
function verifyFraudProof(claim, proof, grant, openSnapshot) {
  try {
    if (!proof || typeof proof !== "object") return { fraudulent: false, reason: "malformed fraud proof" };
    if (proof.pcactn_digest !== claim.pcactn_digest) {
      return { fraudulent: false, reason: "fraud proof targets a different PCActn than the claim" };
    }
    if (proof.bond_ref !== claim.bond_ref) {
      return { fraudulent: false, reason: "fraud proof names a different bond than the claim" };
    }
    if (!openSnapshot || typeof openSnapshot !== "object") {
      return { fraudulent: false, reason: "no frozen open-time snapshot supplied; cannot judge the claim" };
    }
    const recomputed = decide({ ...openSnapshot, grant });
    const summary = {
      releaseGuardianShare: recomputed.releaseGuardianShare,
      r: recomputed.r,
      optimisticAllowed: recomputed.requiredThreshold.optimisticAllowed
    };
    if (summary.releaseGuardianShare !== proof.decision.releaseGuardianShare || summary.optimisticAllowed !== proof.decision.optimisticAllowed || Math.abs(summary.r - proof.decision.r) > 1e-9) {
      return { fraudulent: false, reason: "proof decision does not match an independent recomputation" };
    }
    const margin = Number.isFinite(proof.r_margin) ? Math.max(0, proof.r_margin) : DEFAULT_R_MARGIN;
    const irreversible = claim.reversibility_class === IRREVERSIBLE_CLASS || openSnapshot.action?.action?.reversibility_class === IRREVERSIBLE_CLASS;
    if (irreversible) {
      return { fraudulent: true, slashBondRef: claim.bond_ref, reason: "irreversible action is ineligible for the optimistic path" };
    }
    if (!summary.releaseGuardianShare) {
      return { fraudulent: true, slashBondRef: claim.bond_ref, reason: `Policy VM denies the action: ${recomputed.reasons.join("; ") || "not compliant"}` };
    }
    if (!summary.optimisticAllowed) {
      return { fraudulent: true, slashBondRef: claim.bond_ref, reason: `optimistic path not allowed at real r=${summary.r.toFixed(3)}` };
    }
    if (summary.r > claim.claimed_r + margin) {
      return { fraudulent: true, slashBondRef: claim.bond_ref, reason: `risk understated: claimed ${claim.claimed_r}, real ${summary.r.toFixed(3)}` };
    }
    return { fraudulent: false, reason: "claim is compliant under independent recomputation; bond stands" };
  } catch (e) {
    return { fraudulent: false, reason: `fraud-proof verification error: ${e instanceof Error ? e.message : "unknown"}` };
  }
}
function freezeOpenSnapshot(input) {
  const clone = JSON.parse(JSON.stringify(input));
  const freeze = (o) => {
    if (o && typeof o === "object" && !Object.isFrozen(o)) {
      Object.freeze(o);
      for (const v of Object.values(o)) freeze(v);
    }
  };
  freeze(clone);
  return clone;
}

// packages/pca/src/bond-settlement.ts
var DOMAIN4 = "atlas-pca/bond-settlement/v1\0";
var ESCROW_ACCOUNT = "escrow";
function settlementMessage(body2) {
  const d = canonicalBytesLenient(body2);
  const p = utf8(DOMAIN4);
  const m = new Uint8Array(p.length + d.length);
  m.set(p);
  m.set(d, p.length);
  return m;
}
function settlementEvidenceDigest(claim, fraudVerdict) {
  return hashCanonicalLenient({
    claimDigest: claim.pcactn_digest,
    bond_ref: claim.bond_ref,
    fraudulent: fraudVerdict.fraudulent,
    slashBondRef: fraudVerdict.slashBondRef ?? null,
    reason: fraudVerdict.reason
  });
}
function revocationEvidenceDigest(claim, revokedCapId) {
  return hashCanonicalLenient({
    claimDigest: claim.pcactn_digest,
    bond_ref: claim.bond_ref,
    kind: "revocation",
    revokedCapId
  });
}
function verifySettlement(record, guardianPublicKey) {
  try {
    if (!record || typeof record !== "object") return false;
    const { sig, ...body2 } = record;
    if (typeof sig !== "string") return false;
    return verifyB64u(guardianPublicKey, settlementMessage(body2), sig);
  } catch {
    return false;
  }
}
var DEFAULT_BOND_POLICY = { floor: 1, k: 1, maxOpenClaims: 100, maxOpenAmount: Number.POSITIVE_INFINITY };
function bondAmount(policy, exposure) {
  const e = Number.isFinite(exposure) && exposure > 0 ? exposure : 0;
  return Math.max(policy.floor, policy.k * e);
}
var InMemoryBondAccount = class {
  balances = /* @__PURE__ */ new Map();
  constructor(initial = {}) {
    for (const [k, v] of Object.entries(initial)) this.balances.set(k, v);
  }
  balanceOf(account) {
    return this.balances.get(account) ?? 0;
  }
  debit(account, amount) {
    if (!Number.isFinite(amount) || amount < 0) throw new Error("debit: invalid amount");
    if (this.balanceOf(account) < amount) throw new Error(`debit: insufficient balance for ${account}`);
    this.balances.set(account, this.balanceOf(account) - amount);
  }
  credit(account, amount) {
    if (!Number.isFinite(amount) || amount < 0) throw new Error("credit: invalid amount");
    this.balances.set(account, this.balanceOf(account) + amount);
  }
};
var BondLedger = class {
  /** The guardian/settlement public key (b64u) — hand this to verifiers of the signed records. */
  guardianPublicKey;
  guardianSecret;
  escrow;
  bonds = /* @__PURE__ */ new Map();
  accounts;
  bondPolicy;
  constructor(opts) {
    if (!(opts.guardianSecret instanceof Uint8Array)) {
      throw new Error("BondLedger: guardianSecret must be a Uint8Array");
    }
    this.guardianSecret = opts.guardianSecret;
    this.guardianPublicKey = b64u(publicKeyOf(opts.guardianSecret));
    this.escrow = opts.escrowAccount ?? ESCROW_ACCOUNT;
    this.accounts = opts.accounts ?? new InMemoryBondAccount();
    this.bondPolicy = opts.bondPolicy ?? DEFAULT_BOND_POLICY;
  }
  /** The settled credit balance of `account` (0 if unknown). */
  balanceOf(account) {
    return this.accounts.balanceOf(account);
  }
  /** The lifecycle status of the bond for `claimId`. */
  bondStatus(claimId) {
    return this.bonds.get(claimId)?.status ?? "none";
  }
  credit(account, amount) {
    this.accounts.credit(account, amount);
  }
  signRecord(body2) {
    return { ...body2, sig: b64u(sign(this.guardianSecret, settlementMessage(body2))) };
  }
  now(at) {
    return Number.isFinite(at) ? at : Date.now();
  }
  /**
   * Open (lock) a bond: refuses an unaffordable bond, one below `bondAmount(policy, exposure)`, and
   * one that would breach the per-depositor open-claim caps; debits real collateral. Refuses a non-positive/non-finite amount and a double-open of the same claim.
   * The bond moves from the depositor into escrow; it credits no account until it settles.
   */
  openBond(params) {
    const { claimId, amount, depositor } = params;
    if (typeof claimId !== "string" || claimId.length === 0) throw new Error("openBond: claimId is required");
    if (!Number.isFinite(amount) || amount <= 0) throw new Error("openBond: amount must be a positive finite number");
    if (typeof depositor !== "string" || depositor.length === 0) throw new Error("openBond: depositor is required");
    if (this.bonds.has(claimId)) throw new Error(`openBond: bond ${claimId} already exists (double-open refused)`);
    const required = bondAmount(this.bondPolicy, params.exposure ?? 0);
    if (amount < required) throw new Error(`openBond: amount ${amount} is below the required bond ${required}`);
    let openCount = 0;
    let openSum = 0;
    for (const b of this.bonds.values()) {
      if (b.status === "open" && b.depositor === depositor) {
        openCount += 1;
        openSum += b.amount;
      }
    }
    if (openCount + 1 > this.bondPolicy.maxOpenClaims) throw new Error("openBond: depositor open-claim cap reached");
    if (openSum + amount > this.bondPolicy.maxOpenAmount) throw new Error("openBond: depositor aggregate open-bond cap exceeded");
    if (this.accounts.balanceOf(depositor) < amount) throw new Error("openBond: insufficient balance for the bond");
    this.accounts.debit(depositor, amount);
    this.accounts.credit(this.escrow, amount);
    this.bonds.set(claimId, { claimId, amount, depositor, status: "open" });
    return this.signRecord({
      claimId,
      action: "open",
      amount,
      from: depositor,
      to: this.escrow,
      at: this.now(params.at),
      evidenceDigest: ""
    });
  }
  /**
   * Release a bond back to its depositor after an unchallenged challenge window. Refuses a bond that
   * does not exist or is not currently `open` (double-settle refused). Credits the depositor.
   */
  releaseBond(params) {
    const { claimId } = params;
    const bond = this.bonds.get(claimId);
    if (!bond) throw new Error(`releaseBond: no bond for ${claimId}`);
    if (bond.status !== "open") throw new Error(`releaseBond: bond ${claimId} is already ${bond.status} (double-settle refused)`);
    bond.status = "released";
    this.accounts.debit(this.escrow, bond.amount);
    this.credit(bond.depositor, bond.amount);
    return this.signRecord({
      claimId,
      action: "release",
      amount: bond.amount,
      from: this.escrow,
      to: bond.depositor,
      at: this.now(params.at),
      evidenceDigest: ""
    });
  }
  /**
   * Slash a bond to the treasury — ONLY against a VERIFIED fraud verdict. This method itself re-runs
   * `verifyFraudProof` (against the grant the settlement layer trusts) and refuses unless the
   * server-derived verdict is `fraudulent` and slashes THIS bond; the challenger's assertion alone
   * never authorizes a slash. Refuses a non-existent / already-settled bond (double-settle). The signed
   * record's `evidenceDigest` binds to the recomputed verdict. Credits the treasury.
   */
  slashBond(params) {
    const { claimId, claim, fraudProof, grant, treasury, openSnapshot } = params;
    const bond = this.bonds.get(claimId);
    if (!bond) throw new Error(`slashBond: no bond for ${claimId}`);
    if (bond.status !== "open") throw new Error(`slashBond: bond ${claimId} is already ${bond.status} (double-settle refused)`);
    if (typeof treasury !== "string" || treasury.length === 0) throw new Error("slashBond: treasury is required");
    if (claim.bond_ref !== claimId) throw new Error("slashBond: claim.bond_ref does not match claimId");
    const verdict = verifyFraudProof(claim, fraudProof, grant, openSnapshot);
    if (!verdict.fraudulent || verdict.slashBondRef !== claimId) {
      throw new Error(`slashBond: refused \u2014 no verified fraud verdict slashing ${claimId} (${verdict.reason})`);
    }
    bond.status = "slashed";
    this.accounts.debit(this.escrow, bond.amount);
    this.credit(treasury, bond.amount);
    return this.signRecord({
      claimId,
      action: "slash",
      amount: bond.amount,
      from: this.escrow,
      to: treasury,
      at: this.now(params.at),
      evidenceDigest: settlementEvidenceDigest(claim, verdict)
    });
  }
  /**
   * Slash a bond because a capability in the claim's chain was REVOKED after the bond opened. The
   * authorizing evidence is server-derived (the caller MUST have confirmed `revokedCapId` is both in
   * the claim's chain and currently in the instance's revocation set) — never a challenger assertion.
   * Credits the treasury; binds the record to the revocation evidence. Refuses a missing/already-settled
   * bond (double-settle).
   */
  slashBondOnRevocation(params) {
    const { claimId, claim, revokedCapId, treasury } = params;
    const bond = this.bonds.get(claimId);
    if (!bond) throw new Error(`slashBondOnRevocation: no bond for ${claimId}`);
    if (bond.status !== "open") throw new Error(`slashBondOnRevocation: bond ${claimId} is already ${bond.status} (double-settle refused)`);
    if (typeof treasury !== "string" || treasury.length === 0) throw new Error("slashBondOnRevocation: treasury is required");
    if (claim.bond_ref !== claimId) throw new Error("slashBondOnRevocation: claim.bond_ref does not match claimId");
    if (typeof revokedCapId !== "string" || revokedCapId.length === 0) throw new Error("slashBondOnRevocation: revokedCapId is required");
    bond.status = "slashed";
    this.accounts.debit(this.escrow, bond.amount);
    this.credit(treasury, bond.amount);
    return this.signRecord({
      claimId,
      action: "slash",
      amount: bond.amount,
      from: this.escrow,
      to: treasury,
      at: this.now(params.at),
      evidenceDigest: revocationEvidenceDigest(claim, revokedCapId)
    });
  }
};

// packages/pca/src/zk.ts
var DOMAIN5 = "atlas-pca/zk-compliance/v1\0";
function policyCommitment(grant) {
  return typeof grant?.id === "string" ? grant.id : hashCanonical(grant);
}
function actionCommitment(pcactn) {
  return hashCanonical(pcactn?.action ?? null);
}
function statementMessage(body2) {
  const d = canonicalBytes(body2);
  const p = utf8(DOMAIN5);
  const m = new Uint8Array(p.length + d.length);
  m.set(p);
  m.set(d, p.length);
  return m;
}
function createAttestedComplianceProver(attestorSecret) {
  const publicKey = b64u(publicKeyOf(attestorSecret));
  return {
    publicKey,
    prove(opts) {
      const decision = decide(opts.decideInput);
      if (!decision.releaseGuardianShare) {
        throw new Error(`createAttestedComplianceProver: action is not compliant, nothing to prove (${decision.reasons.join("; ")})`);
      }
      const body2 = {
        v: 1,
        mode: "attested-vm",
        action_commit: actionCommitment(opts.pcactn),
        policy_commit: policyCommitment(opts.decideInput.grant),
        plan_commit: typeof opts.pcactn?.plan?.root === "string" ? opts.pcactn.plan.root : "",
        released: true,
        r: decision.r,
        issued_at: opts.issued_at,
        expires_at: opts.expires_at,
        prover: publicKey
      };
      return { ...body2, sig: b64u(sign(attestorSecret, statementMessage(body2))) };
    }
  };
}
function createZkVerifier(opts) {
  const trusted = new Set(Array.isArray(opts.trustedProverKeys) ? opts.trustedProverKeys : []);
  const expectedPolicy = Array.isArray(opts.policyCommitments) ? new Set(opts.policyCommitments) : void 0;
  const clock = opts.now ?? (() => Date.now());
  const skew = Number.isFinite(opts.clockSkewMs) ? Math.max(0, opts.clockSkewMs) : 0;
  return async (ctx) => {
    const fail2 = (reason) => ({ enforced: true, ok: false, reason });
    try {
      const proof = ctx?.pcactn?.zk_compliance;
      if (proof === void 0 || proof === null) return fail2("no zk_compliance proof present");
      const actionCommit = actionCommitment(ctx.pcactn);
      const planCommit = typeof ctx.pcactn?.plan?.root === "string" ? ctx.pcactn.plan.root : "";
      const wantPolicy = expectedPolicy ?? /* @__PURE__ */ new Set([policyCommitment(ctx.grant)]);
      if (opts.snarkBackend) {
        const policyCommit = expectedPolicy && expectedPolicy.size === 1 ? [...expectedPolicy][0] : policyCommitment(ctx.grant);
        const ok = await opts.snarkBackend.verify({
          proof,
          publicInputs: { action_commit: actionCommit, policy_commit: policyCommit, plan_commit: planCommit },
          ctx
        });
        return ok ? { enforced: true, ok: true } : fail2("snark backend rejected the proof");
      }
      const st = proof;
      if (st.v !== 1 || st.mode !== "attested-vm") return fail2("unrecognized compliance statement");
      if (st.released !== true) return fail2("statement does not assert release");
      if (typeof st.prover !== "string" || !trusted.has(st.prover)) return fail2("prover key is not trusted");
      const { sig, ...body2 } = st;
      if (typeof sig !== "string" || !verifyB64u(st.prover, statementMessage(body2), sig)) {
        return fail2("compliance statement signature does not verify");
      }
      if (!Number.isFinite(st.issued_at) || !Number.isFinite(st.expires_at) || st.expires_at < st.issued_at) {
        return fail2("malformed statement validity window");
      }
      const nowMs = clock();
      if (nowMs + skew < st.issued_at) return fail2("compliance statement not yet valid");
      if (nowMs - skew > st.expires_at) return fail2("compliance statement expired");
      if (st.action_commit !== actionCommit) return fail2("statement does not bind to this action");
      if (st.plan_commit !== planCommit) return fail2("statement does not bind to this plan commitment");
      if (typeof st.policy_commit !== "string" || !wantPolicy.has(st.policy_commit)) {
        return fail2("statement policy commitment is not an expected policy");
      }
      return { enforced: true, ok: true };
    } catch (e) {
      return fail2(`zk verification error (fail closed): ${e instanceof Error ? e.message : "unknown"}`);
    }
  };
}
function pinnedPolicyCommitment(grant) {
  return policyCommitment(grant);
}

// packages/pca/src/objective-risk.ts
var objective_risk_exports = {};
__export(objective_risk_exports, {
  DEFAULT_EPSILON: () => DEFAULT_EPSILON,
  DEFAULT_NATIVE_CONFIG: () => DEFAULT_NATIVE_CONFIG,
  EmbeddingError: () => EmbeddingError,
  InMemoryInverseRegistry: () => InMemoryInverseRegistry,
  METRIC: () => METRIC,
  NATIVE_SCHEME: () => NATIVE_SCHEME,
  ResourceGraph: () => ResourceGraph,
  blastRadius: () => blastRadius,
  byoEmbedder: () => byoEmbedder,
  byoModelId: () => byoModelId,
  calibrate: () => calibrate,
  calibrationDigest: () => calibrationDigest,
  canonicalAction: () => canonicalAction,
  canonicalActionDigest: () => canonicalActionDigest,
  canonicalActionJson: () => canonicalActionJson,
  commitGoal: () => commitGoal,
  committedDistance: () => committedDistance,
  committedDistanceChecked: () => committedDistanceChecked,
  conformalThreshold: () => conformalThreshold,
  conformanceCheck: () => conformanceCheck,
  harmReport: () => harmReport,
  nativeHashEmbedder: () => nativeHashEmbedder,
  objectiveRisk: () => objectiveRisk,
  reversibility: () => reversibility,
  validateVector: () => validateVector,
  vectorDistance: () => vectorDistance,
  verifyGoalCommitment: () => verifyGoalCommitment
});
var clamp013 = (x) => Number.isFinite(x) ? x < 0 ? 0 : x > 1 ? 1 : x : 1;
var cmp = (a, b) => a < b ? -1 : a > b ? 1 : 0;
function normValue(v) {
  if (typeof v === "string") return v.normalize("NFC");
  if (Array.isArray(v)) return v.map(normValue);
  if (v !== null && typeof v === "object") {
    const out = {};
    for (const k of Object.keys(v)) {
      const nk = k.normalize("NFC");
      if (nk in out) throw new TypeError("canonicalAction: duplicate key after NFC normalization");
      out[nk] = normValue(v[k]);
    }
    return out;
  }
  return v;
}
function canonicalAction(a) {
  if (typeof a?.verb !== "string" || typeof a.resource !== "string") throw new TypeError("canonicalAction: verb/resource must be strings");
  const verb = a.verb.normalize("NFC").trim().toLowerCase();
  const resource = a.resource.normalize("NFC").trim();
  if (!verb || !resource) throw new TypeError("canonicalAction: empty verb/resource");
  const params = normValue(a.params ?? {});
  if (params === null || typeof params !== "object" || Array.isArray(params)) throw new TypeError("canonicalAction: params must be an object");
  const c = { verb, resource, params };
  canonicalize(c);
  return c;
}
var canonicalActionJson = (c) => canonicalize(c);
var canonicalActionDigest = (c) => hashCanonicalLenient(c);
var InMemoryInverseRegistry = class {
  m = /* @__PURE__ */ new Map();
  trusted;
  constructor(trustedVerifiers = []) {
    this.trusted = [...new Set(trustedVerifiers)].sort(cmp);
  }
  register(verb, e) {
    this.m.set(verb, { ...e, ...e.verification ? { verification: { ...e.verification } } : {} });
    return this;
  }
  lookup(verb) {
    const e = this.m.get(verb);
    return e ? { ...e } : void 0;
  }
  trustedVerifiers() {
    return this.trusted;
  }
  digest() {
    const entries = [...this.m.entries()].sort(([a], [b]) => cmp(a, b)).map(([verb, e]) => ({ verb, inverseKind: e.inverseKind, fidelity: e.fidelity, verification: e.verification ?? null }));
    return hashCanonicalLenient({ v: 1, trusted: this.trusted, entries });
  }
};
function reversibility(action, registry, authorizedKinds) {
  const e = registry.lookup(action.verb);
  const trusted = e?.verification ? registry.trustedVerifiers().includes(e.verification.verifierId) : false;
  if (!e || !trusted || !authorizedKinds.has(e.inverseKind)) return { class: "irreversible", value: 0 };
  return e.fidelity === "exact" ? { class: "reversible", value: 1, inverseKind: e.inverseKind } : { class: "compensable", value: 0.5, inverseKind: e.inverseKind };
}
var ResourceGraph = class {
  nodes = /* @__PURE__ */ new Map();
  out = /* @__PURE__ */ new Map();
  addNode(n) {
    this.nodes.set(n.id, n);
    if (!this.out.has(n.id)) this.out.set(n.id, []);
    return this;
  }
  addEdge(e) {
    if (!this.nodes.has(e.from) || !this.nodes.has(e.to)) throw new Error("edge endpoints must exist");
    this.out.get(e.from).push(e);
    return this;
  }
  get size() {
    return this.nodes.size;
  }
  node(id) {
    return this.nodes.get(id);
  }
  /** BFS reachable set (including `start`), edge-kind and depth restricted, sorted. */
  reachable(start, scope) {
    if (!this.nodes.has(start)) return [];
    const kinds = scope?.edgeKinds ? new Set(scope.edgeKinds) : void 0;
    const maxDepth = scope?.maxDepth ?? Infinity;
    const seen = /* @__PURE__ */ new Set([start]);
    let frontier = [start];
    for (let d = 0; d < maxDepth && frontier.length; d++) {
      const next = [];
      for (const u of frontier)
        for (const e of this.out.get(u) ?? [])
          if ((!kinds || kinds.has(e.kind)) && !seen.has(e.to)) {
            seen.add(e.to);
            next.push(e.to);
          }
      frontier = next;
    }
    return [...seen].sort(cmp);
  }
  digest() {
    const n = [...this.nodes.values()].map((x) => ({ id: x.id, harm: x.harm ?? {} })).sort((a, b) => cmp(a.id, b.id));
    const e = [...this.out.values()].flat().map((x) => ({ from: x.from, to: x.to, kind: x.kind })).sort((a, b) => cmp(`${a.from}\0${a.to}\0${a.kind}`, `${b.from}\0${b.to}\0${b.kind}`));
    return hashCanonicalLenient({ v: 1, n, e });
  }
};
function blastRadius(action, graph, scope) {
  const reachable = graph.reachable(action.resource, scope);
  if (reachable.length === 0 || graph.size === 0) return { count: 0, reachable, normalized: 1, harm: {} };
  const harm = {};
  for (const id of reachable)
    for (const [d, v] of Object.entries(graph.node(id)?.harm ?? {})) if (Number.isFinite(v) && v > 0) harm[d] = (harm[d] ?? 0) + v;
  return { count: reachable.length, reachable, normalized: reachable.length / graph.size, harm };
}
var EmbeddingError = class extends Error {
};
var maxComponent = (dims) => Math.floor(Math.sqrt(Number.MAX_SAFE_INTEGER / (2 * Math.max(1, dims))));
function validateVector(v, dims) {
  if (!Array.isArray(v) || v.length !== dims) throw new EmbeddingError(`vector must have exactly ${dims} components`);
  const lim = maxComponent(dims);
  for (const x of v) {
    if (!Number.isSafeInteger(x)) throw new EmbeddingError("vector components must be safe integers");
    if (Math.abs(x) > lim) throw new EmbeddingError("vector component out of range");
  }
  return v.map((x) => Object.is(x, -0) ? 0 : x);
}
var NATIVE_SCHEME = "pca-native-hash-ngram-v1";
var DEFAULT_NATIVE_CONFIG = {
  dims: 256,
  ngramMin: 2,
  ngramMax: 4,
  seed: "pca-native-v1",
  fieldWeights: { verb: 4, resource: 2, param: 1 }
};
function validateNativeConfig(c) {
  const okInt = (x, lo, hi) => Number.isSafeInteger(x) && x >= lo && x <= hi;
  if (!okInt(c.dims, 8, 65536)) throw new RangeError("native config: dims must be an integer in [8, 65536]");
  if (!okInt(c.ngramMin, 1, 8) || !okInt(c.ngramMax, c.ngramMin, 8)) throw new RangeError("native config: need 1 <= ngramMin <= ngramMax <= 8");
  if (typeof c.seed !== "string" || !c.seed) throw new RangeError("native config: seed required");
  for (const k of ["verb", "resource", "param"]) if (!okInt(c.fieldWeights[k], 0, 1e3)) throw new RangeError(`native config: fieldWeights.${k} must be an integer in [0, 1000]`);
}
function paramLeaves(v, path, out) {
  if (Array.isArray(v)) v.forEach((x, i) => paramLeaves(x, `${path}[${i}]`, out));
  else if (v !== null && typeof v === "object") for (const k of Object.keys(v).sort()) paramLeaves(v[k], path ? `${path}.${k}` : k, out);
  else out.push(`${path}=${canonicalize(v)}`);
}
function textFeatures(prefix, text, nmin, nmax) {
  const out = [];
  const cps = Array.from(`${text}`);
  for (let n = nmin; n <= nmax; n++) for (let i = 0; i + n <= cps.length; i++) out.push(`${prefix}c${n}:${cps.slice(i, i + n).join("")}`);
  for (const w of text.split(/[^\p{L}\p{N}]+/u)) if (w) out.push(`${prefix}w:${w.toLowerCase()}`);
  return out;
}
function nativeHashEmbedder(config = DEFAULT_NATIVE_CONFIG) {
  validateNativeConfig(config);
  const cfg = { ...config, fieldWeights: { ...config.fieldWeights } };
  const committed = { scheme: NATIVE_SCHEME, ...cfg };
  const modelId = `native:${hashCanonicalLenient(committed)}`;
  const prefix = utf8(`${cfg.seed}`);
  return {
    modelId,
    config: committed,
    dims: cfg.dims,
    embed(a) {
      const v = new Array(cfg.dims).fill(0);
      const add2 = (feat, w) => {
        if (w === 0) return;
        const f = utf8(feat);
        const buf = new Uint8Array(prefix.length + f.length);
        buf.set(prefix);
        buf.set(f, prefix.length);
        const h = sha2563(buf);
        const bucket = (h[0] * 16777216 + h[1] * 65536 + h[2] * 256 + h[3] >>> 0) % cfg.dims;
        v[bucket] = v[bucket] + ((h[4] & 1) === 0 ? w : -w);
      };
      for (const f of textFeatures("v:", a.verb, cfg.ngramMin, cfg.ngramMax)) add2(f, cfg.fieldWeights.verb);
      for (const f of textFeatures("r:", a.resource, cfg.ngramMin, cfg.ngramMax)) add2(f, cfg.fieldWeights.resource);
      const leaves = [];
      paramLeaves(a.params, "", leaves);
      for (const leaf of leaves) for (const f of textFeatures("p:", leaf, cfg.ngramMin, cfg.ngramMax)) add2(f, cfg.fieldWeights.param);
      return v;
    }
  };
}
var byoModelId = (d) => `byo:${hashCanonicalLenient(d)}`;
function byoEmbedder(descriptor, infer, claimedModelId) {
  if (!Number.isSafeInteger(descriptor.dims) || descriptor.dims < 1) throw new RangeError("byo: dims must be a positive integer");
  const { bits } = descriptor.quantization;
  if (!Number.isSafeInteger(bits) || bits < 2 || bits > 31 || !(descriptor.quantization.scale > 0)) throw new RangeError("byo: invalid quantization");
  if (descriptor.inputEncoding !== "pca-canonical-action-json-v1") throw new RangeError("byo: unsupported inputEncoding");
  const modelId = byoModelId(descriptor);
  if (claimedModelId !== void 0 && claimedModelId !== modelId) throw new Error("byo: modelId does not match the committed descriptor");
  const qmax = 2 ** (bits - 1) - 1;
  return {
    modelId,
    config: descriptor,
    dims: descriptor.dims,
    embed(a) {
      const v = validateVector(infer(canonicalActionJson(a)), descriptor.dims);
      for (const x of v) if (Math.abs(x) > qmax) throw new EmbeddingError("byo: component exceeds declared quantization range");
      return v;
    }
  };
}
function conformanceCheck(e, cases) {
  try {
    return cases.every((c) => {
      const v = e.embed(canonicalAction(c.action));
      return v.length === c.vector.length && v.every((x, i) => x === c.vector[i]);
    });
  } catch {
    return false;
  }
}
var METRIC = "half-chord-v1";
var DEFAULT_EPSILON = 1 / 4096;
var goalCommitInput = (g) => ({
  embedderModelId: g.embedderModelId,
  config: g.config,
  goalVector: g.goalVector,
  metric: g.metric,
  epsilon: g.epsilon
});
function commitGoal(embedder, goalAction, epsilon = DEFAULT_EPSILON) {
  if (!(epsilon > 0 && epsilon <= 1)) throw new RangeError("epsilon must be in (0, 1]");
  const goalVector = validateVector(embedder.embed(canonicalAction(goalAction)), embedder.dims);
  const g = { embedderModelId: embedder.modelId, config: embedder.config, goalVector, metric: METRIC, epsilon };
  return { ...g, commit: hashCanonicalLenient(goalCommitInput(g)) };
}
function verifyGoalCommitment(g, embedder) {
  try {
    if (g.metric !== METRIC) return "unknown metric";
    if (!(g.epsilon > 0 && g.epsilon <= 1)) return "bad epsilon";
    if (g.commit !== hashCanonicalLenient(goalCommitInput(g))) return "goal commitment hash mismatch";
    if (g.embedderModelId !== embedder.modelId) return "embedder modelId mismatch";
    if (hashCanonicalLenient(g.config) !== hashCanonicalLenient(embedder.config)) return "embedder config mismatch";
    validateVector(g.goalVector, embedder.dims);
    return null;
  } catch (e) {
    return e instanceof Error ? e.message : "invalid goal commitment";
  }
}
function vectorDistance(a, b, epsilon = DEFAULT_EPSILON) {
  if (a.length !== b.length) return 1;
  let dot = 0, na = 0, nb = 0, same = true;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
    if (a[i] !== b[i]) same = false;
  }
  if (na === 0 || nb === 0) return 1;
  if (same) return 0;
  const cos = Math.max(-1, Math.min(1, dot / Math.sqrt(na * nb)));
  const d = Math.sqrt((1 - cos) / 2);
  if (d < 1e-9) return 0;
  return clamp013(Math.ceil(d / epsilon) * epsilon);
}
function committedDistanceChecked(action, goal, embedder) {
  const bad = verifyGoalCommitment(goal, embedder);
  if (bad) return { ok: false, reason: bad };
  try {
    const v = validateVector(embedder.embed(action), embedder.dims);
    return { ok: true, value: vectorDistance(v, goal.goalVector, goal.epsilon) };
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : "embedding failed" };
  }
}
function committedDistance(action, goal, embedder) {
  try {
    const r = committedDistanceChecked(canonicalAction(action), goal, embedder);
    return r.ok ? r.value : 1;
  } catch {
    return 1;
  }
}
function calibrate(rawScore, benignScores) {
  const n = benignScores.length;
  if (n === 0 || !Number.isFinite(rawScore)) return 1;
  let ge = 0;
  for (const s of benignScores) if (s >= rawScore) ge++;
  return 1 - (1 + ge) / (n + 1);
}
function conformalThreshold(benignScores, alpha) {
  const n = benignScores.length;
  const k = Math.ceil((n + 1) * (1 - alpha));
  if (n === 0 || k > n) return Infinity;
  return [...benignScores].sort((a, b) => a - b)[k - 1];
}
var calibrationDigest = (scores) => hashCanonicalLenient({ v: 1, scores: [...scores].sort((a, b) => a - b) });
function harmReport(units, denoms) {
  let num = 0, den = 0;
  for (const d of denoms) {
    if (!(d.weight > 0) || !(d.ceiling > 0)) continue;
    num += d.weight * Math.min(1, Math.max(0, units[d.id] ?? 0) / d.ceiling);
    den += d.weight;
  }
  return { units, normalized: den === 0 ? 1 : clamp013(num / den) };
}
var WORST_INPUTS = { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0, age: 1 };
function reject(reasons) {
  return {
    r: 1,
    valid: false,
    reasons,
    raw: 1,
    inputs: { ...WORST_INPUTS },
    reversibility: { class: "irreversible", value: 0 },
    blast: { count: 0, reachable: [], normalized: 1, harm: {} },
    harm: { units: {}, normalized: 1 },
    evidenceDigest: ""
  };
}
function objectiveRisk(submitted, ctx) {
  let action;
  try {
    action = canonicalAction(submitted);
  } catch (e) {
    return reject([`action: ${e instanceof Error ? e.message : "not canonicalizable"}`]);
  }
  const reasons = [];
  if (ctx.registry.digest() !== ctx.commitments.registryDigest) reasons.push("registry digest does not match the committed digest");
  if (ctx.graph.digest() !== ctx.commitments.graphDigest) reasons.push("graph digest does not match the committed digest");
  if (ctx.calibration) {
    if (ctx.commitments.calibrationDigest === void 0) reasons.push("calibration set used without a committed digest");
    else if (calibrationDigest(ctx.calibration) !== ctx.commitments.calibrationDigest) reasons.push("calibration digest does not match the committed digest");
  }
  const dist = committedDistanceChecked(action, ctx.goal, ctx.embedder);
  if (!dist.ok) reasons.push(`goal/embedder: ${dist.reason}`);
  if (reasons.length) return reject(reasons);
  const rev = reversibility(action, ctx.registry, ctx.authorizedKinds);
  const blast = blastRadius(action, ctx.graph, ctx.scope);
  const harm = harmReport(blast.harm, ctx.denominations);
  const uncertainty = clamp013(ctx.attestedUncertainty ?? 0);
  const inputs = {
    semanticDistance: dist.value,
    reversibility: rev.value,
    blastRadius: Math.max(blast.normalized, ctx.denominations.length && Object.keys(blast.harm).length ? harm.normalized : 0),
    taint: ctx.taint,
    confidence: 1 - uncertainty,
    age: ctx.age
  };
  const raw = riskScore(inputs, ctx.weights);
  const r = ctx.calibration ? calibrate(raw, ctx.calibration) : raw;
  const evidenceDigest2 = hashCanonicalLenient({
    action: canonicalActionDigest(action),
    scope: { edgeKinds: ctx.scope?.edgeKinds ? [...ctx.scope.edgeKinds].sort(cmp) : null, maxDepth: ctx.scope?.maxDepth ?? null },
    authorized: [...ctx.authorizedKinds].sort(cmp),
    registry: ctx.commitments.registryDigest,
    graph: ctx.commitments.graphDigest,
    goal: ctx.goal.commit,
    calibration: ctx.commitments.calibrationDigest ?? null,
    inputs
  });
  return { r, valid: true, reasons: [], raw, inputs, reversibility: rev, blast, harm, evidenceDigest: evidenceDigest2 };
}

// packages/pca/src/objective-binding.ts
var isObj3 = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
var isStr3 = (v) => typeof v === "string" && v.length > 0;
function readObjectiveCommitment(grant) {
  const env = readEnvelope(grant);
  const raw = env?.objective_risk;
  if (raw === void 0) return {};
  if (!isObj3(raw) || raw.v !== 1) return { malformed: "objective_risk: unsupported shape/version" };
  const emb = raw.embedder;
  if (!isObj3(emb) || emb.scheme !== "native" || !isStr3(emb.model_id) || !isObj3(emb.config)) {
    return { malformed: 'objective_risk.embedder must be { scheme: "native", model_id, config }' };
  }
  if (!isObj3(raw.goal) || !isStr3(raw.goal.commit)) return { malformed: "objective_risk.goal must be a goal commitment" };
  if (!isStr3(raw.registry_digest) || !isStr3(raw.graph_digest)) return { malformed: "objective_risk needs registry_digest and graph_digest" };
  if (raw.calibration_digest !== void 0 && !isStr3(raw.calibration_digest)) return { malformed: "objective_risk.calibration_digest must be a string" };
  if (!Array.isArray(raw.authorized_kinds) || !raw.authorized_kinds.every((k) => typeof k === "string")) {
    return { malformed: "objective_risk.authorized_kinds must be string[]" };
  }
  if (raw.denominations !== void 0 && !Array.isArray(raw.denominations)) return { malformed: "objective_risk.denominations must be an array" };
  if (raw.on_mismatch !== void 0 && raw.on_mismatch !== "deny" && raw.on_mismatch !== "heuristic") {
    return { malformed: 'objective_risk.on_mismatch must be "deny" or "heuristic"' };
  }
  return { commitment: raw };
}
function buildRegistry(cfg) {
  const reg = new InMemoryInverseRegistry(cfg?.trusted_verifiers ?? []);
  for (const e of cfg?.entries ?? []) {
    reg.register(e.verb, {
      inverseKind: e.inverse_kind,
      fidelity: e.fidelity,
      ...e.verification ? { verification: { verifierId: e.verification.verifier_id, evidenceDigest: e.verification.evidence_digest } } : {}
    });
  }
  return reg;
}
function buildGraph(cfg) {
  const g = new ResourceGraph();
  for (const n of cfg?.nodes ?? []) g.addNode(n);
  for (const e of cfg?.edges ?? []) g.addEdge(e);
  return g;
}
function resolveObjectiveRisk(args) {
  const { commitment, malformed } = readObjectiveCommitment(args.grant);
  if (malformed) return { mode: "mismatch", reasons: [malformed], onMismatch: "deny" };
  if (!commitment) return { mode: "none" };
  const onMismatch = commitment.on_mismatch ?? "deny";
  const miss = (...reasons) => ({ mode: "mismatch", reasons, onMismatch });
  try {
    const env = readEnvelope(args.grant);
    if (!env) return miss("grant carries no valid envelope");
    if (!args.instance) return miss("the grant commits objective-risk facts but the instance holds no objective-risk config");
    const registry = buildRegistry(args.instance.registry);
    const graph = buildGraph(args.instance.graph);
    const embedder = nativeHashEmbedder(commitment.embedder.config);
    if (embedder.modelId !== commitment.embedder.model_id) return miss("embedder model_id does not match the committed one");
    const calibration = args.instance.calibration;
    if (commitment.calibration_digest !== void 0) {
      if (!calibration || calibrationDigest(calibration) !== commitment.calibration_digest) {
        return miss("calibration set does not match the committed digest");
      }
    }
    const res = objectiveRisk(args.action, {
      registry,
      authorizedKinds: new Set(commitment.authorized_kinds),
      graph,
      scope: commitment.scope,
      embedder,
      goal: commitment.goal,
      commitments: {
        registryDigest: commitment.registry_digest,
        graphDigest: commitment.graph_digest,
        ...commitment.calibration_digest !== void 0 ? { calibrationDigest: commitment.calibration_digest } : {}
      },
      denominations: commitment.denominations ?? [],
      weights: env.risk_policy.weights,
      taint: args.taint ?? 1,
      age: args.age ?? 1,
      ...commitment.calibration_digest !== void 0 && calibration ? { calibration } : {}
    });
    if (!res.valid) return miss(...res.reasons);
    return {
      mode: "objective",
      inputs: {
        reversibility: res.inputs.reversibility,
        blastRadius: res.inputs.blastRadius,
        semanticDistance: res.inputs.semanticDistance
      },
      r: res.r,
      evidenceDigest: res.evidenceDigest
    };
  } catch (e) {
    return miss(`objective risk evaluation error (fail closed): ${e instanceof Error ? e.message : "unknown"}`);
  }
}

// packages/pca/src/prohibitions.ts
var prohibitions_exports = {};
__export(prohibitions_exports, {
  CONSTITUTION_SIG_DOMAIN: () => CONSTITUTION_SIG_DOMAIN,
  CONSTITUTION_VERSION: () => CONSTITUTION_VERSION,
  EVIDENCE_VERSION: () => EVIDENCE_VERSION,
  MAX_INVARIANTS: () => MAX_INVARIANTS,
  MAX_LEDGER: () => MAX_LEDGER,
  SAFETY_EVIDENCE_SIG_DOMAIN: () => SAFETY_EVIDENCE_SIG_DOMAIN,
  STATE_CHAIN_DOMAIN: () => STATE_CHAIN_DOMAIN,
  STATE_DIGEST_DOMAIN: () => STATE_DIGEST_DOMAIN,
  advanceState: () => advanceState,
  advanceStateStrict: () => advanceStateStrict,
  canonicalState: () => canonicalState,
  checkAndAdvance: () => checkAndAdvance,
  checkProhibitions: () => checkProhibitions,
  composeAuthority: () => composeAuthority,
  constitutionId: () => constitutionId,
  emptyState: () => emptyState,
  evidenceDigest: () => evidenceDigest,
  proveSafety: () => proveSafety,
  safetyBindingId: () => safetyBindingId,
  signConstitution: () => signConstitution,
  signSafetyEvidence: () => signSafetyEvidence,
  stateDigest: () => stateDigest,
  stateProblem: () => stateProblem,
  tickState: () => tickState,
  validateConstitution: () => validateConstitution,
  validateInvariant: () => validateInvariant,
  verifyConstitution: () => verifyConstitution,
  verifySafetyEvidence: () => verifySafetyEvidence,
  verifySignedSafetyEvidence: () => verifySignedSafetyEvidence,
  whenMatches: () => whenMatches
});
var CONSTITUTION_VERSION = 1;
var CONSTITUTION_SIG_DOMAIN = "atlas-pca/constitution/v1\0";
var EVIDENCE_VERSION = 1;
var SAFETY_EVIDENCE_SIG_DOMAIN = "atlas-pca/safety-evidence/v1\0";
var STATE_DIGEST_DOMAIN = "atlas-pca/monitor-state/v1";
var STATE_CHAIN_DOMAIN = "atlas-pca/monitor-state-link/v1";
var MAX_LEDGER = 1e4;
var MAX_INVARIANTS = 256;
var MAX_STATE_ENTRIES = 1e5;
var MAX_STATE_KEYS = 1024;
var MAX_ID_LEN = 128;
var FORBIDDEN_IDS = /* @__PURE__ */ new Set(["__proto__", "constructor", "prototype"]);
function emptyState(now) {
  return { now, seq: 0, parent: null, ledger: {}, latched: {} };
}
function body(c) {
  const { id: _id, sig: _sig, ...rest } = c;
  return rest;
}
function domainMessage(domain, id) {
  const pre = utf8(domain);
  const d = sha2563(utf8(id));
  const m = new Uint8Array(pre.length + d.length);
  m.set(pre);
  m.set(d, pre.length);
  return m;
}
var sigMessage2 = (id) => domainMessage(CONSTITUTION_SIG_DOMAIN, id);
function constitutionId(c) {
  return hashCanonical(body(c));
}
function signConstitution(c, principalSecret) {
  const problems = validateConstitution(c);
  if (problems.length) throw new TypeError("signConstitution: " + problems.join("; "));
  const id = constitutionId(c);
  return { ...body(c), id, sig: b64u(sign(principalSecret, sigMessage2(id))) };
}
function verifyConstitution(sc, expectedPrincipal) {
  try {
    const problems = validateConstitution(sc);
    if (problems.length) return { ok: false, reason: problems[0] };
    if (expectedPrincipal !== void 0 && sc.principal !== expectedPrincipal) return { ok: false, reason: "principal mismatch" };
    if (typeof sc.id !== "string" || sc.id !== constitutionId(sc)) return { ok: false, reason: "id does not match content" };
    if (typeof sc.sig !== "string" || !verifyB64u(sc.principal, sigMessage2(sc.id), sc.sig)) return { ok: false, reason: "bad signature" };
    return { ok: true };
  } catch {
    return { ok: false, reason: "verification error (fail closed)" };
  }
}
var OPS = /* @__PURE__ */ new Set(["eq", "ne", "in", "nin", "lt", "lte", "gt", "gte", "prefix", "exists"]);
var isObj4 = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
var fin3 = (x) => typeof x === "number" && Number.isFinite(x);
var has3 = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
function validateCondition(c) {
  if (!isObj4(c)) return "condition not an object";
  if (typeof c.field !== "string" || !c.field) return "condition.field missing";
  if (typeof c.op !== "string" || !OPS.has(c.op)) return `unknown condition op ${String(c.op)}`;
  if (c.ref !== void 0 && (typeof c.ref !== "string" || !c.ref)) return "bad condition.ref";
  return null;
}
function validateConditions(cs, label) {
  if (!Array.isArray(cs) || cs.length === 0) return `${label} must be a non-empty array`;
  for (const c of cs) {
    const e = validateCondition(c);
    if (e) return e;
  }
  return null;
}
function validateWhen(w, label) {
  if (!isObj4(w)) return `${label}: not an object`;
  const v = w.verb;
  const verbOk = typeof v === "string" && v.length > 0 || Array.isArray(v) && v.length > 0 && v.every((x) => typeof x === "string" && x.length > 0);
  if (!verbOk) return `${label}: bad verb`;
  if (w.resource !== void 0) {
    if (typeof w.resource !== "string") return `${label}: bad resource`;
    if (w.resource.startsWith("re:")) {
      const src = w.resource.slice(3);
      if (src.length > 200 || !isSafeRegexSource(src)) return `${label}: unsafe regex resource`;
      try {
        new RegExp("^(?:" + src + ")$");
      } catch {
        return `${label}: invalid regex resource`;
      }
    }
  }
  if (w.where !== void 0) {
    if (!Array.isArray(w.where)) return `${label}: where not an array`;
    for (const c of w.where) {
      const e = validateCondition(c);
      if (e) return `${label}: ${e}`;
    }
  }
  return null;
}
function validateInvariant(inv) {
  if (!isObj4(inv)) return ["invariant not an object"];
  const rawId = inv.id;
  if (typeof rawId !== "string" || !rawId) return ["<no id>: missing id"];
  const id = rawId;
  const err = (m) => [`${id}: ${m}`];
  if (id.length > MAX_ID_LEN) return err("id too long");
  if (FORBIDDEN_IDS.has(id)) return err("forbidden id");
  let e;
  switch (inv.kind) {
    case "never":
      return (e = validateWhen(inv.when, "when")) ? err(e) : [];
    case "never_unless": {
      if (e = validateWhen(inv.when, "when")) return err(e);
      if (e = validateConditions(inv.unless, "unless")) return err(e);
      return [];
    }
    case "cap":
      if (e = validateWhen(inv.when, "when")) return err(e);
      if (typeof inv.amount !== "string" || !inv.amount.startsWith("action.")) return err("amount must be an action.* path");
      if (!fin3(inv.max) || inv.max < 0) return err("max must be a finite number >= 0");
      if (inv.window_secs !== void 0 && (!fin3(inv.window_secs) || inv.window_secs <= 0)) return err("bad window_secs");
      return [];
    case "rate":
      if (e = validateWhen(inv.when, "when")) return err(e);
      if (!Number.isInteger(inv.max) || inv.max < 0 || inv.max > MAX_LEDGER) return err("max must be an integer in [0,10000]");
      if (!fin3(inv.window_secs) || inv.window_secs <= 0) return err("window_secs must be > 0");
      return [];
    case "never_after":
      if ((e = validateWhen(inv.after, "after")) || (e = validateWhen(inv.forbid, "forbid"))) return err(e);
      return [];
    case "require_prior":
      if ((e = validateWhen(inv.when, "when")) || (e = validateWhen(inv.prior, "prior"))) return err(e);
      return [];
    case "require_approval_over":
      if (e = validateWhen(inv.when, "when")) return err(e);
      if (typeof inv.amount !== "string" || !inv.amount.startsWith("action.")) return err("amount must be an action.* path");
      if (!fin3(inv.threshold) || inv.threshold < 0) return err("threshold must be a finite number >= 0");
      if (e = validateConditions(inv.approved, "approved")) return err(e);
      return [];
    default:
      return err(`unknown invariant kind ${String(inv.kind)}`);
  }
}
function validateConstitution(c) {
  if (!isObj4(c)) return ["constitution not an object"];
  const out = [];
  if (c.version !== CONSTITUTION_VERSION) out.push(`unsupported version ${String(c.version)}`);
  if (typeof c.principal !== "string" || !c.principal) out.push("principal missing");
  if (!Array.isArray(c.invariants)) return [...out, "invariants not an array"];
  if (c.invariants.length > MAX_INVARIANTS) out.push("too many invariants");
  const seen = /* @__PURE__ */ new Set();
  for (const inv of c.invariants) {
    out.push(...validateInvariant(inv));
    const id = isObj4(inv) ? inv.id : void 0;
    if (typeof id === "string") {
      if (seen.has(id)) out.push(`${id}: duplicate id`);
      seen.add(id);
    }
  }
  return out;
}
function stateProblem(state) {
  try {
    if (!isObj4(state) || !fin3(state.now) || !isObj4(state.ledger) || !isObj4(state.latched)) return "malformed monitor state";
    if (!Number.isInteger(state.seq) || state.seq < 0) return "malformed monitor state: seq";
    if (state.parent !== null && typeof state.parent !== "string") return "malformed monitor state: parent";
    if (state.seq === 0 && state.parent !== null) return "malformed monitor state: genesis has a parent";
    if (state.seq > 0 && state.parent === null) return "malformed monitor state: missing chain link";
    const now = state.now;
    const lk = Object.keys(state.ledger);
    const nk = Object.keys(state.latched);
    if (lk.length > MAX_STATE_KEYS || nk.length > MAX_STATE_KEYS) return "malformed monitor state: too many keys";
    let total = 0;
    for (const k of lk) {
      if (FORBIDDEN_IDS.has(k) || k.length > MAX_ID_LEN) return "malformed monitor state: bad ledger key";
      const l = state.ledger[k];
      if (!Array.isArray(l) || l.length > MAX_LEDGER) return "malformed monitor state: bad ledger";
      total += l.length;
      for (const e of l) {
        if (!isObj4(e) || !fin3(e.t) || !fin3(e.amount) || e.amount < 0) return "malformed monitor state: bad ledger entry";
        if (e.t > now) return "malformed monitor state: ledger entry after now (clock regression)";
      }
    }
    if (total > MAX_STATE_ENTRIES) return "malformed monitor state: too many entries";
    for (const k of nk) {
      if (FORBIDDEN_IDS.has(k) || k.length > MAX_ID_LEN) return "malformed monitor state: bad latch key";
      const t = state.latched[k];
      if (!fin3(t) || t > now) return "malformed monitor state: bad latch";
    }
    return null;
  } catch {
    return "malformed monitor state";
  }
}
var cmpEntry = (a, b) => a.t - b.t || a.amount - b.amount;
function canonicalState(state) {
  const p = stateProblem(state);
  if (p) throw new TypeError(p);
  const ledger = {};
  for (const k of Object.keys(state.ledger)) {
    const l = state.ledger[k].map((e) => ({ t: e.t, amount: e.amount })).sort(cmpEntry);
    if (l.length) ledger[k] = l;
  }
  const latched = {};
  for (const k of Object.keys(state.latched)) latched[k] = state.latched[k];
  return { d: STATE_DIGEST_DOMAIN, now: state.now, seq: state.seq, parent: state.parent, ledger, latched };
}
function stateDigest(state) {
  return hashCanonical(canonicalState(state));
}
function tickState(state, now) {
  if (stateProblem(state)) return { ok: false, reason: "malformed monitor state" };
  if (!fin3(now) || now < state.now) return { ok: false, reason: "clock regression" };
  return { ok: true, state: { ...state, now } };
}
function paramsUnavailable(path, ctx) {
  if (typeof path !== "string") return false;
  if (path !== "action.params" && !path.startsWith("action.params.")) return false;
  const p = ctx.action.params;
  return p === void 0 || p === null || typeof p !== "object";
}
function conditionConservative(c, ctx) {
  if (!isObj4(c) || typeof c.field !== "string" || !c.field) return true;
  if (typeof c.op !== "string" || !OPS.has(c.op)) return true;
  if (c.ref !== void 0 && typeof c.ref !== "string") return true;
  if (c.op === "exists") return paramsUnavailable(c.field, ctx) ? true : evaluateCondition(c, ctx);
  if (paramsUnavailable(c.field, ctx) || paramsUnavailable(c.ref, ctx)) return true;
  const f = resolvePath(ctx, c.field);
  if (!f.found) return true;
  let operand;
  if (c.ref !== void 0) {
    const r = resolvePath(ctx, c.ref);
    if (!r.found) return true;
    operand = r.value;
  } else {
    if (!has3(c, "value") || c.value === void 0) return true;
    operand = c.value;
  }
  if ((c.op === "in" || c.op === "nin") && !Array.isArray(operand)) return true;
  if (c.op === "prefix" && !(typeof f.value === "string" && typeof operand === "string")) return true;
  if (c.op === "lt" || c.op === "lte" || c.op === "gt" || c.op === "gte") {
    const a = f.value;
    const comparable = typeof a === "number" && typeof operand === "number" && Number.isFinite(a) && Number.isFinite(operand) || typeof a === "string" && typeof operand === "string";
    if (!comparable) return true;
  }
  return evaluateCondition(c, ctx);
}
function whenMatches(w, ctx) {
  try {
    if (validateWhen(w, "when")) return true;
    const a = ctx?.action;
    if (!a || typeof a.verb !== "string" || typeof a.resource !== "string") return true;
    const oversized = typeof w.resource === "string" && w.resource.startsWith("re:") && a.resource.length > MAX_RE_RESOURCE_LEN;
    if (!predicateMatches({ verb: w.verb, ...oversized ? {} : { resource: w.resource } }, ctx)) return false;
    for (const c of w.where ?? []) if (!conditionConservative(c, ctx)) return false;
    return true;
  } catch {
    return true;
  }
}
function whenAffirmative(w, ctx) {
  try {
    return validateWhen(w, "when") === null && predicateMatches(w, ctx);
  } catch {
    return false;
  }
}
var allHold = (cs, ctx) => cs.every((c) => evaluateCondition(c, ctx));
var windowEntries = (state, id, windowSecs) => {
  const l = has3(state.ledger, id) ? state.ledger[id] : void 0;
  if (!Array.isArray(l)) return [];
  const lo = windowSecs === void 0 ? -Infinity : state.now - windowSecs * 1e3;
  return l.filter((e) => e.t > lo && e.t <= state.now).sort(cmpEntry);
};
function evalOne(inv, ctx, state) {
  switch (inv.kind) {
    case "never":
      return whenMatches(inv.when, ctx) ? { ok: false, reason: inv.description ?? "forbidden action" } : { ok: true };
    case "never_unless": {
      if (!whenMatches(inv.when, ctx)) return { ok: true };
      return allHold(inv.unless, ctx) ? { ok: true } : { ok: false, reason: inv.description ?? "forbidden without required condition" };
    }
    case "cap": {
      if (!whenMatches(inv.when, ctx)) return { ok: true };
      const a = resolvePath(ctx, inv.amount);
      if (!a.found || !fin3(a.value) || a.value < 0) return { ok: false, reason: "amount unresolvable (fail closed)" };
      const spent = windowEntries(state, inv.id, inv.window_secs).reduce((s, e) => s + e.amount, 0);
      return spent + a.value <= inv.max ? { ok: true } : { ok: false, reason: `cap exceeded: ${spent} + ${a.value} > ${inv.max}` };
    }
    case "rate": {
      if (!whenMatches(inv.when, ctx)) return { ok: true };
      const n = windowEntries(state, inv.id, inv.window_secs).length;
      return n + 1 <= inv.max ? { ok: true } : { ok: false, reason: `rate exceeded: ${n + 1} > ${inv.max} per ${inv.window_secs}s` };
    }
    case "never_after": {
      if (!has3(state.latched, inv.id) || !whenMatches(inv.forbid, ctx)) return { ok: true };
      return { ok: false, reason: inv.description ?? "forbidden after trigger" };
    }
    case "require_prior": {
      if (!whenMatches(inv.when, ctx)) return { ok: true };
      return has3(state.latched, inv.id) ? { ok: true } : { ok: false, reason: inv.description ?? "required prior action not admitted" };
    }
    case "require_approval_over": {
      if (!whenMatches(inv.when, ctx)) return { ok: true };
      const a = resolvePath(ctx, inv.amount);
      const over = !a.found || !fin3(a.value) || a.value < 0 || a.value > inv.threshold;
      if (!over) return { ok: true };
      return allHold(inv.approved, ctx) ? { ok: true } : { ok: false, reason: inv.description ?? `approval required over ${inv.threshold}` };
    }
  }
}
function checkProhibitions(action, constitution, state) {
  const fail2 = (id, reason) => ({
    ok: false,
    violated: [id],
    reasons: [reason],
    evaluated: [{ id, kind: "structural", result: "violated", reason }]
  });
  try {
    const cp = validateConstitution(constitution);
    if (cp.length) return fail2("<constitution>", cp[0]);
    const a = action?.action;
    if (!a || typeof a.verb !== "string" || typeof a.resource !== "string") return fail2("<action>", "malformed action");
    const sp = stateProblem(state);
    if (sp) return fail2("<state>", sp);
    const evaluated = [];
    for (const inv of constitution.invariants) {
      let r;
      try {
        r = evalOne(inv, action, state);
      } catch {
        r = { ok: false, reason: "evaluation error (fail closed)" };
      }
      evaluated.push({ id: inv.id, kind: inv.kind, result: r.ok ? "pass" : "violated", ...r.reason ? { reason: r.reason } : {} });
    }
    const bad = evaluated.filter((e) => e.result === "violated");
    return { ok: bad.length === 0, violated: bad.map((e) => e.id), reasons: bad.map((e) => `${e.id}: ${e.reason ?? "violated"}`), evaluated };
  } catch {
    return fail2("<monitor>", "monitor error (fail closed)");
  }
}
function advanceStateStrict(action, constitution, state, now = state?.now) {
  try {
    const cp = validateConstitution(constitution);
    if (cp.length) return { ok: false, reason: cp[0] };
    const sp = stateProblem(state);
    if (sp) return { ok: false, reason: sp };
    if (!fin3(now) || now < state.now) return { ok: false, reason: "clock regression" };
    const a = action?.action;
    if (!a || typeof a.verb !== "string" || typeof a.resource !== "string") return { ok: false, reason: "malformed action" };
    const canon = canonicalState(state);
    const prevDigest = hashCanonical(canon);
    const actionDigest = hashCanonical(action);
    const ledger = {};
    for (const [k, v] of Object.entries(canon.ledger)) ledger[k] = v.slice();
    const latched = { ...canon.latched };
    for (const inv of constitution.invariants) {
      if (inv.kind === "cap" || inv.kind === "rate") {
        const prev = has3(ledger, inv.id) ? ledger[inv.id] : [];
        const lo = inv.window_secs === void 0 ? -Infinity : now - inv.window_secs * 1e3;
        const kept = prev.filter((e) => e.t > lo);
        if (whenMatches(inv.when, action)) {
          let amount = 1;
          if (inv.kind === "cap") {
            const r = resolvePath(action, inv.amount);
            if (!r.found || !fin3(r.value) || r.value < 0) return { ok: false, reason: `${inv.id}: amount unresolvable` };
            amount = r.value;
          }
          kept.push({ t: now, amount });
        }
        kept.sort(cmpEntry);
        if (kept.length > MAX_LEDGER) {
          if (inv.kind === "rate") return { ok: false, reason: `${inv.id}: rate ledger overflow` };
          while (kept.length > MAX_LEDGER) {
            const [x, y] = kept.splice(0, 2);
            kept.unshift({ t: y.t, amount: x.amount + y.amount });
          }
        }
        if (kept.length) ledger[inv.id] = kept;
        else delete ledger[inv.id];
      } else if (inv.kind === "never_after") {
        if (!has3(latched, inv.id) && whenMatches(inv.after, action)) latched[inv.id] = now;
      } else if (inv.kind === "require_prior") {
        if (!has3(latched, inv.id) && whenAffirmative(inv.prior, action)) latched[inv.id] = now;
      }
    }
    const next = {
      now,
      seq: state.seq + 1,
      parent: hashCanonical({ d: STATE_CHAIN_DOMAIN, state: prevDigest, action: actionDigest }),
      ledger,
      latched
    };
    if (stateProblem(next)) return { ok: false, reason: "resulting state invalid" };
    return { ok: true, state: next };
  } catch {
    return { ok: false, reason: "advance error (fail closed)" };
  }
}
function advanceState(action, constitution, state, now = state?.now) {
  const r = advanceStateStrict(action, constitution, state, now);
  return r.ok ? r.state : state;
}
var UNHASHABLE = "<unhashable>";
var safe = (f) => {
  try {
    return f();
  } catch {
    return UNHASHABLE;
  }
};
function proveSafety(action, constitution, state) {
  const r = checkProhibitions(action, constitution, state);
  const cid = safe(() => constitutionId(constitution));
  const adg = safe(() => hashCanonical(action));
  const sdg = safe(() => stateDigest(state));
  const extra = [];
  if (cid === UNHASHABLE) extra.push("<constitution>");
  if (adg === UNHASHABLE) extra.push("<action>");
  if (sdg === UNHASHABLE) extra.push("<state>");
  return {
    v: EVIDENCE_VERSION,
    constitution: cid,
    action_digest: adg,
    state_digest: sdg,
    now: fin3(state?.now) ? state.now : 0,
    evaluated: r.evaluated,
    ok: r.ok && extra.length === 0,
    violated: [...r.violated, ...extra.filter((x) => !r.violated.includes(x))]
  };
}
var evidenceDigest = (e) => hashCanonical(e);
function verifySafetyEvidence(evidence, action, constitution, state) {
  try {
    if (!evidence || evidence.v !== EVIDENCE_VERSION) return { ok: false, reason: "unsupported evidence version" };
    const fresh = proveSafety(action, constitution, state);
    if (fresh.constitution !== evidence.constitution) return { ok: false, reason: "constitution mismatch" };
    if (fresh.action_digest !== evidence.action_digest) return { ok: false, reason: "action digest mismatch" };
    if (fresh.state_digest !== evidence.state_digest) return { ok: false, reason: "state digest mismatch" };
    if (hashCanonical(fresh) !== hashCanonical(evidence)) return { ok: false, reason: "evidence does not reproduce" };
    if (!fresh.ok) return { ok: false, reason: "prohibition violated: " + fresh.violated.join(",") };
    return { ok: true };
  } catch {
    return { ok: false, reason: "verification error (fail closed)" };
  }
}
function safetyBindingId(evidence, signer) {
  return hashCanonical({
    d: SAFETY_EVIDENCE_SIG_DOMAIN,
    signer,
    evidence: hashCanonical(evidence),
    constitution: evidence.constitution,
    action_digest: evidence.action_digest,
    state_digest: evidence.state_digest
  });
}
function signSafetyEvidence(evidence, signerSecret, signerPublic) {
  if (!evidence || evidence.v !== EVIDENCE_VERSION) throw new TypeError("signSafetyEvidence: unsupported evidence");
  for (const d of [evidence.constitution, evidence.action_digest, evidence.state_digest]) {
    if (typeof d !== "string" || !d || d === UNHASHABLE) throw new TypeError("signSafetyEvidence: unbound evidence");
  }
  if (typeof signerPublic !== "string" || !signerPublic) throw new TypeError("signSafetyEvidence: signer missing");
  const id = safetyBindingId(evidence, signerPublic);
  return { evidence, signer: signerPublic, id, sig: b64u(sign(signerSecret, domainMessage(SAFETY_EVIDENCE_SIG_DOMAIN, id))) };
}
function verifySignedSafetyEvidence(signed, expected) {
  const no = (reason) => ({ ok: false, reason });
  try {
    if (!isObj4(signed) || !isObj4(signed.evidence) || !isObj4(expected)) return no("malformed input");
    const ev = signed.evidence;
    if (ev.v !== EVIDENCE_VERSION) return no("unsupported evidence version");
    const signers = Array.isArray(expected.signer) ? expected.signer : [expected.signer];
    if (!signers.length || signers.some((s) => typeof s !== "string" || !s)) return no("no pinned signer");
    if (typeof signed.signer !== "string" || !signers.includes(signed.signer)) return no("signer not trusted");
    if (expected.action === void 0 && expected.actionDigest === void 0) return no("unbound: action not specified");
    if (expected.constitution === void 0 && expected.constitutionId === void 0) return no("unbound: constitution not specified");
    if (expected.state === void 0 && expected.stateDigest === void 0) return no("unbound: state not specified");
    if (typeof signed.id !== "string" || signed.id !== safetyBindingId(ev, signed.signer)) return no("binding id mismatch");
    if (typeof signed.sig !== "string" || !verifyB64u(signed.signer, domainMessage(SAFETY_EVIDENCE_SIG_DOMAIN, signed.id), signed.sig)) return no("bad signature");
    const wantAction = expected.action !== void 0 ? hashCanonical(expected.action) : expected.actionDigest;
    if (expected.action !== void 0 && expected.actionDigest !== void 0 && expected.actionDigest !== wantAction) return no("expected action and digest disagree");
    if (ev.action_digest !== wantAction) return no("action digest mismatch (evidence bound to another action)");
    if (expected.principal !== void 0) {
      const sc = expected.constitution;
      if (!sc || typeof sc.sig !== "string") return no("principal pin requires a signed constitution");
      const vc = verifyConstitution(sc, expected.principal);
      if (!vc.ok) return no("constitution not authentic: " + vc.reason);
    }
    const wantConst = expected.constitution !== void 0 ? constitutionId(expected.constitution) : expected.constitutionId;
    if (expected.constitution !== void 0 && expected.constitutionId !== void 0 && expected.constitutionId !== wantConst) return no("expected constitution and id disagree");
    if (ev.constitution !== wantConst) return no("constitution mismatch (evidence bound to another constitution)");
    const wantState = expected.state !== void 0 ? stateDigest(expected.state) : expected.stateDigest;
    if (expected.state !== void 0 && expected.stateDigest !== void 0 && expected.stateDigest !== wantState) return no("expected state and digest disagree");
    if (ev.state_digest !== wantState) return no("state digest mismatch (evidence bound to another state)");
    if (!Array.isArray(ev.evaluated) || !Array.isArray(ev.violated)) return no("malformed evidence");
    const badRows = ev.evaluated.filter((r) => r?.result !== "pass").map((r) => r?.id);
    if (ev.ok !== (badRows.length === 0 && ev.violated.length === 0)) return no("evidence verdict inconsistent with rows");
    if (expected.action !== void 0 && expected.constitution !== void 0 && expected.state !== void 0) {
      const full = verifySafetyEvidence(ev, expected.action, expected.constitution, expected.state);
      if (!full.ok && ev.ok) return no(full.reason ?? "evidence does not reproduce");
      if (!full.ok && !ev.ok && full.reason !== void 0 && !full.reason.startsWith("prohibition violated")) return no(full.reason);
    } else if (ev.ok && expected.constitution !== void 0) {
      const ids = expected.constitution.invariants.map((i) => i.id);
      if (ev.evaluated.length !== ids.length || ev.evaluated.some((r, i) => r.id !== ids[i])) return no("evidence does not cover every invariant");
    }
    if (expected.requireOk !== false && !ev.ok) return no("prohibition violated: " + ev.violated.join(","));
    return { ok: true };
  } catch {
    return no("verification error (fail closed)");
  }
}
function composeAuthority(permitted, action, constitution, state) {
  const prohibition = checkProhibitions(action, constitution, state);
  const p = permitted === true;
  return {
    allow: p && prohibition.ok,
    decidedBy: !prohibition.ok ? "prohibition" : p ? "none" : "permission",
    permitted: p,
    prohibition
  };
}
function checkAndAdvance(permitted, action, constitution, state, opts = {}) {
  const evidence = proveSafety(action, constitution, state);
  const decision = composeAuthority(permitted, action, constitution, state);
  const refuse = (decidedBy, reason) => ({
    allow: false,
    decidedBy,
    evidence,
    prohibition: decision.prohibition,
    next: state,
    ...reason ? { reason } : {}
  });
  try {
    if (opts.expectedSeq !== void 0 && (!isObj4(state) || state.seq !== opts.expectedSeq)) return refuse("state", "stale state head (seq)");
    if (opts.expectedStateDigest !== void 0 && safe(() => stateDigest(state)) !== opts.expectedStateDigest) return refuse("state", "stale state head (digest)");
    if (!decision.allow) return refuse(decision.decidedBy === "none" ? "permission" : decision.decidedBy);
    if (!evidence.ok) return refuse("prohibition", "evidence not attestable");
    const adv = advanceStateStrict(action, constitution, state);
    if (!adv.ok) return refuse("state", "advance failed: " + adv.reason);
    return { allow: true, decidedBy: "none", evidence, prohibition: decision.prohibition, next: adv.state };
  } catch {
    return refuse("state", "check-and-advance error (fail closed)");
  }
}

// packages/pca/src/progress.ts
var progress_exports = {};
__export(progress_exports, {
  DEFAULT_POTENTIALS: () => DEFAULT_POTENTIALS,
  InMemoryStateSource: () => InMemoryStateSource,
  PROGRESS_SIG_DOMAIN: () => PROGRESS_SIG_DOMAIN,
  PROGRESS_VERSION: () => PROGRESS_VERSION,
  PotentialRegistry: () => PotentialRegistry,
  ProgressTracker: () => ProgressTracker,
  commitGoal: () => commitGoal2,
  dagRemainingPotential: () => dagRemainingPotential,
  dagWeightedPotential: () => dagWeightedPotential,
  goalDigest: () => goalDigest,
  l1FeaturePotential: () => l1FeaturePotential,
  progressStepDigest: () => progressStepDigest,
  signProgressStep: () => signProgressStep,
  stateDigest: () => stateDigest2,
  trajectoryHead: () => trajectoryHead,
  verifyGoalCommitment: () => verifyGoalCommitment2,
  verifyProgressStep: () => verifyProgressStep,
  verifySignedProgressStep: () => verifySignedProgressStep,
  verifySignedTrajectory: () => verifySignedTrajectory,
  verifyTrajectory: () => verifyTrajectory
});
var PROGRESS_VERSION = 2;
var PROGRESS_SIG_DOMAIN = "atlas-pca/progress-step/v2";
function assertInt(n, what) {
  if (typeof n !== "number" || !Number.isSafeInteger(n)) throw new TypeError(`${what}: safe integer required`);
}
var isObj5 = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
var isStr4 = (x) => typeof x === "string";
function snapshot(v) {
  return JSON.parse(canonicalize(v));
}
var PotentialRegistry = class _PotentialRegistry {
  m = /* @__PURE__ */ new Map();
  frozen = false;
  /** Register `fn` under `id` (idempotent re-registration is refused: ids are immutable). */
  register(id, fn, embedder = "") {
    if (this.frozen) throw new Error("registry is frozen");
    if (!isStr4(id) || id.length === 0 || id.length > 128) throw new TypeError("potential id: 1..128 chars");
    if (typeof fn !== "function") throw new TypeError("potential must be a function");
    if (!isStr4(embedder)) throw new TypeError("embedder must be a string");
    if (this.m.has(id)) throw new Error(`potential ${id} already registered`);
    this.m.set(id, { fn, embedder });
    return this;
  }
  /** Resolve a committed id, or undefined (callers must treat that as a denial). */
  get(id) {
    return this.m.get(id);
  }
  has(id) {
    return this.m.has(id);
  }
  /** Registered ids, sorted (deterministic). */
  ids() {
    return [...this.m.keys()].sort();
  }
  /** Forbid further registration. Returns this. */
  freeze() {
    this.frozen = true;
    return this;
  }
  /** Build from a plain record (own enumerable keys only). */
  static from(rec) {
    const r = new _PotentialRegistry();
    for (const k of Object.keys(rec)) {
      const v = rec[k];
      if (typeof v === "function") r.register(k, v);
      else r.register(k, v.fn, v.embedder ?? "");
    }
    return r;
  }
  /** A fresh, mutable registry holding the three built-in potentials. */
  static defaults() {
    return new _PotentialRegistry().register("l1-feature-v1", l1FeaturePotential).register("dag-remaining-v1", dagRemainingPotential).register("dag-weighted-v1", dagWeightedPotential);
  }
};
function toRegistry(r) {
  if (r === void 0) return DEFAULT_POTENTIALS;
  return r instanceof PotentialRegistry ? r : PotentialRegistry.from(r);
}
var l1FeaturePotential = (objective, state) => {
  const t = objective?.target;
  const x = state?.x;
  if (!Array.isArray(t) || !Array.isArray(x) || t.length !== x.length) throw new TypeError("l1-feature-v1: bad shape");
  let d = 0;
  for (let i = 0; i < t.length; i++) {
    assertInt(t[i], "target");
    assertInt(x[i], "x");
    d += Math.abs(t[i] - x[i]);
    assertInt(d, "distance");
  }
  return d;
};
var dagRemainingPotential = (objective, state) => {
  const tasks = objective?.tasks;
  const done = state?.done;
  if (!Array.isArray(tasks) || !Array.isArray(done)) throw new TypeError("dag-remaining-v1: bad shape");
  const ids = new Set(tasks.map((t) => t.id));
  if (ids.size !== tasks.length) throw new TypeError("dag-remaining-v1: duplicate task id");
  const doneSet = new Set(done);
  for (const d of doneSet) if (!ids.has(d)) throw new TypeError(`dag-remaining-v1: unknown task ${d}`);
  let rem = 0;
  for (const t of tasks) {
    assertInt(t.cost, "cost");
    if (t.cost < 0) throw new TypeError("negative cost");
    if (!doneSet.has(t.id)) rem += t.cost;
    assertInt(rem, "remaining");
  }
  return rem;
};
var dagWeightedPotential = (objective, state) => {
  const tasks = objective?.tasks;
  const done = state?.done;
  if (!Array.isArray(tasks) || !Array.isArray(done)) throw new TypeError("dag-weighted-v1: bad shape");
  const byId = /* @__PURE__ */ new Map();
  for (const t of tasks) {
    if (!isObj5(t) || !isStr4(t.id) || t.id.length === 0) throw new TypeError("dag-weighted-v1: bad task");
    if (byId.has(t.id)) throw new TypeError("dag-weighted-v1: duplicate task id");
    assertInt(t.cost, "cost");
    if (t.cost < 0) throw new TypeError("negative cost");
    const deps = t.deps ?? [];
    if (!Array.isArray(deps) || !deps.every(isStr4)) throw new TypeError("dag-weighted-v1: bad deps");
    byId.set(t.id, { cost: t.cost, deps });
  }
  const indeg = /* @__PURE__ */ new Map();
  const rev = /* @__PURE__ */ new Map();
  for (const [id, t] of byId) {
    indeg.set(id, new Set(t.deps).size);
    for (const d of new Set(t.deps)) {
      if (d === id || !byId.has(d)) throw new TypeError(`dag-weighted-v1: bad dependency ${d}`);
      rev.set(d, [...rev.get(d) ?? [], id]);
    }
  }
  const q = [...indeg].filter(([, n]) => n === 0).map(([id]) => id);
  let seen = 0;
  while (q.length) {
    const id = q.pop();
    seen++;
    for (const n of rev.get(id) ?? []) {
      const k = indeg.get(n) - 1;
      indeg.set(n, k);
      if (k === 0) q.push(n);
    }
  }
  if (seen !== byId.size) throw new TypeError("dag-weighted-v1: cycle");
  const doneSet = /* @__PURE__ */ new Set();
  for (const d of done) {
    if (!isStr4(d) || !byId.has(d)) throw new TypeError(`dag-weighted-v1: unknown task ${String(d)}`);
    if (doneSet.has(d)) throw new TypeError("dag-weighted-v1: duplicate done");
    doneSet.add(d);
  }
  for (const d of doneSet) {
    for (const dep of byId.get(d).deps) {
      if (!doneSet.has(dep)) throw new TypeError(`dag-weighted-v1: ${d} done before dependency ${dep}`);
    }
  }
  let rem = 0;
  for (const [id, t] of byId) {
    if (!doneSet.has(id)) rem += t.cost;
    assertInt(rem, "remaining");
  }
  return rem;
};
var DEFAULT_POTENTIALS = PotentialRegistry.defaults().freeze();
function validateGoal(goal) {
  if (!isObj5(goal)) throw new TypeError("goal must be an object");
  assertInt(goal.epsilon, "epsilon");
  assertInt(goal.explorationBudget, "explorationBudget");
  if (goal.epsilon < 1) throw new RangeError("epsilon must be >= 1");
  if (goal.explorationBudget < 0) throw new RangeError("explorationBudget must be >= 0");
  if (!isStr4(goal.potential) || goal.potential.length === 0) throw new TypeError("potential id required");
  if (!isStr4(goal.metric)) throw new TypeError("metric must be a string");
  if (goal.embedder !== void 0 && !isStr4(goal.embedder)) throw new TypeError("embedder must be a string");
}
function goalDigest(goal) {
  validateGoal(goal);
  return hashCanonical({
    t: "pca-goal",
    v: PROGRESS_VERSION,
    objective: goal.objective,
    potential: goal.potential,
    embedder: goal.embedder ?? "",
    metric: goal.metric,
    epsilon: goal.epsilon,
    explorationBudget: goal.explorationBudget
  });
}
function commitGoal2(goal) {
  const c = goalDigest(goal);
  return { goal: snapshot(goal), commitment: c };
}
function verifyGoalCommitment2(goal, commitment) {
  try {
    return goalDigest(goal) === commitment;
  } catch {
    return false;
  }
}
var GENESIS = "genesis";
function stepBodyDigest(s) {
  return hashCanonical({ t: "pca-progress-step", v: PROGRESS_VERSION, ...s });
}
function stateDigest2(state) {
  return hashCanonical({ t: "pca-state", state });
}
function trajectoryHead(steps) {
  return steps.length ? steps[steps.length - 1].digest : GENESIS;
}
function progressStepDigest(step) {
  return step.digest;
}
var ProgressError = class extends Error {
  constructor(code, msg3) {
    super(msg3);
    this.code = code;
  }
};
function resolve(goal, reg) {
  const spec = reg.get(goal.potential);
  if (!spec) throw new ProgressError("unknown-potential", `unknown potential ${goal.potential}`);
  if ((spec.embedder ?? "") !== (goal.embedder ?? "")) throw new ProgressError("embedder-mismatch", "embedder mismatch");
  return spec;
}
function potentialOf(goal, reg, state) {
  const spec = resolve(goal, reg);
  let p;
  try {
    p = spec.fn(goal.objective, state);
    assertInt(p, "potential");
  } catch (e) {
    throw new ProgressError("bad-potential", e.message);
  }
  if (p < 0) throw new ProgressError("bad-potential", "potential must be >= 0");
  return p;
}
function denialOf(e) {
  return e instanceof ProgressError ? e.code : "bad-potential";
}
function classify(pb, pa, epsilon) {
  const required = pb - epsilon;
  if (pa <= required || pa === 0 && pb > 0) return { mode: "progress", charge: 0 };
  const charge = pa - required;
  try {
    assertInt(charge, "charge");
  } catch (e) {
    throw new ProgressError("bad-potential", e.message);
  }
  return { mode: "exploration", charge };
}
var InMemoryStateSource = class {
  constructor(initial, id = "in-memory") {
    this.id = id;
    this.cur = snapshot(initial);
  }
  cur;
  n = 0;
  requests = [];
  /** Mutate the world (what the real action would do). */
  apply(next) {
    this.cur = snapshot(next);
  }
  observe(req) {
    this.requests.push(req);
    const state = snapshot(this.cur);
    return {
      state,
      state_digest: stateDigest2(state),
      source: this.id,
      evidence: { kind: "in-memory", n: this.n++, prior: req.prior_digest, action: req.action_digest }
    };
  }
};
var ProgressTracker = class {
  constructor(goal, commitment, initial, registry, opts = {}) {
    this.commitment = commitment;
    this.opts = opts;
    if (!verifyGoalCommitment2(goal, commitment)) throw new Error("goal does not match commitment");
    this.goal = snapshot(goal);
    this.reg = toRegistry(registry);
    this.cur = snapshot(initial);
    this.curDigest = stateDigest2(this.cur);
    potentialOf(this.goal, this.reg, this.cur);
  }
  seq = 0;
  head = GENESIS;
  spentTotal = 0;
  cur;
  curDigest;
  log = [];
  reg;
  /** Detached snapshot of the committed goal. */
  goal;
  /** Total exploration charged so far (always <= explorationBudget). */
  get spent() {
    return this.spentTotal;
  }
  get remaining() {
    return this.goal.explorationBudget - this.spentTotal;
  }
  get state() {
    return this.cur;
  }
  /** Digest of the current state. */
  get currentStateDigest() {
    return this.curDigest;
  }
  get reached() {
    return potentialOf(this.goal, this.reg, this.cur) === 0;
  }
  /** Proofs issued so far (read-only copy). */
  get steps() {
    return [...this.log];
  }
  /** Attempt a step to a self-reported `after`. Does not advance state on denial. */
  step(after, actionDigest) {
    return this.advance(after, actionDigest, "", "");
  }
  /**
   * Observe the post-action state from a trusted StateSource and step to it. The observation's
   * digest and source id are checked, and the source id + evidence digest are committed into the
   * step. Does not advance on any denial.
   */
  async stepObserved(source, actionDigest) {
    let obs;
    try {
      obs = await source.observe({
        action_digest: actionDigest,
        goal_commitment: this.commitment,
        prior_digest: this.curDigest
      });
      if (!obs || obs.source !== source.id || obs.state_digest !== stateDigest2(obs.state)) {
        return { ok: false, reason: "state-source-mismatch", stepUp: false };
      }
      return this.advance(obs.state, actionDigest, source.id, hashCanonical({ t: "pca-evidence", e: obs.evidence ?? null }));
    } catch {
      return { ok: false, reason: "state-source-mismatch", stepUp: false };
    }
  }
  advance(afterIn, actionDigest, stateSource, evidenceDigest2) {
    if (!isStr4(actionDigest) || actionDigest.length === 0) return { ok: false, reason: "malformed", stepUp: false };
    let after, afterDigest, pb, pa, cls;
    try {
      after = snapshot(afterIn);
      afterDigest = stateDigest2(after);
      pb = potentialOf(this.goal, this.reg, this.cur);
      pa = potentialOf(this.goal, this.reg, after);
      cls = classify(pb, pa, this.goal.epsilon);
    } catch (e) {
      return { ok: false, reason: denialOf(e), stepUp: false };
    }
    if (this.opts.guard && !runGuard(this.opts.guard, { seq: this.seq, before: this.cur, after, action_digest: actionDigest })) {
      return { ok: false, reason: "prohibited", stepUp: false };
    }
    const nextSpent = this.spentTotal + cls.charge;
    if (!Number.isSafeInteger(nextSpent) || nextSpent > this.goal.explorationBudget) {
      return { ok: false, reason: "exploration-exhausted", stepUp: true };
    }
    const body2 = {
      goal_commitment: this.commitment,
      seq: this.seq,
      before: this.cur,
      after,
      before_digest: this.curDigest,
      after_digest: afterDigest,
      action_digest: actionDigest,
      mode: cls.mode,
      potential_before: pb,
      potential_after: pa,
      charge: cls.charge,
      state_source: stateSource,
      evidence_digest: evidenceDigest2,
      prev: this.head
    };
    const step = { ...body2, digest: stepBodyDigest(body2) };
    this.log.push(step);
    this.seq++;
    this.head = step.digest;
    this.spentTotal = nextSpent;
    this.cur = after;
    this.curDigest = afterDigest;
    return { ok: true, step, spent: this.spentTotal, remaining: this.remaining };
  }
};
function runGuard(g, t) {
  try {
    return g(t) === true;
  } catch {
    return false;
  }
}
var fail = (reason) => ({ ok: false, reason });
function isStep(s) {
  if (!isObj5(s)) return false;
  return isStr4(s.goal_commitment) && Number.isSafeInteger(s.seq) && s.seq >= 0 && isStr4(s.before_digest) && isStr4(s.after_digest) && isStr4(s.action_digest) && (s.mode === "progress" || s.mode === "exploration") && Number.isSafeInteger(s.potential_before) && Number.isSafeInteger(s.potential_after) && Number.isSafeInteger(s.charge) && isStr4(s.state_source) && isStr4(s.evidence_digest) && isStr4(s.prev) && isStr4(s.digest) && "before" in s && "after" in s;
}
function verifyProgressStep(goal, commitment, step, opts = {}) {
  try {
    if (!verifyGoalCommitment2(goal, commitment)) return fail("goal-mismatch");
    if (!isStep(step)) return fail("malformed");
    if (step.goal_commitment !== commitment) return fail("goal-mismatch");
    if (opts.expectedSeq !== void 0 && step.seq !== opts.expectedSeq) return fail("seq-mismatch");
    if (opts.expectedPrev !== void 0 && step.prev !== opts.expectedPrev) return fail("chain-break");
    if (opts.expectedActionDigest !== void 0 && step.action_digest !== opts.expectedActionDigest) {
      return fail("action-mismatch");
    }
    if (opts.expectedBeforeDigest !== void 0 && step.before_digest !== opts.expectedBeforeDigest) {
      return fail("state-mismatch");
    }
    if (opts.expectedAfterDigest !== void 0 && step.after_digest !== opts.expectedAfterDigest) {
      return fail("state-mismatch");
    }
    const { digest, ...body2 } = step;
    if (stepBodyDigest(body2) !== digest) return fail("digest-mismatch");
    if (stateDigest2(step.before) !== step.before_digest || stateDigest2(step.after) !== step.after_digest) {
      return fail("state-digest-mismatch");
    }
    const reg = toRegistry(opts.registry);
    let pb, pa, cls;
    try {
      pb = potentialOf(goal, reg, step.before);
      pa = potentialOf(goal, reg, step.after);
      cls = classify(pb, pa, goal.epsilon);
    } catch (e) {
      return fail(denialOf(e));
    }
    if (pb !== step.potential_before || pa !== step.potential_after) return fail("potential-mismatch");
    if (step.mode !== cls.mode) return fail("mode-mismatch");
    if (step.charge !== cls.charge) return fail("charge-mismatch");
    if (opts.trustedStateSources && !opts.trustedStateSources.includes(step.state_source)) {
      return fail("untrusted-state-source");
    }
    if (opts.guard && !runGuard(opts.guard, { seq: step.seq, before: step.before, after: step.after, action_digest: step.action_digest })) {
      return fail("prohibited");
    }
    if (opts.attestation) {
      let ok = false;
      try {
        ok = opts.attestation(step) === true;
      } catch {
        ok = false;
      }
      if (!ok) return fail("attestation-failed");
    }
    return { ok: true, charge: cls.charge };
  } catch {
    return fail("malformed");
  }
}
function verifyTrajectory(goal, commitment, steps, opts = {}) {
  if (!verifyGoalCommitment2(goal, commitment)) return { ok: false, reason: "goal-mismatch", at: -1 };
  if (!Array.isArray(steps)) return { ok: false, reason: "malformed", at: -1 };
  if (opts.expectedActionDigests && opts.expectedActionDigests.length !== steps.length) {
    return { ok: false, reason: "action-mismatch", at: Math.min(opts.expectedActionDigests.length, steps.length) };
  }
  let anchor;
  try {
    anchor = opts.initialDigest ?? (opts.initial === void 0 ? void 0 : stateDigest2(opts.initial));
  } catch {
    return { ok: false, reason: "malformed", at: -1 };
  }
  let prev = GENESIS;
  let spent = 0;
  let finalPotential = -1;
  if (steps.length === 0 && opts.initial !== void 0) {
    try {
      finalPotential = potentialOf(goal, toRegistry(opts.registry), opts.initial);
    } catch (e) {
      return { ok: false, reason: denialOf(e), at: -1 };
    }
  }
  for (let i = 0; i < steps.length; i++) {
    const s = steps[i];
    const r = verifyProgressStep(goal, commitment, s, {
      ...opts,
      expectedSeq: i,
      expectedPrev: prev,
      expectedActionDigest: opts.expectedActionDigests?.[i]
    });
    if (!r.ok) return { ok: false, reason: r.reason, at: i };
    if (anchor !== void 0 && s.before_digest !== anchor) return { ok: false, reason: "discontinuous-state", at: i };
    spent += r.charge;
    if (!Number.isSafeInteger(spent) || spent > goal.explorationBudget) return { ok: false, reason: "budget-exceeded", at: i };
    anchor = s.after_digest;
    prev = s.digest;
    finalPotential = s.potential_after;
  }
  return {
    ok: true,
    spent,
    remaining: goal.explorationBudget - spent,
    reached: finalPotential === 0,
    finalPotential,
    steps: steps.length,
    head: prev
  };
}
function sigMessage3(step, holder) {
  return canonicalBytes({
    d: PROGRESS_SIG_DOMAIN,
    b: {
      holder,
      goal_commitment: step.goal_commitment,
      action_digest: step.action_digest,
      before_digest: step.before_digest,
      after_digest: step.after_digest,
      seq: step.seq,
      prev: step.prev,
      step_digest: step.digest
    }
  });
}
function signProgressStep(step, secretKey, holderPublicKey) {
  return { step, holder: holderPublicKey, sig: b64u(sign(secretKey, sigMessage3(step, holderPublicKey))) };
}
function verifySignedProgressStep(goal, commitment, signed, opts) {
  try {
    if (!isObj5(signed) || !isStr4(signed.holder) || !isStr4(signed.sig) || !isStep(signed.step)) return fail("malformed");
    if (signed.holder !== opts.expectedHolder) return fail("holder-mismatch");
    if (signed.step.action_digest !== opts.expectedActionDigest) return fail("action-mismatch");
    if (signed.step.goal_commitment !== commitment) return fail("goal-mismatch");
    if (!verifyB64u(signed.holder, sigMessage3(signed.step, signed.holder), signed.sig)) return fail("bad-signature");
    return verifyProgressStep(goal, commitment, signed.step, opts);
  } catch {
    return fail("malformed");
  }
}
function verifySignedTrajectory(goal, commitment, signed, opts) {
  if (!Array.isArray(signed)) return { ok: false, reason: "malformed", at: -1 };
  if (opts.expectedActionDigests.length !== signed.length) {
    return { ok: false, reason: "action-mismatch", at: Math.min(opts.expectedActionDigests.length, signed.length) };
  }
  for (let i = 0; i < signed.length; i++) {
    const sp = signed[i];
    try {
      if (!isObj5(sp) || !isStr4(sp.holder) || !isStr4(sp.sig) || !isStep(sp.step)) return { ok: false, reason: "malformed", at: i };
      if (sp.holder !== opts.expectedHolder) return { ok: false, reason: "holder-mismatch", at: i };
      if (sp.step.action_digest !== opts.expectedActionDigests[i]) return { ok: false, reason: "action-mismatch", at: i };
      if (!verifyB64u(sp.holder, sigMessage3(sp.step, sp.holder), sp.sig)) return { ok: false, reason: "bad-signature", at: i };
    } catch {
      return { ok: false, reason: "malformed", at: i };
    }
  }
  const { expectedHolder: _h, ...rest } = opts;
  return verifyTrajectory(goal, commitment, signed.map((s) => s.step), rest);
}

// packages/pca/src/mesh.ts
var mesh_exports = {};
__export(mesh_exports, {
  DEFAULT_MAX_CHAIN_LENGTH: () => DEFAULT_MAX_CHAIN_LENGTH,
  DEFAULT_MAX_CLOCK_SKEW_MS: () => DEFAULT_MAX_CLOCK_SKEW_MS,
  DEFAULT_MAX_HEAD_AGE_MS: () => DEFAULT_MAX_HEAD_AGE_MS,
  MeshDomain: () => MeshDomain,
  MeshWitness: () => MeshWitness,
  assembleMeshProof: () => assembleMeshProof,
  buildMeshExample: () => buildMeshExample,
  checkCosignedHead: () => checkCosignedHead,
  checkHeadAdvance: () => checkHeadAdvance,
  demonstrateForkRejection: () => demonstrateForkRejection,
  effectiveAuthority: () => effectiveAuthority,
  keyRevocationId: () => keyRevocationId,
  meshProofSize: () => meshProofSize,
  revocationLatencyBound: () => revocationLatencyBound,
  signMeshAction: () => signMeshAction,
  verifyMeshProof: () => verifyMeshProof
});
var HEAD_DOMAIN = "atlas-pca/mesh-head/v1\0";
var COSIG_DOMAIN = "atlas-pca/mesh-cosig/v1\0";
var BINDING_DOMAIN = "atlas-pca/mesh-binding/v1\0";
var ACTION_DOMAIN = "atlas-pca/mesh-action/v1\0";
var DEFAULT_MAX_HEAD_AGE_MS = 5 * 6e4;
var DEFAULT_MAX_CLOCK_SKEW_MS = 6e4;
var DEFAULT_MAX_CHAIN_LENGTH = 64;
var MAX_COSIGS = 256;
var MAX_PATH = 128;
var MAX_REV_IDS = 1e6;
function msg2(domain, body2) {
  const b = canonicalBytes(body2);
  const p = utf8(domain);
  const m = new Uint8Array(p.length + b.length);
  m.set(p);
  m.set(b, p.length);
  return m;
}
function keyRevocationId(agentPublic) {
  return `key:${agentPublic}`;
}
var isRec = (x) => typeof x === "object" && x !== null && !Array.isArray(x);
var isStr5 = (x) => typeof x === "string";
var isNat = (x) => typeof x === "number" && Number.isSafeInteger(x) && x >= 0;
var isNum2 = (x) => typeof x === "number" && Number.isFinite(x);
var own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
function validHead(h) {
  if (!isRec(h)) return false;
  if (!isStr5(h.domain) || !isStr5(h.root) || !isStr5(h.rev_root)) return false;
  if (!isNat(h.size) || !isNat(h.rev_size) || !isNum2(h.timestamp)) return false;
  return h.size === 0 === (h.root === "");
}
function validConsistency(c) {
  return isRec(c) && isNat(c.oldSize) && isNat(c.newSize) && Array.isArray(c.path) && c.path.length <= MAX_PATH && c.path.every(isStr5);
}
function validInclusion(i) {
  return isRec(i) && isNat(i.index) && isNat(i.size) && Array.isArray(i.path) && i.path.length <= MAX_PATH;
}
function validAction(a) {
  if (!isRec(a)) return false;
  if (!isStr5(a.type) || !isStr5(a.resource) || !isStr5(a.service_domain) || !isStr5(a.nonce) || !isNum2(a.at)) return false;
  return a.amount === void 0 || isNum2(a.amount);
}
var KNOWN2 = /* @__PURE__ */ new Set(["scope", "resource", "max_amount", "expires", "audience", "max_hops"]);
function intersect(a, b) {
  return a === void 0 ? [...new Set(b)].sort() : a.filter((x) => b.includes(x));
}
function minOf(a, b) {
  return a === void 0 ? b : Math.min(a, b);
}
function effectiveAuthority(caveats) {
  const e = { prefixes: [] };
  for (const c of caveats) {
    if (!KNOWN2.has(c.type)) return { error: `unknown caveat type "${c.type}" (fail closed)` };
    switch (c.type) {
      case "scope":
        if (!Array.isArray(c.actions) || !c.actions.every((x) => typeof x === "string")) return { error: "malformed scope caveat" };
        e.actions = intersect(e.actions, c.actions);
        break;
      case "resource":
        if (typeof c.prefix !== "string") return { error: "malformed resource caveat" };
        e.prefixes.push(c.prefix);
        break;
      case "max_amount":
        if (typeof c.max !== "number" || !Number.isFinite(c.max)) return { error: "malformed max_amount caveat" };
        e.maxAmount = minOf(e.maxAmount, c.max);
        break;
      case "expires":
        if (typeof c.at !== "number" || !Number.isFinite(c.at)) return { error: "malformed expires caveat" };
        e.expiresAt = minOf(e.expiresAt, c.at);
        break;
      case "audience":
        if (!Array.isArray(c.domains) || !c.domains.every((x) => typeof x === "string")) return { error: "malformed audience caveat" };
        e.audience = intersect(e.audience, c.domains);
        break;
      case "max_hops":
        if (typeof c.n !== "number" || !Number.isFinite(c.n)) return { error: "malformed max_hops caveat" };
        e.maxHops = minOf(e.maxHops, c.n);
        break;
    }
  }
  return e;
}
function narrows(child, parent) {
  if (parent.actions !== void 0 && (child.actions === void 0 || !child.actions.every((a) => parent.actions.includes(a)))) return false;
  if (parent.audience !== void 0 && (child.audience === void 0 || !child.audience.every((a) => parent.audience.includes(a)))) return false;
  if (parent.maxAmount !== void 0 && (child.maxAmount === void 0 || child.maxAmount > parent.maxAmount)) return false;
  if (parent.expiresAt !== void 0 && (child.expiresAt === void 0 || child.expiresAt > parent.expiresAt)) return false;
  if (parent.maxHops !== void 0 && (child.maxHops === void 0 || child.maxHops > parent.maxHops)) return false;
  for (const p of parent.prefixes) if (!child.prefixes.includes(p)) return false;
  return true;
}
function admits(e, a, now, chainLen) {
  if (e.actions !== void 0 && !e.actions.includes(a.type)) return `action "${a.type}" not in scope`;
  for (const p of e.prefixes) if (!a.resource.startsWith(p)) return `resource "${a.resource}" outside prefix "${p}"`;
  if (e.maxAmount !== void 0 && (a.amount === void 0 || a.amount > e.maxAmount)) return `amount exceeds ceiling ${e.maxAmount}`;
  if (e.expiresAt !== void 0 && now > e.expiresAt) return "capability expired";
  if (e.audience !== void 0 && !e.audience.includes(a.service_domain)) return "service domain not in audience";
  if (e.maxHops !== void 0 && chainLen > e.maxHops) return `chain exceeds max_hops ${e.maxHops}`;
  return void 0;
}
function checkHeadAdvance(prev, next, proof) {
  try {
    if (!validHead(prev) || !validHead(next)) return "malformed head";
    if (prev.domain !== next.domain) return "head is for a different domain";
    if (next.size < prev.size || next.rev_size < prev.rev_size) return "head rolls back";
    if (next.size === prev.size) {
      if (next.root !== prev.root) return "equivocation (same size, different log)";
    } else {
      if (!validConsistency(proof) || proof.oldSize !== prev.size || proof.newSize !== next.size) {
        return "consistency proof required for a larger head";
      }
      if (!verifyLedgerConsistency(prev.root, next.root, proof)) return "head is not consistent with the previous head (fork or rewrite)";
    }
    if (next.rev_size === prev.rev_size && next.rev_root !== prev.rev_root) return "equivocation (revocation set)";
    return void 0;
  } catch {
    return "malformed head";
  }
}
var MeshWitness = class {
  constructor(secret, opts = {}) {
    this.secret = secret;
    this.opts = opts;
    this.id = encodeKey(publicKeyOf(secret));
  }
  id;
  seen = /* @__PURE__ */ new Map();
  /** The newest head this witness cosigned for `domain` (what a domain must prove consistency from). */
  lastSeen(domain) {
    const s = this.seen.get(domain);
    return s ? { ...s.head } : void 0;
  }
  /** Cosign a head. Throws (and changes nothing) if any rule is violated. */
  cosign(req) {
    const ch = req?.head;
    if (!ch || !validHead(ch.head) || !isStr5(ch.sig)) throw new Error("witness: malformed head");
    const h = ch.head;
    if (!verifyB64u(h.domain, msg2(HEAD_DOMAIN, h), ch.sig)) throw new Error("witness: head not signed by its domain");
    if (this.opts.clock) {
      const skew = this.opts.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS;
      if (h.timestamp > this.opts.clock() + skew) throw new Error("witness: head timestamp is in the future");
    }
    const ids = req.rev_ids;
    if (!Array.isArray(ids) || ids.length > MAX_REV_IDS || !ids.every(isStr5)) throw new Error("witness: malformed revocation list");
    const set = new RevocationSet(ids);
    if (set.size !== h.rev_size || set.root !== h.rev_root) throw new Error("witness: revocation list does not match head");
    const prev = this.seen.get(h.domain);
    if (prev) {
      const why = checkHeadAdvance(prev.head, h, req.consistency);
      if (why) throw new Error(`witness: ${why}`);
      if (h.timestamp < prev.head.timestamp) throw new Error("witness: timestamp regresses");
      const now = new Set(set.list());
      if (!prev.rev.every((id) => now.has(id))) throw new Error("witness: revocation set drops a previously cosigned revocation");
    }
    this.seen.set(h.domain, { head: { ...h }, rev: set.list() });
    return { witness: this.id, sig: b64u(sign(this.secret, msg2(COSIG_DOMAIN, h))) };
  }
  /** Export memory for persistence. Deterministic order. */
  exportState() {
    return { seen: [...this.seen.values()].map((s) => ({ head: { ...s.head }, rev_ids: [...s.rev] })).sort((a, b) => a.head.domain < b.head.domain ? -1 : 1) };
  }
  /** Restore memory; each record must be internally consistent (revocation list reproduces its root). */
  importState(state) {
    const next = /* @__PURE__ */ new Map();
    for (const s of state?.seen ?? []) {
      if (!validHead(s?.head) || !Array.isArray(s.rev_ids) || !s.rev_ids.every(isStr5)) throw new Error("witness: malformed state");
      const set = new RevocationSet(s.rev_ids);
      if (set.size !== s.head.rev_size || set.root !== s.head.rev_root) throw new Error("witness: malformed state");
      next.set(s.head.domain, { head: { ...s.head }, rev: set.list() });
    }
    this.seen.clear();
    for (const [k, v] of next) this.seen.set(k, v);
  }
};
var MeshDomain = class {
  // keyed by head signature
  constructor(name, secret) {
    this.name = name;
    this.secret = secret;
    this.id = encodeKey(publicKeyOf(secret));
  }
  id;
  log = [];
  rev = new RevocationSet();
  snaps = /* @__PURE__ */ new Map();
  /** Vouch that an agent key belongs to this domain. */
  enroll(agent, role) {
    return { agent, domain: this.id, role, sig: b64u(sign(this.secret, msg2(BINDING_DOMAIN, { agent, domain: this.id, role }))) };
  }
  /** Log a delegation hop issued in this domain. Idempotent. */
  record(cap) {
    const h = capHash(cap);
    const i = this.log.indexOf(h);
    if (i >= 0) return i;
    this.log.push(h);
    return this.log.length - 1;
  }
  /** Revoke a capability id (cap.id) or an agent key (keyRevocationId). */
  revoke(id) {
    this.rev.revoke(id);
  }
  /** RFC 9162 consistency proof between two sizes of this domain's current log. */
  consistencyProof(oldSize, newSize = this.log.length) {
    return TransparencyLedger.fromEntries(this.log.map((commit) => ({ commit }))).consistencyProof(oldSize, newSize);
  }
  /**
   * Proof a verifier holding `pin` needs to accept `head` (a head this domain published, larger than
   * the pin). Throws if the pin is not a prefix of that head's log.
   */
  pinProof(pin, head) {
    const snap = this.snaps.get(head.sig);
    if (!snap) throw new Error("pinProof: unknown head");
    const l = TransparencyLedger.fromEntries(snap.log.map((commit) => ({ commit })));
    return { domain: this.id, proof: l.consistencyProof(pin.size, head.head.size) };
  }
  /**
   * Publish a head: domain-signed, then cosigned by `witnesses`, each shown a real consistency proof
   * from ITS last-seen head plus the revocation list. Throws if a witness refuses (unless
   * `opts.threshold` tolerates it); nothing is recorded as published on failure.
   */
  publishHead(witnesses, timestamp, opts = {}) {
    const head = {
      domain: this.id,
      size: this.log.length,
      root: this.log.length === 0 ? "" : merkleRoot(this.log),
      rev_root: this.rev.root,
      rev_size: this.rev.size,
      timestamp
    };
    const ch = { head, sig: b64u(sign(this.secret, msg2(HEAD_DOMAIN, head))), cosigs: [] };
    const ledger = TransparencyLedger.fromEntries(this.log.map((commit) => ({ commit })));
    const rev_ids = this.rev.list();
    const errors = [];
    for (const w of witnesses) {
      const prev = w.lastSeen(this.id);
      let consistency;
      if (prev && prev.size < head.size) consistency = ledger.consistencyProof(prev.size, head.size);
      else if (prev && prev.size > head.size) consistency = { oldSize: prev.size, newSize: head.size, path: [] };
      try {
        ch.cosigs.push(w.cosign({ head: ch, ...consistency ? { consistency } : {}, rev_ids }));
      } catch (e) {
        errors.push(e);
      }
    }
    const need = opts.threshold ?? witnesses.length;
    if (ch.cosigs.length < need) throw errors[0] ?? new Error("publishHead: not enough witnesses");
    this.snaps.set(ch.sig, { log: [...this.log], rev: new RevocationSet(this.rev.list()) });
    return ch;
  }
  /**
   * Build per-hop evidence against a previously published head. Throws if the cap is not in that
   * head's log or if the cap / issuer key is revoked as of that head (no non-membership proof can exist).
   */
  evidence(cap, head, binding) {
    const snap = this.snaps.get(head.sig);
    if (!snap) throw new Error("evidence: unknown head");
    const idx = snap.log.indexOf(capHash(cap));
    if (idx < 0) throw new Error("evidence: capability not in this head");
    const ev = {
      domain: this.id,
      head,
      inclusion: merkleProof(snap.log, idx),
      revocation: {
        cap: snap.rev.nonMembershipProof(cap.id),
        issuer_key: snap.rev.nonMembershipProof(keyRevocationId(cap.issuer))
      }
    };
    if (binding) ev.binding = binding;
    return ev;
  }
};
function signMeshAction(chain2, action, leafSecret) {
  const tip = capHash(chain2[chain2.length - 1]);
  return b64u(sign(leafSecret, msg2(ACTION_DOMAIN, { action, tip })));
}
function assembleMeshProof(args) {
  const heads = [];
  const headIdx = /* @__PURE__ */ new Map();
  const leaves = [];
  const leafIdx = /* @__PURE__ */ new Map();
  const leaf = (l) => {
    const k = JSON.stringify(l);
    let i = leafIdx.get(k);
    if (i === void 0) {
      i = leaves.length;
      leaves.push(l);
      leafIdx.set(k, i);
    }
    return i;
  };
  const compact = (n) => ({
    size: n.size,
    ...n.lo ? { lo: leaf(n.lo) } : {},
    ...n.hi ? { hi: leaf(n.hi) } : {}
  });
  const hops = args.hops.map((ev) => {
    const k = `${ev.head.sig}|${JSON.stringify(ev.head.head)}`;
    let i = headIdx.get(k);
    if (i === void 0) {
      i = heads.length;
      heads.push({ head: ev.head.head, sig: ev.head.sig, cosigs: [...ev.head.cosigs] });
      headIdx.set(k, i);
    } else {
      const have = new Set(heads[i].cosigs.map((c) => c.witness));
      for (const c of ev.head.cosigs) if (!have.has(c.witness)) heads[i].cosigs.push(c);
    }
    const out = {
      domain: ev.domain,
      head: i,
      inclusion: ev.inclusion,
      revocation: { cap: compact(ev.revocation.cap), issuer_key: compact(ev.revocation.issuer_key) }
    };
    if (ev.binding) out.binding = ev.binding;
    return out;
  });
  const proof = {
    chain: args.chain,
    heads,
    rev_leaves: leaves,
    hops,
    action: args.action,
    action_sig: signMeshAction(args.chain, args.action, args.leafSecret)
  };
  if (args.pinProofs && args.pinProofs.length > 0) proof.pin_proofs = args.pinProofs;
  return proof;
}
var bytes = (x) => canonicalBytes(x).length;
function meshProofSize(p) {
  const expand = (c) => ({
    size: c.size,
    ...c.lo !== void 0 && p.rev_leaves[c.lo] ? { lo: p.rev_leaves[c.lo] } : {},
    ...c.hi !== void 0 && p.rev_leaves[c.hi] ? { hi: p.rev_leaves[c.hi] } : {}
  });
  const uncompacted = bytes(p.chain) + bytes(p.action) + bytes(p.action_sig) + p.hops.reduce((n, h) => n + bytes({ ...h, head: p.heads[h.head], revocation: { cap: expand(h.revocation.cap), issuer_key: expand(h.revocation.issuer_key) } }), 0);
  return {
    total_bytes: bytes(p),
    chain_bytes: bytes(p.chain),
    heads_bytes: bytes(p.heads),
    rev_leaves_bytes: bytes(p.rev_leaves),
    hops_bytes: bytes(p.hops),
    uncompacted_bytes: uncompacted
  };
}
function revocationLatencyBound(p) {
  const ok = (x) => typeof x === "number" && Number.isFinite(x) && x >= 0;
  if (!ok(p?.maxHeadAgeMs) || !ok(p?.headIntervalMs) || p.maxClockSkewMs !== void 0 && !ok(p.maxClockSkewMs) || p.pinRefreshMs !== void 0 && !ok(p.pinRefreshMs)) {
    return { published_ms: Infinity, unpinned_ms: Infinity, pinned_ms: Infinity, honest_provers_viable: false };
  }
  const skew = p.maxClockSkewMs ?? 0;
  const unpinned = p.maxHeadAgeMs + skew;
  return {
    published_ms: p.headIntervalMs,
    unpinned_ms: unpinned,
    pinned_ms: p.pinRefreshMs === void 0 ? unpinned : Math.min(unpinned, p.pinRefreshMs),
    honest_provers_viable: p.headIntervalMs + skew < p.maxHeadAgeMs
  };
}
function checkCosignedHead(ch, expectedDomain, t, pinProof) {
  try {
    const h = ch?.head;
    if (!isRec(h) || h.domain !== expectedDomain) return "head is for a different domain";
    if (!validHead(h) || !isStr5(ch.sig)) return "malformed head";
    if (!verifyB64u(h.domain, msg2(HEAD_DOMAIN, h), ch.sig)) return "head not signed by its domain key";
    if (!Array.isArray(ch.cosigs) || ch.cosigs.length > MAX_COSIGS) return "malformed head";
    const pinned = new Set(t.witnesses);
    const good = /* @__PURE__ */ new Set();
    for (const c of ch.cosigs) {
      if (isRec(c) && isStr5(c.witness) && isStr5(c.sig) && pinned.has(c.witness) && !good.has(c.witness) && verifyB64u(c.witness, msg2(COSIG_DOMAIN, h), c.sig)) {
        good.add(c.witness);
      }
    }
    if (good.size < t.threshold) return `head has ${good.size}/${t.threshold} trusted witness cosignatures`;
    const maxAge = t.maxHeadAgeMs ?? DEFAULT_MAX_HEAD_AGE_MS;
    const skew = t.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS;
    if (h.timestamp > t.now + skew) return "head timestamp is in the future";
    if (t.now - h.timestamp > maxAge) return "head is stale";
    const pin = t.pinnedHeads && own(t.pinnedHeads, h.domain) ? t.pinnedHeads[h.domain] : void 0;
    if (pin) {
      const why = checkHeadAdvance(pin, h, pinProof);
      if (why) return `${why} (vs pinned head)`;
    }
    return void 0;
  } catch {
    return "malformed head";
  }
}
function validTrust(t) {
  if (!isRec(t) || !isStr5(t.humanPrincipal) || !Array.isArray(t.witnesses) || !t.witnesses.every(isStr5)) return "invalid trust configuration";
  const distinct = new Set(t.witnesses).size;
  if (!isNat(t.threshold) || t.threshold < 1 || t.threshold > distinct) return "invalid trust configuration: threshold";
  if (!isNum2(t.now)) return "invalid trust configuration: now";
  for (const k of ["maxHeadAgeMs", "maxClockSkewMs", "maxActionAgeMs"]) {
    if (t[k] !== void 0 && !(isNum2(t[k]) && t[k] >= 0)) return `invalid trust configuration: ${k}`;
  }
  if (t.maxChainLength !== void 0 && !(isNat(t.maxChainLength) && t.maxChainLength >= 1)) return "invalid trust configuration: maxChainLength";
  if (t.allowedDomains !== void 0 && !(Array.isArray(t.allowedDomains) && t.allowedDomains.every(isStr5))) return "invalid trust configuration: allowedDomains";
  if (t.pinnedHeads !== void 0 && !isRec(t.pinnedHeads)) return "invalid trust configuration: pinnedHeads";
  return void 0;
}
function expandNM(c, leaves) {
  if (!isRec(c) || !isNat(c.size)) return void 0;
  const out = { size: c.size };
  for (const side of ["lo", "hi"]) {
    const ix = c[side];
    if (ix === void 0) continue;
    if (!isNat(ix) || ix >= leaves.length) return void 0;
    out[side] = leaves[ix];
  }
  return out;
}
function verifyMeshProof(p, t) {
  const trace = [];
  const fail2 = (reason, hop) => ({ ok: false, reason, ...hop !== void 0 ? { hop } : {}, trace });
  try {
    const bad = validTrust(t);
    if (bad) return fail2(bad);
    if (!isRec(p) || !Array.isArray(p.chain) || !Array.isArray(p.hops) || !Array.isArray(p.heads) || !Array.isArray(p.rev_leaves)) return fail2("malformed proof");
    if (!isStr5(p.action_sig) || !validAction(p.action)) return fail2("malformed action");
    if (p.pin_proofs !== void 0 && !(Array.isArray(p.pin_proofs) && p.pin_proofs.length <= MAX_COSIGS && p.pin_proofs.every((x) => isRec(x) && isStr5(x.domain) && validConsistency(x.proof)))) {
      return fail2("malformed pin proofs");
    }
    const chain2 = p.chain;
    if (chain2.length < 1 || chain2.length > (t.maxChainLength ?? DEFAULT_MAX_CHAIN_LENGTH)) return fail2("chain length out of bounds");
    if (p.heads.length > chain2.length || p.rev_leaves.length > 2 * chain2.length) return fail2("evidence tables exceed chain size");
    const chk = verifyChain(chain2, t.humanPrincipal);
    if (!chk.ok) return fail2(`chain: ${chk.reason}`);
    if (p.hops.length !== chain2.length) return fail2("hop evidence count does not match chain length");
    if (!p.rev_leaves.every((l) => isRec(l) && isStr5(l.id) && validInclusion(l.proof))) return fail2("malformed revocation leaves");
    const used = /* @__PURE__ */ new Set();
    for (const ev of p.hops) if (isRec(ev) && isNat(ev.head)) used.add(ev.head);
    if (used.size !== p.heads.length) return fail2("unreferenced or missing head in evidence table");
    const headCache = /* @__PURE__ */ new Map();
    let prev;
    for (let i = 0; i < chain2.length; i++) {
      const cap = chain2[i];
      const ev = p.hops[i];
      if (!isRec(ev) || !isStr5(ev.domain) || !isNat(ev.head) || ev.head >= p.heads.length || !isRec(ev.revocation)) return fail2("malformed hop evidence", i);
      if (t.allowedDomains && !t.allowedDomains.includes(ev.domain)) return fail2("issuing domain not allowed by policy", i);
      const ch = p.heads[ev.head];
      if (!headCache.has(ev.head)) {
        const dom = isRec(ch?.head) && isStr5(ch.head.domain) ? ch.head.domain : "";
        headCache.set(ev.head, checkCosignedHead(ch, dom, t, p.pin_proofs?.find((x) => x.domain === dom)?.proof));
      }
      if (ch.head.domain !== ev.domain) return fail2("source-domain anchor: head is for a different domain", i);
      const headErr = headCache.get(ev.head);
      if (headErr) return fail2(`source-domain anchor: ${headErr}`, i);
      const head = ch.head;
      if (!validInclusion(ev.inclusion) || ev.inclusion.size !== head.size || !verifyInclusion(head.root, ev.inclusion, capHash(cap))) {
        return fail2("hop not included in the issuing domain log", i);
      }
      if (i > 0) {
        const b = ev.binding;
        if (!isRec(b) || !isStr5(b.role) || !isStr5(b.sig) || b.agent !== cap.issuer || b.domain !== ev.domain) return fail2("missing or mismatched domain binding for issuer", i);
        if (!verifyB64u(ev.domain, msg2(BINDING_DOMAIN, { agent: b.agent, domain: b.domain, role: b.role }), b.sig)) {
          return fail2("domain binding signature invalid", i);
        }
      }
      const nmCap = expandNM(ev.revocation.cap, p.rev_leaves);
      const nmKey = expandNM(ev.revocation.issuer_key, p.rev_leaves);
      if (!nmCap || !verifyNonMembership(head.rev_root, nmCap, cap.id)) return fail2("capability revoked (or revocation proof invalid)", i);
      if (!nmKey || !verifyNonMembership(head.rev_root, nmKey, keyRevocationId(cap.issuer))) {
        return fail2("issuer key revoked (or revocation proof invalid)", i);
      }
      const eff = effectiveAuthority(cap.caveats);
      if ("error" in eff) return fail2(eff.error, i);
      if (prev && !narrows(eff, prev)) return fail2("hop widens authority", i);
      prev = eff;
      const next = p.hops[i + 1];
      trace.push({
        hop: i,
        domain: ev.domain,
        issuer: cap.issuer,
        holder: cap.holder,
        crosses_boundary: isRec(next) ? next.domain !== ev.domain : p.action.service_domain !== ev.domain,
        effective: eff
      });
    }
    const skew = t.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS;
    if (p.action.at > t.now + skew) return fail2("action timestamp is in the future");
    if (t.maxActionAgeMs !== void 0 && t.now - p.action.at > t.maxActionAgeMs) return fail2("action is stale");
    const tip = chain2[chain2.length - 1];
    if (!verifyB64u(tip.holder, msg2(ACTION_DOMAIN, { action: p.action, tip: capHash(tip) }), p.action_sig)) {
      return fail2("action not signed by the chain tip holder");
    }
    const denied2 = admits(prev, p.action, t.now, chain2.length);
    if (denied2) return fail2(`action not admitted: ${denied2}`);
    return { ok: true, trace, root_principal: chain2[0].issuer, leaf: tip.holder };
  } catch {
    return fail2("malformed proof");
  }
}
function seedKey(label) {
  return utf8(hashCanonical({ seed: `atlas-pca/mesh-example/${label}` })).slice(0, 32);
}
function buildMeshExample(now = 18e11) {
  const keys = {
    human: seedKey("human"),
    orchestrator: seedKey("orchestrator"),
    tool: seedKey("tool"),
    service: seedKey("service"),
    leaf: seedKey("leaf")
  };
  const leafKey = keys.leaf;
  const pub = (s) => encodeKey(publicKeyOf(s));
  const A = new MeshDomain("org-A", seedKey("domain-A"));
  const B = new MeshDomain("org-B", seedKey("domain-B"));
  const C = new MeshDomain("org-C", seedKey("domain-C"));
  const witnesses = [new MeshWitness(seedKey("witness-1")), new MeshWitness(seedKey("witness-2")), new MeshWitness(seedKey("witness-3"))];
  const root = mintRoot({
    principalSecret: keys.human,
    principalPublic: pub(keys.human),
    holder: pub(keys.orchestrator),
    caveats: [
      { type: "scope", actions: ["payments.refund", "payments.read", "orders.read"] },
      { type: "resource", prefix: "/orders/" },
      { type: "max_amount", max: 500 },
      { type: "expires", at: now + 36e5 },
      { type: "audience", domains: [C.id] }
    ]
  });
  const c1 = delegate(root, pub(keys.tool), [{ type: "scope", actions: ["payments.refund", "payments.read"] }, { type: "max_amount", max: 100 }], keys.orchestrator);
  const c2 = delegate(c1, pub(keys.service), [{ type: "resource", prefix: "/orders/42" }, { type: "max_hops", n: 4 }], keys.tool);
  const c3 = delegate(c2, pub(leafKey), [{ type: "scope", actions: ["payments.refund"] }, { type: "max_amount", max: 50 }], keys.service);
  const chain2 = [root, c1, c2, c3];
  A.record(root);
  const hA0 = A.publishHead(witnesses, now - 2e3);
  A.record(c1);
  const hA = A.publishHead(witnesses, now - 1e3);
  B.record(c2);
  C.record(c3);
  const hB = B.publishHead(witnesses, now - 1e3);
  const hC = C.publishHead(witnesses, now - 1e3);
  const bOrch = A.enroll(pub(keys.orchestrator), "orchestrator");
  const bTool = B.enroll(pub(keys.tool), "tool-agent");
  const bSvc = C.enroll(pub(keys.service), "service-agent");
  const evidence = [A.evidence(root, hA), A.evidence(c1, hA, bOrch), B.evidence(c2, hB, bTool), C.evidence(c3, hC, bSvc)];
  const action = { type: "payments.refund", resource: "/orders/42/line/1", amount: 25, service_domain: C.id, nonce: "n-0001", at: now };
  const proof = assembleMeshProof({ chain: chain2, hops: evidence, action, leafSecret: leafKey });
  const trust = {
    humanPrincipal: pub(keys.human),
    witnesses: witnesses.map((w) => w.id),
    threshold: 2,
    now
  };
  return {
    trust,
    proof,
    evidence,
    domains: { A, B, C },
    witnesses,
    keys,
    chain: chain2,
    heads: { A0: hA0, A: hA, B: hB, C: hC },
    bindings: { orchestrator: bOrch, tool: bTool, service: bSvc }
  };
}
function demonstrateForkRejection() {
  const k = seedKey("fork-domain");
  const hk = seedKey("fork-human");
  const mk = (n) => mintRoot({ principalSecret: hk, principalPublic: encodeKey(publicKeyOf(hk)), holder: encodeKey(publicKeyOf(hk)), caveats: [{ type: "scope", actions: [`a${n}`] }] });
  const w = new MeshWitness(seedKey("fork-witness"));
  const honest = new MeshDomain("X", k);
  honest.record(mk(0));
  honest.record(mk(1));
  honest.publishHead([w], 100);
  honest.record(mk(2));
  let honest_ok = true;
  try {
    honest.publishHead([w], 200);
  } catch {
    honest_ok = false;
  }
  const prior = w.lastSeen(honest.id);
  const fork = new MeshDomain("X", k);
  for (const n of [100, 1, 2, 3]) fork.record(mk(n));
  let reason = "";
  let rejected = false;
  try {
    fork.publishHead([w], 300);
  } catch (e) {
    rejected = true;
    reason = e.message;
  }
  return {
    honest_extension_cosigned: honest_ok,
    fork_larger_than_prior: 4 > prior.size,
    size_only_check_would_accept: 4 >= prior.size,
    fork_rejected: rejected,
    fork_reason: reason
  };
}
export {
  ATTEST_BIND_DOMAIN,
  BEACON_CLOCK_SKEW_MS,
  BEACON_EPOCH_MS,
  BEACON_MAX_VALIDITY_MS,
  BondLedger,
  CONTEXT_STRING,
  DEFAULT_BOND_POLICY,
  DEFAULT_REVERSIBILITY_CLASS,
  DEFAULT_RISK_POLICY,
  DEFAULT_WINDOW_POLICY,
  EMPTY_PARAMS_DIGEST,
  ENVELOPE_CAVEAT,
  ESCROW_ACCOUNT,
  GLOBAL_SCOPE,
  H1,
  H2,
  H3,
  H4,
  H5,
  IRREVERSIBLE_CLASS,
  InMemoryBondAccount,
  L,
  MAX_ATTESTATION_AGE_MS,
  MAX_AUD_LEN,
  MAX_CHAIN_DEPTH,
  MAX_DECIMAL_DIGITS,
  MAX_JSON_BYTES,
  MAX_JSON_DEPTH,
  MAX_NONCE_LEN,
  MAX_RE_RESOURCE_LEN,
  PCACTN_DEFAULT_TTL_MS,
  PCACTN_MAX_LIFETIME_MS,
  PCACTN_MAX_SKEW_MS,
  PCACTN_OPTIONAL_FIELDS,
  PCACTN_REQUIRED_FIELDS,
  PCACTN_VERSION,
  PCACTN_WIRE_VERSION,
  REVEPOCH_DOMAIN,
  REVERSIBILITY_ORDER,
  REVOCATION_EPOCH_REFRESH_MS,
  REVOCATION_EPOCH_VALIDITY_MS,
  RevocationSet,
  SEV_SNP_POLICY_DEBUG_BIT,
  SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384,
  STH_DOMAIN,
  StrictJsonError,
  TransparencyLedger,
  VALID_THRESHOLDS,
  acceptBeacon,
  actionCommitment,
  admit,
  ageSinceTouch,
  agentCaveatContext,
  agent_native_exports as agentNative,
  assembleThreshold,
  attenuate,
  attestationBinding,
  attestationBindingB64u,
  attestationDigest,
  attestationRegistry,
  b64u,
  b64uLen,
  beaconRef,
  bondAmount,
  buildPCActn,
  bytesToScalar,
  canonicalBytes,
  canonicalBytesLenient,
  canonicalBytesStrict,
  canonicalize,
  canonicalizeStrict,
  capHash,
  challengeWindowEnd,
  checkRevocationEpoch,
  checkSevSnpPolicy,
  checkVcekReportBinding,
  claimStatus,
  commitPlan,
  compareUtf8,
  conditionsDigest,
  cost,
  createAttestationVerifier,
  createAttestedComplianceProver,
  createDevAttestor,
  createRevocationChecker,
  createSevSnpVerifier,
  createThresholdVerifier,
  createZkVerifier,
  debit,
  debitConsolidated,
  decide,
  decodeB64uStrict,
  decodeKey,
  decodePCActn,
  decodeSafePoint,
  decodeSig,
  delegate,
  deriveDecideInput,
  detectEquivocation,
  dkgFileComplaint,
  dkgFinalize,
  dkgQualifiedSet,
  dkgRebut,
  dkgResolveBlame,
  dkgRound1,
  dkgRound2,
  dkgSignShare,
  dkgVerifyComplaint,
  dkgVerifyRound1,
  dkgVerifyShare,
  ecdsaP384PublicKey,
  encodeKey,
  encodePCActn,
  encodeSig,
  entryCommit,
  envelopeCaveatEvaluator,
  escalateThreshold,
  evaluateAgentCaveats,
  evaluateCaveats,
  evaluateCondition,
  evaluatePredicates,
  fileFraudProof,
  fingerprintPublicKey,
  freezeOpenSnapshot,
  frostAggregate,
  frostCommit,
  frostDkgSimulate,
  frostSign,
  frostTrustedDealerKeygen,
  frostVerifySigShare,
  generateKeyPair,
  goalCommitOf,
  hasLoneSurrogate,
  hashCanonical,
  hashCanonicalLenient,
  isCanonicalB64u,
  isFrozen,
  isFrozenLiveness,
  isSafeRegexSource,
  issueBeacon,
  issueLivenessBeacon,
  leafHash,
  leak,
  ledgerRootOf,
  livenessBeaconMessage,
  matchAgentBinding,
  merkleProof,
  merkleRoot,
  mesh_exports as mesh,
  mintGrant,
  mintRoot,
  nonceBinds,
  notEnforced,
  objective_risk_exports as objectiveRisk,
  openOptimistic,
  paramsDigest,
  parseSevSnpReport,
  pcactnDigest,
  pinnedPolicyCommitment,
  planGeodesic,
  planLeaf,
  planNodeLeaf,
  policyCommitment,
  predicateMatches,
  progress_exports as progress,
  prohibitions_exports as prohibitions,
  publicKeyOf,
  readEnvelope,
  readObjectiveCommitment,
  recharge,
  rechargeFull,
  requiredThreshold,
  requiresAttestation,
  resolveObjectiveRisk,
  resolvePath,
  resolveWindow,
  revocationEvidenceDigest,
  revokeMessage,
  riskScore,
  safetyBound,
  scalarToBytes,
  serializeSevSnpReport,
  settlementEvidenceDigest,
  sevSnpSignatureToCompact,
  sha2563 as sha256,
  shareMessage,
  sign,
  signPCActn,
  signPreparedShare,
  signRevocationEpoch,
  signShare,
  signTreeHead,
  signerSetHash,
  strictNumberError,
  strictParse,
  strictParseBytes,
  subBudget,
  tbsContainsSubjectKey,
  thresholdMessage,
  toHex,
  toolCallOf,
  unb64u,
  utf8,
  validateRiskPolicy,
  validateWindow,
  validateWireV2,
  verify,
  verifyAttestation,
  verifyB64u,
  verifyBeacon,
  verifyChain,
  verifyClaim,
  verifyFraudProof,
  verifyGoalCommit,
  verifyHeadConsistency,
  verifyInclusion,
  verifyLedgerConsistency,
  verifyLedgerInclusion,
  verifyLivenessBeacon,
  verifyMembership,
  verifyNonMembership,
  verifyOpening,
  verifyPCActnCore,
  verifySettlement,
  verifySevSnpReportSignature,
  verifyThreshold,
  verifyTreeHead,
  verifyVcekChain,
  verifyWitnessedHead,
  withinChallengeWindow
};
/*! Bundled license information:

@noble/hashes/esm/utils.js:
  (*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@scure/base/lib/esm/index.js:
  (*! scure-base - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/curves/esm/abstract/utils.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/curves/esm/abstract/modular.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/curves/esm/abstract/curve.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/curves/esm/abstract/edwards.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/curves/esm/ed25519.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/curves/esm/abstract/weierstrass.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/curves/esm/_shortw_utils.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/curves/esm/nist.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/curves/esm/p384.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/

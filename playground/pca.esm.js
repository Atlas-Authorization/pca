// bundled module
var crypto = typeof globalThis === "object" && "crypto" in globalThis ? globalThis.crypto : void 0;

// bundled module
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
var Hash = class {
};
function createHasher(hashCons) {
  const hashC = (msg2) => hashCons().update(toBytes(msg2)).digest();
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

// bundled module
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

// bundled module
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

// bundled module
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
var sha256 = /* @__PURE__ */ createHasher(() => new SHA256());
var sha512 = /* @__PURE__ */ createHasher(() => new SHA512());

// bundled module
var sha2562 = sha256;

// bundled module
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

// bundled module
var enc = new TextEncoder();
function utf8(s) {
  return enc.encode(s);
}
function sha2563(bytes) {
  return sha2562(bytes);
}
function b64u(bytes) {
  return base64urlnopad.encode(bytes);
}
function unb64u(s) {
  return base64urlnopad.decode(s);
}
function canonicalize(value) {
  return ser(value, /* @__PURE__ */ new Set());
}
function ser(v, seen) {
  if (v === null) return "null";
  switch (typeof v) {
    case "string":
      return JSON.stringify(v);
    case "boolean":
      return v ? "true" : "false";
    case "number":
      if (!Number.isFinite(v)) throw new TypeError("canonicalize: non-finite number");
      return Object.is(v, -0) ? "0" : JSON.stringify(v);
    case "object":
      break;
    default:
      throw new TypeError(`canonicalize: unsupported type ${typeof v}`);
  }
  const o = v;
  if (seen.has(o)) throw new TypeError("canonicalize: cycle");
  seen.add(o);
  try {
    if (Array.isArray(o)) {
      return "[" + o.map((x) => ser(x, seen)).join(",") + "]";
    }
    const proto = Object.getPrototypeOf(o);
    if (proto !== Object.prototype && proto !== null) {
      throw new TypeError("canonicalize: non-plain object");
    }
    const rec = o;
    const keys = Object.keys(rec).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + ser(rec[k], seen)).join(",") + "}";
  } finally {
    seen.delete(o);
  }
}
function canonicalBytes(value) {
  return utf8(canonicalize(value));
}
function hashCanonical(value) {
  return b64u(sha2563(canonicalBytes(value)));
}

// bundled module
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
var hasHexBuiltin = (
  // @ts-ignore
  typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
);
var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
function bytesToHex(bytes) {
  abytes2(bytes);
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
function bytesToNumberBE(bytes) {
  return hexToNumber(bytesToHex(bytes));
}
function bytesToNumberLE(bytes) {
  abytes2(bytes);
  return hexToNumber(bytesToHex(Uint8Array.from(bytes).reverse()));
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
function concatBytes(...arrays) {
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

// bundled module
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
  let Q = P - _1n2;
  let S = 0;
  while (Q % _2n === _0n2) {
    Q /= _2n;
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
    fromBytes: (bytes) => {
      if (bytes.length !== BYTES)
        throw new Error("Field.fromBytes: expected " + BYTES + " bytes, got " + bytes.length);
      return isLE ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
    },
    // TODO: we don't need it here, move out to separate fn
    invertBatch: (lst) => FpInvertBatch(f, lst),
    // We can't move this out because Fp6, Fp12 implement it
    // and it's unclear what to return in there.
    cmov: (a, b, c) => c ? b : a
  });
  return Object.freeze(f);
}

// bundled module
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

// bundled module
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
      const bytes = numberToBytesLE(y, Fp2.BYTES);
      bytes[bytes.length - 1] |= x & _1n4 ? 128 : 0;
      return bytes;
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
    const msg2 = concatBytes(...msgs);
    return modN_LE(cHash(domain(msg2, ensureBytes("context", context), !!prehash)));
  }
  function sign2(msg2, privKey, options = {}) {
    msg2 = ensureBytes("message", msg2);
    if (prehash)
      msg2 = prehash(msg2);
    const { prefix, scalar, pointBytes } = getExtendedPublicKey(privKey);
    const r = hashDomainToScalar(options.context, prefix, msg2);
    const R = G.multiply(r).toRawBytes();
    const k = hashDomainToScalar(options.context, R, pointBytes, msg2);
    const s = modN(r + k * scalar);
    aInRange("signature.s", s, _0n4, CURVE_ORDER);
    const res = concatBytes(R, numberToBytesLE(s, Fp2.BYTES));
    return ensureBytes("result", res, Fp2.BYTES * 2);
  }
  const verifyOpts = VERIFY_DEFAULT;
  function verify2(sig, msg2, publicKey, options = verifyOpts) {
    const { context, zip215 } = options;
    const len = Fp2.BYTES;
    sig = ensureBytes("signature", sig, 2 * len);
    msg2 = ensureBytes("message", msg2);
    publicKey = ensureBytes("publicKey", publicKey, len);
    if (zip215 !== void 0)
      abool("zip215", zip215);
    if (prehash)
      msg2 = prehash(msg2);
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
    const k = hashDomainToScalar(context, R.toRawBytes(), A.toRawBytes(), msg2);
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

// bundled module
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

// bundled module
function generateKeyPair() {
  const secretKey = ed25519.utils.randomPrivateKey();
  return { secretKey, publicKey: ed25519.getPublicKey(secretKey) };
}
function publicKeyOf(secretKey) {
  return ed25519.getPublicKey(secretKey);
}
function sign(secretKey, msg2) {
  return ed25519.sign(msg2, secretKey);
}
function verify(publicKey, msg2, sig) {
  try {
    return ed25519.verify(sig, msg2, publicKey);
  } catch {
    return false;
  }
}
var encodeKey = b64u;
var decodeKey = unb64u;
var encodeSig = b64u;
var decodeSig = unb64u;
function verifyB64u(publicKeyB64u, msg2, sigB64u) {
  try {
    return verify(unb64u(publicKeyB64u), msg2, unb64u(sigB64u));
  } catch {
    return false;
  }
}

// bundled module
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
function verifyInclusion(root, proof, leaf) {
  try {
    if (!proof || !Array.isArray(proof.path)) return false;
    let h = leafHash(leaf);
    for (const step of proof.path) {
      if (step.side !== "L" && step.side !== "R") return false;
      const sib = unb64u(step.hash);
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

// bundled module
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
function seal(body, signerSecret) {
  const body_digest = hashCanonical(bodyOf(body));
  const sig = b64u(sign(signerSecret, sigMessage(body_digest)));
  const cap = {
    id: body_digest,
    issuer: body.issuer,
    holder: body.holder,
    caveats: body.caveats,
    body_digest,
    sig
  };
  if (body.parent !== void 0) cap.parent = body.parent;
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
function verifyChain(chain2, expectedRootIssuer) {
  if (!Array.isArray(chain2) || chain2.length === 0) return { ok: false, reason: "empty chain" };
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

// bundled module
var PCACTN_VERSION = 1;
var SIG_DOMAIN = "atlas-pca/actn/v1\0";
function thresholdMessage(p) {
  const { sig: _sig, threshold: _th, ...body } = p;
  const d = sha2563(canonicalBytes(body));
  const pre = utf8(SIG_DOMAIN);
  const m = new Uint8Array(pre.length + d.length);
  m.set(pre);
  m.set(d, pre.length);
  return m;
}
function signPCActn(body, leafHolderSecret) {
  return { ...body, sig: b64u(sign(leafHolderSecret, thresholdMessage(body))) };
}
function encodePCActn(p) {
  return canonicalize(p);
}
function decodePCActn(s) {
  const v = JSON.parse(s);
  if (typeof v !== "object" || v === null) throw new TypeError("decodePCActn: not an object");
  return v;
}
function pcactnDigest(p) {
  return hashCanonical(p);
}
function buildPCActn(input) {
  const node = input.plan.find((n) => n.id === input.nodeId);
  if (!node) throw new Error(`buildPCActn: unknown plan node ${input.nodeId}`);
  const digest = paramsDigest(input.params);
  if (node.params_digest !== void 0 && node.params_digest !== digest) {
    throw new Error(`buildPCActn: params do not match plan node ${node.id}'s params_digest`);
  }
  const committed = commitPlan(input.plan);
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
    // NOT-YET-ENFORCED stub defaults (M5 attestation / M3 freshness / M1 taint gate).
    attestation: input.attestation ?? { quote_digest: "", epoch: 0, model_id: "unattested", measurement: "", operator: "unattested" },
    provenance: input.provenance ?? { causal_hash: "", taint_level: 0, trusted_refs: [] },
    freshness: input.freshness ?? { beacon_ref: "", epoch: 0, accumulator_witness: "" },
    counter: input.counter,
    risk_claim: input.riskClaim ?? { r: 0, inputs: {} }
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
  const ctx = { pcactn: p, grant: opts.grant, nowEpoch: opts.nowEpoch };
  try {
    if (p.ver === PCACTN_VERSION) checks.version = "pass";
    else fail("version", `unsupported ver ${String(p.ver)}`);
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
    const cond = p.plan?.conditions_digest ?? conditionsDigest();
    const leaf = planLeaf(p.plan?.node_id, p.action, cond);
    if (verifyInclusion(p.plan?.root, p.plan?.inclusion_proof, leaf)) checks.plan_inclusion = "pass";
    else fail("plan_inclusion", "action is not a node of the committed plan");
    checks.plan_root_authorized = "not-enforced";
    const leafCap = Array.isArray(chain2) ? chain2[chain2.length - 1] : void 0;
    if (leafCap && typeof p.sig === "string" && verifyB64u(leafCap.holder, thresholdMessage(p), p.sig)) {
      checks.leaf_signature = "pass";
    } else {
      fail("leaf_signature", "signature does not verify under the leaf holder key");
    }
    if (typeof p.counter === "number" && Number.isInteger(p.counter) && p.counter >= 0) checks.counter = "pass";
    else fail("counter", "missing or not a non-negative integer");
    checks.taint_gate = "not-enforced";
    const run = async (name, hook, applicable = true) => {
      if (!applicable) return;
      const res = await (hook ?? notEnforced)(ctx);
      if (!res.enforced) checks[name] = "not-enforced";
      else if (res.ok) checks[name] = "pass";
      else fail(name, res.reason ?? "rejected");
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

// bundled module
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
  if (t === 1 && b.B >= c) return { admit: true, needStepUp: false, t: 1 };
  return { admit: false, needStepUp: true, t: t === 1 ? 3 : t };
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

// bundled module
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
    risk_policy: args.envelope.risk_policy
  });
  canonicalize(env);
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

// bundled module
function signShare(role, secretKey, message) {
  return { role, publicKey: b64u(publicKeyOf(secretKey)), sig: b64u(sign(secretKey, message)) };
}
function assembleThreshold(shares) {
  return { shares: Array.isArray(shares) ? [...shares] : [] };
}
function verifyThreshold(sig, message, signerSet, t) {
  const registered = /* @__PURE__ */ new Map();
  for (const s of Array.isArray(signerSet) ? signerSet : []) {
    if (!s || typeof s.role !== "string" || typeof s.publicKey !== "string") continue;
    let set = registered.get(s.role);
    if (!set) registered.set(s.role, set = /* @__PURE__ */ new Set());
    set.add(s.publicKey);
  }
  const validRoles = [];
  const seenValid = /* @__PURE__ */ new Set();
  let reason;
  for (const share of sig && Array.isArray(sig.shares) ? sig.shares : []) {
    if (!share || typeof share.role !== "string") {
      reason ??= "malformed share";
      continue;
    }
    if (seenValid.has(share.role)) continue;
    const allowed = registered.get(share.role);
    if (!allowed) {
      reason ??= `role ${share.role} is not in the signer set`;
      continue;
    }
    if (typeof share.publicKey !== "string" || !allowed.has(share.publicKey)) {
      reason ??= `share for role ${share.role} uses a key not registered for that role`;
      continue;
    }
    if (typeof share.sig !== "string" || !verifyB64u(share.publicKey, message, share.sig)) {
      reason ??= `invalid signature for role ${share.role}`;
      continue;
    }
    seenValid.add(share.role);
    validRoles.push(share.role);
  }
  const count = validRoles.length;
  const need = Number.isFinite(t) ? t : Number.POSITIVE_INFINITY;
  const ok = count >= need;
  if (ok) return { ok, count, roles: validRoles };
  return { ok, count, roles: validRoles, reason: reason ?? `only ${count} distinct valid role(s), need ${t}` };
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

// bundled module
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
function resourceMatches(pattern, resource) {
  if (pattern === void 0) return true;
  if (typeof pattern !== "string") return false;
  if (pattern === "*") return true;
  if (pattern.startsWith("re:")) {
    const src = pattern.slice(3);
    if (src.length > 200) return false;
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

// bundled module
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
    const cv = evaluateCaveats(env.caveats, cctx);
    if (!cv.ok) reasons.push(`caveat(s) not satisfied: ${cv.failed.join(", ")}`);
    const dcv = evaluateCaveats(extra, cctx);
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
    const r = riskScore(inputs, pol.weights);
    const irreversible = cctx.reversibilityClass === "irreversible";
    const rt = requiredThreshold(r, pol, { irreversible });
    const adm = admit(r, leaked, pol);
    if (adm.needStepUp) {
      reasons.push(
        rt.t === 1 ? "trust budget depleted: human recharge required" : `risk ${r.toFixed(3)} exceeds auto threshold: step-up to t=${adm.t}`
      );
    }
    const policyOk = pr.allowed && cv.ok && dcv.ok && chainOk;
    const release = policyOk;
    const autoAdmit = release && adm.admit;
    const outBudget = autoAdmit ? debit(leaked, cost(r, pol.kappa)) : leaked;
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

// bundled module
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
  const body = canonicalBytes({ principal, size, root });
  const p = utf8(WITNESS_DOMAIN);
  const m = new Uint8Array(p.length + body.length);
  m.set(p);
  m.set(body, p.length);
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

// bundled module
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
function createRevocationChecker(opts) {
  return (ctx) => {
    const root = opts.root(ctx);
    if (!root) return { enforced: true, ok: false, reason: "no revocation root" };
    const ids = opts.ids ? opts.ids(ctx) : ctx.pcactn.cap_chain.map((c) => c.id);
    for (const id of ids) {
      const proof = opts.proofFor(id, ctx);
      if (!proof) return { enforced: true, ok: false, reason: `no non-membership proof for ${id}` };
      if (!verifyNonMembership(root, proof, id)) {
        return { enforced: true, ok: false, reason: `capability ${id} is revoked or proof invalid` };
      }
    }
    return { enforced: true, ok: true };
  };
}

// bundled module
var GLOBAL_SCOPE = "*";
var DOMAIN = "atlas-pca/beacon/v1\0";
function msg(b) {
  const body = canonicalBytes({ v: b.v, scope: b.scope, epoch: b.epoch, not_after: b.not_after, guardian: b.guardian });
  const p = utf8(DOMAIN);
  const m = new Uint8Array(p.length + body.length);
  m.set(p);
  m.set(body, p.length);
  return m;
}
function issueBeacon(args) {
  const { guardianSecret, epoch, notAfter } = args;
  if (!Number.isInteger(epoch) || !Number.isInteger(notAfter) || notAfter < epoch) {
    throw new RangeError("issueBeacon: need integer epoch <= notAfter");
  }
  const body = { v: 1, scope: args.scope ?? GLOBAL_SCOPE, epoch, not_after: notAfter, guardian: b64u(publicKeyOf(guardianSecret)) };
  return { ...body, sig: b64u(sign(guardianSecret, msg(body))) };
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
export {
  DEFAULT_REVERSIBILITY_CLASS,
  DEFAULT_RISK_POLICY,
  EMPTY_PARAMS_DIGEST,
  ENVELOPE_CAVEAT,
  GLOBAL_SCOPE,
  PCACTN_VERSION,
  REVERSIBILITY_ORDER,
  RevocationSet,
  TransparencyLedger,
  admit,
  ageSinceTouch,
  assembleThreshold,
  attenuate,
  b64u,
  buildPCActn,
  canonicalBytes,
  canonicalize,
  capHash,
  commitPlan,
  conditionsDigest,
  cost,
  createRevocationChecker,
  createThresholdVerifier,
  debit,
  debitConsolidated,
  decide,
  decodeKey,
  decodePCActn,
  decodeSig,
  delegate,
  deriveDecideInput,
  detectEquivocation,
  encodeKey,
  encodePCActn,
  encodeSig,
  entryCommit,
  envelopeCaveatEvaluator,
  escalateThreshold,
  evaluateCaveats,
  evaluateCondition,
  evaluatePredicates,
  generateKeyPair,
  goalCommitOf,
  hashCanonical,
  isFrozen,
  issueBeacon,
  leafHash,
  leak,
  ledgerRootOf,
  merkleProof,
  merkleRoot,
  mintGrant,
  mintRoot,
  notEnforced,
  paramsDigest,
  pcactnDigest,
  planGeodesic,
  planLeaf,
  planNodeLeaf,
  predicateMatches,
  publicKeyOf,
  readEnvelope,
  recharge,
  rechargeFull,
  requiredThreshold,
  resolvePath,
  riskScore,
  safetyBound,
  sha2563 as sha256,
  sign,
  signPCActn,
  signShare,
  subBudget,
  thresholdMessage,
  unb64u,
  utf8,
  validateRiskPolicy,
  verify,
  verifyB64u,
  verifyBeacon,
  verifyChain,
  verifyGoalCommit,
  verifyInclusion,
  verifyLedgerConsistency,
  verifyLedgerInclusion,
  verifyMembership,
  verifyNonMembership,
  verifyOpening,
  verifyPCActnCore,
  verifyThreshold,
  verifyWitnessedHead
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
*/

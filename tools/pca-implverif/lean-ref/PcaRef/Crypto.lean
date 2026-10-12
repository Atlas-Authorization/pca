/- Independent reference primitives in Lean 4 (no mathlib): SHA-256, SHA-512, strict base64url, Ed25519 (strict).
   Written from the RFCs (FIPS 180-4, RFC 4648, RFC 8032) -- NOT derived from any PCA verifier source. -/
namespace PcaRef

/-! ## SHA-256 -/
def K256 : Array UInt32 := #[0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
def H256 : Array UInt32 := #[0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

@[inline] def rotr32 (x : UInt32) (n : UInt32) : UInt32 := (x >>> n) ||| (x <<< (32 - n))

def sha256 (msg : ByteArray) : ByteArray := Id.run do
  let ml := msg.size
  let mut m := msg.push 0x80
  while m.size % 64 != 56 do m := m.push 0
  let bits : UInt64 := (ml.toUInt64) * 8
  for i in [0:8] do m := m.push ((bits >>> (UInt64.ofNat ((7 - i) * 8))) &&& 0xff).toUInt8
  let mut h := H256
  for blk in [0:m.size / 64] do
    let mut w : Array UInt32 := Array.replicate 64 0
    for t in [0:16] do
      let b := blk * 64 + t * 4
      w := w.set! t ((m.get! b).toUInt32 <<< 24 ||| (m.get! (b+1)).toUInt32 <<< 16 ||| (m.get! (b+2)).toUInt32 <<< 8 ||| (m.get! (b+3)).toUInt32)
    for t in [16:64] do
      let s0 := rotr32 w[t-15]! 7 ^^^ rotr32 w[t-15]! 18 ^^^ (w[t-15]! >>> 3)
      let s1 := rotr32 w[t-2]! 17 ^^^ rotr32 w[t-2]! 19 ^^^ (w[t-2]! >>> 10)
      w := w.set! t (w[t-16]! + s0 + w[t-7]! + s1)
    let mut a := h[0]!; let mut b := h[1]!; let mut c := h[2]!; let mut d := h[3]!
    let mut e := h[4]!; let mut f := h[5]!; let mut g := h[6]!; let mut hh := h[7]!
    for t in [0:64] do
      let S1 := rotr32 e 6 ^^^ rotr32 e 11 ^^^ rotr32 e 25
      let ch := (e &&& f) ^^^ ((~~~e) &&& g)
      let t1 := hh + S1 + ch + K256[t]! + w[t]!
      let S0 := rotr32 a 2 ^^^ rotr32 a 13 ^^^ rotr32 a 22
      let maj := (a &&& b) ^^^ (a &&& c) ^^^ (b &&& c)
      let t2 := S0 + maj
      hh := g; g := f; f := e; e := d + t1; d := c; c := b; b := a; a := t1 + t2
    h := #[h[0]! + a, h[1]! + b, h[2]! + c, h[3]! + d, h[4]! + e, h[5]! + f, h[6]! + g, h[7]! + hh]
  let mut out := ByteArray.empty
  for x in h do
    for i in [0:4] do out := out.push ((x >>> (UInt32.ofNat ((3 - i) * 8))) &&& 0xff).toUInt8
  return out

/-! ## SHA-512 -/
def K512 : Array UInt64 := #[0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]
def H512 : Array UInt64 := #[0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
@[inline] def rotr64 (x : UInt64) (n : UInt64) : UInt64 := (x >>> n) ||| (x <<< (64 - n))

def sha512 (msg : ByteArray) : ByteArray := Id.run do
  let ml := msg.size
  let mut m := msg.push 0x80
  while m.size % 128 != 112 do m := m.push 0
  for _ in [0:8] do m := m.push 0
  let bits : UInt64 := (ml.toUInt64) * 8
  for i in [0:8] do m := m.push ((bits >>> (UInt64.ofNat ((7 - i) * 8))) &&& 0xff).toUInt8
  let mut h := H512
  for blk in [0:m.size / 128] do
    let mut w : Array UInt64 := Array.replicate 80 0
    for t in [0:16] do
      let b := blk * 128 + t * 8
      let mut x : UInt64 := 0
      for j in [0:8] do x := (x <<< 8) ||| (m.get! (b + j)).toUInt64
      w := w.set! t x
    for t in [16:80] do
      let s0 := rotr64 w[t-15]! 1 ^^^ rotr64 w[t-15]! 8 ^^^ (w[t-15]! >>> 7)
      let s1 := rotr64 w[t-2]! 19 ^^^ rotr64 w[t-2]! 61 ^^^ (w[t-2]! >>> 6)
      w := w.set! t (w[t-16]! + s0 + w[t-7]! + s1)
    let mut a := h[0]!; let mut b := h[1]!; let mut c := h[2]!; let mut d := h[3]!
    let mut e := h[4]!; let mut f := h[5]!; let mut g := h[6]!; let mut hh := h[7]!
    for t in [0:80] do
      let S1 := rotr64 e 14 ^^^ rotr64 e 18 ^^^ rotr64 e 41
      let ch := (e &&& f) ^^^ ((~~~e) &&& g)
      let t1 := hh + S1 + ch + K512[t]! + w[t]!
      let S0 := rotr64 a 28 ^^^ rotr64 a 34 ^^^ rotr64 a 39
      let maj := (a &&& b) ^^^ (a &&& c) ^^^ (b &&& c)
      let t2 := S0 + maj
      hh := g; g := f; f := e; e := d + t1; d := c; c := b; b := a; a := t1 + t2
    h := #[h[0]! + a, h[1]! + b, h[2]! + c, h[3]! + d, h[4]! + e, h[5]! + f, h[6]! + g, h[7]! + hh]
  let mut out := ByteArray.empty
  for x in h do
    for i in [0:8] do out := out.push ((x >>> (UInt64.ofNat ((7 - i) * 8))) &&& 0xff).toUInt8
  return out

def hexOf (b : ByteArray) : String :=
  let digits := "0123456789abcdef".toList.toArray
  b.foldl (fun s x => s.push digits[(x >>> 4).toNat]! |>.push digits[(x &&& 15).toNat]!) ""

/-! ## base64url, strict (RFC 4648 section 5, no padding, zero trailing bits, len % 4 != 1) -/
def b64Val (c : UInt8) : Option Nat :=
  if 65 <= c && c <= 90 then some (c - 65).toNat
  else if 97 <= c && c <= 122 then some ((c - 97).toNat + 26)
  else if 48 <= c && c <= 57 then some ((c - 48).toNat + 52)
  else if c == 45 then some 62 else if c == 95 then some 63 else none

def b64Chr (v : Nat) : UInt8 :=
  if v < 26 then (v + 65).toUInt8 else if v < 52 then (v - 26 + 97).toUInt8
  else if v < 62 then (v - 52 + 48).toUInt8 else if v == 62 then 45 else 95

def b64Encode (b : ByteArray) : ByteArray := Id.run do
  let mut out := ByteArray.empty
  let n := b.size
  let mut i := 0
  while i + 3 <= n do
    let x := (b.get! i).toNat * 65536 + (b.get! (i+1)).toNat * 256 + (b.get! (i+2)).toNat
    out := out.push (b64Chr (x / 262144)) |>.push (b64Chr ((x / 4096) % 64)) |>.push (b64Chr ((x / 64) % 64)) |>.push (b64Chr (x % 64))
    i := i + 3
  if n - i == 1 then
    let x := (b.get! i).toNat
    out := out.push (b64Chr (x / 4)) |>.push (b64Chr ((x % 4) * 16))
  else if n - i == 2 then
    let x := (b.get! i).toNat * 256 + (b.get! (i+1)).toNat
    out := out.push (b64Chr (x / 1024)) |>.push (b64Chr ((x / 16) % 64)) |>.push (b64Chr ((x % 16) * 4))
  return out

/-- strict decode; `none` on any deviation (alphabet, len % 4 == 1, non-zero trailing bits). -/
def b64Decode (s : ByteArray) : Option ByteArray := Id.run do
  if s.size % 4 == 1 then return none
  let mut vals : Array Nat := #[]
  for c in s.toList do
    match b64Val c with
    | some v => vals := vals.push v
    | none => return none
  let mut out := ByteArray.empty
  let n := vals.size
  let mut i := 0
  while i + 4 <= n do
    let x := vals[i]! * 262144 + vals[i+1]! * 4096 + vals[i+2]! * 64 + vals[i+3]!
    out := out.push (x / 65536).toUInt8 |>.push ((x / 256) % 256).toUInt8 |>.push (x % 256).toUInt8
    i := i + 4
  if n - i == 2 then
    if vals[i+1]! % 16 != 0 then return none
    out := out.push ((vals[i]! * 4 + vals[i+1]! / 16)).toUInt8
  else if n - i == 3 then
    if vals[i+2]! % 4 != 0 then return none
    let x := vals[i]! * 1024 + vals[i+1]! * 16 + vals[i+2]! / 4
    out := out.push (x / 256).toUInt8 |>.push (x % 256).toUInt8
  return some out

/-- strict decode requiring an exact decoded length. -/
def b64DecodeLen (s : String) (n : Nat) : Option ByteArray :=
  match b64Decode s.toUTF8 with
  | some b => if b.size == n then some b else none
  | none => none

/-! ## Ed25519 (RFC 8032), strict verification as the PCA contract requires:
   canonical A and R encodings, R and A not small order and torsion-free, S < L, then [S]B = R + [k]A. -/
def P : Nat := 2^255 - 19
def Lord : Nat := 2^252 + 27742317777372353535851937790883648493
def modPow (b e m : Nat) : Nat := Id.run do
  let mut r := 1; let mut bb := b % m; let mut ee := e
  while ee > 0 do
    if ee % 2 == 1 then r := r * bb % m
    bb := bb * bb % m
    ee := ee / 2
  return r
def inv (a : Nat) : Nat := modPow a (P - 2) P
def D : Nat := (P - 121665) * inv 121666 % P
def SQRTM1 : Nat := modPow 2 ((P - 1) / 4) P

structure Pt where (X Y Z T : Nat)
deriving Inhabited
def Pt.identity : Pt := ⟨0, 1, 1, 0⟩
def Pt.add (p q : Pt) : Pt :=
  let A := (p.Y + P - p.X) * (q.Y + P - q.X) % P
  let B := (p.Y + p.X) * (q.Y + q.X) % P
  let C := p.T * 2 * D % P * q.T % P
  let Dd := p.Z * 2 * q.Z % P
  let E := B + P - A; let F := Dd + P - C; let G := Dd + C; let H := B + A
  ⟨E * F % P, G * H % P, F * G % P, E * H % P⟩
def Pt.mul (k : Nat) (p : Pt) : Pt := Id.run do
  let mut r := Pt.identity; let mut q := p; let mut e := k
  while e > 0 do
    if e % 2 == 1 then r := r.add q
    q := q.add q
    e := e / 2
  return r
def Pt.eq (p q : Pt) : Bool := (p.X * q.Z) % P == (q.X * p.Z) % P && (p.Y * q.Z) % P == (q.Y * p.Z) % P
def Pt.isIdentity (p : Pt) : Bool := p.X % P == 0 && (p.Y % P) == (p.Z % P)

def leNat (b : ByteArray) : Nat := Id.run do
  let mut r := 0
  for i in [0:b.size] do r := r + (b.get! i).toNat * 256^i
  return r
def natLE (x : Nat) (n : Nat) : ByteArray := Id.run do
  let mut out := ByteArray.empty; let mut v := x
  for _ in [0:n] do out := out.push (v % 256).toUInt8; v := v / 256
  return out

def Pt.compress (p : Pt) : ByteArray :=
  let zi := inv p.Z
  let x := p.X * zi % P; let y := p.Y * zi % P
  natLE (y + (x % 2) * 2^255) 32

/-- decompress as the dalek/RFC does (y reduced mod p); canonicality is enforced by the caller via re-compression. -/
def Pt.decompress (b : ByteArray) : Option Pt :=
  let v := leNat b
  let sign := v / 2^255
  let y := (v % 2^255) % P
  let y2 := y * y % P
  let u := (y2 + P - 1) % P
  let vv := (D * y2 + 1) % P
  let x2 := u * inv vv % P
  let x0 := modPow x2 ((P + 3) / 8) P
  let x1 := if x0 * x0 % P == x2 then some x0 else if x0 * SQRTM1 % P * (x0 * SQRTM1 % P) % P == x2 then some (x0 * SQRTM1 % P) else none
  match x1 with
  | none => none
  | some x => let x := if x % 2 != sign then (P - x) % P else x
              some ⟨x, y, 1, x * y % P⟩

def Bpt : Pt := (Pt.decompress (natLE (4 * inv 5 % P) 32)).get!

def smallOrder (p : Pt) : Bool := (p.mul 8).isIdentity
def torsionFree (p : Pt) : Bool := (p.mul Lord).isIdentity

/-- Ed25519 strict verification of (pk, msg, sig) with exact 32/64-byte inputs. -/
def ed25519VerifyStrict (pk msg sig : ByteArray) : Bool :=
  if pk.size != 32 || sig.size != 64 then false else
  match Pt.decompress pk with
  | none => false
  | some A =>
    if A.compress != pk then false else
    let rb := sig.extract 0 32
    match Pt.decompress rb with
    | none => false
    | some R =>
      if R.compress != rb then false else
      if smallOrder A || smallOrder R || !torsionFree A || !torsionFree R then false else
      let S := leNat (sig.extract 32 64)
      if S >= Lord then false else
      let k := leNat (sha512 (rb ++ pk ++ msg)) % Lord
      (Pt.mul S Bpt).eq (R.add (Pt.mul k A))

end PcaRef

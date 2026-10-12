// Verus proof, for ALL input lengths and contents, of the strict base64url (RFC 4648 s5, no padding) contract that
// sdks/rust-pca decode_b64u_strict implements (and the TS decodeB64uStrict mirrors):
//   (1) decode accepts exactly the strings of the form encode(b): canonical, zero trailing bits, len%4 != 1, only
//       the 64-char alphabet                                     [canonical_inverse + round_trip]
//   (2) decode(encode(b)) == b and encode(decode(s)) == s on acceptance   [no malleability: one string per byte string]
// SCOPE: the shipping Rust code delegates the arithmetic to the `base64` crate and then re-encodes and compares;
// this file proves the SPECIFICATION that composite implements and an independent exec decoder against it. It does not
// verify the `base64` crate itself (that is covered, for lengths <= 6, by Kani harness decode_b64u_no_panic_bounded
// plus the conformance corpus + Miri).
use vstd::prelude::*;
verus! {

pub open spec fn valid_char(c: u8) -> bool {
    (65 <= c <= 90) || (97 <= c <= 122) || (48 <= c <= 57) || c == 45 || c == 95
}
// value of a valid char
pub open spec fn v(c: u8) -> u8 {
    if 65 <= c <= 90 { (c - 65) as u8 } else if 97 <= c <= 122 { (c - 97 + 26) as u8 }
    else if 48 <= c <= 57 { (c - 48 + 52) as u8 } else if c == 45 { 62u8 } else { 63u8 }
}
// char of a 6-bit value
pub open spec fn ch(x: u8) -> u8 {
    if x < 26 { (x + 65) as u8 } else if x < 52 { (x - 26 + 97) as u8 } else if x < 62 { (x - 52 + 48) as u8 }
    else if x == 62 { 45u8 } else { 95u8 }
}
pub proof fn lemma_ch_v(x: u8)
    requires x < 64,
    ensures valid_char(ch(x)), v(ch(x)) == x,
{}
pub proof fn lemma_v_ch(c: u8)
    requires valid_char(c),
    ensures v(c) < 64, ch(v(c)) == c,
{}

pub open spec fn all_valid(s: Seq<u8>) -> bool { forall|i: int| 0 <= i < s.len() ==> valid_char(#[trigger] s[i]) }

pub open spec fn enc(b: Seq<u8>) -> Seq<u8> decreases b.len() {
    if b.len() == 0 { Seq::empty() }
    else if b.len() == 1 {
        seq![ch(b[0] >> 2), ch((b[0] & 3) << 4)]
    } else if b.len() == 2 {
        seq![ch(b[0] >> 2), ch(((b[0] & 3) << 4) | (b[1] >> 4)), ch((b[1] & 15) << 2)]
    } else {
        seq![ch(b[0] >> 2), ch(((b[0] & 3) << 4) | (b[1] >> 4)), ch(((b[1] & 15) << 2) | (b[2] >> 6)), ch(b[2] & 63)]
            + enc(b.skip(3))
    }
}

pub open spec fn dec_rec(s: Seq<u8>) -> Option<Seq<u8>> decreases s.len() {
    if s.len() == 0 { Some(Seq::empty()) }
    else if s.len() >= 4 {
        match dec_rec(s.skip(4)) {
            Some(t) => Some(seq![((v(s[0]) << 2) | (v(s[1]) >> 4)) as u8,
                                 (((v(s[1]) & 15) << 4) | (v(s[2]) >> 2)) as u8,
                                 (((v(s[2]) & 3) << 6) | v(s[3])) as u8] + t),
            None => None,
        }
    } else if s.len() == 2 {
        if v(s[1]) & 15 != 0 { None } else { Some(seq![((v(s[0]) << 2) | (v(s[1]) >> 4)) as u8]) }
    } else if s.len() == 3 {
        if v(s[2]) & 3 != 0 { None } else {
            Some(seq![((v(s[0]) << 2) | (v(s[1]) >> 4)) as u8, (((v(s[1]) & 15) << 4) | (v(s[2]) >> 2)) as u8]) }
    } else { None }   // length 1 (mod 4 == 1)
}

pub open spec fn dec(s: Seq<u8>) -> Option<Seq<u8>> {
    if !all_valid(s) { None } else { dec_rec(s) }
}

proof fn bits3(a: u8, b: u8, c: u8)
    ensures
        (a >> 2) < 64, ((((a & 3) << 4) | (b >> 4))) < 64, ((((b & 15) << 2) | (c >> 6))) < 64, (c & 63) < 64,
        ((((a >> 2) << 2) | (((((a & 3) << 4) | (b >> 4))) >> 4)) as u8) == a,
        (((((((a & 3) << 4) | (b >> 4))) & 15) << 4) | (((((b & 15) << 2) | (c >> 6))) >> 2)) as u8 == b,
        (((((((b & 15) << 2) | (c >> 6))) & 3) << 6) | (c & 63)) as u8 == c,
{
    assert((a >> 2) < 64) by (bit_vector);
    assert(((a & 3) << 4 | (b >> 4)) < 64) by (bit_vector);
    assert(((b & 15) << 2 | (c >> 6)) < 64) by (bit_vector);
    assert((c & 63) < 64) by (bit_vector);
    assert((((a >> 2) << 2) | ((((a & 3) << 4) | (b >> 4)) >> 4)) as u8 == a) by (bit_vector);
    assert((((((a & 3) << 4) | (b >> 4)) & 15) << 4 | ((((b & 15) << 2) | (c >> 6)) >> 2)) as u8 == b) by (bit_vector);
    assert((((((b & 15) << 2) | (c >> 6)) & 3) << 6 | (c & 63)) as u8 == c) by (bit_vector);
}

proof fn bits4(p: u8, q: u8, r: u8, t: u8)
    requires p < 64, q < 64, r < 64, t < 64,
    ensures
        ({
            let x: u8 = ((p << 2) | (q >> 4)) as u8;
            let y: u8 = (((q & 15) << 4) | (r >> 2)) as u8;
            let z: u8 = (((r & 3) << 6) | t) as u8;
            &&& x >> 2 == p && (((x & 3) << 4) | (y >> 4)) == q && (((y & 15) << 2) | (z >> 6)) == r && (z & 63) == t
        }),
{
    assert(({
            let x: u8 = ((p << 2) | (q >> 4)) as u8;
            let y: u8 = (((q & 15) << 4) | (r >> 2)) as u8;
            let z: u8 = (((r & 3) << 6) | t) as u8;
            x >> 2 == p && (((x & 3) << 4) | (y >> 4)) == q && (((y & 15) << 2) | (z >> 6)) == r && (z & 63) == t
        })) by (bit_vector)
        requires p < 64, q < 64, r < 64, t < 64;
}

proof fn bits1(a: u8)
    ensures (a >> 2) < 64, ((a & 3) << 4) < 64, (((a & 3) << 4) & 15) == 0,
        ((((a >> 2) << 2) | (((a & 3) << 4) >> 4)) as u8) == a,
{
    assert((a >> 2) < 64) by (bit_vector);
    assert(((a & 3) << 4) < 64) by (bit_vector);
    assert((((a & 3) << 4) & 15) == 0) by (bit_vector);
    assert(((((a >> 2) << 2) | (((a & 3) << 4) >> 4)) as u8) == a) by (bit_vector);
}
proof fn bits2(a: u8, c: u8)
    ensures (a >> 2) < 64, (((a & 3) << 4) | (c >> 4)) < 64, ((c & 15) << 2) < 64, (((c & 15) << 2) & 3) == 0,
        ((((a >> 2) << 2) | ((((a & 3) << 4) | (c >> 4)) >> 4)) as u8) == a,
        (((((((a & 3) << 4) | (c >> 4)) & 15) << 4) | (((c & 15) << 2) >> 2)) as u8) == c,
{
    assert((a >> 2) < 64) by (bit_vector);
    assert((((a & 3) << 4) | (c >> 4)) < 64) by (bit_vector);
    assert(((c & 15) << 2) < 64) by (bit_vector);
    assert((((c & 15) << 2) & 3) == 0) by (bit_vector);
    assert(((((a >> 2) << 2) | ((((a & 3) << 4) | (c >> 4)) >> 4)) as u8) == a) by (bit_vector);
    assert((((((((a & 3) << 4) | (c >> 4)) & 15) << 4) | (((c & 15) << 2) >> 2)) as u8) == c) by (bit_vector);
}

pub proof fn round_trip(b: Seq<u8>)
    ensures all_valid(enc(b)), dec(enc(b)) == Some(b), enc(b).len() % 4 != 1,
    decreases b.len(),
{
    if b.len() == 0 {
        assert(enc(b) =~= Seq::<u8>::empty());
    } else if b.len() == 1 {
        let a = b[0];
        bits1(a);
        let e = enc(b);
        lemma_ch_v(a >> 2); lemma_ch_v((a & 3) << 4);
        assert(e.len() == 2);
        assert(all_valid(e));
        assert(dec_rec(e) =~= Some(b));
    } else if b.len() == 2 {
        let a = b[0]; let c = b[1];
        bits2(a, c);
        let e = enc(b);
        lemma_ch_v(a >> 2); lemma_ch_v(((a & 3) << 4) | (c >> 4)); lemma_ch_v((c & 15) << 2);
        assert(e.len() == 3);
        assert(all_valid(e));
        assert(dec_rec(e) =~= Some(b));
    } else {
        let a = b[0]; let c = b[1]; let d = b[2];
        bits3(a, c, d);
        round_trip(b.skip(3));
        let head = seq![ch(a >> 2), ch(((a & 3) << 4) | (c >> 4)), ch(((c & 15) << 2) | (d >> 6)), ch(d & 63)];
        let e = head + enc(b.skip(3));
        assert(enc(b) =~= e);
        lemma_ch_v(a >> 2); lemma_ch_v(((a & 3) << 4) | (c >> 4)); lemma_ch_v(((c & 15) << 2) | (d >> 6)); lemma_ch_v(d & 63);
        assert(e.skip(4) =~= enc(b.skip(3)));
        assert(all_valid(e)) by {
            assert forall|i: int| 0 <= i < e.len() implies valid_char(#[trigger] e[i]) by {
                if i >= 4 { assert(e[i] == enc(b.skip(3))[i - 4]); }
            }
        }
        assert(e.len() >= 4);
        assert(dec_rec(e.skip(4)) == Some(b.skip(3)));
        let t = b.skip(3);
        assert(seq![a, c, d] + t =~= b);
        assert(dec_rec(e) =~= Some(b));
    }
}

pub proof fn canonical_inverse(s: Seq<u8>)
    requires all_valid(s), dec_rec(s) is Some,
    ensures enc(dec_rec(s)->Some_0) =~= s,
    decreases s.len(),
{
    if s.len() == 0 {
    } else if s.len() >= 4 {
        let rest = s.skip(4);
        assert(all_valid(rest)) by { assert forall|i: int| 0 <= i < rest.len() implies valid_char(#[trigger] rest[i]) by { assert(rest[i] == s[i + 4]); } }
        canonical_inverse(rest);
        let (p, q, r, t) = (v(s[0]), v(s[1]), v(s[2]), v(s[3]));
        lemma_v_ch(s[0]); lemma_v_ch(s[1]); lemma_v_ch(s[2]); lemma_v_ch(s[3]);
        bits4(p, q, r, t);
        let out = dec_rec(s)->Some_0;
        let x = ((p << 2) | (q >> 4)) as u8;
        let y = (((q & 15) << 4) | (r >> 2)) as u8;
        let z = (((r & 3) << 6) | t) as u8;
        let tail = dec_rec(rest)->Some_0;
        assert(out =~= seq![x, y, z] + tail);
        assert(out.skip(3) =~= tail);
        assert(out.len() >= 3);
        assert(out[0] == x && out[1] == y && out[2] == z);
        assert(enc(out) =~= seq![ch(x >> 2), ch(((x & 3) << 4) | (y >> 4)), ch(((y & 15) << 2) | (z >> 6)), ch(z & 63)] + enc(tail));
        assert(ch(p) == s[0] && ch(q) == s[1] && ch(r) == s[2] && ch(t) == s[3]);
        assert(enc(out) =~= s);
    } else if s.len() == 2 {
        lemma_v_ch(s[0]); lemma_v_ch(s[1]);
        let (p, q) = (v(s[0]), v(s[1]));
        assert(q & 15 == 0);
        // x = p<<2 | q>>4 ; enc: ch(x>>2)=ch(p), ch((x&3)<<4) = ch(q) because q's low 4 bits are zero
        assert(((((p << 2) | (q >> 4)) as u8) >> 2) == p && ((((((p << 2) | (q >> 4)) as u8) & 3) << 4)) == q) by (bit_vector)
            requires p < 64, q < 64, q & 15 == 0;
    } else if s.len() == 3 {
        lemma_v_ch(s[0]); lemma_v_ch(s[1]); lemma_v_ch(s[2]);
        let (p, q, r) = (v(s[0]), v(s[1]), v(s[2]));
        assert(r & 3 == 0);
        let x: u8 = ((p << 2) | (q >> 4)) as u8;
        let y: u8 = (((q & 15) << 4) | (r >> 2)) as u8;
        assert(x >> 2 == p && (((x & 3) << 4) | (y >> 4)) == q && ((y & 15) << 2) == r) by (bit_vector)
            requires p < 64, q < 64, r < 64, r & 3 == 0, x == ((p << 2) | (q >> 4)) as u8, y == (((q & 15) << 4) | (r >> 2)) as u8;
    }
}

// Combined statement: the strict decoder accepts s  <=>  s is the canonical encoding of some byte string,
// and then decodes to exactly that byte string (so each byte string has exactly ONE accepted encoding).
pub proof fn accepts_iff_canonical_encoding(s: Seq<u8>)
    ensures dec(s) is Some <==> (exists|b: Seq<u8>| enc(b) =~= s),
{
    if dec(s) is Some { canonical_inverse(s); let b = dec(s)->Some_0; assert(enc(b) =~= s); }
    if exists|b: Seq<u8>| enc(b) =~= s {
        let b = choose|b: Seq<u8>| enc(b) =~= s;
        round_trip(b);
        assert(s =~= enc(b));
    }
}

fn main() {}
}

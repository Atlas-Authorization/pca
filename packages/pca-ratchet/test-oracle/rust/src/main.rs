// Independent oracle for pca-ratchet differential tests, built on curve25519-dalek (a different
// implementation of ristretto255 than @noble/curves). Line protocol on stdin; one answer per line.
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha2::{Digest, Sha512};
use std::io::{self, BufRead};

fn h_point() -> RistrettoPoint {
    let d = Sha512::digest(b"atlas-pca-ratchet/pedersen-generator-H/v1");
    let mut a = [0u8; 64];
    a.copy_from_slice(&d);
    RistrettoPoint::from_uniform_bytes(&a)
}
fn hx32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}
fn pt(s: &str) -> Option<RistrettoPoint> {
    CompressedRistretto(hx32(s)).decompress()
}
fn sc_canon(s: &str) -> Option<Scalar> {
    Option::from(Scalar::from_canonical_bytes(hx32(s)))
}
fn hash_to_scalar(parts: &[&[u8]]) -> Scalar {
    let mut buf = Vec::new();
    for p in parts {
        buf.extend_from_slice(&(p.len() as u32).to_be_bytes());
        buf.extend_from_slice(p);
    }
    let d = Sha512::digest(&buf);
    let mut a = [0u8; 64];
    a.copy_from_slice(&d);
    Scalar::from_bytes_mod_order_wide(&a)
}

// verify_budget csum bmax_dec B0..B31 (e0 e1 z0 z1)*32 a z   (all points/scalars 32-byte hex)
fn verify_budget(t: &[&str]) -> Result<bool, String> {
    let h = h_point();
    let csum = pt(t[0]).ok_or("csum")?;
    let bmax: u128 = t[1].parse().map_err(|_| "bmax")?;
    let n = 32usize;
    let mut bs = Vec::new();
    for i in 0..n {
        bs.push(pt(t[2 + i]).ok_or("B")?);
    }
    let mut o = 2 + n;
    let mut ors = Vec::new();
    for _ in 0..n {
        let e0 = sc_canon(t[o]).ok_or("e0 noncanonical")?;
        let e1 = sc_canon(t[o + 1]).ok_or("e1 noncanonical")?;
        let z0 = sc_canon(t[o + 2]).ok_or("z0 noncanonical")?;
        let z1 = sc_canon(t[o + 3]).ok_or("z1 noncanonical")?;
        ors.push((e0, e1, z0, z1));
        o += 4;
    }
    let a = pt(t[o]).ok_or("agg a")?;
    let z = sc_canon(t[o + 1]).ok_or("agg z noncanonical")?;
    let bm = Scalar::from(bmax);
    let mut cparts: Vec<Vec<u8>> = vec![b"atlas-pca-ratchet/budget/ctx/v1".to_vec(), vec![n as u8], bm.to_bytes().to_vec(), csum.compress().to_bytes().to_vec()];
    for b in &bs {
        cparts.push(b.compress().to_bytes().to_vec());
    }
    let refs: Vec<&[u8]> = cparts.iter().map(|v| v.as_slice()).collect();
    let ctx = hash_to_scalar(&refs).to_bytes();
    for i in 0..n {
        let (e0, e1, z0, z1) = ors[i];
        let b = bs[i];
        let a0 = z0 * h - e0 * b;
        let a1 = z1 * h - e1 * (b - G);
        let e = hash_to_scalar(&[b"atlas-pca-ratchet/budget/bit-or/v1", &ctx, &[i as u8], a0.compress().as_bytes(), a1.compress().as_bytes()]);
        if e0 + e1 != e {
            return Ok(false);
        }
    }
    let mut agg = RistrettoPoint::identity();
    for i in 0..n {
        agg += bs[i] * Scalar::from(1u64 << i);
    }
    let v = bm * G - csum;
    let d = agg - v;
    let e = hash_to_scalar(&[b"atlas-pca-ratchet/budget/agg/v1", &ctx, d.compress().as_bytes(), a.compress().as_bytes()]);
    Ok(z * h == a + e * d)
}

fn main() {
    let h = h_point();
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.is_empty() {
            continue;
        }
        match t[0] {
            "base_multiple" => {
                let k: u64 = t[1].parse().unwrap();
                println!("{}", hex::encode((Scalar::from(k) * G).compress().as_bytes()));
            }
            "h" => println!("{}", hex::encode(h.compress().as_bytes())),
            // pedersen v_dec b_hex32(LE scalar)
            "pedersen" => {
                let v: u128 = t[1].parse().unwrap();
                let b = Scalar::from_bytes_mod_order(hx32(t[2]));
                println!("{}", hex::encode((Scalar::from(v) * G + b * h).compress().as_bytes()));
            }
            "valid_point" => println!("{}", if pt(t[1]).is_some() { 1 } else { 0 }),
            "verify_budget" => match verify_budget(&t[1..]) {
                Ok(true) => println!("1"),
                Ok(false) => println!("0"),
                Err(e) => println!("0 {}", e),
            },
            _ => println!("? unknown"),
        }
    }
}

// Independent-implementation voter (RustCrypto + dalek + fips204 + slh-dsa). Line protocol, tab separated, hex payloads;
// one response line per request line: result hex, "1"/"0" for booleans, or "ERR <msg>" (never panics the batch).
use ed25519_dalek::{Signature as EdSig, Signer as _, SigningKey as EdSk, VerifyingKey as EdVk};
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384, Sha512};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Sha3_256, Sha3_512, Shake128, Shake256};
use std::io::{BufRead, Write};

fn h(a: &str) -> Vec<u8> { hex::decode(a).unwrap_or_default() }

fn hash(algo: &str, m: &[u8]) -> Result<Vec<u8>, String> {
    Ok(match algo {
        "sha256" => Sha256::digest(m).to_vec(),
        "sha384" => Sha384::digest(m).to_vec(),
        "sha512" => Sha512::digest(m).to_vec(),
        "sha3-256" => Sha3_256::digest(m).to_vec(),
        "sha3-512" => Sha3_512::digest(m).to_vec(),
        a if a.starts_with("shake128:") || a.starts_with("shake256:") => {
            let n: usize = a.split(':').nth(1).unwrap().parse().map_err(|_| "len")?;
            let mut out = vec![0u8; n];
            if a.starts_with("shake128") { let mut x = Shake128::default(); x.update(m); x.finalize_xof().read(&mut out); }
            else { let mut x = Shake256::default(); x.update(m); x.finalize_xof().read(&mut out); }
            out
        }
        _ => return Err(format!("algo {algo}")),
    })
}

fn hmac(algo: &str, k: &[u8], m: &[u8]) -> Result<Vec<u8>, String> {
    Ok(match algo {
        "sha256" => { let mut x = <Hmac<Sha256> as Mac>::new_from_slice(k).map_err(|e| e.to_string())?; Mac::update(&mut x, m); x.finalize().into_bytes().to_vec() }
        "sha512" => { let mut x = <Hmac<Sha512> as Mac>::new_from_slice(k).map_err(|e| e.to_string())?; Mac::update(&mut x, m); x.finalize().into_bytes().to_vec() }
        _ => return Err(format!("hmac {algo}")),
    })
}

macro_rules! mldsa {
    ($m:ident, $op:expr, $a:expr) => {{
        let a: &[&str] = $a;
        match $op {
            "MK" => { let seed: [u8; 32] = h(a[0]).try_into().map_err(|_| "seed")?; let (pk, sk) = $m::KG::keygen_from_seed(&seed); format!("{}\t{}", hex::encode(pk.into_bytes()), hex::encode(sk.into_bytes())) }
            "MS" => { let seed: [u8; 32] = h(a[0]).try_into().map_err(|_| "seed")?; let (_pk, sk) = $m::KG::keygen_from_seed(&seed);
                      let rnd: [u8; 32] = if a[2].is_empty() { [0u8; 32] } else { h(a[2]).try_into().map_err(|_| "rnd")? };
                      let sig = sk.try_sign_with_seed(&rnd, &h(a[1]), &[]).map_err(|e| e.to_string())?; hex::encode(sig) }
            "MV" => { let pk: Result<[u8; $m::PK_LEN], _> = h(a[0]).try_into(); let sig: Result<[u8; $m::SIG_LEN], _> = h(a[2]).try_into();
                      match (pk, sig) { (Ok(pk), Ok(sig)) => match $m::PublicKey::try_from_bytes(pk) { Ok(pk) => (if pk.verify(&h(a[1]), &sig, &(if a.len() > 3 { h(a[3]) } else { vec![] })) { "1" } else { "0" }).to_string(), Err(_) => "0".into() }, _ => "0".into() } }
            _ => return Err("op".into()),
        }
    }};
}

fn handle(line: &str) -> Result<String, String> {
    let f: Vec<&str> = line.split('\t').collect();
    match f[0] {
        "FLUSH" => Ok("FLUSHED".into()),
        "H" => Ok(hex::encode(hash(f[1], &h(f[2]))?)),
        "M" => Ok(hex::encode(hmac(f[1], &h(f[2]), &h(f[3]))?)),
        "EP" => { let sk: [u8; 32] = h(f[1]).try_into().map_err(|_| "sk")?; Ok(hex::encode(EdSk::from_bytes(&sk).verifying_key().to_bytes())) }
        "ES" => { let sk: [u8; 32] = h(f[1]).try_into().map_err(|_| "sk")?; Ok(hex::encode(EdSk::from_bytes(&sk).sign(&h(f[2])).to_bytes())) }
        "EV" => {
            let pk: Result<[u8; 32], _> = h(f[2]).try_into(); let sg: Result<[u8; 64], _> = h(f[4]).try_into();
            let (Ok(pk), Ok(sg)) = (pk, sg) else { return Ok("0".into()) };
            let Ok(vk) = EdVk::from_bytes(&pk) else { return Ok("0".into()) };
            let sig = EdSig::from_bytes(&sg); let m = h(f[3]);
            let ok = match f[1] { "dalek" => vk.verify_strict_off(&m, &sig), "dalek-strict" => vk.verify_strict(&m, &sig).is_ok(), _ => return Err("variant".into()) };
            Ok((if ok { "1" } else { "0" }).into())
        }
        "MK" | "MS" | "MV" => {
            let a = &f[2..];
            match f[1] {
                "44" => Ok(mldsa!(ml_dsa_44, f[0], a)), "65" => Ok(mldsa!(ml_dsa_65, f[0], a)), "87" => Ok(mldsa!(ml_dsa_87, f[0], a)), _ => Err("level".into()),
            }
        }
        _ => Err("op".into()),
    }
}

trait VerifyOff { fn verify_strict_off(&self, m: &[u8], s: &EdSig) -> bool; }
impl VerifyOff for EdVk { fn verify_strict_off(&self, m: &[u8], s: &EdSig) -> bool { use ed25519_dalek::Verifier as _; self.verify(m, s).is_ok() } }

fn main() {
    let stdin = std::io::stdin(); let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        if line.is_empty() { writeln!(out).unwrap(); continue; }
        let r = std::panic::catch_unwind(|| handle(&line));
        match r { Ok(Ok(s)) => writeln!(out, "{s}"), Ok(Err(e)) => writeln!(out, "ERR {e}"), Err(_) => writeln!(out, "ERR panic") }.unwrap();
        if line.starts_with("FLUSH") { out.flush().unwrap(); }
    }
    out.flush().unwrap();
}

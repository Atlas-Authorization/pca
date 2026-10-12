// SLH-DSA (RustCrypto slh-dsa 0.1.0) voter. Separate crate: slh-dsa needs signature 2.3-pre, which conflicts with ed25519-dalek.
use slh_dsa::signature::Keypair;
use std::io::{BufRead, Write};
fn h(a: &str) -> Vec<u8> { hex::decode(a).unwrap_or_default() }

fn slh(op: &str, param: &str, a: &[&str]) -> Result<String, String> {
    use slh_dsa::signature::Verifier;
    macro_rules! go { ($p:ty) => {{
        match op {
            "SK" => { // a[0] = sk_seed||sk_prf||pk_seed (3n bytes); returns pk, sk
                let b = h(a[0]); let n = if param == "sha2-128f" { 16 } else { 32 };
                if b.len() != 3 * n { return Err("seed len".into()); }
                let sk = slh_dsa::SigningKey::<$p>::slh_keygen_internal(&b[..n], &b[n..2*n], &b[2*n..]);
                format!("{}\t{}", hex::encode(sk.verifying_key().to_bytes()), hex::encode(sk.to_bytes()))
            }
            "SS" => { let sk = slh_dsa::SigningKey::<$p>::try_from(h(a[0]).as_slice()).map_err(|e| e.to_string())?;
                      let rnd = h(a[2]); let sig = sk.try_sign_with_context(&h(a[1]), &[], if rnd.is_empty() { None } else { Some(&rnd) }).map_err(|e| e.to_string())?;
                      hex::encode(sig.to_bytes()) }
            "SV" => { let vk = slh_dsa::VerifyingKey::<$p>::try_from(h(a[0]).as_slice()); let sg = slh_dsa::Signature::<$p>::try_from(h(a[2]).as_slice());
                      match (vk, sg) { (Ok(vk), Ok(sg)) => (if vk.try_verify_with_context(&h(a[1]), &(if a.len() > 3 { h(a[3]) } else { vec![] }), &sg).is_ok() { "1" } else { "0" }).to_string(), _ => "0".into() } }
            _ => return Err("op".into()),
        } }} }
    Ok(match param { "sha2-128f" => go!(slh_dsa::Sha2_128f), "sha2-256s" => go!(slh_dsa::Sha2_256s), _ => return Err("param".into()) })
}


fn handle(line: &str) -> Result<String, String> {
    let f: Vec<&str> = line.split('\t').collect();
    match f[0] { "FLUSH" => Ok("FLUSHED".into()), "SK" | "SS" | "SV" => slh(f[0], f[1], &f[2..]), _ => Err("op".into()) }
}
fn main() {
    let stdin = std::io::stdin(); let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let r = std::panic::catch_unwind(|| handle(&line));
        match r { Ok(Ok(s)) => writeln!(out, "{s}"), Ok(Err(e)) => writeln!(out, "ERR {e}"), Err(_) => writeln!(out, "ERR panic") }.unwrap();
        if line.starts_with("FLUSH") { out.flush().unwrap(); }
    }
    out.flush().unwrap();
}

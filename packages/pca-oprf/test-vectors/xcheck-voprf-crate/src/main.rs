//! Cross-implementation runner for @atlasauth/pca-oprf.
//!
//! `gen`    : deterministic corpus (fixed blinds + fixed proof nonce) produced by the `voprf` crate.
//! `verify` : reads messages produced by the TypeScript implementation (random proof nonces) on
//!            stdin and checks them with the `voprf` crate in both roles (server re-evaluation,
//!            client finalize with proof verification).
use rand_core::{CryptoRng, Error, RngCore};
use serde_json::{json, Value};
use std::io::Read;
use voprf::{
    BlindedElement, EvaluationElement, Group, OprfClient, OprfServer, PoprfClient, PoprfServer, Proof,
    Ristretto255, VoprfClient, VoprfServer,
};

type G = Ristretto255;

/// RNG that replays fixed bytes (used ONLY to pin the proof nonce for reproducible corpora).
struct Fixed {
    bytes: Vec<u8>,
    pos: usize,
}
impl RngCore for Fixed {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for d in dest.iter_mut() {
            *d = *self.bytes.get(self.pos).unwrap_or(&0);
            self.pos += 1;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for Fixed {}

/// A scalar `r` (32 bytes LE) is drawn by dalek as 64 random bytes reduced mod L: pad with zeros.
fn rng_for(r: &[u8]) -> Fixed {
    let mut bytes = r.to_vec();
    bytes.resize(64, 0);
    Fixed { bytes, pos: 0 }
}
fn scalar(b: &[u8]) -> <G as Group>::Scalar {
    G::deserialize_scalar(b).expect("canonical scalar")
}
fn h(b: impl AsRef<[u8]>) -> String {
    hex::encode(b)
}
fn d(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

fn gen() -> Value {
    // (seed-fill byte, key info, input, public info, blind, proof nonce) - all chosen by us, not from any RFC.
    let mut blind_ctr = 0u8;
    let mut cases = vec![];
    let inputs: Vec<Vec<u8>> = vec![
        vec![0x00],
        b"cap_revoked_1".to_vec(),
        vec![0xff; 31],
        (0..=255u8).collect(),
        vec![0x41; 300],
        "ünïcödé-🔑".as_bytes().to_vec(),
    ];
    let infos: Vec<Vec<u8>> = vec![b"".to_vec(), b"2026-10-08T12".to_vec(), vec![0x00, 0xff, 0x10], vec![0x61; 200]];
    // (label, seed, key_info, input, info, blind, nonce)
    let mut params: Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> = vec![];
    // The RFC 9497 A.1 vector-1 parameters: lets the TS test prove this crate reproduces the official outputs.
    params.push((
        "rfc9497-A.1-vector-1-params".into(),
        d("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
        d("74657374206b6579"),
        d("00"),
        d("7465737420696e666f"),
        d("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
        d("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"),
    ));
    for (i, input) in inputs.iter().enumerate() {
        blind_ctr += 1;
        let mut blind = vec![blind_ctr; 32];
        blind[31] = 0x0a; // keep < L
        let mut nonce = vec![0x40 + blind_ctr; 32];
        nonce[31] = 0x05;
        params.push((
            format!("generated-{i}"),
            vec![0x10 + i as u8; 32],
            format!("xcheck key {i}").into_bytes(),
            input.clone(),
            infos[i % infos.len()].clone(),
            blind,
            nonce,
        ));
    }
    for (label, seed, key_info, input, info, blind, nonce) in params {
        let input = &input;
        // OPRF
        let s = OprfServer::<G>::new_from_seed(&seed, &key_info).unwrap();
        let c = OprfClient::<G>::deterministic_blind_unchecked(input, scalar(&blind)).unwrap();
        let ev = s.blind_evaluate(&c.message);
        let out = c.state.finalize(input, &ev).unwrap();
        let direct = s.evaluate(input).unwrap();
        assert_eq!(out, direct);
        let sk = OprfServerSk::get(&seed, &key_info, 0);
        cases.push(json!({"label":label,"mode":"oprf","seed":h(&seed),"keyInfo":h(&key_info),"skSm":h(sk),
            "input":h(input),"blind":h(&blind),"blindedElement":h(c.message.serialize()),
            "evaluatedElement":h(ev.serialize()),"output":h(out)}));

        // VOPRF
        let s = VoprfServer::<G>::new_from_seed(&seed, &key_info).unwrap();
        let pk = s.get_public_key();
        let c = VoprfClient::<G>::deterministic_blind_unchecked(input, scalar(&blind)).unwrap();
        let ev = s.blind_evaluate(&mut rng_for(&nonce), &c.message);
        let out = c.state.finalize(input, &ev.message, &ev.proof, pk).unwrap();
        let direct = s.evaluate(input).unwrap();
        assert_eq!(out, direct);
        let sk = OprfServerSk::get(&seed, &key_info, 1);
        cases.push(json!({"label":label,"mode":"voprf","seed":h(&seed),"keyInfo":h(&key_info),"skSm":h(sk),
            "pkSm":h(G::serialize_elem(pk)),"input":h(input),"blind":h(&blind),"proofRandomScalar":h(&nonce),
            "blindedElement":h(c.message.serialize()),"evaluatedElement":h(ev.message.serialize()),
            "proof":h(ev.proof.serialize()),"output":h(out)}));

        // POPRF
        let s = PoprfServer::<G>::new_from_seed(&seed, &key_info).unwrap();
        let pk = s.get_public_key();
        let c = PoprfClient::<G>::deterministic_blind_unchecked(input, scalar(&blind)).unwrap();
        let ev = s.blind_evaluate(&mut rng_for(&nonce), &c.message, Some(&info)).unwrap();
        let out = c.state.finalize(input, &ev.message, &ev.proof, pk, Some(&info)).unwrap();
        let direct = s.evaluate(input, Some(&info)).unwrap();
        assert_eq!(out, direct);
        let sk = OprfServerSk::get(&seed, &key_info, 2);
        cases.push(json!({"label":label,"mode":"poprf","seed":h(&seed),"keyInfo":h(&key_info),"skSm":h(sk),
            "pkSm":h(G::serialize_elem(pk)),"input":h(input),"info":h(&info),"blind":h(&blind),
            "proofRandomScalar":h(&nonce),"blindedElement":h(c.message.serialize()),
            "evaluatedElement":h(ev.message.serialize()),"proof":h(ev.proof.serialize()),"output":h(out)}));
    }
    json!({"cases":cases})
}

/// Recover the serialized secret key for a mode via the crate's own `derive_key` (feature `danger`).
struct OprfServerSk;
impl OprfServerSk {
    fn get(seed: &[u8], info: &[u8], mode: u8) -> Vec<u8> {
        let m = match mode {
            0 => voprf::Mode::Oprf,
            1 => voprf::Mode::Voprf,
            _ => voprf::Mode::Poprf,
        };
        let sk = voprf::derive_key::<G>(seed, info, m).unwrap();
        G::serialize_scalar(sk).to_vec()
    }
}

fn verify(input: &str) -> Value {
    let doc: Value = serde_json::from_str(input).expect("json");
    let mut results = vec![];
    for c in doc["cases"].as_array().expect("cases") {
        let mode = c["mode"].as_str().unwrap();
        let g = |k: &str| d(c[k].as_str().unwrap());
        let inp = g("input");
        let blinded = BlindedElement::<G>::deserialize(&g("blindedElement")).expect("blinded");
        let evald = EvaluationElement::<G>::deserialize(&g("evaluatedElement")).expect("evaluated");
        let sk = g("skSm");
        let blind = scalar(&g("blind"));
        let mut ok = true;
        let mut why = String::new();
        let out = match mode {
            "oprf" => {
                let s = OprfServer::<G>::new_with_key(&sk).unwrap();
                let mine = s.blind_evaluate(&blinded);
                if mine.serialize() != evald.serialize() { ok = false; why.push_str("server-mismatch;"); }
                let cl = OprfClient::<G>::deterministic_blind_unchecked(&inp, blind).unwrap();
                if cl.message.serialize() != blinded.serialize() { ok = false; why.push_str("blind-mismatch;"); }
                cl.state.finalize(&inp, &evald).map(h).unwrap_or_else(|e| { ok = false; why.push_str(&format!("{e:?};")); String::new() })
            }
            "voprf" => {
                let s = VoprfServer::<G>::new_with_key(&sk).unwrap();
                let pk = G::deserialize_elem(&g("pkSm")).unwrap();
                if G::serialize_elem(s.get_public_key()).to_vec() != g("pkSm") { ok = false; why.push_str("pk-mismatch;"); }
                let mine = s.blind_evaluate(&mut rng_for(&[7u8; 32]), &blinded);
                if mine.message.serialize() != evald.serialize() { ok = false; why.push_str("server-mismatch;"); }
                let proof = Proof::<G>::deserialize(&g("proof")).unwrap();
                let cl = VoprfClient::<G>::deterministic_blind_unchecked(&inp, blind).unwrap();
                cl.state.finalize(&inp, &evald, &proof, pk).map(h).unwrap_or_else(|e| { ok = false; why.push_str(&format!("{e:?};")); String::new() })
            }
            _ => {
                let s = PoprfServer::<G>::new_with_key(&sk).unwrap();
                let pk = G::deserialize_elem(&g("pkSm")).unwrap();
                let info = g("info");
                let mine = s.blind_evaluate(&mut rng_for(&[7u8; 32]), &blinded, Some(&info)).unwrap();
                if mine.message.serialize() != evald.serialize() { ok = false; why.push_str("server-mismatch;"); }
                let proof = Proof::<G>::deserialize(&g("proof")).unwrap();
                let cl = PoprfClient::<G>::deterministic_blind_unchecked(&inp, blind).unwrap();
                cl.state.finalize(&inp, &evald, &proof, pk, Some(&info)).map(h).unwrap_or_else(|e| { ok = false; why.push_str(&format!("{e:?};")); String::new() })
            }
        };
        if out != c["output"].as_str().unwrap() { ok = false; why.push_str("output-mismatch;"); }
        results.push(json!({"mode":mode,"ok":ok,"why":why,"output":out}));
    }
    json!({"results":results})
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    match arg.as_str() {
        "gen" => println!("{}", serde_json::to_string_pretty(&gen()).unwrap()),
        "verify" => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).unwrap();
            println!("{}", serde_json::to_string_pretty(&verify(&s)).unwrap());
        }
        _ => eprintln!("usage: pca-oprf-xcheck gen|verify"),
    }
}

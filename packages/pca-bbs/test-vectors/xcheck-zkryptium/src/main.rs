//! Cross-implementation runner for @atlasauth/pca-bbs.
//!
//! `gen`    : deterministic keys + signatures and randomized proofs produced by `zkryptium` 0.7.1.
//! `verify` : reads TypeScript-produced (pk, signature, header, messages, ph, indexes, proof) on stdin and
//!            reports whether `zkryptium` accepts the signature and the proof.
use serde_json::{json, Value};
use std::io::Read;
use zkryptium::{
    bbsplus::ciphersuites::Bls12381Sha256,
    keys::pair::KeyPair,
    schemes::{
        algorithms::BBSplus,
        generics::{PoKSignature, Signature},
    },
    bbsplus::keys::BBSplusPublicKey,
    utils::util::bbsplus_utils::get_messages_vec,
};

type S = BBSplus<Bls12381Sha256>;

fn d(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}
fn sig_from(b: &[u8]) -> Result<Signature<S>, String> {
    let arr: [u8; 80] = b.try_into().map_err(|_| "bad-length".to_string())?;
    zkryptium::bbsplus::signature::BBSplusSignature::from_bytes(&arr)
        .map(Signature::BBSplus)
        .map_err(|e| format!("{e:?}"))
}

fn gen() -> Value {
    let message_sets: Vec<Vec<Vec<u8>>> = vec![
        vec![b"only-one".to_vec()],
        vec![b"subject:agent-7".to_vec(), b"scope:read".to_vec(), b"aud:tool.example".to_vec()],
        vec![vec![], vec![0u8; 3], (0..=255u8).collect(), "ünï-🔑".as_bytes().to_vec(), vec![0x41; 300]],
        (0..12u8).map(|i| vec![i; (i as usize) * 5]).collect(),
    ];
    let header = d("11223344556677889900aabbccddeeff");
    let mut cases = vec![];
    for (ci, messages) in message_sets.iter().enumerate() {
        let key_material = vec![0x30 + ci as u8; 32];
        let key_info = format!("pca-bbs xcheck {ci}").into_bytes();
        let kp = KeyPair::<S>::generate(&key_material, Some(&key_info), None).unwrap();
        let (sk, pk) = (kp.private_key(), kp.public_key());
        let sig = Signature::<S>::sign(Some(messages), sk, pk, Some(&header)).unwrap();
        assert!(sig.verify(pk, Some(messages), Some(&header)).is_ok());
        let ph = format!("presentation-{ci}").into_bytes();
        // disclose: first, every second one, and a "none" and "all" selection
        let n = messages.len();
        let selections: Vec<Vec<usize>> = vec![
            (0..n).step_by(2).collect(),
            (0..n).collect(),
            vec![],
            vec![n - 1],
        ];
        let mut proofs = vec![];
        for sel in selections {
            let proof = PoKSignature::<S>::proof_gen(
                pk, &sig.to_bytes(), Some(&header), Some(&ph), Some(messages), Some(&sel),
            ).unwrap();
            let disclosed = get_messages_vec(messages, &sel);
            assert!(proof.proof_verify(pk, Some(&disclosed), Some(&sel), Some(&header), Some(&ph)).is_ok());
            proofs.push(json!({"disclosedIndexes": sel, "proof": hex::encode(proof.to_bytes())}));
        }
        cases.push(json!({
            "keyMaterial": hex::encode(&key_material), "keyInfo": hex::encode(&key_info),
            "secretKey": hex::encode(sk.to_bytes()), "publicKey": hex::encode(pk.to_bytes()),
            "header": hex::encode(&header), "presentationHeader": hex::encode(&ph),
            "messages": messages.iter().map(hex::encode).collect::<Vec<_>>(),
            "signature": hex::encode(sig.to_bytes()),
            "proofs": proofs,
        }));
    }
    json!({"cases": cases})
}

fn verify(input: &str) -> Value {
    let doc: Value = serde_json::from_str(input).expect("json");
    let mut out = vec![];
    for c in doc["cases"].as_array().unwrap() {
        let g = |k: &str| d(c[k].as_str().unwrap());
        let pk = BBSplusPublicKey::from_bytes(&g("publicKey")).map_err(|e| format!("{e:?}"));
        let messages: Vec<Vec<u8>> = c["messages"].as_array().unwrap().iter().map(|m| d(m.as_str().unwrap())).collect();
        let header = g("header");
        let mut res = json!({"signature": null, "proofs": []});
        if let Ok(pk) = &pk {
            res["signature"] = match sig_from(&g("signature")) {
                Ok(s) => match s.verify(pk, Some(&messages), Some(&header)) { Ok(_) => json!("ok"), Err(e) => json!(format!("{e:?}")) },
                Err(e) => json!(e),
            };
            let ph = g("presentationHeader");
            let mut ps = vec![];
            for p in c["proofs"].as_array().unwrap() {
                let idx: Vec<usize> = p["disclosedIndexes"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as usize).collect();
                let proof = PoKSignature::<S>::from_bytes(&d(p["proof"].as_str().unwrap()));
                let r = match proof {
                    Ok(pr) => {
                        let disclosed = get_messages_vec(&messages, &idx);
                        match pr.proof_verify(pk, Some(&disclosed), Some(&idx), Some(&header), Some(&ph)) { Ok(_) => json!("ok"), Err(e) => json!(format!("{e:?}")) }
                    }
                    Err(e) => json!(format!("{e:?}")),
                };
                ps.push(r);
            }
            res["proofs"] = json!(ps);
        } else {
            res["signature"] = json!("bad-public-key");
        }
        out.push(res);
    }
    json!({"results": out})
}

fn main() {
    match std::env::args().nth(1).unwrap_or_default().as_str() {
        "gen" => println!("{}", serde_json::to_string_pretty(&gen()).unwrap()),
        "verify" => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).unwrap();
            println!("{}", serde_json::to_string_pretty(&verify(&s)).unwrap());
        }
        _ => eprintln!("usage: pca-bbs-xcheck gen|verify"),
    }
}

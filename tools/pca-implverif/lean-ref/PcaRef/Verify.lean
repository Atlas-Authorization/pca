/- Reference decision procedure for PCActn (wire v2), core checks only, ed25519 suite. Written independently in Lean 4 from the
   normative description in packages/pca/conformance/README.md and the check order; used for differential testing against the
   conformance corpus (which every shipped verifier also passes). Post-quantum signature verdicts (ml-dsa / slh-dsa / hybrids)
   are NOT implemented: such vectors are reported as skipped unless the expected verdict is a terminal wire failure. -/
import PcaRef.Json
namespace PcaRef

def SIG_DOMAIN : ByteArray := "atlas-pca/actn/v2".toUTF8.push 0
def CAP_DOMAIN : ByteArray := "atlas-pca/cap/v1".toUTF8.push 0
def MAX_LIFETIME : Int := 3600000
def MAX_SKEW : Int := 60000
def MAX_CHAIN : Nat := 16
def MAX_AUD : Nat := 256
def MAX_NONCE : Nat := 128
def MLDSA_PK : Nat := 1952
def MLDSA_SIG : Nat := 3309

def objOf (v : Option J) : Option J := match v with | some (.obj kv) => some (.obj kv) | _ => none
def strOf (v : Option J) : Option String := v.bind J.asStr?
def b64n (v : Option J) (n : Nat) : Bool := match strOf v with | some s => (b64DecodeLen s n).isSome | none => false
def isInt (v : Option J) : Bool := match v with | some x => (safeInt x).isSome | none => false
def isStrO (v : Option J) : Bool := match v with | some (.str _) => true | _ => false
def isNumO (v : Option J) : Bool := match v with | some (.num _) => true | _ => false

structure Suite where (name : String) (sigBytes : Nat) (needsPk : Bool) (needsPqSig : Bool)
def suiteOf (n : String) : Option Suite :=
  if n == "ed25519" then some ⟨n, 64, false, false⟩
  else if n == "ml-dsa-65" then some ⟨n, MLDSA_SIG, true, false⟩
  else if n == "hybrid-ed25519-ml-dsa-65" then some ⟨n, 64, true, true⟩ else none
def resolveAlg (alg : Option J) : Option Suite :=
  match alg with | none => suiteOf "ed25519" | some (.str s) => suiteOf s | some _ => none

def sigWire (p : J) : Bool :=
  let alg := p.get? "alg"
  (match alg with | some (.str _) | none => true | _ => false) &&
  match resolveAlg alg with
  | none => false
  | some su =>
    b64n (p.get? "sig") su.sigBytes &&
    (if su.needsPk then b64n (p.get? "pq_pk") MLDSA_PK else (p.get? "pq_pk").isNone) &&
    (if su.needsPqSig then b64n (p.get? "pq_sig") MLDSA_SIG else (p.get? "pq_sig").isNone)

def closedKeys (o : J) (allowed : List String) : Bool := o.keys.all (fun k => allowed.contains k)

def REQUIRED : List String := ["ver","action","grant_ref","cap_chain","plan","attestation","provenance","freshness","counter","risk_claim","aud","iat","exp","sig"]
def OPTIONAL : List String := ["nonce","caution","rationale_commitment","progress_step","prohibition_evidence","tool_binding","threshold","zk_compliance","bond_ref","alg","pq_pk","pq_sig","intent"]

/-! ### Intent binding (Intent Layer M2; conformance README rule 12) -/
def INTENT_KEYS : List String := ["ref","map_digest","goal_salt","fidelity_ppm","residual_risk_ppm"]
def MAX_GOAL_SALT : Nat := 128
def PPM_ONE : Int := 1000000

/-- the shape of the optional signed `intent` member (closed, all five members, bytes / length / ranges). -/
def intentWire (v : J) : Bool :=
  v.isObj && closedKeys v INTENT_KEYS && INTENT_KEYS.all (fun k => (v.get? k).isSome) &&
  b64n (v.get? "ref") 32 && b64n (v.get? "map_digest") 32 &&
  (match strOf (v.get? "goal_salt") with | some s => !s.isEmpty && s.utf8ByteSize ≤ MAX_GOAL_SALT | none => false) &&
  (match (v.get? "fidelity_ppm").bind safeInt with | some f => decide (0 ≤ f) && decide (f ≤ PPM_ONE) | none => false) &&
  (match (v.get? "residual_risk_ppm").bind safeInt with | some r => decide (0 ≤ r) | none => false)

def withoutKeys (p : J) (ks : List String) : J :=
  match p with | .obj kv => .obj (kv.filter (fun e => !ks.contains e.1)) | x => x

/-- strict canonical bytes of the signed body; none => violation. -/
def signedBody (p : J) : Option String := canonStrict (withoutKeys p ["sig","threshold","pq_sig"])

def validateWire (p : J) : Bool := Id.run do
  if !p.isObj then return false
  if !(p.keys.all (fun k => REQUIRED.contains k || OPTIONAL.contains k)) then return false
  if !(REQUIRED.all (fun k => (p.get? k).isSome)) then return false
  if (signedBody p).isNone then return false
  for k in ["ver","counter","iat","exp"] do
    if !isInt (p.get? k) then return false
  match strOf (p.get? "aud") with
  | some a => if a.isEmpty || a.utf8ByteSize > MAX_AUD then return false
  | none => return false
  match p.get? "nonce" with
  | some n => match n.asStr? with
    | some s => if s.isEmpty || s.utf8ByteSize > MAX_NONCE then return false
    | none => return false
  | none => pure ()
  if !sigWire p then return false
  if !b64n (p.get? "grant_ref") 32 then return false
  let some a := objOf (p.get? "action") | return false
  if !closedKeys a ["verb","resource","params_digest","reversibility_class"] then return false
  if !(isStrO (a.get? "verb") && isStrO (a.get? "resource") && isStrO (a.get? "reversibility_class")) then return false
  if !b64n (a.get? "params_digest") 32 then return false
  let some pl := objOf (p.get? "plan") | return false
  if !closedKeys pl ["root","inclusion_proof","node_id","conditions_digest"] then return false
  if !b64n (pl.get? "root") 32 then return false
  if !isStrO (pl.get? "node_id") then return false
  match pl.get? "conditions_digest" with
  | some cd =>
    if !b64n (some cd) 32 then return false
  | none => pure ()
  let some ip := objOf (pl.get? "inclusion_proof") | return false
  if !closedKeys ip ["index","size","path"] then return false
  if !isInt (ip.get? "index") || !isInt (ip.get? "size") then return false
  let some path := (ip.get? "path").bind J.asArr? | return false
  for st in path do
    if !st.isObj then return false
    if !closedKeys st ["side","hash"] then return false
    match strOf (st.get? "side") with | some "L" | some "R" => pure () | _ => return false
    if !b64n (st.get? "hash") 32 then return false
  let some chain := (p.get? "cap_chain").bind J.asArr? | return false
  for c in chain do
    if !c.isObj then return false
    if !closedKeys c ["id","issuer","holder","body_digest","caveats","sig","parent","alg","pq_pk","pq_sig","holder_pq"] then return false
    for k in ["id","issuer","holder","body_digest"] do
      if !b64n (c.get? k) 32 then return false
    if !sigWire c then return false
    match c.get? "parent" with
    | some par =>
      if !b64n (some par) 32 then return false
    | none => pure ()
    match c.get? "holder_pq" with
    | some hp =>
      if !b64n (some hp) 32 then return false
    | none => pure ()
    match (c.get? "caveats").bind J.asArr? with
    | some cv => if !(cv.all (fun x => x.isObj && isStrO (x.get? "type"))) then return false
    | none => return false
  let some att := objOf (p.get? "attestation") | return false
  if !isInt (att.get? "epoch") then return false
  if !(isStrO (att.get? "quote_digest") && isStrO (att.get? "model_id") && isStrO (att.get? "measurement") && isStrO (att.get? "operator")) then return false
  let some pv := objOf (p.get? "provenance") | return false
  if !(isStrO (pv.get? "causal_hash") && isNumO (pv.get? "taint_level")) then return false
  match (pv.get? "trusted_refs").bind J.asArr? with
  | some r => if !(r.all J.isStr) then return false
  | none => return false
  let some fr := objOf (p.get? "freshness") | return false
  if !(isInt (fr.get? "epoch") && isStrO (fr.get? "beacon_ref") && isStrO (fr.get? "accumulator_witness")) then return false
  let some rc := objOf (p.get? "risk_claim") | return false
  if !(isNumO (rc.get? "r") && (match rc.get? "inputs" with | some (.obj _) => true | _ => false)) then return false
  match p.get? "caution" with
  | some (.num lex) =>
    -- number in [0,1]; only plain decimals/ints are modelled
    match classify lex with
    | .int i =>
      if i < 0 || i > 1 then return false
    | .dec l =>
      if l.startsWith "-" || !(l.startsWith "0.") then return false
    | .other => return false
  | some _ => return false
  | none => pure ()
  match p.get? "rationale_commitment" with
  | some v =>
    if !b64n (some v) 32 then return false
  | none => pure ()
  match p.get? "tool_binding" with
  | some v =>
    if !b64n (some v) 32 then return false
  | none => pure ()
  match p.get? "progress_step" with
  | some v =>
    if !v.isObj then return false
  | none => pure ()
  match p.get? "intent" with
  | some v =>
    if !intentWire v then return false
  | none => pure ()
  match p.get? "prohibition_evidence" with
  | some v =>
    match v with
    | .obj _ | .arr _ => pure ()
    | _ => return false
  | none => pure ()
  match p.get? "threshold" with
  | some th =>
    let some shares := (th.get? "shares").bind J.asArr? | return false
    for s in shares do
      if !(s.isObj && isStrO (s.get? "role")) then return false
      if !b64n (s.get? "publicKey") 32 then return false
      if !b64n (s.get? "sig") 64 then return false
  | none => pure ()
  return true

/-! ### Merkle -/
def leafHash (leaf : J) : ByteArray := sha256 (ByteArray.empty.push 0 ++ (canonLenient leaf).toUTF8)
def nodeHash (l r : ByteArray) : ByteArray := sha256 ((ByteArray.empty.push 1) ++ l ++ r)
partial def splitPt (n : Nat) : Nat := Id.run do
  let mut k := 1
  while k * 2 < n do k := k * 2
  return k
partial def pathShape (idx n : Nat) : List UInt8 :=
  if n ≤ 1 then [] else
  let k := splitPt n
  if idx < k then pathShape idx k ++ [82] else pathShape (idx - k) (n - k) ++ [76]
  -- built leaf->root order: the Rust code pushes top-down then reverses; here recursion appends deepest-first

def verifyInclusion (root : String) (proof : Option J) (leaf : J) : Bool := Id.run do
  let some pr := proof | return false
  let some path := (pr.get? "path").bind J.asArr? | return false
  let some idx := (pr.get? "index").bind safeInt | return false
  let some size := (pr.get? "size").bind safeInt | return false
  if size < 1 || idx < 0 || idx >= size then return false
  let shape := pathShape idx.toNat size.toNat
  if shape.length != path.size then return false
  let mut h := leafHash leaf
  let mut i := 0
  for s in path do
    if !s.isObj then return false
    let side := (strOf (s.get? "side")).getD ""
    if side.toUTF8 != (ByteArray.empty.push shape[i]!) then return false
    let some sib := (strOf (s.get? "hash")).bind (fun x => b64DecodeLen x 32) | return false
    h := if side == "L" then nodeHash sib h else nodeHash h sib
    i := i + 1
  return String.fromUTF8! (b64Encode h) == root

def paramsDigestEmpty : String := hashCanon (.obj #[])
def condDefault : String := hashCanon (.obj #[("pre", .null), ("post", .null)])

def planLeaf (nodeId : Option J) (action : Option J) (cond : String) : Option J := do
  let nid ← nodeId
  match nid with | .null => none | _ => pure ()
  let g := fun (k : String) => (action.bind (fun a => a.get? k)).getD .null
  let pd := match g "params_digest" with | .null => J.str paramsDigestEmpty | v => v
  let rc := match g "reversibility_class" with | .null => J.str "reversible" | v => v
  pure (.obj #[("node_id", nid), ("verb", g "verb"), ("resource", g "resource"), ("params_digest", pd), ("reversibility_class", rc), ("conditions", .str cond)])

/-! ### signatures (ed25519 only) -/
def verifyB64u (pk : String) (msg : ByteArray) (sig : String) : Bool :=
  match b64DecodeLen pk 32, b64DecodeLen sig 64 with
  | some p, some s => ed25519VerifyStrict p msg s
  | _, _ => false

def algName (alg : Option J) : String := match alg with | none => "ed25519" | some (.str s) => s | some _ => "\u0000non-string"
def suiteAllowed (alg : Option J) (allowed : Option (List String)) : Bool :=
  match allowed with | none => true | some l => l.contains (algName alg)

/-- result of a signature-bearing step: .ok b, or .pq when the suite needs a post-quantum verifier we do not have. -/
inductive Sg | ok (b : Bool) | pq

def verifySuite (alg : Option J) (holder : String) (msg : ByteArray) (sig : Option J) : Sg :=
  match resolveAlg alg with
  | none => .ok false
  | some su =>
    if su.name == "ed25519" then
      match strOf sig with | some s => .ok (verifyB64u holder msg s) | none => .ok false
    else .pq

def bodyOf (c : J) : J :=
  let g := fun (k : String) => (c.get? k).getD .null
  let base := #[("issuer", g "issuer"), ("holder", g "holder"), ("caveats", g "caveats"), ("parent", g "parent")]
  match c.get? "holder_pq" with | some hp => .obj (base.push ("holder_pq", hp)) | none => .obj base

def checkSig (c : J) (signer : String) : Sg :=
  match resolveAlg (c.get? "alg") with
  | none => .ok false
  | some su =>
    if su.name != "ed25519" then .pq else
    let body := bodyOf c
    let digest := hashCanon body
    let bd := (strOf (c.get? "body_digest")).getD ""
    let id := (strOf (c.get? "id")).getD ""
    if digest != bd || id != bd then .ok false else
    match b64DecodeLen bd 32 with
    | none => .ok false
    | some d => verifySuite (c.get? "alg") signer (CAP_DOMAIN ++ d) (c.get? "sig")

def optEq (a b : Option J) : Bool :=
  match a, b with | none, none => true | some x, some y => canonLenient x == canonLenient y | _, _ => false

/-- chain verification. returns .ok verdict or .pq if a PQ suite decides the outcome. -/
def verifyChain (chain : Array J) (expRoot : Option String) (allowed : Option (List String)) : Sg := Id.run do
  if chain.isEmpty then return .ok false
  if chain.size > MAX_CHAIN then return .ok false
  if !(chain.all J.isObj) then return .ok false
  let root := chain[0]!
  if (root.get? "parent").isSome then return .ok false
  match expRoot with
  | some e =>
    if strOf (root.get? "issuer") != some e then return .ok false
  | none => pure ()
  if !suiteAllowed (root.get? "alg") allowed then return .ok false
  let mut pqSeen := false
  match checkSig root ((strOf (root.get? "issuer")).getD "") with
  | .ok false => return .ok false
  | .pq => pqSeen := true
  | .ok true => pure ()
  for i in [1:chain.size] do
    let parent := chain[i-1]!; let c := chain[i]!
    let ph := hashCanon parent
    if strOf (c.get? "parent") != some ph then return .ok false
    if !optEq (c.get? "issuer") (parent.get? "holder") then return .ok false
    if !suiteAllowed (c.get? "alg") allowed then return .ok false
    -- pq_binding_ok is true for ed25519 (the only suite modelled)
    match checkSig c ((strOf (parent.get? "holder")).getD "") with
    | .ok false => return .ok false
    | .pq => pqSeen := true
    | .ok true => pure ()
    let pc := ((parent.get? "caveats").bind J.asArr?).getD #[]
    let cc := ((c.get? "caveats").bind J.asArr?).getD #[]
    if cc.size < pc.size then return .ok false
    for j in [0:pc.size] do
      if hashCanon cc[j]! != hashCanon pc[j]! then return .ok false
  return (if pqSeen then .pq else .ok true)

/-- verifier intent policy; a threshold is kept as the raw JSON value so a set-but-invalid one is distinguishable. -/
structure IntentPolicy where
  require : Bool := false
  minFid : Option J := none
  maxRes : Option J := none

def IntentPolicy.active (q : IntentPolicy) : Bool := q.require || q.minFid.isSome || q.maxRes.isSome

/-- from `context.intent_policy` (absent / non-object => no policy; `require` counts only when it is `true`). -/
def IntentPolicy.ofJ (o : Option J) : IntentPolicy :=
  match o with
  | some (.obj kv) =>
    let q := J.obj kv
    { require := (match q.get? "require" with | some (.bool true) => true | _ => false),
      minFid := q.get? "min_fidelity_ppm", maxRes := q.get? "max_residual_risk_ppm" }
  | _ => {}

/-- the exact value N/D (D a power of ten) of a NON-NEGATIVE JSON number lexeme in any lexical form (950000,
    950000.0, 1e6, 4.31e6, 9007199254740991.4); none for a malformed lexeme or an exponent beyond any double. -/
def lexValue (lex : String) : Option (Nat × Nat) := Id.run do
  let (mant, ex) := match lex.splitOn "e" with
    | [m, e] => (m, e)
    | _ => match lex.splitOn "E" with | [m, e] => (m, e) | _ => (lex, "0")
  let ex' := if ex.startsWith "+" then ex.drop 1 else ex
  let some e := ex'.toInt? | return none
  let parts := mant.splitOn "."
  if parts.length > 2 then return none
  let ip := parts[0]!
  let fp := if parts.length > 1 then parts[1]! else ""
  if ip.isEmpty || !(ip.all Char.isDigit) || !(fp.all Char.isDigit) then return none
  let digits := ip ++ fp
  let some d := digits.toNat? | return none
  if d == 0 then return some (0, 1)
  let shift : Int := e - fp.length
  -- beyond these the value is certainly above 2^53 (refused) or below half the least subnormal (rounds to 0)
  if shift > 400 then return none
  if shift + digits.length < -400 then return some (0, 1)
  if shift ≥ 0 then return some (d * 10 ^ shift.toNat, 1)
  return some (d, 10 ^ (-shift).toNat)

/-- round the non-negative rational N/D to the nearest IEEE-754 binary64 (round-half-to-even), exactly as JSON.parse
    and every shipped verifier's float parser do, and return it when that double is an integer <= 2^53-1; none otherwise. -/
def roundedSafeInt (N D : Nat) : Option Nat := Id.run do
  if N == 0 then return some 0
  if N ≥ 9007199254740992 * D then return none -- the nearest double is >= 2^53
  if N < D then
    -- v < 1: the nearest double is an integer only when it is 0 (v <= 2^-1075, the tie goes to even 0) or 1
    -- (v >= 1 - 2^-54, the tie goes to 1.0 whose significand is even)
    if N * 2 ^ 1075 ≤ D then return some 0
    if N * 2 ^ 54 ≥ D * (2 ^ 54 - 1) then return some 1
    return none
  -- 1 <= v < 2^53: binade 2^e <= v < 2^(e+1), e in 0..52, spacing 2^(e-52)
  let mut e : Nat := 0
  for i in [1:53] do
    if 2 ^ i * D ≤ N then e := i
  let k := 52 - e
  let num := N * 2 ^ k
  let fl := num / D
  let rem := num % D
  let m := if 2 * rem > D then fl + 1 else if 2 * rem < D then fl else fl + fl % 2
  if m % 2 ^ k != 0 then return none
  let r := m / 2 ^ k
  if r > MAX_SAFE then return none
  return some r

/-- a set threshold's value: a JSON number whose binary64 VALUE is an integer in [0, 2^53-1] (lexical form irrelevant;
    any leading "-" is refused: negative values and negative zero, including "-1e-400" which JSON.parse makes -0). -/
def thresholdVal (t : Option J) : Option Int :=
  match t with
  | some (.num lex) => if lex.startsWith "-" then none else
      match lexValue lex with
      | some (n, d) => (roundedSafeInt n d).map Int.ofNat
      | none => none
  | _ => none

def thresholdOk (t : Option J) : Bool := t.isNone || (thresholdVal t).isSome

/-- the FIRST caveat of the grant that is an object with type "envelope": its string goal_commit. -/
def rootGoalCommit (grant : J) : Option String :=
  match (grant.get? "caveats").bind J.asArr? with
  | none => none
  | some cs => match cs.find? (fun c => c.isObj && strOf (c.get? "type") == some "envelope") with
    | some e => strOf (e.get? "goal_commit")
    | none => none

/-- the `intent` check: none = not reported (no member, inactive policy); some b = its verdict. `p` is wire-valid. -/
def intentCheck (p grant : J) (q : IntentPolicy) : Option Bool := Id.run do
  let slot := p.get? "intent"
  if slot.isNone && !q.active then return none
  if !(thresholdOk q.minFid && thresholdOk q.maxRes) then return some false
  let some it := slot | return some false
  let some commit := rootGoalCommit grant | return some false
  let ref := (strOf (it.get? "ref")).getD ""
  let md := (strOf (it.get? "map_digest")).getD ""
  let salt := (strOf (it.get? "goal_salt")).getD ""
  let want := hashCanon (.obj #[("d", .str "atlas-pca/goal/v1\x00"), ("goal", .str ("pca-intent:v1:" ++ ref ++ ":" ++ md)), ("salt", .str salt)])
  if want != commit then return some false
  let fid := ((it.get? "fidelity_ppm").bind safeInt).getD 0
  let res := ((it.get? "residual_risk_ppm").bind safeInt).getD 0
  match thresholdVal q.minFid with
  | some m => if fid < m then return some false
  | none => pure ()
  match thresholdVal q.maxRes with
  | some m => if res > m then return some false
  | none => pure ()
  return some true

structure Verdict where
  allow : Bool
  checks : List (String × Bool)
  pq : Bool := false      -- true => a PQ suite decides; this reference cannot give a verdict

def CHECKS : List String := ["wire","version","audience","validity","chain","grant_ref_bound","plan_inclusion","leaf_signature","counter"]

def verifyCore (p : J) (grant : J) (now : Int) (aud : String) (allowed : Option (List String)) (intent : IntentPolicy := {}) : Verdict := Id.run do
  if !validateWire p then return ⟨false, [("wire", false)], false⟩
  -- version
  let ver := (p.get? "ver").bind safeInt
  let versionOk := ver == some 2
  let audOk := strOf (p.get? "aud") == some aud
  let iat := ((p.get? "iat").bind safeInt).getD 0
  let exp := ((p.get? "exp").bind safeInt).getD 0
  let validity := !(exp ≤ iat) && !(exp - iat > MAX_LIFETIME) && !(iat > now + MAX_SKEW) && !(now > exp)
  let chain := ((p.get? "cap_chain").bind J.asArr?).getD #[]
  let chainSg : Sg :=
    if chain.isEmpty then .ok false
    else if chain.size > MAX_CHAIN then .ok false
    else if hashCanon chain[0]! != hashCanon grant then .ok false
    else verifyChain chain (strOf (grant.get? "issuer")) allowed
  let chainOk := match chainSg with | .ok b => b | .pq => true
  let gref := strOf (p.get? "grant_ref")
  let rootId := (chain[0]?).bind (fun c => strOf (c.get? "id"))
  let grOk := match gref, rootId with | some g, some r => !g.isEmpty && g == r | _, _ => false
  let plan := (p.get? "plan").getD (.obj #[])
  let cond := (strOf (plan.get? "conditions_digest")).getD condDefault
  let root := (strOf (plan.get? "root")).getD ""
  let inclOk := match planLeaf (plan.get? "node_id") (p.get? "action") cond with
    | some leaf => verifyInclusion root (plan.get? "inclusion_proof") leaf
    | none => false
  let sigSg : Sg :=
    match chain.back? with
    | none => .ok false
    | some leafCap =>
      let holder := (strOf (leafCap.get? "holder")).getD ""
      if !suiteAllowed (p.get? "alg") allowed then .ok false
      else match signedBody p with
        | none => .ok false
        | some canonBody =>
          let msg := SIG_DOMAIN ++ sha256 canonBody.toUTF8
          verifySuite (p.get? "alg") holder msg (p.get? "sig")
  let sigOk := match sigSg with | .ok b => b | .pq => true
  let pq := (match chainSg with | .pq => true | _ => false) || (match sigSg with | .pq => true | _ => false)
  let counterOk := match (p.get? "counter").bind safeInt with | some i => i ≥ 0 | none => false
  let checks := [("wire", true), ("version", versionOk), ("audience", audOk), ("validity", validity), ("chain", chainOk),
                 ("grant_ref_bound", grOk), ("plan_inclusion", inclOk), ("leaf_signature", sigOk), ("counter", counterOk)]
    ++ (match intentCheck p grant intent with | some b => [("intent", b)] | none => [])
  return ⟨checks.all (·.2), checks, pq⟩

end PcaRef

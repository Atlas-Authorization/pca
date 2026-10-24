import PcaRef.Verify
open PcaRef
/- differential driver: pca-ref <vectors.json> [more corpus files...]. Reads the corpus (lenient parse), runs the Lean reference
   decision procedure on every vector and compares to `expect`. Prints agreement counts and every disagreement. -/
partial def hasSentinel : J → Bool
  | .str s => s.any (· == SENTINEL)
  | .arr xs => xs.any hasSentinel
  | .obj kvs => kvs.any (fun (k, v) => k.any (· == SENTINEL) || hasSentinel v)
  | _ => false

def boolOf (v : Option J) : Bool := match v with | some (.bool b) => b | _ => false

def runFile (path : String) (text : String) : IO (Nat × Nat × Nat × Nat) := do
  let doc ← match parseText text false with | .ok d => pure d | .error e => throw (IO.userError s!"{path}: {e}")
  let vs := ((doc.get? "vectors").bind J.asArr?).getD #[]
  let mut agree := 0; let mut dis := 0; let mut skipped := 0; let mut total := 0
  for v in vs do
    total := total + 1
    let name := (strOf (v.get? "name")).getD "?"
    let ctx := (v.get? "context").getD (.obj #[])
    let now : Int := ((ctx.get? "now").bind safeInt).getD 0
    let aud := (strOf (ctx.get? "aud")).getD ""
    let allowed : Option (List String) := ((ctx.get? "allowed_suites").bind J.asArr?).map (fun a => a.toList.filterMap (fun x => x.asStr?))
    -- `intent_policy_json` (raw JSON text, lexical forms preserved) wins over `intent_policy`
    let intent := match strOf (ctx.get? "intent_policy_json") with
      | some raw => IntentPolicy.ofJ (match parseText raw false with | .ok j => some j | .error _ => none)
      | none => IntentPolicy.ofJ (ctx.get? "intent_policy")
    let grant := (v.get? "grant").getD .null
    let exp := (v.get? "expect").getD .null
    let expAllow := boolOf (exp.get? "allow")
    let expChecks := match exp.get? "checks" with | some (.obj kv) => kv.toList.map (fun (e : String × J) => (e.1, boolOf (some e.2))) | _ => []
    let verdict : Verdict :=
      match (v.get? "pcactn_json").bind J.asStr? with
      | some raw => match parseText raw true with
          | .ok p => verifyCore p grant now aud allowed intent
          | .error _ => ⟨false, [("wire", false)], false⟩
      | none =>
        let p := (v.get? "pcactn").getD .null
        if hasSentinel p then ⟨false, [("wire", false)], false⟩ else verifyCore p grant now aud allowed intent
    let terminalWire := expChecks.length == 1 && expChecks.any (fun (e : String × Bool) => e.1 == "wire" && !e.2)
    let needsPq := (strOf (v.get? "requires")).isSome
    if (verdict.pq || needsPq) && !terminalWire then
      skipped := skipped + 1
    else
      let okAllow := verdict.allow == expAllow
      let okChecks := verdict.checks.length == expChecks.length && expChecks.all (fun (e : String × Bool) => verdict.checks.lookup e.1 == some e.2)
      if okAllow && okChecks then agree := agree + 1
      else
        dis := dis + 1
        IO.println s!"DISAGREE {name}: got allow={verdict.allow} {verdict.checks}, want allow={expAllow} {expChecks}"
  return (total, agree, dis, skipped)

def primChecks (text : String) : IO Unit := do
  let doc ← match parseText text false with | .ok d => pure d | .error e => throw (IO.userError e)
  let pr := (doc.get? "primitives").getD .null
  let mut bad := 0; let mut n := 0
  for c in ((pr.get? "canonical").bind J.asArr?).getD #[] do
    n := n + 1
    let val := (c.get? "value").getD .null
    if some (canonLenient val) != strOf (c.get? "expect") || some (hashCanon val) != strOf (c.get? "hash") then
      bad := bad + 1; IO.println s!"PRIM canonical mismatch {canonLenient val}"
  IO.println s!"canonical: {n - bad}/{n} agree"
  bad := 0; n := 0
  for t in ((pr.get? "json_parse").bind J.asArr?).getD #[] do
    n := n + 1
    let input := (strOf (t.get? "input")).getD ""
    let accept := boolOf (t.get? "accept")
    let got := (parseText input true)
    let ok := match got, accept with
      | .ok v, true => (match strOf (t.get? "canonical") with | some c => canonStrict v == some c | none => true)
      | .error _, false => true
      | _, _ => false
    if !ok then bad := bad + 1; IO.println s!"PRIM json_parse mismatch {repr input}"
  IO.println s!"json_parse: {n - bad}/{n} agree"
  bad := 0; n := 0
  for t in ((pr.get? "b64u").bind J.asArr?).getD #[] do
    n := n + 1
    let input := (strOf (t.get? "input")).getD ""
    let valid := boolOf (t.get? "valid")
    let got := match (t.get? "len").bind safeInt with
      | some l => (b64DecodeLen input l.toNat).isSome
      | none => (b64Decode input.toUTF8).isSome
    if got != valid then bad := bad + 1; IO.println s!"PRIM b64u mismatch {repr input}"
  IO.println s!"b64u: {n - bad}/{n} agree"
  bad := 0; n := 0
  for m in ((pr.get? "merkle").bind J.asArr?).getD #[] do
    let leaves := ((m.get? "leaves").bind J.asArr?).getD #[]
    for p in ((m.get? "proofs").bind J.asArr?).getD #[] do
      n := n + 1
      let i := ((p.get? "index").bind safeInt).getD 0
      if !verifyInclusion ((strOf (m.get? "root")).getD "") (some p) leaves[i.toNat]! then bad := bad + 1; IO.println "PRIM merkle proof rejected"
  IO.println s!"merkle proofs: {n - bad}/{n} verify"

def main (args : List String) : IO UInt32 := do
  let mut rc : UInt32 := 0
  for f in args do
    let text ← if f.endsWith ".gz" then do
        let o ← IO.Process.output { cmd := "gzip", args := #["-dc", f] }
        pure o.stdout
      else IO.FS.readFile f
    -- lone surrogates cannot live in a Lean String: the lenient parser maps them to a sentinel
    if f.endsWith "vectors.json" then primChecks text
    let (t, a, d, s) ← runFile f text
    IO.println s!"{f}: total={t} agree={a} disagree={d} skipped(PQ suite)={s}"
    if d != 0 then rc := 1
  return rc

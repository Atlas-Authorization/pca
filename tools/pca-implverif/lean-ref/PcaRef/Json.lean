/- Reference JSON for PCA: the STRICT profile (README section 2 of the conformance corpus) as an independent parser,
   plus a lenient loader used only to read the corpus files. Numbers are kept as their LEXEME: under the strict profile
   the accepted lexeme is already the canonical form (no exponent, no trailing fractional zero, no "-0"). -/
import PcaRef.Crypto
namespace PcaRef

inductive J where
  | null | bool (b : Bool) | num (lex : String) | str (s : String)
  | arr (xs : Array J) | obj (kvs : Array (String × J))
deriving Inhabited

abbrev MAX_SAFE : Nat := 9007199254740991
def MAX_DEPTH : Nat := 32
def MAX_CHARS : Nat := 1048576
def SENTINEL : Char := Char.ofNat 0x10FFFF

def J.get? : J → String → Option J
  | .obj kvs, k => (kvs.find? (fun p => p.1 == k)).map (·.2)
  | _, _ => none
def J.asStr? : J → Option String | .str s => some s | _ => none
def J.asArr? : J → Option (Array J) | .arr a => some a | _ => none
def J.isObj : J → Bool | .obj _ => true | _ => false
def J.isStr : J → Bool | .str _ => true | _ => false
def J.keys : J → List String | .obj kvs => kvs.toList.map (·.1) | _ => []

/-! ### number classification (what serde_json + number_error + safe_int decide) -/
inductive NumClass where
  | int (v : Int)            -- integer-valued, within i64/u64
  | dec (canon : String)     -- plain decimal with a fractional part, canonical lexeme
  | other                    -- exponent form / integer-valued float / out of range: not modelled by this reference
deriving Inhabited

def isDigits (s : String) : Bool := s.length > 0 && s.all Char.isDigit

def classify (lex : String) : NumClass :=
  if lex.any (fun c => c == 'e' || c == 'E') then .other
  else match lex.splitOn "." with
  | [ip] =>
    let neg := ip.startsWith "-"
    let digs := if neg then (ip.drop 1).toString else ip
    if !isDigits digs then .other
    else
      let v := digs.toNat!
      if v > 18446744073709551615 then .other
      else .int (if neg then -(Int.ofNat v) else Int.ofNat v)
  | [ip, fp] =>
    let digs := if ip.startsWith "-" then (ip.drop 1).toString else ip
    if !isDigits digs || !isDigits fp then .other
    else if fp.endsWith "0" then .other
    else .dec lex
  | _ => .other

/-- number_error (None == acceptable) for a classified number; `none` result means strict-acceptable. -/
def numberOk (c : NumClass) : Option Bool :=
  match c with
  | .int v => some (v.natAbs ≤ MAX_SAFE)
  | .dec lex =>
    let digs := (lex.replace "-" "").replace "." ""
    let sig := (digs.dropWhile (· == '0')).toString.length
    let ip := (lex.splitOn ".")[0]!
    let fp := (lex.splitOn ".")[1]!
    let tiny := (ip == "0" || ip == "-0") && fp.startsWith "000000"
    some (!(tiny) && sig ≤ 15)
  | .other => none

/-- safe_int: Some i only for strictly valid integer-valued numbers. -/
def safeInt (v : J) : Option Int :=
  match v with
  | .num lex => match classify lex with
    | .int i => if i.natAbs ≤ MAX_SAFE then some i else none
    | _ => none
  | _ => none

/-! ### canonical serialisation (keys bytewise sorted, JS string escaping) -/
def hex4 (n : Nat) : String :=
  let d := "0123456789abcdef".toList.toArray
  String.mk [d[(n / 4096) % 16]!, d[(n / 256) % 16]!, d[(n / 16) % 16]!, d[n % 16]!]
def jsString (s : String) : String := Id.run do
  let mut out := "\""
  for c in s.toList do
    if c == '"' then out := out ++ "\\\""
    else if c == '\\' then out := out ++ "\\\\"
    else if c.toNat == 8 then out := out ++ "\\b"
    else if c.toNat == 12 then out := out ++ "\\f"
    else if c.toNat == 10 then out := out ++ "\\n"
    else if c.toNat == 13 then out := out ++ "\\r"
    else if c.toNat == 9 then out := out ++ "\\t"
    else if c.toNat < 32 then out := out ++ "\\u" ++ hex4 c.toNat
    else out := out.push c
  return out ++ "\""

/-- returns none if unsupported number / (strict) a violation. -/
partial def canon (v : J) (strict : Bool) (depth : Nat) : Option String :=
  match v with
  | .null => some "null"
  | .bool true => some "true"
  | .bool false => some "false"
  | .str s => some (jsString s)
  | .num lex =>
    let c := classify lex
    match c with
    | .other => none
    | _ => if strict && numberOk c != some true then none else
           (match c with | .int i => some (toString i) | .dec l => some l | .other => none)
  | .arr xs =>
    if strict && depth > MAX_DEPTH then none else
    let parts := xs.toList.map (fun x => canon x strict (depth + 1))
    if parts.any Option.isNone then none else
    some ("[" ++ ",".intercalate (parts.map Option.get!) ++ "]")
  | .obj kvs =>
    if strict && depth > MAX_DEPTH then none else
    let sorted := kvs.qsort (fun a b => a.1 < b.1)
    let parts := sorted.toList.map (fun (k, x) => (canon x strict (depth + 1)).map (fun s => jsString k ++ ":" ++ s))
    if parts.any Option.isNone then none else
    some ("{" ++ ",".intercalate (parts.map Option.get!) ++ "}")

def canonLenient (v : J) : String := (canon v false 1).getD "\u0000UNSUPPORTED"
def canonStrict (v : J) : Option String := canon v true 1
def hashCanon (v : J) : String := String.fromUTF8! (b64Encode (sha256 (canonLenient v).toUTF8))

/-! ### parser -/
structure St where (b : ByteArray) (strict : Bool)

def isWs (c : UInt8) : Bool := c == 32 || c == 9 || c == 10 || c == 13
partial def skipWs (s : St) (i : Nat) : Nat := if h : i < s.b.size then (if isWs s.b[i] then skipWs s (i+1) else i) else i
def peek (s : St) (i : Nat) : Option UInt8 := if i < s.b.size then some (s.b.get! i) else none
def hexVal (c : UInt8) : Option Nat :=
  if 48 <= c && c <= 57 then some (c - 48).toNat else if 97 <= c && c <= 102 then some ((c - 97).toNat + 10)
  else if 65 <= c && c <= 70 then some ((c - 65).toNat + 10) else none
def hex4At (s : St) (i : Nat) : Option Nat := do   -- i points at 'u'
  let a ← hexVal (← peek s (i+1)); let b ← hexVal (← peek s (i+2)); let c ← hexVal (← peek s (i+3)); let d ← hexVal (← peek s (i+4))
  pure (a * 4096 + b * 256 + c * 16 + d)

partial def parseString (s : St) (i0 : Nat) : Except String (String × Nat) := do
  let mut i := i0 + 1
  let mut out := ByteArray.empty
  repeat
    match peek s i with
    | none => throw "unterminated string"
    | some c =>
      if c == 34 then
        i := i + 1
        match String.fromUTF8? out with
        | some str => return (str, i)
        | none => throw "invalid UTF-8"
      else if c < 32 && s.strict then throw "raw control character in string"
      else if c == 92 then
        i := i + 1
        match peek s i with
        | none => throw "unterminated string"
        | some e =>
          if e == 34 then out := out.push 34
          else if e == 92 then out := out.push 92
          else if e == 47 then out := out.push 47
          else if e == 98 then out := out.push 8
          else if e == 102 then out := out.push 12
          else if e == 110 then out := out.push 10
          else if e == 114 then out := out.push 13
          else if e == 116 then out := out.push 9
          else if e == 117 then
            let some hi := hex4At s i | throw "bad \\u escape"
            i := i + 4
            let mut cp := hi
            let mut lone := false
            if 0xD800 ≤ hi && hi ≤ 0xDBFF then
              if peek s (i+1) == some 92 && peek s (i+2) == some 117 then
                let some lo := hex4At s (i+2) | throw "bad \\u escape"
                i := i + 6
                if !(0xDC00 ≤ lo && lo ≤ 0xDFFF) then lone := true
                else cp := 0x10000 + ((hi - 0xD800) * 1024) + (lo - 0xDC00)
              else lone := true
            else if 0xDC00 ≤ hi && hi ≤ 0xDFFF then lone := true
            if lone then
              if s.strict then throw "lone surrogate in string"
              else out := out ++ (String.singleton SENTINEL).toUTF8
            else out := out ++ (String.singleton (Char.ofNat cp)).toUTF8
          else throw "unknown escape"
          i := i + 1
      else
        out := out.push c
        i := i + 1
  throw "unreachable"

def parseNumber (s : St) (i0 : Nat) : Except String (J × Nat) := do
  let mut i := i0
  if peek s i == some 45 then i := i + 1
  let isD := fun (o : Option UInt8) => match o with | some c => 48 <= c && c <= 57 | none => false
  match peek s i with
  | some 48 => i := i + 1
  | some c => if 49 <= c && c <= 57 then
                while isD (peek s i) do i := i + 1
              else throw "bad number"
  | none => throw "bad number"
  let mut frac := false
  if peek s i == some 46 then
    i := i + 1
    if !isD (peek s i) then throw "bad number"
    while isD (peek s i) do i := i + 1
    frac := true
  let mut exp := false
  if peek s i == some 101 || peek s i == some 69 then
    if s.strict then throw "exponent form is not allowed"
    exp := true
    i := i + 1
    if peek s i == some 43 || peek s i == some 45 then i := i + 1
    if !isD (peek s i) then throw "bad number"
    while isD (peek s i) do i := i + 1
  let lex := String.fromUTF8! (s.b.extract i0 i)
  if s.strict then
    if lex == "-0" then throw "negative zero"
    if frac then
      if lex.endsWith "0" then throw "trailing fractional zero"
      let digs := (lex.replace "-" "").replace "." ""
      if (digs.dropWhile (· == '0')).toString.length > 15 then throw "more than 15 significant digits"
      let ip := (lex.splitOn ".")[0]!; let fp := (lex.splitOn ".")[1]!
      if (ip == "0" || ip == "-0") && fp.startsWith "000000" then throw "below 1e-6"
    else
      let a := if lex.startsWith "-" then (lex.drop 1).toString else lex
      if a.length > 16 then throw "integer outside the safe range"
      if a.toNat! > MAX_SAFE then throw "integer outside the safe range"
  return (J.num lex, i)

partial def parseValue (s : St) (i0 : Nat) (depth : Nat) : Except String (J × Nat) := do
  let i := skipWs s i0
  match peek s i with
  | none => throw "unexpected end of input"
  | some c =>
    if c == 123 then   -- {
      if depth > MAX_DEPTH && s.strict then throw "nesting too deep"
      let mut j := skipWs s (i + 1)
      if peek s j == some 125 then return (J.obj #[], j + 1)
      let mut kvs : Array (String × J) := #[]
      repeat
        j := skipWs s j
        if peek s j != some 34 then throw "expected a string key"
        let (k, j1) ← parseString s j
        if s.strict && kvs.any (fun p => p.1 == k) then throw "duplicate key"
        j := skipWs s j1
        if peek s j != some 58 then throw "expected :"
        let (v, j2) ← parseValue s (j + 1) (depth + 1)
        kvs := kvs.push (k, v)
        j := skipWs s j2
        match peek s j with
        | some 44 => j := j + 1
        | some 125 => return (J.obj kvs, j + 1)
        | _ => throw "expected , or }"
      throw "unreachable"
    else if c == 91 then   -- [
      if depth > MAX_DEPTH && s.strict then throw "nesting too deep"
      let mut j := skipWs s (i + 1)
      if peek s j == some 93 then return (J.arr #[], j + 1)
      let mut xs : Array J := #[]
      repeat
        let (v, j1) ← parseValue s j (depth + 1)
        xs := xs.push v
        j := skipWs s j1
        match peek s j with
        | some 44 => j := j + 1
        | some 93 => return (J.arr xs, j + 1)
        | _ => throw "expected , or ]"
      throw "unreachable"
    else if c == 34 then
      let (str, j) ← parseString s i
      return (J.str str, j)
    else if c == 45 || (48 ≤ c && c ≤ 57) then parseNumber s i
    else
      let rest := s.b.extract i (i + 5)
      let starts := fun (lit : String) => rest.extract 0 lit.length == lit.toUTF8
      if starts "true" then return (J.bool true, i + 4)
      else if starts "false" then return (J.bool false, i + 5)
      else if starts "null" then return (J.null, i + 4)
      else throw "unexpected token"

def parseText (text : String) (strict : Bool) : Except String J := do
  let b := text.toUTF8
  if strict && b.size > MAX_CHARS then throw "input too large"
  let s : St := ⟨b, strict⟩
  let (v, i) ← parseValue s 0 1
  let i := skipWs s i
  if i < b.size then throw "trailing characters after the JSON value"
  return v

end PcaRef

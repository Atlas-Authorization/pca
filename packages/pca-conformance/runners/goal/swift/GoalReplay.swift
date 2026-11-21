// Swift runner for the pca-goal vectors (goals and selector goals): goal digest, lowered policy digest, decision + witness of every
// probe, the fn vectors, and the native expansion of the trait selectors for `sel` vectors. Independent port of the reference
// semantics (adversarial/src/oracle.ts). SHA-256 from CryptoKit (macOS) or swift-crypto (Linux: `import Crypto`, add the package).
// Build: swiftc -O GoalReplay.swift main.swift -o goal-runner ; run: ./goal-runner <vectors-dir>
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

indirect enum J {
    case null, bool(Bool), int(Int), str(String), arr([J]), obj([String: J])
    var s: String { if case .str(let x) = self { return x }; return "" }
    var n: Int { if case .int(let x) = self { return x }; return 0 }
    var a: [J] { if case .arr(let x) = self { return x }; return [] }
    var o: [String: J] { if case .obj(let x) = self { return x }; return [:] }
    var isNull: Bool { if case .null = self { return true }; return false }
    var isTrue: Bool { if case .bool(true) = self { return true }; return false }
    subscript(_ k: String) -> J { o[k] ?? .null }
    func has(_ k: String) -> Bool { o[k] != nil }
}
func O(_ kv: KeyValuePairs<String, J>) -> J { var m = [String: J](); for (k, v) in kv { m[k] = v }; return .obj(m) }
func S(_ s: String) -> J { .str(s) }
func ls(_ xs: [String]) -> J { .arr(xs.map { .str($0) }) }

// ---------------------------------------------------------------- JSON parser
struct Parser {
    let b: [UInt8]; var i = 0
    init(_ d: Data) { b = [UInt8](d) }
    mutating func ws() { while i < b.count, b[i] == 32 || b[i] == 10 || b[i] == 13 || b[i] == 9 { i += 1 } }
    mutating func val() -> J {
        ws()
        let c = b[i]
        if c == UInt8(ascii: "{") {
            i += 1; var m = [String: J](); ws()
            if b[i] == UInt8(ascii: "}") { i += 1; return .obj(m) }
            while true { ws(); let k = str(); ws(); i += 1; m[k] = val(); ws(); let d = b[i]; i += 1; if d == UInt8(ascii: "}") { return .obj(m) } }
        }
        if c == UInt8(ascii: "[") {
            i += 1; var l = [J](); ws()
            if b[i] == UInt8(ascii: "]") { i += 1; return .arr(l) }
            while true { l.append(val()); ws(); let d = b[i]; i += 1; if d == UInt8(ascii: "]") { return .arr(l) } }
        }
        if c == UInt8(ascii: "\"") { return .str(str()) }
        if b[i...].starts(with: Array("true".utf8)) { i += 4; return .bool(true) }
        if b[i...].starts(with: Array("false".utf8)) { i += 5; return .bool(false) }
        if b[i...].starts(with: Array("null".utf8)) { i += 4; return .null }
        var j = i; while j < b.count, b[j] == UInt8(ascii: "-") || (b[j] >= 48 && b[j] <= 57) { j += 1 }
        let n = Int(String(decoding: b[i..<j], as: UTF8.self))!; i = j; return .int(n)
    }
    mutating func str() -> String {
        i += 1; var out = [UInt8]()
        while true {
            let c = b[i]; i += 1
            if c == UInt8(ascii: "\"") { return String(decoding: out, as: UTF8.self) }
            if c != UInt8(ascii: "\\") { out.append(c); continue }
            let e = b[i]; i += 1
            switch e {
            case UInt8(ascii: "n"): out.append(10)
            case UInt8(ascii: "t"): out.append(9)
            case UInt8(ascii: "r"): out.append(13)
            case UInt8(ascii: "b"): out.append(8)
            case UInt8(ascii: "f"): out.append(12)
            case UInt8(ascii: "u"):
                var cp = UInt32(String(decoding: b[i..<i + 4], as: UTF8.self), radix: 16)!; i += 4
                if cp >= 0xD800 && cp < 0xDC00, b[i] == UInt8(ascii: "\\"), b[i + 1] == UInt8(ascii: "u") {
                    let lo = UInt32(String(decoding: b[i + 2..<i + 6], as: UTF8.self), radix: 16)!; i += 6
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                }
                out.append(contentsOf: Array(String(Character(Unicode.Scalar(cp)!)).utf8))
            default: out.append(e)
            }
        }
    }
}

// ---------------------------------------------------------------- canonical JSON / digests
func bytesLess(_ a: String, _ b: String) -> Bool { Array(a.utf8).lexicographicallyPrecedes(Array(b.utf8)) }
func canon(_ v: J) -> String {
    switch v {
    case .null: return "null"
    case .bool(let b): return b ? "true" : "false"
    case .int(let n): return String(n)
    case .str(let s):
        var o = "\""
        for u in s.unicodeScalars {
            switch u.value {
            case 0x22: o += "\\\""
            case 0x5C: o += "\\\\"
            case 8: o += "\\b"
            case 9: o += "\\t"
            case 10: o += "\\n"
            case 12: o += "\\f"
            case 13: o += "\\r"
            case 0..<0x20: o += String(format: "\\u%04x", u.value)
            default: o.unicodeScalars.append(u)
            }
        }
        return o + "\""
    case .arr(let l): return "[" + l.map(canon).joined(separator: ",") + "]"
    case .obj(let m): return "{" + m.keys.sorted(by: bytesLess).map { canon(.str($0)) + ":" + canon(m[$0]!) }.joined(separator: ",") + "}"
    }
}
func b64(_ d: Data) -> String { d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
func sha(_ s: String) -> Data { Data(SHA256.hash(data: Data(s.utf8))) }
func hashCanon(_ v: J) -> String { b64(sha(canon(v))) }
func goalDigest(_ g: J) -> String { hashCanon(O(["d": S("atlas-pca/goal-ir/v1"), "goal": g])) }

// ---------------------------------------------------------------- semantics
func kNot(_ a: Int) -> Int { 2 - a }
func b2k(_ b: Bool) -> Int { b ? 2 : 0 }
func sameUnit(_ a: J, _ b: J) -> Bool { canon(a) == canon(b) }
func eqV(_ x: J, _ y: J) -> Int {
    if x["k"].s == "q" { return y["k"].s == "q" && sameUnit(x["q"]["u"], y["q"]["u"]) ? b2k(x["q"]["n"].n == y["q"]["n"].n) : 1 }
    if x["k"].s == "s" { return y["k"].s == "s" ? b2k(ceq(x["s"].s, y["s"].s)) : 1 }
    return 1
}
func ltV(_ x: J, _ y: J) -> Int { x["k"].s == "q" && y["k"].s == "q" && sameUnit(x["q"]["u"], y["q"]["u"]) ? b2k(x["q"]["n"].n < y["q"]["n"].n) : 1 }
func cmpV(_ op: String, _ x: J?, _ y: J?) -> Int {
    guard let x = x, let y = y else { return 1 }
    switch op {
    case "eq": return eqV(x, y)
    case "ne": return kNot(eqV(x, y))
    case "lt": return ltV(x, y)
    case "gte": return kNot(ltV(x, y))
    case "gt": return ltV(y, x)
    case "lte": return kNot(ltV(y, x))
    default: break
    }
    var t = 1
    if y["k"].s == "set" { t = 0; for it in y["items"].a { t = max(t, eqV(x, it)) } }
    return op == "in" ? t : kNot(t)
}
func term(_ t: J, _ a: J, _ h: J) -> J? {
    switch t["k"].s {
    case "param": return a["params"].o[t["path"].s]
    case "lit": return t["v"]
    default: if let q = h["aggs"].o[t["bid"].s] { return O(["k": S("q"), "q": q]) }; return nil
    }
}
func cond(_ c: J, _ a: J, _ h: J) -> Int {
    switch c["k"].s {
    case "true": return 2
    case "cmp": return cmpV(c["op"].s, term(c["l"], a, h), term(c["r"], a, h))
    case "and": return min(cond(c["a"], a, h), cond(c["b"], a, h))
    case "or": return max(cond(c["a"], a, h), cond(c["b"], a, h))
    default: return kNot(cond(c["c"], a, h))
    }
}
/// Swift's String == is canonical equivalence (NFC == NFD); the IR compares code points, so every comparison goes through ceq.
func ceq(_ a: String, _ b: String) -> Bool { a.utf8.elementsEqual(b.utf8) }
func has(_ l: [J], _ x: J) -> Bool { let cx = canon(x); return l.contains { ceq(canon($0), cx) } }
func partIds(_ o: J, _ p: J) -> [J] {
    switch p["k"].s {
    case "exact": return [p["id"]]
    case "oneof": return p["ids"].a
    default:
        for r in o["rels"].a where ceq(r["rel"].s, p["rel"].s) && ceq(r["anchor"].s, p["anchor"].s) { return r["members"].a }
        return []
    }
}
func resolveRes(_ o: J, _ s: J) -> [J]? {
    if s["k"].s == "any" { return nil }
    if s["k"].s != "all_of" { return partIds(o, s) }
    var acc: [J]? = nil
    for p in s["parts"].a.reversed() { let ids = partIds(o, p); if let a = acc { acc = ids.filter { has(a, $0) } } else { acc = ids } }
    return acc
}
func resOk(_ p: [J]?, _ r: J) -> Bool { p == nil || has(p!, r) }
func verbsOfClass(_ o: J, _ cls: String) -> [J] { o["verbs"].a.filter { $0["cls"].s == cls }.map { $0["verb"] } }
func prohVerbs(_ o: J, _ p: J) -> [J] { p["target"]["k"].s == "verb" ? [p["target"]["verb"]] : verbsOfClass(o, p["target"]["cls"].s) }
func lsel(_ o: J, _ b: J) -> ([J], [J]) { b["sel"]["k"].s == "gids" ? (b["sel"]["gids"].a, []) : ([], verbsOfClass(o, b["sel"]["cls"].s)) }
func applies(_ s: ([J], [J]), _ gid: J, _ verb: J) -> Bool { has(s.0, gid) || has(s.1, verb) }
func inScope(_ b: J, _ a: J, _ x: J) -> Bool {
    let s = b["scope"]
    switch s["k"].s {
    case "session": return ceq(a["sess"].s, x["sess"].s)
    case "principal": return ceq(a["prin"].s, x["prin"].s)
    case "org": return ceq(a["org"].s, x["org"].s)
    default: return has(s["agents"].a, a["agent"]) && has(s["agents"].a, x["agent"])
    }
}
func floorDiv(_ a: Int, _ b: Int) -> Int { let q = a / b; return (a % b != 0 && ((a < 0) != (b < 0))) ? q - 1 : q }
func inWindow(_ w: J, _ a: J, _ x: J) -> Bool {
    let at = a["t"].n, xt = x["t"].n
    switch w["k"].s {
    case "sliding": return at - w["ms"].n < xt && xt <= at
    case "period": return w["ms"].n > 0 && floorDiv(at - w["t0"].n, w["ms"].n) == floorDiv(xt - w["t0"].n, w["ms"].n)
    default: return true
    }
}
func exceeded(_ b: J, _ s: ([J], [J]), _ a: J, _ h: J) -> Int {
    var items = [J]()
    for m in h["adms"].a { let act = m["act"]; if applies(s, m["gid"], act["verb"]) && inScope(b, a, act) && inWindow(b["window"], a, act) { items.append(act) } }
    items.append(a)
    let cap = b["cap"]["n"].n
    switch b["agg"].s {
    case "count": return b2k(items.count > cap)
    case "distinct":
        var vs = Set<String>()
        for x in items { if !x["params"].has(b["key"].s) { return 1 }; vs.insert(canon(x["params"][b["key"].s])) }
        return b2k(vs.count > cap)
    default:
        var ns = [Int]()
        for x in items {
            guard let v = term(b["value"], x, h), v["k"].s == "q", sameUnit(v["q"]["u"], b["cap"]["u"]) else { return 1 }
            ns.append(v["q"]["n"].n)
        }
        return b2k((b["agg"].s == "sum" ? ns.reduce(0, +) : ns.max()!) > cap)
    }
}
func boundDec(_ b: J, _ s: ([J], [J]), _ a: J, _ h: J) -> Int { let e = exceeded(b, s, a, h); return e == 2 ? (b["onExceed"].s == "deny" ? 0 : 1) : (e == 1 ? 1 : 2) }
func stripHoles(_ g: J) -> J {
    var m = g.o
    m["holes"] = .arr([])
    m["grants"] = .arr(g["grants"].a.filter { x in !g["holes"].a.contains { $0["global"].isTrue || has($0["affects"].a, x["gid"]) } })
    return .obj(m)
}
func grantDec(_ g: J, _ o: J, _ gr: J, _ a: J, _ h: J) -> Int {
    let delegOk = a["depth"].n == 0 || has(g["deleg"]["mayTouch"].a, gr["gid"])
    var m = min(b2k(ceq(a["verb"].s, gr["verb"].s) && delegOk), min(b2k(resOk(resolveRes(o, gr["res"]), a["res"])), cond(gr["cond"], a, h)))
    for b in g["bounds"].a { let s = lsel(o, b); if applies(s, gr["gid"], a["verb"]) { m = min(m, boundDec(b, s, a, h)) } }
    return m
}
func decide(_ goal: J, _ o: J, _ a: J, _ h: J) -> J {
    let g = stripHoles(goal); let v = g["validity"]; let t = a["t"].n
    var d = 2
    if t < v["notBefore"].n || t > v["notAfter"].n { d = 0 }
    else if v["maxIdle"].n > 0 && h["last"].n >= 0 && t - h["last"].n > v["maxIdle"].n { d = 0 }
    else if a["depth"].n < 0 || a["depth"].n > g["deleg"]["maxDepth"].n { d = 0 }
    for p in g["prohibits"].a {
        let m = min(b2k(has(prohVerbs(o, p), a["verb"])), min(b2k(resOk(resolveRes(o, p["res"]), a["res"])), cond(p["cond"], a, h)))
        d = min(d, m == 2 ? 0 : (m == 1 ? 1 : 2))
    }
    for c in g["escalateOn"].a { d = min(d, cond(c, a, h) == 0 ? 2 : 1) }
    let per = g["grants"].a.map { grantDec(g, o, $0, a, h) }
    d = min(d, per.max() ?? 0)
    if d != 2 { return O(["decision": S(d == 1 ? "escalate" : "deny"), "witness": .null]) }
    let gr = g["grants"].a[per.firstIndex(of: 2)!]
    let bids = g["bounds"].a.filter { applies(lsel(o, $0), gr["gid"], a["verb"]) }.map { $0["bid"] }
    return O(["decision": S("allow"), "witness": O(["gid": gr["gid"], "bids": .arr(bids)])])
}
let NEG = ["eq": "ne", "ne": "eq", "lt": "gte", "gte": "lt", "gt": "lte", "lte": "gt", "in": "nin", "nin": "in"]
func nnf(_ c: J, _ pos: Bool) -> J {
    switch c["k"].s {
    case "true": return O(["k": S(pos ? "true" : "false")])
    case "cmp": return O(["k": S("atom"), "op": S(pos ? c["op"].s : NEG[c["op"].s]!), "l": c["l"], "r": c["r"]])
    case "and": return O(["k": S(pos ? "and" : "or"), "a": nnf(c["a"], pos), "b": nnf(c["b"], pos)])
    case "or": return O(["k": S(pos ? "or" : "and"), "a": nnf(c["a"], pos), "b": nnf(c["b"], pos)])
    default: return nnf(c["c"], !pos)
    }
}
func pat(_ p: [J]?) -> J { p == nil ? O(["k": S("star")]) : O(["k": S("set"), "ids": .arr(p!)]) }
func lower(_ o: J, _ goal: J) -> J {
    let g = stripHoles(goal)
    let ceils: [J] = g["bounds"].a.map { b in let s = lsel(o, b); return O(["bid": b["bid"], "selGids": .arr(s.0), "selVerbs": .arr(s.1), "agg": b["agg"], "value": b["value"], "key": b["key"], "window": b["window"], "scope": b["scope"], "cap": b["cap"], "onExceed": b["onExceed"]]) }
    return O(["preds": .arr(g["grants"].a.map { O(["gid": $0["gid"], "verb": $0["verb"], "res": pat(resolveRes(o, $0["res"])), "cond": nnf($0["cond"], true)]) }),
              "prohs": .arr(g["prohibits"].a.map { O(["pid": $0["pid"], "verbs": .arr(prohVerbs(o, $0)), "res": pat(resolveRes(o, $0["res"])), "cond": nnf($0["cond"], true)]) }),
              "ceils": .arr(ceils), "escs": .arr(g["escalateOn"].a.map { nnf($0, true) }), "validity": g["validity"], "deleg": g["deleg"]])
}

// ---------------------------------------------------------------- selector expansion (pca-goal selectors.ts / GoalSelect.dfy)
/// An unconfirmed verb carries pca.unreviewed (it is the top of the registry): a class ALLOW never covers it (float == false), a class PROHIBITION or bound over a trait selector ALWAYS covers it, whatever all_of and none_of say (float == true).
func classVerbs(_ cat: J, _ all: [J], _ none: [J], float: Bool) -> [J] {
    cat["verbs"].a.filter { v in
        let ts = v["traits"].a
        let unrev = ts.contains { $0.s == "pca.unreviewed" }
        let inClass = all.allSatisfy { has(ts, $0) } && none.allSatisfy { !has(ts, $0) }
        return float ? (unrev || inClass) : (inClass && !unrev)
    }.map { $0["verb"] }
}
func resolveRole(_ ont: J, _ cat: J, _ verb: String, _ role: String) -> (J, J)? {
    guard let info = cat["verbs"].a.first(where: { $0["verb"].s == verb }), let decl = ont["verbs"].a.first(where: { $0["verb"].s == verb }) else { return nil }
    let paths = info["roles"][role].a
    guard paths.count == 1, let p = decl["params"].a.first(where: { $0["path"].s == paths[0].s }) else { return nil }
    return (p["path"], p["ty"])
}
func xTerm(_ ont: J, _ cat: J, _ verb: String, _ t: J) -> J? {
    if t["k"].s != "role" { return t }
    guard let r = resolveRole(ont, cat, verb, t["role"].s) else { return nil }
    return O(["k": S("param"), "path": r.0, "ty": r.1])
}
func xCond(_ ont: J, _ cat: J, _ verb: String, _ c: J) -> J? {
    switch c["k"].s {
    case "true": return O(["k": S("true")])
    case "cmp":
        guard let l = xTerm(ont, cat, verb, c["l"]), let r = xTerm(ont, cat, verb, c["r"]) else { return nil }
        return O(["k": S("cmp"), "op": c["op"], "l": l, "r": r])
    case "and", "or":
        guard let a = xCond(ont, cat, verb, c["a"]), let b = xCond(ont, cat, verb, c["b"]) else { return nil }
        return O(["k": c["k"], "a": a, "b": b])
    default:
        guard let a = xCond(ont, cat, verb, c["c"]) else { return nil }
        return O(["k": S("not"), "c": a])
    }
}
func boundValue(_ ont: J, _ cat: J, _ vs: [J], _ t: J) -> J? {
    if t["k"].s != "role" { return t }
    var rs = [(J, J)]()
    for v in vs { guard let r = resolveRole(ont, cat, v.s, t["role"].s) else { return nil }; rs.append(r) }
    guard let f = rs.first else { return nil }
    if rs.allSatisfy({ $0.0.s == f.0.s && ceq(canon($0.1), canon(f.1)) }) { return O(["k": S("param"), "path": f.0, "ty": f.1]) }
    if rs.allSatisfy({ ceq(canon($0.1), canon(f.1)) }) { return O(["k": S("param"), "path": S("@" + t["role"].s), "ty": f.1]) }
    return nil
}
func expandSel(_ sg: J, _ ont: J, _ cat: J) -> J {
    var es = [(J, J)]()
    for gr in sg["grants"].a {
        let s = gr["sel"]
        let verbs = s["k"].s == "verb" ? [s["verb"]] : classVerbs(cat, s["all_of"].a, s["none_of"].a, float: false)
        for v in verbs {
            guard let c = xCond(ont, cat, v.s, gr["cond"]) else { continue }
            es.append((gr["gid"], O(["gid": s["k"].s == "class" ? S(gr["gid"].s + "." + v.s) : gr["gid"], "verb": v, "res": gr["res"], "cond": c])))
        }
    }
    func idsOf(_ srcs: [J]) -> [J] { es.filter { has(srcs, $0.0) }.map { $0.1["gid"] } }
    func gidsOfVerbs(_ vs: [J]) -> [J] { es.filter { has(vs, $0.1["verb"]) }.map { $0.1["gid"] } }
    func verbsOfGids(_ g: [J]) -> [J] { es.filter { has(g, $0.1["gid"]) }.map { $0.1["verb"] } }
    var prohibits = [J]()
    for p in sg["prohibits"].a {
        let t = p["target"]; let tk = t["k"].s
        let verbs = tk == "verb" ? [t["verb"]] : tk == "effect" ? verbsOfClass(ont, t["cls"].s) : classVerbs(cat, t["all_of"].a, t["none_of"].a, float: true)
        for v in verbs {
            let c = xCond(ont, cat, v.s, p["cond"]) ?? O(["k": S("true")])
            prohibits.append(O(["pid": tk == "verb" ? p["pid"] : S(p["pid"].s + "." + v.s), "target": O(["k": S("verb"), "verb": v]), "res": p["res"], "cond": c]))
        }
    }
    var bounds = [J]()
    for b in sg["bounds"].a {
        let s = b["sel"]; let sk = s["k"].s
        var gids: [J]?; var rv: [J]
        if sk == "gids" { let g = idsOf(s["gids"].a); gids = g; rv = verbsOfGids(g) }
        else if sk == "effect" { gids = nil; rv = verbsOfClass(ont, s["cls"].s) }
        else { let g = gidsOfVerbs(classVerbs(cat, s["all_of"].a, s["none_of"].a, float: true)); gids = g; rv = verbsOfGids(g) }
        guard let val = boundValue(ont, cat, rv, b["value"]) else { continue }
        if let g = gids, g.isEmpty { continue }
        let sel = gids == nil ? O(["k": S("effect"), "cls": s["cls"]]) : O(["k": S("gids"), "gids": .arr(gids!)])
        bounds.append(O(["bid": b["bid"], "sel": sel, "agg": b["agg"], "value": val, "key": b["key"], "window": b["window"], "scope": b["scope"], "cap": b["cap"], "onExceed": b["onExceed"]]))
    }
    var deleg = sg["deleg"].o; deleg["mayTouch"] = .arr(idsOf(sg["deleg"]["mayTouch"].a))
    let holes: [J] = sg["holes"].a.map { h in var m = h.o; m["affects"] = .arr(idsOf(h["affects"].a)); return .obj(m) }
    return O(["v": .int(1), "principal": sg["principal"], "ontDigest": sg["ontDigest"], "nlDigest": sg["nlDigest"], "sources": sg["sources"],
              "grants": .arr(es.map { $0.1 }), "prohibits": .arr(prohibits), "bounds": .arr(bounds), "validity": sg["validity"], "deleg": .obj(deleg),
              "escalateOn": sg["escalateOn"], "wildcardAck": .arr(idsOf(sg["wildcardAck"].a)), "holes": .arr(holes)])
}

// ---------------------------------------------------------------- fn vectors
let RANK = ["deny": 0, "escalate": 1, "allow": 2]
func meet(_ d: String, _ s: String) -> String { if let r = RANK[s], r < RANK[d]! { return s }; return d }
func walk(_ c: J, _ out: inout Set<String>) {
    switch c["k"].s {
    case "and", "or": walk(c["a"], &out); walk(c["b"], &out)
    case "not": walk(c["c"], &out)
    case "cmp":
        for k in ["l", "r"] { let t = c[k]; if t["k"].s == "param" { for p in ["env.class.", "env.prov.", "env.judge.", "env.world."] where t["path"].s.hasPrefix(p) { out.insert(t["path"].s) } } }
    default: break
    }
}
func runFn(_ v: J) -> J {
    let i = v["input"]
    switch v["fn"].s {
    case "canon": return O(["canon": S(canon(i)), "digest": S(goalDigest(i))])
    case "units":
        let sc = i["schema"], tm = i["terms"]
        return ls(tm.o.keys.filter { !sc.has($0) || canon(sc[$0]) != canon(tm[$0]) }.sorted(by: bytesLess))
    case "polarity": var o = Set<String>(); for w in i.a { walk(w, &o) }; return ls(o.sorted(by: bytesLess))
    case "meet": return S(meet(i["decision"].s, i["signal"].s))
    case "pep":
        let d = i["decision"].s
        if d == "allow" { return .bool(true) }
        if d == "deny" { return .bool(false) }
        let ans = i["answer"], ctx = i["ctx"]
        if ans.isNull || !ans["valid"].isTrue { return .bool(false) }
        for k in ["policy_digest", "action_digest", "history_head"] where ans[k].s != ctx[k].s { return .bool(false) }
        return .bool(true)
    case "commit": return O(["commit": S(b64(sha("pca-goal:v3:commit:\(i["goal_digest"].s):\(i["policy_digest"].s):\(i["salt"].s)"))), "opens_other_goal": .bool(false)])
    case "claim": let rp = i["replayed_ppm"]; return !rp.isNull && rp.n < i["min_ppm"].n ? S(meet(i["base"].s, "escalate")) : i["base"]
    default: fatalError("unknown fn")
    }
}

/// Replays every vector of a directory: (vectors, probes, disagreements).
func goalReplay(_ dir: String) throws -> (Int, Int, [String]) {
    let names = try FileManager.default.contentsOfDirectory(atPath: dir).filter { $0.hasSuffix(".json") && $0 != "index.json" }.sorted()
    var bad = [String](); var probes = 0
    for n in names {
        var p = Parser(try Data(contentsOf: URL(fileURLWithPath: dir + "/" + n)))
        let v = p.val(); let id = v["id"].s
        if v["kind"].s == "fn" { if !ceq(canon(runFn(v)), canon(v["expect"])) { bad.append(id) }; continue }
        let goal = v["goal"], ont = v["ontology"]
        if v.has("sel"), !ceq(canon(expandSel(v["sel"]["goal"], ont, v["sel"]["catalog"])), canon(goal)) { bad.append(id + ":expansion") }
        if goalDigest(goal) != v["goal_digest"].s { bad.append(id + ":goal_digest") }
        if !v["compile"]["ok"].isTrue { continue }
        if hashCanon(lower(ont, goal)) != v["policy_digest"].s { bad.append(id + ":policy_digest") }
        for (i, pr) in v["probes"].a.enumerated() {
            probes += 1
            if !ceq(canon(decide(goal, ont, pr["action"], pr["history"])), canon(pr["expect"])) { bad.append("\(id)#\(i)") }
        }
    }
    return (names.count, probes, bad)
}

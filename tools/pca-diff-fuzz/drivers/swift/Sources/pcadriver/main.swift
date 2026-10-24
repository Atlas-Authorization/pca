// Swift differential driver (wire format v2). Same line protocol as the Go / Rust / Java drivers:
//   pcadriver <corpus.jsonl> <out.jsonl>
// suites : the capability manifest PCASuites.supported (runtime: ML-DSA needs CryptoKit on a 26 OS, or liboqs on Linux)
// verify : PCA.verify(json: raw, grant: lenient, now, audience: aud, allowed_suites?, intent_policy_json? | intent_policy?,
//          intent_v2?) (strict parse failure == wire failure); a verdict whose reason carries `unsupported_suite` is tagged
// chain  : Capability.verifyChain(chain, expected_root_issuer?, allowed_suites?, pq_pins?, trusted_root?)
// canon  : strict parse + canonicalizeStrict + hashCanonical of ANY JSON text
// intent_*: an Intent Layer v2 primitive (raw = its `input_json` when the vector carries one, else its `input` as JSON text,
//          parsed with the SDK's own parser so a negative zero survives); `result` in the `expect` shape, `reason` when refused
//
// Swift strings cannot hold a lone UTF-16 surrogate. A line whose JSON escapes one is read with the scalar U+FDD0 in its place
// (as the conformance tests do); a `raw` that needed it is a lone surrogate in the artifact, which every strict verifier refuses.
import Foundation
@testable import AtlasPCAVerify

let SENTINEL = Canonical.LONE_SURROGATE_SENTINEL

/// Replace each lone `\uD800`-`\uDFFF` escape inside a JSON string with the sentinel; report whether anything was replaced.
func sanitizeLoneSurrogates(_ bs: [UInt8]) -> (String, Bool) {
    let sentinel = Array(String(SENTINEL).utf8)
    func hex(_ at: Int) -> UInt32? {
        guard at + 4 <= bs.count else { return nil }
        var v: UInt32 = 0
        for k in 0..<4 {
            let c = UInt32(bs[at + k])
            switch c {
            case 48...57: v = (v << 4) | (c - 48)
            case 97...102: v = (v << 4) | (c - 87)
            case 65...70: v = (v << 4) | (c - 55)
            default: return nil
            }
        }
        return v
    }
    var out = [UInt8](); out.reserveCapacity(bs.count)
    var replaced = false
    var i = 0, inStr = false
    while i < bs.count {
        let c = bs[i]
        if !inStr { inStr = c == 0x22; out.append(c); i += 1; continue }
        if c == 0x22 { inStr = false; out.append(c); i += 1; continue }
        guard c == 0x5c else { out.append(c); i += 1; continue }
        if i + 1 < bs.count, bs[i + 1] == 0x75, let u = hex(i + 2) {
            if (0xD800...0xDBFF).contains(u), i + 11 < bs.count, bs[i + 6] == 0x5c, bs[i + 7] == 0x75,
               let lo = hex(i + 8), (0xDC00...0xDFFF).contains(lo) {
                out.append(contentsOf: bs[i..<(i + 12)]); i += 12
            } else if (0xD800...0xDFFF).contains(u) {
                out.append(contentsOf: sentinel); replaced = true; i += 6
            } else {
                out.append(contentsOf: bs[i..<(i + 6)]); i += 6
            }
        } else {
            out.append(contentsOf: bs[i..<min(i + 2, bs.count)]); i += 2
        }
    }
    return (String(decoding: out, as: UTF8.self), replaced)
}

func strs(_ v: JSONValue?) -> [String]? { v?.asArray.map { $0.map { $0.asString ?? "" } } }
func strArray(_ a: [String]) -> JSONValue { .array(a.map { .string($0) }) }
func checksValue(_ c: [String: Bool]) -> JSONValue { .object(JObject(uniqueKeysWithValues: c.map { (JKey($0.key), .bool($0.value)) })) }

/// One Intent Layer v2 primitive, reported in exactly the shape of its conformance `expect` (+ the refusal reason).
func intentPrimitive(_ kind: String, _ i: JSONValue) -> (JSONValue, String)? {
    switch kind {
    case "intent_schema":
        let r = PCA.intentSchemaPrimitive(schema: i.get("schema") ?? .null, keys: i.get("keys") ?? .null,
                                          verb: i.get("verb")?.asString ?? "", params: i.get("params") ?? .null)
        var conform: JObject = ["ok": .bool(r.conformOk)]
        if let c = r.code { conform["code"] = .string(c) }
        if let p = r.path, !p.isEmpty { conform["path"] = .string(p) }
        var out: JObject = ["sig": .bool(r.sig), "conform": .object(conform)]
        if let d = r.digest { out["digest"] = .string(d) }
        return (.object(out), "")
    case "intent_revocation":
        return (.object(["ok": .bool(PCA.intentRevocationPrimitive(i))]), "")
    case "intent_world":
        let r = PCA.intentWorldPrimitive(i)
        guard r.ok else { return (.object(["ok": .bool(false)]), r.reason) }
        return (.object(["ok": .bool(true), "world": r.world ?? .null, "single_source": strArray(r.singleSource ?? [])]), "")
    case "intent_provenance":
        let r = PCA.intentProvenancePrimitive(i)
        var out: JObject = ["outcome": .string(r.outcome)]
        if r.outcome != "deny" {
            out["labels"] = .object(JObject(uniqueKeysWithValues: r.labels.map { (JKey($0.key), .string($0.value)) }))
            out["classes"] = .object(JObject(uniqueKeysWithValues: r.classes.map { (JKey($0.key), strArray($0.value)) }))
        }
        if r.outcome == "question" { out["friction"] = r.friction.map { .string($0) } ?? .null }
        return (.object(out), r.reason)
    case "intent_classifier":
        let r = PCA.intentClassifierPrimitive(i)
        return r.ok ? (.object(["ok": .bool(true), "classes": r.classes ?? .null]), "") : (.object(["ok": .bool(false)]), r.reason)
    case "intent_wb_active":
        let r = PCA.intentWBActivePrimitive(i)
        return (.object(["facts": .bool(r.facts), "provenance": .bool(r.provenance), "classes": .bool(r.classes)]), "")
    case "intent_read_purpose":
        let r = PCA.intentReadPurposePrimitive(i)
        return (.object(["outcome": .string(r.outcome), "minimise": strArray(r.minimise), "uncovered": strArray(r.uncovered)]), "")
    case "intent_map_commit":
        // rule 19: the map commitment of `leaves` (a malformed leaf entry has none: `{}`)
        guard let c = PCA.intentMapCommitPrimitive(i) else { return (.object([:]), "malformed leaf entry") }
        return (.object(["map_commit": .string(c)]), "")
    case "intent_map":
        let r = PCA.intentMapPrimitive(i)
        guard r.ok else { return (.object(["ok": .bool(false)]), r.reason) }
        return (.object(["ok": .bool(true), "cell": .array(r.cell.map { .int($0) }), "p_ppm": .int(r.pPpm)]), "")
    default:
        return nil
    }
}

func one(_ c: JSONValue, rawHasLoneSurrogate: Bool) -> JObject {
    let kind = c.get("kind")?.asString ?? ""
    let raw = c.get("raw")?.asString ?? ""
    switch kind {
    case "suites":
        // Suite-capability manifest (packages/pca/conformance/SUITES.md), decided at run time.
        return ["suites": strArray(PCASuites.supported)]
    case "verify":
        if rawHasLoneSurrogate { return ["allow": .bool(false), "checks": .object(["wire": .bool(false)])] }
        guard let grantText = c.get("grant")?.asString, let grant = try? StrictJSON.parseLenient(grantText), grant.isObject else {
            return ["error": .string("exception:grant")]
        }
        // Intent Layer M2: raw JSON text `intent_policy_json` (keeps 950000.0 / 1e6 / -0.0) wins over the object `intent_policy`.
        var policy = c.get("intent_policy").flatMap(IntentPolicy.fromJSON)
        if let text = c.get("intent_policy_json")?.asString {
            guard let p = IntentPolicy.fromJSONText(text) else { return ["error": .string("exception:intent_policy_json")] }
            policy = p
        }
        // Intent Layer v2: optional verifier state; absent = none, present but not an object = malformed.
        var v2: IntentV2Context? = nil
        if let x = c.get("intent_v2") {
            guard let ctx = IntentV2Context.fromJSON(x) else { return ["error": .string("exception:intent_v2")] }
            v2 = ctx
        }
        let g = PCA.verify(json: raw, grant: grant, now: c.get("now")?.safeInt ?? 0, audience: c.get("aud")?.asString ?? "",
                           allowedSuites: strs(c.get("allowed_suites")), intentPolicy: policy, intentV2: v2)
        var out: JObject = ["allow": .bool(g.allow), "checks": checksValue(g.checks)]
        if g.reason.contains(PCASuites.unsupportedSuiteReason) { out["unsupported_suite"] = .string(g.reason) }
        return out
    case "chain":
        // R4-01: raw = {chain, expected_root_issuer?, pq_pins?, trusted_root?, allowed_suites?}
        if rawHasLoneSurrogate { return ["allow": .bool(false), "checks": .object(["chain": .bool(false)])] }
        guard let o = try? StrictJSON.parseLenient(raw), o.isObject else { return ["error": .string("exception:chain")] }
        var pins: [String: String]? = nil
        if let m = o.get("pq_pins")?.asObject { pins = Dictionary(uniqueKeysWithValues: m.map { ($0.key.s, $0.value.asString ?? "") }) }
        let why = Capability.verifyChain(o.get("chain")?.asArray ?? [], expectedRootIssuer: o.get("expected_root_issuer")?.asString,
                                         allowedSuites: strs(o.get("allowed_suites")), pqPins: pins, trustedRoot: o.get("trusted_root"))
        var out: JObject = ["allow": .bool(why == nil), "checks": .object(["chain": .bool(why == nil)])]
        if let w = why, w.contains(PCASuites.unsupportedSuiteReason) { out["unsupported_suite"] = .string(w) }
        return out
    case _ where kind.hasPrefix("intent_"):
        // a lone surrogate in the input reaches the primitive as the sentinel scalar, which every v2 rule treats as one
        guard let input = try? StrictJSON.parseLenient(raw),
              let (result, reason) = intentPrimitive(kind, input) else { return ["error": .string("exception:\(kind)")] }
        var out: JObject = ["result": result]
        if !reason.isEmpty { out["reason"] = .string(reason) } // for expect.reason_contains; never compared otherwise
        return out
    default:
        guard !rawHasLoneSurrogate, let v = try? StrictJSON.parse(raw), let canon = try? Canonical.canonicalizeStrict(v) else {
            return ["error": .string("parse")]
        }
        return ["canon": .string(canon), "hash": .string(Canonical.hashCanonical(v))]
    }
}

let args = CommandLine.arguments
guard args.count == 3, let input = FileManager.default.contents(atPath: args[1]) else {
    FileHandle.standardError.write("usage: pcadriver <corpus.jsonl> <out.jsonl>\n".data(using: .utf8)!)
    exit(2)
}
FileManager.default.createFile(atPath: args[2], contents: nil)
guard let out = FileHandle(forWritingAtPath: args[2]) else { exit(2) }
for lineBytes in input.split(separator: 0x0A, omittingEmptySubsequences: true) {
    let (text, replaced) = sanitizeLoneSurrogates(Array(lineBytes))
    var res: JObject
    var id: JSONValue = .null
    if let c = try? StrictJSON.parseLenient(text), c.isObject {
        id = c.get("id") ?? .null
        let rawLone = replaced && (c.get("raw")?.asString.map { $0.unicodeScalars.contains(SENTINEL) } ?? false)
        res = one(c, rawHasLoneSurrogate: rawLone)
    } else {
        res = ["error": .string("exception:line")]
    }
    res["id"] = id
    out.write((Canonical.canonicalize(.object(res)) + "\n").data(using: .utf8)!)
}
try? out.close()

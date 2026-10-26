// Kotlin differential driver (wire format v2). Same line protocol as the Go / Rust / Java drivers:
//   java -cp <classes>:<kotlin-stdlib>:<bcprov.jar> DriverKt <corpus.jsonl> <out.jsonl>
// suites : the capability manifest Pq.supportedSuites() (packages/pca/conformance/SUITES.md)
// verify : Pca.verifyPcactnJson(raw, lenient grant, now, Audience.Of(aud), allowed_suites?, intent_policy_json? | intent_policy?,
//          intent_v2?) (strict parse failure == wire failure); a verdict whose reason carries `unsupported_suite` is tagged
// chain  : Pca.verifyChain(chain, expected_root_issuer?, allowed_suites?, pq_pins?, trusted_root?)
// canon  : strict parse + canonicalizeStrict + hashStrict of ANY JSON text
// intent_*: an Intent Layer v2 primitive (raw = its `input` as JSON text); `result` in the `expect` shape, `reason` when
//          refused.
import net.atlasauth.pca.verifier.ActionSchema
import net.atlasauth.pca.verifier.Caveats
import net.atlasauth.pca.verifier.IntentClassifier
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.IntentMap
import net.atlasauth.pca.verifier.IntentRevocation
import net.atlasauth.pca.verifier.IntentV2
import net.atlasauth.pca.verifier.IntentWB
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleFacts
import net.atlasauth.pca.verifier.ParamProvenance
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.Pq
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

private fun esc(s: String): String {
    val b = StringBuilder("\"")
    for (c in s) {
        when {
            c == '"' || c == '\\' -> b.append('\\').append(c)
            c < ' ' || c in '\ud800'..'\udfff' -> b.append(String.format("\\u%04x", c.code))
            else -> b.append(c)
        }
    }
    return b.append('"').toString()
}

private fun strings(o: Any?): List<String>? = (o as? List<*>)?.map { it.toString() }

private fun checksJson(checks: Map<String, Boolean>): String =
    checks.entries.joinToString(",", "{", "}") { (k, v) -> esc(k) + ":" + v }

private fun suiteTag(reason: String): String =
    if (reason.contains(Pq.UNSUPPORTED_SUITE)) ",\"unsupported_suite\":" + esc(reason) else ""

/** One Intent Layer v2 primitive in exactly the shape of its conformance `expect`, plus the refusal reason; null = not implemented. */
@Suppress("UNCHECKED_CAST")
private fun intentPrimitive(kind: String, input: Any?): Pair<Map<String, Any?>, String?>? {
    val out = LinkedHashMap<String, Any?>()
    when (kind) {
        "intent_schema" -> {
            val inp = IntentJs.normalize(input) as Map<String, Any?>
            val why = ActionSchema.verify(inp["schema"], inp["keys"])
            val c = ActionSchema.conform(inp["schema"], inp["verb"] as? String ?: "", inp["params"])
            out["sig"] = why == null
            if (why == null) out["digest"] = ActionSchema.digest(inp["schema"])
            out["conform"] = LinkedHashMap<String, Any?>().apply {
                put("ok", c.ok)
                if (!c.ok && c.code != null) put("code", c.code)
                if (!c.ok && c.path != null) put("path", c.path)
            }
            return out to (why ?: c.reason)
        }
        "intent_revocation" -> { out["ok"] = IntentRevocation.checkPrimitive(input); return out to IntentRevocation.primitiveReason(input) }
        "intent_world" -> {
            val r = OracleFacts.decideIntentWorld(input)
            out["ok"] = r.ok
            if (r.ok) { out["world"] = r.world; out["single_source"] = r.singleSource }
            return out to r.reason
        }
        "intent_provenance" -> {
            val r = ParamProvenance.decide(input)
            out["outcome"] = r.outcome
            if (r.outcome != "deny") { out["labels"] = r.labels; out["classes"] = r.classes }
            if (r.outcome == "question") out["friction"] = r.friction
            return out to r.reason
        }
        "intent_classifier" -> {
            val r = IntentClassifier.decide(input)
            out["ok"] = r.ok
            if (r.ok) out["classes"] = r.classes
            return out to r.reason
        }
        "intent_wb_active" -> {
            val a = IntentWB.active(input)
            out["facts"] = a[0]; out["provenance"] = a[1]; out["classes"] = a[2]
            return out to null
        }
        "intent_map_commit" -> { out["map_commit"] = IntentMap.commitLeaves((input as Map<String, Any?>)["leaves"]); return out to null }
        "intent_map" -> {
            val d = IntentMap.decidePrimitive(input)
            out["ok"] = d.ok
            if (d.ok) { out["cell"] = d.cell; out["p_ppm"] = d.pPpm }
            return out to d.reason
        }
        "intent_read_purpose" -> {
            val r = ParamProvenance.decideReadPurpose(input)
            out["outcome"] = r.outcome; out["minimise"] = r.minimise; out["uncovered"] = r.uncovered
            return out to null
        }
        else -> return null
    }
}

@Suppress("UNCHECKED_CAST")
private fun one(c: Map<String, Any?>): String {
    val id = esc(c["id"] as? String ?: "")
    val kind = c["kind"] as? String ?: ""
    val raw = c["raw"] as? String ?: ""
    return try {
        when {
            kind == "suites" ->
                "{\"id\":$id,\"suites\":" + Pq.supportedSuites().joinToString(",", "[", "]") { esc(it) } + "}"
            kind == "verify" -> {
                val grant = Json.parseLenient(c["grant"] as String) as Map<String, Any?>
                // Intent Layer M2: raw JSON text `intent_policy_json` (keeps 950000.0 / 1e6 / -0.0) wins over the object `intent_policy`.
                val ip = if (c["intent_policy_json"] is String) Pca.IntentPolicy.fromJsonText(c["intent_policy_json"] as String)
                else Pca.IntentPolicy.fromJson(c["intent_policy"])
                // Intent Layer v2: the verifier state when PRESENT (a non-object, JSON null included, is a malformed context)
                val v2 = if (c.containsKey("intent_v2")) IntentV2.Context.fromJson(c["intent_v2"]) else null
                val g = Pca.verifyPcactnJson(raw, grant, Json.asLong(c["now"]), Pca.Audience.Of(c["aud"] as String), strings(c["allowed_suites"]), ip, v2)
                "{\"id\":$id,\"allow\":${g.allow},\"checks\":${checksJson(g.checks)}${suiteTag(g.reason)}}"
            }
            kind == "chain" -> {
                // R4-01: raw = {chain, expected_root_issuer?, pq_pins?, trusted_root?, allowed_suites?}
                val o = Json.parseLenient(raw) as Map<String, Any?>
                val eri = o["expected_root_issuer"]
                val why = Pca.verifyChain(
                    o["chain"] as List<Any?>, eri as? String ?: "", eri is String,
                    strings(o["allowed_suites"]), o["pq_pins"] as? Map<String, Any?>, o["trusted_root"] as? Map<String, Any?>,
                )
                val ok = why.isEmpty()
                "{\"id\":$id,\"allow\":$ok,\"checks\":{\"chain\":$ok}${suiteTag(why)}}"
            }
            kind == "policy" -> {
                // Policy layer (packages/pca/conformance/LAYERS.md): raw = JSON text {grant, chain, context}; answers the caveat projection
                // evaluateCaveats(policyCaveats(grant, chain), context) as {allow, failed}
                val pv = Json.parseLenient(raw) as Map<String, Any?>
                val pr = Caveats.evaluateCaveats(Caveats.policyCaveats(pv["grant"], pv["chain"]), pv["context"])
                "{\"id\":$id,\"allow\":${pr.ok},\"failed\":" + pr.failed.joinToString(",", "[", "]") { esc(it) } + "}"
            }
            kind.startsWith("intent_") -> {
                val r = intentPrimitive(kind, Json.parseLenient(raw)) ?: return "{\"id\":$id,\"error\":${esc("exception:$kind")}}"
                "{\"id\":$id,\"result\":${Json.canonicalize(r.first)}" + (r.second?.let { ",\"reason\":" + esc(it) } ?: "") + "}"
            }
            else -> {
                val v = try { Json.parse(raw) } catch (t: Throwable) { return "{\"id\":$id,\"error\":\"parse\"}" }
                val canon = try { Json.canonicalizeStrict(v) } catch (t: Throwable) { return "{\"id\":$id,\"error\":\"parse\"}" }
                "{\"id\":$id,\"canon\":${esc(canon)},\"hash\":${esc(Pca.hashStrict(v))}}"
            }
        }
    } catch (t: Throwable) {
        "{\"id\":$id,\"error\":${esc("exception:" + t.javaClass.simpleName)}}"
    }
}

@Suppress("UNCHECKED_CAST")
fun main(args: Array<String>) {
    Files.newBufferedReader(Path.of(args[0]), StandardCharsets.UTF_8).use { inp ->
        Files.newBufferedWriter(Path.of(args[1]), StandardCharsets.UTF_8).use { out ->
            while (true) {
                val line = inp.readLine() ?: break
                if (line.isEmpty()) continue
                out.write(one(Json.parseLenient(line) as Map<String, Any?>))
                out.write("\n")
                out.flush()
            }
        }
    }
}

// Java differential driver (wire format v2). Same protocol as the other drivers:
//   java -cp <classes>:<bcprov.jar> Driver <corpus.jsonl> <out.jsonl>
// verify: Pca.verifyPcactnJson(raw, lenient grant, now, aud, allowed_suites?, intent_policy_json? | intent_policy?, intent_v2?)  (parse failure == wire failure)
// canon : strict parse + canonicalizeStrict + hashStrict of ANY JSON text
// intent_*: an Intent Layer v2 primitive (raw = its `input` as JSON text); the line carries `result` in the `expect` shape
import net.atlasauth.pca.ActionSchema;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Caveats;
import net.atlasauth.pca.IntentClassifier;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.IntentMap;
import net.atlasauth.pca.IntentRevocation;
import net.atlasauth.pca.IntentV2;
import net.atlasauth.pca.IntentWB;
import net.atlasauth.pca.OracleFacts;
import net.atlasauth.pca.ParamProvenance;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.Pq;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class Driver {
    static String esc(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 0x20 || (c >= 0xd800 && c <= 0xdfff)) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    @SuppressWarnings("unchecked")
    static List<String> allowed(Object o) {
        if (!(o instanceof List)) return null;
        List<String> r = new ArrayList<>();
        for (Object x : (List<Object>) o) r.add(String.valueOf(x));
        return r;
    }

    /** One Intent Layer v2 primitive, reported in exactly the shape of its conformance {@code expect}; null for an unknown kind. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> intentPrimitive(String kind, Object input) {
        Map<String, Object> out = new LinkedHashMap<>();
        switch (kind) {
            case "intent_schema": {
                Map<String, Object> in = (Map<String, Object>) IntentJs.normalize(input);
                boolean sig = ActionSchema.verify(in.get("schema"), in.get("keys")) == null;
                ActionSchema.Conform c = ActionSchema.conform(in.get("schema"), in.get("verb") instanceof String ? (String) in.get("verb") : "", in.get("params"));
                Map<String, Object> conform = new LinkedHashMap<>();
                conform.put("ok", c.ok);
                if (c.code != null) conform.put("code", c.code);
                if (c.path != null) conform.put("path", c.path);
                out.put("sig", sig);
                if (sig) out.put("digest", ActionSchema.digest(in.get("schema")));
                out.put("conform", conform);
                return out;
            }
            case "intent_revocation":
                out.put("ok", IntentRevocation.checkPrimitive(input));
                return out;
            case "intent_world": {
                OracleFacts.WorldResult w = OracleFacts.decideIntentWorld(input);
                out.put("ok", w.ok);
                if (w.ok) { out.put("world", w.world); out.put("single_source", w.singleSource); }
                return out;
            }
            case "intent_provenance": {
                ParamProvenance.ProvResult p = ParamProvenance.decide(input);
                out.put("outcome", p.outcome);
                if (!p.outcome.equals("deny")) {
                    if (p.outcome.equals("question")) out.put("friction", p.friction);
                    out.put("labels", p.labels);
                    out.put("classes", p.classes);
                }
                return out;
            }
            case "intent_classifier": {
                IntentClassifier.ClassResult c = IntentClassifier.decide(input);
                out.put("ok", c.ok);
                if (c.ok) out.put("classes", c.classes);
                return out;
            }
            case "intent_wb_active": {
                boolean[] a = IntentWB.active(input);
                out.put("facts", a[0]);
                out.put("provenance", a[1]);
                out.put("classes", a[2]);
                return out;
            }
            case "intent_read_purpose": {
                ParamProvenance.ReadPurposeResult r = ParamProvenance.decideReadPurpose(input);
                out.put("outcome", r.outcome);
                out.put("minimise", r.minimise);
                out.put("uncovered", r.uncovered);
                return out;
            }
            case "intent_map_commit":
                out.put("map_commit", IntentMap.commitLeaves(((Map<String, Object>) input).get("leaves")));
                return out;
            case "intent_map": {
                IntentMap.Decision d = IntentMap.decidePrimitive(input);
                out.put("ok", d.ok);
                if (d.ok) {
                    List<Object> cell = new ArrayList<>();
                    cell.addAll(d.cell);
                    out.put("cell", cell);
                    out.put("p_ppm", d.pPpm);
                }
                return out;
            }
            default:
                return null;
        }
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] a) throws Exception {
        try (BufferedReader in = Files.newBufferedReader(Path.of(a[0]), StandardCharsets.UTF_8);
             BufferedWriter out = Files.newBufferedWriter(Path.of(a[1]), StandardCharsets.UTF_8)) {
            String line;
            while ((line = in.readLine()) != null) {
                if (line.isEmpty()) continue;
                Map<String, Object> c = (Map<String, Object>) Json.parseLenient(line);
                String id = (String) c.get("id"), kind = (String) c.get("kind"), raw = (String) c.get("raw");
                String r;
                try {
                    if (kind.equals("suites")) {
                        // Suite-capability manifest (packages/pca/conformance/SUITES.md).
                        StringBuilder sb = new StringBuilder("[");
                        for (String su : Pq.supportedSuites()) sb.append(sb.length() > 1 ? "," : "").append(esc(su));
                        r = "{\"id\":" + esc(id) + ",\"suites\":" + sb + "]}";
                    } else if (kind.equals("verify")) {
                        Map<String, Object> grant = (Map<String, Object>) Json.parseLenient((String) c.get("grant"));
                        // Intent Layer M2: optional policy {require?, min_fidelity_ppm?, max_residual_risk_ppm?}, either as raw JSON
                        // text `intent_policy_json` (parsed here; wins when both are present) or as a JSON object `intent_policy`.
                        Pca.IntentPolicy ip = c.get("intent_policy_json") instanceof String
                            ? Pca.IntentPolicy.fromJsonText((String) c.get("intent_policy_json")) : Pca.IntentPolicy.fromJson(c.get("intent_policy"));
                        // Intent Layer v2: optional verifier state `intent_v2` (a JSON object, the vectors' context.intent_v2)
                        Pca.Verdict g = Pca.verifyPcactnJson(raw, grant, Json.asLong(c.get("now")), (String) c.get("aud"), allowed(c.get("allowed_suites")), ip,
                            (c.containsKey("intent_v2") ? IntentV2.Context.fromJson(c.get("intent_v2")) : null));
                        StringBuilder ch = new StringBuilder("{");
                        boolean first = true;
                        for (Map.Entry<String, Boolean> e : g.checks.entrySet()) {
                            ch.append(first ? "" : ",").append(esc(e.getKey())).append(':').append(Boolean.TRUE.equals(e.getValue()));
                            first = false;
                        }
                        r = "{\"id\":" + esc(id) + ",\"allow\":" + g.allow + ",\"checks\":" + ch + "}"
                            + (g.reason != null && g.reason.contains(Pq.UNSUPPORTED_SUITE) ? ",\"unsupported_suite\":" + esc(g.reason) : "") + "}";
                    } else if (kind.equals("chain")) {
                        // R4-01: standalone verifyChain with verifier-side PQ authority; raw = {chain, expected_root_issuer?, pq_pins?, trusted_root?, allowed_suites?}
                        Map<String, Object> co = (Map<String, Object>) Json.parseLenient(raw);
                        Object eri = co.get("expected_root_issuer");
                        String why = Pca.verifyChain((List<Object>) co.get("chain"), eri instanceof String ? (String) eri : null, eri instanceof String,
                            allowed(co.get("allowed_suites")), (Map<String, Object>) co.get("pq_pins"), (Map<String, Object>) co.get("trusted_root"));
                        r = "{\"id\":" + esc(id) + ",\"allow\":" + why.isEmpty() + ",\"checks\":{\"chain\":" + why.isEmpty() + "}"
                            + (why.contains(Pq.UNSUPPORTED_SUITE) ? ",\"unsupported_suite\":" + esc(why) : "") + "}";
                    } else if (kind.equals("policy")) {
                        // Policy layer (packages/pca/conformance/LAYERS.md): raw = JSON text {grant, chain, context}; answers the caveat projection
                        // Authorize.evaluateAgentCaveats(policyCaveats(grant, chain), context, {action}, toolCall) as {allow, failed}: the
                        // agent-native evaluator (predicates + tool_schema); the tool call is the signed verb + params (the reference's toolCallOf)
                        Map<String, Object> pv = (Map<String, Object>) Json.parseLenient(raw);
                        Map<String, Object> pctx = (Map<String, Object>) pv.get("context");
                        Object pact = pctx.get("action");
                        Map<String, Object> pam = pact instanceof Map ? (Map<String, Object>) pact : null;
                        Map<String, Object> pactx = new LinkedHashMap<>();
                        pactx.put("action", pact);
                        Map<String, Object> pcall = new LinkedHashMap<>();
                        pcall.put("tool", pam != null && pam.get("verb") instanceof String ? pam.get("verb") : "");
                        pcall.put("args", pam != null && pam.get("params") instanceof Map ? pam.get("params") : new LinkedHashMap<String, Object>());
                        Caveats.Result pr = Authorize.evaluateAgentCaveats(Caveats.policyCaveats(pv.get("grant"), pv.get("chain")), pctx, pactx, pcall);
                        StringBuilder fl = new StringBuilder("[");
                        for (int k = 0; k < pr.failed.size(); k++) fl.append(k == 0 ? "" : ",").append(esc(pr.failed.get(k)));
                        r = "{\"id\":" + esc(id) + ",\"allow\":" + pr.ok + ",\"failed\":" + fl.append("]") + "}";
                    } else if (kind.startsWith("intent_")) {
                        // Intent Layer v2 primitives: raw = JSON text of the primitive's `input`; result = its `expect` shape.
                        Map<String, Object> res = intentPrimitive(kind, Json.parseLenient(raw));
                        r = res == null ? "{\"id\":" + esc(id) + ",\"error\":\"exception:" + kind + "\"}"
                            : "{\"id\":" + esc(id) + ",\"result\":" + Json.canonicalize(res) + "}";
                    } else {
                        Object v;
                        try { v = Json.parse(raw); } catch (Throwable t) { out.write("{\"id\":" + esc(id) + ",\"error\":\"parse\"}\n"); continue; }
                        String canon;
                        try { canon = Json.canonicalizeStrict(v); } catch (Throwable t) { out.write("{\"id\":" + esc(id) + ",\"error\":\"parse\"}\n"); continue; }
                        r = "{\"id\":" + esc(id) + ",\"canon\":" + esc(canon) + ",\"hash\":" + esc(Pca.hashStrict(v)) + "}";
                    }
                } catch (Throwable t) { r = "{\"id\":" + esc(id) + ",\"error\":\"exception:" + t.getClass().getSimpleName() + "\"}"; }
                out.write(r); out.write('\n'); out.flush();
            }
        }
    }
}

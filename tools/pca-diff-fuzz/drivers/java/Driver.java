// Java differential driver (wire format v2). Same protocol as the other drivers:
//   java -cp <classes>:<bcprov.jar> Driver <corpus.jsonl> <out.jsonl>
// verify: Pca.verifyPcactnJson(raw, lenient grant, now, aud)  (parse failure == wire failure)
// canon : strict parse + canonicalizeStrict + hashStrict of ANY JSON text
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;
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
                    if (kind.equals("verify")) {
                        Map<String, Object> grant = (Map<String, Object>) Json.parseLenient((String) c.get("grant"));
                        Pca.Verdict g = Pca.verifyPcactnJson(raw, grant, Json.asLong(c.get("now")), (String) c.get("aud"), allowed(c.get("allowed_suites")));
                        StringBuilder ch = new StringBuilder("{");
                        boolean first = true;
                        for (Map.Entry<String, Boolean> e : g.checks.entrySet()) {
                            ch.append(first ? "" : ",").append(esc(e.getKey())).append(':').append(Boolean.TRUE.equals(e.getValue()));
                            first = false;
                        }
                        r = "{\"id\":" + esc(id) + ",\"allow\":" + g.allow + ",\"checks\":" + ch + "}}";
                    } else if (kind.equals("chain")) {
                        // R4-01: standalone verifyChain with verifier-side PQ authority; raw = {chain, expected_root_issuer?, pq_pins?, trusted_root?, allowed_suites?}
                        Map<String, Object> co = (Map<String, Object>) Json.parseLenient(raw);
                        Object eri = co.get("expected_root_issuer");
                        String why = Pca.verifyChain((List<Object>) co.get("chain"), eri instanceof String ? (String) eri : null, eri instanceof String,
                            allowed(co.get("allowed_suites")), (Map<String, Object>) co.get("pq_pins"), (Map<String, Object>) co.get("trusted_root"));
                        r = "{\"id\":" + esc(id) + ",\"allow\":" + why.isEmpty() + ",\"checks\":{\"chain\":" + why.isEmpty() + "}}";
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

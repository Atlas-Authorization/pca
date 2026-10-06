import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/** JUnit-free conformance runner. Run from verifiers/java-pca. */
public class ConformanceTest {
    static final String DIR = "../../conformance/";
    static int fails = 0, checks = 0;

    static void check(boolean ok, String msg) {
        checks++;
        if (!ok) { fails++; System.out.println("  FAIL: " + msg); }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> load(String name) throws Exception {
        return (Map<String, Object>) Json.parse(Files.readString(Path.of(DIR + name)));
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        Map<String, Object> doc = load("vectors.json");
        List<Object> vs = (List<Object>) doc.get("vectors");
        if (vs.isEmpty()) throw new IllegalStateException("no vectors");
        int vecFails = 0;
        for (Object x : vs) {
            Map<String, Object> v = (Map<String, Object>) x;
            int before = fails;
            Pca.Verdict got = Pca.verifyPcactnCore((Map<String, Object>) v.get("pcactn"), (Map<String, Object>) v.get("grant"));
            Map<String, Object> exp = (Map<String, Object>) v.get("expect");
            check(got.allow == (Boolean) exp.get("allow"), v.get("name") + ": allow=" + got.allow + " want " + exp.get("allow") + " (" + got.reason + ")");
            for (Map.Entry<String, Object> e : ((Map<String, Object>) exp.get("checks")).entrySet())
                check(got.checks.get(e.getKey()).equals(e.getValue()), v.get("name") + ": check " + e.getKey() + "=" + got.checks.get(e.getKey()) + " want " + e.getValue());
            boolean ok = fails == before;
            if (!ok) vecFails++;
            System.out.println((ok ? "PASS " : "FAIL ") + v.get("name"));
        }

        Map<String, Object> prim = (Map<String, Object>) doc.get("primitives");
        for (Object x : (List<Object>) prim.get("canonical")) {
            Map<String, Object> c = (Map<String, Object>) x;
            String s = Json.canonicalize(c.get("value"));
            check(s.equals(c.get("expect")), "canonical " + s + " vs " + c.get("expect"));
            check(Pca.hashCanonical(c.get("value")).equals(c.get("hash")), "hash for " + s);
        }
        for (Object x : (List<Object>) prim.get("merkle")) {
            Map<String, Object> m = (Map<String, Object>) x;
            List<Object> leaves = (List<Object>) m.get("leaves");
            String root = Pca.merkleRoot(leaves);
            check(root.equals(m.get("root")), "merkle root " + root + " vs " + m.get("root"));
            List<Object> proofs = (List<Object>) m.get("proofs");
            for (int i = 0; i < proofs.size(); i++)
                check(Pca.verifyInclusion(root, (Map<String, Object>) proofs.get(i), leaves.get(i)), "proof " + i);
        }
        check(Pca.paramsDigest(null).equals(prim.get("params_digest_empty")), "empty params digest");

        System.out.println(vs.size() + " vectors (" + (vs.size() - vecFails) + " passed), " + checks + " assertions, " + fails + " failures");
        System.exit(fails == 0 ? 0 : 1);
    }
}

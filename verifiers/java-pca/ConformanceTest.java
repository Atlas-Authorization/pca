import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.Pq;
import net.atlasauth.pca.Threshold;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * JUnit-free conformance runner for PCA wire format v2 (ed25519 + the post-quantum suites + the v2.1
 * agent-leaf threshold-share binding). Run from sdks/java-pca with BouncyCastle on the classpath. ML-DSA-65
 * (FIPS-204) needs a final-FIPS-204 BouncyCastle (bcprov-jdk18on >= 1.80):
 *
 *   BC=~/.m2/repository/org/bouncycastle/bcprov-jdk18on/1.80/bcprov-jdk18on-1.80.jar
 *   javac -cp "$BC" -d out src/net/atlasauth/pca/*.java ConformanceTest.java
 *   java  -cp "out:$BC" ConformanceTest
 *
 * <p>This verifier implements the three CROSS-IMPL suites every verifier at parity must cover (GAP 1):
 * {@code ed25519}, {@code ml-dsa-65} and {@code hybrid-ed25519-ml-dsa-65}, for BOTH the leaf signature
 * ({@code requires:"pq"}) AND non-leaf capability-chain hops ({@code requires:"pq-nonleaf"}). Vectors whose
 * suite is a REGISTERED post-quantum suite this verifier does not implement (ml-dsa-87, slh-dsa-*, the nested
 * hybrid, and their hybrids) are SKIPPED with an explicit count — never silently, never faked. Deliberately
 * unknown-alg / stray-field wire negatives still RUN (they are suite-agnostic fail-closed checks). It also
 * enforces the v2.1 agent-leaf share binding (GAP 2): a BARE agent share and a cross-signer-set replay are
 * REJECTED.
 */
public class ConformanceTest {
    static final String DIR = "../../conformance/";
    static int fails = 0, checks = 0;

    /** The suites this verifier implements — the three cross-impl suites required at parity (GAP 1). */
    static final Set<String> IMPLEMENTED_SUITES = Set.of("ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65");
    /** Every registered suite in the corpus (README: 10 suites). */
    static final Set<String> ALL_REGISTERED_SUITES = Set.of(
        "ed25519", "ml-dsa-65", "ml-dsa-87", "hybrid-ed25519-ml-dsa-65", "hybrid-ed25519-ml-dsa-87",
        "hybrid-nested-ed25519-ml-dsa-65", "slh-dsa-sha2-128f", "slh-dsa-sha2-256s",
        "hybrid-ed25519-slh-dsa-sha2-128f", "hybrid-ed25519-slh-dsa-sha2-256s");

    static void check(boolean ok, String msg) {
        checks++;
        if (!ok) { fails++; System.out.println("  FAIL: " + msg); }
    }

    /** Fixtures are trusted but contain deliberately non-canonical values, so they use the LENIENT profile. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> load(String name) throws Exception {
        return (Map<String, Object>) Json.parseLenient(Files.readString(Path.of(DIR + name)));
    }

    static String str(Object o) { return o instanceof String ? (String) o : ""; }

    /** Raw bytes of a base64url string of arbitrary length; throws (fail-closed) on a malformed input. */
    static byte[] b64uBytes(Object o) {
        byte[] b = Pca.decodeB64uStrict(o, -1);
        if (b == null) throw new IllegalArgumentException("not canonical base64url: " + o);
        return b;
    }

    /**
     * The set of signature suites a vector exercises: the leaf {@code alg} plus every cap-chain hop {@code alg}.
     * An absent {@code alg} is the default ed25519 and contributes nothing to skip (so downgrade vectors, which
     * strip the suite fields, always RUN as the structural negatives they are). Only inspects the parsed
     * {@code pcactn}; raw {@code pcactn_json} vectors are all ed25519 core, so none is ever suite-skipped.
     */
    @SuppressWarnings("unchecked")
    static Set<String> suitesExercised(Map<String, Object> v) {
        Set<String> out = new LinkedHashSet<>();
        Object pco = v.get("pcactn");
        if (!(pco instanceof Map)) return out;
        Map<String, Object> p = (Map<String, Object>) pco;
        if (p.get("alg") instanceof String) out.add((String) p.get("alg"));
        if (p.get("cap_chain") instanceof List) {
            for (Object ho : (List<Object>) p.get("cap_chain")) {
                if (ho instanceof Map && ((Map<String, Object>) ho).get("alg") instanceof String)
                    out.add((String) ((Map<String, Object>) ho).get("alg"));
            }
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        Map<String, Object> doc = load("vectors.json");
        check(Json.asLong(doc.get("format")) == 2 && Json.asLong(doc.get("ver")) == 2, "format-2 vectors");
        check("2.1".equals(doc.get("agent_leaf_binding")), "agent_leaf_binding == 2.1");
        List<Object> vs = (List<Object>) doc.get("vectors");
        if (vs.isEmpty()) throw new IllegalStateException("no vectors");

        int ran = 0, vecFails = 0, skipped = 0;
        // Per-skipped-suite tally and a record of which cross-impl suites got a PASSING positive LEAF vector.
        Map<String, Integer> skipBySuite = new TreeMap<>();
        Set<String> crossImplPositiveLeafPassed = new LinkedHashSet<>();
        for (Object x : vs) {
            Map<String, Object> v = (Map<String, Object>) x;
            Set<String> suites = suitesExercised(v);
            // Skip iff the vector exercises a REGISTERED suite we do not implement. A bogus/unknown alg
            // (e.g. "ml-dsa-999") is NOT registered, so it still runs and is correctly rejected fail-closed.
            String unsupported = null;
            for (String s : suites)
                if (ALL_REGISTERED_SUITES.contains(s) && !IMPLEMENTED_SUITES.contains(s)) { unsupported = s; break; }
            if (unsupported != null) {
                skipped++;
                skipBySuite.merge(unsupported, 1, Integer::sum);
                System.out.println("SKIP " + v.get("name") + " (unimplemented suite: " + unsupported + ")");
                continue;
            }

            int before = fails;
            Map<String, Object> ctx = (Map<String, Object>) v.get("context");
            long now = Json.asLong(ctx.get("now"));
            String aud = (String) ctx.get("aud");
            Map<String, Object> grant = (Map<String, Object>) v.get("grant");
            Pca.Verdict got = v.containsKey("pcactn_json")
                ? Pca.verifyPcactnJson((String) v.get("pcactn_json"), grant, now, aud)
                : Pca.verifyPcactn(v.get("pcactn"), grant, now, aud);
            Map<String, Object> exp = (Map<String, Object>) v.get("expect");
            boolean wantAllow = (Boolean) exp.get("allow");
            check(got.allow == wantAllow, v.get("name") + ": allow=" + got.allow + " want " + wantAllow + " (" + got.reason + ")");
            Map<String, Object> want = (Map<String, Object>) exp.get("checks");
            check(want.keySet().equals(got.checks.keySet()), v.get("name") + ": check set " + got.checks.keySet() + " want " + want.keySet());
            for (Map.Entry<String, Object> e : want.entrySet())
                check(e.getValue().equals(got.checks.get(e.getKey())), v.get("name") + ": check " + e.getKey() + "=" + got.checks.get(e.getKey()) + " want " + e.getValue() + " (" + got.reason + ")");
            boolean ok = fails == before;
            ran++;
            if (!ok) vecFails++;
            System.out.println((ok ? "PASS " : "FAIL ") + v.get("name"));

            // GAP 1 evidence: record each cross-impl LEAF suite proven by a passing positive (allow==true) vector.
            if (ok && wantAllow && "pq".equals(v.get("requires"))) {
                Object pco = v.get("pcactn");
                String leaf = pco instanceof Map && ((Map<String, Object>) pco).get("alg") instanceof String
                    ? (String) ((Map<String, Object>) pco).get("alg") : "ed25519";
                if (IMPLEMENTED_SUITES.contains(leaf)) crossImplPositiveLeafPassed.add(leaf);
            }
            if (ok && wantAllow && (v.get("requires") == null || "".equals(v.get("requires")))) {
                crossImplPositiveLeafPassed.add("ed25519"); // core positives exercise the ed25519 leaf
            }
        }

        // ---- GAP 1: the three cross-impl suites must each be exercised by a passing positive -----------------
        System.out.println();
        for (String s : List.of("ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65"))
            check(crossImplPositiveLeafPassed.contains(s), "GAP1: cross-impl suite exercised by a passing positive: " + s);

        // ---- primitives --------------------------------------------------------------------------------------
        Map<String, Object> prim = (Map<String, Object>) doc.get("primitives");
        for (Object x : (List<Object>) prim.get("canonical")) {
            Map<String, Object> c = (Map<String, Object>) x;
            String s = Json.canonicalizeStrict(c.get("value"));
            check(s.equals(c.get("expect")), "canonical " + s + " vs " + c.get("expect"));
            check(Pca.hashStrict(c.get("value")).equals(c.get("hash")), "hash for " + s);
        }
        for (Object x : (List<Object>) prim.get("json_parse")) {
            Map<String, Object> j = (Map<String, Object>) x;
            String in = (String) j.get("input");
            boolean accepted;
            String canon = null;
            try { canon = Json.canonicalizeStrict(Json.parse(in)); accepted = true; } catch (RuntimeException e) { accepted = false; }
            check(accepted == (Boolean) j.get("accept"), "json_parse accept=" + accepted + " for " + in);
            if (accepted && j.containsKey("canonical")) check(canon.equals(j.get("canonical")), "json_parse canonical " + canon + " for " + in);
        }
        for (Object x : (List<Object>) prim.get("b64u")) {
            Map<String, Object> b = (Map<String, Object>) x;
            int len = b.containsKey("len") ? (int) Json.asLong(b.get("len")) : -1;
            boolean valid = Pca.decodeB64uStrict(b.get("input"), len) != null;
            check(valid == (Boolean) b.get("valid"), "b64u valid=" + valid + " for '" + b.get("input") + "' len " + len);
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

        // ---- GAP 2: v2.1 agent-leaf threshold-share binding --------------------------------------------------
        // Recompute the role/signer-set/t-bound share message for EVERY entry and verify share.sig over it.
        int shareChecks = 0;
        boolean bareAgentRejectVerified = false, wrongSetRejectVerified = false, boundAgentAccepted = false;
        for (Object x : (List<Object>) prim.get("threshold_share")) {
            Map<String, Object> e = (Map<String, Object>) x;
            String role = str(e.get("role"));
            int t = (int) Json.asLong(e.get("t"));
            List<Object> signerSet = (List<Object>) e.get("signer_set");
            byte[] tmsg = b64uBytes(e.get("threshold_message"));
            Map<String, Object> share = (Map<String, Object>) e.get("share");
            boolean wantValid = !e.containsKey("valid") || (Boolean) e.get("valid");
            boolean gotValid = Threshold.verifyShare(role, tmsg, signerSet, t, share);
            String nm = e.containsKey("name") ? (String) e.get("name") : role + "-t" + t;
            check(gotValid == wantValid, "threshold_share " + nm + ": verify=" + gotValid + " want " + wantValid);
            shareChecks++;
            if ("agent-bare-rejected".equals(nm)) bareAgentRejectVerified = !gotValid;
            if ("agent-bound-wrong-set".equals(nm)) wrongSetRejectVerified = !gotValid;
            if ("agent-bound-t1".equals(nm) || "agent-bound-t2".equals(nm)) boundAgentAccepted = gotValid;
        }
        // The v2.1 binding is only meaningful if BOTH the bare-agent and the wrong-signer-set shares are REJECTED
        // AND a properly bound agent share is ACCEPTED.
        check(bareAgentRejectVerified, "GAP2: bare pre-v2.1 agent share (agent-bare-rejected) is REJECTED");
        check(wrongSetRejectVerified, "GAP2: cross-signer-set agent share (agent-bound-wrong-set) is REJECTED");
        check(boundAgentAccepted, "GAP2: a v2.1 signerSetHash‖t-bound agent share is ACCEPTED");

        // ---- post-quantum artifact signatures (same agility seam as the leaf) --------------------------------
        int artRan = 0, artSkipped = 0;
        for (Object x : (List<Object>) prim.get("pq_artifact")) {
            Map<String, Object> a = (Map<String, Object>) x;
            String alg = str(a.get("alg"));
            if (ALL_REGISTERED_SUITES.contains(alg) && !IMPLEMENTED_SUITES.contains(alg)) { artSkipped++; continue; }
            boolean wantValid = !a.containsKey("valid") || (Boolean) a.get("valid");
            boolean gotValid;
            try {
                byte[] msg = b64uBytes(a.get("message"));
                gotValid = Pq.verifyArtifactSignature(alg, str(a.get("ed_pub")), a.get("pq_pk"), msg, a.get("sig"), a.get("pq_sig"));
            } catch (RuntimeException ex) {
                gotValid = false; // fail-closed
            }
            check(gotValid == wantValid, "pq_artifact " + a.get("artifact") + "/" + alg + ": verify=" + gotValid + " want " + wantValid);
            artRan++;
        }

        // ---- report ------------------------------------------------------------------------------------------
        System.out.println();
        System.out.println("VECTORS: " + (ran + skipped) + " total = " + ran + " run (" + (ran - vecFails) + " passed, " + vecFails + " failed), " + skipped + " skipped");
        if (!skipBySuite.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, Integer> en : skipBySuite.entrySet()) sb.append("\n    ").append(en.getKey()).append(": ").append(en.getValue());
            System.out.println("  skipped by unimplemented suite:" + sb);
        }
        System.out.println("THRESHOLD_SHARE (v2.1 agent-leaf binding): " + shareChecks + " shares checked; "
            + "bare-agent rejected=" + bareAgentRejectVerified + ", wrong-set rejected=" + wrongSetRejectVerified
            + ", bound-agent accepted=" + boundAgentAccepted);
        System.out.println("PQ_ARTIFACT: " + artRan + " run, " + artSkipped + " skipped (unimplemented suites)");
        System.out.println("ASSERTIONS: " + checks + " checked, " + fails + " failures");
        System.exit(fails == 0 ? 0 : 1);
    }
}

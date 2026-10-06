package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Reference verifier for the CORE PCActn checks (M0-M3). Byte-matches @atlasauth/pca and go-pca. */
public final class Pca {
    private Pca() {}

    static final byte[] SIG_DOMAIN = "atlas-pca/actn/v1\0".getBytes(StandardCharsets.UTF_8);
    static final byte[] CAP_DOMAIN = "atlas-pca/cap/v1\0".getBytes(StandardCharsets.UTF_8);
    static final String DEFAULT_REV = "reversible";

    public static final class Verdict {
        public boolean allow;
        public final Map<String, Boolean> checks = new LinkedHashMap<>();
        public String reason = "";
        Verdict() {
            for (String k : new String[] {"chain", "plan_inclusion", "leaf_signature", "counter"}) checks.put(k, false);
        }
    }

    // ---- helpers ----
    static String b64(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    static byte[] unb64(String s) {
        if (s == null || s.indexOf('=') >= 0) throw new IllegalArgumentException("bad base64url");
        return Base64.getUrlDecoder().decode(s);
    }

    static byte[] sha(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) md.update(p);
            return md.digest();
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, out, o, p.length); o += p.length; }
        return out;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> asMap(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : new LinkedHashMap<>();
    }

    @SuppressWarnings("unchecked")
    static List<Object> asList(Object o) {
        return o instanceof List ? (List<Object>) o : new ArrayList<>();
    }

    static String asStr(Object o) { return o instanceof String ? (String) o : ""; }

    static byte[] canonBytes(Object v) { return Json.canonicalize(v).getBytes(StandardCharsets.UTF_8); }

    public static String hashCanonical(Object v) { return b64(sha(canonBytes(v))); }

    // ---- Merkle ----
    static byte[] leafHash(Object leaf) { return sha(new byte[] {0x00}, canonBytes(leaf)); }

    static byte[] nodeHash(byte[] l, byte[] r) { return sha(new byte[] {0x01}, l, r); }

    public static String merkleRoot(List<Object> leaves) {
        if (leaves.isEmpty()) throw new IllegalArgumentException("empty leaf set");
        List<byte[]> hs = new ArrayList<>();
        for (Object l : leaves) hs.add(leafHash(l));
        return b64(build(hs));
    }

    static int split(int n) { int k = 1; while (k * 2 < n) k *= 2; return k; }

    static byte[] build(List<byte[]> hs) {
        if (hs.size() == 1) return hs.get(0);
        int k = split(hs.size());
        return nodeHash(build(hs.subList(0, k)), build(hs.subList(k, hs.size())));
    }

    /** Never throws; malformed proofs return false. */
    public static boolean verifyInclusion(String root, Map<String, Object> proof, Object leaf) {
        try {
            if (!(proof.get("path") instanceof List)) return false;
            byte[] h = leafHash(leaf);
            for (Object s : asList(proof.get("path"))) {
                if (!(s instanceof Map)) return false;
                Map<String, Object> step = asMap(s);
                String side = asStr(step.get("side"));
                if (!side.equals("L") && !side.equals("R")) return false;
                byte[] sib = unb64(asStr(step.get("hash")));
                h = side.equals("L") ? nodeHash(sib, h) : nodeHash(h, sib);
            }
            return b64(h).equals(root);
        } catch (RuntimeException e) {
            return false;
        }
    }

    public static String paramsDigest(Object params) {
        return hashCanonical(params == null ? new LinkedHashMap<String, Object>() : params);
    }

    static String conditionsDigest(Object pre, Object post) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("pre", pre);
        m.put("post", post);
        return hashCanonical(m);
    }

    static Map<String, Object> planLeaf(Object nodeId, Map<String, Object> action, String cond) {
        if (nodeId == null) throw new IllegalArgumentException("missing node_id");
        Object pd = action.get("params_digest");
        if (pd == null) pd = paramsDigest(null);
        Object rc = action.get("reversibility_class");
        if (rc == null) rc = DEFAULT_REV;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("node_id", nodeId);
        m.put("verb", action.get("verb"));
        m.put("resource", action.get("resource"));
        m.put("params_digest", pd);
        m.put("reversibility_class", rc);
        m.put("conditions", cond);
        return m;
    }

    // ---- keys ----
    private static final byte[] ED_PREFIX = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};

    static boolean verifyB64u(String pub, byte[] msg, String sig) {
        try {
            byte[] pk = unb64(pub);
            byte[] sg = unb64(sig);
            if (pk.length != 32 || sg.length != 64) return false;
            PublicKey key = KeyFactory.getInstance("Ed25519")
                .generatePublic(new X509EncodedKeySpec(concat(ED_PREFIX, pk)));
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(key);
            s.update(msg);
            return s.verify(sg);
        } catch (Exception e) {
            return false;
        }
    }

    // ---- capability chain ----
    public static String capHash(Map<String, Object> c) { return hashCanonical(c); }

    static Map<String, Object> bodyOf(Map<String, Object> c) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("issuer", c.get("issuer"));
        m.put("holder", c.get("holder"));
        m.put("caveats", c.get("caveats"));
        m.put("parent", c.get("parent"));
        return m;
    }

    /** Returns "" when OK, else an error label. */
    static String checkSig(Map<String, Object> c, String signer, String label) {
        String digest;
        try { digest = hashCanonical(bodyOf(c)); } catch (RuntimeException e) { return label + ": malformed body"; }
        String bd = asStr(c.get("body_digest"));
        String id = asStr(c.get("id"));
        if (!digest.equals(bd) || !id.equals(bd)) return label + ": body digest mismatch";
        byte[] msg;
        try { msg = concat(CAP_DOMAIN, unb64(bd)); } catch (RuntimeException e) { return label + ": bad signature (not signed by expected key)"; }
        if (!verifyB64u(signer, msg, asStr(c.get("sig")))) return label + ": bad signature (not signed by expected key)";
        return "";
    }

    /** Returns "" when valid, else the failure reason. */
    static String verifyChain(List<Object> chain, String expectedRootIssuer, boolean haveIssuer) {
        if (chain.isEmpty()) return "empty chain";
        if (!(chain.get(0) instanceof Map)) return "hop 0: malformed";
        Map<String, Object> root = asMap(chain.get(0));
        if (root.containsKey("parent")) return "hop 0: root must not have a parent";
        if (haveIssuer && !Objects.equals(root.get("issuer"), expectedRootIssuer))
            return "hop 0: root issuer is not the expected principal";
        String e = checkSig(root, asStr(root.get("issuer")), "hop 0");
        if (!e.isEmpty()) return e;
        for (int i = 1; i < chain.size(); i++) {
            String label = "hop " + i;
            if (!(chain.get(i - 1) instanceof Map) || !(chain.get(i) instanceof Map)) return label + ": malformed";
            Map<String, Object> parent = asMap(chain.get(i - 1));
            Map<String, Object> c = asMap(chain.get(i));
            String ph;
            try { ph = capHash(parent); } catch (RuntimeException ex) { return label + ": broken parent link"; }
            if (!Objects.equals(c.get("parent"), ph)) return label + ": broken parent link";
            if (!Objects.equals(c.get("issuer"), parent.get("holder"))) return label + ": issuer is not the parent's bound holder";
            e = checkSig(c, asStr(parent.get("holder")), label);
            if (!e.isEmpty()) return e;
            List<Object> pc = asList(parent.get("caveats"));
            List<Object> cc = asList(c.get("caveats"));
            if (cc.size() < pc.size()) return label + ": drops parent caveat(s)";
            for (int j = 0; j < pc.size(); j++) {
                boolean same;
                try { same = hashCanonical(cc.get(j)).equals(hashCanonical(pc.get(j))); } catch (RuntimeException ex) { same = false; }
                if (!same) return label + ": caveat " + j + " altered or reordered";
            }
        }
        return "";
    }

    // ---- PCActn ----
    public static byte[] thresholdMessage(Map<String, Object> p) {
        Map<String, Object> body = new LinkedHashMap<>();
        for (Map.Entry<String, Object> en : p.entrySet())
            if (!en.getKey().equals("sig") && !en.getKey().equals("threshold")) body.put(en.getKey(), en.getValue());
        return concat(SIG_DOMAIN, sha(canonBytes(body)));
    }

    /** Checks version, capability chain, plan inclusion, leaf signature and counter. */
    public static Verdict verifyPcactnCore(Map<String, Object> pcactn, Map<String, Object> grant) {
        Verdict v = new Verdict();
        boolean[] failed = {false};
        java.util.function.BiConsumer<String, String> fail = (name, why) -> {
            failed[0] = true;
            v.checks.put(name, false);
            if (v.reason.isEmpty()) v.reason = name + ": " + why;
        };
        try {
            Object ver = pcactn.get("ver");
            if (!(ver instanceof Json.Num) || !((Json.Num) ver).raw.equals("1")) fail.accept("version", "unsupported ver");

            List<Object> chain = asList(pcactn.get("cap_chain"));
            if (chain.isEmpty()) {
                fail.accept("chain", "empty chain");
            } else {
                String rh = capHash(asMap(chain.get(0)));
                String gh = capHash(grant);
                if (!rh.equals(gh)) {
                    fail.accept("chain", "chain root is not the grant");
                } else {
                    boolean haveI = grant.get("issuer") instanceof String;
                    String why = verifyChain(chain, asStr(grant.get("issuer")), haveI);
                    if (why.isEmpty()) v.checks.put("chain", true); else fail.accept("chain", why);
                }
            }

            Map<String, Object> plan = asMap(pcactn.get("plan"));
            Map<String, Object> action = asMap(pcactn.get("action"));
            String cond = plan.get("conditions_digest") instanceof String
                ? (String) plan.get("conditions_digest") : conditionsDigest(null, null);
            String root = asStr(plan.get("root"));
            Map<String, Object> proof = asMap(plan.get("inclusion_proof"));
            boolean incl = false;
            try {
                Map<String, Object> leaf = planLeaf(plan.get("node_id"), action, cond);
                incl = verifyInclusion(root, proof, leaf);
            } catch (RuntimeException e) { incl = false; }
            if (incl) v.checks.put("plan_inclusion", true);
            else fail.accept("plan_inclusion", "action is not a node of the committed plan");

            if (!chain.isEmpty()) {
                Map<String, Object> leafCap = asMap(chain.get(chain.size() - 1));
                String holder = asStr(leafCap.get("holder"));
                byte[] msg = thresholdMessage(pcactn);
                if (pcactn.get("sig") instanceof String && verifyB64u(holder, msg, (String) pcactn.get("sig")))
                    v.checks.put("leaf_signature", true);
                else fail.accept("leaf_signature", "signature does not verify under the leaf holder key");
            } else {
                fail.accept("leaf_signature", "signature does not verify under the leaf holder key");
            }

            boolean counterOk = false;
            if (pcactn.get("counter") instanceof Json.Num) {
                try { counterOk = Long.parseLong(((Json.Num) pcactn.get("counter")).raw) >= 0; }
                catch (NumberFormatException e) { counterOk = false; }
            }
            if (counterOk) v.checks.put("counter", true);
            else fail.accept("counter", "missing or not a non-negative integer");

            v.allow = !failed[0];
        } catch (RuntimeException e) {
            v.allow = false;
            v.reason = "malformed PCActn: " + e;
        }
        return v;
    }
}

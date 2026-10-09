package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Threshold-share verification, mirroring {@code packages/pca/src/threshold.ts}. Covers the v2.1 AGENT-LEAF
 * BINDING (conformance {@code agent_leaf_binding: "2.1"}): every role's EXPLICIT share — {@code guardian},
 * {@code principal} AND (new in v2.1) {@code agent} — signs the SAME role/signer-set/threshold-bound bytes
 *
 * <pre>"atlas-pca/share/&lt;role&gt;\0" || sha256(thresholdMessage) || signerSetHash || t(1 byte) || suiteTag</pre>
 *
 * so a share cannot be replayed under another role, in a different signer set, or at a different threshold. The
 * OLD bare-threshold-message agent share (GAP 2) MUST be rejected because it does not verify over these bound
 * bytes, and a share bound to signer set A MUST be rejected against signer set B (the {@code signerSetHash}
 * binding defeats cross-signer-set replay).
 *
 * <p>Fail-closed throughout: an unknown suite, a malformed signer set, a bad base64url field, or a signature
 * that does not verify all return {@code false}; nothing in the verify path swallows an exception into a pass.
 */
public final class Threshold {
    private Threshold() {}

    static final String SIGNER_SET_DOMAIN = "atlas-pca/signerset/v1\0";
    /** Domain-separated suite tag appended for a NON-default suite; ed25519 / absent / unknown => empty. */
    static final String SHARE_SUITE_TAG = "\0atlas-pca/share-suite/v1\0";
    /** Version marker for the v2.1 agent-leaf share binding (matches {@code vectors.json.agent_leaf_binding}). */
    public static final String AGENT_LEAF_SHARE_BINDING_VERSION = "2.1";

    private static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    /**
     * {@code sha256(DOMAIN || canonical(sorted [{publicKey, role[, pq_pk]}]))}, the rows sorted bytewise by
     * {@code (role, publicKey)} so signer and verifier agree however the set is listed. ADDITIVE: a registered
     * {@code pq_pk} is carried into the bound set; an ed25519-only set hashes byte-identically to pre-agility.
     */
    static byte[] signerSetHash(List<Object> signerSet) {
        List<Object> rows = new ArrayList<>();
        for (Object o : signerSet) {
            Map<String, Object> s = Pca.asMap(o);
            Map<String, Object> row = new java.util.LinkedHashMap<>();
            row.put("publicKey", String.valueOf(s.get("publicKey")));
            row.put("role", String.valueOf(s.get("role")));
            if (s.get("pq_pk") instanceof String) row.put("pq_pk", s.get("pq_pk"));
            rows.add(row);
        }
        rows.sort((a, b) -> {
            Map<String, Object> ma = Pca.asMap(a), mb = Pca.asMap(b);
            int c = Json.compareUtf8((String) ma.get("role"), (String) mb.get("role"));
            return c != 0 ? c : Json.compareUtf8((String) ma.get("publicKey"), (String) mb.get("publicKey"));
        });
        return Pca.sha(utf8(SIGNER_SET_DOMAIN), Json.canonicalize(rows).getBytes(StandardCharsets.UTF_8));
    }

    /** Empty for ed25519 / absent / unknown, else {@code SHARE_SUITE_TAG || suite.alg}. */
    static byte[] shareSuiteTag(Object alg, boolean algPresent) {
        Pq.Suite suite = Pq.resolveSigAlg(alg, algPresent);
        if (suite == null || "ed25519".equals(suite.alg)) return new byte[0];
        return utf8(SHARE_SUITE_TAG + suite.alg);
    }

    /** The bytes a share of {@code role} signs. {@code t} MUST be 1, 2 or 3. */
    static byte[] shareMessage(String role, byte[] thresholdMessage, List<Object> signerSet, int t, Object alg, boolean algPresent) {
        if (t < 1 || t > 3) throw new IllegalArgumentException("shareMessage: t must be 1, 2 or 3");
        return Pca.concat(
            utf8("atlas-pca/share/" + role + "\0"),
            Pca.sha(thresholdMessage),
            signerSetHash(signerSet),
            new byte[] {(byte) t},
            shareSuiteTag(alg, algPresent));
    }

    /**
     * Verify a single EXPLICIT threshold share by RECOMPUTING the role/set/t-bound {@link #shareMessage} from
     * the entry (never trusting a precomputed {@code share_message}) and checking {@code share.sig} over it under
     * {@code share.publicKey} (ed25519) / {@code share.pq_pk} (PQ) per {@code share.alg}. Fail-closed; never throws.
     *
     * @param role             the binding role (the threshold_share entry's {@code role})
     * @param thresholdMessage the RAW threshold message bytes (base64url-decoded {@code threshold_message})
     * @param signerSet        the signer set the share is bound into
     * @param t                the threshold (1..3)
     * @param share            {@code {role, publicKey, sig[, alg, pq_pk, pq_sig]}}
     */
    public static boolean verifyShare(String role, byte[] thresholdMessage, List<Object> signerSet, int t, Map<String, Object> share) {
        try {
            byte[] msg = shareMessage(role, thresholdMessage, signerSet, t, share.get("alg"), share.containsKey("alg"));
            String publicKey = Pca.asStr(share.get("publicKey"));
            return Pq.verifyLeafSuite(share.get("alg"), share.containsKey("alg"), publicKey,
                share.get("pq_pk"), msg, share.get("sig"), share.get("pq_sig"));
        } catch (RuntimeException e) {
            return false; // fail-closed: a malformed share never counts as a valid one
        }
    }
}

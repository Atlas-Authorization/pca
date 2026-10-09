package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

/**
 * B4 — post-quantum crypto-agility, mirroring {@code packages/pca/src/pq.ts} (and the Go/Swift/.NET SDKs).
 *
 * <p>An ADDITIVE, backward-compatible algorithm-agility slot for the PCActn leaf signature. An absent {@code alg}
 * (or {@code alg == "ed25519"}) is BYTE-IDENTICAL to the pre-B4 wire — the signed bytes, the {@code sig} field and
 * every verdict are unchanged — so every existing conformance vector and all other SDK verifiers remain valid.
 * B4 only adds OPTIONAL post-quantum suites alongside it:
 * <ul>
 *   <li>{@code ed25519}                    classical 64-byte Ed25519 {@code sig} (unchanged).</li>
 *   <li>{@code ml-dsa-65}                  pure PQ: {@code sig} carries an ML-DSA-65 (FIPS-204) signature, verified
 *                                          under the ML-DSA public key in {@code pq_pk}.</li>
 *   <li>{@code hybrid-ed25519-ml-dsa-65}   BOTH: {@code sig} is the Ed25519 signature (under the leaf holder key,
 *                                          exactly as today) AND {@code pq_sig} is an ML-DSA-65 signature (under
 *                                          {@code pq_pk}), over the SAME canonical message; BOTH must verify.</li>
 * </ul>
 *
 * <p>{@code alg} and {@code pq_pk} are SIGNED (part of the canonical body hashed by {@code thresholdMessage}), so a
 * downgrade of the suite or a swap of the ML-DSA key invalidates every signature. {@code sig} and {@code pq_sig} are
 * the signatures themselves and are EXCLUDED from the signed body (like {@code sig} / {@code threshold}).
 *
 * <p>The ML-DSA primitive is BouncyCastle's {@code MLDSASigner} with {@code MLDSAParameters.ml_dsa_65}
 * (CRYSTALS-Dilithium / FIPS-204, 192-bit category-3 parameter set), pure variant with an EMPTY context —
 * byte-compatible with {@code @noble/post-quantum}'s {@code ml_dsa65} and circl's {@code mldsa65}. ML-DSA-65 sizes:
 * public key 1952 bytes, signature 3309 bytes.
 */
public final class Pq {
    private Pq() {}

    /** ML-DSA-65 (FIPS-204, category 3) encoded sizes, in bytes. */
    public static final int ML_DSA_65_PUBLIC_KEY_BYTES = 1952;
    public static final int ML_DSA_65_SIGNATURE_BYTES = 3309;
    /** Ed25519 signature length, in bytes (unchanged classical suite). */
    public static final int ED25519_SIGNATURE_BYTES = 64;

    /** A signature suite: the decoded {@code sig} byte length and which components / fields it requires. */
    public static final class Suite {
        public final String alg;
        public final int sigBytes;
        public final boolean hasEd25519;
        public final boolean hasMlDsa;
        public final boolean needsPqPk;
        public final boolean needsPqSig;
        Suite(String alg, int sigBytes, boolean hasEd25519, boolean hasMlDsa, boolean needsPqPk, boolean needsPqSig) {
            this.alg = alg;
            this.sigBytes = sigBytes;
            this.hasEd25519 = hasEd25519;
            this.hasMlDsa = hasMlDsa;
            this.needsPqPk = needsPqPk;
            this.needsPqSig = needsPqSig;
        }
    }

    /** The default suite used when {@code alg} is absent — the pre-B4 default. MUST stay "ed25519" forever. */
    public static final String DEFAULT_SIG_ALG = "ed25519";

    /** The closed algorithm registry. */
    static final Map<String, Suite> SUITES = new LinkedHashMap<>();
    static {
        SUITES.put("ed25519", new Suite("ed25519", ED25519_SIGNATURE_BYTES, true, false, false, false));
        SUITES.put("ml-dsa-65", new Suite("ml-dsa-65", ML_DSA_65_SIGNATURE_BYTES, false, true, true, false));
        SUITES.put("hybrid-ed25519-ml-dsa-65",
            new Suite("hybrid-ed25519-ml-dsa-65", ED25519_SIGNATURE_BYTES, true, true, true, true));
    }

    /**
     * Resolve the suite for a PCActn {@code alg} value. {@code algPresent} is false when the field is absent
     * (=> default {@code ed25519}). Returns the default or a known suite, else null (FAIL-CLOSED: caller rejects).
     */
    static Suite resolveSigAlg(Object alg, boolean algPresent) {
        if (!algPresent) return SUITES.get(DEFAULT_SIG_ALG);
        if (!(alg instanceof String)) return null;
        return SUITES.get(alg);
    }

    // ---- ML-DSA-65 verification -------------------------------------------------------------

    /** ML-DSA-65 verify over raw bytes (pure variant, empty context). Never throws; wrong length / bad input => false. */
    public static boolean mlDsa65Verify(byte[] pk, byte[] msg, byte[] sig) {
        if (pk == null || sig == null || pk.length != ML_DSA_65_PUBLIC_KEY_BYTES || sig.length != ML_DSA_65_SIGNATURE_BYTES)
            return false;
        try {
            MLDSAPublicKeyParameters pub = new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, pk);
            MLDSASigner v = new MLDSASigner(); // pure ML-DSA, empty context (matches @noble / circl)
            v.init(false, pub);
            v.update(msg, 0, msg.length);
            return v.verifySignature(sig);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** {@link #mlDsa65Verify} over base64url-encoded key and signature; false on any decoding error. */
    static boolean mlDsa65VerifyB64u(Object pkB64u, byte[] msg, Object sigB64u) {
        byte[] pk = Pca.decodeB64uStrict(pkB64u, ML_DSA_65_PUBLIC_KEY_BYTES);
        byte[] sg = Pca.decodeB64uStrict(sigB64u, ML_DSA_65_SIGNATURE_BYTES);
        if (pk == null || sg == null) return false;
        return mlDsa65Verify(pk, msg, sg);
    }

    // ---- wire-shape validation of the signature fields --------------------------------------

    /**
     * Validate the signature-carrying fields ({@code alg}, {@code sig}, {@code pq_pk}, {@code pq_sig}) per suite.
     * Returns null when well-formed, else a short reason. Strict + fail-closed:
     * unknown alg, wrong sizes, or a field not used by the suite being present, all fail.
     */
    static String validateSignatureWire(Map<String, Object> p) {
        boolean algPresent = p.containsKey("alg");
        Object algV = p.get("alg");
        if (algPresent && !(algV instanceof String)) return "'alg' must be a string";
        Suite suite = resolveSigAlg(algV, algPresent);
        if (suite == null) return "unknown signature alg '" + String.valueOf(algV) + "'";

        if (Pca.decodeB64uStrict(p.get("sig"), suite.sigBytes) == null)
            return "'sig' is not canonical base64url (" + suite.sigBytes + " bytes) for alg '" + suite.alg + "'";

        if (suite.needsPqPk) {
            if (Pca.decodeB64uStrict(p.get("pq_pk"), ML_DSA_65_PUBLIC_KEY_BYTES) == null)
                return "'pq_pk' is not canonical base64url (" + ML_DSA_65_PUBLIC_KEY_BYTES + " bytes)";
        } else if (p.containsKey("pq_pk")) {
            return "'pq_pk' must be absent for alg '" + suite.alg + "'";
        }
        if (suite.needsPqSig) {
            if (Pca.decodeB64uStrict(p.get("pq_sig"), ML_DSA_65_SIGNATURE_BYTES) == null)
                return "'pq_sig' is not canonical base64url (" + ML_DSA_65_SIGNATURE_BYTES + " bytes)";
        } else if (p.containsKey("pq_sig")) {
            return "'pq_sig' must be absent for alg '" + suite.alg + "'";
        }
        return null;
    }

    // ---- the leaf signature SEAM ------------------------------------------------------------

    /**
     * Verify the leaf signature under the PCActn's suite. The single agility seam; everything above it (the full
     * verifier) is unchanged. FAIL-CLOSED: an unknown {@code alg}, a missing component, or any invalid component
     * returns false. Never throws.
     * <ul>
     *   <li>ed25519:   Ed25519 {@code sig} under {@code holder} — byte-identical to the pre-B4 path.</li>
     *   <li>ml-dsa-65: ML-DSA-65 {@code sig} under {@code pq_pk}.</li>
     *   <li>hybrid:    Ed25519 {@code sig} under {@code holder} AND ML-DSA-65 {@code pq_sig} under {@code pq_pk},
     *                  both over {@code message}; BOTH must verify.</li>
     * </ul>
     */
    /**
     * Verify a NON-LEAF transparency/authority artifact signature (STH, revocation, beacon, bond-settlement,
     * safety-certificate, judge-verdict, software-attestation) over {@code msg} under suite {@code alg} — the
     * SAME agility seam as the leaf. {@code edPub} is the Ed25519 key, {@code pqPk} the ML-DSA key. Fail-closed.
     */
    public static boolean verifyArtifactSignature(String alg, String edPub, Object pqPk, byte[] msg, Object sig, Object pqSig) {
        return verifyLeafSuite(alg, true, edPub, pqPk, msg, sig, pqSig);
    }

    static boolean verifyLeafSuite(Object alg, boolean algPresent, String holder, Object pqPk, byte[] msg,
                                   Object sig, Object pqSig) {
        Suite suite = resolveSigAlg(alg, algPresent);
        if (suite == null) return false;
        if (!(sig instanceof String)) return false;
        String sigStr = (String) sig;
        switch (suite.alg) {
            case "ed25519":
                return Pca.verifyB64u(holder, msg, sigStr);
            case "ml-dsa-65":
                return mlDsa65VerifyB64u(pqPk, msg, sigStr);
            case "hybrid-ed25519-ml-dsa-65":
                if (!(pqSig instanceof String)) return false;
                return Pca.verifyB64u(holder, msg, sigStr) && mlDsa65VerifyB64u(pqPk, msg, (String) pqSig);
            default:
                return false;
        }
    }
}

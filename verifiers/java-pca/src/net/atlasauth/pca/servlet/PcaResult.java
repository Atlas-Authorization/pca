package net.atlasauth.pca.servlet;

import net.atlasauth.pca.Pca;

/**
 * The outcome of authorizing one request. Set by {@link PcaFilter} / the Spring interceptor as the {@code "pca"}
 * request attribute on success, and used to shape the {@code 401}/{@code 403} challenge on failure.
 *
 * <p>Immutable. {@link #verdict()} and {@link #pcactn()} are populated once a PCActn was decoded and run through the
 * verifier (outcomes {@link Outcome#ALLOW} and {@link Outcome#DENIED}); they are {@code null} for the earlier
 * failures (absent / undecodable / unknown grant) where no verdict exists yet.
 */
public final class PcaResult {

    /** Why the request was (dis)allowed, in the order the filter can decide it. */
    public enum Outcome {
        /** A PCActn decoded, resolved to a known grant, and the verifier returned allow. */
        ALLOW,
        /** No {@code PCA-Action} header and no {@code {"pcactn":...}} body: nothing to verify. 401. */
        ABSENT,
        /** A PCActn was supplied but could not be base64url/JSON decoded into an object. 401. */
        UNDECODABLE,
        /** The PCActn decoded but its {@code grant_ref} resolved to no registered capability. 401. */
        UNKNOWN_GRANT,
        /** The verifier ran and returned a denying verdict (bad audience, chain, signature, ...). 403. */
        DENIED
    }

    private final Outcome outcome;
    private final Pca.Verdict verdict;
    private final Object pcactn;
    private final String detail;

    PcaResult(Outcome outcome, Pca.Verdict verdict, Object pcactn, String detail) {
        this.outcome = outcome;
        this.verdict = verdict;
        this.pcactn = pcactn;
        this.detail = detail == null ? "" : detail;
    }

    static PcaResult of(Outcome outcome, String detail) { return new PcaResult(outcome, null, null, detail); }

    public Outcome outcome() { return outcome; }

    /** The eight-check verdict, or {@code null} if verification was never reached. */
    public Pca.Verdict verdict() { return verdict; }

    /** The decoded PCActn ({@code Map<String,Object>} tree), or {@code null} if it never decoded. */
    public Object pcactn() { return pcactn; }

    /** A short, non-secret human reason for the outcome. */
    public String detail() { return detail; }

    public boolean allowed() { return outcome == Outcome.ALLOW; }

    /** HTTP status for a non-allow outcome: {@code 403} for a denying verdict, {@code 401} otherwise. */
    public int status() { return outcome == Outcome.DENIED ? 403 : 401; }

    /** The OAuth-style {@code error} token, or {@code null} for a bare "no credentials" challenge. */
    public String error() {
        switch (outcome) {
            case UNDECODABLE: return "invalid_request";
            case UNKNOWN_GRANT: return "invalid_grant";
            case DENIED: return "insufficient_authority";
            default: return null; // ABSENT -> bare challenge
        }
    }

    /** The {@code WWW-Authenticate} value: {@code PCA realm="pca"} plus error/description when there is one. */
    public String wwwAuthenticate() {
        StringBuilder sb = new StringBuilder("PCA realm=\"pca\"");
        String err = error();
        if (err != null) {
            sb.append(", error=\"").append(err).append('"');
            String desc = description();
            if (!desc.isEmpty()) sb.append(", error_description=\"").append(quote(desc)).append('"');
        }
        return sb.toString();
    }

    /** A compact JSON error body. */
    public String jsonBody() {
        String err = error();
        StringBuilder sb = new StringBuilder("{\"error\":");
        sb.append('"').append(jsonEscape(err == null ? "pca_required" : err)).append('"');
        String desc = description();
        if (!desc.isEmpty()) sb.append(",\"error_description\":\"").append(jsonEscape(desc)).append('"');
        return sb.append('}').toString();
    }

    private String description() {
        if (outcome == Outcome.DENIED && verdict != null && verdict.reason != null && !verdict.reason.isEmpty())
            return verdict.reason;
        return detail;
    }

    /** RFC 7235 quoted-string escaping (backslash + double-quote) for a header value. */
    private static String quote(String s) { return s.replace("\\", "\\\\").replace("\"", "\\\""); }

    private static String jsonEscape(String s) {
        StringBuilder b = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }
}

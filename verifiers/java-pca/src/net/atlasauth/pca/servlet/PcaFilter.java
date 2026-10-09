package net.atlasauth.pca.servlet;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Objects;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;

/**
 * A {@link jakarta.servlet.Filter} that enforces Proof-Carrying Authority on every request it covers. It reads a
 * PCActn from the {@code PCA-Action} header (base64url(JSON)) or, failing that, a JSON body {@code {"pcactn":...}},
 * resolves its {@code grant_ref} to a root capability, and runs the existing {@link net.atlasauth.pca.Pca} verifier
 * (the eight offline checks: audience against the signed {@code aud}, cap chain rooted at the resolved grant, plan
 * inclusion, leaf signature, validity, counter, version, wire).
 *
 * <p>On allow it sets the {@code "pca"} request attribute (a {@link PcaResult} carrying the verdict and the decoded
 * PCActn) and continues the chain. On failure it writes {@code 401} (absent / undecodable / unknown grant) or
 * {@code 403} (denying verdict) with a {@code WWW-Authenticate: PCA realm="pca", ...} header and a small JSON body,
 * and does <em>not</em> continue the chain.
 *
 * <p>When the body transport is used the body is buffered so a downstream servlet can still read it.
 *
 * <p>The {@code jakarta.servlet} API is a provided/optional dependency: this class is only loaded inside a servlet
 * container that already supplies it.
 */
public final class PcaFilter implements Filter {

    /** Request attribute holding the {@link PcaResult} after a successful verify. */
    public static final String ATTRIBUTE = PcaCore.ATTRIBUTE;

    private final String audience;
    private final GrantResolver resolver;
    private final Clock clock;

    /** @param audience this resource server's audience; @param resolver grant_ref -> capability. */
    public PcaFilter(String audience, GrantResolver resolver) {
        this(audience, resolver, Clock.systemUTC());
    }

    /** @param clock the clock used for validity/skew checks (handy for tests). */
    public PcaFilter(String audience, GrantResolver resolver, Clock clock) {
        this.audience = Objects.requireNonNull(audience, "audience");
        this.resolver = Objects.requireNonNull(resolver, "resolver");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;

        String header = req.getHeader(PcaCore.HEADER);
        byte[] body = null;
        HttpServletRequest downstream = req;
        if (header == null || header.isBlank()) {
            // Only consume the body when we must; buffer it so downstream can read it again.
            body = req.getInputStream().readAllBytes();
            downstream = new CachedBodyHttpServletRequest(req, body);
        }

        PcaResult result = PcaCore.authorize(header, body, audience, clock.millis(), resolver);
        if (result.allowed()) {
            downstream.setAttribute(ATTRIBUTE, result);
            chain.doFilter(downstream, resp);
        } else {
            writeChallenge(resp, result);
        }
    }

    private static void writeChallenge(HttpServletResponse resp, PcaResult result) throws IOException {
        resp.reset();
        resp.setStatus(result.status());
        resp.setHeader("WWW-Authenticate", result.wwwAuthenticate());
        resp.setContentType("application/json;charset=UTF-8");
        byte[] out = result.jsonBody().getBytes(StandardCharsets.UTF_8);
        resp.setContentLength(out.length);
        resp.getOutputStream().write(out);
    }

    /** Wraps a request so its already-read body can be re-read by a downstream servlet. */
    private static final class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {
        private final byte[] body;

        CachedBodyHttpServletRequest(HttpServletRequest request, byte[] body) {
            super(request);
            this.body = body;
        }

        @Override
        public ServletInputStream getInputStream() {
            final ByteArrayInputStream buf = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override public boolean isFinished() { return buf.available() == 0; }
                @Override public boolean isReady() { return true; }
                @Override public void setReadListener(ReadListener listener) { throw new UnsupportedOperationException(); }
                @Override public int read() { return buf.read(); }
                @Override public int read(byte[] b, int off, int len) { return buf.read(b, off, len); }
            };
        }

        @Override
        public BufferedReader getReader() {
            Charset cs = StandardCharsets.UTF_8;
            String enc = getCharacterEncoding();
            if (enc != null) {
                try { cs = Charset.forName(enc); } catch (RuntimeException ignored) { /* keep UTF-8 */ }
            }
            return new BufferedReader(new InputStreamReader(new ByteArrayInputStream(body), cs));
        }

        @Override
        public int getContentLength() { return body.length; }

        @Override
        public long getContentLengthLong() { return body.length; }
    }
}

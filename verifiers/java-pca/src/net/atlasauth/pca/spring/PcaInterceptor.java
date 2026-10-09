package net.atlasauth.pca.spring;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Objects;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.web.servlet.HandlerInterceptor;

import net.atlasauth.pca.servlet.GrantResolver;
import net.atlasauth.pca.servlet.PcaCore;
import net.atlasauth.pca.servlet.PcaResult;

/**
 * A Spring MVC {@link HandlerInterceptor} that enforces Proof-Carrying Authority, sharing the same
 * {@link PcaCore} decision as {@link net.atlasauth.pca.servlet.PcaFilter}.
 *
 * <p>In {@code preHandle} it reads the PCActn from the {@code PCA-Action} header, resolves its {@code grant_ref},
 * and runs the existing verifier. On allow it sets the {@code "pca"} request attribute (a {@link PcaResult}) and
 * returns {@code true}; on failure it writes {@code 401}/{@code 403} with a {@code WWW-Authenticate} challenge and
 * returns {@code false}.
 *
 * <p>This interceptor uses the header transport only: it does not read the request body (reading it in
 * {@code preHandle} would consume it before a {@code @RequestBody} handler). For body-delivered PCActns register
 * {@link net.atlasauth.pca.servlet.PcaFilter}, which buffers the body.
 *
 * <p>Both {@code jakarta.servlet} and {@code spring-webmvc} are provided/optional dependencies.
 */
public final class PcaInterceptor implements HandlerInterceptor {

    public static final String ATTRIBUTE = PcaCore.ATTRIBUTE;

    private final String audience;
    private final GrantResolver resolver;
    private final Clock clock;

    public PcaInterceptor(String audience, GrantResolver resolver) {
        this(audience, resolver, Clock.systemUTC());
    }

    public PcaInterceptor(String audience, GrantResolver resolver, Clock clock) {
        this.audience = Objects.requireNonNull(audience, "audience");
        this.resolver = Objects.requireNonNull(resolver, "resolver");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        String header = request.getHeader(PcaCore.HEADER);
        PcaResult result = PcaCore.authorize(header, null, audience, clock.millis(), resolver);
        if (result.allowed()) {
            request.setAttribute(ATTRIBUTE, result);
            return true;
        }
        response.reset();
        response.setStatus(result.status());
        response.setHeader("WWW-Authenticate", result.wwwAuthenticate());
        response.setContentType("application/json;charset=UTF-8");
        byte[] out = result.jsonBody().getBytes(StandardCharsets.UTF_8);
        response.setContentLength(out.length);
        response.getOutputStream().write(out);
        return false;
    }
}

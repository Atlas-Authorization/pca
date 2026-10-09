import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import net.atlasauth.pca.Json;
import net.atlasauth.pca.servlet.GrantResolver;
import net.atlasauth.pca.servlet.PcaFilter;
import net.atlasauth.pca.servlet.PcaResult;
import net.atlasauth.pca.spring.PcaInterceptor;

/**
 * JUnit-free runner (mirrors {@code ConformanceTest}) for the PCA servlet filter + Spring interceptor. It reuses
 * the conformance-vector loader to obtain a genuinely-signed, valid PCActn and drives the middleware with
 * spring-test's MockHttpServletRequest/Response.
 *
 *   BC=~/.m2/repository/org/bouncycastle/bcprov-jdk18on/1.80/bcprov-jdk18on-1.80.jar
 *   CP="$BC:jakarta.servlet-api-6.0.0.jar:spring-web-*.jar:spring-webmvc-*.jar:spring-test-*.jar:spring-core-*.jar"
 *   javac -cp "$CP" -d out src/net/atlasauth/pca/**.java ConformanceTest.java PcaMiddlewareTest.java
 *   java  -cp "out:$CP" PcaMiddlewareTest
 */
public class PcaMiddlewareTest {
    static final String DIR = "../../conformance/";
    static int fails = 0, checks = 0;

    static void check(boolean ok, String msg) {
        checks++;
        if (!ok) { fails++; System.out.println("  FAIL: " + msg); }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> load(String name) throws Exception {
        return (Map<String, Object>) Json.parseLenient(Files.readString(Path.of(DIR + name)));
    }

    /** base64url(JSON text), unpadded — the canonical PCA-Action header encoding. */
    static String header(String pcactnJson) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(pcactnJson.getBytes(StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        Map<String, Object> doc = load("vectors.json");
        // Reuse a genuinely-signed, allow=true vector that ships its PCActn as raw strict JSON text.
        Map<String, Object> vec = null;
        for (Object x : (java.util.List<Object>) doc.get("vectors")) {
            Map<String, Object> v = (Map<String, Object>) x;
            if ("valid-raw-json-format-insensitive".equals(v.get("name"))) { vec = v; break; }
        }
        if (vec == null) throw new IllegalStateException("conformance vector not found");

        final String pcactnJson = (String) vec.get("pcactn_json");
        final Map<String, Object> grant = (Map<String, Object>) vec.get("grant");
        Map<String, Object> ctx = (Map<String, Object>) vec.get("context");
        final String aud = (String) ctx.get("aud");
        final long now = Json.asLong(ctx.get("now"));
        final Clock clock = Clock.fixed(Instant.ofEpochMilli(now), ZoneOffset.UTC);

        // The grant_ref the valid PCActn commits to.
        String grantRef = (String) ((Map<String, Object>) Json.parse(pcactnJson)).get("grant_ref");
        GrantResolver resolver = ref -> grantRef.equals(ref) ? grant : null;
        GrantResolver emptyResolver = ref -> null;

        // --- Test 1: valid header -> chain continues + attribute set ---
        {
            PcaFilter filter = new PcaFilter(aud, resolver, clock);
            MockHttpServletRequest req = new MockHttpServletRequest();
            req.addHeader("PCA-Action", header(pcactnJson));
            MockHttpServletResponse resp = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();
            filter.doFilter(req, resp, chain);

            check(chain.getRequest() != null, "valid header: chain should continue");
            check(resp.getStatus() == 200, "valid header: status stays 200, was " + resp.getStatus());
            Object attr = req.getAttribute("pca");
            check(attr instanceof PcaResult, "valid header: 'pca' attribute set");
            if (attr instanceof PcaResult) {
                PcaResult r = (PcaResult) attr;
                check(r.allowed() && r.verdict() != null && r.verdict().allow, "valid header: verdict allows");
                check(r.pcactn() instanceof Map, "valid header: pcactn attached");
            }
            System.out.println("PASS valid-header-continues");
        }

        // --- Test 2: no header (and no body) -> 401 + WWW-Authenticate, chain does NOT continue ---
        {
            PcaFilter filter = new PcaFilter(aud, resolver, clock);
            MockHttpServletRequest req = new MockHttpServletRequest();
            MockHttpServletResponse resp = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();
            filter.doFilter(req, resp, chain);

            check(chain.getRequest() == null, "no header: chain must not continue");
            check(resp.getStatus() == 401, "no header: expected 401, was " + resp.getStatus());
            String wa = resp.getHeader("WWW-Authenticate");
            check(wa != null && wa.startsWith("PCA realm=\"pca\""), "no header: WWW-Authenticate challenge, was " + wa);
            System.out.println("PASS no-header-401");
        }

        // --- Test 3: unknown grant -> 401 ---
        {
            PcaFilter filter = new PcaFilter(aud, emptyResolver, clock);
            MockHttpServletRequest req = new MockHttpServletRequest();
            req.addHeader("PCA-Action", header(pcactnJson));
            MockHttpServletResponse resp = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();
            filter.doFilter(req, resp, chain);

            check(chain.getRequest() == null, "unknown grant: chain must not continue");
            check(resp.getStatus() == 401, "unknown grant: expected 401, was " + resp.getStatus());
            check(resp.getContentAsString().contains("invalid_grant"), "unknown grant: body names invalid_grant");
            System.out.println("PASS unknown-grant-401");
        }

        // --- Test 4: wrong audience -> 403 (denying verdict) ---
        {
            PcaFilter filter = new PcaFilter("rs-wrong-audience", resolver, clock);
            MockHttpServletRequest req = new MockHttpServletRequest();
            req.addHeader("PCA-Action", header(pcactnJson));
            MockHttpServletResponse resp = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();
            filter.doFilter(req, resp, chain);

            check(chain.getRequest() == null, "wrong audience: chain must not continue");
            check(resp.getStatus() == 403, "wrong audience: expected 403, was " + resp.getStatus());
            String wa = resp.getHeader("WWW-Authenticate");
            check(wa != null && wa.contains("insufficient_authority"), "wrong audience: challenge names insufficient_authority");
            System.out.println("PASS wrong-audience-403");
        }

        // --- Test 5 (bonus): body transport {"pcactn":...} -> continues + body re-readable downstream ---
        {
            PcaFilter filter = new PcaFilter(aud, resolver, clock);
            MockHttpServletRequest req = new MockHttpServletRequest();
            byte[] body = ("{\"pcactn\":" + pcactnJson + "}").getBytes(StandardCharsets.UTF_8);
            req.setContent(body);
            req.setContentType("application/json");
            MockHttpServletResponse resp = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();
            filter.doFilter(req, resp, chain);

            check(chain.getRequest() != null, "body transport: chain should continue");
            HttpServletRequest downstream = (HttpServletRequest) chain.getRequest();
            check(downstream.getAttribute("pca") instanceof PcaResult, "body transport: 'pca' attribute set");
            byte[] reread = downstream.getInputStream().readAllBytes();
            check(java.util.Arrays.equals(reread, body), "body transport: body still readable downstream");
            System.out.println("PASS body-transport-continues");
        }

        // --- Test 6 (bonus): Spring interceptor, valid header -> true + attribute set ---
        {
            PcaInterceptor interceptor = new PcaInterceptor(aud, resolver, clock);
            MockHttpServletRequest req = new MockHttpServletRequest();
            req.addHeader("PCA-Action", header(pcactnJson));
            MockHttpServletResponse resp = new MockHttpServletResponse();
            boolean proceed = interceptor.preHandle(req, resp, new Object());
            check(proceed, "interceptor valid header: preHandle returns true");
            check(req.getAttribute("pca") instanceof PcaResult, "interceptor valid header: 'pca' attribute set");

            // and denies on wrong audience
            PcaInterceptor bad = new PcaInterceptor("rs-wrong-audience", resolver, clock);
            MockHttpServletRequest req2 = new MockHttpServletRequest();
            req2.addHeader("PCA-Action", header(pcactnJson));
            MockHttpServletResponse resp2 = new MockHttpServletResponse();
            boolean proceed2 = bad.preHandle(req2, resp2, new Object());
            check(!proceed2 && resp2.getStatus() == 403, "interceptor wrong audience: 403 + preHandle false");
            System.out.println("PASS spring-interceptor");
        }

        System.out.println(checks + " assertions, " + fails + " failures");
        System.exit(fails == 0 ? 0 : 1);
    }
}

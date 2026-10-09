package net.atlasauth.pca.servlet;

import java.util.Map;

/**
 * Resolves a PCActn {@code grant_ref} (canonical base64url, the content address of the root capability) to the
 * capability object that must sit at the root of the cap chain, or {@code null} when the grant is unknown.
 *
 * <p>A capability is represented exactly as the verifier consumes it: a decoded JSON object
 * ({@code Map<String, Object>}, the shape produced by {@link net.atlasauth.pca.Json#parse}). Returning {@code null}
 * (an unknown grant) makes {@link PcaFilter} answer {@code 401}; it is never an allow.
 */
@FunctionalInterface
public interface GrantResolver {
    /**
     * @param grantRef the PCActn's {@code grant_ref} value (never null, but may be any attacker-supplied string)
     * @return the root capability for that reference, or {@code null} if no such grant is registered
     */
    Map<String, Object> resolve(String grantRef);
}

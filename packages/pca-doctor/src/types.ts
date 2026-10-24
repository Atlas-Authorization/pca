/** pca-doctor result and configuration types. */

export type CheckStatus = 'pass' | 'warn' | 'fail' | 'skip';

export interface CheckResult {
  /** Stable id, e.g. `clock`, `store.atomicity`. */
  id: string;
  status: CheckStatus;
  /** What was observed (or why nothing could be). */
  detail: string;
  /** What to do about a warn / fail. */
  remediation?: string;
  /** Raw observations for --json. */
  observed?: Record<string, unknown>;
}

export type ProxyHeader = 'x-forwarded-for' | 'forwarded' | 'x-real-ip';

export interface DoctorConfig {
  /** Base URL of the live deployment (the API that verifies PCActns). */
  url?: string;
  clock?: {
    /** HTTPS URL whose Date header is the reference, or 'local' for this machine's clock. Default https://www.google.com/generate_204. */
    referenceUrl?: string;
    /** Fail beyond this skew (default PCACTN_MAX_SKEW_MS = 60 s). */
    maxSkewMs?: number;
    /** Warn beyond this fraction of maxSkewMs (default 0.25). */
    warnFraction?: number;
    /** Per-request timeout (default 10 s). */
    timeoutMs?: number;
  };
  store?: {
    /** Adapter module path or builtin:<name> (the store conformance kit's adapter interface). */
    adapter?: string;
    options?: Record<string, string>;
    /** Concurrent clients for the conflicting-write probe (default 32). */
    concurrency?: number;
    /** Same-key rounds (default 10). */
    rounds?: number;
  };
  proxy?: {
    /** The deployment's TRUSTED_PROXY_COUNT. */
    trustedProxyCount?: number;
    /** The deployment's TRUSTED_PROXY_HEADER (default x-forwarded-for). */
    header?: ProxyHeader;
    /** How many reverse proxies really sit in front of the API and append to the header (operator's statement). */
    hops?: number;
    /** Send forged forwarding headers to the live URL and watch the rate-limit bucket (default true when url is set). */
    probe?: boolean;
    /** A public, rate-limited path on the deployment (default /v1/pca/suites). */
    probePath?: string;
  };
  verifier?: {
    /** The verifier's allowedSuites option (absent = unset). */
    allowedSuites?: string[];
    /** The verifier's pqPins (issuer Ed25519 identity -> PQ public key, base64url). */
    pqPins?: Record<string, string>;
    /** The verifier supplies its stored root grant as trustedRoot (verifyPCActnCore / requirePCA do). */
    trustedRoot?: boolean;
    allowUnboundPq?: boolean;
    /** requirePCA's insecureAllowUnenforced. */
    insecureAllowUnenforced?: boolean;
    /** requirePCA's `require` list (absent = the defaults). */
    require?: string[];
    /** Directory of the deployed application, to load ITS installed @atlasauth/pca (default: the doctor's own). */
    pcaDir?: string;
  };
}

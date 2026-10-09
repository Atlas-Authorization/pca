package net.atlasauth.pca;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * JSON for PCA wire format v2: a hand-written RFC 8259 parser in two profiles (numbers kept exact as {@link Num})
 * plus the canonical serializers (lenient for content addressing, STRICT for the signed PCActn body).
 *
 * <p>{@link #parse} is the STRICT profile (normative for signed bytes): rejects comments, trailing commas, BOM,
 * non-JSON whitespace, duplicate keys (after unescaping), lone surrogates (raw or escaped), raw control characters
 * in strings, unknown escapes, nesting deeper than {@link #MAX_DEPTH}, input longer than {@link #MAX_CHARS}
 * UTF-8 bytes, and any number not in the canonical wire form (see {@link #numberError}).
 * {@link #parseLenient} accepts any RFC 8259 text and is ONLY for trusted fixtures (conformance files).
 */
public final class Json {
    private Json() {}

    public static final int MAX_DEPTH = 32;
    public static final int MAX_CHARS = 1 << 20;
    public static final int MAX_DECIMAL_DIGITS = 15;
    private static final BigInteger MAX_SAFE = BigInteger.valueOf(9007199254740991L);
    private static final BigDecimal MIN_DECIMAL = new BigDecimal("0.000001");
    private static final Pattern LEXEME = Pattern.compile("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?");

    /** A JSON number kept as its source text (like Go's json.Number). */
    public static final class Num {
        public final String raw;
        public Num(String raw) { this.raw = raw; }
        @Override public String toString() { return raw; }
    }

    // ---- number profile ----
    /**
     * Strict-profile check of a number lexeme. Returns null when canonical, else a reason. Canonical: integers are
     * safe integers (|n| &lt;= 2^53-1, no -0); non-integers are plain decimal (no exponent, no trailing fractional
     * zero), at most 15 significant digits, magnitude &gt;= 1e-6. (Leading +, leading zeros, ".5", "5." fail the
     * lexeme grammar.)
     */
    public static String numberError(String raw) {
        if (raw == null || !LEXEME.matcher(raw).matches()) return "malformed number";
        if (raw.indexOf('e') >= 0 || raw.indexOf('E') >= 0) return "exponent form is not allowed";
        if (raw.equals("-0")) return "negative zero is not allowed";
        if (raw.indexOf('.') >= 0) {
            if (raw.endsWith("0")) return "trailing fractional zero is not canonical";
            String digits = raw.replace("-", "").replace(".", "");
            int z = 0;
            while (z < digits.length() && digits.charAt(z) == '0') z++;
            if (digits.length() - z > MAX_DECIMAL_DIGITS) return "more than 15 significant digits";
            BigDecimal v = new BigDecimal(raw).abs();
            if (v.signum() != 0 && v.compareTo(MIN_DECIMAL) < 0) return "non-integer magnitude below 1e-6";
            return null;
        }
        String abs = raw.startsWith("-") ? raw.substring(1) : raw;
        if (abs.length() > 16 || new BigInteger(abs).compareTo(MAX_SAFE) > 0) return "integer outside the safe range";
        return null;
    }

    /** True iff the value is a strict-profile safe integer (a {@link Num} integer lexeme, Integer or Long). */
    public static boolean isSafeInt(Object o) {
        if (o instanceof Num) {
            String r = ((Num) o).raw;
            return numberError(r) == null && r.indexOf('.') < 0;
        }
        if (o instanceof Integer) return true;
        if (o instanceof Long) { long l = (Long) o; return Math.abs(l) <= 9007199254740991L; }
        return false;
    }

    /** True iff the value is a strict-profile number (integer or plain decimal). */
    public static boolean isStrictNumber(Object o) {
        if (o instanceof Num) return numberError(((Num) o).raw) == null;
        return isSafeInt(o);
    }

    /** Value of a safe integer (call only after {@link #isSafeInt}). */
    public static long asLong(Object o) {
        if (o instanceof Num) return Long.parseLong(((Num) o).raw);
        return ((Number) o).longValue();
    }

    /** Exact decimal value of a strict number. */
    public static BigDecimal asDecimal(Object o) {
        if (o instanceof Num) return new BigDecimal(((Num) o).raw);
        return BigDecimal.valueOf(((Number) o).longValue());
    }

    public static boolean hasLoneSurrogate(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) i++;
                else return true;
            } else if (Character.isLowSurrogate(c)) return true;
        }
        return false;
    }

    // ---- parser ----
    /** STRICT profile. Throws IllegalArgumentException on any deviation. */
    public static Object parse(String s) { return new Parser(s, true).top(); }

    /** Lenient RFC 8259 (fixtures only): duplicate keys / lone surrogates / any number allowed. */
    public static Object parseLenient(String s) { return new Parser(s, false).top(); }

    private static boolean dig(char c) { return c >= '0' && c <= '9'; }

    private static final class Parser {
        final String s;
        final boolean strict;
        int i = 0;
        Parser(String s, boolean strict) { this.s = s; this.strict = strict; }

        Object top() {
            if (s == null) throw new IllegalArgumentException("input is not a string");
            if (strict && (s.length() > MAX_CHARS || s.getBytes(StandardCharsets.UTF_8).length > MAX_CHARS)) throw new IllegalArgumentException("input too large");
            ws();
            Object v = value(1);
            ws();
            if (i != s.length()) throw err("trailing data");
            return v;
        }

        void ws() {
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++; else break;
            }
        }

        IllegalArgumentException err(String m) { return new IllegalArgumentException(m + " at " + i); }

        Object value(int depth) {
            if (i >= s.length()) throw err("unexpected end");
            char c = s.charAt(i);
            switch (c) {
                case '{': return object(depth);
                case '[': return array(depth);
                case '"': return string();
                case 't': lit("true"); return Boolean.TRUE;
                case 'f': lit("false"); return Boolean.FALSE;
                case 'n': lit("null"); return null;
                default: return number();
            }
        }

        void lit(String w) {
            if (!s.startsWith(w, i)) throw err("bad literal");
            i += w.length();
        }

        Map<String, Object> object(int depth) {
            if (strict && depth > MAX_DEPTH) throw err("nesting too deep");
            Map<String, Object> m = new LinkedHashMap<>();
            i++; ws();
            if (i < s.length() && s.charAt(i) == '}') { i++; return m; }
            while (true) {
                ws();
                if (i >= s.length() || s.charAt(i) != '"') throw err("expected key");
                String k = string();
                if (strict && m.containsKey(k)) throw err("duplicate key");
                ws();
                if (i >= s.length() || s.charAt(i) != ':') throw err("expected ':'");
                i++; ws();
                m.put(k, value(depth + 1));
                ws();
                if (i >= s.length()) throw err("unterminated object");
                char c = s.charAt(i++);
                if (c == '}') return m;
                if (c != ',') throw err("expected ',' or '}'");
            }
        }

        List<Object> array(int depth) {
            if (strict && depth > MAX_DEPTH) throw err("nesting too deep");
            List<Object> l = new ArrayList<>();
            i++; ws();
            if (i < s.length() && s.charAt(i) == ']') { i++; return l; }
            while (true) {
                ws();
                l.add(value(depth + 1));
                ws();
                if (i >= s.length()) throw err("unterminated array");
                char c = s.charAt(i++);
                if (c == ']') return l;
                if (c != ',') throw err("expected ',' or ']'");
            }
        }

        int hex4() {
            if (i + 4 > s.length()) throw err("bad \\u escape");
            int v = 0;
            for (int k = 0; k < 4; k++) {
                int d = Character.digit(s.charAt(i + k), 16);
                char ch = s.charAt(i + k);
                boolean ascii = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
                if (!ascii || d < 0) throw err("bad \\u escape");
                v = v * 16 + d;
            }
            i += 4;
            return v;
        }

        String string() {
            StringBuilder sb = new StringBuilder();
            i++;
            while (true) {
                if (i >= s.length()) throw err("unterminated string");
                char c = s.charAt(i++);
                if (c == '"') break;
                if (c < 0x20) throw err("control char in string");
                if (c != '\\') { sb.append(c); continue; }
                if (i >= s.length()) throw err("bad escape");
                char e = s.charAt(i++);
                switch (e) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'u': sb.append((char) hex4()); break;
                    default: throw err("bad escape");
                }
            }
            String out = sb.toString();
            if (strict && hasLoneSurrogate(out)) throw err("lone surrogate in string");
            return out;
        }

        Num number() {
            int st = i;
            if (i < s.length() && s.charAt(i) == '-') i++;
            if (i >= s.length()) throw err("bad number");
            char c = s.charAt(i);
            if (c == '0') i++;
            else if (c >= '1' && c <= '9') { while (i < s.length() && dig(s.charAt(i))) i++; }
            else throw err("bad number");
            if (i < s.length() && s.charAt(i) == '.') {
                i++;
                int fs = i;
                while (i < s.length() && dig(s.charAt(i))) i++;
                if (i == fs) throw err("bad number");
            }
            if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                i++;
                if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
                int es = i;
                while (i < s.length() && dig(s.charAt(i))) i++;
                if (i == es) throw err("bad number");
            }
            String raw = s.substring(st, i);
            if (strict) {
                String e = numberError(raw);
                if (e != null) throw err(e);
            }
            return new Num(raw);
        }
    }

    // ---- canonical serializers ----
    /** LENIENT canonical form (content addressing: capabilities, Merkle leaves). Keys in UTF-8 bytewise order. */
    public static String canonicalize(Object v) {
        StringBuilder sb = new StringBuilder();
        ser(sb, v, false, 1);
        return sb.toString();
    }

    /**
     * STRICT canonical form of a signed PCActn body (wire v2). Additionally throws IllegalArgumentException on:
     * non-canonical numbers, lone surrogates in strings or keys, nesting deeper than 32, unsupported types.
     */
    public static String canonicalizeStrict(Object v) {
        StringBuilder sb = new StringBuilder();
        ser(sb, v, true, 1);
        return sb.toString();
    }

    /** Bytewise UTF-8 comparison of two strings (== Unicode code point order). */
    static int compareUtf8(String a, String b) {
        return Arrays.compareUnsigned(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static void jsString(StringBuilder sb, String s, boolean strict) {
        if (strict && hasLoneSurrogate(s)) throw new IllegalArgumentException("canonicalize: lone surrogate in string");
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else if (Character.isHighSurrogate(c)) {
                        if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                            sb.append(c).append(s.charAt(++i));
                        } else sb.append('�');
                    } else if (Character.isLowSurrogate(c)) {
                        sb.append('�'); // lenient only (strict rejected above)
                    } else sb.append(c);
            }
        }
        sb.append('"');
    }

    /** Lenient number formatting: canonical lexemes are already the shortest round-trip form. */
    static String fmtNumber(String raw) {
        if (numberError(raw) == null) return raw;
        double f;
        try { f = new BigDecimal(raw).doubleValue(); } catch (NumberFormatException e) {
            throw new IllegalArgumentException("canonicalize: non-finite number");
        }
        if (Double.isInfinite(f) || Double.isNaN(f)) throw new IllegalArgumentException("canonicalize: non-finite number");
        if (f == 0) return "0";
        return new BigDecimal(Double.toString(f)).stripTrailingZeros().toPlainString();
    }

    @SuppressWarnings("unchecked")
    private static void ser(StringBuilder sb, Object v, boolean strict, int depth) {
        if (v == null) sb.append("null");
        else if (v instanceof Boolean) sb.append(((Boolean) v) ? "true" : "false");
        else if (v instanceof String) jsString(sb, (String) v, strict);
        else if (v instanceof Num) {
            String raw = ((Num) v).raw;
            if (strict) {
                String e = numberError(raw);
                if (e != null) throw new IllegalArgumentException("canonicalize: " + e);
                sb.append(raw);
            } else sb.append(fmtNumber(raw));
        } else if (v instanceof Integer || v instanceof Long) {
            if (strict && !isSafeInt(v)) throw new IllegalArgumentException("canonicalize: integer outside the safe range");
            sb.append(v.toString());
        } else if (v instanceof List) {
            if (strict && depth > MAX_DEPTH) throw new IllegalArgumentException("canonicalize: nesting too deep");
            sb.append('[');
            boolean first = true;
            for (Object x : (List<Object>) v) {
                if (!first) sb.append(',');
                first = false;
                ser(sb, x, strict, depth + 1);
            }
            sb.append(']');
        } else if (v instanceof Map) {
            if (strict && depth > MAX_DEPTH) throw new IllegalArgumentException("canonicalize: nesting too deep");
            Map<String, Object> m = (Map<String, Object>) v;
            List<String> keys = new ArrayList<>(m.keySet());
            keys.sort(Json::compareUtf8);
            sb.append('{');
            boolean first = true;
            for (String k : keys) {
                if (!first) sb.append(',');
                first = false;
                jsString(sb, k, strict);
                sb.append(':');
                ser(sb, m.get(k), strict, depth + 1);
            }
            sb.append('}');
        } else throw new IllegalArgumentException("canonicalize: unsupported type " + v.getClass());
    }
}

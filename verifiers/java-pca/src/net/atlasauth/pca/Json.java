package net.atlasauth.pca;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Tiny JSON parser (numbers kept exact as {@link Num}) + canonical serializer. */
public final class Json {
    private Json() {}

    /** A JSON number kept as its source text (like Go's json.Number). */
    public static final class Num {
        public final String raw;
        public Num(String raw) { this.raw = raw; }
        @Override public String toString() { return raw; }
    }

    // ---- parser ----
    public static Object parse(String s) {
        Parser p = new Parser(s);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i != s.length()) throw new IllegalArgumentException("trailing data at " + p.i);
        return v;
    }

    private static final class Parser {
        final String s;
        int i = 0;
        Parser(String s) { this.s = s; }

        void ws() {
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++; else break;
            }
        }

        IllegalArgumentException err(String m) { return new IllegalArgumentException(m + " at " + i); }

        Object value() {
            if (i >= s.length()) throw err("unexpected end");
            char c = s.charAt(i);
            switch (c) {
                case '{': return object();
                case '[': return array();
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

        Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<>();
            i++; ws();
            if (i < s.length() && s.charAt(i) == '}') { i++; return m; }
            while (true) {
                ws();
                if (i >= s.length() || s.charAt(i) != '"') throw err("expected key");
                String k = string();
                ws();
                if (i >= s.length() || s.charAt(i) != ':') throw err("expected ':'");
                i++; ws();
                m.put(k, value());
                ws();
                if (i >= s.length()) throw err("unterminated object");
                char c = s.charAt(i++);
                if (c == '}') return m;
                if (c != ',') throw err("expected ',' or '}'");
            }
        }

        List<Object> array() {
            List<Object> l = new ArrayList<>();
            i++; ws();
            if (i < s.length() && s.charAt(i) == ']') { i++; return l; }
            while (true) {
                ws();
                l.add(value());
                ws();
                if (i >= s.length()) throw err("unterminated array");
                char c = s.charAt(i++);
                if (c == ']') return l;
                if (c != ',') throw err("expected ',' or ']'");
            }
        }

        String string() {
            StringBuilder sb = new StringBuilder();
            i++;
            while (true) {
                if (i >= s.length()) throw err("unterminated string");
                char c = s.charAt(i++);
                if (c == '"') return sb.toString();
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
                    case 'u':
                        if (i + 4 > s.length()) throw err("bad \\u escape");
                        sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                        break;
                    default: throw err("bad escape");
                }
            }
        }

        Num number() {
            int st = i;
            if (i < s.length() && s.charAt(i) == '-') i++;
            int ds = i;
            while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
            if (i == ds) throw err("bad number");
            if (i < s.length() && s.charAt(i) == '.') {
                i++;
                int fs = i;
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
                if (i == fs) throw err("bad number");
            }
            if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                i++;
                if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
                int es = i;
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
                if (i == es) throw err("bad number");
            }
            return new Num(s.substring(st, i));
        }
    }

    // ---- canonical serializer ----
    /** Keys sorted by UTF-16 code units (String.compareTo), compact, JS JSON string escaping. */
    public static String canonicalize(Object v) {
        StringBuilder sb = new StringBuilder();
        ser(sb, v);
        return sb.toString();
    }

    private static void jsString(StringBuilder sb, String s) {
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
                        sb.append('�'); // lone surrogate -> U+FFFD (matches Go)
                    } else sb.append(c);
            }
        }
        sb.append('"');
    }

    static String fmtNumber(String raw) {
        double f;
        try { f = new BigDecimal(raw).doubleValue(); } catch (NumberFormatException e) {
            throw new IllegalArgumentException("canonicalize: non-finite number");
        }
        if (Double.isInfinite(f) || Double.isNaN(f)) throw new IllegalArgumentException("canonicalize: non-finite number");
        if (f == 0) return "0";
        return new BigDecimal(Double.toString(f)).stripTrailingZeros().toPlainString();
    }

    @SuppressWarnings("unchecked")
    private static void ser(StringBuilder sb, Object v) {
        if (v == null) sb.append("null");
        else if (v instanceof Boolean) sb.append(((Boolean) v) ? "true" : "false");
        else if (v instanceof String) jsString(sb, (String) v);
        else if (v instanceof Num) sb.append(fmtNumber(((Num) v).raw));
        else if (v instanceof Integer || v instanceof Long) sb.append(v.toString());
        else if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object x : (List<Object>) v) {
                if (!first) sb.append(',');
                first = false;
                ser(sb, x);
            }
            sb.append(']');
        } else if (v instanceof Map) {
            Map<String, Object> m = (Map<String, Object>) v;
            List<String> keys = new ArrayList<>(m.keySet());
            keys.sort(String::compareTo); // UTF-16 code unit order
            sb.append('{');
            boolean first = true;
            for (String k : keys) {
                if (!first) sb.append(',');
                first = false;
                jsString(sb, k);
                sb.append(':');
                ser(sb, m.get(k));
            }
            sb.append('}');
        } else throw new IllegalArgumentException("canonicalize: unsupported type " + v.getClass());
    }
}

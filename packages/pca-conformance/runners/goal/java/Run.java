// Java runner for the pca-goal vectors (goals and selector goals): goal digest, lowered policy digest, decision + witness of every
// probe, the fn vectors, and the native expansion of the trait selectors for `sel` vectors. Independent port of the reference
// semantics (adversarial/src/oracle.ts); no dependencies. Usage: java Run.java <vectors-dir>
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Collectors;

public final class Run {
    // ---------------------------------------------------------------- JSON (objects -> LinkedHashMap, arrays -> ArrayList, ints -> Long)
    static final class P {
        final String s; int i;
        P(String s) { this.s = s; }
        void ws() { while (i < s.length() && " \t\r\n".indexOf(s.charAt(i)) >= 0) i++; }
        Object val() {
            ws();
            char c = s.charAt(i);
            if (c == '{') {
                i++; Map<String, Object> m = new LinkedHashMap<>(); ws();
                if (s.charAt(i) == '}') { i++; return m; }
                while (true) { ws(); String k = str(); ws(); i++; m.put(k, val()); ws(); if (s.charAt(i++) == '}') return m; }
            }
            if (c == '[') {
                i++; List<Object> l = new ArrayList<>(); ws();
                if (s.charAt(i) == ']') { i++; return l; }
                while (true) { l.add(val()); ws(); if (s.charAt(i++) == ']') return l; }
            }
            if (c == '"') return str();
            if (s.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
            if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
            if (s.startsWith("null", i)) { i += 4; return null; }
            int j = i; while (j < s.length() && "-0123456789".indexOf(s.charAt(j)) >= 0) j++;
            Long n = Long.parseLong(s.substring(i, j)); i = j; return n;
        }
        String str() {
            StringBuilder b = new StringBuilder(); i++;
            while (true) {
                char c = s.charAt(i++);
                if (c == '"') return b.toString();
                if (c != '\\') { b.append(c); continue; }
                char e = s.charAt(i++);
                switch (e) {
                    case 'n': b.append('\n'); break; case 't': b.append('\t'); break; case 'r': b.append('\r'); break;
                    case 'b': b.append('\b'); break; case 'f': b.append('\f'); break;
                    case 'u': b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; break;
                    default: b.append(e);
                }
            }
        }
    }
    @SuppressWarnings("unchecked") static Map<String, Object> M(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> L(Object o) { return (List<Object>) o; }
    static String S(Object o) { return (String) o; }
    static long N(Object o) { return (Long) o; }
    static Map<String, Object> m(Object... kv) { Map<String, Object> r = new LinkedHashMap<>(); for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]); return r; }
    static Map<String, Object> merge(Map<String, Object> a, Object... kv) { Map<String, Object> r = new LinkedHashMap<>(a); for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]); return r; }
    static List<Object> list(Collection<?> c) { return new ArrayList<>(c); }

    // ---------------------------------------------------------------- canonical JSON / digests
    static String canon(Object v) {
        if (v == null) return "null";
        if (v instanceof Boolean || v instanceof Long || v instanceof Integer) return v.toString();
        if (v instanceof String) {
            StringBuilder o = new StringBuilder("\"");
            String s = (String) v;
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c == '"') o.append("\\\""); else if (c == '\\') o.append("\\\\");
                else if (c == 8) o.append("\\b"); else if (c == 9) o.append("\\t"); else if (c == 10) o.append("\\n");
                else if (c == 12) o.append("\\f"); else if (c == 13) o.append("\\r");
                else if (c < 0x20) o.append(String.format("\\u%04x", (int) c)); else o.append(c);
            }
            return o.append('"').toString();
        }
        if (v instanceof List) return "[" + L(v).stream().map(Run::canon).collect(Collectors.joining(",")) + "]";
        Map<String, Object> mm = M(v);
        List<String> ks = new ArrayList<>(mm.keySet());
        ks.sort((a, b) -> Arrays.compareUnsigned(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8)));
        return "{" + ks.stream().map(k -> canon(k) + ":" + canon(mm.get(k))).collect(Collectors.joining(",")) + "}";
    }
    static String b64(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }
    static byte[] sha(String s) { try { return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)); } catch (Exception e) { throw new RuntimeException(e); } }
    static String hashCanon(Object v) { return b64(sha(canon(v))); }
    static String goalDigest(Object g) { return hashCanon(m("d", "atlas-pca/goal-ir/v1", "goal", g)); }

    // ---------------------------------------------------------------- semantics
    static int kNot(int a) { return 2 - a; }
    static int b2k(boolean b) { return b ? 2 : 0; }
    static boolean sameUnit(Object a, Object b) { return canon(a).equals(canon(b)); }
    static int eqV(Map<String, Object> x, Map<String, Object> y) {
        String k = S(x.get("k"));
        if (k.equals("q")) return S(y.get("k")).equals("q") && sameUnit(M(x.get("q")).get("u"), M(y.get("q")).get("u")) ? b2k(N(M(x.get("q")).get("n")) == N(M(y.get("q")).get("n"))) : 1;
        if (k.equals("s")) return S(y.get("k")).equals("s") ? b2k(S(x.get("s")).equals(S(y.get("s")))) : 1;
        return 1;
    }
    static int ltV(Map<String, Object> x, Map<String, Object> y) {
        return S(x.get("k")).equals("q") && S(y.get("k")).equals("q") && sameUnit(M(x.get("q")).get("u"), M(y.get("q")).get("u")) ? b2k(N(M(x.get("q")).get("n")) < N(M(y.get("q")).get("n"))) : 1;
    }
    static int cmp(String op, Map<String, Object> x, Map<String, Object> y) {
        if (x == null || y == null) return 1;
        switch (op) {
            case "eq": return eqV(x, y);
            case "ne": return kNot(eqV(x, y));
            case "lt": return ltV(x, y);
            case "gte": return kNot(ltV(x, y));
            case "gt": return ltV(y, x);
            case "lte": return kNot(ltV(y, x));
        }
        int t = 1;
        if (S(y.get("k")).equals("set")) { t = 0; for (Object it : L(y.get("items"))) t = Math.max(t, eqV(x, M(it))); }
        return op.equals("in") ? t : kNot(t);
    }
    static Map<String, Object> term(Map<String, Object> t, Map<String, Object> a, Map<String, Object> h) {
        switch (S(t.get("k"))) {
            case "param": return M(M(a.get("params")).get(S(t.get("path"))));
            case "lit": return M(t.get("v"));
            default: { Object q = M(h.get("aggs")).get(S(t.get("bid"))); return q == null ? null : m("k", "q", "q", q); }
        }
    }
    static int cond(Map<String, Object> c, Map<String, Object> a, Map<String, Object> h) {
        switch (S(c.get("k"))) {
            case "true": return 2;
            case "cmp": return cmp(S(c.get("op")), term(M(c.get("l")), a, h), term(M(c.get("r")), a, h));
            case "and": return Math.min(cond(M(c.get("a")), a, h), cond(M(c.get("b")), a, h));
            case "or": return Math.max(cond(M(c.get("a")), a, h), cond(M(c.get("b")), a, h));
            default: return kNot(cond(M(c.get("c")), a, h));
        }
    }
    static List<Object> partIds(Map<String, Object> o, Map<String, Object> p) {
        String k = S(p.get("k"));
        if (k.equals("exact")) return new ArrayList<>(List.of(p.get("id")));
        if (k.equals("oneof")) return L(p.get("ids"));
        for (Object r : L(o.get("rels"))) if (M(r).get("rel").equals(p.get("rel")) && M(r).get("anchor").equals(p.get("anchor"))) return L(M(r).get("members"));
        return new ArrayList<>();
    }
    /** null = every resource */
    static List<Object> resolve(Map<String, Object> o, Map<String, Object> s) {
        if (S(s.get("k")).equals("any")) return null;
        if (!S(s.get("k")).equals("all_of")) return partIds(o, s);
        List<Object> acc = null;
        List<Object> parts = L(s.get("parts"));
        for (int i = parts.size() - 1; i >= 0; i--) {
            List<Object> ids = partIds(o, M(parts.get(i)));
            if (acc == null) acc = ids; else { List<Object> prev = acc; acc = ids.stream().filter(prev::contains).collect(Collectors.toList()); }
        }
        return acc;
    }
    static boolean resOk(List<Object> p, Object r) { return p == null || p.contains(r); }
    static List<Object> verbsOfClass(Map<String, Object> o, String cls) {
        return L(o.get("verbs")).stream().filter(v -> M(v).get("cls").equals(cls)).map(v -> M(v).get("verb")).collect(Collectors.toList());
    }
    static List<Object> prohVerbs(Map<String, Object> o, Map<String, Object> p) {
        Map<String, Object> t = M(p.get("target"));
        return S(t.get("k")).equals("verb") ? new ArrayList<>(List.of(t.get("verb"))) : verbsOfClass(o, S(t.get("cls")));
    }
    static List<List<Object>> lsel(Map<String, Object> o, Map<String, Object> b) {
        Map<String, Object> s = M(b.get("sel"));
        return S(s.get("k")).equals("gids") ? List.of(L(s.get("gids")), new ArrayList<>()) : List.of(new ArrayList<>(), verbsOfClass(o, S(s.get("cls"))));
    }
    static boolean applies(List<List<Object>> s, Object gid, Object verb) { return s.get(0).contains(gid) || s.get(1).contains(verb); }
    static boolean inScope(Map<String, Object> b, Map<String, Object> a, Map<String, Object> x) {
        Map<String, Object> s = M(b.get("scope"));
        switch (S(s.get("k"))) {
            case "session": return a.get("sess").equals(x.get("sess"));
            case "principal": return a.get("prin").equals(x.get("prin"));
            case "org": return a.get("org").equals(x.get("org"));
            default: return L(s.get("agents")).contains(a.get("agent")) && L(s.get("agents")).contains(x.get("agent"));
        }
    }
    static boolean inWindow(Map<String, Object> w, Map<String, Object> a, Map<String, Object> x) {
        long at = N(a.get("t")), xt = N(x.get("t"));
        switch (S(w.get("k"))) {
            case "sliding": return at - N(w.get("ms")) < xt && xt <= at;
            case "period": { long ms = N(w.get("ms")), t0 = N(w.get("t0")); return ms > 0 && Math.floorDiv(at - t0, ms) == Math.floorDiv(xt - t0, ms); }
            default: return true;
        }
    }
    static int exceeded(Map<String, Object> b, List<List<Object>> s, Map<String, Object> a, Map<String, Object> h) {
        List<Map<String, Object>> items = new ArrayList<>();
        for (Object mm : L(h.get("adms"))) {
            Map<String, Object> act = M(M(mm).get("act"));
            if (applies(s, M(mm).get("gid"), act.get("verb")) && inScope(b, a, act) && inWindow(M(b.get("window")), a, act)) items.add(act);
        }
        items.add(a);
        long cap = N(M(b.get("cap")).get("n"));
        String agg = S(b.get("agg"));
        if (agg.equals("count")) return b2k(items.size() > cap);
        if (agg.equals("distinct")) {
            Set<String> vs = new HashSet<>();
            for (Map<String, Object> x : items) { Map<String, Object> ps = M(x.get("params")); if (!ps.containsKey(S(b.get("key")))) return 1; vs.add(canon(ps.get(S(b.get("key"))))); }
            return b2k(vs.size() > cap);
        }
        long sum = 0, mx = Long.MIN_VALUE;
        for (Map<String, Object> x : items) {
            Map<String, Object> v = term(M(b.get("value")), x, h);
            if (v == null || !S(v.get("k")).equals("q") || !sameUnit(M(v.get("q")).get("u"), M(b.get("cap")).get("u"))) return 1;
            long n = N(M(v.get("q")).get("n")); sum += n; mx = Math.max(mx, n);
        }
        return b2k((agg.equals("sum") ? sum : mx) > cap);
    }
    static int boundDec(Map<String, Object> b, List<List<Object>> s, Map<String, Object> a, Map<String, Object> h) {
        int e = exceeded(b, s, a, h);
        return e == 2 ? (S(b.get("onExceed")).equals("deny") ? 0 : 1) : (e == 1 ? 1 : 2);
    }
    static Map<String, Object> strip(Map<String, Object> g) {
        List<Object> keep = new ArrayList<>();
        for (Object x : L(g.get("grants"))) {
            boolean hit = false;
            for (Object hh : L(g.get("holes"))) if (Boolean.TRUE.equals(M(hh).get("global")) || L(M(hh).get("affects")).contains(M(x).get("gid"))) hit = true;
            if (!hit) keep.add(x);
        }
        return merge(g, "holes", new ArrayList<>(), "grants", keep);
    }
    static int grantDec(Map<String, Object> g, Map<String, Object> o, Map<String, Object> gr, Map<String, Object> a, Map<String, Object> h) {
        boolean delegOk = N(a.get("depth")) == 0 || L(M(g.get("deleg")).get("mayTouch")).contains(gr.get("gid"));
        int m = Math.min(b2k(a.get("verb").equals(gr.get("verb")) && delegOk), Math.min(b2k(resOk(resolve(o, M(gr.get("res"))), a.get("res"))), cond(M(gr.get("cond")), a, h)));
        for (Object bb : L(g.get("bounds"))) {
            Map<String, Object> b = M(bb);
            List<List<Object>> s = lsel(o, b);
            if (applies(s, gr.get("gid"), a.get("verb"))) m = Math.min(m, boundDec(b, s, a, h));
        }
        return m;
    }
    static Map<String, Object> decide(Map<String, Object> goal, Map<String, Object> o, Map<String, Object> a, Map<String, Object> h) {
        Map<String, Object> g = strip(goal);
        Map<String, Object> v = M(g.get("validity"));
        long t = N(a.get("t"));
        int d = 2;
        if (t < N(v.get("notBefore")) || t > N(v.get("notAfter"))) d = 0;
        else if (N(v.get("maxIdle")) > 0 && N(h.get("last")) >= 0 && t - N(h.get("last")) > N(v.get("maxIdle"))) d = 0;
        else if (N(a.get("depth")) < 0 || N(a.get("depth")) > N(M(g.get("deleg")).get("maxDepth"))) d = 0;
        for (Object pp : L(g.get("prohibits"))) {
            Map<String, Object> p = M(pp);
            int m = Math.min(b2k(prohVerbs(o, p).contains(a.get("verb"))), Math.min(b2k(resOk(resolve(o, M(p.get("res"))), a.get("res"))), cond(M(p.get("cond")), a, h)));
            d = Math.min(d, m == 2 ? 0 : (m == 1 ? 1 : 2));
        }
        for (Object c : L(g.get("escalateOn"))) d = Math.min(d, cond(M(c), a, h) == 0 ? 2 : 1);
        List<Integer> per = new ArrayList<>();
        for (Object gr : L(g.get("grants"))) per.add(grantDec(g, o, M(gr), a, h));
        d = Math.min(d, per.isEmpty() ? 0 : Collections.max(per));
        if (d != 2) return m("decision", d == 1 ? "escalate" : "deny", "witness", null);
        Map<String, Object> gr = M(L(g.get("grants")).get(per.indexOf(2)));
        List<Object> bids = new ArrayList<>();
        for (Object bb : L(g.get("bounds"))) if (applies(lsel(o, M(bb)), gr.get("gid"), a.get("verb"))) bids.add(M(bb).get("bid"));
        return m("decision", "allow", "witness", m("gid", gr.get("gid"), "bids", bids));
    }
    static final Map<String, String> NEG = Map.of("eq", "ne", "ne", "eq", "lt", "gte", "gte", "lt", "gt", "lte", "lte", "gt", "in", "nin", "nin", "in");
    static Map<String, Object> nnf(Map<String, Object> c, boolean pos) {
        switch (S(c.get("k"))) {
            case "true": return m("k", pos ? "true" : "false");
            case "cmp": return m("k", "atom", "op", pos ? c.get("op") : NEG.get(S(c.get("op"))), "l", c.get("l"), "r", c.get("r"));
            case "and": return m("k", pos ? "and" : "or", "a", nnf(M(c.get("a")), pos), "b", nnf(M(c.get("b")), pos));
            case "or": return m("k", pos ? "or" : "and", "a", nnf(M(c.get("a")), pos), "b", nnf(M(c.get("b")), pos));
            default: return nnf(M(c.get("c")), !pos);
        }
    }
    static Map<String, Object> pat(List<Object> p) { return p == null ? m("k", "star") : m("k", "set", "ids", p); }
    static Map<String, Object> lower(Map<String, Object> o, Map<String, Object> goal) {
        Map<String, Object> g = strip(goal);
        List<Object> preds = new ArrayList<>(), prohs = new ArrayList<>(), ceils = new ArrayList<>(), escs = new ArrayList<>();
        for (Object xx : L(g.get("grants"))) { Map<String, Object> x = M(xx); preds.add(m("gid", x.get("gid"), "verb", x.get("verb"), "res", pat(resolve(o, M(x.get("res")))), "cond", nnf(M(x.get("cond")), true))); }
        for (Object pp : L(g.get("prohibits"))) { Map<String, Object> p = M(pp); prohs.add(m("pid", p.get("pid"), "verbs", prohVerbs(o, p), "res", pat(resolve(o, M(p.get("res")))), "cond", nnf(M(p.get("cond")), true))); }
        for (Object bb : L(g.get("bounds"))) {
            Map<String, Object> b = M(bb); List<List<Object>> s = lsel(o, b);
            ceils.add(m("bid", b.get("bid"), "selGids", s.get(0), "selVerbs", s.get(1), "agg", b.get("agg"), "value", b.get("value"), "key", b.get("key"), "window", b.get("window"), "scope", b.get("scope"), "cap", b.get("cap"), "onExceed", b.get("onExceed")));
        }
        for (Object c : L(g.get("escalateOn"))) escs.add(nnf(M(c), true));
        return m("preds", preds, "prohs", prohs, "ceils", ceils, "escs", escs, "validity", g.get("validity"), "deleg", g.get("deleg"));
    }

    // ---------------------------------------------------------------- selector expansion (pca-goal selectors.ts / GoalSelect.dfy)
    static List<Object> strs(Object o) { return o == null ? new ArrayList<>() : L(o); }
    /** An unconfirmed verb carries pca.unreviewed (it is the top of the registry): a class ALLOW never covers it (floating = false), a class PROHIBITION or bound over a trait selector ALWAYS covers it, whatever all_of and none_of say (floating = true). */
    static List<Object> classVerbs(Map<String, Object> cat, List<Object> all, List<Object> none, boolean floating) {
        List<Object> out = new ArrayList<>();
        for (Object vv : L(cat.get("verbs"))) {
            List<Object> ts = L(M(vv).get("traits"));
            boolean unrev = ts.contains("pca.unreviewed");
            boolean inClass = ts.containsAll(all) && none.stream().noneMatch(ts::contains);
            if (floating ? (unrev || inClass) : (inClass && !unrev)) out.add(M(vv).get("verb"));
        }
        return out;
    }
    /** {path, ty} or null */
    static Object[] resolveRole(Map<String, Object> ont, Map<String, Object> cat, String verb, String role) {
        Map<String, Object> info = null, decl = null;
        for (Object v : L(cat.get("verbs"))) if (M(v).get("verb").equals(verb)) { info = M(v); break; }
        for (Object v : L(ont.get("verbs"))) if (M(v).get("verb").equals(verb)) { decl = M(v); break; }
        if (info == null || decl == null) return null;
        List<Object> paths = strs(M(info.get("roles")).get(role));
        if (paths.size() != 1) return null;
        for (Object p : L(decl.get("params"))) if (M(p).get("path").equals(paths.get(0))) return new Object[] {M(p).get("path"), M(p).get("ty")};
        return null;
    }
    static Map<String, Object> xTerm(Map<String, Object> ont, Map<String, Object> cat, String verb, Map<String, Object> t) {
        if (!S(t.get("k")).equals("role")) return t;
        Object[] r = resolveRole(ont, cat, verb, S(t.get("role")));
        return r == null ? null : m("k", "param", "path", r[0], "ty", r[1]);
    }
    static Map<String, Object> xCond(Map<String, Object> ont, Map<String, Object> cat, String verb, Map<String, Object> c) {
        switch (S(c.get("k"))) {
            case "true": return m("k", "true");
            case "cmp": { Map<String, Object> l = xTerm(ont, cat, verb, M(c.get("l"))), r = xTerm(ont, cat, verb, M(c.get("r"))); return l == null || r == null ? null : m("k", "cmp", "op", c.get("op"), "l", l, "r", r); }
            case "and": case "or": { Map<String, Object> a = xCond(ont, cat, verb, M(c.get("a"))), b = xCond(ont, cat, verb, M(c.get("b"))); return a == null || b == null ? null : m("k", c.get("k"), "a", a, "b", b); }
            default: { Map<String, Object> a = xCond(ont, cat, verb, M(c.get("c"))); return a == null ? null : m("k", "not", "c", a); }
        }
    }
    static Map<String, Object> boundValue(Map<String, Object> ont, Map<String, Object> cat, List<Object> vs, Map<String, Object> t) {
        if (!S(t.get("k")).equals("role")) return t;
        List<Object[]> rs = new ArrayList<>();
        for (Object v : vs) { Object[] r = resolveRole(ont, cat, S(v), S(t.get("role"))); if (r == null) return null; rs.add(r); }
        if (rs.isEmpty()) return null;
        boolean same = true, sameTy = true;
        for (Object[] r : rs) {
            sameTy &= canon(r[1]).equals(canon(rs.get(0)[1]));
            same &= r[0].equals(rs.get(0)[0]) && canon(r[1]).equals(canon(rs.get(0)[1]));
        }
        if (same) return m("k", "param", "path", rs.get(0)[0], "ty", rs.get(0)[1]);
        if (sameTy) return m("k", "param", "path", "@" + S(t.get("role")), "ty", rs.get(0)[1]);
        return null;
    }
    static Map<String, Object> expandSel(Map<String, Object> sg, Map<String, Object> ont, Map<String, Object> cat) {
        List<Object[]> es = new ArrayList<>(); // {src, grant}
        for (Object gg : L(sg.get("grants"))) {
            Map<String, Object> gr = M(gg), s = M(gr.get("sel"));
            List<Object> verbs = S(s.get("k")).equals("verb") ? new ArrayList<>(List.of(s.get("verb"))) : classVerbs(cat, strs(s.get("all_of")), strs(s.get("none_of")), false);
            for (Object v : verbs) {
                Map<String, Object> c = xCond(ont, cat, S(v), M(gr.get("cond")));
                if (c == null) continue;
                es.add(new Object[] {gr.get("gid"), m("gid", S(s.get("k")).equals("class") ? gr.get("gid") + "." + v : gr.get("gid"), "verb", v, "res", gr.get("res"), "cond", c)});
            }
        }
        java.util.function.Function<List<Object>, List<Object>> idsOf = srcs -> es.stream().filter(e -> srcs.contains(e[0])).map(e -> M(e[1]).get("gid")).collect(Collectors.toList());
        java.util.function.Function<List<Object>, List<Object>> gidsOfVerbs = vs -> es.stream().filter(e -> vs.contains(M(e[1]).get("verb"))).map(e -> M(e[1]).get("gid")).collect(Collectors.toList());
        java.util.function.Function<List<Object>, List<Object>> verbsOfGids = g -> es.stream().filter(e -> g.contains(M(e[1]).get("gid"))).map(e -> M(e[1]).get("verb")).collect(Collectors.toList());
        List<Object> prohibits = new ArrayList<>();
        for (Object pp : L(sg.get("prohibits"))) {
            Map<String, Object> p = M(pp), t = M(p.get("target"));
            String tk = S(t.get("k"));
            List<Object> verbs = tk.equals("verb") ? new ArrayList<>(List.of(t.get("verb"))) : tk.equals("effect") ? verbsOfClass(ont, S(t.get("cls"))) : classVerbs(cat, strs(t.get("all_of")), strs(t.get("none_of")), true);
            for (Object v : verbs) {
                Map<String, Object> c = xCond(ont, cat, S(v), M(p.get("cond")));
                prohibits.add(m("pid", tk.equals("verb") ? p.get("pid") : p.get("pid") + "." + v, "target", m("k", "verb", "verb", v), "res", p.get("res"), "cond", c != null ? c : m("k", "true")));
            }
        }
        List<Object> bounds = new ArrayList<>();
        for (Object bb : L(sg.get("bounds"))) {
            Map<String, Object> b = M(bb), s = M(b.get("sel"));
            List<Object> gids, rv;
            String sk = S(s.get("k"));
            if (sk.equals("gids")) { gids = idsOf.apply(strs(s.get("gids"))); rv = verbsOfGids.apply(gids); }
            else if (sk.equals("effect")) { gids = null; rv = verbsOfClass(ont, S(s.get("cls"))); }
            else { gids = gidsOfVerbs.apply(classVerbs(cat, strs(s.get("all_of")), strs(s.get("none_of")), true)); rv = verbsOfGids.apply(gids); }
            Map<String, Object> val = boundValue(ont, cat, rv, M(b.get("value")));
            if (val == null || (gids != null && gids.isEmpty())) continue;
            Map<String, Object> sel = gids == null ? m("k", "effect", "cls", s.get("cls")) : m("k", "gids", "gids", gids);
            bounds.add(m("bid", b.get("bid"), "sel", sel, "agg", b.get("agg"), "value", val, "key", b.get("key"), "window", b.get("window"), "scope", b.get("scope"), "cap", b.get("cap"), "onExceed", b.get("onExceed")));
        }
        List<Object> holes = new ArrayList<>();
        for (Object hh : L(sg.get("holes"))) holes.add(merge(M(hh), "affects", idsOf.apply(strs(M(hh).get("affects")))));
        return m("v", 1L, "principal", sg.get("principal"), "ontDigest", sg.get("ontDigest"), "nlDigest", sg.get("nlDigest"), "sources", sg.get("sources"),
            "grants", es.stream().map(e -> e[1]).collect(Collectors.toList()), "prohibits", prohibits, "bounds", bounds, "validity", sg.get("validity"),
            "deleg", merge(M(sg.get("deleg")), "mayTouch", idsOf.apply(strs(M(sg.get("deleg")).get("mayTouch")))), "escalateOn", sg.get("escalateOn"),
            "wildcardAck", idsOf.apply(strs(sg.get("wildcardAck"))), "holes", holes);
    }

    // ---------------------------------------------------------------- fn vectors
    static final Map<String, Integer> RANK = Map.of("deny", 0, "escalate", 1, "allow", 2);
    static String meet(String d, String s) { return RANK.containsKey(s) && RANK.get(s) < RANK.get(d) ? s : d; }
    static void walk(Map<String, Object> c, TreeSet<String> out) {
        switch (S(c.get("k"))) {
            case "and": case "or": walk(M(c.get("a")), out); walk(M(c.get("b")), out); break;
            case "not": walk(M(c.get("c")), out); break;
            case "cmp": for (String k : new String[] {"l", "r"}) { Map<String, Object> t = M(c.get(k)); if (S(t.get("k")).equals("param")) for (String p : new String[] {"env.class.", "env.prov.", "env.judge.", "env.world."}) if (S(t.get("path")).startsWith(p)) out.add(S(t.get("path"))); } break;
            default:
        }
    }
    static Object runFn(Map<String, Object> v) {
        Object in = v.get("input");
        switch (S(v.get("fn"))) {
            case "canon": return m("canon", canon(in), "digest", goalDigest(in));
            case "units": {
                Map<String, Object> sc = M(M(in).get("schema")), tm = M(M(in).get("terms"));
                List<String> bad = new ArrayList<>();
                for (String p : tm.keySet()) if (!sc.containsKey(p) || !canon(sc.get(p)).equals(canon(tm.get(p)))) bad.add(p);
                bad.sort((a, b) -> Arrays.compareUnsigned(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8)));
                return list(bad);
            }
            case "polarity": { TreeSet<String> o = new TreeSet<>((a, b) -> Arrays.compareUnsigned(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8))); for (Object w : L(in)) walk(M(w), o); return list(o); }
            case "meet": return meet(S(M(in).get("decision")), S(M(in).get("signal")));
            case "pep": {
                String d = S(M(in).get("decision"));
                if (d.equals("allow")) return Boolean.TRUE;
                if (d.equals("deny")) return Boolean.FALSE;
                Map<String, Object> ans = M(M(in).get("answer")), ctx = M(M(in).get("ctx"));
                if (ans == null || !Boolean.TRUE.equals(ans.get("valid"))) return Boolean.FALSE;
                for (String k : new String[] {"policy_digest", "action_digest", "history_head"}) if (!Objects.equals(ans.get(k), ctx.get(k))) return Boolean.FALSE;
                return Boolean.TRUE;
            }
            case "commit": return m("commit", b64(sha("pca-goal:v3:commit:" + S(M(in).get("goal_digest")) + ":" + S(M(in).get("policy_digest")) + ":" + S(M(in).get("salt")))), "opens_other_goal", Boolean.FALSE);
            case "claim": { Object rp = M(in).get("replayed_ppm"); return rp != null && N(rp) < N(M(in).get("min_ppm")) ? meet(S(M(in).get("base")), "escalate") : M(in).get("base"); }
            default: throw new IllegalStateException("unknown fn " + v.get("fn"));
        }
    }

    /** Replays every vector of a directory: {vectors, probes, disagreements}. */
    public static Object[] replay(String dir) throws Exception {
        Path d = Path.of(dir);
        List<String> names;
        try (var st = Files.list(d)) { names = st.map(p -> p.getFileName().toString()).filter(n -> n.endsWith(".json") && !n.equals("index.json")).sorted().collect(Collectors.toList()); }
        List<String> bad = new ArrayList<>();
        int probes = 0;
        for (String n : names) {
            Map<String, Object> v = M(new P(Files.readString(d.resolve(n), StandardCharsets.UTF_8)).val());
            String id = S(v.get("id"));
            if (S(v.get("kind")).equals("fn")) { if (!canon(runFn(v)).equals(canon(v.get("expect")))) bad.add(id); continue; }
            Map<String, Object> goal = M(v.get("goal")), ont = M(v.get("ontology"));
            if (v.get("sel") != null && !canon(expandSel(M(M(v.get("sel")).get("goal")), ont, M(M(v.get("sel")).get("catalog")))).equals(canon(goal))) bad.add(id + ":expansion");
            if (!goalDigest(goal).equals(v.get("goal_digest"))) bad.add(id + ":goal_digest");
            if (!Boolean.TRUE.equals(M(v.get("compile")).get("ok"))) continue;
            if (!hashCanon(lower(ont, goal)).equals(v.get("policy_digest"))) bad.add(id + ":policy_digest");
            List<Object> ps = L(v.get("probes"));
            for (int i = 0; i < ps.size(); i++) {
                probes++;
                Map<String, Object> p = M(ps.get(i));
                if (!canon(decide(goal, ont, M(p.get("action")), M(p.get("history")))).equals(canon(p.get("expect")))) bad.add(id + "#" + i);
            }
        }
        return new Object[] {names.size(), probes, bad};
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        Object[] r = replay(args[0]);
        List<String> bad = (List<String>) r[2];
        System.out.println("java: " + r[0] + " vectors, " + r[1] + " probes, " + bad.size() + " disagreements");
        bad.stream().limit(20).forEach(b -> System.out.println("   " + b));
        if (!bad.isEmpty() || (Integer) r[0] == 0) System.exit(1);
    }
}

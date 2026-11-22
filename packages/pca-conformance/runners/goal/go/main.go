// Go runner for the pca-goal vectors (independent port of the reference semantics, written from formal/dafny/GoalIr.dfy). Usage: go run . <vectors-dir>
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type M = map[string]any

func canon(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		if x {
			return "true"
		}
		return "false"
	case json.Number:
		return x.String()
	case string:
		var b strings.Builder
		b.WriteByte('"')
		for _, r := range x {
			switch {
			case r == '"':
				b.WriteString(`\"`)
			case r == '\\':
				b.WriteString(`\\`)
			case r == '\b':
				b.WriteString(`\b`)
			case r == '\t':
				b.WriteString(`\t`)
			case r == '\n':
				b.WriteString(`\n`)
			case r == '\f':
				b.WriteString(`\f`)
			case r == '\r':
				b.WriteString(`\r`)
			case r < 0x20:
				fmt.Fprintf(&b, `\u%04x`, r)
			default:
				b.WriteRune(r)
			}
		}
		b.WriteByte('"')
		return b.String()
	case []any:
		p := make([]string, len(x))
		for i, e := range x {
			p[i] = canon(e)
		}
		return "[" + strings.Join(p, ",") + "]"
	case M:
		ks := make([]string, 0, len(x))
		for k := range x {
			ks = append(ks, k)
		}
		sort.Strings(ks) // Go string order is UTF-8 byte order
		p := make([]string, len(ks))
		for i, k := range ks {
			p[i] = canon(k) + ":" + canon(x[k])
		}
		return "{" + strings.Join(p, ",") + "}"
	}
	panic(fmt.Sprintf("canon: %T", v))
}
func b64(h [32]byte) string   { return base64.RawURLEncoding.EncodeToString(h[:]) }
func hashCanon(v any) string  { return b64(sha256.Sum256([]byte(canon(v)))) }
func goalDigest(g any) string { return hashCanon(M{"d": "atlas-pca/goal-ir/v1", "goal": g}) }
func num(v any) float64       { f, _ := v.(json.Number).Float64(); return f }
func str(v any) string        { s, _ := v.(string); return s }
func arr(v any) []any         { a, _ := v.([]any); return a }
func obj(v any) M             { m, _ := v.(M); return m }
func ival(v any) int64        { i, _ := v.(json.Number).Int64(); return i }

// Kleene truth 0/1/2 (false/unknown/true); decisions 0/1/2 (deny/escalate/allow); meet = min, join = max
func kNot(a int) int { return 2 - a }
func b2k(b bool) int {
	if b {
		return 2
	}
	return 0
}
func minI(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxI(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func eqV(x, y M) int {
	switch str(x["k"]) {
	case "q":
		if str(y["k"]) == "q" && canon(obj(x["q"])["u"]) == canon(obj(y["q"])["u"]) {
			return b2k(ival(obj(x["q"])["n"]) == ival(obj(y["q"])["n"]))
		}
	case "s":
		if str(y["k"]) == "s" {
			return b2k(str(x["s"]) == str(y["s"]))
		}
	}
	return 1
}
func ltV(x, y M) int {
	if str(x["k"]) == "q" && str(y["k"]) == "q" && canon(obj(x["q"])["u"]) == canon(obj(y["q"])["u"]) {
		return b2k(ival(obj(x["q"])["n"]) < ival(obj(y["q"])["n"]))
	}
	return 1
}
func cmpOp(op string, x, y M) int {
	if x == nil || y == nil {
		return 1
	}
	switch op {
	case "eq":
		return eqV(x, y)
	case "ne":
		return kNot(eqV(x, y))
	case "lt":
		return ltV(x, y)
	case "gte":
		return kNot(ltV(x, y))
	case "gt":
		return ltV(y, x)
	case "lte":
		return kNot(ltV(y, x))
	}
	t := 1
	if str(y["k"]) == "set" {
		t = 0
		for _, it := range arr(y["items"]) {
			t = maxI(t, eqV(x, obj(it)))
		}
	}
	if op == "in" {
		return t
	}
	return kNot(t)
}
func term(t M, a M, h M) M {
	switch str(t["k"]) {
	case "param":
		if v, ok := obj(a["params"])[str(t["path"])]; ok {
			return obj(v)
		}
		return nil
	case "lit":
		return obj(t["v"])
	}
	if q, ok := obj(h["aggs"])[str(t["bid"])]; ok {
		return M{"k": "q", "q": q}
	}
	return nil
}
func cond(c M, a M, h M) int {
	switch str(c["k"]) {
	case "true":
		return 2
	case "cmp":
		return cmpOp(str(c["op"]), term(obj(c["l"]), a, h), term(obj(c["r"]), a, h))
	case "and":
		return minI(cond(obj(c["a"]), a, h), cond(obj(c["b"]), a, h))
	case "or":
		return maxI(cond(obj(c["a"]), a, h), cond(obj(c["b"]), a, h))
	}
	return kNot(cond(obj(c["c"]), a, h))
}
func strs(v any) []string {
	out := []string{}
	for _, x := range arr(v) {
		out = append(out, str(x))
	}
	return out
}
func has(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
func partIds(o M, p M) []string {
	switch str(p["k"]) {
	case "exact":
		return []string{str(p["id"])}
	case "oneof":
		return strs(p["ids"])
	}
	for _, r := range arr(o["rels"]) {
		rr := obj(r)
		if str(rr["rel"]) == str(p["rel"]) && str(rr["anchor"]) == str(p["anchor"]) {
			return strs(rr["members"])
		}
	}
	return []string{}
}

// pattern: nil = every resource
func resolve(o M, s M) []string {
	switch str(s["k"]) {
	case "any":
		return nil
	case "all_of":
		var acc []string
		first := true
		ps := arr(s["parts"])
		for i := len(ps) - 1; i >= 0; i-- {
			ids := partIds(o, obj(ps[i]))
			if first {
				acc, first = ids, false
				continue
			}
			n := []string{}
			for _, id := range ids {
				if has(acc, id) {
					n = append(n, id)
				}
			}
			acc = n
		}
		return acc
	}
	return partIds(o, s)
}
func resOk(p []string, r string) bool { return p == nil || has(p, r) }
func verbsOfClass(o M, cls string) []string {
	out := []string{}
	for _, v := range arr(o["verbs"]) {
		vv := obj(v)
		if str(vv["cls"]) == cls {
			out = append(out, str(vv["verb"]))
		}
	}
	return out
}
func prohVerbs(o M, p M) []string {
	t := obj(p["target"])
	if str(t["k"]) == "verb" {
		return []string{str(t["verb"])}
	}
	return verbsOfClass(o, str(t["cls"]))
}
func lsel(o M, b M) ([]string, []string) {
	s := obj(b["sel"])
	if str(s["k"]) == "gids" {
		return strs(s["gids"]), []string{}
	}
	return []string{}, verbsOfClass(o, str(s["cls"]))
}
func applies(g, v []string, gid, verb string) bool { return has(g, gid) || has(v, verb) }
func inScope(b, a, x M) bool {
	s := obj(b["scope"])
	switch str(s["k"]) {
	case "session":
		return str(a["sess"]) == str(x["sess"])
	case "principal":
		return str(a["prin"]) == str(x["prin"])
	case "org":
		return str(a["org"]) == str(x["org"])
	}
	ag := strs(s["agents"])
	return has(ag, str(a["agent"])) && has(ag, str(x["agent"]))
}
func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}
func inWindow(w, a, x M) bool {
	switch str(w["k"]) {
	case "sliding":
		return ival(x["t"]) > ival(a["t"])-ival(w["ms"]) && ival(x["t"]) <= ival(a["t"])
	case "period":
		ms := ival(w["ms"])
		return ms > 0 && floorDiv(ival(a["t"])-ival(w["t0"]), ms) == floorDiv(ival(x["t"])-ival(w["t0"]), ms)
	}
	return true
}
func exceeded(b M, g, v []string, a M, h M) int {
	items := []M{}
	for _, m := range arr(h["adms"]) {
		mm := obj(m)
		x := obj(mm["act"])
		if applies(g, v, str(mm["gid"]), str(x["verb"])) && inScope(b, a, x) && inWindow(obj(b["window"]), a, x) {
			items = append(items, x)
		}
	}
	items = append(items, a)
	cap := ival(obj(b["cap"])["n"])
	switch str(b["agg"]) {
	case "count":
		return b2k(int64(len(items)) > cap)
	case "distinct":
		seen := map[string]bool{}
		for _, x := range items {
			pv, ok := obj(x["params"])[str(b["key"])]
			if !ok {
				return 1
			}
			seen[canon(pv)] = true
		}
		return b2k(int64(len(seen)) > cap)
	}
	var sum, mx int64
	for i, x := range items {
		t := term(obj(b["value"]), x, h)
		if t == nil || str(t["k"]) != "q" || canon(obj(t["q"])["u"]) != canon(obj(b["cap"])["u"]) {
			return 1
		}
		n := ival(obj(t["q"])["n"])
		sum += n
		if i == 0 || n > mx {
			mx = n
		}
	}
	if str(b["agg"]) == "sum" {
		return b2k(sum > cap)
	}
	return b2k(mx > cap)
}
func boundDec(b M, g, v []string, a M, h M) int {
	e := exceeded(b, g, v, a, h)
	if e == 2 {
		if str(b["onExceed"]) == "deny" {
			return 0
		}
		return 1
	}
	if e == 1 {
		return 1
	}
	return 2
}
func strip(goal M) M {
	hs := arr(goal["holes"])
	grants := []any{}
	for _, gr := range arr(goal["grants"]) {
		g := obj(gr)
		drop := false
		for _, h := range hs {
			hh := obj(h)
			if hh["global"] == true || has(strs(hh["affects"]), str(g["gid"])) {
				drop = true
			}
		}
		if !drop {
			grants = append(grants, gr)
		}
	}
	out := M{}
	for k, v := range goal {
		out[k] = v
	}
	out["grants"] = grants
	out["holes"] = []any{}
	return out
}
func decide(goal, o, a, h M) M {
	g := strip(goal)
	v := obj(g["validity"])
	d := 2
	switch {
	case ival(a["t"]) < ival(v["notBefore"]) || ival(a["t"]) > ival(v["notAfter"]):
		d = 0
	case ival(v["maxIdle"]) > 0 && ival(h["last"]) >= 0 && ival(a["t"])-ival(h["last"]) > ival(v["maxIdle"]):
		d = 0
	case ival(a["depth"]) < 0 || ival(a["depth"]) > ival(obj(g["deleg"])["maxDepth"]):
		d = 0
	}
	verb := str(a["verb"])
	for _, p := range arr(g["prohibits"]) {
		pp := obj(p)
		m := minI(b2k(has(prohVerbs(o, pp), verb)), minI(b2k(resOk(resolve(o, obj(pp["res"])), str(a["res"]))), cond(obj(pp["cond"]), a, h)))
		x := 2
		if m == 2 {
			x = 0
		} else if m == 1 {
			x = 1
		}
		d = minI(d, x)
	}
	for _, c := range arr(g["escalateOn"]) {
		if cond(obj(c), a, h) == 0 {
			d = minI(d, 2)
		} else {
			d = minI(d, 1)
		}
	}
	best, idx := -1, -1
	grants := arr(g["grants"])
	for i, gr := range grants {
		gg := obj(gr)
		delegOk := ival(a["depth"]) == 0 || has(strs(obj(g["deleg"])["mayTouch"]), str(gg["gid"]))
		m := minI(b2k(verb == str(gg["verb"]) && delegOk), minI(b2k(resOk(resolve(o, obj(gg["res"])), str(a["res"]))), cond(obj(gg["cond"]), a, h)))
		for _, b := range arr(g["bounds"]) {
			bs, bv := lsel(o, obj(b))
			if applies(bs, bv, str(gg["gid"]), verb) {
				m = minI(m, boundDec(obj(b), bs, bv, a, h))
			}
		}
		if m > best {
			best = m
		}
		if m == 2 && idx < 0 {
			idx = i
		}
	}
	if len(grants) == 0 {
		best = 0
	}
	d = minI(d, best)
	if d != 2 {
		if d == 1 {
			return M{"decision": "escalate", "witness": nil}
		}
		return M{"decision": "deny", "witness": nil}
	}
	gid := str(obj(grants[idx])["gid"])
	bids := []any{}
	for _, b := range arr(g["bounds"]) {
		bs, bv := lsel(o, obj(b))
		if applies(bs, bv, gid, verb) {
			bids = append(bids, str(obj(b)["bid"]))
		}
	}
	return M{"decision": "allow", "witness": M{"gid": gid, "bids": bids}}
}

// lowering (GoalCompile.dfy Lower) for the policy digest
var neg = map[string]string{"eq": "ne", "ne": "eq", "lt": "gte", "gte": "lt", "gt": "lte", "lte": "gt", "in": "nin", "nin": "in"}

func nnf(c M, pos bool) M {
	switch str(c["k"]) {
	case "true":
		if pos {
			return M{"k": "true"}
		}
		return M{"k": "false"}
	case "cmp":
		op := str(c["op"])
		if !pos {
			op = neg[op]
		}
		return M{"k": "atom", "op": op, "l": c["l"], "r": c["r"]}
	case "and", "or":
		k := str(c["k"])
		if !pos {
			if k == "and" {
				k = "or"
			} else {
				k = "and"
			}
		}
		return M{"k": k, "a": nnf(obj(c["a"]), pos), "b": nnf(obj(c["b"]), pos)}
	}
	return nnf(obj(c["c"]), !pos)
}
func pat(p []string) M {
	if p == nil {
		return M{"k": "star"}
	}
	ids := []any{}
	for _, x := range p {
		ids = append(ids, x)
	}
	return M{"k": "set", "ids": ids}
}
func anyStrs(xs []string) []any {
	out := []any{}
	for _, x := range xs {
		out = append(out, x)
	}
	return out
}
func lower(o, goal M) M {
	g := strip(goal)
	preds, prohs, ceils, escs := []any{}, []any{}, []any{}, []any{}
	for _, x := range arr(g["grants"]) {
		xx := obj(x)
		preds = append(preds, M{"gid": xx["gid"], "verb": xx["verb"], "res": pat(resolve(o, obj(xx["res"]))), "cond": nnf(obj(xx["cond"]), true)})
	}
	for _, p := range arr(g["prohibits"]) {
		pp := obj(p)
		prohs = append(prohs, M{"pid": pp["pid"], "verbs": anyStrs(prohVerbs(o, pp)), "res": pat(resolve(o, obj(pp["res"]))), "cond": nnf(obj(pp["cond"]), true)})
	}
	for _, b := range arr(g["bounds"]) {
		bb := obj(b)
		bs, bv := lsel(o, bb)
		ceils = append(ceils, M{"bid": bb["bid"], "selGids": anyStrs(bs), "selVerbs": anyStrs(bv), "agg": bb["agg"], "value": bb["value"], "key": bb["key"], "window": bb["window"], "scope": bb["scope"], "cap": bb["cap"], "onExceed": bb["onExceed"]})
	}
	for _, c := range arr(g["escalateOn"]) {
		escs = append(escs, nnf(obj(c), true))
	}
	return M{"preds": preds, "prohs": prohs, "ceils": ceils, "escs": escs, "validity": g["validity"], "deleg": g["deleg"]}
}

var rank = map[string]int{"deny": 0, "escalate": 1, "allow": 2}

func meet(d, s string) string {
	if r, ok := rank[s]; ok && r < rank[d] {
		return s
	}
	return d
}
func polarity(ws []any) []any {
	set := map[string]bool{}
	var walk func(c M)
	walk = func(c M) {
		switch str(c["k"]) {
		case "and", "or":
			walk(obj(c["a"]))
			walk(obj(c["b"]))
		case "not":
			walk(obj(c["c"]))
		case "cmp":
			for _, t := range []any{c["l"], c["r"]} {
				tt := obj(t)
				if str(tt["k"]) == "param" {
					p := str(tt["path"])
					for _, pre := range []string{"env.class.", "env.prov.", "env.judge.", "env.world."} {
						if strings.HasPrefix(p, pre) {
							set[p] = true
						}
					}
				}
			}
		}
	}
	for _, w := range ws {
		walk(obj(w))
	}
	ks := []string{}
	for k := range set {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	out := []any{}
	for _, k := range ks {
		out = append(out, k)
	}
	return out
}
func units(schema, terms M) []any {
	ks := []string{}
	for k := range terms {
		s, ok := schema[k]
		if !ok || canon(s) != canon(terms[k]) {
			ks = append(ks, k)
		}
	}
	sort.Strings(ks)
	out := []any{}
	for _, k := range ks {
		out = append(out, k)
	}
	return out
}
func runFn(v M) any {
	i := obj(v["input"])
	switch str(v["fn"]) {
	case "canon":
		return M{"canon": canon(v["input"]), "digest": goalDigest(v["input"])}
	case "units":
		return units(obj(i["schema"]), obj(i["terms"]))
	case "polarity":
		return polarity(v["input"].([]any))
	case "meet":
		return meet(str(i["decision"]), str(i["signal"]))
	case "pep":
		d := str(i["decision"])
		if d == "allow" {
			return true
		}
		if d == "deny" {
			return false
		}
		ans := obj(i["answer"])
		ctx := obj(i["ctx"])
		if ans == nil || ans["valid"] != true {
			return false
		}
		for _, k := range []string{"policy_digest", "action_digest", "history_head"} {
			if ans[k] != ctx[k] {
				return false
			}
		}
		return true
	case "commit":
		return M{"commit": b64(sha256.Sum256([]byte("pca-goal:v3:commit:" + str(i["goal_digest"]) + ":" + str(i["policy_digest"]) + ":" + str(i["salt"])))), "opens_other_goal": false}
	case "claim":
		if i["replayed_ppm"] != nil && ival(i["replayed_ppm"]) < ival(i["min_ppm"]) {
			return meet(str(i["base"]), "escalate")
		}
		return str(i["base"])
	}
	panic("unknown fn")
}

// ---- selector expansion (pca-goal selectors.ts / formal/dafny/GoalSelect.dfy)
// An unconfirmed verb carries pca.unreviewed (it is the top of the registry): a class ALLOW never covers it (float = false), a class PROHIBITION or bound over a trait selector ALWAYS covers it, whatever all_of and none_of say (float = true).
func classVerbs(cat M, allOf, noneOf []string, float bool) []string {
	out := []string{}
	for _, vv := range arr(cat["verbs"]) {
		v := obj(vv)
		ts := strs(v["traits"])
		inClass := true
		for _, t := range allOf {
			if !has(ts, t) {
				inClass = false
			}
		}
		for _, t := range noneOf {
			if has(ts, t) {
				inClass = false
			}
		}
		unrev := has(ts, "pca.unreviewed")
		if (float && (unrev || inClass)) || (!float && inClass && !unrev) {
			out = append(out, str(v["verb"]))
		}
	}
	return out
}
func resolveRole(ont, cat M, verb, role string) (string, any, bool) {
	var info, decl M
	for _, vv := range arr(cat["verbs"]) {
		if str(obj(vv)["verb"]) == verb {
			info = obj(vv)
			break
		}
	}
	for _, vv := range arr(ont["verbs"]) {
		if str(obj(vv)["verb"]) == verb {
			decl = obj(vv)
			break
		}
	}
	if info == nil || decl == nil {
		return "", nil, false
	}
	roles, _ := info["roles"].(M)
	paths := strs(roles[role])
	if len(paths) != 1 {
		return "", nil, false
	}
	for _, pp := range arr(decl["params"]) {
		if str(obj(pp)["path"]) == paths[0] {
			return paths[0], obj(pp)["ty"], true
		}
	}
	return "", nil, false
}
func xTerm(ont, cat M, verb string, t M) (M, bool) {
	if str(t["k"]) == "role" {
		p, ty, ok := resolveRole(ont, cat, verb, str(t["role"]))
		if !ok {
			return nil, false
		}
		return M{"k": "param", "path": p, "ty": ty}, true
	}
	return t, true
}
func xCond(ont, cat M, verb string, c M) (M, bool) {
	switch str(c["k"]) {
	case "true":
		return M{"k": "true"}, true
	case "cmp":
		l, ok1 := xTerm(ont, cat, verb, obj(c["l"]))
		r, ok2 := xTerm(ont, cat, verb, obj(c["r"]))
		if !ok1 || !ok2 {
			return nil, false
		}
		return M{"k": "cmp", "op": c["op"], "l": l, "r": r}, true
	case "and", "or":
		a, ok1 := xCond(ont, cat, verb, obj(c["a"]))
		b, ok2 := xCond(ont, cat, verb, obj(c["b"]))
		if !ok1 || !ok2 {
			return nil, false
		}
		return M{"k": c["k"], "a": a, "b": b}, true
	}
	a, ok := xCond(ont, cat, verb, obj(c["c"]))
	if !ok {
		return nil, false
	}
	return M{"k": "not", "c": a}, true
}
func boundValue(ont, cat M, vs []string, t M) (M, bool) {
	if str(t["k"]) != "role" {
		return t, true
	}
	type R struct {
		p  string
		ty string
		o  any
	}
	rs := []R{}
	for _, v := range vs {
		p, ty, ok := resolveRole(ont, cat, v, str(t["role"]))
		if !ok {
			return nil, false
		}
		rs = append(rs, R{p, canon(ty), ty})
	}
	if len(rs) == 0 {
		return nil, false
	}
	same, sameTy := true, true
	for _, r := range rs {
		if r.p != rs[0].p || r.ty != rs[0].ty {
			same = false
		}
		if r.ty != rs[0].ty {
			sameTy = false
		}
	}
	if same {
		return M{"k": "param", "path": rs[0].p, "ty": rs[0].o}, true
	}
	if sameTy {
		return M{"k": "param", "path": "@" + str(t["role"]), "ty": rs[0].o}, true
	}
	return nil, false
}
func expandSel(sg, ont, cat M) M {
	type EG struct {
		src string
		g   M
	}
	es := []EG{}
	for _, gg := range arr(sg["grants"]) {
		gr := obj(gg)
		s := obj(gr["sel"])
		var verbs []string
		if str(s["k"]) == "verb" {
			verbs = []string{str(s["verb"])}
		} else {
			verbs = classVerbs(cat, strs(s["all_of"]), strs(s["none_of"]), false)
		}
		for _, v := range verbs {
			c, ok := xCond(ont, cat, v, obj(gr["cond"]))
			if !ok {
				continue
			}
			gid := str(gr["gid"])
			if str(s["k"]) == "class" {
				gid = gid + "." + v
			}
			es = append(es, EG{str(gr["gid"]), M{"gid": gid, "verb": v, "res": gr["res"], "cond": c}})
		}
	}
	idsOf := func(srcs []string) []any {
		out := []any{}
		for _, e := range es {
			if has(srcs, e.src) {
				out = append(out, e.g["gid"])
			}
		}
		return out
	}
	toS := func(a []any) []string {
		o := []string{}
		for _, x := range a {
			o = append(o, x.(string))
		}
		return o
	}
	gidsOfVerbs := func(vs []string) []any {
		out := []any{}
		for _, e := range es {
			if has(vs, str(e.g["verb"])) {
				out = append(out, e.g["gid"])
			}
		}
		return out
	}
	verbsOfGids := func(g []string) []string {
		out := []string{}
		for _, e := range es {
			if has(g, str(e.g["gid"])) {
				out = append(out, str(e.g["verb"]))
			}
		}
		return out
	}
	prohibits := []any{}
	for _, pp := range arr(sg["prohibits"]) {
		p := obj(pp)
		t := obj(p["target"])
		var verbs []string
		switch str(t["k"]) {
		case "verb":
			verbs = []string{str(t["verb"])}
		case "effect":
			verbs = verbsOfClass(ont, str(t["cls"]))
		default:
			verbs = classVerbs(cat, strs(t["all_of"]), strs(t["none_of"]), true)
		}
		for _, v := range verbs {
			c, ok := xCond(ont, cat, v, obj(p["cond"]))
			if !ok {
				c = M{"k": "true"}
			}
			pid := str(p["pid"])
			if str(t["k"]) != "verb" {
				pid = pid + "." + v
			}
			prohibits = append(prohibits, M{"pid": pid, "target": M{"k": "verb", "verb": v}, "res": p["res"], "cond": c})
		}
	}
	bounds := []any{}
	for _, bb := range arr(sg["bounds"]) {
		b := obj(bb)
		s := obj(b["sel"])
		var rv []string
		var gids []any
		isEffect := str(s["k"]) == "effect"
		switch str(s["k"]) {
		case "gids":
			gids = idsOf(strs(s["gids"]))
			rv = verbsOfGids(toS(gids))
		case "effect":
			rv = verbsOfClass(ont, str(s["cls"]))
		default:
			gids = gidsOfVerbs(classVerbs(cat, strs(s["all_of"]), strs(s["none_of"]), true))
			rv = verbsOfGids(toS(gids))
		}
		val, ok := boundValue(ont, cat, rv, obj(b["value"]))
		if !ok || (!isEffect && len(gids) == 0) {
			continue
		}
		sel := M{"k": "effect", "cls": s["cls"]}
		if !isEffect {
			sel = M{"k": "gids", "gids": gids}
		}
		bounds = append(bounds, M{"bid": b["bid"], "sel": sel, "agg": b["agg"], "value": val, "key": b["key"], "window": b["window"], "scope": b["scope"], "cap": b["cap"], "onExceed": b["onExceed"]})
	}
	grants := []any{}
	for _, e := range es {
		grants = append(grants, e.g)
	}
	deleg := M{}
	for k, v := range obj(sg["deleg"]) {
		deleg[k] = v
	}
	deleg["mayTouch"] = idsOf(strs(obj(sg["deleg"])["mayTouch"]))
	holes := []any{}
	for _, hh := range arr(sg["holes"]) {
		h := M{}
		for k, v := range obj(hh) {
			h[k] = v
		}
		h["affects"] = idsOf(strs(obj(hh)["affects"]))
		holes = append(holes, h)
	}
	return M{"v": json.Number("1"), "principal": sg["principal"], "ontDigest": sg["ontDigest"], "nlDigest": sg["nlDigest"], "sources": sg["sources"],
		"grants": grants, "prohibits": prohibits, "bounds": bounds, "validity": sg["validity"], "deleg": deleg, "escalateOn": sg["escalateOn"],
		"wildcardAck": idsOf(strs(sg["wildcardAck"])), "holes": holes}
}
func main() {
	dir := os.Args[1]
	ents, _ := os.ReadDir(dir)
	names := []string{}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".json") && e.Name() != "index.json" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	bad := []string{}
	probes := 0
	for _, n := range names {
		raw, _ := os.ReadFile(filepath.Join(dir, n))
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var v M
		if err := dec.Decode(&v); err != nil {
			panic(err)
		}
		if str(v["kind"]) == "fn" {
			if canon(runFn(v)) != canon(v["expect"]) {
				bad = append(bad, str(v["id"]))
			}
			continue
		}
		if sel, ok := v["sel"].(M); ok {
			if canon(expandSel(obj(sel["goal"]), obj(v["ontology"]), obj(sel["catalog"]))) != canon(v["goal"]) {
				bad = append(bad, str(v["id"])+":expansion")
			}
		}
		if goalDigest(v["goal"]) != str(v["goal_digest"]) {
			bad = append(bad, str(v["id"])+":goal_digest")
		}
		if obj(v["compile"])["ok"] != true {
			continue
		}
		if hashCanon(lower(obj(v["ontology"]), obj(v["goal"]))) != str(v["policy_digest"]) {
			bad = append(bad, str(v["id"])+":policy_digest")
		}
		for i, p := range arr(v["probes"]) {
			probes++
			pp := obj(p)
			got := decide(obj(v["goal"]), obj(v["ontology"]), obj(pp["action"]), obj(pp["history"]))
			if canon(got) != canon(pp["expect"]) {
				bad = append(bad, fmt.Sprintf("%s#%d", str(v["id"]), i))
			}
		}
	}
	fmt.Printf("go: %d vectors, %d probes, %d disagreements\n", len(names), probes, len(bad))
	for i, b := range bad {
		if i < 20 {
			fmt.Println("  ", b)
		}
	}
	if len(bad) > 0 || len(names) == 0 {
		os.Exit(1)
	}
}

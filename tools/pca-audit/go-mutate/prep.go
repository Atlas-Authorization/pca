package main

// Prep mode: the per-package work every shard used to repeat (full-suite baseline, per-test coverage, ~25 min) runs ONCE,
// together with the type-check verdicts and the schema test binary; the mutants are then packed into shards by their
// measured cost (selected tests' run times, plus a rebuild for the standalone ones) so that every shard holds about the
// same work and none exceeds the budget. Every mutant of the package is in exactly one shard's plan, carried and decided
// ones included, so each shard still reports its complete slice.

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type prepOpts struct {
	dir                  string
	budget               time.Duration
	minShards, maxShards int
	verify               int
}

type planMut struct {
	ID       int     `json:"id"`
	Key      string  `json:"key"`
	Mode     string  `json:"mode"` // done | schema | build
	Status   string  `json:"status,omitempty"`
	Carried  bool    `json:"carried,omitempty"`
	Evidence string  `json:"evidence,omitempty"`
	Sel      []int   `json:"sel"` // indices into the common test list; null = the full suite, [] = no test
	Cost     float64 `json:"cost"`
}

type planCommon struct {
	SrcHash string    `json:"src_hash"`
	Tests   []string  `json:"tests"`
	Dur     []float64 `json:"dur"`  // seconds: each test alone (as the coverage run measured it)
	Full    float64   `json:"full"` // seconds: the full suite (go test, as the baseline measured it)
}

type planFile struct {
	Mutants []planMut `json:"mutants"`
}

// loadPlan: the mutants of one plan file (with common.json next to it) as tasks; decided ones get their status.
func loadPlan(path string, all []Mut, srcHash string) ([]*Mut, []*task, error) {
	var c planCommon
	var pl planFile
	for _, x := range []struct {
		p string
		v any
	}{{filepath.Join(filepath.Dir(path), "common.json"), &c}, {path, &pl}} {
		b, err := os.ReadFile(x.p)
		if err == nil { err = json.Unmarshal(b, x.v) }
		if err != nil { return nil, nil, fmt.Errorf("plan %s: %v", x.p, err) }
	}
	if c.SrcHash != srcHash { return nil, nil, fmt.Errorf("plan %s was made for other sources (%s, these are %s)", path, c.SrcHash, srcHash) }
	if len(c.Dur) != len(c.Tests) { return nil, nil, fmt.Errorf("plan %s: %d tests, %d durations", path, len(c.Tests), len(c.Dur)) }
	var mine []*Mut
	var tasks []*task
	for _, pm := range pl.Mutants {
		if pm.ID < 0 || pm.ID >= len(all) || all[pm.ID].Key != pm.Key { return nil, nil, fmt.Errorf("plan %s: mutant %d (%s) is not this source's", path, pm.ID, pm.Key) }
		m := &all[pm.ID]
		mine = append(mine, m)
		switch pm.Mode {
		case "done":
			if pm.Status == "" { return nil, nil, fmt.Errorf("plan %s: mutant %d decided without a status", path, pm.ID) }
			m.Status, m.Carried, m.Evidence = pm.Status, pm.Carried, pm.Evidence
		case "schema", "build":
			t := &task{m: m, schema: pm.Mode == "schema"}
			d := c.Full
			if pm.Sel != nil {
				d = 0
				t.tests = make([]string, 0, len(pm.Sel))
				for _, i := range pm.Sel {
					if i < 0 || i >= len(c.Tests) { return nil, nil, fmt.Errorf("plan %s: mutant %d selects test %d of %d", path, pm.ID, i, len(c.Tests)) }
					t.tests = append(t.tests, c.Tests[i])
					d += c.Dur[i]
				}
			}
			t.lim = limit(time.Duration(d * float64(time.Second)))
			tasks = append(tasks, t)
		default:
			return nil, nil, fmt.Errorf("plan %s: mutant %d has mode %q", path, pm.ID, pm.Mode)
		}
	}
	return mine, tasks, nil
}

// cmdFor: the schema test binary with args (under the -exec wrapper), no mutant active.
func cmdFor(o runOpts, bin string, args ...string) *exec.Cmd {
	var c *exec.Cmd
	if o.execw != "" { c = exec.Command(o.execw, append([]string{bin}, args...)...) } else { c = exec.Command(bin, args...) }
	c.Dir = o.abs
	for _, e := range os.Environ() { if !strings.HasPrefix(e, "GOMUT_ID=") { c.Env = append(c.Env, e) } }
	return c
}

// overlayBuild: does the package (production files only) compile with m applied?
func overlayBuild(o runOpts, m *Mut, tag string) error {
	p := filepath.Join(o.abs, m.File)
	src, err := os.ReadFile(p)
	if err != nil { return err }
	mp := filepath.Join(o.tmp, fmt.Sprintf("v%s%d.go", tag, m.ID))
	op := mp + ".json"
	os.WriteFile(mp, []byte(string(src[:m.start])+m.repl+string(src[m.end:])), 0o644)
	ov, _ := json.Marshal(map[string]any{"Replace": map[string]string{p: mp}})
	os.WriteFile(op, ov, 0o644)
	defer os.Remove(mp)
	defer os.Remove(op)
	args := []string{"build", "-overlay", op}
	if o.tags != "" { args = append(args, "-tags", o.tags) }
	c := exec.Command("go", append(args, ".")...)
	c.Dir = o.abs
	if out, err := c.CombinedOutput(); err != nil { return fmt.Errorf("%v: %s", err, tail(string(out), 300)) }
	return nil
}

func spread(ms []*Mut, n int) []*Mut {
	if len(ms) <= n { return ms }
	var out []*Mut
	for i := 0; i < n; i++ { out = append(out, ms[i*len(ms)/n]) }
	return out
}

func doPrep(o runOpts, p prepOpts, names []string, mine, toRun []*Mut, srcHash string) error {
	if err := os.MkdirAll(filepath.Join(p.dir, "plan"), 0o755); err != nil { return err }
	mode := map[*Mut]string{}
	for _, m := range mine { if m.Carried { mode[m] = "done" } }
	durOf := map[string]time.Duration{}
	sel := map[*Mut][]string{}
	var full time.Duration
	siteOf := map[*Mut]*site{}
	bin := filepath.Join(p.dir, "schema.test")
	var execDur, fullRun, buildDur time.Duration
	if len(toRun) > 0 {
		var blocks map[string]map[string]*covBlock
		var err error
		sel, full, blocks, err = coverageSelect(o.abs, o.tmp, o.tags, o.par, toRun, durOf, true)
		if err != nil { return err }
		t0 := time.Now()
		an, err := newAnalysis(o.abs, o.tags, names)
		if err != nil { return err }
		fmt.Fprintf(os.Stderr, "go-mutate: type check of %d file(s) in %v\n", len(names), time.Since(t0).Round(time.Second))
		t0 = time.Now()
		sites := map[string][]*site{}
		byKey := map[string]*site{}
		pkgSel, fails := 0, 0
		for _, m := range toRun {
			tests, ok := sel[m]
			if !ok && m.fnL1 == 0 {
				if ts, ok2 := an.pkgSelect(m, blocks); ok2 { sel[m], tests, ok = ts, ts, true; pkgSel++ }
			}
			v, ev := an.verdict(m)
			switch {
			case v == vFail:
				m.Status, m.Evidence, mode[m] = "build-failed", ev, "done"
				fails++
			case v == vOK && ok && len(tests) == 0:
				m.Status, mode[m] = "SURVIVED", "done"
				fmt.Printf("SURVIVED %d %s:%d:%d %s | %s (no test executes it)\n", m.ID, m.File, m.Line, m.col, m.Desc, m.Src)
			case v == vOK:
				mode[m] = "build"
				if s := an.siteFor(m); s != nil {
					if e := byKey[an.siteKey(s)]; e != nil { s = e } else { byKey[an.siteKey(s)] = s; sites[m.File] = append(sites[m.File], s) }
					s.muts = append(s.muts, m)
					siteOf[m], mode[m] = s, "schema"
				}
			default:
				mode[m] = "build"
			}
		}
		fmt.Fprintf(os.Stderr, "go-mutate: verdicts in %v: %d package-level mutant(s) selected by reference, %d rejected by the type checker, %d guarded site(s)\n",
			time.Since(t0).Round(time.Second), pkgSel, fails, len(byKey))
		if len(byKey) > 0 {
			if err := an.buildSchema(sites, o.tmp, o.tags, bin); err != nil { return err }
			for m, s := range siteOf { if s.dead { mode[m] = "build"; delete(siteOf, m) } }
		}
		if len(siteOf) > 0 {
			// the schema binary with no mutant active must pass the whole suite: a guard that changed behaviour fails here
			t0 = time.Now()
			if out, err := cmdFor(o, bin, "-test.paniconexit0", "-test.count=1", "-test.timeout=60m").CombinedOutput(); err != nil {
				return fmt.Errorf("the unmutated suite FAILS in the schema build:\n%s", tail(string(out), 6000))
			}
			fullRun = time.Since(t0)
			var ds []time.Duration
			for i := 0; i < 3; i++ {
				t1 := time.Now()
				if out, err := cmdFor(o, bin, "-test.run=^$").CombinedOutput(); err != nil { return fmt.Errorf("the schema binary does not start: %v\n%s", err, tail(string(out), 2000)) }
				ds = append(ds, time.Since(t1))
			}
			sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
			execDur = ds[1]
			fmt.Fprintf(os.Stderr, "go-mutate: schema binary: full suite %v, start-up %v\n", fullRun.Round(time.Second), execDur.Round(time.Millisecond))
		}
		if err := crossCheck(o, p, toRun, mode, siteOf, sel, durOf, bin); err != nil { return err }
		for _, m := range toRun {
			if mode[m] != "build" { continue }
			// one rebuild of the package (the cost every standalone mutant pays), on a warm cache
			t1 := time.Now()
			if err := overlayProbe(o); err != nil { return err }
			buildDur = time.Since(t1)
			fmt.Fprintf(os.Stderr, "go-mutate: standalone rebuild %v\n", buildDur.Round(time.Second))
			break
		}
	}
	if fullRun == 0 { fullRun = full }
	return writePlan(o, p, mine, mode, siteOf, sel, durOf, full, fullRun, execDur, buildDur, srcHash)
}

// overlayProbe: the time of one standalone test build (a source change forces the package rebuild + link).
func overlayProbe(o runOpts) error {
	g, _ := filepath.Glob(filepath.Join(o.abs, "*.go"))
	var f string
	for _, x := range g { if !strings.HasSuffix(x, "_test.go") { f = x; break } }
	src, err := os.ReadFile(f)
	if err != nil { return err }
	mp := filepath.Join(o.tmp, "probe.go")
	op := filepath.Join(o.tmp, "probe.json")
	os.WriteFile(mp, append(src, []byte("\n// go-mutate rebuild probe\n")...), 0o644)
	ov, _ := json.Marshal(map[string]any{"Replace": map[string]string{f: mp}})
	os.WriteFile(op, ov, 0o644)
	args := []string{"test", "-c", "-vet=off", "-o", filepath.Join(o.tmp, "probe.test"), "-overlay", op}
	if o.tags != "" { args = append(args, "-tags", o.tags) }
	c := exec.Command("go", append(args, ".")...)
	c.Dir = o.abs
	if out, err := c.CombinedOutput(); err != nil { return fmt.Errorf("rebuild probe: %v\n%s", err, tail(string(out), 2000)) }
	os.Remove(filepath.Join(o.tmp, "probe.test"))
	return nil
}

// crossCheck: the type checker's verdicts (a sample of each direction) against real builds, and one schema mutant per guard
// kind against its standalone build + run: any difference refuses the plan.
func crossCheck(o runOpts, p prepOpts, toRun []*Mut, mode map[*Mut]string, siteOf map[*Mut]*site, sel map[*Mut][]string, durOf map[string]time.Duration, bin string) error {
	var rej, acc []*Mut
	for _, m := range toRun {
		if mode[m] == "done" && m.Status == "build-failed" && strings.HasPrefix(m.Evidence, "type check:") { rej = append(rej, m) }
		if mode[m] == "schema" { acc = append(acc, m) }
	}
	type check struct {
		m    *Mut
		fail bool
	}
	var cs []check
	for _, m := range spread(rej, p.verify) { cs = append(cs, check{m, true}) }
	for _, m := range spread(acc, p.verify) { cs = append(cs, check{m, false}) }
	var bad []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan bool, max(1, o.par))
	for _, c := range cs {
		wg.Add(1)
		go func(c check) {
			defer wg.Done()
			sem <- true
			defer func() { <-sem }()
			err := overlayBuild(o, c.m, "c")
			if (err != nil) != c.fail {
				mu.Lock()
				bad = append(bad, fmt.Sprintf("mutant %d %s:%d %s | %s: type check says build-failed=%v, the build says %v (%s)", c.m.ID, c.m.File, c.m.Line, c.m.Desc, c.m.Src, c.fail, err, c.m.Evidence))
				mu.Unlock()
			}
		}(c)
	}
	wg.Wait()
	// one schema mutant per guard kind (the cheapest with a test selection) run both ways
	best := map[int]*Mut{}
	cost := func(m *Mut) time.Duration {
		var d time.Duration
		for _, t := range sel[m] { d += durOf[t] }
		return d
	}
	for m, s := range siteOf {
		if ts, ok := sel[m]; !ok || len(ts) == 0 { continue }
		if b := best[s.kind]; b == nil || cost(m) < cost(b) || cost(m) == cost(b) && m.ID < b.ID { best[s.kind] = m }
	}
	type pair struct {
		alone, schema *Mut
		kind          int
	}
	var tasks []*task
	var pairs []pair
	for k, m := range best {
		a, b := *m, *m
		lim := limit(cost(m))
		tasks = append(tasks, &task{m: &a, tests: sel[m], lim: lim}, &task{m: &b, tests: sel[m], lim: lim, schema: true})
		pairs = append(pairs, pair{&a, &b, k})
	}
	if len(tasks) > 0 {
		so := o
		so.schemaBin = bin
		runTasks(tasks, so)
	}
	for _, pr := range pairs {
		if pr.alone.Status != pr.schema.Status {
			bad = append(bad, fmt.Sprintf("mutant %d %s:%d %s | %s (%s guard): standalone %s, schema %s", pr.alone.ID, pr.alone.File, pr.alone.Line, pr.alone.Desc, pr.alone.Src, kindName[pr.kind], pr.alone.Status, pr.schema.Status))
		}
	}
	fmt.Fprintf(os.Stderr, "go-mutate: cross-check: %d type-check verdict(s) built for real, %d guard kind(s) run both ways, %d difference(s)\n", len(cs), len(pairs), len(bad))
	if len(bad) > 0 { return fmt.Errorf("the schema / type-check shortcuts disagree with real builds:\n%s", strings.Join(bad, "\n")) }
	return nil
}

// writePlan packs the mutants into shards (largest first into the least loaded shard) so that each shard's estimated work
// stays within budget x workers, and writes plan/common.json, plan/<i>.json, plan/count and plan/summary.json.
func writePlan(o runOpts, p prepOpts, mine []*Mut, mode map[*Mut]string, siteOf map[*Mut]*site, sel map[*Mut][]string, durOf map[string]time.Duration,
	full, fullRun, execDur, buildDur time.Duration, srcHash string) error {
	var tests []string
	for t := range durOf { tests = append(tests, t) }
	sort.Strings(tests)
	idx := map[string]int{}
	c := planCommon{SrcHash: srcHash, Tests: tests, Full: full.Seconds()}
	for i, t := range tests { idx[t] = i; c.Dur = append(c.Dur, durOf[t].Seconds()) }
	ex := execDur.Seconds()
	// shortcut: a standalone build runs next to other workers' builds and tests; 1.5x the lone rebuild, refine from shard logs
	bs := 1.5 * buildDur.Seconds()
	const warm = 240.0 // shortcut: a shard's first standalone build also compiles the dependencies (cold build cache)
	type item struct {
		pm   planMut
		cost float64
		m    *Mut
	}
	var items []*item
	counts := map[string]int{}
	kinds := map[string]int{}
	for _, m := range mine {
		md := mode[m]
		if md == "" { md = "build" }
		it := &item{m: m, pm: planMut{ID: m.ID, Key: m.Key, Mode: md}}
		counts[md]++
		if md == "done" {
			it.pm.Status, it.pm.Carried, it.pm.Evidence = m.Status, m.Carried, m.Evidence
		} else {
			ts, ok := sel[m]
			cst := fullRun.Seconds()
			if ok {
				it.pm.Sel = make([]int, 0, len(ts))
				cst = ex
				for _, t := range ts {
					i, has := idx[t]
					if !has { return fmt.Errorf("mutant %d selects %s, which the coverage run did not time", m.ID, t) }
					it.pm.Sel = append(it.pm.Sel, i)
					cst += math.Max(0, durOf[t].Seconds()-ex)
				}
			}
			if md == "build" { cst += bs }
			if s := siteOf[m]; s != nil && md == "schema" { kinds[kindName[s.kind]]++ }
			it.cost = cst
		}
		it.pm.Cost = math.Round(it.cost*10) / 10
		items = append(items, it)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].cost != items[j].cost { return items[i].cost > items[j].cost }
		return items[i].pm.ID < items[j].pm.ID
	})
	total := 0.0
	for _, it := range items { total += it.cost }
	capS := p.budget.Seconds() * float64(max(1, o.par))
	R := max(p.minShards, int(math.Ceil(total/capS)))
	var bins [][]*item
	var loads []float64
	for {
		bins, loads = make([][]*item, R), make([]float64, R)
		warmed := make([]bool, R)
		zero := 0
		for _, it := range items {
			if it.cost == 0 { bins[zero%R] = append(bins[zero%R], it); zero++; continue }
			j := 0
			for k := 1; k < R; k++ { if loads[k] < loads[j] { j = k } }
			if it.pm.Mode == "build" && !warmed[j] { loads[j] += warm; warmed[j] = true }
			loads[j] += it.cost
			bins[j] = append(bins[j], it)
		}
		mx := 0.0
		for _, l := range loads { mx = math.Max(mx, l) }
		if mx <= capS || R > p.maxShards { break }
		R += max(1, R/50)
	}
	if R > p.maxShards {
		return fmt.Errorf("the plan needs more than %d shards (%.0f worker-hours of mutant work at %v per shard with %d workers)", p.maxShards, total/3600, p.budget, o.par)
	}
	for j := range bins {
		if len(bins[j]) == 0 { return fmt.Errorf("shard %d of %d has no mutant (fewer mutants than shards)", j, R) }
	}
	w := func(name string, v any) error {
		b, err := json.Marshal(v)
		if err != nil { return err }
		return os.WriteFile(filepath.Join(p.dir, "plan", name), b, 0o644)
	}
	if err := w("common.json", c); err != nil { return err }
	mx := 0.0
	for j, b := range bins {
		pf := planFile{}
		for _, it := range b { pf.Mutants = append(pf.Mutants, it.pm) }
		if err := w(strconv.Itoa(j)+".json", pf); err != nil { return err }
		mx = math.Max(mx, loads[j])
	}
	if err := os.WriteFile(filepath.Join(p.dir, "plan", "count"), []byte(strconv.Itoa(R)+"\n"), 0o644); err != nil { return err }
	sum := map[string]any{"mutants": len(mine), "modes": counts, "schema_guards": kinds, "shards": R, "workers": o.par,
		"est_worker_hours": math.Round(total/36) / 100, "est_max_shard_minutes": math.Round(mx/float64(max(1, o.par))/6) / 10,
		"full_suite_s": math.Round(fullRun.Seconds()), "startup_s": math.Round(ex*100) / 100, "standalone_rebuild_s": math.Round(buildDur.Seconds())}
	if err := w("summary.json", sum); err != nil { return err }
	sb, _ := json.Marshal(sum)
	fmt.Fprintf(os.Stderr, "go-mutate: plan: %s\n", sb)
	return nil
}

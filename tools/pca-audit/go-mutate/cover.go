package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type covBlock struct {
	l1, c1, l2, c2 int
	tests          map[string]bool // tests that executed it
}

var profLine = regexp.MustCompile(`^(.+):(\d+)\.(\d+),(\d+)\.(\d+) \d+ (\d+)$`)

// coverageSelect builds the package's test binary with coverage, runs every top-level test alone with a profile, and maps
// each mutant to the tests that execute its position: an empty (non-nil) list = no test executes it, no entry = the position
// is outside every coverage block (run the full suite). Every test must pass on its own and the full suite must pass, or
// the mutation run is refused (a failing test would turn mutants into bogus kills). durOf gets each test's run time; full
// is the full suite's.
func coverageSelect(abs, tmp, tags string, par int, muts []*Mut, durOf map[string]time.Duration) (map[*Mut][]string, time.Duration, error) {
	targs := []string{"test", "-count=1"}
	if tags != "" { targs = append(targs, "-tags", tags) }
	bc := exec.Command("go", append(targs, ".")...)
	bc.Dir = abs
	t0 := time.Now()
	if out, err := bc.CombinedOutput(); err != nil {
		return nil, 0, fmt.Errorf("the unmutated suite FAILS:\n%s", out)
	}
	full := time.Since(t0)
	fmt.Fprintf(os.Stderr, "go-mutate: baseline (full suite) %v\n", full.Round(time.Second))

	bin := filepath.Join(tmp, "cov.test")
	cargs := []string{"test", "-c", "-cover", "-covermode=set", "-o", bin}
	if tags != "" { cargs = append(cargs, "-tags", tags) }
	cc := exec.Command("go", append(cargs, ".")...)
	cc.Dir = abs
	if out, err := cc.CombinedOutput(); err != nil { return nil, 0, fmt.Errorf("coverage build failed:\n%s", out) }
	lc := exec.Command(bin, "-test.list", ".")
	lc.Dir = abs
	lo, err := lc.Output()
	if err != nil { return nil, 0, fmt.Errorf("-test.list failed: %v", err) }
	var names []string
	for _, n := range strings.Fields(string(lo)) {
		if strings.HasPrefix(n, "Test") || strings.HasPrefix(n, "Example") || strings.HasPrefix(n, "Fuzz") { names = append(names, n) }
	}
	if len(names) == 0 { return nil, 0, fmt.Errorf("the coverage binary lists no tests") }

	pdir := filepath.Join(tmp, "prof")
	os.MkdirAll(pdir, 0o755)
	blocks := map[string]map[string]*covBlock{} // file -> "l1.c1,l2.c2" -> block
	var mu sync.Mutex
	var fails []string
	ch := make(chan int)
	var wg sync.WaitGroup
	t1 := time.Now()
	for w := 0; w < par; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				n := names[i]
				pf := filepath.Join(pdir, fmt.Sprintf("%d.out", i))
				c := exec.Command(bin, "-test.run", "^"+n+"$", "-test.count=1", "-test.timeout=20m", "-test.coverprofile="+pf)
				c.Dir = abs
				s := time.Now()
				out, err := c.CombinedOutput()
				d := time.Since(s)
				mu.Lock()
				durOf[n] = d
				if err != nil {
					o := string(out)
					if len(o) > 2000 { o = o[len(o)-2000:] }
					fails = append(fails, n+":\n"+o)
				} else if e := readProfile(pf, n, blocks); e != nil {
					fails = append(fails, n+": "+e.Error())
				}
				mu.Unlock()
				os.Remove(pf)
			}
		}()
	}
	for i := range names { ch <- i }
	close(ch)
	wg.Wait()
	if len(fails) > 0 {
		sort.Strings(fails)
		return nil, 0, fmt.Errorf("%d test(s) fail when run alone (fix the test's hidden dependency on another test):\n%s", len(fails), strings.Join(fails, "\n"))
	}
	fmt.Fprintf(os.Stderr, "go-mutate: coverage of %d tests in %v\n", len(names), time.Since(t1).Round(time.Second))

	sel := map[*Mut][]string{}
	fullN, none, tot := 0, 0, 0
	for _, m := range muts {
		in := false
		set := map[string]bool{}
		for _, b := range blocks[m.File] {
			// inclusive on both ends: a larger selection is always safe
			if (m.Line > b.l1 || m.Line == b.l1 && m.col >= b.c1) && (m.Line < b.l2 || m.Line == b.l2 && m.col <= b.c2) {
				in = true
				for t := range b.tests { set[t] = true }
			}
		}
		if !in { fullN++; continue }
		ts := make([]string, 0, len(set))
		for t := range set { ts = append(ts, t) }
		sort.Strings(ts)
		sel[m] = ts
		if len(ts) == 0 { none++ }
		tot += len(ts)
	}
	fmt.Fprintf(os.Stderr, "go-mutate: selection: %d mutants, %d outside every block (full suite), %d executed by no test, %.1f tests per mutant on average\n",
		len(muts), fullN, none, float64(tot)/float64(max(1, len(muts)-fullN)))
	return sel, full, nil
}

// readProfile merges one test's profile into blocks (every block is recorded; the test only on blocks it executed).
func readProfile(pf, test string, blocks map[string]map[string]*covBlock) error {
	f, err := os.Open(pf)
	if err != nil { return err }
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		ln := sc.Text()
		if strings.HasPrefix(ln, "mode:") { continue }
		g := profLine.FindStringSubmatch(ln)
		if g == nil { return fmt.Errorf("bad profile line %q", ln) }
		file := filepath.Base(g[1])
		k := g[2] + "." + g[3] + "," + g[4] + "." + g[5]
		if blocks[file] == nil { blocks[file] = map[string]*covBlock{} }
		b := blocks[file][k]
		if b == nil {
			b = &covBlock{tests: map[string]bool{}}
			fmt.Sscan(g[2], &b.l1); fmt.Sscan(g[3], &b.c1); fmt.Sscan(g[4], &b.l2); fmt.Sscan(g[5], &b.c2)
			blocks[file][k] = b
		}
		if g[6] != "0" { b.tests[test] = true }
	}
	return sc.Err()
}

// cacheSnapshot: GOCACHE and the files it holds now (relative paths).
func cacheSnapshot() (string, map[string]bool) {
	out, err := exec.Command("go", "env", "GOCACHE").Output()
	dir := strings.TrimSpace(string(out))
	keep := map[string]bool{}
	if err != nil || dir == "" || dir == "off" { return "", keep }
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() { r, _ := filepath.Rel(dir, p); keep[r] = true }
		return nil
	})
	return dir, keep
}

// trimCache removes every GOCACHE file that is not in keep (the mutants' builds). Callers hold no build in flight.
func trimCache(dir string, keep map[string]bool) {
	if dir == "" { return }
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if r, _ := filepath.Rel(dir, p); !keep[r] { os.Remove(p) }
		}
		return nil
	})
}

// go-mutate: minimal AST-guided mutation tester for sdks/go-pca (go-mutesting/gremlins stand-in; uses `go test -overlay`
// so shards run in parallel on one tree). Usage: go-mutate -dir <module dir> [-shard i/n] [-list] [-files a.go,b.go] [-tags t1,t2] [-out f.json]
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"context"
	"time"
	"sync"
	"syscall"
)

type Mut struct {
	ID     int    `json:"id"`
	File   string `json:"file"`
	Line   int    `json:"line"`
	Desc   string `json:"mutant"`
	Src    string `json:"line_text"`
	start, end int
	col        int // 1-based byte column of start (coverage block lookup)
	repl   string
	Status string `json:"status"`
	// carry-forward identity (targeted mode): Key is stable across runs while the mutant's function is unchanged, DefHash is
	// the token hash of its enclosing function (comments/whitespace ignored), ShellHash that of everything outside every function
	// of its file, SrcHash that of the whole production source of the run.
	Key       string `json:"key"`
	DefHash   string `json:"def_hash"`
	ShellHash string `json:"shell_hash"`
	SrcHash   string `json:"src_hash"`
	Carried   bool   `json:"carried,omitempty"`
	Evidence  string `json:"evidence,omitempty"` // run-error: the line that shows no test decided it
}

// isErrorResult: `err`, a package error value, or a new error built in the return.
func isErrorResult(r ast.Expr) bool {
	switch v := r.(type) {
	case *ast.Ident:
		return v.Name == "err" || strings.HasPrefix(v.Name, "Err")
	case *ast.CallExpr:
		if s, ok := v.Fun.(*ast.SelectorExpr); ok {
			if p, ok := s.X.(*ast.Ident); ok {
				return (p.Name == "errors" && s.Sel.Name == "New") || (p.Name == "fmt" && s.Sel.Name == "Errorf")
			}
		}
	}
	return false
}

// isReasonResult: a non-empty string literal, or a concatenation that starts with one.
func isReasonResult(r ast.Expr) bool {
	switch v := r.(type) {
	case *ast.BasicLit:
		return v.Kind == token.STRING && v.Value != `""` && v.Value != "``"
	case *ast.BinaryExpr:
		return v.Op == token.ADD && isReasonResult(v.X)
	}
	return false
}

// blankNoCall: `_ = x`, which does nothing to remove.
func blankNoCall(x *ast.AssignStmt) bool {
	for _, l := range x.Lhs {
		if id, ok := l.(*ast.Ident); !ok || id.Name != "_" {
			return false
		}
	}
	for _, r := range x.Rhs {
		if _, ok := r.(*ast.CallExpr); ok {
			return false
		}
	}
	return true
}

// capOutput keeps the first and last MiB of a mutant's output: a mutant that prints without end must not exhaust this
// process (its address space is capped too). A "--- FAIL:" lost in the dropped middle only makes it a run error, never a kill.
type capOutput struct{ head, tail []byte }

func (c *capOutput) Write(p []byte) (int, error) {
	const keep = 1 << 20
	n := len(p)
	if room := keep - len(c.head); room > 0 {
		k := min(room, len(p))
		c.head = append(c.head, p[:k]...)
		p = p[k:]
	}
	c.tail = append(c.tail, p...)
	if len(c.tail) > 2*keep {
		c.tail = append(c.tail[:0], c.tail[len(c.tail)-keep:]...)
	}
	return n, nil
}

func (c *capOutput) String() string { return string(c.head) + string(c.tail) }

// killedBy: the first failing test and its first message line (diagnostic only: it names the test that killed a mutant, so a
// mutant that should be equivalent but is sometimes killed can be traced to its flaky test).
func killedBy(o string) string {
	ls := strings.Split(o, "\n")
	for i, l := range ls {
		if strings.HasPrefix(l, "--- FAIL:") {
			out := strings.TrimSpace(l)
			for j := i + 1; j < len(ls) && j <= i+2; j++ { if t := strings.TrimSpace(ls[j]); t != "" { out += " | " + t } }
			if len(out) > 300 { out = out[:300] }
			return out
		}
	}
	return ""
}

// runErrorEvidence: a failing go test counts as a kill only when a test itself failed ("--- FAIL:", printed by t.Error/
// t.Fatal and by the testing runner for a test that panicked). A runtime fatal error (out of memory under the shard's
// ulimit -v, stack overflow, ...) or a signal death prints no such line: that is a run error, listed with this evidence.
func runErrorEvidence(o string) string {
	for _, l := range strings.Split(o, "\n") {
		if strings.HasPrefix(l, "fatal error:") || strings.HasPrefix(l, "runtime: out of memory") || strings.HasPrefix(l, "signal: ") ||
			strings.Contains(l, "goroutine stack exceeds") {
			return strings.TrimSpace(l)
		}
	}
	if strings.Contains(o, "--- FAIL:") { return "" }
	// a panic in package init or in a goroutine the test started: name it, so the ledger reason can be checked against it
	for _, l := range strings.Split(o, "\n") {
		if strings.HasPrefix(l, "panic: ") { return "no test failed: " + strings.TrimSpace(l) }
	}
	return "no test failed: " + lastLine(o)
}

func lastLine(o string) string {
	ls := strings.Split(strings.TrimSpace(o), "\n")
	return strings.TrimSpace(ls[len(ls)-1])
}

type poolEntry struct{ S, D, H, A string }

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// funcSpan: byte range of a top-level function declaration and its label (receiver.name#ordinal).
type funcSpan struct {
	start, end int
	label      string
	hash       string
}

// tokenHashes hashes the token stream of each function range and of the rest ("shell") separately: comments and layout
// do not count, anything else does.
func tokenHashes(path string, src []byte, fs *token.FileSet, f *ast.File) ([]funcSpan, string) {
	var spans []funcSpan
	seen := map[string]int{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil { continue }
		name := fd.Name.Name
		if fd.Recv != nil && len(fd.Recv.List) == 1 {
			name = string(src[fs.Position(fd.Recv.List[0].Type.Pos()).Offset:fs.Position(fd.Recv.List[0].Type.End()).Offset]) + "." + name
		}
		seen[name]++
		spans = append(spans, funcSpan{start: fs.Position(fd.Pos()).Offset, end: fs.Position(fd.End()).Offset, label: fmt.Sprintf("%s#%d", name, seen[name])})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	hs := make([]*strings.Builder, len(spans)+1)
	for i := range hs { hs[i] = &strings.Builder{} }
	var sc scanner.Scanner
	file := fs.AddFile(path+"#scan", -1, len(src))
	sc.Init(file, src, nil, 0)
	for {
		pos, tok, lit := sc.Scan()
		if tok == token.EOF { break }
		off := file.Offset(pos)
		idx := len(spans) // shell
		for i := range spans {
			if off >= spans[i].start && off < spans[i].end { idx = i; break }
		}
		hs[idx].WriteString(tok.String()); hs[idx].WriteByte(0); hs[idx].WriteString(lit); hs[idx].WriteByte(0)
	}
	for i := range spans { spans[i].hash = sum([]byte(hs[i].String())) }
	return spans, sum([]byte(hs[len(spans)].String()))
}

var binSwap = map[token.Token][]string{
	token.EQL: {"!="}, token.NEQ: {"=="}, token.LSS: {"<=", ">="}, token.LEQ: {"<", ">"}, token.GTR: {">=", "<="}, token.GEQ: {">", "<"},
	token.ADD: {"-"}, token.SUB: {"+"}, token.MUL: {"/"}, token.QUO: {"*"}, token.REM: {"*"},
	token.LAND: {"||"}, token.LOR: {"&&"}, token.AND: {"|"}, token.OR: {"&"}, token.XOR: {"&"},
	token.SHL: {">>"}, token.SHR: {"<<"}, token.AND_NOT: {"&"},
}

func gen(path string) []Mut {
	src, _ := os.ReadFile(path)
	fs := token.NewFileSet()
	f, err := parser.ParseFile(fs, path, src, parser.ParseComments)
	if err != nil { panic(err) }
	lines := strings.Split(string(src), "\n")
	var ms []Mut
	spans, shell := tokenHashes(path, src, fs, f)
	occ := map[string]int{}
	add := func(p, e token.Pos, repl, desc string) {
		s, en := fs.Position(p).Offset, fs.Position(e).Offset
		ln, col := fs.Position(p).Line, fs.Position(p).Column
		label, dh := "", sum(nil)
		for _, sp := range spans {
			if s >= sp.start && s < sp.end { label, dh = sp.label, sp.hash; break }
		}
		m := Mut{File: filepath.Base(path), Line: ln, Desc: desc, Src: strings.TrimSpace(lines[ln-1]), start: s, end: en, col: col, repl: repl, DefHash: dh, ShellHash: shell}
		base := m.File + "|" + label + "|" + desc + "|" + m.Src
		m.Key = fmt.Sprintf("%s|%d", base, occ[base])
		occ[base]++
		ms = append(ms, m)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BinaryExpr:
			for _, r := range binSwap[x.Op] {
				add(x.OpPos, x.OpPos+token.Pos(len(x.Op.String())), r, fmt.Sprintf("binary %s -> %s", x.Op, r))
			}
		case *ast.IfStmt:
			c := x.Cond
			if id, ok := c.(*ast.Ident); !ok || (id.Name != "true" && id.Name != "false") {
				// keep the condition's text: `if v, ok := m[k]; ok` with the bare literal does not compile (ok unused), so it never ran
				t := string(src[fs.Position(c.Pos()).Offset:fs.Position(c.End()).Offset])
				add(c.Pos(), c.End(), "("+t+") || true", "if-cond -> true")
				add(c.Pos(), c.End(), "("+t+") && false", "if-cond -> false")
			}
		case *ast.UnaryExpr:
			if x.Op == token.NOT {
				add(x.Pos(), x.X.Pos(), "", "remove !")
			}
		case *ast.BasicLit:
			if x.Kind == token.INT {
				v := x.Value
				if v == "0" {
					add(x.Pos(), x.End(), "1", "int 0 -> 1")
				} else if v == "1" {
					add(x.Pos(), x.End(), "0", "int 1 -> 0")
					add(x.Pos(), x.End(), "2", "int 1 -> 2")
				} else if !strings.HasPrefix(v, "0x") && !strings.HasPrefix(v, "0b") {
					add(x.Pos(), x.End(), "("+v+"+1)", "int "+v+" -> +1")
					add(x.Pos(), x.End(), "("+v+"-1)", "int "+v+" -> -1")
				} else {
					add(x.Pos(), x.End(), "("+v+"+1)", "int "+v+" -> +1")
				}
			}
		case *ast.ReturnStmt:
			for _, r := range x.Results {
				if id, ok := r.(*ast.Ident); ok && (id.Name == "true" || id.Name == "false") {
					o := "true"
					if id.Name == "true" { o = "false" }
					add(id.Pos(), id.End(), o, "return "+id.Name+" -> "+o)
				}
				switch {
				case isErrorResult(r): // an early error return that reports success
					add(r.Pos(), r.End(), "nil", "return error -> nil")
				case isReasonResult(r): // this SDK reports a refusal as a reason string; "" is success
					add(r.Pos(), r.End(), `""`, "return reason -> empty")
				}
				if l, ok := r.(*ast.BasicLit); ok && l.Kind == token.STRING && (l.Value == `""` || l.Value == "``") {
					add(r.Pos(), r.End(), `"mutant"`, "return empty -> reason")
				}
			}
		case *ast.AssignStmt:
			if len(x.Rhs) == 1 && x.Tok == token.ASSIGN || x.Tok == token.DEFINE {
				// bool literal assignment flip
				for _, r := range x.Rhs {
					if id, ok := r.(*ast.Ident); ok && (id.Name == "true" || id.Name == "false") {
						o := "true"
						if id.Name == "true" { o = "false" }
						add(id.Pos(), id.End(), o, "assign "+id.Name+" -> "+o)
					}
				}
			}
			if x.Tok != token.DEFINE && !blankNoCall(x) {
				add(x.Pos(), x.End(), "_ = 0", "remove assignment")
			}
			if x.Tok == token.ADD_ASSIGN || x.Tok == token.SUB_ASSIGN {
				o := "-="; if x.Tok == token.SUB_ASSIGN { o = "+=" }
				add(x.TokPos, x.TokPos+2, o, x.Tok.String()+" -> "+o)
			}
		case *ast.IncDecStmt:
			o := "--"; if x.Tok == token.DEC { o = "++" }
			add(x.TokPos, x.TokPos+2, o, x.Tok.String()+" -> "+o)
		case *ast.ExprStmt:
			// statement removal for call statements
			if _, ok := x.X.(*ast.CallExpr); ok {
				add(x.Pos(), x.End(), "_ = 0", "remove call statement")
			}
		case *ast.DeferStmt:
			add(x.Pos(), x.End(), "_ = 0", "remove defer")
		case *ast.GoStmt:
			add(x.Pos(), x.End(), "_ = 0", "remove go statement")
		case *ast.BranchStmt:
			if x.Label == nil && x.Tok == token.CONTINUE {
				add(x.Pos(), x.End(), "_ = 0", "remove continue")
				add(x.Pos(), x.End(), "break", "continue -> break")
			} else if x.Label == nil && x.Tok == token.BREAK {
				add(x.Pos(), x.End(), "_ = 0", "remove break")
			}
		case *ast.CaseClause:
			if n := len(x.Body); n > 0 {
				add(x.Body[0].Pos(), x.Body[n-1].End(), "_ = 0", "remove case body")
			}
		}
		return true
	})
	return ms
}

func main() {
	dir := flag.String("dir", ".", "")
	shard := flag.String("shard", "0/1", "")
	list := flag.Bool("list", false, "")
	files := flag.String("files", "", "")
	out := flag.String("out", "", "")
	timeout := flag.Duration("timeout", 90*time.Second, "")
	runf := flag.String("run", "", "go test -run regexp (local dev: restrict the oracle to the tests that cover the file)")
	ids := flag.String("ids", "", "comma list of mutant ids to run (default all)")
	carry := flag.String("carry", "", "targeted mode: pool.json of earlier results (mut-carry/baseline.mjs); only mutants it cannot vouch for are run")
	par := flag.Int("j", 1, "parallel workers within shard")
	tags := flag.String("tags", "", "comma list of build tags passed to `go test -tags` (and used to select the mutated files)")
	flag.Parse()
	var si, sn int
	fmt.Sscanf(*shard, "%d/%d", &si, &sn)
	abs, _ := filepath.Abs(*dir)
	var all []Mut
	var names []string
	if *files != "" { names = strings.Split(*files, ",") } else {
		g, _ := filepath.Glob(filepath.Join(abs, "*.go"))
		// only files the test build compiles under -tags: a file excluded by its build constraint (e.g. less_cgo.go without
		// -tags less) is never compiled, so every mutant in it would "survive" without being tested
		bc := build.Default
		if *tags != "" { bc.BuildTags = strings.Split(*tags, ",") }
		for _, p := range g {
			if strings.HasSuffix(p, "_test.go") { continue }
			if ok, err := bc.MatchFile(abs, filepath.Base(p)); err != nil || !ok {
				fmt.Fprintf(os.Stderr, "go-mutate: skipping %s (excluded by its build constraint under tags %q)\n", filepath.Base(p), *tags)
				continue
			}
			names = append(names, filepath.Base(p))
		}
	}
	sort.Strings(names)
	for _, n := range names { all = append(all, gen(filepath.Join(abs, n))...) }
	srcAll := sha256.New()
	for _, n := range names { b, _ := os.ReadFile(filepath.Join(abs, n)); srcAll.Write([]byte(n)); srcAll.Write([]byte{0}); srcAll.Write(b) }
	srcHash := hex.EncodeToString(srcAll.Sum(nil))
	for i := range all { all[i].ID = i; all[i].SrcHash = srcHash }
	if *list { for _, m := range all { fmt.Printf("%d %s:%d %s | %s\n", m.ID, m.File, m.Line, m.Desc, m.Src) }; fmt.Println("total", len(all)); return }
	tmp, _ := os.MkdirTemp("", "gomut")
	defer os.RemoveAll(tmp)
	var mine []*Mut
	want := map[int]bool{}
	for _, s := range strings.Split(*ids, ",") { var n int; if _, e := fmt.Sscanf(s, "%d", &n); e == nil { want[n] = true } }
	for i := range all { if i%sn == si && (len(*ids) == 0 || want[i]) { mine = append(mine, &all[i]) } }
	// Targeted mode. A pooled result is reused only when the mutant's function and the file's non-function code are token-identical
	// (killed only: a killed-timeout and a run-error are never carried, so a new deadline test re-measures them), or the whole production source is identical (build-failed: another file may have made it compile). Survivors,
	// unseen mutants and everything else run again. Tests/corpus changes were vetted by baseline.mjs before the pool was handed over.
	toRun := mine
	if *carry != "" {
		var pool struct{ Entries map[string]poolEntry }
		pb, err := os.ReadFile(*carry)
		if err == nil { err = json.Unmarshal(pb, &pool) }
		if err != nil { fmt.Fprintf(os.Stderr, "go-mutate: cannot use -carry %s: %v\n", *carry, err); os.Exit(1) }
		toRun = nil
		unseen, nonkill, changed := 0, 0, 0
		for _, m := range mine {
			e, ok := pool.Entries[m.Key]
			switch {
			case !ok: unseen++
			case e.D != m.DefHash || e.H != m.ShellHash: changed++
			case e.S == "killed" || (e.S == "build-failed" && e.A == m.SrcHash):
				m.Status, m.Carried = e.S, true
				continue
			default: nonkill++
			}
			toRun = append(toRun, m)
		}
		fmt.Fprintf(os.Stderr, "go-mutate: carry: %d result(s) carried, %d to run (%d unseen, %d function/file changed, %d earlier non-kills or uncompilable under changed sources)\n", len(mine)-len(toRun), len(toRun), unseen, changed, nonkill)
	}
	// Coverage-guided test selection (default; -run turns it off for local dev). Every mutant used to run the WHOLE suite
	// (~65 s) and every shard paid a ~1 min baseline per file (86 files), so shards hit the 5 h job limit. Instead: one
	// coverage build, each top-level test run alone with a profile, and each mutant runs only the tests that execute its
	// position. A test that never executes the mutated code cannot observe the mutant, so this never turns a kill into a
	// survivor; a position outside every coverage block (package-level declarations, case expressions) runs the full suite.
	cov := *runf == "" && len(toRun) > 0
	var sel map[*Mut][]string // nil entry = full suite
	durOf := map[string]time.Duration{}
	var full time.Duration
	if cov {
		var err error
		sel, full, err = coverageSelect(abs, tmp, *tags, *par, toRun, durOf)
		if err != nil { fmt.Fprintf(os.Stderr, "go-mutate: %v; refusing to mutate\n", err); os.Exit(1) }
	}
	// Baseline per mutated file (non-coverage mode; same flags and GOMUT_FILE as its mutants): it must PASS (a failing
	// baseline would turn every mutant into a bogus kill), and it sets the per-mutant time limit. A fixed limit near the
	// suite's own run time counted almost every mutant as "killed-timeout" once the oracle tests grew.
	base := map[string]time.Duration{}
	for _, m := range toRun {
		if cov { break }
		if _, ok := base[m.File]; ok { continue }
		bargs := []string{"test", "-count=1"}
		if *tags != "" { bargs = append(bargs, "-tags", *tags) }
		if *runf != "" { bargs = append(bargs, "-run", *runf) }
		bc := exec.Command("go", append(bargs, ".")...)
		bc.Dir = abs
		bc.Env = append(os.Environ(), "GOMUT_FILE="+m.File)
		t0 := time.Now()
		if bo, err := bc.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "go-mutate: the unmutated baseline FAILS for %s; refusing to mutate:\n%s\n", m.File, bo)
			os.Exit(1)
		}
		base[m.File] = time.Since(t0)
		fmt.Fprintf(os.Stderr, "go-mutate: baseline %s %v\n", m.File, base[m.File].Round(time.Second))
	}
	limitOf := func(m *Mut) time.Duration {
		d := base[m.File]
		if cov {
			if names, ok := sel[m]; ok && names != nil {
				d = 0
				for _, n := range names { d += durOf[n] }
			} else { d = full }
		}
		// margin: a timeout is not a kill (it needs a proof that the mutant itself loops), so GC pauses, -j 3 contention and
		// slow runners must never time out a behaviour-preserving mutant
		l := 5*d + 30*time.Second
		if l < 60*time.Second { l = 60 * time.Second }
		return l
	}
	var doneN int64
	var doneMu sync.Mutex
	t0 := time.Now()
	// Every mutant's package build lands in GOCACHE (~100 MB for this package): ~150 mutants filled a runner's disk. Keep
	// what the cache held before the mutants ran and drop the rest every 20 mutants, with no mutant in flight (gc).
	var gc sync.RWMutex
	cacheDir, keep := cacheSnapshot()
	ch := make(chan *Mut)
	var wg sync.WaitGroup
	for w := 0; w < *par; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for m := range ch {
				// no test executes this position (in the unmutated run): nothing can observe the mutant, so it only gets
				// compiled (a mutant that does not compile is build-failed, not an uncovered survivor)
				uncovered := false
				if names, ok := sel[m]; cov && ok && len(names) == 0 { uncovered = true }
				gc.RLock()
				wt := filepath.Join(tmp, fmt.Sprintf("t%d", m.ID))
				os.MkdirAll(wt, 0o755)
				p := filepath.Join(abs, m.File)
				src, _ := os.ReadFile(p)
				mut := string(src[:m.start]) + m.repl + string(src[m.end:])
				mp := filepath.Join(tmp, fmt.Sprintf("m%d.go", m.ID))
				os.WriteFile(mp, []byte(mut), 0o644)
				ov, _ := json.Marshal(map[string]any{"Replace": map[string]string{p: mp}})
				op := filepath.Join(tmp, fmt.Sprintf("o%d.json", m.ID))
				os.WriteFile(op, ov, 0o644)
				lim := limitOf(m)
				hard := lim + time.Minute
				if *timeout > hard { hard = *timeout }
				ctx, cancel := context.WithTimeout(context.Background(), hard)
				targs := []string{"test", "-count=1", "-failfast", "-vet=off", "-timeout", lim.String(), "-overlay", op} // vet would turn a mutant such as `s == "a" && s == "b"` into a build failure no test decided
				if *tags != "" { targs = append(targs, "-tags", *tags) }
				if *runf != "" { targs = append(targs, "-run", *runf) }
				if names := sel[m]; cov && names != nil { targs = append(targs, "-run", "^("+strings.Join(names, "|")+")$") }
				if uncovered { targs = append(targs, "-run", "^$") }
				cmd := exec.Command("go", append(targs, ".")...)
				cmd.Dir = abs
				// GOTMPDIR: a killed (timed-out) go test leaves its test binary behind; it goes with wt
				cmd.Env = append(os.Environ(), "GOTMPDIR="+wt)
				// non-coverage mode: the heavy oracle tests run only when they cover the mutated file (k042RequireCovers)
				if !cov { cmd.Env = append(cmd.Env, "GOMUT_FILE="+m.File) }
				cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
				ob := &capOutput{}
				cmd.Stdout, cmd.Stderr = ob, ob
				cmd.Start()
				done := make(chan error, 1)
				go func() { done <- cmd.Wait() }()
				var err error
				timedOut := false
				select {
				case err = <-done:
				case <-ctx.Done():
					timedOut = true
					syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					err = <-done
				}
				o := []byte(ob.String())
				cancel()
				switch {
				case err == nil: m.Status = "SURVIVED"
				case strings.Contains(string(o), "[build failed]") || strings.Contains(string(o), "[setup failed]"): m.Status = "build-failed"
				case strings.Contains(string(o), "test timed out"): m.Status, m.Evidence = "killed-timeout", "go test -timeout "+lim.String()+" expired"
				case timedOut: m.Status, m.Evidence = "killed-timeout", "hard limit "+hard.String()+" expired"
				default:
					m.Status = "killed"
					if ev := runErrorEvidence(string(o)); ev != "" { m.Status, m.Evidence = "run-error", ev } else { m.Evidence = killedBy(string(o)) }
				}
				os.Remove(mp); os.Remove(op); os.RemoveAll(wt)
				gc.RUnlock()
				if m.Status == "run-error" { fmt.Printf("RUN-ERROR %d %s:%d:%d %s | %s | %s\n", m.ID, m.File, m.Line, m.col, m.Desc, m.Src, m.Evidence) }
				if m.Status == "SURVIVED" && uncovered { fmt.Printf("SURVIVED %d %s:%d:%d %s | %s (no test executes it)\n", m.ID, m.File, m.Line, m.col, m.Desc, m.Src) } else if m.Status == "SURVIVED" { fmt.Printf("SURVIVED %d %s:%d:%d %s | %s\n", m.ID, m.File, m.Line, m.col, m.Desc, m.Src) }
				doneMu.Lock(); doneN++; n := doneN
				if n%100 == 0 { fmt.Fprintf(os.Stderr, "go-mutate: %d/%d mutants run, %v\n", n, len(toRun), time.Since(t0).Round(time.Second)) }
				doneMu.Unlock()
				if n%20 == 0 { gc.Lock(); trimCache(cacheDir, keep); gc.Unlock() }
			}
		}(w)
	}
	for _, m := range toRun { ch <- m }
	close(ch); wg.Wait()
	cnt := map[string]int{}
	for _, m := range mine { cnt[m.Status]++ }
	fmt.Println("SUMMARY", *shard, cnt)
	if *out != "" { b, _ := json.MarshalIndent(mine, "", " "); os.WriteFile(*out, b, 0o644) }
}

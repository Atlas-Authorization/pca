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
		ln := fs.Position(p).Line
		label, dh := "", sum(nil)
		for _, sp := range spans {
			if s >= sp.start && s < sp.end { label, dh = sp.label, sp.hash; break }
		}
		m := Mut{File: filepath.Base(path), Line: ln, Desc: desc, Src: strings.TrimSpace(lines[ln-1]), start: s, end: en, repl: repl, DefHash: dh, ShellHash: shell}
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
				add(c.Pos(), c.End(), "true", "if-cond -> true")
				add(c.Pos(), c.End(), "false", "if-cond -> false")
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
		case *ast.CaseClause:
			// nothing
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
	// (killed), or the whole production source is identical (build-failed: another file may have made it compile). Survivors,
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
			case e.S == "killed" || e.S == "killed-timeout" || (e.S == "build-failed" && e.A == m.SrcHash):
				m.Status, m.Carried = e.S, true
				continue
			default: nonkill++
			}
			toRun = append(toRun, m)
		}
		fmt.Fprintf(os.Stderr, "go-mutate: carry: %d result(s) carried, %d to run (%d unseen, %d function/file changed, %d earlier non-kills or uncompilable under changed sources)\n", len(mine)-len(toRun), len(toRun), unseen, changed, nonkill)
	}
	// Baseline per mutated file (same flags and GOMUT_FILE as its mutants): it must PASS (a failing baseline would turn
	// every mutant into a bogus kill), and it sets the per-mutant time limit. A fixed limit near the suite's own run time
	// counted almost every mutant as "killed-timeout" once the oracle tests grew (the baseline took 40.0 s against 40 s).
	base := map[string]time.Duration{}
	for _, m := range toRun {
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
	limitOf := func(f string) time.Duration {
		l := 3*base[f] + 15*time.Second
		if l < 40*time.Second { l = 40 * time.Second }
		return l
	}
	ch := make(chan *Mut)
	var wg sync.WaitGroup
	for w := 0; w < *par; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for m := range ch {
				p := filepath.Join(abs, m.File)
				src, _ := os.ReadFile(p)
				mut := string(src[:m.start]) + m.repl + string(src[m.end:])
				mp := filepath.Join(tmp, fmt.Sprintf("m%d.go", m.ID))
				os.WriteFile(mp, []byte(mut), 0o644)
				ov, _ := json.Marshal(map[string]any{"Replace": map[string]string{p: mp}})
				op := filepath.Join(tmp, fmt.Sprintf("o%d.json", m.ID))
				os.WriteFile(op, ov, 0o644)
				lim := limitOf(m.File)
				hard := lim + time.Minute
				if *timeout > hard { hard = *timeout }
				ctx, cancel := context.WithTimeout(context.Background(), hard)
				targs := []string{"test", "-count=1", "-failfast", "-timeout", lim.String(), "-overlay", op}
				if *tags != "" { targs = append(targs, "-tags", *tags) }
				if *runf != "" { targs = append(targs, "-run", *runf) }
				cmd := exec.Command("go", append(targs, ".")...)
				cmd.Dir = abs
				// the heavy oracle tests run only when they cover the mutated file (see k042RequireCovers in the tests)
				cmd.Env = append(os.Environ(), "GOMUT_FILE="+m.File)
				cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
				var ob strings.Builder
				cmd.Stdout, cmd.Stderr = &ob, &ob
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
				case strings.Contains(string(o), "test timed out"): m.Status = "killed-timeout"
				case timedOut: m.Status = "killed-timeout"
				default: m.Status = "killed"
				}
				os.Remove(mp); os.Remove(op)
				if m.Status == "SURVIVED" { fmt.Printf("SURVIVED %d %s:%d %s | %s\n", m.ID, m.File, m.Line, m.Desc, m.Src) }
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

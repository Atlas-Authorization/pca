// go-mutate: minimal AST-guided mutation tester for sdks/go-pca (go-mutesting/gremlins stand-in; uses `go test -overlay`
// so shards run in parallel on one tree). Usage: go-mutate -dir <module dir> [-shard i/n] [-list] [-files a.go,b.go] [-tags t1,t2] [-out f.json]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
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
	add := func(p, e token.Pos, repl, desc string) {
		s, en := fs.Position(p).Offset, fs.Position(e).Offset
		ln := fs.Position(p).Line
		ms = append(ms, Mut{File: filepath.Base(path), Line: ln, Desc: desc, Src: strings.TrimSpace(lines[ln-1]), start: s, end: en, repl: repl})
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
	ids := flag.String("ids", "", "comma list of mutant ids to run (default all)")
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
	for i := range all { all[i].ID = i }
	if *list { for _, m := range all { fmt.Printf("%d %s:%d %s | %s\n", m.ID, m.File, m.Line, m.Desc, m.Src) }; fmt.Println("total", len(all)); return }
	tmp, _ := os.MkdirTemp("", "gomut")
	defer os.RemoveAll(tmp)
	var mine []*Mut
	want := map[int]bool{}
	for _, s := range strings.Split(*ids, ",") { var n int; if _, e := fmt.Sscanf(s, "%d", &n); e == nil { want[n] = true } }
	for i := range all { if i%sn == si && (len(*ids) == 0 || want[i]) { mine = append(mine, &all[i]) } }
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
				ctx, cancel := context.WithTimeout(context.Background(), *timeout)
				targs := []string{"test", "-count=1", "-timeout", "40s", "-overlay", op}
				if *tags != "" { targs = append(targs, "-tags", *tags) }
				cmd := exec.Command("go", append(targs, ".")...)
				cmd.Dir = abs
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
				case timedOut: m.Status = "killed-timeout"
				default: m.Status = "killed"
				}
				os.Remove(mp); os.Remove(op)
				if m.Status == "SURVIVED" { fmt.Printf("SURVIVED %d %s:%d %s | %s\n", m.ID, m.File, m.Line, m.Desc, m.Src) }
			}
		}(w)
	}
	for _, m := range mine { ch <- m }
	close(ch); wg.Wait()
	cnt := map[string]int{}
	for _, m := range mine { cnt[m.Status]++ }
	fmt.Println("SUMMARY", *shard, cnt)
	if *out != "" { b, _ := json.MarshalIndent(mine, "", " "); os.WriteFile(*out, b, 0o644) }
}

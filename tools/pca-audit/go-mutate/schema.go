package main

// Mutant schemata (prep mode): every mutant the type checker accepts is compiled into ONE test binary of the package, each
// guarded by `gomutID == <id>` (GOMUT_ID at run time), so a mutant costs one run of its selected tests instead of a package
// rebuild + link. The guarded copy of a mutant is the mutant's own source text (the same replacement a standalone build
// applies), placed where it runs exactly when and how the standalone mutant would; the unmutated copy keeps the original
// line:col positions (/*line*/ directives), so panics, runtime.Caller and error texts read the same. Whatever cannot be
// guarded exactly (constant contexts, cgo and generic code, labelled switch headers, ...) stays a standalone build ("build"
// mode, the old path). A mutant the type checker rejects is build-failed without a build; prep cross-checks a sample of
// both verdicts and of each guard kind against real standalone builds and refuses a plan on any mismatch.

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/scanner"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type verdict int8

const (
	vUnknown verdict = iota // only a real build can tell
	vOK                     // compiles as a standalone mutant
	vFail                   // a standalone build of it fails
)

// site kinds, in nesting priority for equal ranges (outer first)
const (
	kCaseBody = iota // a case clause body ("remove case body")
	kRest            // a declaration statement + the rest of its statement list
	kInitDecl        // an if / switch header's := init, hoisted into a block around the statement
	kHoist           // an impure switch tag / range expression, hoisted into a block around the statement
	kStmt            // a statement in a statement list
	kDecl            // a := or var statement in a statement list (typed declarations + guarded assignment)
	kClosure         // a simple statement in a header (for init/post, if/switch init): an immediately called closure
	kCond            // a boolean condition (if / for / tagless case): exactly one copy is evaluated
	kPick            // a pure expression: gomutP[T](active, mutated, original)
)

var kindName = []string{"case-body", "rest", "init-decl", "hoist", "stmt", "decl", "closure", "cond", "pick"}

type site struct {
	file   string
	kind   int
	a, b   int // replaced region (byte offsets in the original file)
	ra, rb int // the part that differs between the copies (kDecl / kInitDecl / kHoist)
	typ    string
	decls  string
	lhs    string
	kw     string
	cont   int
	muts   []*Mut
	kids   []*site
	dead   bool
}

type fileInfo struct {
	name   string
	path   string
	src    []byte
	f      *ast.File
	tf     *token.File
	cgo    bool
	pkgNms []*types.PkgName // the file's imports (not _ or .)
}

type analysis struct {
	abs    string
	fset   *token.FileSet
	files  map[string]*fileInfo
	pkg    *types.Package
	info   *types.Info
	ok     bool
	uses   map[types.Object][]token.Pos // every reference (prod files)
	testID map[string]bool              // identifiers that appear in the package's _test.go files
	fnBase map[*ast.FuncDecl]verdict
}

func newAnalysis(abs, tags string, names []string) (*analysis, error) {
	a := &analysis{abs: abs, fset: token.NewFileSet(), files: map[string]*fileInfo{}, uses: map[types.Object][]token.Pos{}, testID: map[string]bool{}, fnBase: map[*ast.FuncDecl]verdict{}}
	var list []*ast.File
	for _, n := range names {
		p := filepath.Join(abs, n)
		src, err := os.ReadFile(p)
		if err != nil { return nil, err }
		f, err := parser.ParseFile(a.fset, p, src, parser.ParseComments)
		if err != nil { return nil, err }
		fi := &fileInfo{name: n, path: p, src: src, f: f, tf: a.fset.File(f.Pos())}
		for _, im := range f.Imports { if im.Path.Value == `"C"` { fi.cgo = true } }
		a.files[n] = fi
		list = append(list, f)
	}
	// identifiers of the test files (package-level selection: a test that names an object reads it without any prod block)
	if g, _ := filepath.Glob(filepath.Join(abs, "*_test.go")); len(g) > 0 {
		for _, p := range g {
			src, err := os.ReadFile(p)
			if err != nil { return nil, err }
			var sc scanner.Scanner
			sc.Init(token.NewFileSet().AddFile(p, -1, len(src)), src, nil, 0)
			for {
				_, tok, lit := sc.Scan()
				if tok == token.EOF { break }
				if tok == token.IDENT { a.testID[lit] = true }
			}
		}
	}
	exports, err := goListExports(abs, tags)
	if err != nil { return nil, err }
	imp := importer.ForCompiler(a.fset, "gc", func(path string) (io.ReadCloser, error) {
		f, ok := exports[path]
		if !ok || f == "" { return nil, fmt.Errorf("no export data for %s", path) }
		return os.Open(f)
	})
	a.info = &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{},
		Implicits: map[ast.Node]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
	var errs []error
	conf := types.Config{Importer: imp, FakeImportC: true, Sizes: types.SizesFor("gc", runtime.GOARCH), GoVersion: goVersion(abs),
		Error: func(err error) { errs = append(errs, err) }}
	a.pkg, _ = conf.Check(list[0].Name.Name, a.fset, list, a.info)
	bad := 0
	for _, e := range errs {
		if te, ok := e.(types.Error); ok {
			if fi := a.files[filepath.Base(a.fset.Position(te.Pos).Filename)]; fi != nil && fi.cgo { continue } // FakeImportC leftovers
		}
		if bad < 10 { fmt.Fprintf(os.Stderr, "go-mutate: type check: %v\n", e) }
		bad++
	}
	a.ok = a.pkg != nil && bad == 0
	if !a.ok { fmt.Fprintf(os.Stderr, "go-mutate: the package does not type-check (%d error(s)): every mutant is a standalone build\n", bad) }
	for id, obj := range a.info.Uses { a.uses[obj] = append(a.uses[obj], id.Pos()) }
	for _, fi := range a.files {
		for _, im := range fi.f.Imports {
			var obj types.Object
			if im.Name != nil { obj = a.info.Defs[im.Name] } else { obj = a.info.Implicits[im] }
			if pn, ok := obj.(*types.PkgName); ok && pn.Name() != "_" && pn.Name() != "." { fi.pkgNms = append(fi.pkgNms, pn) }
		}
	}
	return a, nil
}

func goListExports(abs, tags string) (map[string]string, error) {
	args := []string{"list", "-export", "-deps", "-f", "{{.ImportPath}}\t{{.Export}}"}
	if tags != "" { args = append(args, "-tags", tags) }
	c := exec.Command("go", append(args, ".")...)
	c.Dir = abs
	out, err := c.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok { return nil, fmt.Errorf("go list -export: %v\n%s", err, tail(string(ee.Stderr), 2000)) }
		return nil, fmt.Errorf("go list -export: %v", err)
	}
	m := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		if p, e, ok := strings.Cut(l, "\t"); ok { m[p] = e }
	}
	return m, nil
}

func goVersion(abs string) string {
	b, _ := os.ReadFile(filepath.Join(abs, "go.mod"))
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "go" { return "go" + f[1] }
	}
	return ""
}

func (a *analysis) off(fi *fileInfo, p token.Pos) int { return fi.tf.Offset(p) }

// pathTo: the chain of nodes (file first) that contain [s, e).
func (a *analysis) pathTo(fi *fileInfo, s, e int) []ast.Node {
	var path []ast.Node
	ast.Inspect(fi.f, func(n ast.Node) bool {
		if n == nil || !n.Pos().IsValid() || !n.End().IsValid() { return false }
		if a.off(fi, n.Pos()) <= s && e <= a.off(fi, n.End()) { path = append(path, n); return true }
		return false
	})
	return path
}

func generic(fd *ast.FuncDecl) bool {
	if fd.Type.TypeParams != nil { return true }
	if fd.Recv != nil && len(fd.Recv.List) == 1 {
		t := fd.Recv.List[0].Type
		if s, ok := t.(*ast.StarExpr); ok { t = s.X }
		switch t.(type) { case *ast.IndexExpr, *ast.IndexListExpr: return true }
	}
	return false
}

func (a *analysis) text(fi *fileInfo, n ast.Node) string { return string(fi.src[a.off(fi, n.Pos()):a.off(fi, n.End())]) }

// funcLit: the function as a function literal (receiver first), with m applied when m != nil.
func (a *analysis) funcLit(fi *fileInfo, fd *ast.FuncDecl, m *Mut) string {
	var b strings.Builder
	b.WriteString("func(")
	var ps []string
	if fd.Recv != nil {
		for _, f := range fd.Recv.List { ps = append(ps, fieldText(a, fi, f)...) }
	}
	for _, f := range fd.Type.Params.List { ps = append(ps, fieldText(a, fi, f)...) }
	b.WriteString(strings.Join(ps, ", ") + ")")
	if rs := fd.Type.Results; rs != nil { b.WriteString(" " + a.text(fi, rs)) }
	b.WriteString(" ")
	lo, hi := a.off(fi, fd.Body.Lbrace), a.off(fi, fd.Body.Rbrace)+1
	if m == nil { b.Write(fi.src[lo:hi]) } else { b.Write(fi.src[lo:m.start]); b.WriteString(m.repl); b.Write(fi.src[m.end:hi]) }
	return b.String()
}

// fieldText names every parameter (a literal cannot mix named and unnamed ones once the receiver is a parameter)
func fieldText(a *analysis, fi *fileInfo, f *ast.Field) []string {
	t := a.text(fi, f.Type)
	if len(f.Names) == 0 { return []string{"_ " + t} }
	var out []string
	for _, n := range f.Names { out = append(out, n.Name+" "+t) }
	return out
}

func (a *analysis) checkExpr(fi *fileInfo, text string) error {
	e, err := parser.ParseExprFrom(a.fset, "gomut-check.go", text, parser.SkipObjectResolution)
	if err != nil { return err }
	return types.CheckExpr(a.fset, a.pkg, fi.f.Name.End(), e, nil)
}

// verdict: does the standalone mutant compile? Exact for mutants in a non-generic function body or a package-level var
// initializer (types.CheckExpr of the mutated function / initializer, plus file-level unused imports); vUnknown otherwise.
func (a *analysis) verdict(m *Mut) (verdict, string) {
	fi := a.files[m.File]
	if !a.ok || fi == nil || fi.cgo { return vUnknown, "" }
	var top ast.Decl
	for _, d := range fi.f.Decls {
		if a.off(fi, d.Pos()) <= m.start && m.end <= a.off(fi, d.End()) { top = d; break }
	}
	switch d := top.(type) {
	case *ast.FuncDecl:
		if d.Body == nil || generic(d) || m.start < a.off(fi, d.Body.Lbrace) || m.end > a.off(fi, d.Body.Rbrace)+1 { return vUnknown, "" }
		base, ok := a.fnBase[d]
		if !ok {
			base = vOK
			if err := a.checkExpr(fi, a.funcLit(fi, d, nil)); err != nil {
				base = vUnknown
				fmt.Fprintf(os.Stderr, "go-mutate: %s: %s does not check as a literal (%v): its mutants are standalone builds\n", m.File, d.Name.Name, err)
			}
			a.fnBase[d] = base
		}
		if base != vOK { return vUnknown, "" }
		if err := a.checkExpr(fi, a.funcLit(fi, d, m)); err != nil { return vFail, "type check: " + err.Error() }
	case *ast.GenDecl:
		if d.Tok != token.VAR { return vUnknown, "" }
		var spec *ast.ValueSpec
		for _, s := range d.Specs {
			if a.off(fi, s.Pos()) <= m.start && m.end <= a.off(fi, s.End()) { spec, _ = s.(*ast.ValueSpec) }
		}
		if spec == nil || len(spec.Values) != len(spec.Names) { return vUnknown, "" }
		j := -1
		for i, v := range spec.Values { if a.off(fi, v.Pos()) <= m.start && m.end <= a.off(fi, v.End()) { j = i } }
		if j < 0 { return vUnknown, "" }
		v := spec.Values[j]
		lo, hi := a.off(fi, v.Pos()), a.off(fi, v.End())
		lhs := "_ ="
		if spec.Type != nil { lhs = "var _ " + a.text(fi, spec.Type) + " =" }
		wrap := func(body string) string { return "func() {\n" + lhs + " (" + body + ")\n}" }
		if err := a.checkExpr(fi, wrap(string(fi.src[lo:hi]))); err != nil { return vUnknown, "" }
		if err := a.checkExpr(fi, wrap(string(fi.src[lo:m.start])+m.repl+string(fi.src[m.end:hi]))); err != nil { return vFail, "type check: " + err.Error() }
	default:
		return vUnknown, ""
	}
	// an import whose every use the mutant removes is "imported and not used" (a replacement that keeps the original text,
	// such as if-cond -> "(cond) || true", removes none)
	if strings.Contains(m.repl, string(fi.src[m.start:m.end])) { return vOK, "" }
	for _, pn := range fi.pkgNms {
		us, all := 0, true
		for _, p := range a.uses[pn] {
			if a.fset.File(p) != fi.tf { continue }
			us++
			if o := a.off(fi, p); o < m.start || o >= m.end { all = false }
		}
		if us > 0 && all { return vFail, "type check: " + strconv.Quote(pn.Imported().Path()) + " imported and not used" }
	}
	return vOK, ""
}

func (fi *fileInfo) importName(path string) string {
	for _, pn := range fi.pkgNms { if pn.Imported().Path() == path { return pn.Name() } }
	return ""
}

// typeText: t written so that it means t at a site in fi, or false.
func (a *analysis) typeText(t types.Type, fi *fileInfo) (string, bool) {
	t = types.Default(t)
	ok := true
	own := func(o types.Object) { if o.Pkg() != nil && o.Pkg() != a.pkg && !o.Exported() { ok = false } }
	var walk func(t types.Type, depth int)
	walkTuple := func(tu *types.Tuple, depth int) { for i := 0; i < tu.Len(); i++ { walk(tu.At(i).Type(), depth+1) } }
	walk = func(t types.Type, depth int) {
		if !ok { return }
		if depth > 40 { ok = false; return }
		switch x := t.(type) {
		case *types.Basic:
			if x.Info()&types.IsUntyped != 0 || x.Kind() == types.Invalid { ok = false }
			if x.Kind() == types.UnsafePointer && fi.importName("unsafe") != "unsafe" { ok = false }
		case *types.Named:
			own(x.Obj())
			if ta := x.TypeArgs(); ta != nil { for i := 0; i < ta.Len(); i++ { walk(ta.At(i), depth+1) } }
		case *types.Alias:
			own(x.Obj())
			if ta := x.TypeArgs(); ta != nil { for i := 0; i < ta.Len(); i++ { walk(ta.At(i), depth+1) } }
		case *types.Pointer:
			walk(x.Elem(), depth+1)
		case *types.Slice:
			walk(x.Elem(), depth+1)
		case *types.Array:
			walk(x.Elem(), depth+1)
		case *types.Map:
			walk(x.Key(), depth+1); walk(x.Elem(), depth+1)
		case *types.Chan:
			walk(x.Elem(), depth+1)
		case *types.Signature:
			if x.TypeParams() != nil { ok = false; return }
			walkTuple(x.Params(), depth); walkTuple(x.Results(), depth)
		case *types.Struct:
			for i := 0; i < x.NumFields(); i++ { own(x.Field(i)); walk(x.Field(i).Type(), depth+1) }
		case *types.Interface:
			if x.IsImplicit() { ok = false; return }
			for i := 0; i < x.NumExplicitMethods(); i++ { own(x.ExplicitMethod(i)); walk(x.ExplicitMethod(i).Type(), depth+1) }
			for i := 0; i < x.NumEmbeddeds(); i++ { walk(x.EmbeddedType(i), depth+1) }
		default:
			ok = false
		}
	}
	walk(t, 0)
	if !ok { return "", false }
	s := types.TypeString(t, func(p *types.Package) string {
		if p == a.pkg { return "" }
		n := fi.importName(p.Path())
		if n == "" { ok = false }
		return n
	})
	return s, ok
}

func isBool(t types.Type) bool {
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsBoolean != 0
}

// pure: evaluating e (or m's mutant of it) can neither panic nor have a side effect, so both copies may be evaluated.
func (a *analysis) pure(fi *fileInfo, e ast.Expr, m *Mut) bool {
	if tv, ok := a.info.Types[e]; ok && tv.Value != nil { return true }
	ok := true
	ast.Inspect(e, func(n ast.Node) bool {
		if !ok || n == nil { return false }
		if x, isE := n.(ast.Expr); isE {
			if tv, has := a.info.Types[x]; has && tv.Value != nil { return false }
		}
		switch x := n.(type) {
		case *ast.Ident, *ast.BasicLit, *ast.ParenExpr, *ast.KeyValueExpr:
		case *ast.FuncLit:
			return false // creating a closure runs nothing
		case *ast.CompositeLit:
			for _, el := range x.Elts { if !a.pure(fi, el, m) { ok = false } }
			return false
		case *ast.UnaryExpr:
			if x.Op == token.ARROW { ok = false }
		case *ast.BinaryExpr:
			op := x.Op.String()
			if m != nil && a.off(fi, x.OpPos) == m.start { op = m.repl }
			y := a.info.Types[x.Y]
			if y.Type == nil || a.info.Types[x.X].Type == nil { ok = false; return false }
			switch op {
			case "/", "%":
				if b, isB := y.Type.Underlying().(*types.Basic); !isB || b.Info()&types.IsInteger != 0 {
					if y.Value == nil || constant.Sign(y.Value) == 0 { ok = false }
				}
			case "<<", ">>":
				if y.Value == nil { ok = false }
			case "==", "!=":
				switch a.info.Types[x.X].Type.Underlying().(type) {
				case *types.Basic, *types.Pointer, *types.Chan:
				default:
					ok = false
				}
			}
		case *ast.SelectorExpr:
			if sel, has := a.info.Selections[x]; has && (sel.Kind() != types.FieldVal || sel.Indirect()) { ok = false }
			if ok && !a.pure(fi, x.X, m) { ok = false }
			return false
		case *ast.CallExpr:
			tv := a.info.Types[x.Fun]
			switch {
			case tv.IsType():
				switch tv.Type.Underlying().(type) {
				case *types.Basic, *types.Interface, *types.Slice:
				default:
					ok = false
				}
			case tv.IsBuiltin():
				id, _ := ast.Unparen(x.Fun).(*ast.Ident)
				if id == nil { ok = false; return false }
				switch id.Name { case "len", "cap", "min", "max", "real", "imag", "complex": default: ok = false }
			default:
				ok = false
			}
			for _, arg := range x.Args { if ok && !a.pure(fi, arg, m) { ok = false } }
			return false
		default:
			ok = false
		}
		return ok
	})
	return ok
}

func (a *analysis) siteKey(s *site) string { return fmt.Sprintf("%s|%d|%d|%d", s.file, s.kind, s.a, s.b) }

// siteFor: the guard that runs m exactly like its standalone build, or nil (build mode).
func (a *analysis) siteFor(m *Mut) *site {
	fi := a.files[m.File]
	if fi == nil || fi.cgo { return nil }
	P := a.pathTo(fi, m.start, m.end)
	// a literal in a type (array length: [2]T{...}, x.([4]T), [3]byte(s), G[[2]T]) changes the type, which no run-time switch
	// can do: such a mutant is a standalone build (its type-check verdict already made it build-failed when it cannot compile)
	for _, n := range P[1:] { if a.isTypeExpr(n) { return nil } }
	if m.Desc == "remove case body" {
		for _, n := range P {
			cc, ok := n.(*ast.CaseClause)
			if !ok || len(cc.Body) == 0 || a.off(fi, cc.Body[0].Pos()) != m.start || a.off(fi, cc.Body[len(cc.Body)-1].End()) != m.end { continue }
			if br, ok := cc.Body[len(cc.Body)-1].(*ast.BranchStmt); ok && br.Tok == token.FALLTHROUGH { return nil }
			return &site{file: m.File, kind: kCaseBody, a: m.start, b: m.end}
		}
		return nil
	}
	for i := len(P) - 1; i >= 1; i-- {
		st, isS := P[i].(ast.Stmt)
		if !isS { continue }
		var child ast.Node
		if i+1 < len(P) { child = P[i+1] }
		return a.stmtSite(fi, m, P, i, st, child)
	}
	return a.pkgSite(fi, m, P)
}

func (a *analysis) isTypeExpr(n ast.Node) bool {
	switch n.(type) {
	case *ast.ArrayType, *ast.StructType, *ast.FuncType, *ast.MapType, *ast.ChanType, *ast.InterfaceType, *ast.Ellipsis:
		return true
	}
	e, ok := n.(ast.Expr)
	return ok && a.info.Types[e].IsType()
}

// listOf: the statement list holding st and st's index in it (a labelled statement is not a list element here).
func listOf(parent ast.Node, st ast.Stmt) ([]ast.Stmt, int) {
	var l []ast.Stmt
	switch p := parent.(type) {
	case *ast.BlockStmt: l = p.List
	case *ast.CaseClause: l = p.Body
	case *ast.CommClause: l = p.Body
	}
	for i, s := range l { if s == st { return l, i } }
	return nil, -1
}

func (a *analysis) stmtSite(fi *fileInfo, m *Mut, P []ast.Node, i int, st ast.Stmt, child ast.Node) *site {
	parent := P[i-1]
	list, idx := listOf(parent, st)
	inList := idx >= 0
	labelled := false
	if _, ok := parent.(*ast.LabeledStmt); ok {
		labelled = true
		if gp := P[i-2]; gp != nil { _, j := listOf(gp, parent.(ast.Stmt)); inList = j >= 0 }
	}
	S := &site{file: m.File, a: a.off(fi, st.Pos()), b: a.off(fi, st.End())}
	switch x := st.(type) {
	case *ast.CaseClause:
		e, isE := child.(ast.Expr)
		if !isE || i < 3 { return nil }
		sw, isSw := P[i-2].(*ast.SwitchStmt)
		if !isSw { return nil }
		if sw.Tag == nil { return a.condSite(fi, m, e) }
		return a.pickSite(fi, m, e)
	case *ast.IfStmt:
		if child == x.Cond { return a.condSite(fi, m, x.Cond) }
		return nil
	case *ast.ForStmt:
		if child == x.Cond { return a.condSite(fi, m, x.Cond) }
		return nil
	case *ast.SwitchStmt:
		if child != x.Tag || x.Tag == nil { return nil }
		if s := a.pickSite(fi, m, x.Tag); s != nil { return s }
		if x.Init != nil || labelled { return nil }
		return a.hoistSite(fi, m, st, x.Tag)
	case *ast.RangeStmt:
		if child != x.X { return nil }
		if s := a.pickSite(fi, m, x.X); s != nil { return s }
		if labelled { return nil }
		if x.Value == nil { // at most one iteration variable and a constant len: the range expression is not evaluated
			t := a.info.Types[x.X].Type
			if t == nil { return nil }
			if p, ok := t.Underlying().(*types.Pointer); ok { t = p.Elem() }
			if _, ok := t.Underlying().(*types.Array); ok { return nil }
		}
		return a.hoistSite(fi, m, st, x.X)
	case *ast.DeclStmt:
		if !inList || labelled { return nil }
		gd := x.Decl.(*ast.GenDecl)
		if gd.Tok == token.VAR && len(gd.Specs) == 1 {
			vs := gd.Specs[0].(*ast.ValueSpec)
			if len(vs.Values) > 0 && m.start >= a.off(fi, vs.Values[0].Pos()) && m.end <= a.off(fi, vs.Values[len(vs.Values)-1].End()) {
				var names []string
				for _, n := range vs.Names { names = append(names, n.Name) }
				S.kind, S.lhs = kDecl, strings.Join(names, ", ")
				S.ra, S.rb = a.off(fi, vs.Values[0].Pos()), a.off(fi, vs.Values[len(vs.Values)-1].End())
				if vs.Type != nil {
					S.decls = "var " + S.lhs + " " + a.text(fi, vs.Type) + "; "
					return S
				}
				if d, ok := a.declsOf(fi, vs.Names); ok { S.decls = d; return S }
			}
		}
		return a.restSite(fi, m, list, idx)
	case *ast.AssignStmt:
		if x.Tok == token.DEFINE {
			ra, rb := a.off(fi, x.Rhs[0].Pos()), a.off(fi, x.Rhs[len(x.Rhs)-1].End())
			if m.start < ra || m.end > rb { return nil }
			var lhs []string
			var ids []*ast.Ident
			for _, l := range x.Lhs {
				id, _ := l.(*ast.Ident)
				if id == nil { return nil }
				lhs = append(lhs, id.Name)
				if id.Name != "_" && a.info.Defs[id] != nil { ids = append(ids, id) }
			}
			switch p := parent.(type) {
			case *ast.ForStmt:
				if p.Init != st { return nil }
				for _, r := range x.Rhs { if a.off(fi, r.Pos()) <= m.start && m.end <= a.off(fi, r.End()) { return a.pickSite(fi, m, r) } }
				return nil
			case *ast.IfStmt, *ast.SwitchStmt:
				if !stmtIs(p, st) { return nil }
				if _, sw := p.(*ast.SwitchStmt); sw && i >= 2 { if _, l := P[i-2].(*ast.LabeledStmt); l { return nil } }
				d, ok := a.declsOf(fi, ids)
				if !ok { return nil }
				N := p.(ast.Stmt)
				I := &site{file: m.File, kind: kInitDecl, a: a.off(fi, N.Pos()), b: a.off(fi, N.End()), ra: ra, rb: rb, decls: d, lhs: strings.Join(lhs, ", ")}
				if q, ok := p.(*ast.IfStmt); ok { I.kw, I.cont = "if", a.off(fi, q.Cond.Pos()) } else {
					q := p.(*ast.SwitchStmt)
					I.kw = "switch"
					if q.Tag != nil { I.cont = a.off(fi, q.Tag.Pos()) } else { I.cont = a.off(fi, q.Body.Lbrace) }
				}
				return I
			}
			if !inList || labelled { return nil }
			if d, ok := a.declsOf(fi, ids); ok {
				S.kind, S.decls, S.lhs, S.ra, S.rb = kDecl, d, strings.Join(lhs, ", "), ra, rb
				return S
			}
			return a.restSite(fi, m, list, idx)
		}
	}
	switch st.(type) {
	case *ast.ExprStmt, *ast.SendStmt, *ast.IncDecStmt, *ast.AssignStmt, *ast.GoStmt, *ast.DeferStmt, *ast.ReturnStmt, *ast.BranchStmt:
	default:
		return nil
	}
	if inList {
		S.kind = kStmt
		return S
	}
	switch p := parent.(type) {
	case *ast.ForStmt:
		if p.Init == st || p.Post == st { S.kind = kClosure; return S }
	case *ast.IfStmt:
		if p.Init == st { S.kind = kClosure; return S }
	case *ast.SwitchStmt:
		if p.Init == st { S.kind = kClosure; return S }
	}
	return nil
}

func stmtIs(p ast.Node, st ast.Stmt) bool {
	switch q := p.(type) {
	case *ast.IfStmt: return q.Init == st
	case *ast.SwitchStmt: return q.Init == st
	}
	return false
}

func (a *analysis) declsOf(fi *fileInfo, ids []*ast.Ident) (string, bool) {
	var b strings.Builder
	for _, id := range ids {
		obj := a.info.Defs[id]
		if obj == nil { return "", false }
		t, ok := a.typeText(obj.Type(), fi)
		if !ok { return "", false }
		b.WriteString("var " + id.Name + " " + t + "; ")
	}
	return b.String(), true
}

func (a *analysis) condSite(fi *fileInfo, m *Mut, e ast.Expr) *site {
	tv, ok := a.info.Types[e]
	if !ok || tv.Type == nil || !isBool(tv.Type) { return nil }
	return &site{file: m.File, kind: kCond, a: a.off(fi, e.Pos()), b: a.off(fi, e.End())}
}

func (a *analysis) pickSite(fi *fileInfo, m *Mut, e ast.Expr) *site {
	tv, ok := a.info.Types[e]
	if !ok || tv.Type == nil || !a.pure(fi, e, m) { return nil }
	t, ok := a.typeText(tv.Type, fi)
	if !ok { return nil }
	return &site{file: m.File, kind: kPick, a: a.off(fi, e.Pos()), b: a.off(fi, e.End()), typ: t}
}

func (a *analysis) hoistSite(fi *fileInfo, m *Mut, st ast.Stmt, e ast.Expr) *site {
	tv, ok := a.info.Types[e]
	if !ok || tv.Type == nil { return nil }
	t, ok := a.typeText(tv.Type, fi)
	if !ok { return nil }
	return &site{file: m.File, kind: kHoist, a: a.off(fi, st.Pos()), b: a.off(fi, st.End()), ra: a.off(fi, e.Pos()), rb: a.off(fi, e.End()), typ: t}
}

// restSite: the declaration and everything after it in its list, one copy per mutant (labels would be duplicated: refused;
// a trailing fallthrough cannot move into a block: refused; large copies stay standalone builds).
func (a *analysis) restSite(fi *fileInfo, m *Mut, list []ast.Stmt, idx int) *site {
	if idx < 0 { return nil }
	last := list[len(list)-1]
	if br, ok := last.(*ast.BranchStmt); ok && br.Tok == token.FALLTHROUGH { return nil }
	lab := false
	for _, s := range list[idx:] {
		ast.Inspect(s, func(n ast.Node) bool {
			switch n.(type) {
			case *ast.FuncLit: return false
			case *ast.LabeledStmt: lab = true
			}
			return !lab
		})
	}
	if lab { return nil }
	S := &site{file: m.File, kind: kRest, a: a.off(fi, list[idx].Pos()), b: a.off(fi, last.End())}
	if S.b-S.a > 16<<10 { return nil }
	return S
}

// pkgSite: a mutant in a package-level var initializer, outside every function literal: the outermost constant
// subexpression around it is picked (both copies are constants), unless it sits where a constant is required.
func (a *analysis) pkgSite(fi *fileInfo, m *Mut, P []ast.Node) *site {
	if len(P) < 3 { return nil }
	gd, ok := P[1].(*ast.GenDecl)
	if !ok || gd.Tok != token.VAR { return nil }
	vs, ok := P[2].(*ast.ValueSpec)
	if !ok { return nil }
	in := false
	for _, v := range vs.Values { if a.off(fi, v.Pos()) <= m.start && m.end <= a.off(fi, v.End()) { in = true } }
	if !in { return nil }
	for j := 3; j < len(P); j++ {
		switch x := P[j].(type) {
		case *ast.ArrayType, *ast.StructType, *ast.FuncType, *ast.MapType, *ast.ChanType, *ast.Ellipsis, *ast.InterfaceType, *ast.IndexListExpr:
			return nil
		case *ast.KeyValueExpr:
			if j+1 < len(P) && P[j+1] == x.Key { return nil }
		case *ast.IndexExpr:
			if tv := a.info.Types[x.X]; tv.IsType() || isGenericFunc(tv.Type) { return nil }
		}
		e, isE := P[j].(ast.Expr)
		if !isE { continue }
		tv, ok := a.info.Types[e]
		if !ok || tv.Value == nil { continue }
		return a.pickSite(fi, m, e)
	}
	return nil
}

func isGenericFunc(t types.Type) bool {
	s, ok := t.(*types.Signature)
	return ok && s.TypeParams() != nil
}

// pkgSelect: the tests that can observe a mutant of a package-level var/const declaration, from the references to the
// objects it declares (and to every package-level var/const whose declaration refers to those, transitively). Any reference
// the coverage cannot see (an init function, a declaration's type, a signature, a test file naming it, an initializer that
// calls something) means the full suite (ok = false).
func (a *analysis) pkgSelect(m *Mut, blocks map[string]map[string]*covBlock) ([]string, bool) {
	fi := a.files[m.File]
	if !a.ok || fi == nil { return nil, false }
	P := a.pathTo(fi, m.start, m.end)
	if len(P) < 3 { return nil, false }
	gd, ok := P[1].(*ast.GenDecl)
	if !ok || (gd.Tok != token.VAR && gd.Tok != token.CONST) { return nil, false }
	vs, ok := P[2].(*ast.ValueSpec)
	if !ok { return nil, false }
	for _, n := range P[3:] { if _, lit := n.(*ast.FuncLit); lit { return nil, false } }
	set := map[types.Object]bool{}
	seed := func(g *ast.GenDecl, s *ast.ValueSpec) bool {
		for _, n := range s.Names { if o := a.info.Defs[n]; o != nil { set[o] = true } }
		if g.Tok == token.VAR {
			for _, v := range s.Values { if a.calls(v) { return false } }
		}
		return true
	}
	if !seed(gd, vs) { return nil, false }
	if gd.Tok == token.CONST { // implicit repetition: the following specs without values repeat this expression
		after := false
		for _, s := range gd.Specs {
			q := s.(*ast.ValueSpec)
			if q == vs { after = true; continue }
			if after && len(q.Values) == 0 { seed(gd, q); continue }
			if after { break }
		}
	}
	for changed := true; changed; {
		changed = false
		for _, f := range a.files {
			for _, d := range f.f.Decls {
				g, ok := d.(*ast.GenDecl)
				if !ok || (g.Tok != token.VAR && g.Tok != token.CONST) { continue }
				implicit := false
				for _, s := range g.Specs {
					q := s.(*ast.ValueSpec)
					if len(q.Values) > 0 { implicit = false }
					hit := implicit
					if !hit { hit = a.refers(q, set) }
					if !hit { continue }
					if g.Tok == token.CONST { implicit = true }
					for _, n := range q.Names {
						if o := a.info.Defs[n]; o != nil && !set[o] {
							set[o] = true
							changed = true
							if g.Tok == token.VAR { for _, v := range q.Values { if a.calls(v) { return nil, false } } }
						}
					}
				}
			}
		}
	}
	tests := map[string]bool{}
	for o := range set {
		if a.testID[o.Name()] { return nil, false }
		for _, p := range a.uses[o] {
			rf := a.files[filepath.Base(a.fset.Position(p).Filename)]
			if rf == nil { return nil, false }
			ro := a.off(rf, p)
			var top ast.Decl
			for _, d := range rf.f.Decls { if a.off(rf, d.Pos()) <= ro && ro < a.off(rf, d.End()) { top = d; break } }
			switch d := top.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.Name == "init" { return nil, false }
				if d.Body == nil || p < d.Body.Lbrace { return nil, false }
				if !a.testsAround(rf, p, blocks, tests) { return nil, false }
			case *ast.GenDecl:
				if d.Tok == token.TYPE { return nil, false }
				// a var/const spec: its own objects are in the set (fixpoint above); a function literal in it is code
				if a.inFuncLit(rf, d, p) && !a.testsAround(rf, p, blocks, tests) { return nil, false }
			default:
				return nil, false
			}
		}
	}
	out := make([]string, 0, len(tests))
	for t := range tests { out = append(out, t) }
	sort.Strings(out)
	return out, true
}

func (a *analysis) refers(q *ast.ValueSpec, set map[types.Object]bool) bool {
	hit := false
	look := func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && set[a.info.Uses[id]] { hit = true }
		return !hit
	}
	if q.Type != nil { ast.Inspect(q.Type, look) }
	for _, v := range q.Values { ast.Inspect(v, look) }
	return hit
}

// calls: the expression calls something other than a builtin or a conversion (it could store what it computes elsewhere).
func (a *analysis) calls(e ast.Expr) bool {
	c := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			if tv := a.info.Types[x.Fun]; !tv.IsType() && !tv.IsBuiltin() { c = true }
		}
		return !c
	})
	return c
}

func (a *analysis) inFuncLit(fi *fileInfo, d ast.Node, p token.Pos) bool {
	in := false
	ast.Inspect(d, func(n ast.Node) bool {
		if fl, ok := n.(*ast.FuncLit); ok && fl.Body.Lbrace <= p && p <= fl.Body.Rbrace { in = true }
		return !in
	})
	return in
}

// testsAround adds the tests that execute position p (its block, or any block of the innermost function around it).
func (a *analysis) testsAround(fi *fileInfo, p token.Pos, blocks map[string]map[string]*covBlock, out map[string]bool) bool {
	pos := a.fset.Position(p)
	if set, in := testsAt(blocks, fi.name, pos.Line, pos.Column); in {
		for t := range set { out[t] = true }
		return true
	}
	var body *ast.BlockStmt
	ast.Inspect(fi.f, func(n ast.Node) bool {
		var b *ast.BlockStmt
		switch x := n.(type) {
		case *ast.FuncDecl: b = x.Body
		case *ast.FuncLit: b = x.Body
		}
		if b != nil && b.Lbrace <= p && p <= b.Rbrace { body = b }
		return n == nil || (n.Pos() <= p && p <= n.End())
	})
	if body == nil { return false }
	l, r := a.fset.Position(body.Lbrace), a.fset.Position(body.Rbrace)
	set, in := testsIn(blocks, fi.name, l.Line, l.Column, r.Line, r.Column)
	if !in { return false }
	for t := range set { out[t] = true }
	return true
}

// ---- rendering ----

func (a *analysis) dir(fi *fileInfo, off int) string {
	p := fi.tf.Position(fi.tf.Pos(off))
	return fmt.Sprintf("/*line %s:%d:%d*/", fi.path, p.Line, p.Column)
}

func mutText(src []byte, m *Mut, lo, hi int) string {
	return string(src[lo:m.start]) + m.repl + string(src[m.end:hi])
}

// tree nests the live sites of one file; returns the roots.
func tree(sites []*site) []*site {
	live := []*site{}
	for _, s := range sites { s.kids = nil; if !s.dead { live = append(live, s) } }
	sort.Slice(live, func(i, j int) bool {
		x, y := live[i], live[j]
		if x.a != y.a { return x.a < y.a }
		if x.b != y.b { return x.b > y.b }
		return x.kind < y.kind
	})
	var roots, stack []*site
	for _, s := range live {
		for len(stack) > 0 {
			t := stack[len(stack)-1]
			if t.a <= s.a && s.b <= t.b { break }
			if t.b > s.a { s.dead = true; break } // crossing regions cannot nest: standalone builds (never expected)
			stack = stack[:len(stack)-1]
		}
		if s.dead { continue }
		if len(stack) == 0 { roots = append(roots, s) } else { p := stack[len(stack)-1]; p.kids = append(p.kids, s) }
		stack = append(stack, s)
	}
	return roots
}

func (a *analysis) emit(fi *fileInfo, lo, hi int, kids []*site, out *strings.Builder) {
	pos := lo
	for _, k := range kids {
		if k.a < lo || k.b > hi || k.a < pos { continue }
		out.Write(fi.src[pos:k.a])
		a.render(fi, k, out)
		out.WriteString(a.dir(fi, k.b))
		pos = k.b
	}
	out.Write(fi.src[pos:hi])
}

func idList(ms []*Mut) string {
	var p []string
	for _, m := range ms { p = append(p, "gomutID == "+strconv.Itoa(m.ID)) }
	return strings.Join(p, " || ")
}

func (a *analysis) render(fi *fileInfo, s *site, out *strings.Builder) {
	src := fi.src
	chain := func(body func(m *Mut) string, dflt func()) {
		for i, m := range s.muts {
			if i > 0 { out.WriteString(" else ") }
			out.WriteString("if gomutID == " + strconv.Itoa(m.ID) + " {" + body(m) + "\n}")
		}
		out.WriteString(" else {")
		dflt()
		out.WriteString("\n}")
	}
	switch s.kind {
	case kStmt, kCaseBody, kRest:
		chain(func(m *Mut) string { return a.dir(fi, s.a) + mutText(src, m, s.a, s.b) }, func() { out.WriteString(a.dir(fi, s.a)); a.emit(fi, s.a, s.b, s.kids, out) })
	case kClosure:
		out.WriteString("func() {")
		chain(func(m *Mut) string { return a.dir(fi, s.a) + mutText(src, m, s.a, s.b) }, func() { out.WriteString(a.dir(fi, s.a)); a.emit(fi, s.a, s.b, s.kids, out) })
		out.WriteString("\n}()")
	case kDecl:
		out.WriteString(s.decls)
		chain(func(m *Mut) string { return s.lhs + " = " + a.dir(fi, s.ra) + mutText(src, m, s.ra, s.rb) },
			func() { out.WriteString(s.lhs + " = " + a.dir(fi, s.ra)); a.emit(fi, s.ra, s.rb, s.kids, out) })
	case kInitDecl:
		out.WriteString("{ " + s.decls)
		chain(func(m *Mut) string { return s.lhs + " = " + a.dir(fi, s.ra) + mutText(src, m, s.ra, s.rb) },
			func() { out.WriteString(s.lhs + " = " + a.dir(fi, s.ra)); a.emit(fi, s.ra, s.rb, s.kids, out) })
		out.WriteString("\n" + a.dir(fi, s.a) + s.kw + " ")
		a.emit(fi, s.cont, s.b, s.kids, out)
		out.WriteString("\n}")
	case kHoist:
		h := "gomutH" + strconv.Itoa(s.muts[0].ID)
		out.WriteString("{ var " + h + " " + s.typ + "\n")
		chain(func(m *Mut) string { return h + " = " + a.dir(fi, s.ra) + mutText(src, m, s.ra, s.rb) },
			func() { out.WriteString(h + " = " + a.dir(fi, s.ra)); a.emit(fi, s.ra, s.rb, s.kids, out) })
		out.WriteString("\n" + a.dir(fi, s.a))
		a.emit(fi, s.a, s.ra, s.kids, out)
		out.WriteString(h + a.dir(fi, s.rb))
		a.emit(fi, s.rb, s.b, s.kids, out)
		out.WriteString("\n}")
	case kCond:
		out.WriteString("(")
		for _, m := range s.muts {
			out.WriteString("gomutID == " + strconv.Itoa(m.ID) + " && bool(" + a.dir(fi, s.a) + mutText(src, m, s.a, s.b) + ") || ")
		}
		out.WriteString("!(" + idList(s.muts) + ") && bool(" + a.dir(fi, s.a))
		a.emit(fi, s.a, s.b, s.kids, out)
		out.WriteString("))")
	case kPick:
		for _, m := range s.muts {
			out.WriteString("gomutP[" + s.typ + "](gomutID == " + strconv.Itoa(m.ID) + ", " + a.dir(fi, s.a) + mutText(src, m, s.a, s.b) + ", ")
		}
		out.WriteString(a.dir(fi, s.a))
		a.emit(fi, s.a, s.b, s.kids, out)
		out.WriteString(strings.Repeat(")", len(s.muts)))
	}
}

const schemaHelper = `package %s

import (
	"os"
	"strconv"
)

// gomutID: the mutant this schema binary runs (GOMUT_ID); -1 runs the unmutated code
var gomutID = gomutActive()

func gomutActive() int32 {
	v, err := strconv.ParseInt(os.Getenv("GOMUT_ID"), 10, 32)
	if err != nil {
		return -1
	}
	return int32(v)
}

func gomutP[T any](c bool, a, b T) T {
	if c {
		return a
	}
	return b
}
`

const helperName = "zz_gomut_schema.go"

var errLine = regexp.MustCompile(`(?m)^\s*(\S+\.go):(\d+):(\d+): (.*)$`)

// buildSchema renders every file with live sites, builds the test binary, and on compile errors drops the sites the errors
// point into (their mutants become standalone builds) and builds again.
func (a *analysis) buildSchema(sites map[string][]*site, tmp, tags, bin string) error {
	for round := 1; ; round++ {
		ov := map[string]string{}
		hp := filepath.Join(tmp, helperName)
		if err := os.WriteFile(hp, []byte(fmt.Sprintf(schemaHelper, a.pkg.Name())), 0o644); err != nil { return err }
		ov[filepath.Join(a.abs, helperName)] = hp
		n := 0
		for name, ss := range sites {
			fi := a.files[name]
			roots := tree(ss)
			if len(roots) == 0 { continue }
			var out strings.Builder
			a.emit(fi, 0, len(fi.src), roots, &out)
			p := filepath.Join(tmp, "schema-"+name)
			if err := os.WriteFile(p, []byte(out.String()), 0o644); err != nil { return err }
			ov[fi.path] = p
			for _, s := range ss { if !s.dead { n++ } }
		}
		ob, _ := json.Marshal(map[string]any{"Replace": ov})
		op := filepath.Join(tmp, "schema-overlay.json")
		if err := os.WriteFile(op, ob, 0o644); err != nil { return err }
		args := []string{"test", "-c", "-vet=off", "-gcflags=-e", "-o", bin, "-overlay", op}
		if tags != "" { args = append(args, "-tags", tags) }
		c := exec.Command("go", append(args, ".")...)
		c.Dir = a.abs
		t0 := time.Now()
		o, err := c.CombinedOutput()
		fmt.Fprintf(os.Stderr, "go-mutate: schema build round %d: %d guarded site(s), %v, ok=%v\n", round, n, time.Since(t0).Round(time.Second), err == nil)
		if err == nil { return nil }
		if round == 6 { return fmt.Errorf("the schema build still fails after %d rounds:\n%s", round, tail(string(o), 4000)) }
		dropped := 0
		for _, g := range errLine.FindAllStringSubmatch(string(o), -1) {
			name := filepath.Base(g[1])
			if name == helperName || strings.HasSuffix(name, "_test.go") { return fmt.Errorf("the schema build fails outside the guarded sites:\n%s", tail(string(o), 4000)) }
			ss := sites[name]
			fi := a.files[name]
			if fi == nil { return fmt.Errorf("the schema build fails in %s:\n%s", name, tail(string(o), 4000)) }
			line, _ := strconv.Atoi(g[2])
			hit := false
			// a site already dropped (by an earlier error on the same line) still counts as the error's site
			drop := func(s *site) { hit = true; if !s.dead { s.dead = true; dropped++ } }
			for _, s := range ss {
				if l1, l2 := fi.tf.Line(fi.tf.Pos(s.a)), fi.tf.Line(fi.tf.Pos(s.b)); l1 <= line && line <= l2 { drop(s) }
			}
			if hit { continue }
			// no site on that line (a missing return at a function's end, ...): every site of the enclosing function
			for _, d := range fi.f.Decls {
				l1, l2 := fi.tf.Line(d.Pos()), fi.tf.Line(d.End())
				if l1 > line || line > l2 { continue }
				for _, s := range ss {
					if a.off(fi, d.Pos()) <= s.a && s.b <= a.off(fi, d.End()) { drop(s) }
				}
			}
			if !hit { return fmt.Errorf("the schema build fails at %s:%d, where no guarded site is:\n%s", name, line, tail(string(o), 4000)) }
		}
		if dropped == 0 { return fmt.Errorf("the schema build fails and no error maps to a guarded site:\n%s", tail(string(o), 4000)) }
		// indented: CI problem matchers would turn bare file:line: lines into job error annotations, though nothing failed
		fmt.Fprintf(os.Stderr, "go-mutate: schema build: %d site(s) dropped to standalone builds:\n  | %s\n", dropped, strings.ReplaceAll(tail(string(o), 1500), "\n", "\n  | "))
	}
}

func tail(s string, n int) string {
	if len(s) > n { return "..." + s[len(s)-n:] }
	return s
}

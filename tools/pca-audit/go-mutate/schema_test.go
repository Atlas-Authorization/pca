package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A literal in a type position changes the type, so it never gets a run-time guard (the schema build of these once failed
// with "cannot use [][3]string as [][2]string in argument to gomutP[[][2]string]"); everything else on those lines still does,
// and the schema of the whole file compiles in its first round.
const typePosSrc = `package x

import "strings"

const N = 4

func F(m any, s string) int {
	t := [][2]string{{"a", "b"}}
	v, _ := m.([4]int)
	var b [N]byte
	const M = 3
	var c [M]byte
	if strings.HasPrefix(s, "a") {
		return len(t) + v[0] + len(b) + len(c) + 7
	}
	return 0
}
`

func TestTypePositionLiteralsAreNeverGuarded(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod":    "module x\n\ngo 1.23\n",
		"a.go":      typePosSrc,
		"a_test.go": "package x\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) { _ = F(nil, \"a\") }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil { t.Fatal(err) }
	}
	ms := gen(filepath.Join(dir, "a.go"))
	an, err := newAnalysis(dir, "", []string{"a.go"})
	if err != nil || !an.ok { t.Fatalf("analysis: %v (ok=%v)", err, an != nil && an.ok) }
	sites := map[string][]*site{}
	byKey := map[string]*site{}
	var typed, guarded int
	for i := range ms {
		m := &ms[i]
		m.ID = i
		v, ev := an.verdict(m)
		line := strings.TrimSpace(strings.Split(typePosSrc, "\n")[m.Line-1])
		inType := strings.HasPrefix(m.Desc, "int ") && (strings.HasPrefix(line, "t := ") || strings.HasPrefix(line, "v, _ := ") || line == "const N = 4")
		if strings.HasPrefix(m.Desc, "if-cond") && v != vOK { t.Errorf("%s | %s: verdict %v (%s): the replacement keeps the strings use", m.Desc, line, v, ev) }
		if inType { // whatever the verdict (doPrep asks only for vOK ones)
			typed++
			if s := an.siteFor(m); s != nil { t.Errorf("%s | %s: a literal in a type got a %s guard", m.Desc, line, kindName[s.kind]) }
			continue
		}
		if v != vOK { continue }
		s := an.siteFor(m)
		if s == nil { continue }
		guarded++
		if e := byKey[an.siteKey(s)]; e != nil { s = e } else { byKey[an.siteKey(s)] = s; sites[m.File] = append(sites[m.File], s) }
		s.muts = append(s.muts, m)
	}
	// [2]string, [4]int and const N: two mutants each; const M = 3 is a local const (a whole-rest copy, consistent): guarded
	if typed != 6 { t.Errorf("%d type-position mutants, want 6", typed) }
	if guarded == 0 { t.Fatal("no mutant got a guard: the test proves nothing") }
	if err := an.buildSchema(sites, t.TempDir(), "", filepath.Join(t.TempDir(), "schema.test")); err != nil { t.Fatal(err) }
	for _, ss := range sites {
		for _, s := range ss { if s.dead { t.Errorf("site %s dropped: the schema did not compile in its first round", an.siteKey(s)) } }
	}
}

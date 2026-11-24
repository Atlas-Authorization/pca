// GoalHarness.dfy - differential driver for the goal compiler. NOT part of the proof (built with --no-verify). One case per line:
//   <op> <goal tape> | <ontology tape> | <action tape> | <history tape>       op in typecheck compile decideg decidep render
// A tape is space-separated tokens: kN (keyword), iN (integer), s<hex>.<hex>... (string as code points; bare `s` = empty).
// The result tape is printed in the same syntax. The same file is built for cs/go/java/py/js and must print identical transcripts,
// equal to those of the production bridge (packages/pca-verified-core/test/diverse/drive-goal-prod.cts).
include "../Goal.dfy"
module GoalHarness {
  import opened GoalIr
  import opened GoalRender
  import opened GoalApi
  import Std.FileIO

  method Split(line: string) returns (out: seq<string>) {
    out := [];
    var cur: string := "";
    var k := 0;
    while k < |line| {
      if line[k] == ' ' { if |cur| > 0 { out := out + [cur]; cur := ""; } } else { cur := cur + [line[k]]; }
      k := k + 1;
    }
    if |cur| > 0 { out := out + [cur]; }
  }
  function HexD(c: char): int {
    if '0' <= c <= '9' then (c as int) - ('0' as int) else if 'a' <= c <= 'f' then (c as int) - ('a' as int) + 10 else 0
  }
  method ParseInt(s: string) returns (r: int) {
    r := 0;
    var neg := false;
    var k := 0;
    if |s| > 0 && s[0] == '-' { neg := true; k := 1; }
    while k < |s| { r := r * 10 + ((s[k] as int) - ('0' as int)); k := k + 1; }
    if neg { r := -r; }
  }
  method ParseStr(s: string) returns (out: string) {
    out := "";
    var cur := 0;
    var has := false;
    var k := 0;
    while k <= |s| {
      if k == |s| || s[k] == '.' {
        if has { out := out + [cur as char]; }
        cur := 0; has := false;
      } else { cur := cur * 16 + HexD(s[k]); has := true; }
      k := k + 1;
    }
  }
  method ParseTok(t: string) returns (tk: Tok) {
    if |t| == 0 { tk := TI(0); return; }
    var body := t[1..];
    if t[0] == 'k' { var n := ParseInt(body); tk := TKw(n); }
    else if t[0] == 'i' { var n := ParseInt(body); tk := TI(n); }
    else { var s := ParseStr(body); tk := TS(s); }
  }
  function DigitC(d: nat): char requires d < 10 { match d { case 0 => '0' case 1 => '1' case 2 => '2' case 3 => '3' case 4 => '4' case 5 => '5' case 6 => '6' case 7 => '7' case 8 => '8' case _ => '9' } }
  function NS(n: nat): string decreases n { if n < 10 then [DigitC(n)] else NS(n / 10) + [DigitC(n % 10)] }
  function IS(i: int): string { if i < 0 then "-" + NS((-i) as nat) else NS(i as nat) }
  function HexC(d: nat): char requires d < 16 { if d < 10 then DigitC(d) else ['a','b','c','d','e','f'][d - 10] }
  function HexS(n: nat): string decreases n { if n < 16 then [HexC(n)] else HexS(n / 16) + [HexC(n % 16)] }
  function StrS(s: string): string decreases |s| {
    if |s| == 0 then "" else HexS(s[0] as int) + (if |s| > 1 then "." + StrS(s[1..]) else "")
  }
  function TokS(t: Tok): string { match t case TKw(k) => "k" + IS(k) case TI(i) => "i" + IS(i) case TS(s) => "s" + StrS(s) }
  function ToksS(ts: seq<Tok>): string decreases |ts| { if |ts| == 0 then "" else TokS(ts[0]) + (if |ts| > 1 then " " else "") + ToksS(ts[1..]) }

  method RunCase(line: string) returns (out: string) {
    var toks := Split(line);
    if |toks| == 0 { out := ""; return; }
    var groups: seq<seq<Tok>> := [[]];
    var k := 1;
    while k < |toks| {
      if toks[k] == "|" { groups := groups + [[]]; }
      else { var tk := ParseTok(toks[k]); groups := groups[..|groups| - 1] + [groups[|groups| - 1] + [tk]]; }
      k := k + 1;
    }
    while |groups| < 4 { groups := groups + [[]]; }
    var op := toks[0];
    var res: seq<Tok>;
    if op == "typecheck" { res := TypecheckT(groups[0], groups[1]); }
    else if op == "compile" { res := CompileT(groups[0], groups[1]); }
    else if op == "decideg" { res := DecideGoalT(groups[0], groups[1], groups[2], groups[3]); }
    else if op == "decidep" { res := DecidePolicyT(groups[0], groups[1], groups[2], groups[3]); }
    else if op == "render" { res := RenderT(groups[0]); }
    else { res := [TI(-1)]; }
    out := ToksS(res);
  }

  method Run(path: string) {
    var rd := FileIO.ReadBytesFromFile(path);
    if rd.Failure? { print "ERR ", rd.error, "\n"; return; }
    var bytes := rd.value;
    var cur: string := "";
    var k := 0;
    while k < |bytes| {
      var b := bytes[k];
      if b == 10 { var o := RunCase(cur); print o, "\n"; cur := ""; } else { cur := cur + [(b as int) as char]; }
      k := k + 1;
    }
  }
}

method Main(args: seq<string>) {
  if |args| < 2 { print "usage: goalharness <casefile>\n"; return; }
  GoalHarness.Run(args[1]);
}

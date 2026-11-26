//! schema-gen <input.json> <output.json>: writes ONE source tree that holds a whole group of mutants (cargo-mutants' list and
//! stmt-mut's), each behind a runtime switch, so the group costs one build instead of one build per mutant (mutant schemata).
//! Run from the repo root; the driver is ../schema-build.mjs.
//!
//! input.json: { "root": "<crate>/src/lib.rs", "crate": "atlas_pca", "orig": "<dir holding the pristine copy of every file>",
//!               "mutants": [ {id, kind: "cm", file, genre, span: {start: {line, column}, end: {line, column}}, replacement}
//!                          | {id, kind: "stmt", file, genre, start, end, repl} ] }
//! output.json: { "fallback": { "<id>": "<why>" }, "ranges": { "<file>": [[start, end, [ids]]] }, "schema": <count> }
//!   fallback: mutants this tree does NOT hold (the driver hands them to a real per-mutant build); ranges: the byte range of every
//!   mutant's text and of every site in the WRITTEN file (rustc errors are mapped back to mutants through them).
//!
//! Each mutated site keeps cargo-mutants' exact text: the active branch of a site is the original region with that one mutant's edit
//! applied (cargo-mutants' span replaced by its replacement), every other site inside it unmutated. A mutant is active when
//! `<crate>::__pca_schema::m(id)` is true (env PCA_MUTANT=id, read once per process). The forms:
//!   expression (operator swap / delete, match-guard value, if-condition value):
//!       (if m(a) { (<region, edit a>) } else if m(b) { (<region, edit b>) } else { (<region>) })
//!     a binary operator's region is its whole operator chain (the maximal tree of binary expressions around it), so the swapped
//!     operator re-associates exactly as in cargo-mutants' text (`a - b * c` with `*` -> `+` is `a - b + c`, not `a - (b + c)`)
//!   function body (FnValue):  if m(a) { <value a> } else if .. else { <original statements> }
//!   deleted statement (`x?;`, `return Err(..)`, break, continue -> `()`):  (if !m(a) { <original>; })
//!   if-let body replaced by its else branch:  { if m(a) <else block> else <then block> }
//!   let-else branch forced:  if m(a) { D } <let statement>
//!   deleted match arm:  <pattern> if !m(a) => <body>     (the value falls through to the later arms, as with the arm deleted)
//! Not expressible, so always a fallback: const fn (no runtime switch in const evaluation), async fn and fns returning `impl Trait`
//! (both branches must have one type), struct-field deletion, anything outside a fn, and a mutant whose region partly overlaps
//! another's. Every schema mutant is checked by ROUND TRIP before it is kept: the written file is parsed back, every switch is
//! collapsed for that mutant alone, and the enclosing item must equal (as a fully parenthesized token tree) the same item of the file
//! with cargo-mutants' / stmt-mut's own replacement applied; the unmutated collapse must equal the original. A mismatch is a fallback.
use proc_macro2::{LineColumn, Span};
use quote::ToTokens;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::visit_mut::{self, VisitMut};
use syn::{Block, Expr, ImplItem, Item, Stmt, TraitItem, UnOp};

pub fn line_starts(src: &str) -> Vec<usize> {
    let mut v = vec![0];
    v.extend(src.match_indices('\n').map(|(i, _)| i + 1));
    v
}

/// byte offset of a proc-macro2 position (1-based line, 0-based column in chars); None outside the text
pub fn off(src: &str, st: &[usize], p: LineColumn) -> Option<usize> {
    let s = *st.get(p.line.checked_sub(1)?)?;
    let line = &src[s..];
    let mut n = 0;
    for (k, c) in line.chars().enumerate() {
        if k == p.column {
            return Some(s + n);
        }
        if c == '\n' {
            return None;
        }
        n += c.len_utf8();
    }
    if line.chars().count() == p.column { Some(s + n) } else { None }
}

fn r(src: &str, st: &[usize], sp: Span) -> (usize, usize) {
    (off(src, st, sp.start()).unwrap_or(usize::MAX), off(src, st, sp.end()).unwrap_or(usize::MAX))
}

struct FnInfo {
    s: usize,
    e: usize,
    cnst: bool,
    asy: bool,
    imp: bool,
}

#[derive(Default)]
struct Info {
    fns: Vec<FnInfo>,
    bodies: HashMap<(usize, usize), usize>,
    bin: HashMap<usize, (usize, usize, usize)>, // operator start -> (operator end, chain start, chain end)
    un: HashMap<usize, (usize, usize, usize)>,  // operator start -> (operator end, expression start, expression end)
    arms: HashMap<usize, (usize, usize, bool)>, // arm start -> (arm end, `=>` start, has a guard)
    guards: HashMap<usize, usize>,              // guard expression start -> end
}

struct Scan<'a> {
    src: &'a str,
    st: &'a [usize],
    info: Info,
    chain: Option<(usize, usize)>,
}

struct HasImpl(bool);
impl<'ast> Visit<'ast> for HasImpl {
    fn visit_type_impl_trait(&mut self, _: &'ast syn::TypeImplTrait) {
        self.0 = true;
    }
}

impl Scan<'_> {
    fn r(&self, sp: Span) -> (usize, usize) {
        r(self.src, self.st, sp)
    }
    fn func(&mut self, whole: Span, sig: &syn::Signature, block: &Block) {
        let (s, e) = self.r(whole);
        let mut hi = HasImpl(false);
        if let syn::ReturnType::Type(_, t) = &sig.output {
            hi.visit_type(t);
        }
        let i = self.info.fns.len();
        self.info.fns.push(FnInfo { s, e, cnst: sig.constness.is_some(), asy: sig.asyncness.is_some(), imp: hi.0 });
        // cargo-mutants' FnValue span: first statement start .. last statement end
        if let (Some(f), Some(l)) = (block.stmts.first(), block.stmts.last()) {
            self.info.bodies.insert((self.r(f.span()).0, self.r(l.span()).1), i);
        }
    }
}

impl<'ast> Visit<'ast> for Scan<'_> {
    fn visit_item_fn(&mut self, i: &'ast syn::ItemFn) {
        self.func(i.span(), &i.sig, &i.block);
        visit::visit_item_fn(self, i);
    }
    fn visit_impl_item_fn(&mut self, i: &'ast syn::ImplItemFn) {
        self.func(i.span(), &i.sig, &i.block);
        visit::visit_impl_item_fn(self, i);
    }
    fn visit_trait_item_fn(&mut self, i: &'ast syn::TraitItemFn) {
        if let Some(b) = &i.default {
            self.func(i.span(), &i.sig, b);
        }
        visit::visit_trait_item_fn(self, i);
    }
    fn visit_expr(&mut self, e: &'ast Expr) {
        let outer = self.chain;
        if let Expr::Binary(b) = e {
            // the chain: binary expressions directly nested in binary expressions (anything else, parens included, delimits it)
            let root = outer.unwrap_or_else(|| self.r(e.span()));
            let (a, z) = self.r(b.op.span());
            self.info.bin.insert(a, (z, root.0, root.1));
            self.chain = Some(root);
        } else {
            match e {
                Expr::Unary(u) if matches!(u.op, UnOp::Not(_) | UnOp::Neg(_)) => {
                    let (a, z) = self.r(u.op.span());
                    let (s, t) = self.r(e.span());
                    self.info.un.insert(a, (z, s, t));
                }
                Expr::Match(m) => {
                    for arm in &m.arms {
                        let (s, t) = self.r(arm.span());
                        let fa = self.r(arm.fat_arrow_token.span()).0;
                        self.info.arms.insert(s, (t, fa, arm.guard.is_some()));
                        if let Some((_, g)) = &arm.guard {
                            let (gs, ge) = self.r(g.span());
                            self.info.guards.insert(gs, ge);
                        }
                    }
                }
                _ => {}
            }
            self.chain = None;
        }
        visit::visit_expr(self, e);
        self.chain = outer;
    }
}

/// one mutant as the generator sees it: the cargo-mutants / stmt-mut edit [a, b) -> real, and the text the schema branch uses
#[derive(Clone)]
pub struct In {
    pub id: u32,
    pub file: String,
    pub genre: String,
    pub a: usize,
    pub b: usize,
    pub real: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum K {
    Expr,
    Block,
    Guard,
    IfElse,
    Prefix,
    Arm(usize),
}

#[derive(Clone)]
struct Mu {
    id: u32,
    a: usize,
    b: usize,
    repl: String,
}

#[derive(Clone)]
struct Site {
    s: usize,
    e: usize,
    k: K,
    mus: Vec<Mu>,
    kids: Vec<usize>,
}

fn classify(m: &In, src: &str, info: &Info) -> Result<(usize, usize, K, Mu), String> {
    if m.a > m.b || m.b > src.len() || !src.is_char_boundary(m.a) || !src.is_char_boundary(m.b) {
        return Err("span outside the file".into());
    }
    let f = info.fns.iter().filter(|f| f.s <= m.a && m.b <= f.e).min_by_key(|f| f.e - f.s).ok_or("outside a function")?;
    if f.cnst {
        return Err("const fn".into());
    }
    if f.asy {
        return Err("async fn".into());
    }
    if f.imp {
        return Err("fn returning impl Trait".into());
    }
    let mu = Mu { id: m.id, a: m.a, b: m.b, repl: m.real.clone() };
    let whole = |k: K| Ok((m.a, m.b, k, mu.clone()));
    let miss = |what: &str| Err(format!("no {what} at the span"));
    match m.genre.as_str() {
        "FnValue" => if info.bodies.contains_key(&(m.a, m.b)) { whole(K::Block) } else { miss("function body") },
        "BinaryOperator" => match info.bin.get(&m.a) {
            Some(&(z, s, e)) if z == m.b => Ok((s, e, K::Expr, mu.clone())),
            _ => miss("binary operator"),
        },
        "UnaryOperator" => match info.un.get(&m.a) {
            Some(&(z, s, e)) if z == m.b => Ok((s, e, K::Expr, mu.clone())),
            _ => miss("unary operator"),
        },
        "MatchArm" => match info.arms.get(&m.a) {
            Some(&(z, fa, false)) if z == m.b && m.real.is_empty() => whole(K::Arm(fa)),
            _ => miss("guardless match arm"),
        },
        "MatchArmGuard" => match info.guards.get(&m.a) {
            Some(&z) if z == m.b => whole(K::Expr),
            _ => miss("match guard"),
        },
        "IfCondition" => whole(K::Expr),
        "IfLet" => whole(K::IfElse),
        "LetElse" => {
            let o = &src[m.a..m.b];
            let tail = format!(" {o}");
            if m.real.starts_with("if true ") && m.real.ends_with(&tail) && m.real.len() > 8 + tail.len() {
                let d = m.real[8..m.real.len() - tail.len()].to_string();
                Ok((m.a, m.b, K::Prefix, Mu { repl: d, ..mu.clone() }))
            } else {
                Err("let-else replacement not in stmt-mut's form".into())
            }
        }
        "TryStatement" | "ReturnErr" | "Break" | "Continue" => if m.real == "()" { whole(K::Guard) } else { Err("statement deletion that is not ()".into()) },
        g => Err(format!("genre {g} has no schema form")),
    }
}

struct R<'a> {
    src: &'a str,
    sites: &'a [Site],
    p: &'a str,
    out: String,
    ranges: Vec<(usize, usize, Vec<u32>)>,
}

impl R<'_> {
    fn range(&mut self, x: usize, y: usize, kids: &[usize]) {
        let st = self.sites;
        let mut p = x;
        for &k in kids {
            let (s, e) = (st[k].s, st[k].e);
            if s >= p && e <= y {
                self.out.push_str(&self.src[p..s]);
                self.site(k);
                p = e;
            }
        }
        self.out.push_str(&self.src[p..y]);
    }
    fn branch(&mut self, i: usize, j: usize) {
        let st = self.sites;
        let (s, e, mu) = (st[i].s, st[i].e, &st[i].mus[j]);
        let b0 = self.out.len();
        if (mu.a, mu.b) == (s, e) {
            self.out.push_str(&mu.repl);
        } else {
            self.range(s, mu.a, &st[i].kids);
            self.out.push_str(&mu.repl);
            self.range(mu.b, e, &st[i].kids);
        }
        self.ranges.push((b0, self.out.len(), vec![mu.id]));
    }
    fn orig(&mut self, i: usize) {
        let st = self.sites;
        self.range(st[i].s, st[i].e, &st[i].kids);
    }
    fn site(&mut self, i: usize) {
        let st = self.sites;
        let s = &st[i];
        let p = self.p;
        let r0 = self.out.len();
        let id0 = s.mus[0].id;
        match s.k {
            K::Expr => {
                self.out.push_str("(if ");
                for j in 0..s.mus.len() {
                    if j > 0 {
                        self.out.push_str(" else if ");
                    }
                    let _ = write!(self.out, "{p}({}) {{ (", s.mus[j].id);
                    self.branch(i, j);
                    self.out.push_str(") }");
                }
                self.out.push_str(" else { (");
                self.orig(i);
                self.out.push_str(") })");
            }
            K::Block => {
                for j in 0..s.mus.len() {
                    if j > 0 {
                        self.out.push_str(" else ");
                    }
                    let _ = write!(self.out, "if {p}({}) {{ ", s.mus[j].id);
                    self.branch(i, j);
                    self.out.push_str(" }");
                }
                self.out.push_str(" else { ");
                self.orig(i);
                self.out.push_str(" }");
            }
            K::Guard => {
                let _ = write!(self.out, "(if !{p}({id0}) {{ ");
                self.orig(i);
                self.out.push_str("; })");
            }
            K::IfElse => {
                let _ = write!(self.out, "{{ if {p}({id0}) ");
                self.branch(i, 0);
                self.out.push_str(" else ");
                self.orig(i);
                self.out.push_str(" }");
            }
            K::Prefix => {
                let _ = write!(self.out, "if {p}({id0}) ");
                self.branch(i, 0);
                self.out.push(' ');
                self.orig(i);
            }
            K::Arm(fa) => {
                self.range(s.s, fa, &s.kids);
                let b0 = self.out.len();
                let _ = write!(self.out, " if !{p}({id0}) ");
                self.ranges.push((b0, self.out.len(), vec![id0]));
                self.range(fa, s.e, &s.kids);
            }
        }
        self.ranges.push((r0, self.out.len(), s.mus.iter().map(|m| m.id).collect()));
    }
}

/// sites of one file from its live mutants: (sites, roots); a mutant that cannot be placed goes to `fb`
fn build_sites(src: &str, info: &Info, muts: &[In], fb: &mut BTreeMap<u32, String>) -> (Vec<Site>, Vec<usize>) {
    let mut sites: Vec<Site> = vec![];
    let mut by: HashMap<(usize, usize), usize> = HashMap::new();
    for m in muts {
        if fb.contains_key(&m.id) {
            continue;
        }
        match classify(m, src, info) {
            Err(why) => {
                fb.insert(m.id, why);
            }
            Ok((s, e, k, mu)) => match by.get(&(s, e)) {
                Some(&i) if sites[i].k != k => {
                    fb.insert(m.id, "region shared with another form".into());
                }
                Some(&i) if !matches!(k, K::Expr | K::Block) => {
                    let _ = i;
                    fb.insert(m.id, "a second mutant of a one-mutant form".into());
                }
                Some(&i) => sites[i].mus.push(mu),
                None => {
                    by.insert((s, e), sites.len());
                    sites.push(Site { s, e, k, mus: vec![mu], kids: vec![] });
                }
            },
        }
    }
    let mut order: Vec<usize> = (0..sites.len()).collect();
    order.sort_by_key(|&i| (sites[i].s, std::cmp::Reverse(sites[i].e)));
    let (mut stack, mut roots): (Vec<usize>, Vec<usize>) = (vec![], vec![]);
    for i in order {
        while let Some(&t) = stack.last() {
            if sites[t].e <= sites[i].s { stack.pop(); } else { break; }
        }
        if let Some(&t) = stack.last() {
            let (ts, te, s, e) = (sites[t].s, sites[t].e, sites[i].s, sites[i].e);
            let bad = e > te
                || sites[t].mus.iter().any(|mu| (mu.a, mu.b) != (ts, te) && mu.a < e && s < mu.b)
                || matches!(sites[t].k, K::Arm(fa) if s < fa && fa < e);
            if bad {
                for mu in &sites[i].mus {
                    fb.insert(mu.id, "region overlaps another mutated region".into());
                }
                continue;
            }
            sites[t].kids.push(i);
        } else {
            roots.push(i);
        }
        stack.push(i);
    }
    (sites, roots)
}

fn render(src: &str, sites: &[Site], roots: &[usize], p: &str) -> (String, Vec<(usize, usize, Vec<u32>)>) {
    let mut r = R { src, sites, p, out: String::with_capacity(src.len() * 2), ranges: vec![] };
    let mut pos = 0;
    for &k in roots {
        r.out.push_str(&src[pos..sites[k].s]);
        r.site(k);
        pos = sites[k].e;
    }
    r.out.push_str(&src[pos..]);
    (r.out, r.ranges)
}

// ---- round trip: collapse the switches for one mutant, compare with the real replacement

fn sw_id(e: &Expr) -> Option<(u32, bool)> {
    match e {
        Expr::Call(c) => {
            let Expr::Path(p) = &*c.func else { return None };
            let n = p.path.segments.len();
            if n < 2 || p.path.segments[n - 2].ident != "__pca_schema" || p.path.segments[n - 1].ident != "m" || c.args.len() != 1 {
                return None;
            }
            match c.args.first() {
                Some(Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(i), .. })) => i.base10_parse().ok().map(|v| (v, false)),
                _ => None,
            }
        }
        Expr::Unary(u) if matches!(u.op, UnOp::Not(_)) => sw_id(&u.expr).map(|(v, n)| (v, !n)),
        _ => None,
    }
}

fn block_expr(b: &Block) -> Expr {
    Expr::Block(syn::ExprBlock { attrs: vec![], label: None, block: b.clone() })
}

struct Collapse(u32);
impl Collapse {
    fn pick(&self, i: &syn::ExprIf) -> Option<Expr> {
        let (k, neg) = sw_id(&i.cond)?;
        if neg {
            if i.else_branch.is_some() {
                return None;
            }
            if k == self.0 {
                return syn::parse_str::<Expr>("()").ok();
            }
            return match i.then_branch.stmts.as_slice() {
                [Stmt::Expr(x, Some(_))] => Some(x.clone()),
                _ => None,
            };
        }
        let (_, els) = i.else_branch.as_ref()?;
        Some(if k == self.0 { block_expr(&i.then_branch) } else { (**els).clone() })
    }
}
impl VisitMut for Collapse {
    fn visit_expr_mut(&mut self, e: &mut Expr) {
        loop {
            let n = match e {
                Expr::If(i) => self.pick(i),
                _ => None,
            };
            match n {
                Some(n) => *e = n,
                None => break,
            }
        }
        visit_mut::visit_expr_mut(self, e);
    }
    fn visit_block_mut(&mut self, b: &mut Block) {
        let a = self.0;
        // the let-else form: `if m(k) { D }` before the let statement
        b.stmts.retain_mut(|s| {
            if let Stmt::Expr(Expr::If(i), None) = s {
                if i.else_branch.is_none() {
                    if let Some((k, false)) = sw_id(&i.cond) {
                        if k != a {
                            return false;
                        }
                        *i.cond = syn::parse_str::<Expr>("true").expect("true");
                    }
                }
            }
            true
        });
        visit_mut::visit_block_mut(self, b);
    }
    fn visit_expr_match_mut(&mut self, m: &mut syn::ExprMatch) {
        let a = self.0;
        let guard = |arm: &syn::Arm| arm.guard.as_ref().and_then(|(_, g)| sw_id(g));
        m.arms.retain(|arm| !matches!(guard(arm), Some((k, true)) if k == a));
        for arm in &mut m.arms {
            if matches!(guard(&*arm), Some((_, true))) {
                arm.guard = None;
            }
        }
        visit_mut::visit_expr_match_mut(self, m);
    }
}

/// a canonical form: parens and single-expression blocks dropped, then every operand of an operator explicitly parenthesized,
/// so two trees print alike exactly when they group alike
struct Norm;
fn paren(x: &mut Expr) {
    let inner = std::mem::replace(x, Expr::Verbatim(Default::default()));
    *x = Expr::Paren(syn::ExprParen { attrs: vec![], paren_token: Default::default(), expr: Box::new(inner) });
}
impl VisitMut for Norm {
    fn visit_expr_mut(&mut self, e: &mut Expr) {
        loop {
            let n = match e {
                Expr::Paren(p) => Some((*p.expr).clone()),
                Expr::Block(b) if b.label.is_none() && b.attrs.is_empty() && b.block.stmts.len() == 1 => match &b.block.stmts[0] {
                    Stmt::Expr(x, None) => Some(x.clone()),
                    _ => None,
                },
                _ => None,
            };
            match n {
                Some(n) => *e = n,
                None => break,
            }
        }
        visit_mut::visit_expr_mut(self, e);
        match e {
            Expr::Binary(b) => {
                paren(&mut b.left);
                paren(&mut b.right);
            }
            Expr::Unary(u) => paren(&mut u.expr),
            Expr::Cast(c) => paren(&mut c.expr),
            Expr::Reference(x) => paren(&mut x.expr),
            Expr::Assign(x) => {
                paren(&mut x.left);
                paren(&mut x.right);
            }
            Expr::Range(x) => {
                if let Some(s) = &mut x.start {
                    paren(s);
                }
                if let Some(s) = &mut x.end {
                    paren(s);
                }
            }
            _ => {}
        }
    }
    fn visit_block_mut(&mut self, b: &mut Block) {
        while b.stmts.len() == 1 {
            let inner = match &b.stmts[0] {
                Stmt::Expr(Expr::Block(x), None) if x.label.is_none() && x.attrs.is_empty() => x.block.stmts.clone(),
                _ => break,
            };
            b.stmts = inner;
        }
        visit_mut::visit_block_mut(self, b);
    }
}

fn span_of(sp: Span, src: &str, st: &[usize]) -> (usize, usize) {
    r(src, st, sp)
}

/// index path of the innermost item (a top-level item, an item of an inline mod, or an impl / trait item) holding `pos`
fn locate(items: &[Item], src: &str, st: &[usize], pos: usize) -> Option<Vec<usize>> {
    for (i, it) in items.iter().enumerate() {
        let (s, e) = span_of(it.span(), src, st);
        if s <= pos && pos < e {
            let mut v = vec![i];
            match it {
                Item::Mod(m) => {
                    if let Some((_, c)) = &m.content {
                        if let Some(mut r) = locate(c, src, st, pos) {
                            v.append(&mut r);
                        }
                    }
                }
                Item::Impl(im) => {
                    if let Some(j) = im.items.iter().position(|x| { let (s, e) = span_of(x.span(), src, st); s <= pos && pos < e }) {
                        v.push(j);
                    }
                }
                Item::Trait(t) => {
                    if let Some(j) = t.items.iter().position(|x| { let (s, e) = span_of(x.span(), src, st); s <= pos && pos < e }) {
                        v.push(j);
                    }
                }
                _ => {}
            }
            return Some(v);
        }
    }
    None
}

enum U {
    I(Item),
    Ii(ImplItem),
    Ti(TraitItem),
}

fn unit(items: &[Item], path: &[usize]) -> Option<U> {
    let it = items.get(*path.first()?)?;
    if path.len() == 1 {
        return Some(U::I(it.clone()));
    }
    match it {
        Item::Mod(m) => unit(&m.content.as_ref()?.1, &path[1..]),
        Item::Impl(im) if path.len() == 2 => im.items.get(path[1]).cloned().map(U::Ii),
        Item::Trait(t) if path.len() == 2 => t.items.get(path[1]).cloned().map(U::Ti),
        _ => None,
    }
}

/// the item at `path`, every switch collapsed for `active` (0: none), in canonical form
fn eval(f: &syn::File, path: &[usize], active: u32) -> Option<String> {
    let mut u = unit(&f.items, path)?;
    let (mut c, mut n) = (Collapse(active), Norm);
    Some(match &mut u {
        U::I(x) => { c.visit_item_mut(x); n.visit_item_mut(x); x.to_token_stream().to_string() }
        U::Ii(x) => { c.visit_impl_item_mut(x); n.visit_impl_item_mut(x); x.to_token_stream().to_string() }
        U::Ti(x) => { c.visit_trait_item_mut(x); n.visit_trait_item_mut(x); x.to_token_stream().to_string() }
    })
}

/// round trip of one generated file: the mutants whose collapsed item differs from the real mutant's (or whose unmutated item
/// differs from the original), with the reason
fn round_trip(src: &str, out: &str, muts: &[In], live: &[u32]) -> Result<Vec<(u32, String)>, String> {
    let st = line_starts(src);
    let orig = syn::parse_file(src).map_err(|e| format!("original does not parse: {e}"))?;
    let sch = syn::parse_file(out).map_err(|e| format!("generated file does not parse: {e} (a generator bug)"))?;
    let mut bad = vec![];
    let mut seen: HashMap<Vec<usize>, bool> = HashMap::new();
    for m in muts.iter().filter(|m| live.contains(&m.id)) {
        let Some(path) = locate(&orig.items, src, &st, m.a) else {
            bad.push((m.id, "no enclosing item".into()));
            continue;
        };
        let ok0 = *seen.entry(path.clone()).or_insert_with(|| eval(&sch, &path, 0).is_some() && eval(&sch, &path, 0) == eval(&orig, &path, 0));
        if !ok0 {
            bad.push((m.id, "round trip: the unmutated item differs from the original".into()));
            continue;
        }
        let real = format!("{}{}{}", &src[..m.a], m.real, &src[m.b..]);
        let rf = match syn::parse_file(&real) {
            Ok(f) => f,
            Err(_) => {
                // the real mutant does not even parse (it can only be unviable): its build decides that
                bad.push((m.id, "the real mutant does not parse".into()));
                continue;
            }
        };
        let (a, b) = (eval(&sch, &path, m.id), eval(&rf, &path, 0));
        if a.is_none() || a != b {
            bad.push((m.id, "round trip: the collapsed schema differs from the real mutant".into()));
        }
    }
    Ok(bad)
}

/// one file: (written text, ranges); mutants not held go to `fb`
pub fn gen_file(src: &str, muts: &[In], p: &str, fb: &mut BTreeMap<u32, String>) -> Result<(String, Vec<(usize, usize, Vec<u32>)>), String> {
    let st = line_starts(src);
    let ast = syn::parse_file(src).map_err(|e| format!("does not parse: {e}"))?;
    let mut sc = Scan { src, st: &st, info: Info::default(), chain: None };
    sc.visit_file(&ast);
    let info = sc.info;
    for _round in 0..4 {
        let (sites, roots) = build_sites(src, &info, muts, fb);
        let (out, ranges) = render(src, &sites, &roots, p);
        let live: Vec<u32> = sites.iter().flat_map(|s| s.mus.iter().map(|m| m.id)).filter(|id| !fb.contains_key(id)).collect();
        let bad = match round_trip(src, &out, muts, &live) {
            Ok(b) => b,
            // a generator bug: never fatal for the run, never a dropped mutant; the whole file goes to the real per-mutant builds
            Err(e) if !live.is_empty() => {
                eprintln!("::warning::{e}: all {} mutant(s) of this file fall back", live.len());
                live.iter().map(|&id| (id, "generated file does not parse".to_string())).collect()
            }
            Err(e) => return Err(e),
        };
        if bad.is_empty() {
            return Ok((out, ranges));
        }
        for (id, why) in bad {
            fb.insert(id, why);
        }
    }
    Err("round trip still failing after 4 rounds (a generator bug)".into())
}

pub fn runtime(n: u32) -> String {
    format!(
        r#"//! Mutation schema switch (GENERATED by schema-gen for the mutation workflow; never committed).
#![allow(dead_code, missing_docs, clippy::all)]
use std::io::Write as _;
use std::sync::atomic::{{AtomicBool, Ordering}};
use std::sync::{{Mutex, OnceLock}};

const N: usize = {n};
#[allow(clippy::declare_interior_mutable_const)]
const UNSEEN: AtomicBool = AtomicBool::new(false);
static SEEN: [AtomicBool; N] = [UNSEEN; N];
static ACTIVE: OnceLock<u32> = OnceLock::new();
static TRACE: OnceLock<Option<Mutex<std::fs::File>>> = OnceLock::new();

/// true when mutant `id` is the active one (PCA_MUTANT, read once per process); with PCA_SCHEMA_TRACE=<dir> every site's first
/// reach is appended to <dir>/<pid> (first line: the process arguments), which maps each test to the mutants it reaches
#[inline]
pub fn m(id: u32) -> bool {{
    if let Some(t) = TRACE.get_or_init(open_trace) {{
        if !SEEN[id as usize % N].swap(true, Ordering::Relaxed) {{
            if let Ok(mut f) = t.lock() {{
                let _ = writeln!(f, "{{id}}");
            }}
        }}
    }}
    *ACTIVE.get_or_init(|| std::env::var("PCA_MUTANT").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(0)) == id
}}

fn open_trace() -> Option<Mutex<std::fs::File>> {{
    let dir = std::env::var_os("PCA_SCHEMA_TRACE")?;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(std::path::Path::new(&dir).join(std::process::id().to_string())).ok()?;
    let args: Vec<String> = std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect();
    let _ = writeln!(f, "#{{}}", args.join("\u{{1f}}"));
    Some(Mutex::new(f))
}}
"#,
        n = n as usize + 1
    )
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 3 {
        eprintln!("usage: schema-gen <input.json> <output.json>");
        std::process::exit(2);
    }
    let input: Value = serde_json::from_str(&std::fs::read_to_string(&a[1]).expect("input")).expect("input json");
    let root = input["root"].as_str().expect("root").to_string();
    let krate = input["crate"].as_str().expect("crate").to_string();
    let orig = std::path::PathBuf::from(input["orig"].as_str().expect("orig"));
    let p = format!("::{krate}::__pca_schema::m");
    let mut files: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut max_id = 0u32;
    for m in input["mutants"].as_array().expect("mutants") {
        files.entry(m["file"].as_str().expect("file").to_string()).or_default().push(m.clone());
        max_id = max_id.max(m["id"].as_u64().expect("id") as u32);
    }
    files.entry(root.clone()).or_default();
    let mut fb: BTreeMap<u32, String> = BTreeMap::new();
    let mut ranges = Map::new();
    for (file, ms) in &files {
        let src = std::fs::read_to_string(orig.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        let st = line_starts(&src);
        let mut ins = vec![];
        for m in ms {
            let id = m["id"].as_u64().unwrap() as u32;
            let genre = m["genre"].as_str().unwrap_or("").to_string();
            let edit = if m["kind"] == "cm" {
                let lc = |v: &Value| LineColumn { line: v["line"].as_u64().unwrap_or(0) as usize, column: (v["column"].as_u64().unwrap_or(1) as usize).saturating_sub(1) };
                match (off(&src, &st, lc(&m["span"]["start"])), off(&src, &st, lc(&m["span"]["end"]))) {
                    (Some(x), Some(y)) => Some((x, y, m["replacement"].as_str().unwrap_or("").to_string())),
                    _ => None,
                }
            } else {
                Some((m["start"].as_u64().unwrap() as usize, m["end"].as_u64().unwrap() as usize, m["repl"].as_str().unwrap_or("").to_string()))
            };
            match edit {
                Some((x, y, real)) => ins.push(In { id, file: file.clone(), genre, a: x, b: y, real }),
                None => { fb.insert(id, "span outside the file".into()); }
            }
        }
        let (mut out, rs) = match gen_file(&src, &ins, &p, &mut fb) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("{file}: {e}");
                std::process::exit(1);
            }
        };
        if *file == root {
            out.push_str(&format!("\n// mutation schema switch (generated)\n#[doc(hidden)]\npub mod __pca_schema;\n#[doc(hidden)]\nextern crate self as {krate};\n"));
            let dir = std::path::Path::new(&root).parent().expect("root dir");
            std::fs::write(dir.join("__pca_schema.rs"), runtime(max_id)).expect("write the switch module");
        }
        if !rs.is_empty() || *file == root {
            std::fs::write(file, &out).unwrap_or_else(|e| panic!("{file}: {e}"));
        }
        ranges.insert(file.clone(), json!(rs.iter().map(|(s, e, ids)| json!([s, e, ids])).collect::<Vec<_>>()));
    }
    let total: usize = files.values().map(|v| v.len()).sum();
    let out = json!({ "fallback": fb.iter().map(|(k, v)| (k.to_string(), json!(v))).collect::<Map<_, _>>(), "ranges": ranges, "schema": total - fb.len() });
    std::fs::write(&a[2], out.to_string()).expect("output");
    eprintln!("schema-gen: {} mutant(s), {} in the schema, {} fallback", total, total - fb.len(), fb.len());
}

#[cfg(test)]
mod tests {
    use super::*;
    const P: &str = "::atlas_pca::__pca_schema::m";

    /// a mutant from its exact text: the n-th (0-based) occurrence of `what` in `src`, replaced by `real`
    fn mu(src: &str, id: u32, genre: &str, what: &str, n: usize, real: &str) -> In {
        let a = src.match_indices(what).nth(n).unwrap_or_else(|| panic!("{what} #{n}")).0;
        In { id, file: "x.rs".into(), genre: genre.into(), a, b: a + what.len(), real: real.into() }
    }
    fn run_gen(src: &str, muts: &[In]) -> (String, BTreeMap<u32, String>) {
        let mut fb = BTreeMap::new();
        let (out, _) = gen_file(src, muts, P, &mut fb).expect("gen");
        (out, fb)
    }

    #[test]
    fn line_column_offsets_count_chars() {
        let s = "ab\né x + y\n";
        let st = line_starts(s);
        assert_eq!(off(s, &st, LineColumn { line: 2, column: 2 }), Some(s.find('x').unwrap()));
        assert_eq!(off(s, &st, LineColumn { line: 2, column: 99 }), None);
    }

    #[test]
    fn every_form_round_trips_and_is_held() {
        let src = "fn f(a: u32, b: u32, c: u32, o: Option<u32>, ok: bool) -> Result<u32, ()> {\n    \
            if !ok { return Err(()); }\n    \
            let Some(x) = o else { return Err(()) };\n    \
            if let Some(y) = o { g(y)?; } else { g(0)?; }\n    \
            for i in 0..3 { if i == 1 { continue; } break; }\n    \
            let v = match a { 0 => 1, n if n > 9 => 2, _ => 3 };\n    \
            Ok(a - b * c + x + v)\n}\nfn g(_: u32) -> Result<(), ()> { Ok(()) }\n";
        let muts = vec![
            mu(src, 1, "UnaryOperator", "!", 0, ""),
            mu(src, 2, "ReturnErr", "return Err(())", 0, "()"),
            {
                let o = "let Some(x) = o else { return Err(()) };";
                let mut m = mu(src, 3, "LetElse", o, 0, "");
                m.real = format!("if true {} {}", "{ return Err(()) }", o);
                m
            },
            mu(src, 4, "IfLet", "{ g(y)?; }", 0, "{ g(0)?; }"),
            mu(src, 5, "TryStatement", "g(y)?", 0, "()"),
            mu(src, 6, "Continue", "continue", 0, "()"),
            mu(src, 7, "Break", "break", 0, "()"),
            mu(src, 8, "BinaryOperator", "==", 0, "!="),
            mu(src, 9, "MatchArm", "0 => 1,", 0, ""),
            mu(src, 10, "MatchArmGuard", "n > 9", 0, "true"),
            mu(src, 11, "MatchArmGuard", "n > 9", 0, "false"),
            mu(src, 12, "BinaryOperator", "*", 0, "+"),
            mu(src, 13, "BinaryOperator", "-", 1, "/"),
            mu(src, 14, "IfCondition", "!ok", 0, "true"),
            {
                let body = "Ok(())";
                let a = src.rfind(body).unwrap();
                In { id: 15, file: "x.rs".into(), genre: "FnValue".into(), a, b: a + body.len(), real: "Ok(Default::default())".into() }
            },
        ];
        let (out, fb) = run_gen(src, &muts);
        assert!(fb.is_empty(), "fallbacks: {fb:?}\n{out}");
        // the chain is the region: `*` -> `+` re-associates as in cargo-mutants' text
        assert!(out.contains(&format!("{P}(12) {{ (a - b + c + x + v) }}")), "{out}");
        assert!(out.contains(&format!("0  if !{P}(9) => 1,")), "{out}");
        assert!(out.contains(&format!("(if !{P}(2) {{ return Err(()); }})")), "{out}");
        assert!(out.contains(&format!("if {P}(3) {{ return Err(()) }} let Some(x)")), "{out}");
        assert!(out.contains(&format!("if {P}(15) {{ Ok(Default::default()) }} else {{ Ok(()) }}")), "{out}");
        syn::parse_file(&out).expect("the schema parses");
    }

    #[test]
    fn the_round_trip_refuses_a_wrong_grouping() {
        // a hand-made schema that isolates `b * c` (the non-maximal region): collapsed for the mutant it reads a - (b + c),
        // cargo-mutants' text a - b + c; the check must tell them apart
        let src = "fn f(a: u32, b: u32, c: u32) -> u32 { a - b * c }\n";
        let wrong = format!("fn f(a: u32, b: u32, c: u32) -> u32 {{ a - (if {P}(1) {{ (b + c) }} else {{ (b * c) }}) }}\n");
        let m = mu(src, 1, "BinaryOperator", "*", 0, "+");
        let st = line_starts(src);
        let orig = syn::parse_file(src).unwrap();
        let path = locate(&orig.items, src, &st, m.a).unwrap();
        let real = syn::parse_file(&format!("{}{}{}", &src[..m.a], m.real, &src[m.b..])).unwrap();
        let w = syn::parse_file(&wrong).unwrap();
        assert_ne!(eval(&w, &path, 1), eval(&real, &path, 0));
        assert_eq!(eval(&w, &path, 0), eval(&orig, &path, 0));
        // and the generator's own schema passes
        let (out, fb) = run_gen(src, &[m]);
        assert!(fb.is_empty(), "{fb:?}");
        assert!(out.contains(&format!("{P}(1) {{ (a - b + c) }}")), "{out}");
    }

    #[test]
    fn unexpressible_forms_fall_back() {
        let src = "const fn k(a: u32) -> u32 { a + 1 }\nasync fn s(a: u32) -> u32 { a + 1 }\nfn i(a: u32) -> impl Fn() -> u32 { move || a + 1 }\nconst C: u32 = 1 + 2;\n";
        let muts = vec![mu(src, 1, "BinaryOperator", "+", 0, "-"), mu(src, 2, "BinaryOperator", "+", 1, "-"), mu(src, 3, "BinaryOperator", "+", 2, "-"), mu(src, 4, "BinaryOperator", "+", 3, "-")];
        let (_, fb) = run_gen(src, &muts);
        assert_eq!(fb.len(), 4, "{fb:?}");
        assert_eq!(fb[&1], "const fn");
        assert_eq!(fb[&2], "async fn");
        assert_eq!(fb[&3], "fn returning impl Trait");
        assert_eq!(fb[&4], "outside a function");
    }

    #[test]
    fn a_span_that_is_not_the_form_falls_back() {
        let src = "fn f(a: u32) -> u32 { a + 1 }\n";
        let (_, fb) = run_gen(src, &[mu(src, 1, "BinaryOperator", "a", 1, "b")]);
        assert_eq!(fb[&1], "no binary operator at the span");
    }

    #[test]
    fn the_runtime_has_one_seen_slot_per_id() {
        assert!(runtime(41).contains("const N: usize = 42;"));
    }
}

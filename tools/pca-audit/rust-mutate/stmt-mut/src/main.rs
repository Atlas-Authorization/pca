//! stmt-mut <file.rs>...: prints a JSON array of the mutants cargo-mutants 27 never makes, for production code only (items
//! under #[cfg(test)] or #[test] are skipped):
//!   if <plain boolean> (a path, field, call, method call, macro or index, optionally negated) -> forced true, forced false
//!   if let P = E { A } else { B }                -> { B } in place of { A } (the pattern never matches)
//!   let P = E else { D };                       -> `if true { D }` before it (the else branch always taken)
//!   continue / break                            -> ()
//!   <expr>?;  (a bare fallible statement)        -> ();
//!   return Err(..)                              -> ()
//! Each mutant is a byte range of the file and its replacement. The driver (stmt-run.mjs) drops those on a line where
//! cargo-mutants already has a mutant, builds and tests each one as cargo-mutants does.
use proc_macro2::LineColumn;
use serde_json::{json, Value};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, Stmt, UnOp};

struct V<'a> {
    file: &'a str,
    src: &'a str,
    starts: Vec<usize>,
    fns: Vec<String>,
    tys: Vec<String>,
    out: Vec<Value>,
}

fn is_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("test")
            || (a.path().is_ident("cfg") && a.meta.require_list().is_ok_and(|l| l.tokens.to_string().trim() == "test"))
    })
}

fn plain(e: &Expr) -> bool {
    match e {
        Expr::Paren(p) => plain(&p.expr),
        Expr::Group(g) => plain(&g.expr),
        Expr::Unary(u) if matches!(u.op, UnOp::Not(_)) => plain(&u.expr),
        Expr::Path(_) | Expr::Field(_) | Expr::Call(_) | Expr::MethodCall(_) | Expr::Macro(_) | Expr::Index(_) => true,
        _ => false,
    }
}

impl<'a> V<'a> {
    fn off(&self, p: LineColumn) -> usize {
        let s = self.starts[p.line - 1];
        s + self.src[s..].chars().take(p.column).map(char::len_utf8).sum::<usize>()
    }
    fn text(&self, s: proc_macro2::Span) -> &'a str {
        &self.src[self.off(s.start())..self.off(s.end())]
    }
    fn add(&mut self, at: proc_macro2::Span, range: (usize, usize), repl: String, genre: &str, what: &str) {
        let Some(f) = self.fns.last() else { return };
        let p = at.start();
        self.out.push(json!({"file": self.file, "line": p.line, "col": p.column + 1, "start": range.0, "end": range.1,
            "repl": repl, "genre": genre, "fn": f, "desc": format!("{what} in {f}")}));
    }
    fn whole(&self, s: proc_macro2::Span) -> (usize, usize) {
        (self.off(s.start()), self.off(s.end()))
    }
    fn with_fn(&mut self, name: String, f: impl FnOnce(&mut Self)) {
        self.fns.push(name);
        f(self);
        self.fns.pop();
    }
}

impl<'a, 'ast> Visit<'ast> for V<'a> {
    fn visit_item_fn(&mut self, i: &'ast syn::ItemFn) {
        if !is_test(&i.attrs) {
            self.with_fn(i.sig.ident.to_string(), |v| visit::visit_item_fn(v, i));
        }
    }
    fn visit_item_mod(&mut self, i: &'ast syn::ItemMod) {
        if !is_test(&i.attrs) {
            visit::visit_item_mod(self, i);
        }
    }
    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        if is_test(&i.attrs) {
            return;
        }
        let ty = match &*i.self_ty {
            syn::Type::Path(p) => p.path.segments.last().map_or("_".into(), |s| s.ident.to_string()),
            _ => "_".into(),
        };
        self.tys.push(ty);
        visit::visit_item_impl(self, i);
        self.tys.pop();
    }
    fn visit_impl_item_fn(&mut self, i: &'ast syn::ImplItemFn) {
        if !is_test(&i.attrs) {
            let name = format!("{}::{}", self.tys.last().map_or("_", String::as_str), i.sig.ident);
            self.with_fn(name, |v| visit::visit_impl_item_fn(v, i));
        }
    }
    fn visit_trait_item_fn(&mut self, i: &'ast syn::TraitItemFn) {
        if !is_test(&i.attrs) {
            self.with_fn(i.sig.ident.to_string(), |v| visit::visit_trait_item_fn(v, i));
        }
    }
    fn visit_expr_if(&mut self, i: &'ast syn::ExprIf) {
        if let Expr::Let(_) = &*i.cond {
            let els = i.else_branch.as_ref().map_or("{}".to_string(), |(_, e)| match &**e {
                Expr::Block(b) => self.text(b.block.span()).to_string(),
                other => format!("{{ {} }}", self.text(other.span())),
            });
            let r = self.whole(i.then_branch.span());
            self.add(i.cond.span(), r, els, "IfLet", "replace if let body with its else branch");
        } else if plain(&i.cond) {
            let r = self.whole(i.cond.span());
            for b in ["true", "false"] {
                self.add(i.cond.span(), r, b.into(), "IfCondition", &format!("replace if condition with {b}"));
            }
        }
        visit::visit_expr_if(self, i);
    }
    fn visit_local(&mut self, i: &'ast syn::Local) {
        if let Some(init) = &i.init {
            if let Some((_, d)) = &init.diverge {
                let r = self.whole(i.span());
                let repl = format!("if true {} {}", self.text(d.span()), self.text(i.span()));
                self.add(i.span(), r, repl, "LetElse", "take the let-else branch");
            }
        }
        visit::visit_local(self, i);
    }
    fn visit_stmt(&mut self, s: &'ast Stmt) {
        if let Stmt::Expr(e @ Expr::Try(_), Some(_)) = s {
            let r = self.whole(e.span());
            self.add(e.span(), r, "()".into(), "TryStatement", "delete ? statement");
        }
        visit::visit_stmt(self, s);
    }
    fn visit_expr_continue(&mut self, i: &'ast syn::ExprContinue) {
        let r = self.whole(i.span());
        self.add(i.span(), r, "()".into(), "Continue", "delete continue");
    }
    fn visit_expr_break(&mut self, i: &'ast syn::ExprBreak) {
        let r = self.whole(i.span());
        self.add(i.span(), r, "()".into(), "Break", "delete break");
        visit::visit_expr_break(self, i);
    }
    fn visit_expr_return(&mut self, i: &'ast syn::ExprReturn) {
        if let Some(Expr::Call(c)) = i.expr.as_deref() {
            if matches!(&*c.func, Expr::Path(p) if p.path.is_ident("Err")) {
                let r = self.whole(i.span());
                self.add(i.span(), r, "()".into(), "ReturnErr", "delete return Err");
            }
        }
        visit::visit_expr_return(self, i);
    }
}

fn main() {
    let mut all = Vec::new();
    for file in std::env::args().skip(1) {
        let src = std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{file}: {e}"));
        let ast = syn::parse_file(&src).unwrap_or_else(|e| panic!("{file}: {e}"));
        let mut starts = vec![0];
        starts.extend(src.match_indices('\n').map(|(i, _)| i + 1));
        let mut v = V { file: &file, src: &src, starts, fns: vec![], tys: vec![], out: vec![] };
        v.visit_file(&ast);
        all.extend(v.out);
    }
    println!("{}", Value::Array(all));
}

#[cfg(test)]
mod tests {
    use super::*;
    fn muts(src: &str) -> Vec<(String, String)> {
        let mut starts = vec![0];
        starts.extend(src.match_indices('\n').map(|(i, _)| i + 1));
        let mut v = V { file: "x.rs", src, starts, fns: vec![], tys: vec![], out: vec![] };
        v.visit_file(&syn::parse_file(src).unwrap());
        v.out.iter().map(|m| {
            let (a, b) = (m["start"].as_u64().unwrap() as usize, m["end"].as_u64().unwrap() as usize);
            (m["desc"].as_str().unwrap().to_string(), format!("{}{}{}", &src[..a], m["repl"].as_str().unwrap(), &src[b..]))
        }).collect()
    }
    #[test]
    fn each_form_and_its_rewrite() {
        let src = "fn f(o: Option<u8>, ok: bool) -> Result<u8, ()> {\n    if !ok { return Err(()); }\n    if ok == true { g()?; }\n    let Some(x) = o else { return Err(()) };\n    if let Some(y) = o { h(y) } else { h(0) }\n    for i in 0..3 { if i == 1 { continue; } break; }\n    Ok(x)\n}\n#[cfg(test)]\nmod t { fn z(a: bool) { if a {} } }\n#[test]\nfn w() { if q {} }\n";
        let got = muts(src);
        let d: Vec<&str> = got.iter().map(|x| x.0.as_str()).collect();
        assert_eq!(d, ["replace if condition with true in f", "replace if condition with false in f", "delete return Err in f",
            "delete ? statement in f", "take the let-else branch in f", "delete return Err in f",
            "replace if let body with its else branch in f", "delete continue in f", "delete break in f"]);
        assert!(got[0].1.contains("    if true { return Err(()); }"));
        assert!(got[2].1.contains("if !ok { (); }"));
        assert!(got[3].1.contains("if ok == true { (); }"));
        assert!(got[4].1.contains("    if true { return Err(()) } let Some(x) = o else { return Err(()) };"));
        assert!(got[6].1.contains("if let Some(y) = o { h(0) } else { h(0) }"));
        assert!(got[7].1.contains("if i == 1 { (); }"));
    }
    #[test]
    fn methods_are_named_by_their_type() {
        let got = muts("impl<'a> P<'a> { fn at(&self) { if self.x {} } }");
        assert_eq!(got[0].0, "replace if condition with true in P::at");
    }
}

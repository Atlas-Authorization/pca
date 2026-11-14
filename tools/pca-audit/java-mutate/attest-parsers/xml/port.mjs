// faithful JS port of AttestXml.java (post-edit) + the test's dump format
class AErr extends Error {}
const isSp = c => c === " " || c === "\t" || c === "\n" || c === "\r";
function mkNode() { return { elem: false, name: "", prefix: "", local: "", ns: "", attrs: [], decls: [], children: [], text: "", parent: null }; }
function lookupNs(n, p) { for (let e = n; e; e = e.parent) for (const d of e.decls) if (d.prefix === p) return d.uri; return null; }
function appendText(n, t) { const k = n.children.length; if (k > 0 && !n.children[k - 1].elem) { n.children[k - 1].text += t; return; }
  const c = mkNode(); c.text = t; c.parent = n; n.children.push(c); }
function resolveNames(n) { const i = n.name.indexOf(":"); n.prefix = i >= 0 ? n.name.slice(0, i) : ""; n.local = i >= 0 ? n.name.slice(i + 1) : n.name;
  const uri = lookupNs(n, n.prefix); if (n.prefix !== "" && uri === null) throw new AErr("namespace prefix " + n.prefix + " is not bound");
  n.ns = uri === null ? "" : uri;
  for (const a of n.attrs) { if (a.prefix === "") continue; const u = lookupNs(n, a.prefix); if (u === null) throw new AErr("namespace prefix " + a.prefix + " is not bound"); a.ns = u; } }
function asciiDigits(s, from, hex) { if (from >= s.length) return false; for (let i = from; i < s.length; i++) { const c = s[i];
  const ok = (c >= "0" && c <= "9") || (hex && ((c >= "a" && c <= "f") || (c >= "A" && c <= "F"))); if (!ok) return false; } return true; }
export function xmlDecode(s) { let sb = ""; for (let i = 0; i < s.length;) { if (s[i] !== "&") { sb += s[i]; i++; continue; }
  const j = s.indexOf(";", i); if (j < 0) throw new AErr("unterminated entity reference"); const ent = s.slice(i + 1, j); i = j + 1;
  switch (ent) { case "lt": sb += "<"; break; case "gt": sb += ">"; break; case "amp": sb += "&"; break; case "quot": sb += '"'; break; case "apos": sb += "'"; break;
    default: { if (!ent.startsWith("#")) throw new AErr("undefined entity &" + ent + ";"); const hex = ent.startsWith("#x"); const from = hex ? 2 : 1;
      const invalid = "invalid character reference &" + ent + ";"; if (!asciiDigits(ent, from, hex)) throw new AErr(invalid);
      const v = BigInt((hex ? "0x" : "") + ent.slice(from)); if (v > 0x10ffffn) throw new AErr(invalid); const n = Number(v);
      const legal = n === 0x9 || n === 0xa || n === 0xd || (n >= 0x20 && n <= 0xd7ff) || (n >= 0xe000 && n <= 0xfffd) || n >= 0x10000;
      if (!legal) throw new AErr(invalid); sb += String.fromCodePoint(n); } } } return sb; }
export function parseXml(s) { const doc = { root: null, violation: "" }; let cur = null; let i = 0;
  const note = v => { if (doc.violation === "") doc.violation = v; };
  while (i < s.length) {
    if (s[i] !== "<") { let end = s.indexOf("<", i); if (end < 0) end = s.length; const txt = s.slice(i, end); i = end;
      if (cur === null) { for (const c of txt) if (!isSp(c)) throw new AErr("text outside the document element"); continue; }
      appendText(cur, xmlDecode(txt)); continue; }
    if (s.startsWith("<!--", i)) { const j = s.indexOf("-->", i + 4); if (j < 0) throw new AErr("unterminated comment"); note("XML comments are not permitted"); i = j + 3; }
    else if (s.startsWith("<?", i)) { const j = s.indexOf("?>", i); if (j < 0) throw new AErr("unterminated processing instruction"); note("XML processing instructions are not permitted"); i = j + 2; }
    else if (s.startsWith("<![CDATA[", i)) { const j = s.indexOf("]]>", i); if (j < 0 || cur === null) throw new AErr("misplaced or unterminated CDATA section"); appendText(cur, s.slice(i + 9, j)); i = j + 3; }
    else if (s.startsWith("<!DOCTYPE", i)) { let depth = 0, j = i; for (; j < s.length; j++) { const c = s[j]; if (c === "[") depth++; else if (c === "]") depth--; else if (c === ">" && depth <= 0) break; }
      if (j >= s.length) throw new AErr("unterminated DOCTYPE"); note("DTD / DOCTYPE is not permitted"); i = j + 1; }
    else if (s.startsWith("</", i)) { const j = s.indexOf(">", i); if (j < 0 || cur === null) throw new AErr("unexpected end tag"); let e = j;
      while (" \t\r\n".indexOf(s[e - 1]) >= 0) e--; const name = s.slice(i + 2, e);
      if (name !== cur.name) throw new AErr("end tag </" + name + "> does not match <" + cur.name + ">"); cur = cur.parent; i = j + 1; }
    else { const st = parseStartTag(s.slice(i), doc, note); i += st.n; st.node.parent = cur;
      if (cur === null) { if (doc.root !== null) throw new AErr("more than one document element"); doc.root = st.node; } else cur.children.push(st.node);
      resolveNames(st.node); if (!st.selfClose) cur = st.node; } }
  if (cur !== null) throw new AErr("element <" + cur.name + "> is not closed"); if (doc.root === null) throw new AErr("no document element"); return doc; }
function parseStartTag(rest, doc, note) { let i = 1, j = i;
  while (j < rest.length && !isSp(rest[j]) && rest[j] !== "/" && rest[j] !== ">") j++;
  const name = rest.slice(i, j); if (name === "") throw new AErr("malformed start tag");
  const node = mkNode(); node.elem = true; node.name = name; const seen = new Set(); i = j; const st = { node, selfClose: false, n: 0 };
  while (true) { while (i < rest.length && isSp(rest[i])) i++; if (i >= rest.length) throw new AErr("unterminated start tag");
    if (rest[i] === ">") { st.n = i + 1; return st; }
    if (rest[i] === "/") { if (i + 1 < rest.length && rest[i + 1] === ">") { st.selfClose = true; st.n = i + 2; return st; } throw new AErr("malformed start tag"); }
    let k = i; while (k < rest.length && !isSp(rest[k]) && rest[k] !== "=" && rest[k] !== ">" && rest[k] !== "/") k++;
    const aname = rest.slice(i, k); while (k < rest.length && isSp(rest[k])) k++;
    if (aname === "" || k >= rest.length || rest[k] !== "=") throw new AErr("malformed attribute"); k++;
    while (k < rest.length && isSp(rest[k])) k++;
    if (k >= rest.length || (rest[k] !== '"' && rest[k] !== "'")) throw new AErr("unquoted attribute value");
    const q = rest[k]; const e = rest.indexOf(q, k + 1); if (e < 0) throw new AErr("unterminated attribute value");
    const raw = rest.slice(k + 1, e); if (raw.indexOf("<") >= 0) throw new AErr("'<' in an attribute value");
    const val = xmlDecode(raw); i = e + 1;
    if (seen.has(aname)) throw new AErr("attribute " + aname + " is repeated"); seen.add(aname);
    if (aname.toLowerCase().startsWith("xml:")) note("xml:* attribute '" + aname + "' is not permitted (C14N 1.1 profile)");
    if (aname === "xmlns") node.decls.push({ prefix: "", uri: val });
    else if (aname.startsWith("xmlns:")) node.decls.push({ prefix: aname.slice(6), uri: val });
    else { const c = aname.indexOf(":"); node.attrs.push({ name: aname, prefix: c >= 0 ? aname.slice(0, c) : "", local: c >= 0 ? aname.slice(c + 1) : aname, ns: "", value: val }); } } }
const escT = s => [...s].map(r => r === "&" ? "&amp;" : r === "<" ? "&lt;" : r === ">" ? "&gt;" : r === "\r" ? "&#xD;" : r).join("");
const escA = s => [...s].map(r => r === "&" ? "&amp;" : r === "<" ? "&lt;" : r === '"' ? "&quot;" : r === "\t" ? "&#x9;" : r === "\n" ? "&#xA;" : r === "\r" ? "&#xD;" : r).join("");
const cmpU8 = (a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
export function canonicalize(n, parentScope, skip) { const out = []; c14n(out, n, parentScope, new Map(), skip); return out.join(""); }
function c14n(out, n, parentScope, rendered, skip) { const scope = new Map(parentScope); for (const d of n.decls) scope.set(d.prefix, d.uri);
  const emit = []; for (const [p, uri] of scope) { if (p === "xml" || (uri === "" && p !== "")) continue; let r = rendered.get(p); if (r === undefined) r = ""; if (r === uri) continue; emit.push(p); }
  emit.sort(cmpU8); const nr = new Map(rendered); out.push("<" + n.name);
  for (const p of emit) { if (p === "") out.push(' xmlns="' + escA(scope.get(p)) + '"'); else out.push(" xmlns:" + p + '="' + escA(scope.get(p)) + '"'); nr.set(p, scope.get(p)); }
  const key = a => (a.ns === "" ? "0" : "1") + a.ns + a.local;
  const attrs = [...n.attrs].sort((a, b) => cmpU8(key(a), key(b)));
  for (const a of attrs) out.push(" " + a.name + '="' + escA(a.value) + '"'); out.push(">");
  for (const c of n.children) { if (c === skip) continue; if (c.elem) c14n(out, c, scope, nr, skip); else out.push(escT(c.text)); }
  out.push("</" + n.name + ">"); }
// ---- dump (mirrors the Java test)
export const q = s => s === null || s === undefined ? "null" : '"' + [...Array(s.length).keys()].map(i => { const c = s.charCodeAt(i);
  if (c === 92) return "\\\\"; if (c === 34) return '\\"'; if (c === 10) return "\\n"; if (c === 13) return "\\r"; if (c === 9) return "\\t";
  if (c < 0x20 || c > 0x7e) return "\\u" + c.toString(16).padStart(4, "0"); return s[i]; }).join("") + '"';
function textContent(n) { return n.elem ? n.children.map(textContent).join("") : n.text; }
function dumpNode(n, parent) { let s = (n.parent === parent ? "" : "!parent ") + (n.elem ? "E" : "T") + "(" + [n.name, n.prefix, n.local, n.ns, n.text].map(q).join(",");
  s += ",d["; for (const d of n.decls) s += q(d.prefix) + "=" + q(d.uri) + ";"; s += "],a[";
  for (const a of n.attrs) s += [a.name, a.prefix, a.local, a.ns, a.value].map(q).join(",") + ";"; s += "],{";
  for (const c of n.children) s += dumpNode(c, n); return s + "})"; }
export function dump(src) { try { const d = parseXml(src); return "V" + q(d.violation) + " " + dumpNode(d.root, null) + " TC" + q(textContent(d.root)) + " C" + q(canonicalize(d.root, new Map(), null)); }
  catch (e) { if (e instanceof AErr) return "ERR:" + e.message; throw e; } }

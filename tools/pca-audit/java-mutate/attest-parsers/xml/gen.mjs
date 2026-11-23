import { dump } from "./port.mjs";
import fs from "fs";
const hand = [
 // whitespace in tags and around '=' (tab, CR, LF, space)
 "<a\tx=\"1\"/>", "<a\rx=\"1\"/>", "<a\nx=\"1\"/>", "<a x\t=\t\"1\"\r/>", "<a x =\n'1'></a >", "<a x= \"1\" ></a\t>", "<a></a\r\n>", "<a\t/>", "<a\r></a>",
 // attribute name scanning stops
 "<a x>=\"1\"/>", "<a x/=\"1\"/>", "<a x=\"1\"y=\"2\"/>", "<a x", "<a x ", "<a x=", "<a x= ", "<a x='1'/>", "<a x='\"'/>", "<a x=\"'\"/>", "<a x='1\"/>", "<a =\"1\"/>",
 "<a/", "<a/x>", "<a", "<abc", "<a ", "<a></a", "</a>", "<a></a></a>", "<a></b >", "<a></ >", "<a></\ta>", "<a>< /a>",
 // names with a leading colon and prefixes
 "<:a/>", "<a :x=\"1\"/>", "<a xmlns:p=\"u\" p:=\"1\"/>", "<p: xmlns:p=\"u\"/>", "<a xmlns:=\"u\"/>",
 "<a xmlns:XML=\"u\" XML:lang=\"en\"/>", "<a xmlns:Xml=\"u\" Xml:space=\"x\"/>", "<a xmlns:xmlx=\"u\" xmlx:y=\"1\"/>",
 // default namespace behaviour
 "<a><b/></a>", "<a xmlns=\"u\"><b xmlns=\"\"/></a>", "<a xmlns=\"\"/>", "<a xmlns:p=\"\"/>", "<a xmlns:p=\"u\"><b xmlns:p=\"\"/></a>",
 "<a xmlns:xml=\"http://www.w3.org/XML/1998/namespace\"><b/></a>", "<a xmlns=\"a&amp;b&quot;&#9;\" xmlns:p=\"&lt;&#xA;\"/>", "<a xmlns:p=\"u\"><p:b xmlns:p=\"u\"/></a>",
 // attribute order: unqualified first, then namespace + local
 "<a xmlns:p=\"u\" xmlns:q=\"t\" p:x=\"1\" y=\"2\" q:z=\"3\" b=\"4\" p:a=\"5\"/>", "<a xmlns:p=\"u\" p:x=\"1\" y=\"2\"/>", "<a xmlns:p=\"z\" p:a=\"1\" zz=\"2\"/>",
 // text, CDATA merge and entities
 "<a>x<![CDATA[y]]>z</a>", "<a><![CDATA[y]]></a>", "<a><![CDATA[]]></a>", "<a><b/>x<![CDATA[y]]><c/>z</a>", "<a>x<!-- c -->y</a>", "<a>x<?p?>y</a>", "<![CDATA[x]]><a/>", "<a><![CDATA[x]]</a>",
 "<a>&lt;&gt;&amp;&quot;&apos;</a>", "<a x=\"&apos;\"/>", "<a>&;</a>", "<a>&</a>", "<a>&amp</a>", "<a>&nbsp;</a>", "<a>&LT;</a>", "<a>&#;</a>", "<a>&#x;</a>", "<a>&#X41;</a>", "<a>&#-1;</a>", "<a>&#+65;</a>",
 "<a>&#x2f;&#x2F;&#x2a;&#x2A;&#x39;&#x30;&#x40;&#90;&#57;&#109;&#47;&#0000065;&#x000041;</a>", "<a>&#x2g;</a>", "<a>&#x2G;</a>", "<a>&#x2`;</a>", "<a>&#x2@;</a>", "<a>&#x2/;</a>", "<a>&#x2:;</a>", "<a>&#4a;</a>", "<a>&#4/;</a>", "<a>&#4:;</a>",
 "<a>&#x1F;</a>", "<a>&#x20;</a>", "<a>&#xD7FF;</a>", "<a>&#xD800;</a>", "<a>&#xDFFF;</a>", "<a>&#xE000;</a>", "<a>&#xFFFD;</a>", "<a>&#xFFFE;</a>", "<a>&#xFFFF;</a>", "<a>&#x10000;</a>", "<a>&#x10FFFF;</a>", "<a>&#x110000;</a>",
 "<a>&#x9;&#xA;&#xD;&#9;&#10;&#13;</a>", "<a>&#x8;</a>", "<a>&#xB;</a>", "<a>&#xC;</a>", "<a>&#xE;</a>", "<a>&#x0;</a>", "<a>&#1114111;</a>", "<a>&#1114112;</a>", "<a>&#x100000000000000000000041;</a>", "<a>&#99999999999999999999;</a>",
 // comments, PIs, DOCTYPE
 "<a><!----></a>", "<a><!---->x</a>", "<a><!-->--></a>", "<a><!--></a>", "<a><?></a>", "<a><?x?></a>", "<a><?x</a>", "<!DOCTYPE a><a/>", "<!DOCTYPE a [<!ENTITY e \"]\">]><a/>", "<!DOCTYPE a [[]]><a/>", "<!DOCTYPE a ]><a/>", "<!DOCTYPE a [", "<a><!DOCTYPE x></a>",
 "<a xml:lang=\"en\" xmlns:xml=\"http://www.w3.org/XML/1998/namespace\"><!-- c --></a>", "<!-- c --><a><?p?></a>", "<a/><!-- c -->", " <a/> ", "\t\r\n<a/>\r\n", "", "x", "<a/>x", "<a/><b/>",
 "<a b=\"<\"/>", "<a b=\"1\" b=\"2\"/>", "<a b=\"1\" B=\"2\"/>", "<a>&#x41</a>",
];
const seeds = [
 "<?xml version=\"1.0\"?>\n<r:Root xmlns:r=\"urn:r\" xmlns=\"urn:d\" r:id='1' b=\"x&amp;y\">\r\n\t<Item a=\"&#x41;&lt;\" r:k = \"v\">t&gt;<![CDATA[c<]]></Item><e/></r:Root>",
 "<d:M xmlns:d=\"u\"><d:E n=\"x\">1&#9;</d:E>\n<F/><!--c--></d:M>",
];
const subs = ["", " ", "\t", "<", ">", "/", "=", "\"", "'", "&", ";", ":", "x", "!", "?", "[", "]", "-"];
const sweep = [];
for (const s of seeds) for (let i = 0; i <= s.length; i++) for (const r of subs) { sweep.push(s.slice(0, i) + r + s.slice(i + 1)); sweep.push(s.slice(0, i) + r + s.slice(i)); }
const pick = [...new Set([...hand, ...seeds, ...sweep.filter((_, k) => k % 19 === 0)])];
const rows = pick.map(s => [s, dump(s)]);
const ec = {}; for (const [, d] of rows) { const k = d.startsWith("ERR:") ? d.replace(/<.*?>|&.*?;|prefix \S+|attribute \S+/g, "*") : "OK"; ec[k] = (ec[k] || 0) + 1; }
console.log(rows.length, ec);
const jl = s => '"' + [...Array(s.length).keys()].map(i => { const c = s.charCodeAt(i);
  if (c === 34) return '\\"'; if (c === 92) return '\\\\'; if (c === 10) return '\\n'; if (c === 13) return '\\r'; if (c === 9) return '\\t'; if (c >= 0x20 && c < 0x7f) return s[i];
  return "\\u" + c.toString(16).padStart(4, "0"); }).join("") + '"';
fs.writeFileSync("rows.java.txt", rows.map(([s, d]) => `        {${jl(s)},\n            ${jl(d)}},`).join("\n") + "\n");

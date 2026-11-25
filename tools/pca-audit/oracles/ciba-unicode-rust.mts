// Writes the Unicode property tables the native (Rust) CIBA bridge needs, read from THIS JavaScript runtime's regex engine (the
// same ICU tables the TS reference's /\p{..}/u checks use), so the native payee checks agree with the reference code point for code point.
// Usage: node tools/pca-audit/oracles/ciba-unicode-rust.mts > sdks/rust-pca/src/ciba_unicode.rs
const GROUPS: [string, RegExp][] = [
  ['latin', /\p{Script=Latin}/u],
  ['cyrillic', /\p{Script=Cyrillic}/u],
  ['greek', /\p{Script=Greek}/u],
  ['armenian', /\p{Script=Armenian}/u],
  ['hebrew', /\p{Script=Hebrew}/u],
  ['arabic', /\p{Script=Arabic}/u],
  ['cjk', /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Bopomofo}]/u],
  ['indic-thai', /[\p{Script=Devanagari}\p{Script=Bengali}\p{Script=Tamil}\p{Script=Thai}\p{Script=Georgian}]/u],
];
const L = /\p{L}/u, M = /\p{M}/u, CCF = /[\p{Cc}\p{Cf}]/u;
const UND = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\u2028\u2029\uFFF9-\uFFFD]/u;
type R = [number, number, number];
const tabs: Record<string, R[]> = { LETTER_GROUPS: [], MARK: [], CC_CF: [], UNDISPLAYABLE: [] };
const push = (t: R[], cp: number, tag: number) => {
  const last = t[t.length - 1];
  if (last && last[1] === cp - 1 && last[2] === tag) last[1] = cp;
  else t.push([cp, cp, tag]);
};
for (let cp = 0; cp <= 0x10ffff; cp++) {
  if (cp >= 0xd800 && cp <= 0xdfff) continue; // not a Rust char
  const ch = String.fromCodePoint(cp);
  if (L.test(ch)) push(tabs.LETTER_GROUPS, cp, GROUPS.findIndex(([, re]) => re.test(ch)) + 1);
  if (M.test(ch)) push(tabs.MARK, cp, 0);
  if (CCF.test(ch)) push(tabs.CC_CF, cp, 0);
  if (UND.test(ch)) push(tabs.UNDISPLAYABLE, cp, 0);
}
const hex = (n: number) => '0x' + n.toString(16);
let out = `//! Unicode property tables for the CIBA payee checks, generated from the JavaScript reference runtime (ICU ${process.versions.icu},\n`;
out += `//! Unicode ${process.versions.unicode}). Do not edit by hand. Sorted, disjoint, inclusive code point ranges.\n\n`;
out += `/// Script group names; a letter's tag indexes this (0: a letter outside the named groups).\n`;
out += `pub(crate) const GROUP_NAMES: [&str; ${GROUPS.length + 1}] = ["other", ${GROUPS.map(([n]) => JSON.stringify(n)).join(', ')}];\n\n`;
const doc: Record<string, string> = {
  LETTER_GROUPS: 'General_Category=Letter, tagged with the script group',
  MARK: 'General_Category=Mark',
  CC_CF: 'General_Category=Control or Format',
  UNDISPLAYABLE: 'Control, Format, Private_Use, Unassigned, U+2028, U+2029, U+FFF9..U+FFFD',
};
for (const [name, t] of Object.entries(tabs)) {
  const tagged = name === 'LETTER_GROUPS';
  out += `/// ${doc[name]}.\n#[rustfmt::skip]\npub(crate) const ${name}: [${tagged ? '(u32, u32, u8)' : '(u32, u32)'}; ${t.length}] = [\n`;
  for (let i = 0; i < t.length; i += 8) out += '    ' + t.slice(i, i + 8).map(([a, b, g]) => (tagged ? `(${hex(a)}, ${hex(b)}, ${g})` : `(${hex(a)}, ${hex(b)})`)).join(', ') + ',\n';
  out += '];\n\n';
}
out += `/// The tag of \`c\` in a sorted range table, if covered.\npub(crate) fn lookup<T: Copy>(t: &[(u32, u32, T)], c: char) -> Option<T> {\n    let c = c as u32;\n    let i = t.partition_point(|r| r.1 < c);\n    t.get(i).filter(|r| r.0 <= c).map(|r| r.2)\n}\n\n`;
out += `/// Whether \`c\` is in a sorted range table.\npub(crate) fn contains(t: &[(u32, u32)], c: char) -> bool {\n    let c = c as u32;\n    let i = t.partition_point(|r| r.1 < c);\n    t.get(i).is_some_and(|r| r.0 <= c)\n}\n`;
process.stdout.write(out);

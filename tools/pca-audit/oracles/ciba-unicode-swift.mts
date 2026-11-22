// Writes the Unicode property tables the native (Swift) CIBA bridge needs, read from THIS JavaScript runtime's regex engine (the
// same ICU tables the TS reference's /\p{..}/u checks use), so the native payee checks agree with the reference code point for code
// point. Same groups and tables as ciba-unicode-rust.mts; only the output shape differs (flat [UInt32] arrays, which the Swift type
// checker handles quickly, where an array of tuples would not).
// Usage: node tools/pca-audit/oracles/ciba-unicode-swift.mts > sdks/swift-pca/Sources/AtlasPCAVerify/CibaUnicode.swift
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
const tabs: Record<string, R[]> = { letterGroups: [], mark: [], ccCf: [], undisplayable: [] };
const push = (t: R[], cp: number, tag: number) => {
  const last = t[t.length - 1];
  if (last && last[1] === cp - 1 && last[2] === tag) last[1] = cp;
  else t.push([cp, cp, tag]);
};
for (let cp = 0; cp <= 0x10ffff; cp++) {
  if (cp >= 0xd800 && cp <= 0xdfff) continue; // not a Unicode.Scalar
  const ch = String.fromCodePoint(cp);
  if (L.test(ch)) push(tabs.letterGroups, cp, GROUPS.findIndex(([, re]) => re.test(ch)) + 1);
  if (M.test(ch)) push(tabs.mark, cp, 0);
  if (CCF.test(ch)) push(tabs.ccCf, cp, 0);
  if (UND.test(ch)) push(tabs.undisplayable, cp, 0);
}
const hex = (n: number) => '0x' + n.toString(16);
let out = `// Unicode property tables for the CIBA payee checks, generated from the JavaScript reference runtime (ICU ${process.versions.icu},\n`;
out += `// Unicode ${process.versions.unicode}). Do not edit by hand. Sorted, disjoint, inclusive code point ranges, flattened.\n\n`;
out += `enum CibaUnicode {\n`;
out += `    /// Script group names; a letter's tag indexes this (0: a letter outside the named groups).\n`;
out += `    static let groupNames: [String] = ["other", ${GROUPS.map(([n]) => JSON.stringify(n)).join(', ')}]\n\n`;
const doc: Record<string, string> = {
  letterGroups: 'General_Category=Letter as (first, last, group tag) triples',
  mark: 'General_Category=Mark as (first, last) pairs',
  ccCf: 'General_Category=Control or Format as (first, last) pairs',
  undisplayable: 'Control, Format, Private_Use, Unassigned, U+2028, U+2029, U+FFF9..U+FFFD as (first, last) pairs',
};
for (const [name, t] of Object.entries(tabs)) {
  const tagged = name === 'letterGroups';
  const flat = t.flatMap(([a, b, g]) => (tagged ? [hex(a), hex(b), String(g)] : [hex(a), hex(b)]));
  out += `    /// ${doc[name]}.\n    static let ${name}: [UInt32] = [\n`;
  const step = tagged ? 12 : 12;
  for (let i = 0; i < flat.length; i += step) out += '        ' + flat.slice(i, i + step).join(', ') + ',\n';
  out += '    ]\n\n';
}
out += `    /// The tag of \`v\` in a flattened (first, last, tag) table, if covered.\n`;
out += `    static func lookup(_ t: [UInt32], _ v: UInt32) -> UInt32? {\n`;
out += `        var lo = 0, hi = t.count / 3\n        while lo < hi {\n            let mid = (lo + hi) / 2\n`;
out += `            if t[mid * 3 + 1] < v { lo = mid + 1 } else { hi = mid }\n        }\n`;
out += `        return lo < t.count / 3 && t[lo * 3] <= v ? t[lo * 3 + 2] : nil\n    }\n\n`;
out += `    /// Whether \`v\` is in a flattened (first, last) table.\n`;
out += `    static func contains(_ t: [UInt32], _ v: UInt32) -> Bool {\n`;
out += `        var lo = 0, hi = t.count / 2\n        while lo < hi {\n            let mid = (lo + hi) / 2\n`;
out += `            if t[mid * 2 + 1] < v { lo = mid + 1 } else { hi = mid }\n        }\n`;
out += `        return lo < t.count / 2 && t[lo * 2] <= v\n    }\n}\n`;
process.stdout.write(out);

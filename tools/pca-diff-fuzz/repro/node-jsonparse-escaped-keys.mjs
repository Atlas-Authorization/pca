// Pure-Node reproducer (no PCA code): on some V8 builds JSON.parse is NOT a pure function of its input.
// Parsing text X, then a plain-key sibling Y, then X again can yield a different object for X the
// second time (a property is silently dropped). Found by the PCA metamorphic suite: the TS reference
// verifier flipped verdict between two byte-different but JSON-equivalent encodings of one PCActn.
// Run: node repro/node-jsonparse-escaped-keys.mjs   (prints UNSTABLE on an affected build)
const P = String.raw; // keep backslashes literal
const X = P`{"r":0,"inputs":{"a":{"\u006AH|\u002F\u0028y":true,"\u01c5":{"\ud83d\ude00":{"\u002f":"é","\u0023":"\u007F","\ud83d\uDE00":84},"é":null},"\\":false}}}`;
const Y = P`{"r":0,"inputs":{"a":{"jH|/(y":true,"\\":false,"ǅ":{"é":null,"😀":{"/":"é","#":"","😀":84}}}}}`;
const s = (t) => JSON.stringify(JSON.parse(t));
const first = s(X);
s(Y);
const second = s(X);
console.log(process.version, first === second ? 'stable' : 'UNSTABLE');
if (first !== second) { console.log(' first :', first); console.log(' second:', second); }

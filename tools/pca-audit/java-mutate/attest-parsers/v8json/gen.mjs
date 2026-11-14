import { check } from "./cmp.mjs";
import { v8JsonError } from "./port.mjs";
import fs from "fs";
const hand = [
 "[]", "[ ]", "[\n]", "[1]", "[ 1 , 2 ]", "[t,", "[t,1]", "[tx,1]", "{\"a\":t,", "{\"a\":t,\"b\":1}", "{\"a\":t}", "[1,]x", "[1:2]", "[1/2]", "1E5", "1e-5", "1e+5", "-1E-0", "[55]", "[0]", "[-0.5e9]", "[9]",
 "{\"a\":1, \"b\":2}", "{\"a\":1,\"b\":2}", "{\"a\":1,\n\"b\":2}", "{\"a\":1, 2}", "{ }", "{\"a\" : 1 }",
 "\"\u0000\"", "\u0000", "\"\u001f\"", "\"\u0020\"", "\" \"", "\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"", "\"\\#\"", "\"\\]\"", "\"\\0\"", "\"\\c\"", "\"\\g\"", "\"\\s\"", "\"\\u\"", "\"\\u123\"", "\"\\u0a9f\\uAF00\"", "\"\\u09af\"", "\"\\uAF09\"",
 "\"\\ug000\"", "\"\\u@000\"", "\"\\u`000\"", "\"\\uG000\"", "\"\\u/000\"", "\"\\u:000\"", "\"\\u000g\"", "\"\\u000G\"",
 "\"\\", "\"a\\", "\"\\\u00ff\"", "\"\\\u0100\"", "\"\\\u00e9\" abcdefghijklmnopqrstuvwxyz", "\"\\\u0101 abcdefghijklmnopqrstuvwxyz\"", "\"\\\ud83d\ude00\"",
 "t\"", "tr-", "nu1", "fa9", "t0", "nx", "n", "nul", "fals", "truE", "[t]", "t\u0001",
 "NaN", "Infinity", "undefined", "[object Object]", "NaN ", "-Infinity", "nan",
 ":", "/", "x", "0x", "-x", "-", "--1", "+1", ".5", "01", "-01", "1.", "1.e5", "1e", "1e+", "1e-", "1ex",
 "x2345678901234567890", "x23456789012345678901", "x234567890123456789012", "123456789x12345678901", "1234567890x1234567890", "12345678901x123456789", "[1,1,1,1,1,1,1,1,1,1,x]",
 "123456789012345678x01234567890", "1234567890123456789x1234567890", "12345678901234567890x234567890", "123456789012345678901x34567890",
 "[1,2,3,4,5,6,7,8,9,10,11,1]x", "[1,2,3,4,5,6,7,8,9,10,11,12,13,14]x", "[1,2,3,4,5,6,7,8,9,10,11,12,13,14]  x",
 "\"a\nb\"", "\"a\rb\"", "\r\"a\rb\"", "\r\n\"a\u0001\"", "\n\r\n\r\"\u0001\"", "\r\r\"\u0001\"", "[1\r", "[1\n", "[1\r\n", "[1\r\r", "\r\n\r\n[1 2]", "\n\n\n  {\"a\" 1}", "\r{\"a\" 1}", " \t[1 2]",
 "\ud83d\ude00", "[\ud83d\ude00]", "[\ud800]", "[\udc00]", "[\ud800\ud800]", "[\udc00\ud800]", "abcdefghi\ud83d\ude00jklmnopqrstuvwxyz", "abcdefgh\ud83d\ude00ijklmnopqrstuvwxyz", "[1,2,3,4,5,6,7,8,9,x\ud83d\ude00]", "[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,x\ud83d\ude00\ud83d\ude00\ud83d\ude00\ud83d\ude00\ud83d\ude00\ud83d\ude00\ud83d\ude00]",
 "[1,2,3,4,5,6,7,8,x123456789\ud83d\ude0012345]", "[1,2,3,4,5,6,7,8,x12345678\ud83d\ude00012345]", "\ud83d[1,2,3,4,5,6,7,8,9,10,11,12,x", "\ude00\ud83d[1,2,3,4,5,6,7,8,9,10,11,x",
 "{\"a\":[1,{\"b\":[true,false,null]}]}", "{\"\":\"\"}", "  \"x\"  ", "", " ", "\n", "{", "[", "\"", "{\"a\"", "{\"a\":", "{\"a\":1", "[1", "[1,", "{\"a\":1,",
];
const seeds = ['{"a":[1,-2.5e+3,true,false,null,"x\\n\\u00e9"],"b":{}}', '[0,1.25E-2,"\\"\\\\\\/\\b\\f\\r\\t",[]]', '\r\n{\n "k" : "v" ,\r "n":\t-0}\n', '"\ud83d\ude00 abcdefghijklmnopqrstuvwxyz"'];
const subs = ['', ' ', '\n', '\r', 'x', '"', '\\', ',', ':', ']', '}', '-', '.', 'e', '0', 'u', '\u0001', '\ud800', 't'];
const fuzz = [];
for (const s of seeds) for (let i = 0; i <= s.length; i++) for (const r of subs) fuzz.push(s.slice(0, i) + r + s.slice(i + 1));
// deterministic sample: every 7th fuzz row
const pick = [...new Set([...hand, ...fuzz.filter((_, k) => k % 7 === 0)])];
const { cats, rows } = check(pick);
if (Object.keys(cats).length) { console.log("MISMATCH", cats); process.exit(1); }
const jlit = s => '"' + [...Array(s.length).keys()].map(i => { const c = s.charCodeAt(i);
  if (c === 34) return '\\"'; if (c === 92) return '\\\\'; if (c >= 0x20 && c < 0x7f) return s[i];
  return "\\u" + c.toString(16).padStart(4, "0"); }).join("") + '"';
// note: Java processes \\u escapes before lexing, so \\u000a / \\u000d / \\u0022 / \\u005c inside a literal break the source
const jlit2 = s => '"' + [...Array(s.length).keys()].map(i => { const c = s.charCodeAt(i);
  if (c === 34) return '\\"'; if (c === 92) return '\\\\'; if (c === 10) return '\\n'; if (c === 13) return '\\r'; if (c === 9) return '\\t'; if (c >= 0x20 && c < 0x7f) return s[i];
  return "\\u" + c.toString(16).padStart(4, "0"); }).join("") + '"';
const lines = rows.map(([s, e]) => `        {${jlit2(s)}, ${jlit2(e)}},`);
console.log(rows.length, "rows");
fs.writeFileSync("rows.java.txt", lines.join("\n") + "\n");

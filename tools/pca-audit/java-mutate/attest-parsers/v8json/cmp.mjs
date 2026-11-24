import { v8JsonError } from "./port.mjs";
const oracle = s => { try { JSON.parse(s); return ""; } catch (e) { return e.message.replace(/[\ud800-\udfff]/g, m => m); } };
const fix = s => { let o=""; for (let i=0;i<s.length;i++){const c=s.charCodeAt(i); if(c>=0xd800&&c<=0xdbff&&i+1<s.length&&s.charCodeAt(i+1)>=0xdc00&&s.charCodeAt(i+1)<=0xdfff){o+=s[i]+s[++i];} else if(c>=0xd800&&c<=0xdfff) o+="�"; else o+=s[i];} return o; };
export function check(set) { const cats = {}; const rows = []; for (const s of set) { const a = v8JsonError(s), b = fix(oracle(s)); if (a !== b) { const k = b.replace(/\d+/g,"N").slice(0,40)+" <- "+a.slice(0,25); (cats[k] ??= []).push(s); } else rows.push([s,a]); } return {cats, rows}; }

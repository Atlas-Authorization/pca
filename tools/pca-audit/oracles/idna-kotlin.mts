// Oracle: WHATWG domain-to-ASCII (UTS 46 as Node's URL implements it) over hostile and ordinary hosts. Used by the JVM lanes to check an ICU4J based host mapper.
// PORTING: domainToAscii(word) -> the host of ws://<word> as url.domainToASCII returns it ('' when it cannot be encoded);
//          urlHost(word)       -> new URL('https://' + word).host, or null when the URL does not parse.
import { domainToASCII } from 'node:url';
import { Oracle, refWrite } from './lib.mjs';

const o = new Oracle('idna-kotlin', 'tools/pca-audit/oracles/idna-kotlin.mts', 'TS-reference oracle for WHATWG domain to ASCII (UTS 46).');
const WORDS = [
  'example.com', 'EXAMPLE.COM', 'münchen.de', 'MÜNCHEN.DE', 'faß.de', 'FASS.de', 'ß', 'ΣΑΣ.gr', 'σας.gr', 'xn--mnchen-3ya.de', 'XN--MNCHEN-3YA.DE', 'xn--', 'xn--a-.de', 'xn--a.com',
  'xn--zca.com', 'xn--ls8h.la', '例え.jp', '例え。jp', '例え．jp', '例え｡jp', 'a­b.com', 'a​b.com', 'a‍b.com', 'a‌b.com', 'ab⁠cd.com', '😀.com', 'a b.com', 'a_b.com',
  'a-.com', '-a.com', 'ab--c.com', 'a..b', 'a.b.', '.a', '', 'İ.com', 'ı.com', '́a.com', 'á.com', 'ａｂｃ.com', 'ＡＢＣ.ＣＯＭ', '١٢٣.com', 'א.com', 'aא.com', 'א1.com', 'אa.com',
  'a%C3%BCb.com', 'a%41b.com', '%41.com', 'a%zzb.com', 'ǆ.com', '͸.com', '\ud800.com', 'ᡀ.com', '가.kr', '한국.kr', 'bücher.example', 'ΒΟΛΟΣ.gr', 'ab·cd.com', 'l·l.com', 'a͵b.com', 'a׳b.com',
  '⒈.com', 'é.com', 'é.com', 'a/b', 'a?b', 'a#b', 'a:b', 'a@b', 'a[b', 'a\\b', 'a|b', 'a^b', 'a<b', 'a>b', 'a"b', 'a`b', 'a{b}', 'a\tb', '　a.com', 'a.com　', 'ab­', '­',
  '1.2.3.4', '0x7f.1', 'a.1', 'a.0x', 'a.09', 'ℌ.com', '㎒.com', 'ﬁ.com', '℃.com', 'a.xn--zca', 'a.xn--0ca', 'xn--a--', 'xn----', 'xn--ab-', 'xn--abcdefghijklmnopqrstuvwxyz0123456789',
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com',
];
let n = 0;
for (const w of WORDS) {
  await o.run('domainToAscii', `${n++}`, (s: string) => domainToASCII(s), [w]);
  await o.run('urlHost', `${n++}`, (s: string) => { try { return new URL('https://' + s).host; } catch { return null; } }, [w]);
}
refWrite(o, 'idna-kotlin');

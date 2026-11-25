// Oracle: the WHATWG host parser's domain-to-ASCII (UTS 46) as Node reads it: new URL(url).host / .hostname, node:url domainToASCII.
// PORTING: urlHost(url) -> WhatwgUrl.parse(url).host (null = the reference threw) and Dpop.urlHost(url); both are compared with the reference's .hostname (host plus
//   non-default port for Dpop: cases use no port). domainToAscii(word) -> Ciba.asciiForm's host step, observable as asciiForm(word) when the word is non-ASCII.
import { domainToASCII } from 'node:url';
import { Oracle, refWrite } from './lib.mjs';

const o = new Oracle('idna', 'tools/pca-audit/oracles/idna-java.mts', 'TS-reference oracle for the URL standard domain-to-ASCII.');
const HOSTS = [
  'example.com', 'EXAMPLE.COM', 'münchen.de', 'MÜNCHEN.DE', 'faß.de', 'FAẞ.de', 'ς.com', 'Σ.com', 'βόλος.com', 'ශ්‍රී.com', 'نامه‌ای.com', 'a‍b.com', 'a‌b.com',
  '例え.jp', '例え。jp', '例え．jp', '例え｡jp', 'ＡＢＣ.com', 'ｅｘａｍｐｌｅ.com', '①.com', 'a­b.com', 'a​b.com', 'a⁠b.com', 'a﻿b.com', 'a️b.com',
  'xn--mnchen-3ya.de', 'XN--MNCHEN-3YA.DE', 'xn--', 'xn--a.com', 'xn--zz.com', 'xn--mnchen-3yb.de', 'xn--0.pt', 'xn--e-.com', 'xn--ab-.com', 'xn--ls8h.la', 'xn--n3h.com', 'xn--a-ecp.ru',
  '😀.com', '☃.net', 'a.b.c.d', 'a..b', '.a', 'a.', '..', '-a.com', 'a-.com', 'ab--c.com', 'xx--yy.com', 'a_b.com', 'a b.com', 'a%20b.com', 'a%41.com', 'm%C3%BCnchen.de', 'm%c3%bcnchen.de', 'm%zz.de',
  'a^b', 'a|b', 'a<b', 'a>b', 'a\u0080b', 'ü^b', 'ü|b', 'ü<b', 'ü>b', 'ü%41', 'ü\u0000',
  'ab́.com', '́ab.com', 'à.com', 'אב.com', 'aא.com', 'אa.com', 'אב-1.com', 'اب.com', 'ابa.com', '١٢.com', 'ا١1.com',
  'ǅ.com', 'ǆ.com', 'ẞ.com', 'İ.com', 'ı.com', 'ſ.com', 'ǰ.com', '℀.com', '㎒.com', '﷼.com', 'ﬁ.com', 'ａ.com', 'Ａ.com',
  '\u{10400}.com', '\u{1F600}x.com', '\u{E0001}.com', '\u{FFFF}.com', '\u{10FFFF}.com', '\ud800.com', '͸.com', '\u{2FA1D}.com', '\u{1E900}.com',
  'a'.repeat(63) + '.com', 'a'.repeat(64) + '.com', 'é'.repeat(63) + '.com', 'é'.repeat(40) + '.com', ('a'.repeat(60) + '.').repeat(5) + 'com', 'ü.ü.ü',
  'ab.ٴ.com', '.ü', 'ü.', 'x.。', 'ᄀ.com', '가.com', '가.com', '가.com', 'กำ.com', 'क्‍.com', 'क्‌.com', 'ك‌.com',
];
const urlOf = (h: string) => 'https://' + h + '/p';
const hostOf = (u: string) => new URL(u).host;
for (const [i, h] of HOSTS.entries()) await o.run('urlHost', `${i} ${JSON.stringify(h).slice(0, 50)}`, hostOf, [urlOf(h)]);
const PAYEES = ['Zoë', 'münchen', 'MÜNCHEN', 'faß', 'a ü b', '例え', '例え。jp', 'ａｂｃ', 'a­b', '☃', '😀', 'xn--a', 'ǘ', 'ǅ', 'ς', '١٢٣', 'a‍b', 'ß.de', 'ü/x', 'ü#x', 'ü?x', 'ü\\x', 'ü%41', 'ü%zz', 'a%c3%bcb', '1.2.3.ü', 'ü.1', 'ü.0x1'];
for (const [i, p] of PAYEES.entries()) await o.run('domainToAscii', `${i} ${JSON.stringify(p).slice(0, 40)}`, domainToASCII, [p]);
refWrite(o, 'idna');

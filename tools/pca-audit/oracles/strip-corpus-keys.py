#!/usr/bin/env python3
"""Rewrite oracle corpora in place without private key material. Every secret member (JWK `d`, `seed`, `secret`, `secretKey`, `regSeed`,
`tsSeed`) whose value is the key the oracles derive from a label (sha256("atlas-pca-conformance/" + label), base64url; the ES256 form
clears the top bit of byte 0) becomes {"$seed": label} ({"$seed": label, "es256": true} for ES256); the replay harnesses derive the
value from the label when they load a corpus. Labels are the string literals of every generator in this directory.
Usage: strip-corpus-keys.py <corpus.json.gz>...      Exit 1 if a secret member of a listed corpus is not label-derived."""
import base64, glob, gzip, hashlib, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
KEYS = "d|seed|secret|secretKey|regSeed|tsSeed|oldSeed|newSeed|ancestorSeed|issuerSecret|agentLeafSecret|k1|k2|receiptSeed|sk|signerSecret|principalSecret|holderSecret|principalSeed|holder0Seed|holderSeed|issuer_seed|holder_seed|authoritySeed|edSecret|recvSecret"

def digest(label):
    return hashlib.sha256(("atlas-pca-conformance/" + label).encode()).digest()

def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

src = ""
for f in glob.glob(HERE + "/*.mts") + glob.glob(HERE + "/*.mjs") + glob.glob(HERE + "/../oracles-base/*.mjs") + glob.glob(HERE + "/../oracles-base/*.mts"):
    src += open(f).read() + "\n"
labels = set(re.findall(r"'([^'\n]{1,60})'", src)) | set(re.findall(r'"([^"\n]{1,60})"', src)) | set(re.findall(r"`([^`\n$]{1,60})`", src))
# labels a generator really derived (PCA_SEED_LABELS=<dir of files written with PCA_SEED_LOG>), if given
if os.environ.get("PCA_SEED_LABELS"):
    for f in glob.glob(os.environ["PCA_SEED_LABELS"] + "/*.txt"):
        for line in open(f):
            try: labels.add(__import__("json").loads(line))
            except ValueError: pass
# `${...}` template labels (seed(`prefix${x}`)): the prefix joined with every short literal and every small integer
for pre in {p for p in re.findall(r"`([^`$\n]{1,40})\$\{", src) if re.match(r"(?:ref|base)[a-z0-9-]*/", p)} | set(re.findall(r"seed\('([a-z0-9-]+/)'\s*\+", src)):
    labels |= {pre + x for x in labels if len(x) <= 10 and " " not in x} | {pre + str(i) for i in range(200)}
table = {}
for l in labels:
    d = digest(l)
    table[b64u(d)] = '{"$seed":%s}' % __import__("json").dumps(l, ensure_ascii=False)
    table.setdefault(b64u(bytes([d[0] & 0x7F]) + d[1:]), '{"$seed":%s,"es256":true}' % __import__("json").dumps(l, ensure_ascii=False))

ANY = "--any" in sys.argv   # also positional string values (a corpus whose args are bare seeds: connect)
# EC P-384 / P-521 scalars and Ed448 seeds longer than one digest: the idkit key kit joins the digests of L, L/2, L/3 (L/2 for Ed448,
# cut to 57 bytes) and, for EC, clears the top bits so the scalar is below the group order (0x7f for P-384, 0x01 for P-521).
long_table = {}
for l in labels:
    dd = [digest(l), digest(l + "/2"), digest(l + "/3")]
    cat = b"".join(dd)
    e384 = bytearray(cat[:48]); e384[0] &= 0x7F
    e521 = bytearray(cat[:66]); e521[0] &= 0x01
    ed448 = dd[0] + dd[1][:25]
    long_table[b64u(bytes(e384))] = '{"$seed":%s,"ec":"P-384"}' % __import__("json").dumps(l, ensure_ascii=False)
    long_table[b64u(bytes(e521))] = '{"$seed":%s,"ec":"P-521"}' % __import__("json").dumps(l, ensure_ascii=False)
    long_table[b64u(ed448)] = '{"$seed":%s,"ed448":true}' % __import__("json").dumps(l, ensure_ascii=False)

for path in [a for a in sys.argv[1:] if a != "--any"]:
    text = gzip.open(path).read().decode()
    n = 0
    def sub(m):
        global n
        v = table.get(m.group(2))
        if v is None:
            return m.group(0)
        n += 1
        return '"%s":%s' % (m.group(1), v)
    text = re.sub(r'"(%s)":"([A-Za-z0-9_-]{43})"' % KEYS, sub, text)
    text = re.sub(r'"d":"([A-Za-z0-9_-]{64}|[A-Za-z0-9_-]{76}|[A-Za-z0-9_-]{88})"', lambda x: '"d":' + long_table.get(x.group(1), '"' + x.group(1) + '"'), text)
    if ANY:
        text = re.sub(r'("\$bytes":)"([A-Za-z0-9_-]{43})"', lambda x: x.group(1) + table.get(x.group(2), '"' + x.group(2) + '"'), text)
        text = re.sub(r'(?<![:\w])"([A-Za-z0-9_-]{43})"(?!\s*:)', lambda x: table.get(x.group(1), x.group(0)), text)
    def arr(m):
        return m.group(1) + re.sub(r'"([A-Za-z0-9_-]{43})"', lambda x: table.get(x.group(1), x.group(0)), m.group(2)) + "]"
    text = re.sub(r'("holderSeeds":\[)([^\]]*)\]', arr, text)
    with open(path, "wb") as f:
        f.write(gzip.compress(text.encode(), 9, mtime=0))
    print(path, "replaced", n)

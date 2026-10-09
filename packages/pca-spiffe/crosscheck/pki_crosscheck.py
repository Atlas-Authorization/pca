"""Independent chain verdicts for the generated test PKI (fixtures/generated/) and the go-spiffe chain.
Run: PATH=/opt/homebrew/opt/openssl/bin:$PATH uv run --with cryptography python crosscheck/pki_crosscheck.py
Writes fixtures/pki-crosscheck.json. Verdicts come from the OpenSSL command line (`openssl verify`) and from the
Python `cryptography` x509 verifier; the script fails if the two disagree."""
import datetime, json, pathlib, re, subprocess, tempfile
import cryptography
from cryptography import x509
from cryptography.x509.verification import PolicyBuilder, Store

fx = pathlib.Path(__file__).parent.parent / 'fixtures'
gen = fx / 'generated'
NOW = datetime.datetime(2027, 6, 1, tzinfo=datetime.timezone.utc)

def load(path): return x509.load_pem_x509_certificate(pathlib.Path(path).read_bytes())

def openssl_ok(leaf, untrusted, roots, at):
    cmd = ['openssl', 'verify', '-attime', str(int(at.timestamp())), '-no-CApath', '-no-CAstore']
    for r in roots: cmd += ['-CAfile', str(r)]
    for u in untrusted: cmd += ['-untrusted', str(u)]
    cmd.append(str(leaf))
    return subprocess.run(cmd, capture_output=True, text=True).returncode == 0

def crypto_ok(leaf, untrusted, roots, at):
    try:
        v = PolicyBuilder().store(Store([load(r) for r in roots])).time(at).build_client_verifier()
        v.verify(load(leaf), [load(u) for u in untrusted])
        return True
    except Exception:
        return False

cases = []
def case(name, leaf, untrusted, roots, at=NOW):
    a = openssl_ok(leaf, untrusted, roots, at)
    b = crypto_ok(leaf, untrusted, roots, at)
    cases.append({'name': name, 'leaf': pathlib.Path(leaf).name, 'untrusted': [pathlib.Path(u).name for u in untrusted], 'roots': [pathlib.Path(r).name for r in roots],
                  'at': at.isoformat(), 'openssl': a, 'cryptography': b})

G = lambda n: gen / f'{n}.pem'
case('leaf via inter0 to root', G('leaf'), [G('inter0')], [G('root')])
case('leaf signed directly by root', G('leaf-direct'), [], [G('root')])
case('leaf under inter-under-inter0 (pathlen 0 exceeded)', G('leaf-via-chain'), [G('inter-under-inter0'), G('inter0')], [G('root')])
case('leaf under inter without keyCertSign', G('leaf-noks'), [G('inter-noks')], [G('root')])
case('leaf under inter that is not a CA', G('leaf-notca'), [G('inter-notca')], [G('root')])
case('expired leaf', G('leaf-expired'), [G('inter0')], [G('root')])
case('chain to an unrelated root', G('leaf'), [G('inter0')], [G('other-root')])
case('missing intermediate', G('leaf'), [], [G('root')])
case('before validity starts', G('leaf'), [G('inter0')], [G('root')], datetime.datetime(2026, 6, 1, tzinfo=datetime.timezone.utc))
for c in cases:
    assert c['openssl'] == c['cryptography'], ('verifiers disagree', c)
(fx / 'pki-crosscheck.json').write_text(json.dumps({
    'generator': f"openssl verify ({subprocess.run(['openssl','version'],capture_output=True,text=True).stdout.strip()}) + python cryptography {cryptography.__version__}, crosscheck/pki_crosscheck.py",
    'cases': cases}, indent=1))
print('verdicts agree on', len(cases), 'cases;', sum(1 for c in cases if c['openssl']), 'accepted')
for c in cases: print(' ', c['openssl'], c['name'])

"""RFC 8705 x5t#S256 cross-check: certificates are built and hashed by `cryptography` and OpenSSL (not by pca-dpop), then
pca-dpop must reproduce the same thumbprint and accept/refuse the binding.
Run (package dir, openssl on PATH):
  uv run --with cryptography python crosscheck/mtls_crosscheck.py "$OUT"   # $OUT: empty scratch directory"""
import base64, datetime, hashlib, pathlib, subprocess, sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)

def make(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=36500))
            .sign(key, hashes.SHA256()))
    return cert

a, b = make('mtls-crosscheck-a'), make('mtls-crosscheck-b')
(out / 'a.pem').write_bytes(a.public_bytes(serialization.Encoding.PEM))
(out / 'b.pem').write_bytes(b.public_bytes(serialization.Encoding.PEM))
der = a.public_bytes(serialization.Encoding.DER)
want = base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b'=').decode()
assert want == base64.urlsafe_b64encode(a.fingerprint(hashes.SHA256())).rstrip(b'=').decode()
# third opinion: OpenSSL's own fingerprint of the same certificate
fp = subprocess.run(['openssl', 'x509', '-in', str(out / 'a.pem'), '-noout', '-fingerprint', '-sha256'], capture_output=True, text=True, check=True).stdout
hexfp = fp.strip().split('=', 1)[1].replace(':', '')
assert bytes.fromhex(hexfp) == hashlib.sha256(der).digest(), 'openssl disagrees with cryptography'
(out / 'x5t.txt').write_text(want)
print('independent x5t#S256 computed')
subprocess.run(['pnpm', 'dlx', 'tsx', 'crosscheck/mtls-check.mts', str(out / 'a.pem'), want, str(out / 'b.pem')], check=True)

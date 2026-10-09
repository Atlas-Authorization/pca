#!/bin/sh
# Generates the test PKI in fixtures/generated/ with OpenSSL (version recorded in VERSIONS.txt).
# These certificates are produced by this script; they are NOT official SPIFFE test data.
set -eu
OUT="$(cd "$(dirname "$0")" && pwd)/generated"
rm -rf "$OUT"; mkdir -p "$OUT"; cd "$OUT"
openssl version > VERSIONS.txt
NB="20261001000000Z"; NA="20361001000000Z"
withids() { cp "$1" "$1.x"; printf 'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' >> "$1.x"; }
key() { openssl ecparam -name prime256v1 -genkey -noout -out "$1.key" 2>/dev/null; }
ca() { # name extfile [issuer]
  key "$1"; withids "$2"
  openssl req -new -key "$1.key" -subj "/O=Test/CN=$1" -out "$1.csr" 2>/dev/null
  if [ $# -ge 3 ]; then
    openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -CAcreateserial -not_before "$NB" -not_after "$NA" -extfile "$2.x" -out "$1.pem" 2>/dev/null
  else
    openssl x509 -req -in "$1.csr" -signkey "$1.key" -not_before "$NB" -not_after "$NA" -extfile "$2.x" -out "$1.pem" 2>/dev/null
  fi
}
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > ext-root
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' > ext-inter0
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > ext-inter
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature\n' > ext-inter-noks
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n' > ext-notca
leafext() { # file san [extra]
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=%s\n%s' "$2" "${3:-}" > "$1"
}
ca root ext-root
ca other-root ext-root
ca inter0 ext-inter0 root
ca inter ext-inter root
ca inter-under-inter0 ext-inter inter0
ca inter-noks ext-inter-noks root
ca inter-notca ext-notca root
leaf() { # name extfile signer [not_before not_after]
  key "$1"; withids "$2"
  openssl req -new -key "$1.key" -subj "/O=Test/CN=$1" -out "$1.csr" 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -CAcreateserial -not_before "${4:-$NB}" -not_after "${5:-$NA}" -extfile "$2.x" -out "$1.pem" 2>/dev/null
}
leafext ext-leaf 'URI:spiffe://example.org/workload/db'
leaf leaf ext-leaf inter0
leaf leaf-direct ext-leaf root
leaf leaf-via-chain ext-leaf inter-under-inter0
leaf leaf-noks ext-leaf inter-noks
leaf leaf-notca ext-leaf inter-notca
leaf leaf-expired ext-leaf inter0 20200101000000Z 20210101000000Z
leafext ext-two 'URI:spiffe://example.org/a,URI:spiffe://example.org/b'; leaf leaf-two-uri ext-two inter0
leafext ext-dns 'DNS:example.org'; leaf leaf-dns-only ext-dns inter0
leafext ext-root-path 'URI:spiffe://example.org'; leaf leaf-root-path ext-root-path inter0
leafext ext-other 'URI:spiffe://other.org/x'; leaf leaf-other-td ext-other inter0
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectAltName=URI:spiffe://example.org/workload/db\n1.2.3.4=critical,ASN1:UTF8String:x\n' > ext-crit
leaf leaf-unknown-critical ext-crit inter0
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature\nsubjectAltName=URI:spiffe://example.org/workload/db\n' > ext-isca; leaf leaf-is-ca ext-isca inter0
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyCertSign\nsubjectAltName=URI:spiffe://example.org/workload/db\n' > ext-cs; leaf leaf-cert-sign ext-cs inter0
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,cRLSign\nsubjectAltName=URI:spiffe://example.org/workload/db\n' > ext-crl; leaf leaf-crl-sign ext-crl inter0
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,keyEncipherment\nsubjectAltName=URI:spiffe://example.org/workload/db\n' > ext-nods; leaf leaf-no-digital-signature ext-nods inter0
printf 'basicConstraints=critical,CA:FALSE\nsubjectAltName=URI:spiffe://example.org/workload/db\n' > ext-noku; leaf leaf-no-key-usage ext-noku inter0
rm -f ext-* ext-*.x *.csr *.srl *.key
ls

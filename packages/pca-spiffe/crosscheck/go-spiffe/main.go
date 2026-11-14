// Cross-check of @atlasauth/pca-spiffe against go-spiffe v2 (the reference Go implementation).
//
// It verifies, with go-spiffe, the SAME inputs the TypeScript package is tested on:
//   - every SPIFFE ID string in fixtures/pyspiffe.json,
//   - every chain in fixtures/pki-crosscheck.json plus each deliberately wrong leaf of fixtures/generated,
//   - JWT-SVIDs it signs itself now (ES256, RS256, PS256 and the tamper variants of fixtures/pyspiffe.json).
// and writes go-spiffe's accept/reject verdicts to --out. The vitest file src/go-spiffe.crosscheck.test.ts reads
// that file (env PCA_GO_SPIFFE_VERDICTS) and fails when the TypeScript verdict differs.
//
//	cd crosscheck/go-spiffe && go mod tidy && go run . --fixtures ../../fixtures --out /tmp/go-spiffe-verdicts.json
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

type idCase struct {
	ID      string `json:"id"`
	GoValid bool   `json:"go_valid"`
}

type x509Case struct {
	Name      string   `json:"name"`
	Leaf      string   `json:"leaf"`
	Untrusted []string `json:"untrusted"`
	Roots     []string `json:"roots"`
	At        string   `json:"at"`
	GoValid   bool     `json:"go_valid"`
	GoError   string   `json:"go_error,omitempty"`
}

type jwtCase struct {
	Name     string            `json:"name"`
	Token    string            `json:"token"`
	Audience string            `json:"audience"`
	Alg      string            `json:"alg"`
	JWK      map[string]string `json:"jwk"`
	GoValid  bool              `json:"go_valid"`
	GoError  string            `json:"go_error,omitempty"`
}

type output struct {
	Generator string     `json:"generator"`
	IDs       []idCase   `json:"ids"`
	X509      []x509Case `json:"x509"`
	JWT       []jwtCase  `json:"jwt"`
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func readCerts(path string) []*x509.Certificate {
	raw, err := os.ReadFile(path)
	must(err)
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		must(err)
		out = append(out, c)
	}
	return out
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func signJWT(alg string, header, claims map[string]any, key crypto.Signer) string {
	hb, err := json.Marshal(header)
	must(err)
	cb, err := json.Marshal(claims)
	must(err)
	signing := b64(hb) + "." + b64(cb)
	digest := sha256.Sum256([]byte(signing))
	var sig []byte
	switch alg {
	case "ES256":
		k := key.(*ecdsa.PrivateKey)
		r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
		must(err)
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	case "RS256":
		sig, err = rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, digest[:])
		must(err)
	case "PS256":
		sig, err = rsa.SignPSS(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		must(err)
	default:
		must(fmt.Errorf("unsupported alg %s", alg))
	}
	return signing + "." + b64(sig)
}

func jwkEC(k *ecdsa.PrivateKey) map[string]string {
	x := make([]byte, 32)
	y := make([]byte, 32)
	k.PublicKey.X.FillBytes(x)
	k.PublicKey.Y.FillBytes(y)
	return map[string]string{"kty": "EC", "crv": "P-256", "x": b64(x), "y": b64(y), "kid": "k1"}
}

func jwkRSA(k *rsa.PrivateKey) map[string]string {
	e := []byte{0x01, 0x00, 0x01}
	return map[string]string{"kty": "RSA", "n": b64(k.PublicKey.N.Bytes()), "e": b64(e), "kid": "k1"}
}

func main() {
	fixtures := flag.String("fixtures", "../../fixtures", "fixtures directory of @atlasauth/pca-spiffe")
	outPath := flag.String("out", "go-spiffe-verdicts.json", "where to write the verdicts")
	flag.Parse()

	out := output{Generator: "go-spiffe v2 (see go.mod), crosscheck/go-spiffe/main.go"}

	// ---- SPIFFE IDs ----
	var py struct {
		IDs []struct {
			ID string `json:"id"`
		} `json:"ids"`
	}
	raw, err := os.ReadFile(filepath.Join(*fixtures, "pyspiffe.json"))
	must(err)
	must(json.Unmarshal(raw, &py))
	for _, c := range py.IDs {
		_, err := spiffeid.FromString(c.ID)
		out.IDs = append(out.IDs, idCase{ID: c.ID, GoValid: err == nil})
	}

	// ---- X.509-SVID chains ----
	td, err := spiffeid.TrustDomainFromString("example.org")
	must(err)
	var pki struct {
		Cases []x509Case `json:"cases"`
	}
	raw, err = os.ReadFile(filepath.Join(*fixtures, "pki-crosscheck.json"))
	must(err)
	must(json.Unmarshal(raw, &pki))
	cases := pki.Cases
	for _, leaf := range []string{
		"leaf-is-ca", "leaf-cert-sign", "leaf-crl-sign", "leaf-no-digital-signature", "leaf-no-key-usage",
		"leaf-root-path", "leaf-two-uri", "leaf-dns-only", "leaf-unknown-critical", "leaf-other-td",
	} {
		cases = append(cases, x509Case{Name: "leaf violation: " + leaf, Leaf: leaf + ".pem", Untrusted: []string{"inter0.pem"}, Roots: []string{"root.pem"}, At: "2027-06-01T00:00:00+00:00"})
	}
	gen := filepath.Join(*fixtures, "generated")
	for _, c := range cases {
		chain := readCerts(filepath.Join(gen, c.Leaf))
		for _, u := range c.Untrusted {
			chain = append(chain, readCerts(filepath.Join(gen, u))...)
		}
		var roots []*x509.Certificate
		for _, r := range c.Roots {
			roots = append(roots, readCerts(filepath.Join(gen, r))...)
		}
		at, err := time.Parse(time.RFC3339, c.At)
		must(err)
		_, _, verr := x509svid.Verify(chain, x509bundle.FromX509Authorities(td, roots), x509svid.WithTime(at))
		res := x509Case{Name: c.Name, Leaf: c.Leaf, Untrusted: c.Untrusted, Roots: c.Roots, At: c.At, GoValid: verr == nil}
		if verr != nil {
			res.GoError = verr.Error()
		}
		out.X509 = append(out.X509, res)
	}

	// ---- JWT-SVIDs, signed now so they are inside their validity window ----
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	now := time.Now().Unix()
	sub := "spiffe://example.org/workload/db"
	base := func() map[string]any {
		return map[string]any{"sub": sub, "aud": []string{"rs"}, "exp": now + 3600, "iat": now}
	}
	with := func(f func(m map[string]any)) map[string]any { m := base(); f(m); return m }
	hdr := func(typ string) map[string]any { return map[string]any{"kid": "k1", "typ": typ} }
	type spec struct {
		name   string
		alg    string
		claims map[string]any
		signer crypto.Signer
		typ    string
		jwk    map[string]string
		aud    string
	}
	ecJWK, rsaJWK := jwkEC(ecKey), jwkRSA(rsaKey)
	specs := []spec{
		{"valid ES256", "ES256", base(), ecKey, "JWT", ecJWK, "rs"},
		{"valid RS256", "RS256", base(), rsaKey, "JWT", rsaJWK, "rs"},
		{"valid PS256", "PS256", base(), rsaKey, "JWT", rsaJWK, "rs"},
		{"wrong audience", "ES256", with(func(m map[string]any) { m["aud"] = []string{"other"} }), ecKey, "JWT", ecJWK, "rs"},
		{"expired", "ES256", with(func(m map[string]any) { m["exp"] = now - 3600 }), ecKey, "JWT", ecJWK, "rs"},
		{"missing exp", "ES256", with(func(m map[string]any) { delete(m, "exp") }), ecKey, "JWT", ecJWK, "rs"},
		{"missing aud", "ES256", with(func(m map[string]any) { delete(m, "aud") }), ecKey, "JWT", ecJWK, "rs"},
		{"sub is not a SPIFFE ID", "ES256", with(func(m map[string]any) { m["sub"] = "not-a-spiffe-id" }), ecKey, "JWT", ecJWK, "rs"},
		{"sub with trailing slash", "ES256", with(func(m map[string]any) { m["sub"] = "spiffe://example.org/a/" }), ecKey, "JWT", ecJWK, "rs"},
		{"signed by another key", "ES256", base(), otherKey, "JWT", ecJWK, "rs"},
		{"typ is not JWT", "ES256", base(), ecKey, "at+jwt", ecJWK, "rs"},
		{"trust domain of another bundle", "ES256", with(func(m map[string]any) { m["sub"] = "spiffe://evil.example/x" }), ecKey, "JWT", ecJWK, "rs"},
	}
	for _, s := range specs {
		header := hdr(s.typ)
		header["alg"] = s.alg
		token := signJWT(s.alg, header, s.claims, s.signer)
		var pub crypto.PublicKey
		if s.alg == "ES256" {
			pub = &ecKey.PublicKey
		} else {
			pub = &rsaKey.PublicKey
		}
		bundle := jwtbundle.FromJWTAuthorities(td, map[string]crypto.PublicKey{"k1": pub})
		_, verr := jwtsvid.ParseAndValidate(token, bundle, []string{s.aud})
		res := jwtCase{Name: s.name, Token: token, Audience: s.aud, Alg: s.alg, JWK: s.jwk, GoValid: verr == nil}
		if verr != nil {
			res.GoError = verr.Error()
		}
		out.JWT = append(out.JWT, res)
	}

	// Harness sanity: if the known-good inputs are not accepted, the harness (not the package) is broken.
	for _, c := range out.X509 {
		if c.Name == "leaf via inter0 to root" && !c.GoValid {
			must(fmt.Errorf("harness broken: go-spiffe rejects the good chain: %s", c.GoError))
		}
	}
	for _, c := range out.JWT {
		if (c.Name == "valid ES256" || c.Name == "valid RS256" || c.Name == "valid PS256") && !c.GoValid {
			must(fmt.Errorf("harness broken: go-spiffe rejects %s: %s", c.Name, c.GoError))
		}
	}

	enc, err := json.MarshalIndent(out, "", " ")
	must(err)
	must(os.WriteFile(*outPath, enc, 0o600))
	fmt.Printf("go-spiffe verdicts: %d ids, %d x509, %d jwt -> %s\n", len(out.IDs), len(out.X509), len(out.JWT), *outPath)
}

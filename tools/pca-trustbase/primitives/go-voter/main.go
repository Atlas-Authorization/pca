// Go standard-library voter (crypto/ed25519, crypto/sha256|sha512, crypto/hmac). Same line protocol as rust-voter.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"strings"
)

func h(s string) []byte { b, _ := hex.DecodeString(s); return b }

func newHash(a string) func() hash.Hash {
	switch a {
	case "sha256":
		return sha256.New
	case "sha384":
		return sha512.New384
	case "sha512":
		return sha512.New
	}
	return nil
}

func handle(f []string) (res string) {
	defer func() {
		if r := recover(); r != nil {
			res = "ERR panic"
		}
	}()
	switch f[0] {
	case "FLUSH":
		return "FLUSHED"
	case "H":
		nh := newHash(f[1])
		if nh == nil {
			return "ERR algo"
		}
		x := nh()
		x.Write(h(f[2]))
		return hex.EncodeToString(x.Sum(nil))
	case "M":
		nh := newHash(f[1])
		if nh == nil {
			return "ERR algo"
		}
		x := hmac.New(nh, h(f[2]))
		x.Write(h(f[3]))
		return hex.EncodeToString(x.Sum(nil))
	case "EP":
		return hex.EncodeToString(ed25519.NewKeyFromSeed(h(f[1])).Public().(ed25519.PublicKey))
	case "ES":
		return hex.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(h(f[1])), h(f[2])))
	case "EV":
		pk, sg := h(f[2]), h(f[4])
		if len(pk) != 32 || len(sg) != 64 {
			return "0"
		}
		if ed25519.Verify(ed25519.PublicKey(pk), h(f[3]), sg) {
			return "1"
		}
		return "0"
	}
	return "ERR op"
}

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer out.Flush()
	for {
		line, err := in.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimRight(line, "\n")
			fmt.Fprintln(out, handle(strings.Split(line, "\t")))
			if strings.HasPrefix(line, "FLUSH") {
				out.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	pca "github.com/Atlas-Authorization/pca-go"
)

type in struct {
	ID            string   `json:"id"`
	Kind          string   `json:"kind"`
	Raw           string   `json:"raw"`
	Grant         string   `json:"grant"`
	Now           int64    `json:"now"`
	Aud           string   `json:"aud"`
	AllowedSuites []string `json:"allowed_suites"`
}

// verify: raw = PCActn JSON text (strict profile via the SDK's own ParsePCActn; failure == wire failure), grant = lenient parse.
// canon: StrictParse + Canonicalize (strict canonical form) + HashCanonical of any JSON text.
func one(c in) (res map[string]any) {
	res = map[string]any{"id": c.ID}
	defer func() {
		if r := recover(); r != nil {
			res = map[string]any{"id": c.ID, "error": fmt.Sprintf("exception:%v", r)}
		}
	}()
	if c.Kind == "chain" {
		// R4-01: raw = JSON text of {chain, expected_root_issuer?, pq_pins?, trusted_root?, allowed_suites?}.
		pv, err := pca.StrictParse(c.Raw) // json.Number-preserving, same parser the SDK uses for chains
		o, _ := pv.(map[string]any)
		if err != nil || o == nil {
			res["error"] = "exception:chain"
			return
		}
		chain, _ := o["chain"].([]any)
		iss, haveIss := o["expected_root_issuer"].(string)
		var allowed []string
		if al, ok := o["allowed_suites"].([]any); ok {
			allowed = []string{}
			for _, a := range al {
				s, _ := a.(string)
				allowed = append(allowed, s)
			}
		}
		var pins map[string]string
		if pm, ok := o["pq_pins"].(map[string]any); ok {
			pins = map[string]string{}
			for k, x := range pm {
				pins[k], _ = x.(string)
			}
		}
		trusted, _ := o["trusted_root"].(map[string]any)
		_, ok := pca.VerifyChainPolicy(chain, iss, haveIss, allowed, pins, trusted)
		res["allow"] = ok
		res["checks"] = map[string]bool{"chain": ok}
		return
	}
	if c.Kind == "verify" {
		gv, err := pca.ParseJSONLenient([]byte(c.Grant))
		gm, _ := gv.(map[string]any)
		if err != nil || gm == nil {
			res["error"] = "exception:grant"
			return
		}
		p, perr := pca.ParsePCActn(c.Raw)
		if perr != nil {
			res["allow"] = false
			res["checks"] = map[string]bool{"wire": false}
			return
		}
		vd, err := pca.VerifyPCActnCorePolicy(p, gm, c.Now, c.Aud, c.AllowedSuites)
		if err != nil {
			res["error"] = "exception:" + err.Error()
			return
		}
		res["allow"] = vd.Allow
		res["checks"] = vd.Checks
		return
	}
	v, err := pca.StrictParse(c.Raw)
	if err != nil {
		res["error"] = "parse"
		return
	}
	s, err := pca.Canonicalize(v)
	if err != nil {
		res["error"] = "parse"
		return
	}
	h, _ := pca.HashCanonical(v)
	res["canon"] = s
	res["hash"] = h
	return
}

func main() {
	f, _ := os.Open(os.Args[1])
	defer f.Close()
	o, _ := os.Create(os.Args[2])
	defer o.Close()
	w := bufio.NewWriter(o)
	defer w.Flush()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<28)
	for sc.Scan() {
		var c in
		json.Unmarshal(sc.Bytes(), &c)
		b, _ := json.Marshal(one(c))
		w.Write(b)
		w.WriteByte('\n')
	}
}

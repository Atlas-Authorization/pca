// PCA Verified driver (Go): a working reference driver over the Atlas Go verifier.
//
// Protocol (docs/pca/reference/pca-verified-protocol.md): `driver <in.jsonl> <out.jsonl>`. One JSON object per input line; exactly one
// JSON object per output line carrying the same `id`. To drive your own implementation keep main() and replace the calls inside one().
// Setup: `go mod init pcadriver && go get github.com/Atlas-Authorization/pca-go@latest && go build -o driver .` (this template is written
// against the 0.5 API of pca-go; if `go build` reports a missing symbol, `go get` the 0.5 release once it is tagged).
// A kind you do not implement: answer {"id": ..., "error": "unsupported"}; the runner then reports that layer as unsupported.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	pca "github.com/Atlas-Authorization/pca-go"
)

type in struct {
	ID            string          `json:"id"`
	Kind          string          `json:"kind"`
	Raw           string          `json:"raw"`
	Grant         string          `json:"grant"`
	Now           int64           `json:"now"`
	Aud           string          `json:"aud"`
	AllowedSuites []string        `json:"allowed_suites"`
	IntentPolicy  json.RawMessage `json:"intent_policy"`
	// IntentPolicyJSON is raw policy JSON text (keeps 950000.0 / 1e6 / -0.0); it wins over IntentPolicy.
	IntentPolicyJSON *string `json:"intent_policy_json"`
	// IntentV2 is the Intent Layer v2 verifier state (context.intent_v2), read with the SDK's lenient loader.
	IntentV2 json.RawMessage `json:"intent_v2"`
}

// verify: raw = PCActn JSON text (optional intent_policy object => VerifyOptions.Intent, optional intent_v2 object =>
// VerifyOptions.IntentV2) (strict profile via the SDK's own ParsePCActn; failure == wire failure), grant = lenient parse.
// canon: StrictParse + Canonicalize (strict canonical form) + HashCanonical of any JSON text.
func one(c in) (res map[string]any) {
	res = map[string]any{"id": c.ID}
	defer func() {
		if r := recover(); r != nil {
			res = map[string]any{"id": c.ID, "error": fmt.Sprintf("exception:%v", r)}
		}
	}()
	if c.Kind == "suites" {
		// Suite-capability manifest (packages/pca/conformance/SUITES.md): the registered suites this build implements.
		res["suites"] = pca.SupportedSuites()
		return
	}
	if c.Kind == "produce" {
		// raw = {op, args, keys, pq_keys?}: one producer vector case; answer {out} or {error}.
		pv, err := pca.ParseJSONLenient([]byte(c.Raw))
		o, _ := pv.(map[string]any)
		if err != nil || o == nil {
			res["error"] = "parse"
			return
		}
		op, _ := o["op"].(string)
		args, _ := o["args"].(map[string]any)
		keys, _ := o["keys"].(map[string]any)
		pqKeys, _ := o["pq_keys"].(map[string]any)
		out, err := pca.ProduceVector(op, args, keys, pqKeys)
		if err != nil {
			res["error"] = err.Error()
		} else {
			res["out"] = out
		}
		return
	}
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
		why, ok := pca.VerifyChainPolicy(chain, iss, haveIss, allowed, pins, trusted)
		res["allow"] = ok
		res["checks"] = map[string]bool{"chain": ok}
		if strings.Contains(why, pca.UnsupportedSuite) {
			res["unsupported_suite"] = why
		}
		return
	}
	if c.Kind == "policy" {
		// Policy layer (packages/pca/conformance/LAYERS.md): raw = JSON text {grant, chain, context}; answers the caveat projection
		// EvaluateAgentCaveats(PolicyCaveats(grant, chain), context, {action}, toolCall) as {allow, failed}: the agent-native
		// evaluator (predicates + tool_schema); the tool call is the signed verb + params (the reference's toolCallOf)
		pv, err := pca.ParseJSONLenient([]byte(c.Raw))
		o, _ := pv.(map[string]any)
		ctx, _ := o["context"].(map[string]any)
		if err != nil || o == nil || ctx == nil {
			res["error"] = "exception:policy"
			return
		}
		act := ctx["action"]
		am, _ := act.(map[string]any)
		verb, _ := am["verb"].(string)
		args, _ := am["params"].(map[string]any)
		if args == nil {
			args = map[string]any{}
		}
		ok, failed := pca.EvaluateAgentCaveats(pca.PolicyCaveats(o["grant"], o["chain"]), ctx, map[string]any{"action": act}, &pca.ToolCall{Tool: verb, Args: args})
		if failed == nil {
			failed = []string{}
		}
		res["allow"] = ok
		res["failed"] = failed
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
		// Intent Layer M2: optional intent_policy object, parsed with the SDK's lenient loader (json.Number numbers).
		opts := pca.VerifyOptions{AllowedSuites: c.AllowedSuites}
		if len(c.IntentPolicy) > 0 {
			ipv, ierr := pca.ParseJSONLenient(c.IntentPolicy)
			if ierr != nil {
				res["error"] = "exception:intent_policy"
				return
			}
			opts.Intent = pca.IntentPolicyFromJSON(ipv)
		}
		if c.IntentPolicyJSON != nil {
			ip, ierr := pca.IntentPolicyFromJSONText(*c.IntentPolicyJSON)
			if ierr != nil {
				res["error"] = "exception:intent_policy_json"
				return
			}
			opts.Intent = ip
		}
		if len(c.IntentV2) > 0 && string(c.IntentV2) != "null" {
			iv, ierr := pca.ParseJSONLenient(c.IntentV2)
			ctx := pca.IntentV2ContextFromJSON(iv)
			if ierr != nil || ctx == nil {
				res["error"] = "exception:intent_v2"
				return
			}
			opts.IntentV2 = ctx
		}
		opts.InsecureSkipPlanRootCheck = true // the reference driver verifies the core only, with no plan configured
		vd, err := pca.VerifyPCActnCoreWith(p, gm, c.Now, c.Aud, opts)
		if err != nil {
			res["error"] = "exception:" + err.Error()
			return
		}
		res["allow"] = vd.Allow
		res["checks"] = vd.Checks
		if strings.Contains(vd.Reason, pca.UnsupportedSuite) {
			res["unsupported_suite"] = vd.Reason
		}
		return
	}
	if c.Kind != "canon" {
		res["error"] = "unsupported" // e.g. `stateful`: this template does not run sequences
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

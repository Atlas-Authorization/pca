using System.Text.Json;
using AtlasPca;

var lines = File.ReadAllLines(args[0]);
using var o = new StreamWriter(args[1]);
foreach (var line in lines)
{
    using var cd = JsonDocument.Parse(line);
    var root = cd.RootElement;
    var id = root.GetProperty("id").GetString()!;
    var kind = root.GetProperty("kind").GetString()!;
    var r = new Dictionary<string, object?> { ["id"] = id };
    if (kind == "suites")
    {
        // Suite-capability manifest (packages/pca/conformance/SUITES.md).
        r["suites"] = Pq.SupportedSuites();
        o.WriteLine(JsonSerializer.Serialize(r));
        continue;
    }
    var raw = root.GetProperty("raw").GetString()!;
    try
    {
        if (kind == "verify")
        {
            var grant = (Dictionary<string, object?>)Pca.ParseJson(root.GetProperty("grant").GetString()!)!;
            List<string>? allowed = null;
            if (root.TryGetProperty("allowed_suites", out var asEl) && asEl.ValueKind == JsonValueKind.Array)
                allowed = asEl.EnumerateArray().Select(z => z.GetString()!).ToList();
            // Intent Layer M2: optional policy {require?, min_fidelity_ppm?, max_residual_risk_ppm?}, either as raw JSON text
            // `intent_policy_json` (parsed with this SDK's parser; wins when both are present) or as a JSON object `intent_policy`
            // (re-parsed from its raw text so the number spelling is kept).
            var intentPolicy = root.TryGetProperty("intent_policy_json", out var ipjEl) && ipjEl.ValueKind == JsonValueKind.String
                ? IntentPolicy.FromJsonText(ipjEl.GetString()!)
                : root.TryGetProperty("intent_policy", out var ipEl) ? IntentPolicy.FromJson(Pca.ParseJson(ipEl.GetRawText())) : null;
            // Intent Layer v2: optional verifier state `intent_v2` (a JSON object, the vectors' context.intent_v2)
            var intentV2 = root.TryGetProperty("intent_v2", out var v2El) ? IntentV2Context.FromJson(Pca.ParseJson(v2El.GetRawText())) : null;
            var g = Pca.VerifyRaw(raw, grant, root.GetProperty("now").GetInt64(), root.GetProperty("aud").GetString()!, allowed, intentPolicy, intentV2);
            r["allow"] = g.Allow;
            r["checks"] = g.Checks.ToDictionary(kv => kv.Key, kv => kv.Value);
            if (g.Reason.Contains(Pq.UnsupportedSuite)) r["unsupported_suite"] = g.Reason;
        }
        else if (kind == "chain")
        {
            // locals are cq*-prefixed: never reuse this driver's file/stream variable names (lines, o, root, ...)
            var cq = (Dictionary<string, object?>)Pca.ParseJson(raw)!;
            var cqChain = (List<object?>)cq["chain"]!;
            cq.TryGetValue("expected_root_issuer", out var cqIssuer);
            IReadOnlyDictionary<string, string>? cqPins = null;
            if (cq.TryGetValue("pq_pins", out var cqPo) && cqPo is Dictionary<string, object?> cqPd)
                cqPins = cqPd.ToDictionary(kv => kv.Key, kv => (kv.Value as string) ?? "");
            var cqTrusted = cq.TryGetValue("trusted_root", out var cqTo) ? cqTo as Dictionary<string, object?> : null;
            List<string>? cqAllowed = cq.TryGetValue("allowed_suites", out var cqAo) && cqAo is List<object?> cqAl ? cqAl.Select(z => (string)z!).ToList() : null;
            var (cqWhy, cqOk) = Pca.VerifyChain(cqChain, cqIssuer, cqIssuer != null, cqAllowed, cqPins, cqTrusted);
            r["allow"] = cqOk;
            r["checks"] = new Dictionary<string, bool> { ["chain"] = cqOk };
            if (cqWhy != null && cqWhy.Contains(Pq.UnsupportedSuite)) r["unsupported_suite"] = cqWhy;
        }
        else if (kind == "policy")
        {
            // Policy layer (packages/pca/conformance/LAYERS.md): raw = JSON text {grant, chain, context}; answers the caveat projection
            // Pca.EvaluateAgentCaveats(PolicyCaveats(grant, chain), context, {action}, toolCall) as {allow, failed}: the agent-native
            // evaluator (predicates + tool_schema); the tool call is the signed verb + params (the reference's toolCallOf)
            var pv = (Dictionary<string, object?>)Pca.ParseJson(raw)!;
            var pctx = pv.GetValueOrDefault("context") as Dictionary<string, object?>;
            var pact = pctx?.GetValueOrDefault("action");
            var pam = pact as Dictionary<string, object?>;
            var pr = Pca.EvaluateAgentCaveats(Caveats.PolicyCaveats(pv.GetValueOrDefault("grant"), pv.GetValueOrDefault("chain")), pctx,
                new Dictionary<string, object?> { ["action"] = pact },
                new ToolCall(pam?.GetValueOrDefault("verb") as string ?? "", pam?.GetValueOrDefault("params") as Dictionary<string, object?> ?? new Dictionary<string, object?>()));
            r["allow"] = pr.Ok;
            r["failed"] = pr.Failed.ToList();
        }
        else if (kind.StartsWith("intent_", StringComparison.Ordinal))
        {
            // Intent Layer v2 primitives: raw = JSON text of the primitive's `input`; result = its `expect` shape.
            var res = IntentPrimitives.Result(kind, Pca.ParseJson(raw));
            if (res == null) r["error"] = "exception:" + kind;
            else r["result"] = JsonDocument.Parse(Pca.Canonicalize(res)).RootElement.Clone();
        }
        else
        {
            string? s = null; object? v = null;
            try { v = Pca.ParseStrict(raw); s = Pca.Canonicalize(v); } catch { r["error"] = "parse"; }
            if (!r.ContainsKey("error")) { r["canon"] = s; r["hash"] = Pca.HashCanonical(v); }
        }
    }
    catch (Exception e) { r = new Dictionary<string, object?> { ["id"] = id, ["error"] = "exception:" + e.GetType().Name }; }
    o.WriteLine(JsonSerializer.Serialize(r));
}

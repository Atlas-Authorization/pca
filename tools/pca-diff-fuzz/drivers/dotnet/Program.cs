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
    var raw = root.GetProperty("raw").GetString()!;
    var r = new Dictionary<string, object?> { ["id"] = id };
    try
    {
        if (kind == "verify")
        {
            var grant = (Dictionary<string, object?>)Pca.ParseJson(root.GetProperty("grant").GetString()!)!;
            List<string>? allowed = null;
            if (root.TryGetProperty("allowed_suites", out var asEl) && asEl.ValueKind == JsonValueKind.Array)
                allowed = asEl.EnumerateArray().Select(z => z.GetString()!).ToList();
            var g = Pca.VerifyRaw(raw, grant, root.GetProperty("now").GetInt64(), root.GetProperty("aud").GetString()!, allowed);
            r["allow"] = g.Allow;
            r["checks"] = g.Checks.ToDictionary(kv => kv.Key, kv => kv.Value);
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

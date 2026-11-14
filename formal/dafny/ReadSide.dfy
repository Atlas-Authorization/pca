// ReadSide.dfy - read-side authorization (track K5): tighten-only masking, label soundness of a redacted read, and the sink rule.
// Standalone; no assume / axiom / extern. Model of packages/pca/src/readside.ts: a mode is an integer RANK (show 0 < last4 < bucket
// < token < hash < drop 5), a response is a sequence of fields (class, dropped?), a read receipt carries a label set.
//   EffectiveNeverWeaker   the mode actually applied is never weaker than the grant's, whatever a caller (or injected text) asks for;
//   EffectiveIsOneOf       it is exactly the grant's mode or the stricter request (nothing else);
//   LabelsSound            every field that is not dropped contributes its class to the receipt's labels (no under-labelling);
//   LabelsExact            and no other class is in the labels;
//   SinkAllowIsSubset      an allowed sink flow carries only labels the grant allows for that sink;
//   SinkEscalateNeedsAsk   an escalation happens only when some label is in the sink's ask set and none is outside allow + ask;
//   SinkDenyOnForeignLabel one label outside allow + ask denies;
//   ChainLabelsUnion       the labels of a receipt chain are the union of its receipts' labels (nothing is forgotten).
module ReadSide {
  datatype Field = Field(cls: string, dropped: bool)
  datatype Verdict = Allow | Escalate | Deny

  function Effective(grant: int, request: int): int { if request > grant then request else grant }

  lemma EffectiveNeverWeaker(grant: int, request: int)
    ensures Effective(grant, request) >= grant
    ensures Effective(grant, request) >= request
  {
  }

  lemma EffectiveIsOneOf(grant: int, request: int)
    ensures Effective(grant, request) == grant || Effective(grant, request) == request
    ensures Effective(grant, request) == grant || request > grant
  {
  }

  function Labels(fs: seq<Field>): set<string> { set i | 0 <= i < |fs| && !fs[i].dropped :: fs[i].cls }

  lemma LabelsSound(fs: seq<Field>, i: int)
    requires 0 <= i < |fs| && !fs[i].dropped
    ensures fs[i].cls in Labels(fs)
  {
    assert 0 <= i < |fs| && !fs[i].dropped && fs[i].cls == fs[i].cls;
  }

  lemma LabelsExact(fs: seq<Field>, c: string)
    requires c in Labels(fs)
    ensures exists i :: 0 <= i < |fs| && !fs[i].dropped && fs[i].cls == c
  {
  }

  function SinkVerdict(allow: set<string>, ask: set<string>, labels: set<string>): Verdict {
    if exists l :: l in labels && l !in allow && l !in ask then Deny
    else if exists l :: l in labels && l in ask then Escalate
    else Allow
  }

  lemma SinkAllowIsSubset(allow: set<string>, ask: set<string>, labels: set<string>)
    requires allow !! ask
    requires SinkVerdict(allow, ask, labels) == Allow
    ensures labels <= allow
  {
    forall l | l in labels ensures l in allow {
      assert l in allow || l in ask;
      assert !(l in ask);
    }
  }

  lemma SinkEscalateNeedsAsk(allow: set<string>, ask: set<string>, labels: set<string>)
    requires SinkVerdict(allow, ask, labels) == Escalate
    ensures labels <= allow + ask
    ensures exists l :: l in labels && l in ask
  {
  }

  lemma SinkDenyOnForeignLabel(allow: set<string>, ask: set<string>, labels: set<string>, l: string)
    requires l in labels && l !in allow && l !in ask
    ensures SinkVerdict(allow, ask, labels) == Deny
  {
  }

  function ChainLabels(rs: seq<set<string>>): set<string> { set i, l | 0 <= i < |rs| && l in rs[i] :: l }

  lemma ChainLabelsUnion(rs: seq<set<string>>, i: int, l: string)
    requires 0 <= i < |rs| && l in rs[i]
    ensures l in ChainLabels(rs)
  {
    assert 0 <= i < |rs| && l in rs[i];
  }
}

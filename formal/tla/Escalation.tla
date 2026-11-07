---------------------------- MODULE Escalation ----------------------------
(***************************************************************************
 Escalation protocol (goal-to-decision G-T4, F7; security contract C-51).
 Implementation: packages/pca/src/escalation.ts, server/require-pca.ts.

 The verifier decision for an action is allow, escalate or deny. The PEP may
 admit an escalated action only with a principal-signed answer bound to
 (policy, action, history head); the replay counter (the head) spends it.
 Each admission records WHY it happened, so the invariants speak about the
 basis, not about later state.

 Mode: "good" is the implementation. The bad_* modes are deliberate defects
 and MUST produce a counterexample:
   bad_implicit  escalate with no answer admitted (host maps the 403 to allow)
   bad_rebind    the answer is not bound to the action (replay onto another)
   bad_nohead    the answer is not bound to the history head (stale state)
   bad_nospend   the head does not advance, so one answer admits twice
   bad_deny_up   an answer also upgrades a hard deny
   bad_norender  the answer is not bound to the canonical approval render (K7, C-460):
                 the principal signs over what a wallet DREW, not what the action IS
 ***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS Actions, Policies, MaxHead, Mode

VARIABLES policy, head, dec, answers, log, n

vars == <<policy, head, dec, answers, log, n>>
Decs == {"allow", "escalate", "deny"}

Init ==
  /\ policy \in Policies /\ head = 0
  /\ dec \in [Actions -> Decs]
  /\ answers = {} /\ log = {} /\ n = 0

\* K7: the canonical render of an action is a function of the action alone (modelled as the action itself). What the principal is
\* SHOWN may be any render: a wallet or a channel can draw something else. The answer records the render it was given over.
\* the principal signs an answer only for an action it was asked about (an escalate)
\* Bounded model: at most MaxHead + 1 answers exist (one per admission the head allows, plus one stale), which keeps the state
\* space finite; every bad_* defect needs at most two answers to show its counterexample.
Answer(a) == /\ dec[a] = "escalate"
             /\ Cardinality(answers) <= MaxHead
             /\ \E shown \in Actions : answers' = answers \cup {<<policy, a, head, shown>>}
             /\ UNCHANGED <<policy, head, dec, log, n>>

Matches(ans, a) ==
  /\ ans[1] = policy
  /\ (Mode = "bad_rebind" \/ ans[2] = a)
  /\ (Mode = "bad_nohead" \/ ans[3] = head)
  /\ (Mode = "bad_norender" \/ ans[4] = a)

\* a log record: <<action, decision at admission, basis, the answer used or "none", head at admission, admission number>>
\* n counts admissions (it equals head unless the head fails to advance), so two admissions are always two distinct log
\* records and a double spend can never hide behind an identical record. Admissions stop at the bound (n = MaxHead).
Admit(a) ==
  /\ n < MaxHead
  /\ \/ /\ dec[a] = "allow"
        /\ log' = log \cup {<<a, "allow", "decision", "none", head, n>>}
     \/ /\ dec[a] = "escalate"
        /\ \E ans \in answers : Matches(ans, a) /\ log' = log \cup {<<a, "escalate", "answer", ans, head, n>>}
     \/ /\ dec[a] = "escalate" /\ Mode = "bad_implicit"
        /\ log' = log \cup {<<a, "escalate", "implicit", "none", head, n>>}
     \/ /\ dec[a] = "deny" /\ Mode = "bad_deny_up"
        /\ \E ans \in answers : Matches(ans, a) /\ log' = log \cup {<<a, "deny", "answer", ans, head, n>>}
  /\ head' = IF Mode = "bad_nospend" THEN head ELSE head + 1
  /\ n' = n + 1
  /\ UNCHANGED <<policy, dec, answers>>

\* a new grant: decisions are recomputed (answers for the old policy stay in the set but no longer match)
Repolicy(p, d) == /\ policy' = p /\ dec' = d /\ UNCHANGED <<head, answers, log, n>>

Next == (\E a \in Actions : Answer(a) \/ Admit(a)) \/ (\E p \in Policies, d \in [Actions -> Decs] : Repolicy(p, d))
Spec == Init /\ [][Next]_vars

\* escalation never becomes allow implicitly
NoImplicitAllow == \A r \in log : r[2] = "escalate" => r[3] = "answer"
\* a hard deny is never admitted
NoDenyAdmitted == \A r \in log : r[2] # "deny"
\* an answer is bound to its action and to the head it was issued at, and admits at most once
AnswerBound == \A r \in log : r[3] = "answer" => (r[4][2] = r[1] /\ r[4][3] = r[5])
AnswerOnce == \A r, s \in log : (r # s /\ r[3] = "answer" /\ s[3] = "answer") => r[4] # s[4]
\* K7: an answer admits an action only if it was given over that action's own canonical render
AnswerRendered == \A r \in log : r[3] = "answer" => r[4][4] = r[1]
Safe == NoImplicitAllow /\ NoDenyAdmitted /\ AnswerBound /\ AnswerOnce /\ AnswerRendered
=============================================================================

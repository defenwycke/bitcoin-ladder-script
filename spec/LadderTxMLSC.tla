------------------------ MODULE LadderTxMLSC ------------------------
(***************************************************************************)
(* End-to-end model of TX_MLSC lifecycle: creation → UTXO → spend.        *)
(* Verifies output_index binding, creation proof verification,             *)
(* shared tree integrity, and adversarial attack rejection.                *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

(***************************************************************************)
(* Constants                                                               *)
(***************************************************************************)

CONSTANTS
    MaxOutputs,    \* Max outputs per transaction (e.g. 3)
    MaxRungs       \* Max rungs in shared tree (e.g. 4)

\* Abstract leaf values (stand for hash outputs)
LeafValues == 1..4
\* Abstract root values (computed from leaves)
RootValues == 100..120

\* Simplified hash: deterministic, injective within domain
Hash(a, b) == a * 100 + b

(***************************************************************************)
(* Transaction model                                                       *)
(***************************************************************************)

\* A rung in the creation proof
CreationRung == [output_index: 0..(MaxOutputs-1), leaf: LeafValues]

\* A transaction has outputs (values) and a shared tree (rungs → root)
Transaction == [
    n_outputs: 1..MaxOutputs,
    rungs: Seq(CreationRung),
    root: RootValues \cup {0}  \* 0 = not yet computed
]

(***************************************************************************)
(* Root computation (abstract Merkle tree)                                  *)
(***************************************************************************)

\* Compute root from rungs (simplified: hash all leaves sequentially)
ComputeRoot(rungs) ==
    IF Len(rungs) = 0 THEN 0
    ELSE IF Len(rungs) = 1 THEN rungs[1].leaf + 100  \* offset to RootValues range
    ELSE
        LET base == rungs[1].leaf + 100
        IN IF Len(rungs) >= 2 THEN Hash(base, rungs[2].leaf)
           ELSE base

(***************************************************************************)
(* Creation proof validation                                               *)
(***************************************************************************)

ValidateCreation(tx) ==
    LET n == Len(tx.rungs) IN
    \* V1: non-empty
    IF n = 0 THEN "REJECT_EMPTY"
    \* V2: output_index in range
    ELSE IF \E i \in 1..n : tx.rungs[i].output_index >= tx.n_outputs
         THEN "REJECT_OUTPUT_RANGE"
    \* V3: all outputs covered
    ELSE IF \E o \in 0..(tx.n_outputs-1) :
                ~(\E i \in 1..n : tx.rungs[i].output_index = o)
         THEN "REJECT_UNCOVERED"
    \* V4: root matches
    ELSE IF tx.root # ComputeRoot(tx.rungs)
         THEN "REJECT_ROOT_MISMATCH"
    ELSE "ACCEPT"

(***************************************************************************)
(* Spend verification                                                      *)
(***************************************************************************)

\* A spend attempt: which output, which rung, claimed leaf
SpendAttempt == [
    output_index: 0..(MaxOutputs-1),
    rung_index: 0..(MaxRungs-1),
    claimed_leaf: LeafValues
]

VerifySpend(tx, spend) ==
    LET n == Len(tx.rungs) IN
    \* S1: rung_index in range
    IF spend.rung_index >= n THEN "REJECT_RUNG_RANGE"
    \* S2: claimed leaf matches actual leaf at rung_index
    ELSE IF spend.claimed_leaf # tx.rungs[spend.rung_index + 1].leaf
         THEN "REJECT_LEAF_MISMATCH"
    \* S3: rung's output_index matches spent output
    ELSE IF tx.rungs[spend.rung_index + 1].output_index # spend.output_index
         THEN "REJECT_OUTPUT_INDEX_MISMATCH"
    \* S4: verify root (proof reconstruction)
    ELSE IF tx.root # ComputeRoot(tx.rungs)
         THEN "REJECT_ROOT_MISMATCH"
    ELSE "ACCEPT"

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES
    tx,
    spend,
    phase,
    createResult,
    spendResult

vars == <<tx, spend, phase, createResult, spendResult>>

Init ==
    /\ tx \in [n_outputs: 1..MaxOutputs,
               rungs: UNION {[1..n -> CreationRung] : n \in 1..MaxRungs},
               root: RootValues \cup {0}]
    /\ spend \in SpendAttempt
    /\ phase = "create"
    /\ createResult = "PENDING"
    /\ spendResult = "PENDING"

StepCreate ==
    /\ phase = "create"
    /\ createResult' = ValidateCreation(tx)
    /\ phase' = "spend"
    /\ UNCHANGED <<tx, spend, spendResult>>

StepSpend ==
    /\ phase = "spend"
    /\ spendResult' = VerifySpend(tx, spend)
    /\ phase' = "done"
    /\ UNCHANGED <<tx, spend, createResult>>

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepCreate \/ StepSpend \/ StepDone

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: Creation result is always valid
Inv_CreateResultValid ==
    phase # "create" =>
        createResult \in {"ACCEPT", "REJECT_EMPTY", "REJECT_OUTPUT_RANGE",
                          "REJECT_UNCOVERED", "REJECT_ROOT_MISMATCH", "PENDING"}

\* I2: Spend result is always valid
Inv_SpendResultValid ==
    phase = "done" =>
        spendResult \in {"ACCEPT", "REJECT_RUNG_RANGE", "REJECT_LEAF_MISMATCH",
                         "REJECT_OUTPUT_INDEX_MISMATCH", "REJECT_ROOT_MISMATCH", "PENDING"}

\* I3: ADVERSARIAL — wrong output_index always rejected at spend
\* If the rung's output_index doesn't match the spend's output_index,
\* the spend must be rejected (never ACCEPT)
Inv_OutputIndexEnforced ==
    (phase = "done" /\ spendResult = "ACCEPT")
    => (spend.rung_index < Len(tx.rungs) =>
            tx.rungs[spend.rung_index + 1].output_index = spend.output_index)

\* I4: ADVERSARIAL — wrong leaf always rejected
\* If the claimed leaf doesn't match the actual leaf, spend is rejected
Inv_LeafBindingEnforced ==
    (phase = "done" /\ spendResult = "ACCEPT")
    => (spend.rung_index < Len(tx.rungs) =>
            spend.claimed_leaf = tx.rungs[spend.rung_index + 1].leaf)

\* I5: ADVERSARIAL — wrong root always rejected at creation
\* If the root doesn't match ComputeRoot(rungs), creation is rejected
Inv_RootMismatchRejected ==
    (phase # "create" /\ createResult = "ACCEPT")
    => tx.root = ComputeRoot(tx.rungs)

\* I6: Accepted creation covers all outputs
Inv_AllOutputsCovered ==
    (phase # "create" /\ createResult = "ACCEPT")
    => \A o \in 0..(tx.n_outputs-1) :
           \E i \in 1..Len(tx.rungs) : tx.rungs[i].output_index = o

\* I7: End-to-end: if both creation and spend succeed, the binding is correct
Inv_EndToEndBinding ==
    (phase = "done" /\ createResult = "ACCEPT" /\ spendResult = "ACCEPT")
    => /\ tx.root = ComputeRoot(tx.rungs)                                    \* root verified
       /\ spend.rung_index < Len(tx.rungs)                                    \* rung in range
       /\ tx.rungs[spend.rung_index + 1].output_index = spend.output_index    \* output bound
       /\ spend.claimed_leaf = tx.rungs[spend.rung_index + 1].leaf            \* leaf bound

\* I8: ADVERSARIAL — uncovered output always rejected at creation
Inv_UncoveredOutputRejected ==
    (phase # "create" /\ createResult = "ACCEPT")
    => ~(\E o \in 0..(tx.n_outputs-1) :
             ~(\E i \in 1..Len(tx.rungs) : tx.rungs[i].output_index = o))

SafetyInvariant ==
    /\ Inv_CreateResultValid
    /\ Inv_SpendResultValid
    /\ Inv_OutputIndexEnforced
    /\ Inv_LeafBindingEnforced
    /\ Inv_RootMismatchRejected
    /\ Inv_AllOutputsCovered
    /\ Inv_EndToEndBinding
    /\ Inv_UncoveredOutputRejected

=============================================================================

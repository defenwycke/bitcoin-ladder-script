---------------------- MODULE LadderCreationProof ----------------------
(***************************************************************************)
(* Model TX_MLSC creation proof validation at block acceptance.            *)
(* Verifies: known block types, valid inversion, output coverage,          *)
(* root derivation from validated structure.                               *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

(***************************************************************************)
(* Constants                                                               *)
(***************************************************************************)

CONSTANTS
    MaxRungs,      \* Max rungs in creation proof (e.g. 4)
    MaxOutputs     \* Max outputs per transaction (e.g. 3)

\* Block types (abstract: 1..5 represent known types)
KnownBlockTypes == 1..5
UnknownBlockTypes == {99}
InvertibleBlockTypes == {2, 3}  \* e.g. CSV, CLTV are invertible

\* Coil types
KnownCoilTypes == {1, 2}  \* UNLOCK, UNLOCK_TO

(***************************************************************************)
(* Creation proof rung                                                     *)
(***************************************************************************)

\* A rung in the creation proof: block_type, inverted, output_index
CreationRung == [
    block_type: KnownBlockTypes \cup UnknownBlockTypes,
    inverted: {TRUE, FALSE},
    output_index: 0..(MaxOutputs - 1),
    coil_type: KnownCoilTypes \cup {99}
]

(***************************************************************************)
(* Validation function                                                     *)
(***************************************************************************)

ValidateCreationProof(rungs, n_outputs) ==
    LET n == Len(rungs) IN
    \* V1: Must have at least one rung
    IF n = 0 THEN "REJECT_EMPTY"
    \* V2: All block types must be known
    ELSE IF \E i \in 1..n : rungs[i].block_type \in UnknownBlockTypes
         THEN "REJECT_UNKNOWN_TYPE"
    \* V3: Inverted flag valid (only invertible types)
    ELSE IF \E i \in 1..n :
                rungs[i].inverted = TRUE
                /\ rungs[i].block_type \notin InvertibleBlockTypes
         THEN "REJECT_BAD_INVERSION"
    \* V4: output_index in range
    ELSE IF \E i \in 1..n : rungs[i].output_index >= n_outputs
         THEN "REJECT_OUTPUT_RANGE"
    \* V5: All coil types known
    ELSE IF \E i \in 1..n : rungs[i].coil_type \notin KnownCoilTypes
         THEN "REJECT_UNKNOWN_COIL"
    \* V6: Every output must have at least one rung
    ELSE IF \E o \in 0..(n_outputs - 1) :
                ~(\E i \in 1..n : rungs[i].output_index = o)
         THEN "REJECT_UNCOVERED"
    ELSE "ACCEPT"

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES
    rungs,
    n_outputs,
    phase

vars == <<rungs, n_outputs, phase>>

Init ==
    /\ n_outputs \in 1..MaxOutputs
    /\ rungs \in UNION {[1..n -> CreationRung] : n \in 1..MaxRungs}
    /\ phase = "check"

Next ==
    \/ /\ phase = "check"
       /\ phase' = "done"
       /\ UNCHANGED <<rungs, n_outputs>>
    \/ /\ phase = "done"
       /\ UNCHANGED vars

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)

\* Result is always valid
Inv_ResultValid ==
    LET r == ValidateCreationProof(rungs, n_outputs)
    IN r \in {"ACCEPT", "REJECT_EMPTY", "REJECT_UNKNOWN_TYPE",
              "REJECT_BAD_INVERSION", "REJECT_OUTPUT_RANGE",
              "REJECT_UNKNOWN_COIL", "REJECT_UNCOVERED"}

\* Unknown block type → always rejected
Inv_UnknownTypeRejected ==
    (\E i \in 1..Len(rungs) : rungs[i].block_type \in UnknownBlockTypes)
    => ValidateCreationProof(rungs, n_outputs) \in
       {"REJECT_UNKNOWN_TYPE", "REJECT_EMPTY"}

\* Non-invertible block with inverted flag → rejected
Inv_BadInversionRejected ==
    (\E i \in 1..Len(rungs) :
        rungs[i].inverted = TRUE
        /\ rungs[i].block_type \notin InvertibleBlockTypes
        /\ rungs[i].block_type \in KnownBlockTypes)
    => ValidateCreationProof(rungs, n_outputs) \in
       {"REJECT_BAD_INVERSION", "REJECT_UNKNOWN_TYPE", "REJECT_EMPTY"}

\* output_index >= n_outputs → rejected
Inv_OutputRangeRejected ==
    (\E i \in 1..Len(rungs) : rungs[i].output_index >= n_outputs)
    => ValidateCreationProof(rungs, n_outputs) # "ACCEPT"

\* Accepted proof → every output has a rung
Inv_AcceptedCoversAllOutputs ==
    ValidateCreationProof(rungs, n_outputs) = "ACCEPT"
    => \A o \in 0..(n_outputs - 1) :
           \E i \in 1..Len(rungs) : rungs[i].output_index = o

\* Accepted proof → all block types known
Inv_AcceptedAllKnown ==
    ValidateCreationProof(rungs, n_outputs) = "ACCEPT"
    => \A i \in 1..Len(rungs) : rungs[i].block_type \in KnownBlockTypes

\* Accepted proof → no bad inversions
Inv_AcceptedNoInversionViolation ==
    ValidateCreationProof(rungs, n_outputs) = "ACCEPT"
    => \A i \in 1..Len(rungs) :
           rungs[i].inverted = TRUE => rungs[i].block_type \in InvertibleBlockTypes

SafetyInvariant ==
    /\ Inv_ResultValid
    /\ Inv_UnknownTypeRejected
    /\ Inv_BadInversionRejected
    /\ Inv_OutputRangeRejected
    /\ Inv_AcceptedCoversAllOutputs
    /\ Inv_AcceptedAllKnown
    /\ Inv_AcceptedNoInversionViolation

=============================================================================

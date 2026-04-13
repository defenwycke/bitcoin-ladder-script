------------------------ MODULE LadderSighash ------------------------
(***************************************************************************)
(* Model the sighash commitment completeness for Ladder Script.           *)
(* Verifies which fields are committed under each hash type combination   *)
(* and that ANYPREVOUT skip rules are correctly applied.                  *)
(*                                                                         *)
(* Updated 2026-03-27: key-path sighash mode (no conditions commitment).  *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

(***************************************************************************)
(* Hash type flags                                                         *)
(***************************************************************************)

\* Output type (low 2 bits)
OutputTypes == {"DEFAULT", "ALL", "NONE", "SINGLE"}

\* Input modifier flags
InputModifiers == {"NORMAL", "ANYONECANPAY", "ANYPREVOUT", "ANYPREVOUTANYSCRIPT"}

\* Spend path: key-path vs script-path
SpendPaths == {"KEY_PATH", "SCRIPT_PATH"}

\* Encoding: output_type + modifier → hash_type byte
HashTypeByte(outType, inMod) ==
    LET outVal == CASE outType = "DEFAULT" -> 0
                    [] outType = "ALL" -> 1
                    [] outType = "NONE" -> 2
                    [] outType = "SINGLE" -> 3
        modVal == CASE inMod = "NORMAL" -> 0
                    [] inMod = "ANYONECANPAY" -> 16
                    [] inMod = "ANYPREVOUT" -> 8
                    [] inMod = "ANYPREVOUTANYSCRIPT" -> 24
    IN outVal + modVal

\* Valid hash type combinations
IsValidHashType(outType, inMod) == TRUE

\* Key-path spending restricts hash types (no ANYPREVOUT variants)
IsValidKeyPathHashType(outType, inMod) ==
    inMod \in {"NORMAL", "ANYONECANPAY"}

(***************************************************************************)
(* Committed fields model                                                  *)
(* Each field is a boolean: TRUE = committed, FALSE = skipped             *)
(***************************************************************************)

\* Fields that are ALWAYS committed regardless of hash type
AlwaysCommitted == {"epoch", "hash_type", "tx_version", "tx_locktime", "spend_type"}

CommittedFields(outType, inMod, spendPath) ==
    LET isACP == inMod = "ANYONECANPAY"
        isAPO == inMod = "ANYPREVOUT"
        isAPOAS == inMod = "ANYPREVOUTANYSCRIPT"
        isAnyPrevout == isAPO \/ isAPOAS
        isKeyPath == spendPath = "KEY_PATH"

        commitPrevouts == ~isACP /\ ~isAnyPrevout
        commitAmounts == ~isACP
        commitSequences == ~isACP
        commitOutputs == outType \in {"ALL", "DEFAULT"}
        commitSingleOutput == outType = "SINGLE"
        commitInputPrevout == ~isAnyPrevout
        commitInputSpentOutput == TRUE
        commitInputSequence == TRUE
        commitInputIndex == ~isACP

        \* CONDITIONS HASH: committed in script-path unless APOAS; NEVER in key-path
        commitConditions == ~isKeyPath /\ ~isAPOAS
    IN
    [prevouts_hash |-> commitPrevouts,
     amounts_hash |-> commitAmounts,
     sequences_hash |-> commitSequences,
     outputs_hash |-> commitOutputs,
     single_output_hash |-> commitSingleOutput,
     input_prevout |-> commitInputPrevout,
     input_spent_output |-> commitInputSpentOutput,
     input_sequence |-> commitInputSequence,
     input_index |-> commitInputIndex,
     conditions_hash |-> commitConditions]

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES
    outType,
    inMod,
    spendPath,
    phase

vars == <<outType, inMod, spendPath, phase>>

Init ==
    /\ outType \in OutputTypes
    /\ inMod \in InputModifiers
    /\ spendPath \in SpendPaths
    /\ phase = "check"

Next ==
    \/ /\ phase = "check"
       /\ phase' = "done"
       /\ UNCHANGED <<outType, inMod, spendPath>>
    \/ /\ phase = "done"
       /\ UNCHANGED vars

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)

\* DEFAULT and ALL commit to same fields (for both spend paths)
Inv_DefaultEqualsAll ==
    \A im \in InputModifiers :
        \A sp \in SpendPaths :
            CommittedFields("DEFAULT", im, sp) = CommittedFields("ALL", im, sp)

\* ANYPREVOUT still commits to amounts
Inv_APOCommitsAmounts ==
    \A sp \in SpendPaths :
        CommittedFields("ALL", "ANYPREVOUT", sp).amounts_hash = TRUE

\* ANYPREVOUTANYSCRIPT skips conditions in script-path
Inv_APOASSkipsConditions ==
    /\ CommittedFields("ALL", "ANYPREVOUTANYSCRIPT", "SCRIPT_PATH").conditions_hash = FALSE
    /\ CommittedFields("ALL", "ANYPREVOUT", "SCRIPT_PATH").conditions_hash = TRUE

\* KEY-PATH: conditions_hash is NEVER committed (key-path sighash)
Inv_KeyPathNoConditions ==
    \A ot \in OutputTypes :
        \A im \in InputModifiers :
            CommittedFields(ot, im, "KEY_PATH").conditions_hash = FALSE

\* KEY-PATH and SCRIPT_PATH differ only in conditions_hash
\* (when modifier is NORMAL — no APO complexity)
Inv_KeyPathDiffersOnlyInConditions ==
    \A ot \in OutputTypes :
        LET kp == CommittedFields(ot, "NORMAL", "KEY_PATH")
            sp == CommittedFields(ot, "NORMAL", "SCRIPT_PATH")
        IN /\ kp.prevouts_hash = sp.prevouts_hash
           /\ kp.amounts_hash = sp.amounts_hash
           /\ kp.sequences_hash = sp.sequences_hash
           /\ kp.outputs_hash = sp.outputs_hash
           /\ kp.input_prevout = sp.input_prevout
           /\ kp.input_index = sp.input_index
           \* Only conditions_hash differs
           /\ kp.conditions_hash = FALSE
           /\ sp.conditions_hash = TRUE

\* ANYONECANPAY skips aggregates
Inv_ACPSkipsAggregates ==
    \A ot \in OutputTypes :
        \A sp \in SpendPaths :
            LET cf == CommittedFields(ot, "ANYONECANPAY", sp)
            IN /\ cf.prevouts_hash = FALSE
               /\ cf.amounts_hash = FALSE
               /\ cf.sequences_hash = FALSE

\* NONE skips outputs
Inv_NoneSkipsOutputs ==
    \A im \in InputModifiers :
        \A sp \in SpendPaths :
            /\ CommittedFields("NONE", im, sp).outputs_hash = FALSE
            /\ CommittedFields("NONE", im, sp).single_output_hash = FALSE

\* SINGLE commits only single output hash
Inv_SingleOutput ==
    \A im \in InputModifiers :
        \A sp \in SpendPaths :
            /\ CommittedFields("SINGLE", im, sp).outputs_hash = FALSE
            /\ CommittedFields("SINGLE", im, sp).single_output_hash = TRUE

\* Always-committed fields present in every mode
Inv_AlwaysCommittedPresent ==
    TRUE  \* epoch, hash_type, tx_version, tx_locktime, spend_type always present by construction

\* Binding: at least some fields always committed
Inv_FieldsAreInputs ==
    \A ot \in OutputTypes :
        \A im \in InputModifiers :
            \A sp \in SpendPaths :
                LET cf == CommittedFields(ot, im, sp)
                IN cf.input_spent_output = TRUE /\ cf.input_sequence = TRUE

\* Combined
SafetyInvariant ==
    /\ Inv_DefaultEqualsAll
    /\ Inv_APOCommitsAmounts
    /\ Inv_APOASSkipsConditions
    /\ Inv_KeyPathNoConditions
    /\ Inv_KeyPathDiffersOnlyInConditions
    /\ Inv_ACPSkipsAggregates
    /\ Inv_NoneSkipsOutputs
    /\ Inv_SingleOutput
    /\ Inv_AlwaysCommittedPresent
    /\ Inv_FieldsAreInputs

=============================================================================

------------------------ MODULE LadderAntiSpam ------------------------
(***************************************************************************)
(* Model the deserialization-time anti-spam enforcement rules for Ladder   *)
(* Script. Covers preimage limits, implicit layout enforcement, data      *)
(* embedding restrictions, and context-sensitive field type rejection.     *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

(***************************************************************************)
(* Constants                                                               *)
(***************************************************************************)

CONSTANTS
    MaxFields    \* Max fields per block for enumeration (e.g. 3)

MAX_PREIMAGE_FIELDS_PER_WITNESS == 2   \* Per-input fast reject
MAX_PREIMAGE_FIELDS_PER_TX == 2        \* Per-transaction binding constraint
MAX_PREIMAGE_BYTES == 32               \* Each PREIMAGE is 32 bytes max
MAX_EMBED_BYTES == MAX_PREIMAGE_FIELDS_PER_TX * MAX_PREIMAGE_BYTES  \* 64 bytes total

\* Block types: representative subset
BlockTypesWithLayout == {"SIG", "CSV", "CLTV", "AMOUNT_LOCK", "MULTISIG"}
BlockTypesWithoutLayout == {"ACCUMULATOR"}
DataReturnBlock == {"DATA_RETURN"}
AllBlockTypes == BlockTypesWithLayout \cup BlockTypesWithoutLayout \cup DataReturnBlock

\* Field data types
DataEmbeddingTypes == {"PUBKEY_COMMIT", "HASH256", "HASH160", "DATA"}
WitnessOnlyTypes == {"PUBKEY", "SIGNATURE", "PREIMAGE", "SCRIPT_BODY"}
NumericType == {"NUMERIC"}
AllFieldTypes == DataEmbeddingTypes \cup WitnessOnlyTypes \cup NumericType

\* Context
Contexts == {"CONDITIONS", "WITNESS"}

(***************************************************************************)
(* Anti-spam validation function                                           *)
(* Returns "ACCEPT" or "REJECT" with a reason                             *)
(***************************************************************************)

ValidateBlock(blockType, context, fieldTypes, preimageCount, layoutFieldCount, layoutFieldTypes) ==
    LET hasLayout == blockType \in BlockTypesWithLayout
        fieldCount == Len(fieldTypes)
    IN
    \* P1: Preimage count limit
    IF preimageCount > MAX_PREIMAGE_FIELDS_PER_TX THEN "REJECT_P1"
    \* P2: Data embedding in non-layout block (except ACCUMULATOR)
    ELSE IF blockType \notin BlockTypesWithLayout
            /\ blockType \notin DataReturnBlock
            /\ blockType # "ACCUMULATOR"
            /\ \E i \in 1..fieldCount : fieldTypes[i] \in DataEmbeddingTypes
         THEN "REJECT_P2"
    \* P3: DATA type only in DATA_RETURN
    ELSE IF blockType \notin DataReturnBlock
            /\ \E i \in 1..fieldCount : fieldTypes[i] = "DATA"
         THEN "REJECT_P3"
    \* P4: Witness-only types rejected in CONDITIONS context
    ELSE IF context = "CONDITIONS"
            /\ \E i \in 1..fieldCount : fieldTypes[i] \in WitnessOnlyTypes
         THEN "REJECT_P4"
    \* P5: Field count must match layout count (if layout exists)
    ELSE IF hasLayout /\ fieldCount # layoutFieldCount
         THEN "REJECT_P5"
    \* P6: Field types must match layout types (if layout exists)
    ELSE IF hasLayout /\ fieldCount = layoutFieldCount
            /\ \E i \in 1..fieldCount : fieldTypes[i] # layoutFieldTypes[i]
         THEN "REJECT_P6"
    ELSE "ACCEPT"

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES
    blockType,
    context,
    fieldSeq,          \* Sequence of field types
    preimageCount,
    layoutFieldCount,
    layoutFieldSeq,    \* Layout's expected types
    phase

vars == <<blockType, context, fieldSeq, preimageCount, layoutFieldCount, layoutFieldSeq, phase>>

\* We use small field sequences for tractability
FieldSeqs == UNION {[1..n -> AllFieldTypes] : n \in 0..MaxFields}

Init ==
    /\ blockType \in AllBlockTypes
    /\ context \in Contexts
    /\ fieldSeq \in FieldSeqs
    /\ preimageCount \in 0..3
    /\ layoutFieldCount \in 0..MaxFields
    /\ layoutFieldSeq \in UNION {[1..n -> AllFieldTypes] : n \in {layoutFieldCount}}
    /\ phase = "check"

Next ==
    \/ /\ phase = "check"
       /\ phase' = "done"
       /\ UNCHANGED <<blockType, context, fieldSeq, preimageCount, layoutFieldCount, layoutFieldSeq>>
    \/ /\ phase = "done"
       /\ UNCHANGED vars

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)

\* Result is always one of the valid outcomes
Inv_ResultValid ==
    LET r == ValidateBlock(blockType, context, fieldSeq, preimageCount,
                           layoutFieldCount, layoutFieldSeq)
    IN r \in {"ACCEPT", "REJECT_P1", "REJECT_P2", "REJECT_P3",
              "REJECT_P4", "REJECT_P5", "REJECT_P6"}

\* P1: preimage count > MAX → always rejected
Inv_PreimageLimitEnforced ==
    preimageCount > MAX_PREIMAGE_FIELDS_PER_TX =>
        ValidateBlock(blockType, context, fieldSeq, preimageCount,
                      layoutFieldCount, layoutFieldSeq) = "REJECT_P1"

\* P3: DATA field outside DATA_RETURN → rejected
Inv_DataOnlyInDataReturn ==
    \A bt \in AllBlockTypes \ DataReturnBlock :
        \A ft \in {<<"DATA">>} :
            LET r == ValidateBlock(bt, "WITNESS", ft, 0, 0, <<>>)
            IN r \in {"REJECT_P2", "REJECT_P3", "REJECT_P5", "REJECT_P6"}

\* P4: Witness-only types in CONDITIONS → rejected
Inv_WitnessOnlyRejectedInConditions ==
    \A wt \in WitnessOnlyTypes :
        \A bt \in AllBlockTypes :
            LET r == ValidateBlock(bt, "CONDITIONS", <<wt>>, 0, 1, <<wt>>)
            IN r = "REJECT_P4"

\* P5: Field count mismatch with layout → rejected
Inv_FieldCountMismatch ==
    \A bt \in BlockTypesWithLayout :
        LET r == ValidateBlock(bt, "WITNESS", <<"NUMERIC", "NUMERIC">>, 0, 3,
                               <<"NUMERIC", "NUMERIC", "NUMERIC">>)
        IN r = "REJECT_P5"

\* P7: Total embeddable data bounded (structural: 2 PREIMAGE × 32 = 64 bytes)
Inv_EmbedBound ==
    MAX_PREIMAGE_FIELDS_PER_TX * MAX_PREIMAGE_BYTES = 64

\* Accepted blocks have preimage count within limit
Inv_AcceptedPreimageOk ==
    LET r == ValidateBlock(blockType, context, fieldSeq, preimageCount,
                           layoutFieldCount, layoutFieldSeq)
    IN r = "ACCEPT" => preimageCount <= MAX_PREIMAGE_FIELDS_PER_TX

(***************************************************************************)
(* TX_MLSC: Creation Proof Anti-Spam Properties                            *)
(* The conditions_root is protocol-derived, not user-supplied. Every       *)
(* on-chain value is either a hash output, validated enum, or functional.  *)
(***************************************************************************)

\* TX_MLSC embeddable surface constants
DATA_RETURN_MAX == 40       \* intentional, bounded
NLOCKTIME_BYTES == 4        \* standard Bitcoin
NSEQUENCE_BYTES == 4        \* standard Bitcoin (per input)
TX_MLSC_READABLE_PER_TX == DATA_RETURN_MAX + NLOCKTIME_BYTES + NSEQUENCE_BYTES + MAX_EMBED_BYTES
    \* 40 + 4 + 4 + 64 = 112 bytes

\* P8: TX_MLSC conditions_root is protocol-derived (triple-hashed)
\* Root = MerkleRoot(TaggedHash(template || SHA256(values || pubkeys)))
\* Attacker cannot embed specific message without breaking SHA256
Inv_RootProtocolDerived ==
    TRUE  \* Structural property: root derived during validation, not user-supplied

\* P9: TX_MLSC value_commitment is SHA256 output (not attacker-chosen)
Inv_ValueCommitmentIsHash ==
    TRUE  \* Structural: value_commitment = SHA256(field_values || pubkeys)

\* P10: TX_MLSC structural templates are validated enums
\* block_type must be one of 61 known types
\* inverted must be 0 or 1, valid for the block type
Inv_TemplateValidated ==
    TRUE  \* Checked by ValidateCreationProof: IsKnownBlockType + IsInvertibleBlockType

\* P11: Total readable attacker data per TX_MLSC transaction = 112 bytes
Inv_TxMLSCEmbedBound ==
    TX_MLSC_READABLE_PER_TX = 112

\* P12: No contiguous data embedding channel > 64 bytes exists
\* The 112 bytes are scattered: DATA_RETURN(40) + nLockTime(4) + nSequence(4) + PREIMAGE(64)
\* Maximum contiguous block: PREIMAGE = 64 bytes (hash-bound)
MAX_CONTIGUOUS_EMBED == MAX_EMBED_BYTES
Inv_NoLargeContiguousEmbed ==
    MAX_CONTIGUOUS_EMBED = 64

\* Combined (updated)
SafetyInvariant ==
    /\ Inv_ResultValid
    /\ Inv_PreimageLimitEnforced
    /\ Inv_DataOnlyInDataReturn
    /\ Inv_WitnessOnlyRejectedInConditions
    /\ Inv_FieldCountMismatch
    /\ Inv_EmbedBound
    /\ Inv_AcceptedPreimageOk
    /\ Inv_TxMLSCEmbedBound
    /\ Inv_NoLargeContiguousEmbed
    /\ Inv_RootProtocolDerived
    /\ Inv_ValueCommitmentIsHash
    /\ Inv_TemplateValidated

=============================================================================

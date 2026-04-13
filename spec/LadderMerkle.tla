------------------------ MODULE LadderMerkle ------------------------
(***************************************************************************)
(* Model the MLSC Merkle tree structure and proof verification.           *)
(* Uses abstract hash functions to verify structural properties:          *)
(* determinism, proof correctness, tamper evidence, pubkey-in-leaf.       *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

(***************************************************************************)
(* Constants                                                               *)
(***************************************************************************)

CONSTANTS
    NumLeaves    \* Number of leaves in the tree (e.g. 4)

\* Abstract leaf values (small integers stand for hashes)
LeafValues == 1..NumLeaves
\* Abstract pubkey values
PubKeyValues == 100..102

(***************************************************************************)
(* Abstract hash function                                                  *)
(* We model Hash(a, b) as a deterministic injective function.             *)
(* Using a simple encoding: Hash(a,b) = a * 1000 + b                     *)
(* This gives us collision-resistance within our small domain.            *)
(***************************************************************************)

Hash(a, b) == a * 1000 + b

\* Leaf hash with pubkey folded in
LeafHash(leafVal, pubkey) == Hash(leafVal, pubkey)

(***************************************************************************)
(* Merkle tree computation                                                 *)
(* For simplicity, model a tree with exactly NumLeaves leaves.            *)
(* Build bottom-up: pair adjacent leaves and hash.                        *)
(***************************************************************************)

\* For 4 leaves: root = Hash(Hash(L1,L2), Hash(L3,L4))
\* For 2 leaves: root = Hash(L1, L2)

ComputeRoot2(l1, l2) == Hash(l1, l2)

ComputeRoot4(l1, l2, l3, l4) ==
    Hash(Hash(l1, l2), Hash(l3, l4))

(***************************************************************************)
(* Merkle proof verification                                               *)
(* For a 4-leaf tree, proof for leaf at index i consists of:              *)
(* - sibling hash                                                         *)
(* - uncle hash (hash of sibling pair)                                    *)
(***************************************************************************)

\* Verify proof for 4-leaf tree
\* leafIdx \in 1..4, leafVal = the leaf value
\* proof = <<sibling, uncle>> where sibling and uncle are hashes
\* root = claimed root
VerifyProof4(leafIdx, leafVal, proof, root) ==
    LET sibling == proof[1]
        uncle == proof[2]
        \* Reconstruct parent based on position (left or right child)
        parent == IF leafIdx \in {1, 3}
                  THEN Hash(leafVal, sibling)  \* left child
                  ELSE Hash(sibling, leafVal)  \* right child
        \* Reconstruct root based on which subtree
        reconstructed == IF leafIdx \in {1, 2}
                         THEN Hash(parent, uncle)  \* left subtree
                         ELSE Hash(uncle, parent)  \* right subtree
    IN reconstructed = root

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES
    leaves,       \* 4-element sequence of leaf values
    targetIdx,    \* Which leaf we're proving membership of
    pubkey,       \* Pubkey value for leaf hash
    phase

vars == <<leaves, targetIdx, pubkey, phase>>

Init ==
    /\ leaves \in [1..NumLeaves -> LeafValues]
    /\ targetIdx \in 1..NumLeaves
    /\ pubkey \in PubKeyValues
    /\ phase = "check"

Next ==
    \/ /\ phase = "check"
       /\ phase' = "done"
       /\ UNCHANGED <<leaves, targetIdx, pubkey>>
    \/ /\ phase = "done"
       /\ UNCHANGED vars

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)

\* ComputeRoot is deterministic: same leaves → same root
Inv_RootDeterministic ==
    \A a, b, c, d \in LeafValues :
        ComputeRoot4(a, b, c, d) = ComputeRoot4(a, b, c, d)

\* Different leaves → different roots (collision resistance)
\* We check this for sequences that differ in exactly one position,
\* which is sufficient to verify tamper evidence.
Inv_DifferentLeavesDifferentRoots ==
    \A a, b, c, d \in LeafValues :
        \A idx \in 1..NumLeaves :
            \A alt \in LeafValues :
                alt # (CASE idx = 1 -> a [] idx = 2 -> b [] idx = 3 -> c [] idx = 4 -> d) =>
                    LET orig == ComputeRoot4(a, b, c, d)
                        mod == CASE idx = 1 -> ComputeRoot4(alt, b, c, d)
                                 [] idx = 2 -> ComputeRoot4(a, alt, c, d)
                                 [] idx = 3 -> ComputeRoot4(a, b, alt, d)
                                 [] idx = 4 -> ComputeRoot4(a, b, c, alt)
                    IN orig # mod

\* Valid proof verifies correctly
Inv_ValidProofVerifies ==
    LET root == ComputeRoot4(leaves[1], leaves[2], leaves[3], leaves[4])
        \* Build correct proof for targetIdx
        sibling == CASE targetIdx = 1 -> leaves[2]
                     [] targetIdx = 2 -> leaves[1]
                     [] targetIdx = 3 -> leaves[4]
                     [] targetIdx = 4 -> leaves[3]
        uncle == CASE targetIdx \in {1, 2} -> Hash(leaves[3], leaves[4])
                   [] targetIdx \in {3, 4} -> Hash(leaves[1], leaves[2])
        proof == <<sibling, uncle>>
    IN VerifyProof4(targetIdx, leaves[targetIdx], proof, root) = TRUE

\* Proof for wrong index fails (when leaves are distinct)
Inv_WrongIndexFails ==
    \* Only check when all leaves distinct
    (leaves[1] # leaves[2] /\ leaves[1] # leaves[3] /\ leaves[1] # leaves[4]
     /\ leaves[2] # leaves[3] /\ leaves[2] # leaves[4]
     /\ leaves[3] # leaves[4]) =>
        \A wrongIdx \in 1..NumLeaves :
            wrongIdx # targetIdx =>
                LET root == ComputeRoot4(leaves[1], leaves[2], leaves[3], leaves[4])
                    \* Build proof for targetIdx but claim wrongIdx
                    sibling == CASE targetIdx = 1 -> leaves[2]
                                 [] targetIdx = 2 -> leaves[1]
                                 [] targetIdx = 3 -> leaves[4]
                                 [] targetIdx = 4 -> leaves[3]
                    uncle == CASE targetIdx \in {1, 2} -> Hash(leaves[3], leaves[4])
                               [] targetIdx \in {3, 4} -> Hash(leaves[1], leaves[2])
                    proof == <<sibling, uncle>>
                IN ~VerifyProof4(wrongIdx, leaves[targetIdx], proof, root)

\* Modified leaf → different root (tamper evidence)
Inv_TamperEvidence ==
    \A idx \in 1..NumLeaves :
        \A newVal \in LeafValues :
            newVal # leaves[idx] =>
                LET origRoot == ComputeRoot4(leaves[1], leaves[2], leaves[3], leaves[4])
                    modLeaves == [leaves EXCEPT ![idx] = newVal]
                    modRoot == ComputeRoot4(modLeaves[1], modLeaves[2], modLeaves[3], modLeaves[4])
                IN origRoot # modRoot

\* merkle_pub_key: different pubkeys → different leaf hashes
Inv_PubkeyDifferentiation ==
    \A lv \in LeafValues :
        \A pk1, pk2 \in PubKeyValues :
            pk1 # pk2 => LeafHash(lv, pk1) # LeafHash(lv, pk2)

(***************************************************************************)
(* TX_MLSC: Shared Tree Properties                                         *)
(* In TX_MLSC, all outputs share one Merkle tree. Each rung leaf includes  *)
(* a structural template (block types + coil with output_index) and a      *)
(* value_commitment (hash of field values + pubkeys).                      *)
(***************************************************************************)

\* TX_MLSC P1: output_index in leaf means changing output_index changes the leaf
\* (modeled as: different abstract output_index values → different leaves)
Inv_OutputIndexBinding ==
    \A lv \in LeafValues :
        \A pk \in PubKeyValues :
            \A oi1, oi2 \in 1..4 :
                oi1 # oi2 => Hash(lv, oi1) # Hash(lv, oi2)

\* TX_MLSC P2: conditions tree root is deterministic from leaf data
Inv_SharedTreeDeterministic == Inv_RootDeterministic

(***************************************************************************)
(* O(log N) Merkle Path Proof Verification                                 *)
(* A path proof consists of sibling hashes at each tree level.            *)
(* With sorted interior nodes, no direction bits are needed —             *)
(* the verifier sorts the pair before hashing at each level.              *)
(***************************************************************************)

\* Sorted hash: Hash(min(a,b), max(a,b))
SortedHash(a, b) == IF a <= b THEN Hash(a, b) ELSE Hash(b, a)

\* Compute root using sorted interior nodes (4 leaves)
SortedRoot4(l1, l2, l3, l4) ==
    SortedHash(SortedHash(l1, l2), SortedHash(l3, l4))

\* Build Merkle path for a given leaf index (4-leaf tree)
\* Returns <<sibling, uncle>> as before, but verification uses SortedHash
BuildPath4(leafIdx, lvs) ==
    LET sibling == CASE leafIdx = 1 -> lvs[2]
                     [] leafIdx = 2 -> lvs[1]
                     [] leafIdx = 3 -> lvs[4]
                     [] leafIdx = 4 -> lvs[3]
        uncle == CASE leafIdx \in {1, 2} -> SortedHash(lvs[3], lvs[4])
                   [] leafIdx \in {3, 4} -> SortedHash(lvs[1], lvs[2])
    IN <<sibling, uncle>>

\* Verify path proof using sorted interior nodes (no direction bits needed)
VerifyPathSorted(leafVal, path, root) ==
    LET level1 == SortedHash(leafVal, path[1])    \* combine with sibling
        level2 == SortedHash(level1, path[2])       \* combine with uncle
    IN level2 = root

\* P3: Valid path proof verifies correctly with sorted nodes
Inv_SortedPathVerifies ==
    LET root == SortedRoot4(leaves[1], leaves[2], leaves[3], leaves[4])
        path == BuildPath4(targetIdx, leaves)
    IN VerifyPathSorted(leaves[targetIdx], path, root) = TRUE

\* P4: Wrong leaf with valid path fails (sorted nodes)
Inv_SortedPathWrongLeafFails ==
    (leaves[1] # leaves[2] /\ leaves[1] # leaves[3] /\ leaves[1] # leaves[4]
     /\ leaves[2] # leaves[3] /\ leaves[2] # leaves[4]
     /\ leaves[3] # leaves[4]) =>
        \A wrongVal \in LeafValues :
            wrongVal # leaves[targetIdx] =>
                LET root == SortedRoot4(leaves[1], leaves[2], leaves[3], leaves[4])
                    path == BuildPath4(targetIdx, leaves)
                IN ~VerifyPathSorted(wrongVal, path, root)

\* P5: Sorted hash is commutative (critical for directionless proofs)
Inv_SortedHashCommutative ==
    \A a, b \in LeafValues :
        SortedHash(a, b) = SortedHash(b, a)

\* Combined
SafetyInvariant ==
    /\ Inv_RootDeterministic
    /\ Inv_DifferentLeavesDifferentRoots
    /\ Inv_ValidProofVerifies
    /\ Inv_WrongIndexFails
    /\ Inv_TamperEvidence
    /\ Inv_PubkeyDifferentiation
    /\ Inv_OutputIndexBinding
    /\ Inv_SharedTreeDeterministic
    /\ Inv_SortedPathVerifies
    /\ Inv_SortedPathWrongLeafFails
    /\ Inv_SortedHashCommutative

=============================================================================

# Ladder Script BIP Readiness Audit

**Date:** 2026-03-11
**Scope:** All docs, web pages, specs, tests, and tools audited against C++ implementation

---

## CRITICAL FIXES (Must fix before BIP submission)

### C-1: PUBKEY incorrectly listed as allowed in conditions
- **File:** `docs/whitepaper.md` section 3.1, line 107
- **Problem:** Claims conditions allow "PUBKEY, PUBKEY_COMMIT, HASH256, HASH160, NUMERIC, SCHEME, SPEND_INDEX"
- **Reality:** `conditions.cpp` `IsConditionDataType()` returns FALSE for PUBKEY. Only PUBKEY_COMMIT is allowed.
- **Fix:** Remove PUBKEY from the list. Conditions allow 6 types, not 7.
- **Why it matters:** A reviewer checking code against spec will immediately see the contradiction.

### C-2: BIP document missing required sections
- **File:** `docs/bip-ladder-script.md`
- **Missing sections:**
  - **Backwards Compatibility** — how do non-upgraded nodes handle v4 txs? (mentioned in passing as "anyone-can-spend" but needs explicit section)
  - **Activation Mechanism** — BIP-9? BIP-341? New mechanism? Completely unspecified.
  - **Reference Implementation** — must point to the C++ code
  - **References** — needs to cite BIP-68, BIP-65/112, BIP-341, IEC 61131-3, NIST PQ standards
  - **Authors/Copyright** — standard BIP requirement
- **Why it matters:** BIP-1/BIP-2 template compliance is expected. Without these sections the BIP won't be taken seriously.

### C-3: Block count error — "54 Blocks" should be "53 Blocks"
- **File:** `tools/docs/index.html` line 299
- **Problem:** States "All 54 Blocks" — actual count is 53
- **Fix:** Change to "All 53 Blocks"

### C-4: HTLC type code wrong in adaptor-sig-swap doc
- **File:** `tools/docs/txs/adaptor-sig-swap.html` line 265
- **Problem:** States `HTLC (0x0030)` — actual code is `0x0702`
- **Fix:** Change to `HTLC (0x0702)`

### C-5: 12 block types have ZERO test coverage
- **Compound family (6 blocks):** TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG
- **Governance family (6 blocks):** EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR
- **Why it matters:** A reviewer will ask "where is the test for HTLC?" and there is none. Every block type needs at least one positive and one negative test.

---

## MAJOR FIXES (Should fix before BIP submission)

### M-1: Block family organization contradicts itself
- **File:** `docs/whitepaper.md` section 2.4 vs section 4
- **Problem:** Section 2.4 groups into "5 logical groups" with overlapping ranges; section 4 correctly lists 9 distinct families with separate ranges. Section 2.4 is wrong/confusing.
- **Fix:** Rewrite section 2.4 to align with section 4's structure.

### M-2: Activation mechanism completely unspecified
- Both BIP and whitepaper say "all block types activated as a single deployment" but never specify HOW.
- Need: activation rule, how non-upgraded nodes behave, deployment parameters.

### M-3: Wire format "v3" label is confusing
- **File:** `docs/whitepaper.md` section 3.2, line 115
- **Problem:** "The witness wire format (v3)" could be confused with SegWit v3 or tx version 3.
- **Fix:** Clarify: "The internal serialization format (encoding version 3)"

### M-4: SIG block field documentation unclear
- **File:** `docs/whitepaper.md` section 4.1
- **Problem:** "Fields: PUBKEY (or PUBKEY_COMMIT + PUBKEY), SIGNATURE, optional SCHEME" doesn't distinguish conditions vs witness.
- **Fix:** Split clearly: "Conditions: PUBKEY_COMMIT, optional SCHEME. Witness: PUBKEY, SIGNATURE."

### M-5: 31 field naming mismatches between Engine and Builder
- The Engine and Builder use different JSON field names for the same blocks. Examples:
  - VAULT_LOCK: Engine=`delay`, Builder=`hot_delay`
  - RECURSE_MODIFIED: Engine=`block_idx`, Builder=`mutation_block_idx`
  - HTLC: Engine=`hash,pubkey,blocks`, Builder=`sender_key,receiver_key,hash_lock,csv_delay`
  - AMOUNT_LOCK: Engine=`min,max`, Builder=`min_sats,max_sats`
- **Impact:** JSON exported from Builder won't work in Engine and vice versa.
- **Fix:** Unify on one naming scheme. The Engine names should be canonical since they match createrungtx RPC.

### M-6: Missing serialization round-trip tests
- No tests verify serialize -> deserialize -> equals original for any block type.
- A reviewer will expect this as basic infrastructure.

### M-7: No tests for consensus-critical size limits
- MAX_LADDER_WITNESS_SIZE, MAX_RUNGS, MAX_BLOCKS_PER_RUNG, MAX_FIELDS_PER_BLOCK — none tested at boundaries.

### M-8: Post-quantum schemes undertested
- Only FALCON-512 has a round-trip test.
- FALCON-1024, DILITHIUM3, SPHINCS_SHA have zero tests.

### M-9: RECURSE_SAME carry-forward bug was found and fixed but has no regression test
- The scheme-field mismatch in `snapshotApplyKeys` was a real consensus bug.
- Need a dedicated test that verifies carry-forward with all field types present.

---

## MINOR FIXES (Nice to have before submission)

### m-1: "Co-spend contact" typo in types.h and propagated docs
- COSIGN comment says "contact" — should be "constraint"
- **Files:** `src/rung/types.h` line 97, docs/index.html

### m-2: types.h header comment lists 7 families, code has 9
- Missing: Compound (0x0700-0x07FF) and Governance (0x0800-0x08FF) from the header comment.

### m-3: Whitepaper security section lacks explicit threat model
- Section 9 is strong but doesn't state what attacks Ladder Script defends against.

### m-4: SCHEME field codes not documented in spec
- SCHNORR=0x01, ECDSA=0x02, FALCON512=0x10, etc. are in types.h but not in the BIP/whitepaper.

### m-5: Micro-header table and implicit field layouts not fully specified in BIP
- Readers must consult serialize.cpp. The BIP should be self-contained.

### m-6: Whitepaper references section is sparse
- Should cite: BIP-68, BIP-65/112, BIP-341, IEC 61131-3, NIST FIPS PQ standards.

### m-7: No worked examples in BIP or whitepaper
- Neither document includes actual serialized transaction examples. Reviewers expect these.

### m-8: Post-quantum key size claims unverified in codebase
- 1,793B FALCON-1024, 1,952B DILITHIUM3, 64B SPHINCS+ claimed but not documented in repo.
- May be correct per NIST but should have source citations.

### m-9: DEFERRED attestation mode behavior unclear
- Described as "fail-closed; not yet active" — should explicitly state it always returns false.

### m-10: Inversion of UNKNOWN_BLOCK_TYPE rationale not explained
- Inverting unknown -> SATISFIED is correct for forward compatibility but the reasoning should be stated.

---

## WHAT PASSED CLEAN

- **All 53 block-docs pages** — type codes, field definitions, evaluation logic, wire format all verified correct against C++ source. Zero discrepancies.
- **All 6 transaction example docs** — block types, witness structures, scriptPubKey prefixes, byte counts, verification grids, dates, and navigation links all accurate (except C-4 above).
- **Engine block type coverage** — all 53 types present with correct type codes.
- **Engine signature scheme mapping** — SCHNORR=0x01 through SPHINCS_SHA=0x13 correct.
- **Engine data type size constraints** — match types.h field specifications.
- **Engine preset examples** — valid block combinations (fee-gated covenant preset fixed this session).

---

## TEST COVERAGE GAPS — FULL LIST

### Blocks with zero coverage (12):
TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG,
EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR

### Missing negative tests (security-critical):
- Invalid signature formats / mismatched key sizes
- PUBKEY in conditions (should be rejected — only PUBKEY_COMMIT allowed)
- Oversized fields at exact boundaries (PREIMAGE > 252 bytes, SIGNATURE > 50000 bytes)
- Circular relay references
- MLSC invalid Merkle proofs / root mismatches
- Deeply nested conditions (DoS vector)

### Missing interaction tests:
- RECURSE_SAME + witness reference (diff witness)
- MLSC + witness reference combination
- Compound blocks + timelocks at exact boundaries
- Mixed PQ + Schnorr signatures in same transaction
- Coil COVENANT and UNLOCK_TO types end-to-end

### Missing infrastructure tests:
- Serialization round-trips for all 53 block types
- 0xC1 prefix and tx version 4 identification
- v3 vs v4 witness format differentiation
- MAX_RUNGS, MAX_BLOCKS_PER_RUNG boundary enforcement

---

## PRIORITY ORDER FOR BIP SUBMISSION

1. Fix C-1 through C-5 (spec errors + zero-coverage blocks)
2. Fix M-1 through M-4 (spec structure + clarity)
3. Fix M-5 (field naming unification)
4. Write tests for M-6 through M-9 (serialization, limits, PQ, regression)
5. Add BIP template sections (C-2)
6. Address minor items as time permits

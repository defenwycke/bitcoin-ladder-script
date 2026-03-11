# Ladder Script BIP Readiness Audit

**Date:** 2026-03-11
**Scope:** All docs, web pages, specs, tests, and tools audited against C++ implementation

---

## FIXED (commit `6c98ba6`)

- **C-1** FIXED: PUBKEY removed from allowed condition types in whitepaper + BIP (only PUBKEY_COMMIT)
- **C-3** FIXED: "54 Blocks" → "53 Blocks" in docs index
- **C-4** FIXED: HTLC type code 0x0030 → 0x0702 in adaptor-sig-swap doc
- **M-1** FIXED: Whitepaper section 2.4 now lists all 9 families with correct ranges
- **M-3** FIXED: Wire format "(v3)" clarified as "serialization encoding version 3"
- **M-4** FIXED: SIG block now clearly separates conditions (PUBKEY_COMMIT, SCHEME) vs witness (PUBKEY, SIGNATURE)
- **m-1** FIXED: "Co-spend contact" → "constraint" in types.h, BIP, whitepaper, block-docs, docs index (all instances)
- **m-2** FIXED: types.h header comment now lists all 9 families with block type names
- **m-4** FIXED: SCHEME field codes documented in whitepaper section 5.1
- **m-9** FIXED: DEFERRED attestation explicitly documented as always-false
- **m-10** FIXED: UNKNOWN_BLOCK_TYPE inversion rationale explained
- **Extra** FIXED: PQ key size range 2,420 → 1,952 bytes on info page
- **Extra** FIXED: Compound block "8-16 bytes savings" claims replaced with precise description
- **Extra** FIXED: BIP data types table PUBKEY context corrected to "Witness only"
- **Extra** FIXED: PUBKEY marked "(witness only; conditions use PUBKEY_COMMIT)" in whitepaper data types table

---

## REMAINING — BEFORE BIP SUBMISSION

### Critical

#### C-2: BIP missing activation mechanism
- The BIP has Backwards Compatibility, Rationale, Reference Implementation, Security Considerations, and Copyright sections (agent initially reported these missing — they exist).
- **Still missing:** Explicit activation mechanism. "All block types activate as a single deployment" but doesn't specify BIP-9 signaling, height-locked, flag day, or other mechanism.
- **Action:** Add a "Deployment" subsection to the BIP specifying the soft fork activation method.

#### C-5: 12 block types have ZERO functional test coverage
- **Compound family (6):** TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG
- **Governance family (6):** EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR
- **Action:** Write at least 1 positive + 1 negative test per block type in `rung_basic.py`.

### Major

#### M-5: 31 field naming mismatches between Engine and Builder
- Engine and Builder use different JSON field names for the same blocks:
  - VAULT_LOCK: Engine=`delay`, Builder=`hot_delay`
  - RECURSE_MODIFIED: Engine=`block_idx`, Builder=`mutation_block_idx`
  - HTLC: Engine=`hash,pubkey,blocks`, Builder=`sender_key,receiver_key,hash_lock,csv_delay`
  - AMOUNT_LOCK: Engine=`min,max`, Builder=`min_sats,max_sats`
- **Impact:** JSON exported from Builder won't work in Engine and vice versa.
- **Action:** Unify on Engine names (they match createrungtx RPC).

#### M-6: Missing serialization round-trip tests
- No tests verify serialize → deserialize → equals original for any block type.
- **Action:** Add round-trip tests for all 53 block types.

#### M-7: No tests for consensus-critical size limits
- MAX_LADDER_WITNESS_SIZE, MAX_RUNGS, MAX_BLOCKS_PER_RUNG, MAX_FIELDS_PER_BLOCK — none tested at boundaries.
- **Action:** Add boundary tests.

#### M-8: Post-quantum schemes undertested
- Only FALCON-512 has a round-trip test.
- FALCON-1024, DILITHIUM3, SPHINCS_SHA have zero tests.
- **Action:** Add round-trip tests for each PQ scheme.

#### M-9: RECURSE_SAME carry-forward needs regression test
- The scheme-field mismatch in `snapshotApplyKeys` was a real consensus bug (fixed this session).
- **Action:** Add a dedicated test verifying carry-forward with all field types present.

### Minor

#### m-3: Whitepaper security section lacks explicit threat model
- Section 9 doesn't explicitly name the attack classes defended against.

#### m-5: Micro-header table not fully specified in whitepaper
- Readers must consult serialize.cpp. The BIP has the full table but the whitepaper doesn't.

#### m-6: Whitepaper references section is sparse
- Should cite: BIP-68, BIP-65/112, BIP-341, IEC 61131-3, NIST FIPS PQ standards.
- (The BIP already cites these — whitepaper could reference the BIP.)

#### m-7: No worked examples in whitepaper
- Neither doc includes actual serialized transaction hex examples.
- (The tx example docs on the website serve this purpose but aren't in the BIP.)

#### m-8: Post-quantum key size claims lack source citations
- 1,793B FALCON-1024, 1,952B DILITHIUM3, 32B SPHINCS+ — correct per NIST FIPS 204/206 but should cite standards.

---

## WHAT PASSED CLEAN

- **All 53 block-docs pages** — type codes, field definitions, evaluation logic, wire format all verified correct. Zero discrepancies.
- **All 6 transaction example docs** — block types, witness structures, scriptPubKey prefixes, byte counts, verification grids, dates, nav links all accurate.
- **Engine block type coverage** — all 53 types present with correct type codes.
- **Engine signature scheme mapping** — SCHNORR=0x01 through SPHINCS_SHA=0x13 correct.
- **Engine data type size constraints** — match types.h field specifications.
- **Ladder-script info page** — 53 block types verified, all families correct, all codes correct. Only 1 error found (PQ key size, now fixed).
- **BIP document** — has Rationale, Backwards Compatibility, Reference Implementation, Security Considerations, Test Vectors, Copyright sections. Wire format fully specified with micro-header table. Much more complete than initially reported.

---

## TEST COVERAGE GAPS — FULL LIST

### Blocks with zero functional test coverage (12):
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
- MAX_RUNGS, MAX_BLOCKS_PER_RUNG boundary enforcement

---

## PRIORITY ORDER FOR BIP SUBMISSION

1. Write tests for C-5 (12 untested block types — ~24 tests minimum)
2. Add activation mechanism to BIP (C-2)
3. Unify Engine/Builder field names (M-5)
4. Write round-trip serialization tests (M-6)
5. Write size limit boundary tests (M-7)
6. Write PQ scheme tests (M-8)
7. Add RECURSE_SAME regression test (M-9)
8. Address minor items as time permits

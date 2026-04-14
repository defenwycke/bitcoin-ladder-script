# Ladder Script

A typed transaction format for Bitcoin, derived from industrial PLC ladder logic.

**[Full overview, examples, and live playground](https://ladder-script.org/)** | **[Ladder Engine](https://ladder-script.org/ladder-engine.html)** | **[QABIO Playground](https://ladder-script.org/qabio-playground/)** | **[Block Reference](https://ladder-script.org/block-docs/)**

```
  RUNG 0: ──[ SIG: Alice ]──[ CSV: 144 ]──────────────( UNLOCK )──
  RUNG 1: ──[ MULTISIG: 2-of-3 ]──────────────────────( UNLOCK )──
  RUNG 2: ──[ /CSV: 144 ]──[ SIG: Bob ]───────────────( UNLOCK )──   ← breach remedy
```

Bitcoin Script is a stack machine where every element is an opaque byte array. A public key, a hash, a timelock, and a JPEG are indistinguishable at the protocol level. Each new capability requires a new opcode, a soft fork, and years of coordination.

Ladder Script replaces this with **typed function blocks** organised into **rungs**. Every byte has a declared type. Every condition is a named block with validated fields. Evaluation is deterministic: AND within rungs, OR across rungs, first satisfied rung wins. Untyped data is a parse error — not policy, not non-standard, a *parse error*.

## Status

**Prototype on a private signet.** The protocol runs end-to-end — the Ladder Engine at ladder-script.org lets you build, sign, and broadcast real transactions on the live signet backed by `bitcoin-core-ladder`, a clean Bitcoin Core v30 fork. The QABIO playground successfully broadcasts multi-party FALCON-512 batches.

**Not yet BIP-ready.** The first attempt at formal BIP drafts surfaced enough load-bearing spec gaps (unspecified creation proof, prose-only sighash, consensus rules living in `types.h` rather than the spec) that submission would be premature. The project is currently in an audit phase — hardening the reference implementation and preparing to re-draft the spec as smaller modular BIPs once the consensus rules are locked down.

**Not for mainnet.** This is research-stage protocol work. Don't point real money at it.

## How it works

The name and structure are borrowed from ladder logic, the programming model used in industrial PLCs (programmable logic controllers) for decades. A spending policy is a ladder. Each rung is a possible spending path containing typed condition blocks. Blocks on the same rung are AND — all must be satisfied. Rungs are OR — the first satisfied rung authorises the spend.

The output format is **MLSC** (Merkelized Ladder Script Conditions): a shared 33-byte commitment (`0xDF || conditions_root`) regardless of policy complexity. Only the exercised spending path is revealed at spend time. Unused paths stay permanently hidden.

**TX_MLSC** lifts the commitment from per-output to per-transaction: a single `conditions_root` at the transaction level, shared across all outputs in the same transaction, with each rung's coil declaring its `output_index`. This removes duplicated condition trees in batch payments and is the foundation QABIO builds on.

Transaction version 4 (`RUNG_TX`). Soft fork activation — non-upgraded nodes see v4 as anyone-can-spend, the same upgrade path as SegWit and Taproot.

## What makes it different

**Contact inversion.** Non-key blocks can be inverted. `[/CSV: 144]` means "spend BEFORE 144 blocks" — a primitive Bitcoin has never had. Key-consuming blocks (SIG, MULTISIG, etc.) cannot be inverted, closing the garbage-pubkey data embedding vector. This enables breach remedies, dead man's switches, governance vetoes, and time-bounded escrows natively.

**Anti-spam hardening.** Eleven data types, enforced at the deserialiser before any cryptographic operation. Three coordinated defenses close all practical data embedding surfaces: `merkle_pub_key` folds public keys into the Merkle leaf hash (no writable pubkey field in conditions), selective inversion prevents key-consuming blocks from being inverted, and hash lock deprecation removes standalone preimage blocks. If it doesn't parse as a typed field, it doesn't enter the mempool.

**Post-quantum signatures.** FALCON-512, FALCON-1024, Dilithium3, and SPHINCS+ are native signature schemes, implemented and running on the live signet. A single SCHEME field on any signature block routes verification to classical Schnorr or any PQ algorithm. The COSIGN pattern lets a single PQ anchor protect unlimited child UTXOs. Incremental migration without a flag day.

**Multi-party post-quantum batches (QABIO).** An N-party extension that lets a set of participants settle a single atomic batch transaction under one FALCON-512 coordinator signature. Each participant commits to the batch via a priming transaction, the coordinator assembles the batch and signs once, and the batch either settles atomically or every participant recovers their funds via an escape-rung SIG sweep. `QABI_PRIME` and `QABI_SPEND` are the two new block types that implement the commit-reveal protocol. See [docs/QABIO.md](docs/QABIO.md).

**Wire efficiency.** Compound blocks collapse common multi-block patterns (HTLC, PTLC, TIMELOCKED_MULTISIG) into single blocks. Relays allow shared conditions across rungs without duplication. Template references let inputs inherit conditions with field-level diffs.

**Legacy migration.** Seven legacy block types wrap P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR key-path, and P2TR script-path as typed Ladder Script blocks. Identical spending semantics, fully typed fields. Designed for a three-phase migration: coexistence, legacy-in-blocks, then sunset of raw legacy formats.

## 63 Block Types

| Family | Blocks |
|--------|--------|
| Signature | SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG |
| Timelock | CSV, CSV_TIME, CLTV, CLTV_TIME |
| Hash | TAGGED_HASH, HASH_GUARDED |
| Covenant | CTV, VAULT_LOCK, AMOUNT_LOCK |
| Recursion | RECURSE_SAME, RECURSE_MODIFIED, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_SPLIT, RECURSE_DECAY |
| Anchor | ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE, ANCHOR_SEAL, ANCHOR_ORACLE, DATA_RETURN |
| PLC | HYSTERESIS_FEE, HYSTERESIS_VALUE, TIMER_CONTINUOUS, TIMER_OFF_DELAY, LATCH_SET, LATCH_RESET, COUNTER_DOWN, COUNTER_PRESET, COUNTER_UP, COMPARE, SEQUENCER, ONE_SHOT, RATE_LIMIT, COSIGN |
| Compound | TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG |
| Governance | EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR, OUTPUT_CHECK |
| Legacy | P2PK_LEGACY, P2PKH_LEGACY, P2SH_LEGACY, P2WPKH_LEGACY, P2WSH_LEGACY, P2TR_LEGACY, P2TR_SCRIPT_LEGACY |
| QABIO | QABI_PRIME, QABI_SPEND |

## Try it

- **[Ladder Engine](https://ladder-script.org/ladder-engine.html)** — browser-based visual builder. Load an example from the preset library, switch to SIMULATE, step through evaluation. The RPC tab shows the wire-format JSON. The SIGNET tab lets you fund, sign, and broadcast real transactions on the live signet.
- **[QABIO Playground](https://ladder-script.org/qabio-playground/)** — multi-party batch sandbox. Spin up N participants, prime their UTXOs against a shared QABIO block, build the coordinator-signed batch, and broadcast. Supports the coordinator-bails escape-sweep flow.
- **[Block Reference](https://ladder-script.org/block-docs/)** — visual documentation for every block type.

All three tools talk to the live signet at `ladder-script.org/api/ladder/*`, which reverse-proxies to a `bitcoin-core-ladder` v30 node running the custom consensus rules.

## Repositories

This project is split across two repositories:

- **[defenwycke/bitcoin-core-ladder-script](https://github.com/defenwycke/bitcoin-core-ladder-script)** — reference implementation. A clean fork of Bitcoin Core v30 with `src/rung/` added for the Ladder Script evaluator, serializer, policy, sighash, Merkle commitment code, QABIO extension, PQ signature verification (liboqs), and descriptor language. This is where the C++ code and functional tests live.
- **[defenwycke/bitcoin-ladder-script](https://github.com/defenwycke/bitcoin-ladder-script)** (this repo) — specs, docs, website, and deployment infrastructure.

### What's in this repo

```
tools/             Labs tree — landing page, Ladder Engine, QABIO playground,
                   block-docs, tx preset docs. Deployed to ladder-script.org.
docs/              Markdown specs and guides (see below).
spec/              TLA+ models for consensus-critical invariants.
patches/           Patch files for applying changes against Bitcoin Core v30.
proxy/             FastAPI-based ladder-proxy service for the live signet.
deploy/            nginx vhost, cutover script, and runbook for ladder-script.org.
tests/             Python test scaffolding and fixtures.
scripts/           Build and smoke-test helpers.
```

### What's NOT in this repo

The C++ reference implementation (`src/rung/*`), unit tests (`rung_tests.cpp`), and functional tests (`test/functional/feature_qabi.py`, etc.) live in `bitcoin-core-ladder-script`. When the docs reference source files like `src/rung/evaluator.cpp`, they mean files in the sibling repo.

## Documentation

- [INTRODUCTION.md](docs/INTRODUCTION.md) — what Ladder Script is and why
- [BLOCK_LIBRARY.md](docs/BLOCK_LIBRARY.md) — all block types with fields and semantics
- [BLOCK_LIBRARY_IMPL.md](docs/BLOCK_LIBRARY_IMPL.md) — implementation notes per block
- [TX_MLSC_SPEC.md](docs/TX_MLSC_SPEC.md) — transaction-level MLSC specification
- [QABIO.md](docs/QABIO.md) — N-party PQ batch I/O extension
- [MERKLE-UTXO-SPEC.md](docs/MERKLE-UTXO-SPEC.md) — MLSC Merkle commitment and UTXO layout
- [EXAMPLES.md](docs/EXAMPLES.md) — worked scenarios with RPC JSON
- [ENGINE_GUIDE.md](docs/ENGINE_GUIDE.md) — how to use the visual builder
- [INTEGRATION.md](docs/INTEGRATION.md) — wallet and application integration guide
- [REVIEW_GUIDE.md](docs/REVIEW_GUIDE.md) — recommended reading order for reviewers
- [SOFT_FORK_GUIDE.md](docs/SOFT_FORK_GUIDE.md) — proposed activation path
- [IMPLEMENTATION_NOTES.md](docs/IMPLEMENTATION_NOTES.md) — spec deviations and why
- [POSSIBILITIES.md](docs/POSSIBILITIES.md) — design space exploration
- [FAQ.md](docs/FAQ.md) — common questions
- [GLOSSARY.md](docs/GLOSSARY.md) — terminology reference

## License

MIT

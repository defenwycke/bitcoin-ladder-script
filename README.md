# Moved

**This repository has moved into the Bitcoin Core fork.**

The entire Ladder Script project — consensus implementation, spec, BIP wireframe, TLA+ models, engine, QABIO playground, block reference, signet proxy, deploy scripts, and the ladder-script.org website source — now lives in a single monorepo:

### → **[github.com/defenwycke/bitcoin-core-ladder-script](https://github.com/defenwycke/bitcoin-core-ladder-script)** (branch `ladder-script`)

### → **[ladder-script.org](https://ladder-script.org)** (live site)

## Why

Two repos had ended up with diverging duplicates of `src/rung/`, the functional tests, the TLA+ specs, and most of the docs. The split cost more attention than it saved. The consensus fork is the natural home for everything — the BIP will reference a library extracted from `src/rung/`, so the spec, the implementation, and the tools all belong in the same tree.

## Where things are now

| What | New location |
|------|--------------|
| C++ consensus (`src/rung/`) | `bitcoin-core-ladder-script:src/rung/` |
| Spec docs + BIP wireframe | `bitcoin-core-ladder-script:doc/ladder-script/` |
| Engine, playground, block reference | `bitcoin-core-ladder-script:tools/` |
| Signet proxy | `bitcoin-core-ladder-script:proxy/` |
| Deploy script for ladder-script.org | `bitcoin-core-ladder-script:deploy/` |
| TLA+ specs | `bitcoin-core-ladder-script:spec/` |
| Functional tests | `bitcoin-core-ladder-script:test/functional/feature_{rung,qabi}_*.py` |

The final state of this repo before the migration is tagged at commit `6f3f16c` for forensic reference.

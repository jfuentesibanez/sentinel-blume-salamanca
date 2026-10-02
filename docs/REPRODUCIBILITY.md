# Reproduction and verification

## Read-only checks

`python3 tools/verify_snapshot.py` checks the export's file hashes, publication
inventory, canonical ciphertexts and recorded phase-11 recovery counts. It does
not call a solver, modify frozen data or fetch sources.

With NumPy installed, `python3 tools/recheck_phase11.py` regenerates synthetic
ciphertexts from the sealed truth and holdout positions, and recomputes all 160
archived IDP scores with the independent Python formula from phase11. It checks
the formula, inputs and archived scores. It does not independently recreate
the RNG-generated keys, audit every search operation, reproduce a search or
verify the historical telegrams. Earlier fuller audits are retained as records.

## Building portable solvers

Requires a C++17 compiler, available as `c++` or through the `CXX` environment variable:

```sh
python3 tools/build_solvers.py
```

Builds phase10 baseline, phase11 capped variant and phase7 key-regeneration
helper into `.repro/bin/`. It never replaces the frozen sources, headers,
manifests or original recorded results. It runs no search. The new binaries
will generally have different hashes from the original Mac binaries.

Frozen search commands, seeds, widths and budgets are in each phase's manifests.
Read them and prepare a separate result directory before a future reproduction.
The current helpers do not automatically run those commands.

## Why the old verifiers are not the export verifier

Original verifiers hash the larger working directory, including compiled Mac
executables, cache files or the thesis PDF, and some invoke those executables.
Those assets were not all published. Other frozen scripts contain original
absolute paths. Consequently an unchanged original verification script can fail
in this clone even when all selected source/data files match their original hashes.

Use the export inventory to distinguish omitted files from corrupted retained
files. Do not silently rewrite an original manifest to make a partial export
look like the complete original workspace. New results require new manifests.

## Dependencies

- Standard-library checks: Python3.10+.
- Numerical archive recheck: Python and NumPy (`requirements.txt`).
- C++ rebuilding: C++17 compiler. Standard-library RNG implementation and time
  limits can affect trajectories across platforms.
- Some original document scripts additionally use pypdf/pdfplumber or local
  runtime paths. They are retained records, not required for reading this repo.

Raw Gutenberg texts, language provenance and UD licence files are retained.
Models are literary proxies, not authenticated 1937 commercial-code models.
Keep truth construction/evaluation separate from a ciphertext-only solver.

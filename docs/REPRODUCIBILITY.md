# Reproduction and verification

## Read-only checks

`python3 tools/verify_snapshot.py` checks the current export's file hashes, the
phase 13 baseline and phase 14/15 publication inventories, canonical ciphertexts,
recorded phase 11/14 recovery counts and phase 15 static metadata. It does not call a solver, modify frozen data or fetch
sources.

With NumPy installed, `python3 tools/recheck_phase11.py` regenerates synthetic
ciphertexts from the sealed truth and holdout positions, and recomputes all 160
archived IDP scores with the independent Python formula from phase 11. It checks
the formula, inputs and archived scores. It does not independently recreate
the RNG-generated keys, audit every search operation, reproduce a search or
verify the historical telegrams. Earlier fuller audits are retained as records.

`python3 tools/recheck_phase14.py` is also read-only and requires NumPy. It
regenerates the four synthetic ciphertext pairs from the sealed truth and holdout
positions, recomputes all 160 final archived IDP scores, checks the recorded K2
recovery counts and compares the 16 OFF/ON prefixes. It runs no solver or new
search. Reading synthetic truth here is external evaluation after the searches;
truth remains outside the solver. This helper does not independently recreate
RNG-generated keys, audit every operation or verify the historical telegrams.
The fuller [phase 14 saved-log audit](../work/phase14_root/post_run_audit.json)
and [independent review](../work/phase14_root/post_ejecucion_independiente.txt)
are retained separately.

## Phase 15 recorded-data replay

`python3 tools/recheck_phase15.py` uses only the standard library and writes no
files. It checks the twelve CSVs, every backend marker, reconstructed fixed-anchor
keys, recorded improvement flags and local ranks, and regenerates synthetic
ciphertexts from sealed truth. It performs **zero new IDP evaluations or searches**.
It does not recreate RNG keys, mathematically rescore candidates or replay every
greedy choice. The fuller numerical audit recomputed two states per profile and
is preserved separately, with its 48 backend calls. Every phase 15 anchor is
privileged; these ranks are not a recovery benchmark from unknown keys.

## Publication records

[source_inventory.jsonl](../provenance/source_inventory.jsonl) and
[snapshot.json](../provenance/snapshot.json) remain the phase 13 baseline,
covering 1,720 original research files. Their dates and counts do not describe
the later addition. [phase14_source_inventory.jsonl](../provenance/phase14_source_inventory.jsonl)
and [phase14_update.json](../provenance/phase14_update.json) record the phase 14
addition. The original research files retain their recorded bytes.

[file_hashes.json](../provenance/file_hashes.json) is the current export checksum
record, including updated collaborator documentation. The earlier checksum
record is preserved as [phase13_file_hashes.json](../provenance/phase13_file_hashes.json).
That earlier record describes the baseline, so it will not match documentation
intentionally updated for later phases. A hash establishes byte identity, not the
truth of a result or permission to republish a source.

[phase15_source_inventory.jsonl](../provenance/phase15_source_inventory.jsonl)
and [phase15_update.json](../provenance/phase15_update.json) record the static
diagnostic and historical correction. The phase 14 checksum record is preserved
as [phase14_file_hashes.json](../provenance/phase14_file_hashes.json). Current
entry documents intentionally differ; frozen earlier research files do not.

## Building portable solvers

Requires a C++17 compiler with `__int128` support (GCC or Clang), available as
`c++` or through the `CXX` environment variable:

```sh
python3 tools/build_solvers.py
```

Builds the phase 10 baseline, phase 11 capped variant, phase 14 checkpoint
variant, phase 15 static evaluator and phase 7 key-regeneration helper into `.repro/bin/`. It never replaces
the frozen sources, headers, manifests or original recorded results. It runs no search. The new binaries
will generally have different hashes from the original Mac binaries. The original
phase 14/15 compiled executables are not republished; their hashes remain in the
frozen build and experiment records.

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

- Standard-library checks: Python 3.10+.
- Numerical archive recheck: Python and NumPy (`requirements.txt`).
- C++ rebuilding: C++17 compiler. Standard-library RNG implementation and time
  limits can affect trajectories across platforms.
- Some original document scripts additionally use pypdf/pdfplumber or local
  runtime paths. They are retained records, not required for reading this repo.

Raw Gutenberg texts, language provenance and UD licence files are retained.
Models are literary proxies, not authenticated 1937 commercial-code models.
Keep truth construction/evaluation separate from a ciphertext-only solver.

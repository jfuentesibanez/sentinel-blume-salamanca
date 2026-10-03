# Reproduction and verification

## Read-only checks

`python3 tools/verify_snapshot.py` checks the current export's file hashes, the
phase 13 baseline and phase 14/15/16/17 publication inventories, canonical ciphertexts,
recorded phase 11/14 recovery counts, phase 15 static metadata, phase 16
privileged trajectory metadata and phase 17 saved-log descriptor metadata. It does not call a solver, modify frozen data
or fetch sources.

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

## Phase 16 recorded-trajectory replay

`python3 tools/recheck_phase16.py` uses only the standard library and writes no
files. It checks selected resource hashes and accounts for omitted original
executables through the export inventory. It checks the sealed plan, both
approvals, completed manifest, audit guard, saved audit receipts and evaluation;
regenerates the eight synthetic ciphertexts from saved keys and holdout offsets;
and reconstructs every proposal, acceptance, sweep event, archive and backend
marker from the twenty CSVs. It compares all external Hamming and target metrics,
group totals and eight policy contrasts with the recorded evaluation.

This performs **zero new IDP evaluations or solver trajectories**. It does not
recreate RNG keys, mathematically rescore candidates, repeat the independent
audit or reproduce a search. Its source-copy replay assertions require running
Python without `-O`. Every start is privileged. Main B 8/8 versus A 6/8 and
positive B 4/4 are separate denominators, not unknown-key recovery rates.

The fuller [numerical audit](../work/phase16_root/post_run_audit.json) sampled
the initial and last evaluated state of each profile: forty exact evaluations,
charged even when a key repeats. It used a direct feasible-offset reference.
All 799,172 trajectory rows were replayed, not all mathematically rescored.
Known cost remains 732,572 main + 66,600 scientific positives + 40 audit =
799,212 IDP-equivalent calls; mock policy controls and the public replay add zero.

## Phase 17 saved-log descriptor replay

`python3 tools/recheck_phase17.py` uses only the standard library and writes no
files. It checks the selected phase 17 inventory, the fixed plan's ten input
hashes, approved source, both pre-execution reviews, execution/launcher receipts,
and saved root and independent audits. It loads only the approved `compute(root)`
definitions and their dependencies from source text, without running the writer
CLI or creating bytecode caches. It recomputes deterministic descriptors from
four saved CSVs, four summaries, saved geometry and phase 16's external evaluation,
then compares `analysis.json` and `comparison.csv` with those results.

The replay reads **no truth file, model or ciphertext** and invokes no RNG,
scorer, solver, subprocess or network. It adds **zero IDP evaluations, truth-score
calculations, trajectories or searches**. The recorded root guard protected
3,151 files in the original workspace; the public replay checks only the exported
selection and original read hashes, not the complete local baseline. The saved
baseline manifest may be checked as a preservation record without requiring all
its listed files in the clone. Run Python without `-O`.

This is a post hoc descriptive reading of two outcome-selected failed A paths
and their paired B paths, totalling 183,143 existing rows. It introduces no new
recovery rate and does not establish a global barrier or rule out other routes.
The source move catalogue has 16,649 distinct neighbours at each final A key;
all are lower in score and no direct join to a recorded B current state was found.
Phase 16 remains the latest experiment and its known total stays 799,212.
See the [fixed plan](../work/phase17_records/plan.json),
[analysis receipt](../work/phase17_records/run_receipt.json) and
[independent audit](../work/phase17_review/post_ejecucion_independiente.json).

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

[phase16_source_inventory.jsonl](../provenance/phase16_source_inventory.jsonl)
and [phase16_update.json](../provenance/phase16_update.json) record the trajectories,
audits and bounded catalogue-access notes. The previous checksum record is
preserved as [phase15_file_hashes.json](../provenance/phase15_file_hashes.json).
Phase 16 protected 2,793 files in the original local baseline, including existing
public copies. That count does not describe the number of files in this export.

[phase17_source_inventory.jsonl](../provenance/phase17_source_inventory.jsonl)
and [phase17_update.json](../provenance/phase17_update.json) record the saved-log
reading, approvals, audits and bounded BOE notes. The previous checksum record
is preserved as [phase16_file_hashes.json](../provenance/phase16_file_hashes.json).
Frozen phase 16 inputs, sources, plans, results and earlier research retain their bytes;
only current entry documents and public verification tools receive new versions.

## Building portable solvers

Requires a C++17 compiler with `__int128` support (GCC or Clang), available as
`c++` or through the `CXX` environment variable:

```sh
python3 tools/build_solvers.py
```

Builds the phase 10 baseline, phase 11 capped variant, phase 14 checkpoint
variant, phase 15 static evaluator, phase 16 trajectory evaluator and phase 7
key-regeneration helper into `.repro/bin/`. It never replaces
the frozen sources, headers, manifests or original recorded results. It runs no search. The new binaries
will generally have different hashes from the original Mac binaries. The original
phase 14/15/16 compiled executables are not republished; their hashes remain in the
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

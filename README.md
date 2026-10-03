# BLUME SALAMANCA — The Independent Sentinel

Historical and cryptanalytic research into two encrypted telegrams sent from
Zurich to **BLUME SALAMANCA on 8 January 1937**. A project by Javier Fuentes for
[The Independent Sentinel](https://theindependentsentinel.substack.com/).

**Status, 3 October 2026: unsolved.** No verified plaintext, key or identification
of BLUME. Historical evidence, hypotheses and synthetic experiments are kept
separate. The latest numbered research checkpoint is **phase 17**, a post hoc reading
of two selected failed A paths and their paired B paths saved in phase 16.
It read 183,143 existing rows with zero new IDP calls or trajectories. Both
final A keys are strict local maxima over the 16,649 source neighbours, with
no direct joins to recorded B current states; this does not establish a global
barrier or exclude other routes. **Phase 16 remains the latest experiment.**
From privileged Hamming-4/8 starts on four new synthetic cases, best-improvement policy B ended
at K2 in **8/8** main trajectories and immediate-update A in **6/8**. B used
about 20% more main calls; four separate positive controls ended at K2 in 4/4.
This is local evidence from starts derived from the truth, not recovery from
unknown keys. The known phase 16 cost is 799,212 IDP calls including controls
and the numerical audit. The earlier phase 15 static diagnosis and phase 14
pilot with 32 runs and zero K2 recoveries remain preserved. Kent's verified
serial-to-roll mapping and the telegram-629 erratum stand; bounded Internet
Archive catalogue queries supplied no new target document. Three bounded
phase 17 BOE web queries, over two calls and zero document openings, supplied
no BLUME identification and do not establish absence from the historical corpus.

A separate **3 October 2026 historical follow-up** reached the official Gazeta
form directly: Texto/DOC with submitted publication dates 1936–1938 returned
no BLUME documents. Salamanca as a response control declared 2,471 results;
50 records arrived, 20 metadata records were read, and one 1938 control PDF
was checked on two pages. This approximate search supplies no BLUME identity
or corpus-absence finding. It added zero IDP calls or cryptanalytic experiments.
See the [direct Gazeta note](work/primary_history_20261003/resultado_directo_gazeta.txt).

A later [review with Claude, in Spanish](outputs/Sentinel_BLUME_revision_Claude_2026-10-03.txt)
checked its critique against saved values and static code with zero new scoring.
Two exchanges completed; Claude declared reading three files, not the phase 16
source or all thirteen supplied links. The final short correction, pending then, was later sent once and accepted
after Javier supplied a new access signal. See the [closure note](outputs/Sentinel_BLUME_cierre_revision_Claude_2026-10-03.txt). The proposed SHAB/FOSC route yielded an institutional
guide and one failed follow-up HTTP request; no corpus query or commercial
notice was read. This adds no historical identity or cryptanalytic experiment.

## Start here

1. [Context for Claude and other collaborators](docs/CONTEXT_FOR_CLAUDE.md): the
   case, established facts, open questions and the most useful next tasks.
2. [Current research status](docs/STATUS.md): results and limits of the latest phases.
3. [Latest checkpoint report, in Spanish](outputs/Sentinel_BLUME_fase17_2026-10-03.txt);
   [latest experiment report](outputs/Sentinel_BLUME_fase16_2026-10-03.txt).
4. [Sources and archival references](docs/SOURCES.md).
5. [Reproduction and verification](docs/REPRODUCIBILITY.md).

For a browser-only review, reading the context and status is enough to begin.
For a code or data audit, clone the repository and use the paths below. Merely
opening this URL does not give a model automatic access to every file.

## Canonical ciphertexts

The files contain lowercase ASCII letters without spaces or a trailing newline.
The normalized hashes below use **uppercase letters without whitespace**.

| Message | Body | File | Normalized SHA-256 |
| --- | ---: | --- | --- |
| T1 | 615 letters, 123 groups | [ct1.txt](work/source/ct1.txt) | `e266615d92019276513c1b7656f10c4f1a3d1e8eb739d28fd481ae337a434c55` |
| T2 | 160 letters, 32 groups | [ct2.txt](work/source/ct2.txt) | `8fd5cfb82fc3c39fe0ee007b19ada7e74b4ae7747cd9b794d36dce101e17a644` |

Readings corrected in T1: group 38 `SOLRS`, group 48 `ACCEL`, group 122 `FTULX`.
Group 113 is `RBEEP`. The address is outside these body lengths.

## Repository map

| Path | Contents |
| --- | --- |
| `docs/` | Entry points written for collaborators; current interpretations |
| `work/source/` | Canonical ciphertexts and upstream provenance |
| `work/history/` | Selected research notes, catalogue metadata, source ledgers and archival references |
| `work/crypto/`, `work/phase*_crypto/` | Code, designs, recorded experiments, evaluation results and audits |
| `work/phase17_records/`, `work/phase17_review/` | Post hoc descriptors of four saved phase 16 paths; plan, approvals and audits |
| `work/phase5_language/`, `work/languages/` | Literary language models, holdouts and additional corpus data |
| `work/phase12_claude/`, `work/phase13_claude/` | Proposed next experiment and our critical review of Claude's suggestions |
| `outputs/` | Research reports and selected earlier deliverables |
| `provenance/` | Inventory of the original workspace and explicit publication decisions |
| `tools/` | Portable snapshot verification and rebuilding helpers |

The latest documents in `docs/` describe our current conclusions. Older reports,
upstream notes and failed experiments are historical records, with their own
dates and scopes. In particular, upstream claims excluding languages or broad
cipher families **are not established conclusions of this project**.

## Verify the snapshot

Requires Python 3.10 or newer. This check does not run a cryptographic search:

```sh
python3 tools/verify_snapshot.py
```

Optional numerical recheck of the 160 archived phase-11 IDP scores, using NumPy:

```sh
python3 -m pip install -r requirements.txt
python3 tools/recheck_phase11.py
python3 tools/recheck_phase14.py
```

Standard-library replays of recorded keys, decisions, ranks and costs:

```sh
python3 tools/recheck_phase15.py
python3 tools/recheck_phase16.py
python3 tools/recheck_phase17.py
python3 tools/recheck_gazeta_20261003.py
```

These replays perform no objective scoring or new search. Phase 15 anchors and
phase 16 starts are privileged. The phase 16 replay reconstructs all trajectory
events and target metrics from saved records; it does not repeat the numerical audit.
The phase 17 helper verifies the selected export and recomputes saved-log
descriptors only, without truth, models, RNG, scorers or the complete local baseline.
The Gazeta helper checks own saved receipts, counters and published hashes;
it reads no referenced external bodies or images and performs no HTTP request.

See [REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md) before running any older script.
Some frozen scripts check files or executable hashes from the original Mac
workspace, or contain its absolute paths. They are not portable entry points.

## Scope of publication

This is a public research export, not a recursive upload of the original
workspace. It retains our analyses, transcriptions, experiment inputs and outputs,
models, code and licensed reference material. Duplicate output packages are
mapped in the inventory rather than uploaded repeatedly.

External scans and full recent publications are linked instead of republished.
The ADAP digitization explicitly declares `In Copyright`; the local BAR
manifests did not establish a redistribution licence. Account operations,
correspondence packages, app-interface captures, caches and old ZIP files are
outside this export. Every original research-workspace file is accounted for in
[source_inventory.jsonl](provenance/source_inventory.jsonl), with its hash,
publication decision and retained location or source references where available.

The original phase-13 inventory and snapshot remain baseline records. The
phase-14 selection is recorded separately in
[phase14_update.json](provenance/phase14_update.json) and
[phase14_source_inventory.jsonl](provenance/phase14_source_inventory.jsonl).
Current checksums cover the updated repository; the original checksum manifest
is retained as [phase13_file_hashes.json](provenance/phase13_file_hashes.json).
The phase 15 addition has its own [inventory](provenance/phase15_source_inventory.jsonl)
and [update record](provenance/phase15_update.json). The previous checksum record
is preserved as [phase14_file_hashes.json](provenance/phase14_file_hashes.json).
The phase 16 trajectories and catalogue-access notes have a separate
[inventory](provenance/phase16_source_inventory.jsonl) and
[update record](provenance/phase16_update.json). The phase 15 checksum record is
preserved as [phase15_file_hashes.json](provenance/phase15_file_hashes.json).
The phase 17 saved-log reading and bounded BOE notes have their own
[inventory](provenance/phase17_source_inventory.jsonl) and
[update record](provenance/phase17_update.json). The phase 16 checksum record is
preserved as [phase16_file_hashes.json](provenance/phase16_file_hashes.json).
The subsequent direct Gazeta query has a separate
[inventory](provenance/gazeta_20261003_source_inventory.jsonl) and
[update record](provenance/gazeta_20261003_update.json), without a new cryptanalytic phase.
The phase 17 checksum is preserved as [phase17_file_hashes.json](provenance/phase17_file_hashes.json).

Original research files were not edited to make this export. Retained files
preserve their bytes. Existing manifests still describe the larger original
workspace; the new export verifier checks this repository's selected contents.

## Attribution

Historical discovery and publication routes include Regula Bochsler and Klaus
Schmeh. The transcription and public cryptanalytic discussion include Daniel
Bourdeau, Richard Bean and William Higinbotham; specific claims are attributed
in the source records. Their participation does not imply endorsement of this
repository or our conclusions.

Code and data have several licences. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
No single licence is applied to every external item or to the entire research collection.

The later Claude review and SHAB access attempt have a separate
[inventory](provenance/claude_review_20261003_source_inventory.jsonl) and
[update record](provenance/claude_review_20261003_update.json). The Gazeta checksum
is preserved as [gazeta_20261003_file_hashes.json](provenance/gazeta_20261003_file_hashes.json).

The later delivery closure has its own [inventory](provenance/claude_final_20261003_source_inventory.jsonl)
and [update record](provenance/claude_final_20261003_update.json). The preceding
review checksum is preserved as [claude_review_20261003_file_hashes.json](provenance/claude_review_20261003_file_hashes.json).

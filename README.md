# BLUME SALAMANCA — The Independent Sentinel

Historical and cryptanalytic research into two encrypted telegrams sent from
Zurich to **BLUME SALAMANCA on 8 January 1937**. A project by Javier Fuentes for
[The Independent Sentinel](https://theindependentsentinel.substack.com/).

**Status, 2 October 2026: unsolved.** No verified plaintext, key or identification
of BLUME. Historical evidence, hypotheses and synthetic experiments are kept
separate. The current research checkpoint is **phase 13**.

## Start here

1. [Context for Claude and other collaborators](docs/CONTEXT_FOR_CLAUDE.md): the
   case, established facts, open questions and the most useful next tasks.
2. [Current research status](docs/STATUS.md): results and limits of the latest phases.
3. [Latest detailed report, in Spanish](outputs/Sentinel_BLUME_fase13_2026-10-02.txt).
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
```

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

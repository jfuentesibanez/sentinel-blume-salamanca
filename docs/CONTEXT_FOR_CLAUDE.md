# Context for Claude

This is a research handoff for **The Independent Sentinel**, Javier Fuentes's
newsletter. The assistant working with him is called Sentinel. The aim is to
investigate the history and attempt the decipherment of the BLUME SALAMANCA
telegrams, while keeping evidence and conjecture distinct.

## Established starting point

- Two encrypted telegrams were submitted in Zurich on **8 January 1937**,
  at **11:31** and **17:34**, addressed to **BLUME SALAMANCA**. Bodies contain
  **615** and **160** letters. Canonical files and hashes are in the README.
- The Swiss Federal Archives file is **E4320B#1974/47#277***, a collective file
  about Spain in 1936–1938. PTT's legal service forwarded copies to the Federal
  Prosecutor on **15 January 1937**; its reference **6011.8.3** is an internal
  contemporary reference, not a verified current archival call number.
- Werner Leodegar Oswald was questioned on **28 April 1937**. His office was
  PATVAG, Bahnhofstrasse 12, Zurich. He attributed submission to his brother
  Viktor and suggested a wool transaction intended to recover Swiss export
  balances frozen in Spain, with secrecy from Hisma.
- Werner expressly said he did **not know the content** and **did not have the
  key**. His explanation is testimony and conjecture, not recovered plaintext.
- A project involving Hunziker and bombs appears in a separate question in the
  same interrogation. Its presence does not identify what these telegrams say.
- BLUME remains unidentified: person, firm, registered telegraphic address or
  alias are possibilities. Salamanca supplies the destination, not the identity.

For primary references and reading limits, see [SOURCES.md](SOURCES.md) and the
Spanish [interrogation cotejo](../work/phase13_claude/interrogatorio_cotejo.txt).

## Historical line

Readings in the edited collection ADAP D III supply context about Hisma,
Bernhardt, German-Spanish compensation trade and negotiations in January 1937.
Document 187 is dated 7 January, one day before the telegrams. Temporal
proximity does not establish a particular Oswald/BLUME transaction. Werner's
own mention of Hisma is a separate contemporary testimonial fact.

The old references for documents 187, 180 and 206 use serial/frame numbers.
Phase 14 read the Kent supplement's actual page images and headers: serial
643 → T120, roll 296, p. 778; serial 3176 → T120, roll 1594, p. 793. The second
row explicitly includes 3176 with 3171–3174. The title page identifies volume
III, 1966; the HTML record's year 1962 does not override that image.

The target frames have not yet been read in T120. NARA record 6921696 describes
postwar paper copies of Reich Foreign Office records and lists T120 as an
additional resource. Its “Not Yet Available Online” notice applies to that
series; it does not establish whether rolls 296 or 1594 are accessible online.
No current German archival signature or custodian of an individual original
has been inferred from the conversion.

The official German archive guide assigns 1936–1945 trade-policy records to the
Bundesarchiv as a general orientation. Political records also require the PAAA
route. This does not establish the present custodian of an individual document.

## Cryptanalytic line

Double columnar transposition is a working hypothesis, not an identified cipher.
A commercial codebook, possibly transformed again, remains open. Five-letter
groups alone do not distinguish these systems. All 123 groups in T1 and all 32
in T2 are unique; none are shared. This is descriptive, not a family test.

T2 visibly bears Cde. The Madrid 1932 Telegraph Regulations use CDE for the
administrative category of agreed language and allow artificial words of up to
five letters. This does not identify a codebook or exclude transposition.
Article 41(c)(3) permits adding the indication in transit or at destination with
the origin office's agreement, so its visible absence in T1 does not establish
a different category. The regulations took effect on 1 January 1934; all possible
changes before January 1937 have not been reviewed. The route tariff remains
unverified. Sources and page references are in [SOURCES.md](SOURCES.md).

The recent experiments search **K2 only on synthetic message pairs with known
widths**, using literary German/French models. They do not recover K1 and are
not attacks on the historical ciphertexts. A literary model is not a validated
model of commercial telegram language in 1937.

Phase 14 is the latest completed pilot. Four fresh synthetic German/French pairs
at widths 20 × 25, two rounds and four arms produced 32 runs of 100,000 IDP
calls. A/B used cap 5,000 with checkpoint admission OFF/ON; C/D used cap 33,298
with OFF/ON. Each arm recorded **0/8** exact K2 recoveries in the final top five.

All arms paid to score the common pool at 50,000 calls; only ON offered its
survivors as parents. There were no periodic refreshes. The design measures
admission of checkpoint survivors as parents with inherited uses, rather than diversity alone
or the complete effect of renewal. Total search cost was 3,200,000 IDP calls;
controls cost 35,253 more, including a preserved failed harness attempt. No run
hit the time limit. All 16 OFF/ON prefixes at the same cap were identical, and
all eight four-arm blocks shared their complete checkpoint pool.

Code, controls, operation replay, numerical scores and hashes passed audit.
The long cap produced 22 observed convergences and the short cap none, but no
recoveries. True K2 scored above every final archived key in all 32 runs. This
is a search limitation on this panel, not proof of a global optimum or validation
of the model for historical commercial telegrams. No method or parameter was
changed after seeing these results. See the [phase 14 report](../outputs/Sentinel_BLUME_fase14_2026-10-03.txt)
and [frozen experiment records](../work/phase14_crypto/).

Phase 11 remains an earlier diagnostic panel: eight synthetic pairs, two rounds,
two methods, 32 runs of 100,000 IDP calls. The population baseline recovered K2
in 2/16 rounds and 1/8 pairs; the variant with cap 5,000 in 3/16 rounds and 2/8 pairs.
All recoveries were German 12 × 15; none were French or 20 × 25. Neither panel
establishes general superiority or excludes a language or cipher family.

## Previous Claude review

Claude Opus 5.5 Medium reviewed a supplied summary. It reported one public
query and no BAR/MDZ image reading. We did not treat that as source verification.
Its NARA citation was independently checked. Its suggested experiment was not
adopted unchanged: without a local cap, processed/converged refresh counters
coincide; with a cap of 20,000, refresh after four fully capped children might
not fit the total budget. A high-scoring shuffled null does not automatically
invalidate a scorer, and six wins out of eight do not establish statistical
superiority. Truth-near starts are privileged diagnostics and need separate cost.

The revised design was implemented, audited, sealed and executed in phase 14.
Claude's comments on boundaries, RNG, costs, use counts and the archive informed
the review before sealing. Claude did not execute the pilot or certify its new
binary. Read [the earlier decisions](../work/phase13_claude/crypto_decisiones_preimplementacion.txt),
[implementation decisions](../work/phase14_crypto/IMPLEMENTATION_DECISIONS.txt)
and [saved-log audit](../work/phase14_root/post_run_audit.json) before proposing
another search. Preserve the failed result and use reserved cases for a new design.

## Useful next tasks

1. Confirm access to T120/296, frames 254221–254222, and T120/1594, frames
   682876–682878 and 682895–682896. Read the frames, especially the attached
   telegram. The Kent rows are already verified. Keep serial, roll, frame and
   current archive signature distinct.
2. Investigate the telegraphic-address interpretation and CDE/tariff evidence,
   or locate a specific codebook tied to Oswald. Cite direct sources and state
   what was read, rather than extrapolating from generic five-letter grouping.
3. Diagnose the phase 14 search failure using its saved logs.
   Any new method needs a new design and reserved cases before another search.
   Keep truth outside the solver and count all objective calls, cuts and preparation
   costs. Avoid tuning on this panel or substituting score for recovery.

When reporting: give exact paths or primary URLs, separate facts/testimony/
hypotheses, scope negative findings, and identify what would verify a proposed
link. A plausible historical story or high-scoring output is not a decipherment.
Do not contact people, purchase material, use personal connectors or run new
searches just because an old document contains such a suggestion.

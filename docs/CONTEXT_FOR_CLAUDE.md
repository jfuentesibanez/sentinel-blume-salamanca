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

Phase 15 corrected an overstatement in the phase 14 report. ADAP document 180
of 1 January 1937 cites the earlier telegram 629 of 31 December 1936 at
3176/682878. Its printed attachment is the protocol at 682877; the citation does
not establish that the telegram itself was physically attached. The telegram
text remains unread and no BLUME link is established. The earlier report is
preserved; use the [new erratum](../work/phase15_history/ERRATA.txt).

Phase 16 established HTTP access to Internet Archive's public catalogue API.
Two query texts led to four requests: two inaccessible web-tool openings and
two successful JSON GETs. The generic query declared 139 results and returned
50 metadata records; the targeted query returned all 26 declared records,
unrelated to the diplomatic rolls. No object page, scan or target telegram was
opened. This is a bounded catalogue result, not proof of general digital absence.
See the [final access note](../work/phase16_history/FINAL_resultado.txt) and
[sources](SOURCES.md). T120/296 and T120/1594 remain unverified digital objects.

Phase 17 made three literal BOE web queries over two calls, seeking BLUME with
Salamanca or 1936/1937 in the Gazeta route. It opened zero original documents.
Most results were outside that route; the sole Gazeta URL was from 1856 and
was not opened. No BLUME identity or absence from the historical corpus follows.
Neither the historical database nor a local Salamanca register was read directly.
See the [bounded BOE note](../work/phase17_history/resultado.txt) and
[query ledger](../work/phase17_history/ledger.json).

A later direct Gazeta round on 3 October 2026 reached the official form and
submitted Texto/DOC with publication-date FPU filters 1936-01-01–1938-12-31.
BLUME returned no documents; the fixed Salamanca control declared 2,471 results.
Only 20 metadata records from the first 50 delivered were read. One 1938 control
PDF, BOE-A-1938-14911, was checked on two pages and contains Salamanca university
affiliations, with no BLUME or Oswald link. The service warns of approximate
historical text results. Neither absence from originals nor OCR sensitivity or
telegraphic-register coverage follows.

The two declared access stages totalled four interface readings, two direct
queries and one original: two observable web openings and five own HTTP requests.
A failed preflight guard added zero HTTP; the original global deadline was retained.
This historical follow-up added zero IDP or cryptanalytic experiments and does
not supersede phases 16/17. See the [direct note](../work/primary_history_20261003/resultado_directo_gazeta.txt),
[ledger](../work/primary_history_20261003/ledger.json) and
[independent review](../work/primary_history_20261003/review_final.txt).

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

The recent experiments examine **K2 only on synthetic message pairs with known
widths**, using literary German/French models. They do not recover K1 and are
not attacks on the historical ciphertexts. A literary model is not a validated
model of commercial telegram language in 1937.

Phase 17 is the latest research checkpoint. It describes the two failed A paths
and their paired successful B paths already saved in phase 16: German case
20262401/H8 and 20262402/H4. These outcome-selected cases make this an exploratory
post hoc reading. Its plan was fixed before aggregation; it is not a new
confirmatory experiment or recovery-rate panel.

The reading checked 183,143 existing CSV rows. Each final A key is a strict local
maximum over all 16,649 distinct source neighbours: all lower, none equal or
higher. Any nonidentity first source move lowers the score at these keys. The
recorded comparison found no direct join from those final neighbourhoods to B's
recorded current states; A visited only B's initial state, with no shared later
current state. No recorded route witness was found. These facts do not prove
no escape route, a global barrier height, minimum-loss route or global optimum.

Both A paths first accepted source move 1 at call 2. B's first choices were
moves 3,418 and 6,349, evaluated at calls 3,419 and 6,350 and adopted at call
16,650. The common scored prefix ends with A's first acceptance; later row
indices use different bases. Selection and updating remain intertwined.

The approved source, plan, receipts and independent audit all bind their hashes.
No IDP, truth-score calculation, RNG, solver trajectory or search was added,
and no truth/model input was read. The known phase 16 cost remains 799,212;
its outcomes and positive-control denominator are unchanged. Read the
[phase 17 report](../outputs/Sentinel_BLUME_fase17_2026-10-03.txt),
[fixed reading plan](../work/phase17_records/plan.json),
[analysis](../work/phase17_records/analysis.json),
[comparison table](../work/phase17_records/comparison.csv) and
[independent audit](../work/phase17_review/post_ejecucion_independiente.json).

Phase 16 is the latest completed experiment: privileged local trajectories
from Hamming-4/8 starts derived from true K2, on four fresh cases at widths
20 × 25. Four distinct seeds produced four key pairs and four text offsets.
Each case has two nested starts and two policies, so sixteen main trajectories
form eight paired comparisons on four cases, not sixteen independent samples.

A accepts strict exact-score improvements immediately and continues the sweep.
B scores neighbours of a fixed sweep-start key and accepts the greatest strict
improvement at the end of a complete sweep, with the first source index on ties.
Both use the same fixed order of 16,649 source moves, without shuffle. Selection
and updating change together; the test does not isolate order or reproduce the
source's shuffled HC or the phase 14 algorithm. Hamming counts differing positions;
two/four construction swaps give upper bounds on graph distance, not exact distances.

B ended at K2 in **8/8 main trajectories**, A in **6/8**: B 4/4 and A 3/4
at each start class. All recorded target-visited and final-top-five outcomes
coincided with those final-key outcomes in this panel; the metrics remain
separate. Four one-swap positive controls, B 4/4, are excluded from 8/8.
Their success was not an execution gate or grounds for changing the main cases.

A used 332,988 main exact calls; B 399,584, about 20% more. Main calls totalled
732,572; positives added 66,600 and the direct numerical audit 40: **799,212
known IDP-equivalent calls**. Mock controls used 78 callbacks and zero IDP;
external evaluation and record replay used zero IDP. All twenty trajectories
completed without time cuts, process failures or partial sweeps. Every row and
backend marker was replayed; only the fixed forty selections were mathematically
rescored by the independent direct-offset reference.

Two final-key comparisons favoured B and six succeeded with both policies.
The failed A paths observed complete sweeps without improvement; K2 was never
evaluated there. A adopted K2 earlier in all six pairs where both succeeded;
B evaluated it earlier in two of them. Its H8 successes
had three improving sweeps and no subsequent stable sweep, so success does not
certify convergence. Eleven convergence flags differ from the four `converged`
stop reasons; sixteen stops were call limits. These are separate recorded facts.

This supports local paths under this panel, not random-key attraction, general
superiority of B, language-specific rates, global optimality, an explanation of
the phase 14 failures, K1/plaintext recovery or historical decipherment. Literary
holdouts and distinct offsets are not authenticated commercial telegram models
or guarantees of linguistic independence. Read the [phase 16 report](../outputs/Sentinel_BLUME_fase16_2026-10-03.txt),
[plan](../work/phase16_crypto/plan20.json), [evaluation](../work/phase16_crypto/evaluation.json)
and [independent review](../work/phase16_root/post_ejecucion_independiente.txt).

Phase 14 is an earlier search pilot. Four fresh synthetic German/French pairs
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

Phase 15 is an earlier privileged STATIC landscape test.
Four fresh cases at 20×25 used two distinct key pairs and four plaintext offsets.
It received planted-key-derived anchors: true K2, native swap (0,1), omitted swap
(1,24). Each anchor and its 16,649 source neighbours were scored without moving
the anchor, by legacy and exact dyadic formulas. No unknown-key search ran.

The 12 complete profiles cost 399,600 backends, plus 9 artificial controls and
48 independently recomputed audit backends. True K2 was the strict local maximum
from all four true anchors and first-ranked from all four native swaps. It cannot
appear in the omitted-swap one-step set. Best omitted-profile states still have
Hamming 2; higher IDP can move farther away in Hamming. Hamming is not graph distance.

The formula error reached 1.41169e-9 IDP, above epsilon, but no measured
anchor-improvement decision or greedy edge changed across 199,800 states, and
the local top-five lists matched. This scopes the arithmetic concern; it does
not rule out effects in another trajectory. The exact lattice spacing is
1/(760×2^23), larger than 1e-12. The source set omits 22 simple swaps but each
omitted swap is reachable in two steps; the graph is connected. No causal
explanation of phase 14's failures or historical cipher exclusion follows.

Read [the phase 15 report](../outputs/Sentinel_BLUME_fase15_2026-10-03.txt),
[frozen plan](../work/phase15_crypto/plan12.json),
[evaluation](../work/phase15_crypto/evaluation.json) and
[independent post-run audit](../work/phase15_root/post_ejecucion_independiente.txt).
The additional two-step reading in the report is explicitly post-hoc geometry
of saved states, not a preregistered primary metric or an executed trajectory.

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

No fresh Claude consultation occurred in phase 15: Computer Use could not access
the locked Mac. Its plan/code and saved records were independently reviewed by
the internal team. Do not attribute those reviews or the phase 15 run to Claude.
No new Claude consultation occurred in phase 16 either. The Mac remained locked,
and there was no new attempt to access it. Phase 16 design, execution and audits
are internal Sentinel work; no Claude approval or certification is claimed.
The phase 17 saved-log reading and audits also had no fresh Claude consultation.

## Useful next tasks

1. Confirm access to T120/296, frames 254221–254222, and T120/1594, frames
   682876–682878 and 682895–682896. Read the frames, especially the earlier
   telegram 629 cited by ADAP document 180. The Kent rows are already verified. Keep serial, roll, frame and
   current archive signature distinct.
2. Investigate the telegraphic-address interpretation and CDE/tariff evidence,
   or locate a specific codebook tied to Oswald. Cite direct sources and state
   what was read, rather than extrapolating from generic five-letter grouping.
3. Study entry to the local region from starts without a known key, or routes
   beyond the intersections described in phase 17. Any new scoring needs a fresh
   design and reserved cases. Count all calls, cuts, preparation and failed
   attempts. Declare privileged starts and keep them separate from ciphertext-only
   recovery. Preserve phase 15/16 budgets, swaps and move orders and phase 17
   descriptors; do not tune on their known solutions.

When reporting: give exact paths or primary URLs, separate facts/testimony/
hypotheses, scope negative findings, and identify what would verify a proposed
link. A plausible historical story or high-scoring output is not a decipherment.
Do not contact people, purchase material, use personal connectors or run new
searches just because an old document contains such a suggestion.

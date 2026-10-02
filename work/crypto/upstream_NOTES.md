# "BLUME SALAMANCA" telegrams, Zurich → London, 8 January 1937 — attempted, not solved (third session, 15–16 Sept 2026)

Two telegrams were sent from Zurich via London (one annotated *via Angleterre Eastern*) to Spain on 8 January
1937. Both begin *BLUME SALAMANCA*, most likely a telegraphic address (Blume, Salamanca) followed by five-letter
groups. The historian Regula Bochsler found them in the Swiss Federal Police files on Werner Oswald, founder of
the Emser Werke (*Nylon und Napalm*, 2022), and Klaus Schmeh posted them on Facebook. Oswald told the police
they concerned "wool business" in Spain; Bochsler doubts that, given his ties to Franco's side. Salamanca was
Franco's headquarters in January 1937.

**Status: in progress (30 Sept 2026).** The second telegram (160 letters) is now in hand and transcribed (below), and
a joint attack on both telegrams is under way; the rest of this section is the state after the September sessions.

**Before 30 Sept: not solved, and set aside.** No plaintext has been recovered. The cipher is a transposition of what
looks like telegraphic Spanish. Every transposition family that a single 615-letter message can be tested for
with methods proven on planted controls has been excluded. What remains is the family the evidence points to
anyway, a double columnar transposition with two keys of eleven letters or more, and a single message of this
length is below what any method known to us can break without a crib or a second message in the same key.

## Transcription

The first telegram's photograph was retrieved from Schmeh's Facebook post at 1,134 × 1,012 px (`telegram1.jpg`);
the second telegram is not in the post's public preview (it was found on 30 Sept 2026, below). `tg.py` holds
**123 groups, 615 letters** (`ct1.txt`). The transcription checks against the form: 123 groups + BLUME +
SALAMANCA = **125 words**, the figure written in the *Wörter* box, with the pencilled (50) and (100) at the
right groups. Group 113 (`RBEEP`, word 115) has a red stroke through it but is counted. (Earlier versions of these
notes said group 121: the form's own count, with (50) at ACCEL and (100) at TNCEN, puts RBEEP at 113.)

**Corrected 30 Sept 2026 (GitHub issue 14, Richard Bean).** Three letters were misread as I where the typewriter
has L (its L carries a serif only at the foot, its I at both ends): groups 38, 48 and 122 are **SOLRS**, **ACCEL**
and **FTULX**, not SOIRS, ACCEI and FTUIX. All three are clear on the photograph, and a re-reading of all 123 groups
at twice the size found no other difference. With the correction, the SHA-256 of the 615 letters (upper case, no
spaces) is `e266615d92019276513c1b7656f10c4f1a3d1e8eb739d28fd481ae337a434c55`, the value Bean gives, so his
transcription and ours now agree letter for letter. His issue also gives the SHA-256 of a 160-letter text,
`8fd5cfb82fc3c39fe0ee007b19ada7e74b4ae7747cd9b794d36dce101e17a644`, which matches no 160-letter stretch of this
telegram, with or without BLUME SALAMANCA; it is the second telegram (next paragraph).

**The second telegram (30 Sept 2026).** Bean then pointed to the full image of Schmeh's post, which the public
preview crops, at a Facebook image-server address that needs no login (saved as `telegram2.jpg`, 2,048 × 1,376 px;
the address expires on 5 Oct 2026). He adds that the top comment on the post, by William Higinbotham, carries a
transcription matching his hash (not seen here: the comments need a login). Form: stamp "I A* 14.00z – 1486 –
8 JAN 37", office 910 Zurich, *via angleterre Eastern* in pencil, fee 14 fr, "Cde" stamp, handed in 17 34, passed
to London Mcl. at 17 40; sender "Dr ing. W. E. Oswald, Bureau Bahnhofstr 12, Zürich". So it went the same afternoon
(no. 1, serial 1381, fee 49.90, went at 11 31 / 11 42). BLUME SALAMANCA and **32 groups, 160 letters** (`tg.py`
T2, `ct2.txt`), read from the image; the SHA-256 of the 160 letters is Bean's value exactly, so the transcription
agrees with his letter for letter. Index of coincidence 0.071 (no. 1: 0.0695), top letters a 23, e 19, r 15, n 14,
o 11, i 11, no q, k, w or x: another transposition of Spanish-like text.

```
NOCUO APMOE PMFZC EEOVO ONRTI  PEFIC ACFCL GRNLN DNSDA RTGUL  ANAIA EAROA ITISI TNUNS LRSNA
AAOUD EASRG SJTRS PIRED BUSNR  ROEMI FRNVE AUMIA GREEE AAATI  LFARA EAETT NOAIS EERNA FHEEN  SATOB REFUD
```

The statistics and searches below were run on the uncorrected text. The errors are substitutions, so no letter moved
and every transposition test stands. Re-run on the corrected text, the lag scan's maximum is z = 3.4 (was 3.3), at
the same lags (129 and 50); the index of coincidence is 0.0695 (was 0.0699); i falls from 46 to 43 and l rises from
17 to 20. The other letter counts quoted below and the 45 doubled letters are unchanged; the chi-squared, bigram and
log-likelihood figures move by amounts too small to matter (three letters in 615).

## What the letters say

**It is a transposition.** The index of coincidence is **0.0699**, the value of a natural language (random
letters give 0.038; codes and polyalphabetic ciphers much less). The ciphertext has no bigram structure of its
own: the bigram-repeat statistic is 1,956 against 1,832 ± 63 for the same letters shuffled and 3,522 for
Spanish prose of the same length, so it is not a substitution; the letters are the plaintext's letters,
reordered. Forty-five doubled letters in 614 adjacent pairs is exactly the shuffled expectation.

**The language is most likely Spanish, but telegraphic Spanish, not prose.** This session re-checked the
claim of the earlier notes and found it weaker than stated. Against seven corpora the letter counts fit no
literary language well:

| corpus | chi-squared of the 615 letters | chi-squared of real 615-letter windows of that corpus |
|---|---|---|
| Spanish (sp53 corpus) | 129 | 52 |
| Latin | 131 | 40 |
| French | 136 | 41 |
| Italian | 161 | 32 |
| Spanish (Gutenberg novels) | 178 | 25 |
| English | 212 | 32 |
| German | 403 | 57 |

Spanish still has the best log-likelihood per letter (−2.89 against −2.91 Latin, −2.92 French), and only the
Iberian and Italian profiles allow **o at 11.2 %**, which rules out French, German and English. But the text has
only **2 q** where Spanish prose expects 12, half the expected **l, u and a**, and too many **p (35), t, i, n,
c, m, x (6) and k (2)**. That is the profile of a commercial telegram: articles and *que* dropped, figures
spelled out (*mil, ciento, cinco, treinta, pesetas*), and trade words such as *punto, precio, kilos, textil,
exportación*. It matters for the search: a quadgram model trained on novels will score the true plaintext
nearer −4.5 per quadgram than the −3.9 of prose. Anything below about −4.8 is still unmistakable against the
−5.6 to −6.3 that wrong keys produce, so nothing below has been missed on that account.

## Excluded

Each search was first shown to recover planted Spanish of the same length.

### Single transpositions (all excluded)

| family | search | planted control | real telegram |
|---|---|---|---|
| rail fence, 2–60 rails, all offsets | exhaustive (`families.py`) | found exactly | best −6.34 per quadgram (Spanish −4.1, shuffled −6.3) |
| skip / decimation, every step and start | exhaustive | found exactly | at shuffle level |
| route transpositions, grids 2–60 wide: columns up/down/snake, rows reversed/snake, diagonals, spirals | exhaustive, both directions | found exactly | at shuffle level |
| single columnar, widths 4–20 | annealing (`trans.py`) | recovers widths 9, 14, 19 | best −6.03 |
| single columnar, widths 21–61 | annealing (`dt/st.exe`, 20 restarts × 2 M steps) | **fails** a planted width 41 (15 rows): a wrong key scores −4.18 against the true key's −3.90, so this run proves nothing on its own | best −5.27 at width 61, rising smoothly with width, i.e. spurious |
| **lag scan** (see below) | exhaustive over lags 1–599 | z = 11–22 at the expected lag | **max z 3.3**, no lag stands out |

107,594 fixed-pattern readings were scored in the first session.

### The lag scan, which settles three families at once

In any single columnar transposition, letters that were adjacent in the plaintext sit a fixed distance apart
in the ciphertext (the column length in one direction, the width in the other). The same is true of the
**reversed-direction double transposition** (plaintext written into the columns and read off by rows, twice):
neighbours land exactly **w1 × w2** positions apart, apart from the pairs that straddle a column end. So a
single scan scoring the Spanish bigram probability of every pair of letters at each lag from 1 to 599, in
both orders, tests every one of these keyed systems for every width, with no key search at all (`lagscan.py`).

Planted controls (reversed-direction double transposition, 19 × 8, 23 × 9, 17 × 29) light up at exactly
lag w1 × w2 with **z = 22.0, 21.0 and 11.1**. The real telegram never exceeds **z = 3.3** at any lag, which is
what the maximum of 1,198 noise values looks like. This excludes single columnar at any width, in either
direction, and reversed-direction double columnar for every width pair with w1 × w2 below about 560. (The
two-key reversed-direction annealing run that was in progress when the session opened was stopped as
redundant once this was seen.) The two mixed conventions (rows then columns, columns then rows) do not put
neighbours at one fixed lag; they are covered by the exhaustive searches below.

The scan says something about the forward direction too, though less than one would like. Forward double
columnar transposition scatters plaintext neighbours over many lags, yet in **40 of 40 plants of Spanish
prose** at random widths 15–30 × 15–30 the strongest lag still reached **z = 5.5 to 9.1** (median 6.9),
because every column pair of the second rectangle collects its share of neighbours at one lag. On a
telegraphese proxy (the same prose with articles, *que*, *y*, *de* and the like removed and spelled numbers
and trade words sprinkled in, lag-1 bigram score −2.28 against −2.23 for prose) the median was 7.2, but one
plant in 40 fell to 1.4. The telegram's 3.3 therefore sits at about the 3rd to 5th percentile of what a
forward double transposition of Spanish at those widths produces: mild evidence, not proof, that either the
plaintext is further from Spanish prose than our proxy or the system is not a plain double columnar
transposition at all.

### Double columnar, forward direction (rows written, columns read, twice), the German *Doppelwürfel*

This is the family to expect from a firm in Franco's German-linked orbit in 1937, and it is the one that
cannot be reduced to a lag test: neighbours are scattered over w2 × (w1 − 1) different distances.

**Full-key annealing** (`dt/dt.exe`, Spanish quadgrams, multithreaded). Planted power: same key to width 17,
two keys to about 11 × 14; beyond that it fails on plants. On the real telegram: same key widths 2–30 in both
directions, two keys 2–16 × 2–16 forward. Best −5.65 per quadgram (reversed, width 29), with the best score
rising smoothly with width, the signature of a spurious fit. Nothing.

**Divide and conquer after Lasry, Kopal and Wacker (2014).** Undo a candidate second key; if it is right,
the intermediate text is the column readout of the plaintext rectangle, and its columns pair off row by row
into good Spanish bigrams. That pairing score (IDP) depends only on the second key and the first width, so the
second key can be searched alone and the first key then solved as a single columnar transposition.
`dt/Idp2.cs` implements it with an exact sliding-window score (0.16 ms per evaluation at 19 × 23), an
optional one-to-one column assignment instead of best-partner, and three search modes.

*Local search fails, and the reason is measured.* On a planted 19 × 23 message the true second key scores
−2.19 and a random key −2.46. One random swap away from the true key already averages −2.36; five swaps,
−2.44; there is no gradient beyond three or four swaps out of 23! keys. Annealing and full-neighbourhood hill
climbing (6–10 restarts of 300 k–1 M evaluations) stall at −2.30 (best-partner) or −2.40 (assignment).
Clipping the bigram log-probabilities at −4 or −3 and a complete first rectangle (15 × 23, where the score is
exact) change nothing. On 615 letters with keys near 20, the IDP landscape is a needle, so the published
method's success on the 599-letter challenge must rest on far more compute than a workstation evening,
or on details we could not retrieve (the paper and thesis are behind 403s from here).

*Exhaustive enumeration of the second key works.* For w2 ≤ 10 every permutation can be scored (10! = 3.6 M
at up to 0.3 ms each) and the twelve best carried into the first-key stage. Planted proofs:

| plant | second key rank among all w2! | plaintext read |
|---|---|---|
| 19 × 8 | **1 of 40,320** | yes, −3.88 per quadgram (*…cosas en verdad harto buenas donde se da cuenta quienes eran maese pedro y su mono…*) |
| 23 × 9 | **1 of 362,880** | partly, −4.51 (first-key annealing at width 23 not fully converged; the signal is unmistakable) |
| 30 × 10 | **1 of 3,628,800** | yes, −4.40 (*…pagadle luego…*) |
| 35 × 9 | **1** | yes, −4.24 (*…compañero eterno mío en todos mis caminos y carreras, luego volvía dici…*) |
| 41 × 8 | **1** | yes, −4.41 (*…lugar y muere en… los muros de la fam…*) |
| 45 × 9 | 13th | first-key stage fails at 12 rows |
| 50 × 8, 61 × 9 | 1 | first-key stage fails at 12 and 10 rows |

So the proven region is **w2 ≤ 10 with w1 ≤ 41** (columns of at least 15 letters).

*Real telegram, forward direction, w2 = 2–10 × w1 = 2–41 (360 width pairs, every second key, 5.2 h on ten
threads):* **nothing.** Best pairing score −2.21 (at 40 × 10 and 39 × 10, the geometries with the most
alignment freedom and so the highest noise ceiling; the twelve best keys of every pair went on to the
first-key stage); best first-key reading −5.51 per quadgram, at width 41, where wrong keys always score
highest. Every reading is at the level wrong keys produce on plants (`dt/exhaust_fwd_w2_2-10_w1_2-41.txt`).

*Real telegram, columns-then-rows mixed convention (first key written into columns and read by rows, second
written in rows and read by columns; `IDP_INV=2`, plant 19 × 8 read at −3.87), w2 = 2–10 × w1 = 2–61:*
nothing. 540 width pairs, every second key enumerated; best stride score −2.69 (planted true keys score about
−2.20) and best first-key reading −5.85 per quadgram, both at noise level (`dt/exhaust_mixed_w2_2-10_w1_2-61.txt`).

*Real telegram, rows-then-columns mixed convention (`IDP_INV=3`, plant 19 × 8 read at −3.88), w2 = 2–10 ×
w1 = 2–41:* **nothing.** 360 width pairs; best pairing score −2.24, best first-key reading −5.49 per quadgram at width 41,
noise level (`dt/exhaust_mixed3_w2_2-10_w1_2-41.txt`, 4.9 h on five threads).

## What is left, and why it stops here

| region | status |
|---|---|
| forward double columnar, w2 ≤ 10, w1 ≤ 41 | excluded by exhaustive second-key search |
| forward double columnar, w2 = 11 | feasible (40 M keys × 40 widths, about 3 h on 22 cores); not run |
| forward double columnar, both keys ≥ 12 | **open**; no method proven on plants at 615 letters |
| forward, w1 ≥ 42 | open; the first-key stage fails on plants with fewer than 15 rows |
| all reversed-direction and single systems | excluded by the lag scan |

The open region is exactly where practice puts the answer. German-trained users of the *Doppelwürfel*
were told to take two key phrases of 15 to 25 letters each, and a Swiss firm dealing with Franco's Germans
in January 1937 would have been handed such a system. A single 615-letter message under two long keys is at
or beyond the frontier of published ciphertext-only attacks (Lasry's challenge solution needed 599 letters,
keys of 20 and 25, and hours of computation with a method whose landscape we found to be a needle at this
length). It is not a matter of another evening's compute.

What would break it:

1. **The second telegram**, sent the same day by the same firm, probably in the same keys. **In hand since
   30 Sept 2026** (see Transcription): Schmeh's post ("Can anyone decipher these two telegrams…") shows both,
   but only the first is in its public preview, and Richard Bean (issue 14) pointed to the full image. It has
   160 letters against 615, so the two are not the equal-length depth that the classical joint anagramming of a
   double transposition needs. Under the same keys, though, any candidate key pair must make both read at once.
2. **A crib.** The letter counts promise *pesetas*, *kilos*, *punto*, spelled numbers, and the firm's own
   names (*HOVAG*, the Holzverzuckerungs-AG at Ems, fits the letters; *Oswald* does not: there is no w).
   With a known 8–10-letter word and known widths the two keys can be pinned by hand.
3. **The key phrases themselves**, if the Federal Police file records the system (Bochsler's book may say).

## Files

* `ct1.txt`, `tg.py` — the transcription (three letters corrected 30 Sept 2026, issue 14). `telegram1.jpg` — the photograph.
* `ct2.txt`, `tg.py` (T2, CT2) — the second telegram, 160 letters (30 Sept 2026). `telegram2.jpg` — its photograph.
* `families.py`, `trans.py`, `double.py` — first-session Python searches.
* `dt/Dt.cs`, `dt/Dt2.cs`, `dt/St.cs` — C# annealers: double (forward), double (reversed), single columnar.
* `dt/Idp2.cs` — divide-and-conquer solver: `sa` / `hc` local search, `exhaust` enumeration, `IDP_INV=0|1|2`
  for the three conventions, `bench`, `plant`, `exhaustplant`. Build with .NET Framework
  `csc.exe -o+ -out:idp6.exe Idp2.cs`; needs `../q4_es.bin` (from `export_q4.py`).
* `dt/probe.py`, `dt/probe2.py` — the landscape probe (score against number of swaps from the true key).
* `dt/run_*.txt`, `dt/idp*_plant*.txt`, `dt/plant_*.txt`, `dt/exhaust_*.txt` — run logs.

Reproduce the controls: `dt/idp6.exe exhaustplant dt/plain_es.txt 5000 615 19 8 12 1 11` (from `dt/`), and
the lag scan with the Python block recorded in the session (statistics against `corpus/es_2000.txt`).


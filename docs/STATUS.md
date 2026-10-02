# Research status — 3 October 2026

**No verified historical plaintext, key or BLUME identity.** Phase 14 verified
the Kent serial-to-roll conversions and completed an audited synthetic pilot.
None of its four arms recovered K2.

| Area | What is established | What remains open |
| --- | --- | --- |
| Ciphertext | T1 = 615 and T2 = 160 letters; hashes and corrected readings fixed | Cipher family, language, keys, plaintext |
| Recipient | Address reads BLUME SALAMANCA | Person, firm, registered address or alias |
| Wool | Werner suggested wool, frozen export balances and secrecy from Hisma | Whether those telegrams concern that transaction |
| Arms | Separate Hunziker question in the interrogation | A link to these two messages |
| German documents | Bounded ADAP readings supply January 1937 context | Direct Oswald/BLUME transaction or current document signatures |
| Kent | Serial 643 → T120/296, p. 778; serial 3176 → T120/1594, p. 793; volume III, 1966 | Roll access, target frames and current archival signatures |
| Codebook | Cde in T2 matches the administrative CDE category in the Madrid 1932 regulations | Specific codebook, applicable route tariff or a code request tied to Oswald |
| Synthetic K2 | Phase 14: 32 audited runs at known widths 20 × 25; zero recoveries | Search failure diagnosis, reserved cases and suitability for historical use |

## Latest synthetic pilot

Phase 14 used four fresh German/French synthetic pairs, two rounds and four
arms: 32 runs, each with exactly 100,000 IDP calls. It searched K2 only at known
widths 20 × 25. It did not search K1 or the historical telegrams.

| Arm | Local cap | Checkpoint pool admission | Exact K2 in final top five |
| --- | ---: | --- | ---: |
| A | 5,000 | OFF | 0/8 |
| B | 5,000 | ON | 0/8 |
| C | 33,298 | OFF | 0/8 |
| D | 33,298 | ON | 0/8 |

All arms scored the common checkpoint pool at 50,000 calls; ON also offered its
survivors as parents, with inherited use counts. There were no periodic
refreshes. This isolates that admission rule, rather than the full benefit of
renewal or diversity alone.

The runs used 3,200,000 IDP calls in total, with no time cuts. The 16 OFF/ON
pairs had identical prefixes at the same cap; all eight groups of four arms
shared the complete checkpoint pool. Controls, operation replay, numerical
scores and protected-file hashes passed. The controls cost another 35,253 IDP
calls, including a preserved failed harness attempt.

The long cap produced 22 observed convergences; the short cap produced none.
Neither cap recovered a key. The true K2 scored above every final archived key
in all 32 runs. This shows a search limitation under this design and budget;
it does not establish a global optimum, validate literary models for commercial
telegrams or exclude a historical language or cipher family.

Inputs and results: [phase 14](../work/phase14_crypto/).
Audit: [saved-log audit](../work/phase14_root/post_run_audit.json) and
[independent review](../work/phase14_root/post_ejecucion_independiente.txt).
Detailed limits: [phase 14 report](../outputs/Sentinel_BLUME_fase14_2026-10-03.txt).

## Earlier phase 11 pilot

Eight pairs × two rounds × two methods = 32 runs; each used 100,000 IDP calls.

| Model / widths | Population baseline | Local cap 5,000 |
| --- | ---: | ---: |
| German 12 × 15 | 2/4 | 3/4 |
| German 20 × 25 | 0/4 | 0/4 |
| French 12 × 15 | 0/4 | 0/4 |
| French 20 × 25 | 0/4 | 0/4 |
| Total exact K2 recoveries | 2/16 | 3/16 |

The variant recovered one additional pair but also lost a round found by the
baseline. It changes both effort per climb and refresh frequency. With width 25,
one complete move sweep needs 16,649 proposals; a cap of 5,000 cannot finish it.
On the 27 failed rounds, the true K2 scored above every returned archived key.
That is an observed search limitation, not proof of a global optimum.

Inputs and results: [phase 11](../work/phase11_crypto/).
Detailed limits: [phase 11 report](../outputs/Sentinel_BLUME_fase11_2026-10-02.txt).

## Next evidence to obtain

Confirm access to T120/296, frames 254221–254222, and T120/1594, frames
682876–682878 and 682895–682896. Read those frames, especially the attached
telegram. The Kent conversion is complete; the original-frame reading is not.
NARA record 6921696 describes paper copies and lists T120 as an additional
resource. Its online-availability notice does not establish access to either
roll.

Keep the codebook and telegraphic-address leads open. CDE is a service category;
it identifies neither a codebook nor a cipher and does not exclude transposition.
Before another synthetic search, diagnose the recorded failure and define a new
design with reserved cases.

## Source and version discipline

The canonical body hashes are authoritative for ciphertext comparisons. Older
upstream notes and reports remain dated evidence; their statements should not
silently replace current conclusions. A file hash proves that bytes match a
recorded copy, not that its contents are true or freely redistributable.

The research reports were kept unchanged. Some contain obsolete local paths or
private-chat references from their original context. Those are historical
provenance, not public primary evidence. Use [SOURCES.md](SOURCES.md) for source access.

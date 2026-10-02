# Research status — 2 October 2026

**No verified historical plaintext, key or BLUME identity.** Phase 13 is the
latest research checkpoint represented here. Publication of this repository
did not add a new cryptographic experiment.

| Area | What is established | What remains open |
| --- | --- | --- |
| Ciphertext | T1=615 and T2=160 letters; hashes and corrected readings fixed | Cipher family, language, keys, plaintext |
| Recipient | Address reads BLUME SALAMANCA | Person, firm, registered address or alias |
| Wool | Werner suggested wool, frozen export balances and secrecy from Hisma | Whether those telegrams concern that transaction |
| Arms | Separate Hunziker question in the interrogation | A link to these two messages |
| German documents | Bounded ADAP readings supply January-1937 context | Direct Oswald/BLUME transaction or current document signatures |
| Kent | NARA conversion supplements and a catalogue location verified | Rows for 643/3176 and corresponding T120 rolls |
| Codebook | Historically plausible open alternative; groups described | Specific book, tariff classification or a code request tied to Oswald |
| Synthetic K2 | Frozen phase-11 inputs, logs and numerical results | Reliable recovery for long widths and suitability for historical use |
| New design | Decisions and critical review written | Implementation, audit, sealing and execution |

## Latest synthetic pilot

Eight pairs × two rounds × two methods = 32 runs; each used 100,000 IDP calls.

| Model / widths | Population baseline | Local cap 5,000 |
| --- | ---: | ---: |
| German 12×15 | 2/4 | 3/4 |
| German 20×25 | 0/4 | 0/4 |
| French 12×15 | 0/4 | 0/4 |
| French 20×25 | 0/4 | 0/4 |
| Total exact K2 recoveries | 2/16 | 3/16 |

The variant recovered one additional pair but also lost a round found by the
baseline. It changes both effort per climb and refresh frequency. With width 25,
one complete move sweep needs 16,649 proposals; a cap of 5,000 cannot finish it.
On the 27 failed rounds, the true K2 scored above every returned archived key.
That is an observed search limitation, not proof of a global optimum.

Inputs and results: [phase11](../work/phase11_crypto/).
Detailed limits: [phase11 report](../outputs/Sentinel_BLUME_fase11_2026-10-02.txt).

## Source and version discipline

The canonical body hashes are authoritative for ciphertext comparisons. Older
upstream notes and reports remain dated evidence; their statements should not
silently replace current conclusions. A file hash proves that bytes match a
recorded copy, not that its contents are true or freely redistributable.

The research reports were kept unchanged. Some contain obsolete local paths or
private-chat references from their original context. Those are historical
provenance, not public primary evidence. Use [SOURCES.md](SOURCES.md) for source access.

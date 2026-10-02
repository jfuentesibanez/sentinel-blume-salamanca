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
NARA confirms that the Kent catalogue contains serial-to-roll conversion
supplements for T120. A digital catalogue record locates a supplement at
printed page 770. **No row for serial 643 or 3176 has yet been read.** No current
German archival signature has been inferred from those numbers.

The official German archive guide assigns 1936–1945 trade-policy records to the
Bundesarchiv as a general orientation. Political records also require the PAAA
route. This does not establish the present custodian of an individual document.

## Cryptanalytic line

Double columnar transposition is a working hypothesis, not an identified cipher.
A commercial codebook, possibly transformed again, remains open. Five-letter
groups alone do not distinguish these systems. All 123 groups in T1 and all 32
in T2 are unique; none are shared. This is descriptive, not a family test.

The recent experiments search **K2 only on synthetic message pairs with known
widths**, using literary German/French models. They do not recover K1 and are
not attacks on the historical ciphertexts. A literary model is not a validated
model of commercial telegram language in 1937.

Phase 11: eight synthetic pairs, two rounds, two methods, 32 runs of 100,000 IDP
calls. The frozen population baseline recovered K2 in 2/16 rounds and 1/8 pairs;
the cap-5000 variant in 3/16 rounds and 2/8 pairs. All recoveries were German
12×15; none were French or 20×25. This is a small paired diagnostic panel, not
evidence of general superiority or language/cipher exclusions.

## Previous Claude review

Claude Opus 5.5 Medium reviewed a supplied summary. It reported one public
query and no BAR/MDZ image reading. We did not treat that as source verification.
Its NARA citation was independently checked. Its suggested experiment was not
adopted unchanged: without a local cap, processed/converged refresh counters
coincide; with a cap of 20,000, refresh after four fully capped children might
not fit the total budget. A high-scoring shuffled null does not automatically
invalidate a scorer, and six wins out of eight do not establish statistical
superiority. Truth-near starts are privileged diagnostics and need separate cost.

Our revised proposal remains **unimplemented and unexecuted**. Read
[the decisions](../work/phase13_claude/crypto_decisiones_preimplementacion.txt)
and [the internal review](../work/phase13_claude/crypto_revision_interna.txt)
before proposing another search. The proposal measures checkpoint-parent fusion
with the inherited-use rule, not diversity alone or the complete effect of renewal.

## Useful next tasks

1. Read actual Kent conversion-table rows for 643 and 3176, with the page image
   and header. Distinguish serial, roll, frame and current archive signature.
2. Investigate the telegraphic-address interpretation and CDE/tariff evidence,
   or locate a specific codebook tied to Oswald. Cite direct sources and state
   what was read, rather than extrapolating from generic five-letter grouping.
3. Audit the revised synthetic design and implementation plan before searches.
   Truth stays outside the solver; all objective calls, cuts and preparation
   costs count. Avoid tuning on results or substituting a score for recovery
   after failures.

When reporting: give exact paths or primary URLs, separate facts/testimony/
hypotheses, scope negative findings, and identify what would verify a proposed
link. A plausible historical story or high-scoring output is not a decipherment.
Do not contact people, purchase material, use personal connectors or run new
searches just because an old document contains such a suggestion.

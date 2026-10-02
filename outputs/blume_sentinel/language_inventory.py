#!/usr/bin/env python3
"""Compare preserved letter counts with five public Universal Dependencies samples.

This is a unigram diagnostic, not a detector of plaintext language or a solver.
Samples are modern prose, not authenticated 1937 commercial telegrams.
Python standard library only. Run with --corpus-dir pointing to downloaded files.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import random
import unicodedata

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
REPOS = {
    "es": ("Spanish", "UD_Spanish-AnCora", "es_ancora-ud-test.conllu"),
    "de": ("German", "UD_German-GSD", "de_gsd-ud-test.conllu"),
    "fr": ("French", "UD_French-GSD", "fr_gsd-ud-test.conllu"),
    "it": ("Italian", "UD_Italian-ISDT", "it_isdt-ud-test.conllu"),
    "en": ("English", "UD_English-EWT", "en_ewt-ud-test.conllu"),
}


def norm(text):
    text = text.replace("ß", "ss").replace("œ", "oe").replace("Œ", "OE").replace("æ", "ae")
    return "".join(c for c in unicodedata.normalize("NFKD", text).upper() if c in ALPHABET)


def chi(text, probs):
    count = Counter(text)
    return sum((count[c] - len(text)*probs[c])**2 / (len(text)*probs[c]) for c in ALPHABET)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    base = Path(__file__).resolve().parent
    p.add_argument("--corpus-dir", type=Path, default=base / "language_corpora")
    p.add_argument("--source-dir", type=Path, default=base / "sources")
    p.add_argument("--output", type=Path, default=base / "language_comparison.json")
    p.add_argument("--seed", type=int, default=20261001)
    p.add_argument("--windows", type=int, default=1000)
    args = p.parse_args()
    corpus, source_meta = {}, {}
    for code, (language, repo, filename) in REPOS.items():
        raw = (args.corpus_dir / (code + ".conllu")).read_bytes()
        sentences = [s[9:] for s in raw.decode().splitlines() if s.startswith("# text = ")]
        corpus[code] = norm(" ".join(sentences))
        git_blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        source_meta[code] = {
            "language": language,
            "url": f"https://github.com/UniversalDependencies/{repo}/blob/master/{filename}",
            "exact_blob_api": f"https://api.github.com/repos/UniversalDependencies/{repo}/git/blobs/{git_blob}",
            "sha256": hashlib.sha256(raw).hexdigest(), "sentences": len(sentences),
            "all_normalized_letters": len(corpus[code]),
        }
    size = min(map(len, corpus.values()))
    corpus = {code: text[:size] for code, text in corpus.items()}
    messages = {name: norm((args.source_dir / name).read_text()) for name in ("ct1.txt", "ct2.txt")}
    results = []
    for index, (code, text) in enumerate(corpus.items()):
        counts = Counter(text)
        probs = {c: (counts[c]+0.5)/(size+13) for c in ALPHABET}
        rng = random.Random(args.seed + index)
        values = {}
        for name, ct in messages.items():
            observed = chi(ct, probs)
            simulated = sorted(chi(text[s:s+len(ct)], probs) for s in
                               (rng.randrange(size-len(ct)+1) for _ in range(args.windows)))
            values[name] = {
                "letters": len(ct),
                "log_likelihood_per_letter_natural_log": sum(math.log(probs[c]) for c in ct)/len(ct),
                "chi_squared": observed,
                "same_sample_windows_chi2_median": simulated[len(simulated)//2],
                "same_sample_windows_chi2_p95": simulated[int(0.95*(len(simulated)-1))],
                "fraction_windows_chi2_at_least_observed": sum(v >= observed for v in simulated)/len(simulated),
            }
        results.append({"code": code, **source_meta[code], "sample_letters_used": size,
                        "letter_counts_used": {c: counts[c] for c in ALPHABET}, "messages": values})
    report = {"date": "2026-10-01", "normalization": "NFKD, accents removed, A-Z only; ß->SS, œ->OE, æ->AE",
              "balanced_letters_per_language": size, "seed": args.seed, "windows_per_length_language": args.windows,
              "sample_selection": "First equal number of normalized letters from # text metadata in each official UD test set.",
              "limitations": "Modern prose and differing treebank genres. Unigrams cannot identify a transposition or prove a language. Resampled windows use the same source as the frequency estimate; their tail fractions are descriptive, not independent significance tests. No historic plaintext inferred.",
              "results": results}
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n")
    print("balanced sample letters:", size)
    for name in messages:
        print(name)
        for r in sorted(results, key=lambda x: x["messages"][name]["log_likelihood_per_letter_natural_log"], reverse=True):
            d = r["messages"][name]
            print(r["code"], "logp", round(d["log_likelihood_per_letter_natural_log"], 4),
                  "chi2", round(d["chi_squared"], 2), "window_tail", d["fraction_windows_chi2_at_least_observed"])


if __name__ == "__main__":
    main()

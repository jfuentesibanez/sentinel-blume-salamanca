#!/usr/bin/env python3
"""Verify the BLUME source texts. Python standard library only.

Usage: python3 verify_sources.py --output verification.json
Photo transcription is a human review; a matching hash does not validate a photo.
"""
import argparse
from collections import Counter
from hashlib import sha256
import json
from math import gcd
from pathlib import Path

EXPECTED = {
    "ct1.txt": (615, "e266615d92019276513c1b7656f10c4f1a3d1e8eb739d28fd481ae337a434c55"),
    "ct2.txt": (160, "8fd5cfb82fc3c39fe0ee007b19ada7e74b4ae7747cd9b794d36dce101e17a644"),
}
CORRECTIONS = {38: "SOLRS", 48: "ACCEL", 122: "FTULX"}


def normalize(raw):
    text = raw.decode("ascii").upper()
    unexpected = sorted(set(c for c in text if not ("A" <= c <= "Z" or c.isspace())))
    if unexpected:
        raise ValueError(f"Unexpected characters, not silently discarded: {unexpected}")
    return "".join(c for c in text if "A" <= c <= "Z")


def inspect(path):
    raw = path.read_bytes()
    text = normalize(raw)
    expected_n, expected_hash = EXPECTED[path.name]
    counts = Counter(text)
    digest = sha256(text.encode("ascii")).hexdigest()
    result = {
        "file": path.name,
        "normalization": "ASCII uppercase A-Z; whitespace removed; other characters rejected",
        "length": len(text), "groups_of_five": len(text) // 5,
        "sha256_normalized": digest,
        "sha256_raw_file": sha256(raw).hexdigest(),
        "expected_length": expected_n, "expected_sha256": expected_hash,
        "valid": len(text) == expected_n and digest == expected_hash,
        "index_of_coincidence": sum(n * (n - 1) for n in counts.values()) / (len(text) * (len(text) - 1)),
        "letter_counts": {c: counts[c] for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
        "groups": [text[i:i+5] for i in range(0, len(text), 5)],
    }
    if path.name == "ct1.txt":
        result["corrections"] = {
            str(g): {"expected": value, "observed": text[5*(g-1):5*g],
                     "valid": text[5*(g-1):5*g] == value}
            for g, value in CORRECTIONS.items()
        }
        result["visual_uncertainty"] = [{"group_1_based": 113, "reading": "RBEEP",
                                          "confidence": "medium", "reason": "Red ink overlaps typewritten letters."}]
        result["valid"] &= all(c["valid"] for c in result["corrections"].values())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=Path(__file__).resolve().parent / "sources")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    records = [inspect(args.source_dir / filename) for filename in EXPECTED]
    report = {
        "status": "verified_text_hashes_not_plaintext",
        "messages": records,
        "length_gcd": gcd(*(r["length"] for r in records)),
        "shared_rectangle_constraint": "Without padding, a shared width dividing both lengths must divide 5. Widths >5 require an incomplete rectangle for at least one message at each stage.",
        "interpretation": "IC is compatible with preserved letter frequencies; it does not establish cipher type or plaintext language.",
    }
    serialized = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(serialized, encoding="utf-8")
    print(serialized, end="")
    return 0 if all(r["valid"] for r in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())

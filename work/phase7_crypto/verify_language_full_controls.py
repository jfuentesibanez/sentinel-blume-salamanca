"""Audit planted truth and output scores without any search-code dependency."""
from pathlib import Path
import hashlib
import json
import math
import struct
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

manifest = json.loads((HERE / "full_language_manifest.json").read_text())
assert manifest["completed"] and manifest["protected_inputs_unchanged"]
for entry in manifest["files_before"]:
    assert sha(ROOT / entry["path"]) == entry["sha256"]
assert sha(HERE / "full_language_controls.jsonl") == manifest["log_sha256"]
assert len(manifest["runs"]) == 8
assert all(run["status"] == "completed" and run["rows"] == 2 for run in manifest["runs"])
rows = [json.loads(line) for line in (HERE / "full_language_controls.jsonl").read_text().splitlines()]
assert len(rows) == 16

tables = {}
holdouts = {}
for model in manifest["models"]:
    folder = ROOT / "work/phase5_language" / model
    provenance = json.loads((folder / "provenance.json").read_text())
    assert sha(folder / "model.bin") == provenance["model_sha256"]
    assert sha(folder / "holdout.txt") == provenance["holdout_sha256"]
    holdouts[model] = ''.join(c.lower() for c in (folder / "holdout.txt").read_text() if c.isascii() and c.isalpha())
    raw = (folder / "model.bin").read_bytes()
    tables[model] = {}
    offset = 0
    for n in (2, 3, 4):
        count = 26 ** n
        table = struct.unpack_from('<%df' % count, raw, offset)
        assert all(math.isfinite(x) and x <= 0 for x in table)
        assert abs(sum(10 ** x for x in table) - 1) < 1e-5
        tables[model][n] = table
        offset += count * 4
    assert offset == len(raw)

def enc(text, key):
    return ''.join(text[column::len(key)] for column in key)

def dec(text, key):
    width = len(key)
    columns, offset = {}, 0
    for column in key:
        length = len(range(column, len(text), width))
        columns[column] = text[offset:offset + length]
        offset += length
    assert offset == len(text)
    return ''.join(columns[i % width][i // width] for i in range(len(text)))

def score(messages, table, n):
    total, count = 0, 0
    for text in messages:
        for i in range(len(text) - n + 1):
            code = 0
            for char in text[i:i+n]:
                code = code * 26 + ord(char) - 97
            total += table[code]
            count += 1
    return total / count

truth_cache, seen = {}, set()
for row in rows:
    assert row["mode"] == "full" and row["variant"] == "source"
    assert not row["oracle_k2_disclosed"] and not row["negative"]
    assert row["reencryption_consistency"] and row["lengths"] == [615, 160]
    assert row["outer_rounds"] == 3 and row["restarts"] == 8
    assert row["k1_seconds_limit"] == 3 and row["k2_seconds_limit"] == 5
    identity = (row["language_model"], row["w1"], row["w2"], row["plant_seed"], row["messages_scored"])
    assert identity not in seen
    seen.add(identity)
    body = holdouts[row["language_model"]]
    key = (len(body), row["w1"], row["w2"], row["plant_seed"])
    if key not in truth_cache:
        command = [str(HERE / "regenerate_planted_keys"), str(row["plant_seed"]), str(len(body)), str(row["w1"]), str(row["w2"])]
        truth_cache[key] = json.loads(subprocess.check_output(command, text=True))
    for field in ("sample_position", "true_k1", "true_k2"):
        assert row[field] == truth_cache[key][field]
    for field, width in (("k1", row["w1"]), ("k2", row["w2"]), ("stage_k2", row["w2"])):
        assert sorted(row[field]) == list(range(width))
    start = row["sample_position"]
    truth = [body[start:start+615], body[start+615:start+775]]
    assert list(map(len, truth)) == [615, 160]
    ciphertexts = [enc(enc(text, row["true_k1"]), row["true_k2"]) for text in truth]
    recovered = [dec(dec(text, row["k2"]), row["k1"]) for text in ciphertexts]
    assert [enc(enc(text, row["k1"]), row["k2"]) for text in recovered] == ciphertexts
    assert row["correct_letters"] == [sum(a == b for a, b in zip(x, y)) for x, y in zip(recovered, truth)]
    assert row["exact_k1"] == (row["k1"] == row["true_k1"])
    assert row["exact_k2"] == (row["k2"] == row["true_k2"])
    assert row["stage_exact_k2"] == (row["stage_k2"] == row["true_k2"])
    assert row["exact_both_plaintexts"] == (recovered == truth)
    for n in (3, 4):
        for messages, prefix in ((recovered, "q"), (truth, "truth_q")):
            independent = score(messages[:row["messages_scored"]], tables[row["language_model"]][n], n)
            assert abs(independent - row[prefix + str(n)]) < 1e-7

cells = []
for model in manifest["models"]:
    for w1, w2 in manifest["bands"]:
        for nmsg in (1, 2):
            subset = [x for x in rows if x["language_model"] == model and x["w1"] == w1 and x["w2"] == w2 and x["messages_scored"] == nmsg]
            assert len(subset) == 2
            cells.append({"language_model": model, "w1": w1, "w2": w2,
                          "messages_scored": nmsg, "denominator": 2,
                          "exact_both_plaintexts": sum(x["exact_both_plaintexts"] for x in subset),
                          "exact_k1": sum(x["exact_k1"] for x in subset),
                          "exact_k2": sum(x["exact_k2"] for x in subset),
                          "stage_exact_k2": sum(x["stage_exact_k2"] for x in subset),
                          "budget_expired": sum(x["budget_expired"] for x in subset),
                          "idp_evaluations": sum(x["idp_evals"] for x in subset),
                          "seconds": sum(x["seconds"] for x in subset),
                          "correct_letters": [x["correct_letters"] for x in subset],
                          "true_minus_selected_idp": [x["true_k2_idp"] - x["stage_k2_idp"] for x in subset]})

summary = {
    "phase": "7",
    "scope": "Small paired synthetic pilot; no robust recovery calibration, no historical attack",
    "rows": 16,
    "planted_pairs": 8,
    "models": manifest["models"],
    "keys_disclosed": False,
    "widths_disclosed": True,
    "exact_both_plaintexts": sum(x["exact_both_plaintexts"] for x in rows),
    "budget_expired_rows": sum(x["budget_expired"] for x in rows),
    "cells": cells,
    "limits": ["Two seeds per model and band, paired single/joint rows; no independent success-rate estimate.",
               "Literary holdout from one work per language; no 1937 telegram register coverage.",
               "Key widths known, conv0 only, shared keys, no padding; easier than unrestricted BLUME search.",
               "No language-specific shuffled negatives in this pilot.",
               "Failure does not exclude a language, double transposition, widths or key regions.",
               "The log's budget_expired flag combines stages and rounds; it does not identify the exhausted stage or cause."]}
(HERE / "full_language_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
verification = {"passed": True, "rows_checked": len(rows), "plaintexts_checked": len(rows) * 2,
                "rng_truth_cases_checked": len(truth_cache), "independent_score_checks": len(rows) * 4,
                "protected_input_files_checked": len(manifest["files_before"]),
                "frozen_inputs_unchanged": True,
                "truth_not_disclosed_to_solver": "Source reviewed: source_full receives used ciphertext, widths, model, search seed and budgets. Planted truth is accessed only after solver return to evaluate results.",
                "artifact_sha256": {name: sha(HERE / name) for name in ("run_language_full_controls.py", "regenerate_planted_keys.cpp", "regenerate_planted_keys", "verify_language_full_controls.py", "full_language_controls.jsonl", "full_language_manifest.json", "full_language_summary.json")}}
(HERE / "verification.json").write_text(json.dumps(verification, ensure_ascii=False, indent=2) + "\n")
print(json.dumps({"verification_passed": True, "rows": 16, "exact_both_plaintexts": summary["exact_both_plaintexts"], "budget_expired_rows": summary["budget_expired_rows"], "cells": cells}, ensure_ascii=False))

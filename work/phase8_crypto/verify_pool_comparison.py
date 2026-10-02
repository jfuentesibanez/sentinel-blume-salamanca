"""External evaluation. Never passes truth or evaluation back to the solver."""
from pathlib import Path
from collections import Counter
import hashlib
import json
import math
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def enc(text, key):
    return ''.join(text[column::len(key)] for column in key)

def dec(text, key):
    columns, offset = {}, 0
    for column in key:
        count = len(range(column, len(text), len(key)))
        columns[column] = text[offset:offset+count]
        offset += count
    assert offset == len(text)
    return ''.join(columns[i % len(key)][i // len(key)] for i in range(len(text)))

def ngram(messages, table, n):
    total, count = 0, 0
    for text in messages:
        for position in range(len(text)-n+1):
            index = 0
            for char in text[position:position+n]:
                index = 26 * index + ord(char) - 97
            total += table[index]
            count += 1
    return total / count

def json_write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")

manifest = json.loads((HERE / "comparison_manifest.json").read_text())
assert manifest["completed"] and manifest["protected_unchanged"]
assert manifest["predefined_seeds"] == [20261801, 20261802]
assert manifest["cases_sealed_before_solver_at_unix"] <= manifest["ended_at_unix"]
assert manifest["protected_before"] == manifest["protected_after"]
for file in manifest["protected_before"]:
    assert sha(ROOT / file["path"]) == file["sha256"]
for name, expected in manifest["source_hashes"].items():
    assert sha(HERE / name) == expected
assert sha(HERE / "solver_outputs.jsonl") == manifest["solver_output_sha256"]
assert sha(HERE / "planted_truth.jsonl") == manifest["truth_sha256"]
truths = {x["case_id"]: x for x in map(json.loads, (HERE / "planted_truth.jsonl").read_text().splitlines())}
rows = list(map(json.loads, (HERE / "solver_outputs.jsonl").read_text().splitlines()))
assert len(rows) == 16 and len(truths) == 8
assert len(manifest["cases"]) == 8 and len(manifest["runs"]) == 8
assert all(x["status"] == "completed" and x["rows"] == 2 for x in manifest["runs"])
models, bodies = {}, {}
for name in manifest["models"]:
    folder = ROOT / "work/phase5_language" / name
    provenance = json.loads((folder / "provenance.json").read_text())
    assert sha(folder / "model.bin") == provenance["model_sha256"]
    assert sha(folder / "holdout.txt") == provenance["holdout_sha256"]
    bodies[name] = ''.join(c.lower() for c in (folder / "holdout.txt").read_text() if c.isascii() and c.isalpha())
    raw = (folder / "model.bin").read_bytes()
    offset = 0
    models[name] = {}
    for n in (2, 3, 4):
        count = 26**n
        table = struct.unpack_from('<%df' % count, raw, offset)
        assert all(math.isfinite(value) and value <= 0 for value in table)
        assert abs(sum(10**value for value in table)-1) < 1e-5
        models[name][n] = table
        offset += count * 4
    assert offset == len(raw)

evaluated, trace_score_checks = [], 0
case_metadata = {x["case_id"]: x for x in manifest["cases"]}
for row in rows:
    case = case_metadata[row["case_id"]]
    truth = truths[row["case_id"]]
    assert row["mode"] == "ciphertext_only_comparison" and row["messages_scored"] == 2
    assert row["convention"] == 0 and row["lengths"] == [615, 160]
    assert row["search_seed"] == case["search_seed"]
    assert row["w1"] == case["w1"] and row["w2"] == case["w2"]
    assert not any(key.startswith("true_") or key.startswith("truth_") for key in row)
    body = bodies[row["language_model"]]
    position = truth["sample_position"]
    originals = [body[position:position+615], body[position+615:position+775]]
    ciphertexts = [enc(enc(text, truth["true_k1"]), truth["true_k2"]) for text in originals]
    for file, expected in zip(case["ciphertext_files"], ciphertexts):
        assert sha(ROOT / file["path"]) == file["sha256"]
        assert (ROOT / file["path"]).read_text().strip().lower() == expected
    table = models[row["language_model"]][3]
    recovered = [dec(dec(text, row["k2"]), row["k1"]) for text in ciphertexts]
    assert [enc(enc(text, row["k1"]), row["k2"]) for text in recovered] == ciphertexts
    assert row["reencryption_consistency"]
    assert abs(ngram(recovered, table, 3)-row["q3"]) < 1e-7
    assert len(row["rounds"]) == 3
    computed_k2_evaluations, computed_k2_seconds = 0, 0
    true_key_rounds, evaluated_true_key_rounds = [], []
    evaluation_traces = []
    for round_info in row["rounds"]:
        index = round_info["round"]
        assert 0 <= index < 3
        pool = round_info["pool"]
        keys = [tuple(x["k2"]) for x in pool]
        assert len(set(keys)) == len(keys) and 1 <= len(keys) <= 5
        assert [x["rank"] for x in pool] == list(range(1, len(pool)+1))
        assert [x["idp"] for x in pool] == sorted((x["idp"] for x in pool), reverse=True)
        for key in keys:
            assert sorted(key) == list(range(row["w2"]))
        stage = round_info["k2_stage"]
        assert stage["evaluations_limit"] == 300000 and stage["seconds_limit"] == 5
        assert stage["evaluations"] == round_info["pool_evaluations"] + round_info["swap_evaluations"] + round_info["hill_evaluations"]
        computed_k2_evaluations += stage["evaluations"]
        computed_k2_seconds += stage["seconds"]
        traces = [x for x in row["candidate_traces"] if x["round"] == index]
        count = 1 if row["policy"] == "single" else len(pool)
        assert len(traces) == count
        assert [x["pool_rank"] for x in traces] == list(range(1, count+1))
        true_ranks = [x["rank"] for x in pool if x["k2"] == truth["true_k2"]]
        if true_ranks:
            true_key_rounds.append({"round": index, "ranks": true_ranks})
        if any(rank <= count for rank in true_ranks):
            evaluated_true_key_rounds.append(index)
        for kind in ("k1_stage", "final_k2_stage"):
            assert sum(trace[kind]["evaluations_limit"] for trace in traces) <= 2000000
            assert abs(sum(trace[kind]["seconds_limit"] for trace in traces)-3) < 1e-9
        for trace in traces:
            candidate = pool[trace["pool_rank"]-1]
            assert trace["start_k2"] == candidate["k2"]
            assert trace["pool_idp"] == candidate["idp"]
            assert sorted(trace["k1"]) == list(range(row["w1"]))
            assert sorted(trace["final_k2"]) == list(range(row["w2"]))
            intermediate_recovered = [dec(dec(text, trace["start_k2"]), trace["k1"]) for text in ciphertexts]
            final_recovered = [dec(dec(text, trace["final_k2"]), trace["k1"]) for text in ciphertexts]
            assert abs(ngram(intermediate_recovered, table, 3)-trace["after_k1_q3"]) < 1e-7
            assert abs(ngram(final_recovered, table, 3)-trace["final_q3"]) < 1e-7
            trace_score_checks += 2
            for kind in ("k1_stage", "final_k2_stage"):
                stage = trace[kind]
                assert stage["evaluations"] == stage["feature_evaluations"] + stage["q_evaluations"]
                assert stage["evaluations"] <= stage["evaluations_limit"]
                assert 0 <= stage["setup_seconds"] <= stage["seconds"]
                assert stage["cut"] == (stage["cause"] != "algorithm_finished")
                assert stage["cut"] == (stage["cut_phase"] != "none")
                if stage["cause"] in ("evaluations", "evaluations_and_wall_time"):
                    assert stage["evaluations"] == stage["evaluations_limit"]
                if stage["cause"] in ("wall_time", "evaluations_and_wall_time"):
                    assert stage["seconds"] >= stage["seconds_limit"]
            evaluation_traces.append({"round": index, "pool_rank": trace["pool_rank"],
                                      "start_exact_k2": trace["start_k2"] == truth["true_k2"],
                                      "exact_k1": trace["k1"] == truth["true_k1"],
                                      "final_exact_k2": trace["final_k2"] == truth["true_k2"],
                                      "exact_both_plaintexts": final_recovered == originals})
    assert computed_k2_evaluations == row["k2_cache_charged_evaluations"]
    assert abs(computed_k2_seconds-row["k2_cache_charged_seconds"]) < 1e-7
    assert sum(x["k1_stage"]["evaluations"] + x["final_k2_stage"]["evaluations"] for x in row["candidate_traces"]) == row["dependent_evaluations"]
    assert sum(x["k1_stage"]["initial_q_evaluations"] + x["final_k2_stage"]["initial_q_evaluations"] for x in row["candidate_traces"]) == row["dependent_initial_q_evaluations"]
    assert row["charged_total_evaluations"] == row["dependent_evaluations"] + row["k2_cache_charged_evaluations"]
    assert abs(row["charged_total_seconds"] - row["dependent_seconds"] - row["k2_cache_charged_seconds"]) < 1e-7
    selected = max(row["candidate_traces"], key=lambda x: x["final_q3"])
    assert row["selected_round"] == selected["round"] and row["selected_pool_rank"] == selected["pool_rank"]
    assert row["k1"] == selected["k1"] and row["k2"] == selected["final_k2"]
    assert row["q3"] == selected["final_q3"]
    evaluated.append({"case_id": row["case_id"], "language_model": row["language_model"],
                      "w1": row["w1"], "w2": row["w2"], "policy": row["policy"],
                      "exact_k1": row["k1"] == truth["true_k1"],
                      "exact_k2": row["k2"] == truth["true_k2"],
                      "exact_both_plaintexts": recovered == originals,
                      "correct_letters": [sum(a == b for a, b in zip(x, y)) for x, y in zip(recovered, originals)],
                      "truth_q3": ngram(originals, table, 3), "returned_q3": row["q3"],
                      "selected_round": row["selected_round"], "selected_pool_rank": row["selected_pool_rank"],
                      "true_k2_in_pool": true_key_rounds,
                      "true_k2_evaluated_rounds": evaluated_true_key_rounds,
                      "charged_seconds": row["charged_total_seconds"],
                      "charged_evaluations": row["charged_total_evaluations"],
                      "dependent_seconds": row["dependent_seconds"],
                      "dependent_evaluations": row["dependent_evaluations"],
                      "candidate_evaluation": evaluation_traces})

comparisons = []
for case_id in truths:
    matched = [x for x in rows if x["case_id"] == case_id]
    assert len(matched) == 2 and matched[0]["rounds"] == matched[1]["rounds"]
    assert matched[0]["k2_cache_charged_seconds"] == matched[1]["k2_cache_charged_seconds"]
    assert matched[0]["k2_cache_charged_evaluations"] == matched[1]["k2_cache_charged_evaluations"]
    single = next(x for x in evaluated if x["case_id"] == case_id and x["policy"] == "single")
    pool = next(x for x in evaluated if x["case_id"] == case_id and x["policy"] == "pool5")
    comparisons.append({"case_id": case_id, "single_exact": single["exact_both_plaintexts"],
                        "pool_exact": pool["exact_both_plaintexts"],
                        "pool_minus_single_seconds": pool["charged_seconds"] - single["charged_seconds"],
                        "pool_minus_single_evaluations": pool["charged_evaluations"] - single["charged_evaluations"],
                        "single_q3": single["returned_q3"], "pool_q3": pool["returned_q3"]})

cells = []
for model in manifest["models"]:
    for w1, w2 in manifest["bands"]:
        for policy in manifest["policies"]:
            subset = [x for x in evaluated if x["language_model"] == model and x["w1"] == w1 and x["w2"] == w2 and x["policy"] == policy]
            assert len(subset) == 2
            cells.append({"language_model": model, "w1": w1, "w2": w2, "policy": policy,
                          "denominator": 2, "exact_both_plaintexts": sum(x["exact_both_plaintexts"] for x in subset),
                          "true_k2_in_any_pool": sum(bool(x["true_k2_in_pool"]) for x in subset),
                          "charged_seconds": sum(x["charged_seconds"] for x in subset),
                          "charged_evaluations": sum(x["charged_evaluations"] for x in subset)})
cut_causes = Counter()
for row in rows:
    for trace in row["candidate_traces"]:
        for kind in ("k1_stage", "final_k2_stage"):
            cut_causes[(row["policy"], kind, trace[kind]["cause"])] += 1
    for round_info in row["rounds"]:
        cut_causes[(row["policy"], "shared_k2_stage", round_info["k2_stage"]["cause"])] += 1
summary = {"phase": "8", "paired_cases": 8, "rows": 16,
           "historical_attack": False, "ground_truth_disclosed_to_solver": False,
           "cells": cells, "paired_comparisons": comparisons,
           "single_exact": sum(x["exact_both_plaintexts"] for x in evaluated if x["policy"] == "single"),
           "pool_exact": sum(x["exact_both_plaintexts"] for x in evaluated if x["policy"] == "pool5"),
           "pool_only_recoveries": sum(x["pool_exact"] and not x["single_exact"] for x in comparisons),
           "single_only_recoveries": sum(x["single_exact"] and not x["pool_exact"] for x in comparisons),
           "total_charged_seconds_by_policy": {policy: sum(x["charged_seconds"] for x in evaluated if x["policy"] == policy) for policy in manifest["policies"]},
           "total_charged_evaluations_by_policy": {policy: sum(x["charged_evaluations"] for x in evaluated if x["policy"] == policy) for policy in manifest["policies"]},
           "cut_causes": [{"policy": policy, "stage": stage, "cause": cause, "count": count} for (policy, stage, cause), count in sorted(cut_causes.items())],
           "limits": ["Only two seeds per model and band; policies paired, not independent samples.",
                      "Known widths, shared keys, conv0, no padding; one literary holdout per language.",
                      "Identical maximum budgets do not guarantee equal actual costs; both are reported.",
                      "K2 computed once and charged identically to both policies; charged totals are not actual process time.",
                      "Initial plaintext score calls are recorded separately, with time counted inside the stage.",
                      "No language-specific shuffled controls in this pilot; no exclusion of BLUME language, cipher or keys."]}
(HERE / "external_evaluation.jsonl").write_text(''.join(json.dumps(x, separators=(",", ":")) + "\n" for x in evaluated))
json_write(HERE / "comparison_summary.json", summary)
verification = {"passed": True, "rows_checked": len(rows), "ciphertexts_checked": len(truths)*2,
                "returned_plaintexts_checked": len(rows)*2, "candidate_score_checks": trace_score_checks,
                "shared_pools_exactly_equal_between_policies": True,
                "candidates_distinct": True, "per_round_budget_split_checked": True,
                "final_selection_by_q3_only_checked": True,
                "protected_files_checked": len(manifest["protected_before"]), "protected_unchanged": True,
                "source_review": "Ciphertext-only CLI; no ground-truth argument, oracle option, holdout input, truth score or truth lookup in phase8 main/solver functions. Budget starts before ICT construction.",
                "artifact_sha256": {name: sha(HERE / name) for name in ("pool_solver.cpp", "pool_solver", "run_pool_comparison.py", "verify_pool_comparison.py", "comparison_manifest.json", "solver_outputs.jsonl", "planted_truth.jsonl", "external_evaluation.jsonl", "comparison_summary.json")}}
json_write(HERE / "verification.json", verification)
print(json.dumps({"passed": True, "single_exact": summary["single_exact"], "pool_exact": summary["pool_exact"], "pool_only_recoveries": summary["pool_only_recoveries"], "single_only_recoveries": summary["single_only_recoveries"], "cells": cells, "verification": verification}, ensure_ascii=False))

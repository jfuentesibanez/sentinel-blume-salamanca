"""Predefined fresh, paired synthetic comparison; truth stays outside solver."""
from pathlib import Path
import hashlib
import json
import subprocess
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SEEDS = (20261801, 20261802)
MODELS = ("de_fold", "fr_fold")
BANDS = ((12, 15), (20, 25))
MASK = (1 << 64) - 1

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")

def enc(text, key):
    return ''.join(text[column::len(key)] for column in key)

manifest_path = HERE / "comparison_manifest.json"
if manifest_path.exists():
    raise SystemExit("Refusing to overwrite an existing manifest")
protected = []
for directory in ("crypto", "phase2_crypto", "phase3_crypto", "phase4_crypto", "phase5_crypto", "phase5_language", "phase7_crypto"):
    protected.extend(sorted(path for path in (ROOT / "work" / directory).rglob('*') if path.is_file()))
manifest = {
    "date": "2026-10-02",
    "scope": "Synthetic joint-message controls only; no historical attack",
    "policies": ["single", "pool5"],
    "models": list(MODELS), "bands": [list(x) for x in BANDS],
    "predefined_seeds": list(SEEDS), "planted_pairs": 8, "expected_rows": 16,
    "messages_scored": 2, "lengths": [615, 160], "convention": 0,
    "key_widths_disclosed": True, "keys_disclosed": False,
    "shared_k2": "Three K2 pools computed once per pair, cached identically for both policies; the same measured K2 time/evaluations are charged to each policy. Actual process time therefore differs from sum of charged times.",
    "candidate_rule": "Single uses rank1. Pool uses up to5 distinct returned K2 candidates per round, ranked by IDP; duplicates removed. No score from planted truth is available to solver.",
    "selection_rule": "Best final trigram plaintext score across every evaluated candidate and all3rounds; ties retain first.",
    "candidate_budgets": "Per-round K1 and final-K2 limits divided by number of candidates evaluated. No unused budget redistribution. K1 table construction is inside the candidate time limit.",
    "k1_seconds_per_round": 3, "k2_seconds_per_round": 5, "final_seconds_per_round": 3,
    "k1_evaluations_per_round": 2000000, "k2_evaluations_per_round": 300000,
    "final_evaluations_per_round": 2000000, "k1_restarts_per_candidate": 8,
    "cost_caveat": "Equal maxima do not guarantee equal actual cost. Initial plaintext score calls are recorded separately from capped proposal counts, and their elapsed time remains in stage time. Candidate/table/move setup and stage cutoff metrics are logged.",
    "corpus_limit": "One literary work per language, disjoint training/holdout sections; not a1937 telegram corpus.",
    "negative_controls": "No new shuffled controls in this paired policy pilot.",
    "protected_before": [{"path": str(path.relative_to(ROOT)), "sha256": sha(path)} for path in protected],
    "source_hashes": {name: sha(HERE / name) for name in ("pool_solver.cpp", "pool_solver", "run_pool_comparison.py")},
    "case_generation_helper": {"path": "work/phase7_crypto/regenerate_planted_keys", "sha256": sha(ROOT / "work/phase7_crypto/regenerate_planted_keys")},
    "cases": [], "runs": [], "started_at_unix": time.time(),
}
write_json(manifest_path, manifest)
(HERE / "ciphertexts").mkdir(exist_ok=True)
truths = []
for model in MODELS:
    folder = ROOT / "work/phase5_language" / model
    body = ''.join(c.lower() for c in (folder / "holdout.txt").read_text() if c.isascii() and c.isalpha())
    for w1, w2 in BANDS:
        for seed in SEEDS:
            case_id = f"{model}_{w1}x{w2}_{seed}"
            helper = [str(ROOT / "work/phase7_crypto/regenerate_planted_keys"), str(seed), str(len(body)), str(w1), str(w2)]
            planted = json.loads(subprocess.check_output(helper, text=True))
            position = planted["sample_position"]
            texts = [body[position:position+615], body[position+615:position+775]]
            assert list(map(len, texts)) == [615, 160]
            ciphertexts = [enc(enc(text, planted["true_k1"]), planted["true_k2"]) for text in texts]
            files = [HERE / "ciphertexts" / f"{case_id}_T{index}.txt" for index in (1, 2)]
            for path, text in zip(files, ciphertexts):
                path.write_text(text.upper() + "\n")
            truths.append({"case_id": case_id, "language_model": model, "w1": w1, "w2": w2,
                           "plant_seed": seed, **planted})
            search_seed = (seed ^ 0xb7e151628aed2a6b) & MASK
            command = [str(HERE / "pool_solver"), str(folder / "model.bin"),
                       *map(str, files), str(w1), str(w2), str(search_seed),
                       "3", "5", "3", "2000000", "300000", "2000000"]
            manifest["cases"].append({"case_id": case_id, "language_model": model,
                                      "w1": w1, "w2": w2, "plant_seed": seed,
                                      "search_seed": search_seed, "command": command,
                                      "ciphertext_files": [{"path": str(path.relative_to(ROOT)), "sha256": sha(path)} for path in files]})

# Seal all8 cases and seeds before any solver invocation.
(HERE / "planted_truth.jsonl").write_text(''.join(json.dumps(x, separators=(",", ":")) + "\n" for x in truths))
manifest["truth_sha256"] = sha(HERE / "planted_truth.jsonl")
manifest["cases_sealed_before_solver_at_unix"] = time.time()
write_json(manifest_path, manifest)
log_path = HERE / "solver_outputs.jsonl"
with log_path.open("x") as out:
    for case in manifest["cases"]:
        began = time.monotonic()
        run = {"case_id": case["case_id"], "command": case["command"]}
        try:
            result = subprocess.run(case["command"], check=True, text=True, capture_output=True, timeout=105)
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            assert len(rows) == 2 and {x["policy"] for x in rows} == {"single", "pool5"}
            assert rows[0]["rounds"] == rows[1]["rounds"]
            for row in rows:
                assert row["reencryption_consistency"]
                assert not any(key.startswith("true_") or key.startswith("truth_") for key in row)
                row["case_id"] = case["case_id"]
                row["language_model"] = case["language_model"]
                out.write(json.dumps(row, separators=(",", ":")) + "\n")
            out.flush()
            run.update(status="completed", rows=2, wall_seconds=time.monotonic()-began)
        except Exception as error:
            run.update(status="error", error=str(error), wall_seconds=time.monotonic()-began)
            manifest["runs"].append(run)
            write_json(manifest_path, manifest)
            raise
        manifest["runs"].append(run)
        write_json(manifest_path, manifest)
        print(json.dumps({key: value for key, value in run.items() if key != "command"}), flush=True)
manifest["protected_after"] = [{"path": str(path.relative_to(ROOT)), "sha256": sha(path)} for path in protected]
assert manifest["protected_before"] == manifest["protected_after"]
manifest["protected_unchanged"] = True
manifest["solver_output_sha256"] = sha(log_path)
manifest["ended_at_unix"] = time.time()
manifest["completed"] = True
write_json(manifest_path, manifest)

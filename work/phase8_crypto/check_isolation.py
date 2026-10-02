"""Small isolation check using an existing ciphertext pair, not a new control."""
from pathlib import Path
import hashlib
import json
import subprocess

HERE = Path(__file__).resolve().parent
manifest = json.loads((HERE / "comparison_manifest.json").read_text())
case = manifest["cases"][0]
assert case["case_id"] == "de_fold_12x15_20261801"
command = case["command"][:]
# Evaluation limits, not wall time, determine this small repeat. Widths,
# ciphertext, model and seed remain exactly those of the sealed original case.
command[7:10] = ["60", "60", "60"]
command[10:13] = ["8000", "1500", "5000"]
directory = HERE / "isolation_check"
directory.mkdir(exist_ok=True)
source = (HERE / "pool_solver.cpp").read_text()
main_source = source[source.index('int main(int argc, char** argv)'):]
assert 'read(argv[2])' in main_source and 'read(argv[3])' in main_source
assert 'Model model(argv[1])' in main_source
assert 'baseline_cli_main' not in main_source
assert 'std::ifstream' not in main_source and 'getenv' not in main_source

ignored_time_fields = {"seconds", "setup_seconds", "k2_cache_charged_seconds",
                       "dependent_seconds", "charged_total_seconds"}
def strip_timing(value):
    if isinstance(value, dict):
        return {key: strip_timing(item) for key, item in value.items() if key not in ignored_time_fields}
    if isinstance(value, list):
        return [strip_timing(item) for item in value]
    return value

decoys = [
    {"true_k1": list(range(12)), "true_k2": list(range(15)), "truth_q3": 999999},
    {"true_k1": list(reversed(range(12))), "true_k2": list(reversed(range(15))), "truth_q3": -999999},
]
normalized = []
for index, decoy in enumerate(decoys, 1):
    (directory / "planted_truth.jsonl").write_text(json.dumps(decoy) + "\n")
    output = subprocess.check_output(command, text=True, cwd=directory, timeout=30)
    rows = list(map(json.loads, output.splitlines()))
    assert len(rows) == 2
    for row in rows:
        for trace in row['candidate_traces']:
            for kind in ('k1_stage', 'final_k2_stage'):
                assert trace[kind]['cause'] != 'wall_time'
        for round_info in row['rounds']:
            assert round_info['k2_stage']['cause'] == 'evaluations'
    (directory / f"repeat{index}.jsonl").write_text(output)
    normalized.append(strip_timing(rows))
assert normalized[0] == normalized[1]
result = {
    "passed": True, "scope": "Same sealed pair; not an additional recovery control",
    "case_id": case["case_id"], "command": command,
    "different_local_truth_decoys": decoys,
    "identical_results_after_removing_elapsed_times": True,
    "score_keys_candidates_limits_and_causes_equal": True,
    "wall_time_never_exhausted": True,
    "truth_decoy_not_an_input": "CLI receives only model, ciphertext paths, widths, search seed and budgets; no external truth argument or lookup in phase8 entry point.",
    "limit": "A source/interface check plus two poisoned-local-metadata repeats; not a general information-flow proof.",
    "output_sha256": {f"repeat{index}.jsonl": hashlib.sha256((directory / f"repeat{index}.jsonl").read_bytes()).hexdigest() for index in (1, 2)},
}
(HERE / "isolation_check.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
print(json.dumps({"passed": True, "case_id": case["case_id"], "identical_non_timing_results": True}))

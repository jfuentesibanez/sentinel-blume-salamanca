"""Small, paired calibration with both keys unknown. Synthetic inputs only.

Uses frozen phase4 CLI and source-neighbourhood solver. No old file is edited.
The CLI creates planted truth but passes only ciphertext, widths, model and
search budgets to source_full. Truth is printed only for external evaluation.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
MODELS = ("de_fold", "fr_fold")
BANDS = ((12, 15), (20, 25))
SEEDS = (20261601, 20261602)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

inputs = [
    ROOT / "work/phase4_crypto/phase4",
    ROOT / "work/phase4_crypto/phase4.cpp",
    ROOT / "work/phase4_crypto/source_moves.h",
    ROOT / "work/phase3_crypto/phase3.cpp",
    ROOT / "work/phase3_crypto/ict_search.h",
    ROOT / "work/crypto/double_search.cpp",
]
for model in MODELS:
    inputs += [ROOT / "work/phase5_language" / model / name
               for name in ("model.bin", "holdout.txt", "provenance.json")]

manifest_path = HERE / "full_language_manifest.json"
log_path = HERE / "full_language_controls.jsonl"
if manifest_path.exists() or log_path.exists():
    raise SystemExit("Refusing to overwrite an existing run")

manifest = {
    "date": "2026-10-02",
    "mode": "full; both K1 and K2 unknown to source_full",
    "variant": "source",
    "historical_attack": False,
    "lengths": [615, 160],
    "bands": [list(x) for x in BANDS],
    "models": list(MODELS),
    "seeds": list(SEEDS),
    "messages_scored": [1, 2],
    "convention": "conv0: forward irregular columnar transposition twice, no padding",
    "widths_disclosed": True,
    "keys_disclosed": False,
    "restarts": 8,
    "outer_rounds": 3,
    "k1_seconds_per_round": 3,
    "k2_seconds_per_round": 5,
    "final_k2_seconds_per_round": 3,
    "max_idp_evaluations_per_round": 300000,
    "max_k1_evaluations_per_round": 2000000,
    "max_final_k2_evaluations_per_round": 2000000,
    "outer_selection": "best trigram plaintext score; truth unavailable",
    "process_timeout_seconds": 90,
    "paired_observations": "Two seeds per band/model; same seed and widths share keys across language models. Single/joint rows share the planted pair and are not independent.",
    "de_digraph_omitted": "Same German work; this pilot targets absence of full-key calibration, not spelling sensitivity.",
    "negative_controls": "None added in this small pilot; earlier phase4 shuffled negatives are separate and are not language-specific negative controls.",
    "model_limit": "One literary work per language, with disjoint training/holdout sections. No claim of coverage for commercial telegrams in 1937.",
    "files_before": [{"path": str(p.relative_to(ROOT)), "sha256": sha(p)} for p in inputs],
    "started_at_unix": time.time(),
    "runs": [],
}

def save():
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")

save()
with log_path.open("x") as out:
    for model in MODELS:
        for w1, w2 in BANDS:
            for seed in SEEDS:
                cmd = [str(ROOT / "work/phase4_crypto/phase4"), "source",
                       str(ROOT / "work/phase5_language" / model / "model.bin"),
                       str(ROOT / "work/phase5_language" / model / "holdout.txt"),
                       str(w1), str(w2), str(seed), "8", "3", "5"]
                began = time.monotonic()
                run = {"language_model": model, "w1": w1, "w2": w2,
                       "seed": seed, "command": cmd}
                try:
                    proc = subprocess.run(cmd, check=True, text=True,
                                          capture_output=True, timeout=90)
                    rows = [json.loads(x) for x in proc.stdout.splitlines()]
                    assert len(rows) == 2
                    assert {x["messages_scored"] for x in rows} == {1, 2}
                    for row in rows:
                        assert row["mode"] == "full"
                        assert row["variant"] == "source"
                        assert not row["oracle_k2_disclosed"] and not row["negative"]
                        assert row["lengths"] == [615, 160]
                        assert row["reencryption_consistency"]
                        row["language_model"] = model
                        out.write(json.dumps(row, separators=(",", ":")) + "\n")
                    out.flush()
                    run.update(status="completed", rows=2,
                               wall_seconds=time.monotonic() - began)
                except Exception as error:
                    run.update(status="error", error=str(error),
                               wall_seconds=time.monotonic() - began)
                    manifest["runs"].append(run)
                    save()
                    raise
                manifest["runs"].append(run)
                save()
                print(json.dumps(run), flush=True)

manifest["ended_at_unix"] = time.time()
manifest["log_sha256"] = sha(log_path)
manifest["files_after"] = [{"path": str(p.relative_to(ROOT)), "sha256": sha(p)} for p in inputs]
manifest["protected_inputs_unchanged"] = manifest["files_before"] == manifest["files_after"]
assert manifest["protected_inputs_unchanged"]
manifest["completed"] = True
save()

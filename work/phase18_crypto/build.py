"""Build phase18 and run one mock-only control attempt; never generate or score truth."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
MOCK_BUDGET = 200


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def core_bytes(path):
    body = path.read_bytes()
    return body[body.index(b"struct Core {"):body.index(b"\nint trajectory_main")]


def frozen_inputs():
    previous = ROOT / "work/phase16_crypto"
    old = json.loads((previous / "build_record.json").read_text())
    assert sha(previous / "trajectory.cpp") == old["source_sha256"]
    assert sha(previous / "exact_scorer.h") == old["exact_header_sha256"]
    assert core_bytes(HERE / "trajectory.cpp") == core_bytes(previous / "trajectory.cpp")
    copied = {}
    for name in ("exact_scorer.h", "moves.json", "LICENSE-CrypTool-2.txt"):
        assert (HERE / name).read_bytes() == (previous / name).read_bytes()
        copied[name] = sha(HERE / name)
    dependencies = {}
    for name, digest in old["frozen_dependencies"].items():
        assert sha(ROOT / name) == digest
        dependencies[name] = digest
    return {"phase16_source_sha256": old["source_sha256"],
            "core_sha256": hashlib.sha256(core_bytes(HERE / "trajectory.cpp")).hexdigest(),
            "core_byte_identical_to_phase16": True,
            "exact_header_sha256": copied["exact_scorer.h"],
            "copied_frozen_files": copied,
            "frozen_dependencies": dependencies}


def require_unsealed():
    if (HERE / "sealed_design.json").exists() or (HERE / "truth.jsonl").exists():
        raise SystemExit("No build or controls after phase18 truth/seal")


def build():
    require_unsealed()
    record_path = HERE / "build_record.json"
    attempt_path = HERE / "build_attempt.json"
    if record_path.exists() or attempt_path.exists():
        raise SystemExit("Phase18 build attempt already recorded; no silent retry")
    frozen = frozen_inputs()
    command = ["/usr/bin/clang++", "-std=c++17", "-O3",
               str(HERE / "trajectory.cpp"), "-o", str(HERE / "trajectory")]
    began = time.monotonic()
    timed_out = False
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired as error:
        timed_out = True
        decode = lambda value: value.decode() if isinstance(value, bytes) else (value or "")
        result = subprocess.CompletedProcess(command, 124, decode(error.stdout), decode(error.stderr))
    stdout = HERE / "build_stdout.local.txt"
    stderr = HERE / "build_stderr.local.txt"
    stdout.write_text(result.stdout)
    stderr.write_text(result.stderr)
    record = {"status": "compiled" if result.returncode == 0 else "failed_no_retry",
              "compiler_command": command, "returncode": result.returncode, "timed_out": timed_out,
              "source_sha256": sha(HERE / "trajectory.cpp"), **frozen,
              "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr),
              "seconds": time.monotonic() - began,
              "new_IDP_calls": 0, "mock_callback_calls": 0,
              "truth_generated": False, "main_trajectories": 0,
              "rng_executions": 0}
    save(attempt_path, record)
    if result.returncode:
        raise SystemExit(json.dumps(record))
    macros = subprocess.check_output(
        ["/usr/bin/clang++", "-std=c++17", "-dM", "-E", "-x", "c++", "-"],
        input="#include <random>\n", text=True)
    record.update(
        binary_sha256=sha(HERE / "trajectory"),
        compiler_version=subprocess.check_output(["/usr/bin/clang++", "--version"], text=True),
        standard_library_macros=[line for line in macros.splitlines()
                                if line.startswith(("#define _LIBCPP_VERSION ", "#define __GLIBCXX__ "))])
    save(record_path, record)
    print(json.dumps(record, indent=2))


def controls():
    require_unsealed()
    directory = HERE / "control_attempts"
    directory.mkdir(exist_ok=True)
    attempt_path = directory / "attempt1.json"
    if attempt_path.exists() or any(directory.glob("output*.jsonl")):
        raise SystemExit("Phase18 mock attempt already recorded; no silent retry")
    build_record = json.loads((HERE / "build_record.json").read_text())
    assert sha(HERE / "trajectory.cpp") == build_record["source_sha256"]
    assert sha(HERE / "trajectory") == build_record["binary_sha256"]
    assert frozen_inputs()["exact_header_sha256"] == build_record["exact_header_sha256"]
    began = time.monotonic()
    timed_out = False
    try:
        result = subprocess.run([str(HERE / "trajectory"), "policy-controls"],
                                capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired as error:
        timed_out = True
        decode = lambda value: value.decode() if isinstance(value, bytes) else (value or "")
        result = subprocess.CompletedProcess([], 124, decode(error.stdout), decode(error.stderr))
    output = directory / "output1.jsonl"
    trace = directory / "calls1.log"
    output.write_text(result.stdout)
    trace.write_text(result.stderr)
    idp_marks = [list(map(int, line.split()[1:])) for line in result.stderr.splitlines()
                 if line.startswith("@calls ")]
    mock_marks = [int(line.split()[1]) for line in result.stderr.splitlines()
                  if line.startswith("@mock_calls ")]
    charged = idp_marks[-1] if idp_marks else [0, 0]
    callbacks = mock_marks[-1] if mock_marks else 0
    try:
        row = json.loads(result.stdout.splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        row = {"status": "failed_unparsed"}
    record = {"attempt": 1, "returncode": result.returncode, "timed_out": timed_out,
              "status": row.get("status", "failed"), "seconds": time.monotonic() - began,
              "source_sha256": sha(HERE / "trajectory.cpp"),
              "binary_sha256": sha(HERE / "trajectory"),
              "exact_header_sha256": sha(HERE / "exact_scorer.h"),
              "actual_legacy_IDP_calls": charged[0], "actual_exact_IDP_calls": charged[1],
              "mock_callback_calls": callbacks, "total_mock_callback_budget": MOCK_BUDGET,
              "output_sha256": sha(output), "trace_sha256": sha(trace),
              "fixture_record": row, "truth_generated": False, "main_runs": 0}
    save(attempt_path, record)
    finalize_saved_controls()


def finalize_saved_controls():
    """Validate the existing one control attempt without invoking any process."""
    require_unsealed()
    if (HERE / "control_results.json").exists():
        raise SystemExit("Mock result already finalized; no repeat")
    directory = HERE / "control_attempts"
    record = json.loads((directory / "attempt1.json").read_text())
    output = directory / "output1.jsonl"
    trace = directory / "calls1.log"
    assert sha(output) == record["output_sha256"] and sha(trace) == record["trace_sha256"]
    assert sha(HERE / "trajectory.cpp") == record["source_sha256"]
    assert sha(HERE / "trajectory") == record["binary_sha256"]
    assert sha(HERE / "exact_scorer.h") == record["exact_header_sha256"]
    row = json.loads(output.read_text().splitlines()[-1])
    assert row == record["fixture_record"]
    callbacks = record["mock_callback_calls"]
    mock_marks = [int(line.split()[1]) for line in trace.read_text().splitlines()
                  if line.startswith("@mock_calls ")]
    charged = [record["actual_legacy_IDP_calls"], record["actual_exact_IDP_calls"]]
    assert callbacks <= MOCK_BUDGET
    assert mock_marks == list(range(1, callbacks + 1))
    if record["returncode"] or record["status"] != "passed" or sum(charged):
        raise SystemExit(json.dumps(record))
    # Phase16's successful single attempt used59 callbacks;78 was its cumulative
    # count including an earlier8-fixture19-callback preparation, not one suite run.
    assert row["policy_fixtures"] == 16 and callbacks == row["mock_callback_calls"] == 59
    assert row["new_exact_IDP_calls"] == row["new_legacy_IDP_calls"] == 0
    record.update(policy_fixtures=16, actual_exact_IDP_calls_all_attempts=charged[1],
                  actual_legacy_IDP_calls_all_attempts=charged[0],
                  inherited_controls_byte_equivalent_except_charge_instrumentation=True)
    save(HERE / "control_results.json", record)
    frozen = {name: sha(HERE / name) for name in
              ("trajectory.cpp", "trajectory", "build.py", "exact_scorer.h", "moves.json",
               "LICENSE-CrypTool-2.txt", "ATTRIBUTION.txt", "build_record.json", "control_results.json")}
    save(HERE / "sourcefreeze.json",
         {"status": "ready_for_independent_pre_truth_audit", "hashes": frozen,
          "new_IDP_calls": 0, "mock_callback_calls": callbacks,
          "truth_generated": False, "rng_executions": 0, "main_runs": 0})
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("build", "controls", "finalize-saved-controls"))
    action = parser.parse_args().action
    {"build": build, "controls": controls, "finalize-saved-controls": finalize_saved_controls}[action]()

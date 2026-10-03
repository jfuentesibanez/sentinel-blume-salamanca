"""Replay saved B records only. No scorer, RNG, plaintext, or target input.

Required profile fields: policy, max_calls, max_sweeps, csv_path, summary_path,
start_path, start_sha256. Optional: soft_seconds (default30), moves_path.
Required run fields: summary, csv_sha256, summary_sha256, backend_marker_calls
(integer exact-call count). Optional calls_path/calls_sha256 enable an additional
literal backend-marker replay. Paths resolve against the workspace root.

audit_profile returns first/last already-charged samples in numeric_samples.
Use that field for numerical references, avoiding a second CSV replay.
numeric_samples is a convenience entrypoint that performs one complete audit.
No command-line action is provided, and this helper is not executed at creation.
"""
from pathlib import Path
from itertools import groupby
import csv
import hashlib
import json
import math


FIELDS = ["call", "sweep", "move_index", "move_kind", "base_numerator",
          "numerator", "base_numeric", "candidate_numeric", "improves_base",
          "accepted_immediate", "archive_changed"]
DEFAULT_MOVES_PATH = "work/phase18_crypto/moves.json"


def require(condition, message):
    """Keep checks active even when the caller uses python -O."""
    if not condition:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def workspace_path(root, path):
    root = Path(root).resolve()
    resolved = (root / path).resolve()
    require(resolved.is_relative_to(root), "Record path escapes workspace")
    return resolved


def read_key(text, width, separator=":"):
    values = tuple(map(int, text.split(separator) if separator else text.split()))
    require(len(values) == width and sorted(values) == list(range(width)),
            "Saved key is not a permutation of the declared width")
    return values


def sample_record(row, key, numerator):
    return {"call": int(row["call"]), "sweep": int(row["sweep"]),
            "move_index": int(row["move_index"]), "numeric": list(key),
            "numerator": numerator}


def audit_profile(profile, run, root):
    """Reconstruct a successful saved B route without objective evaluations."""
    require(profile["policy"] == "B", "Phase18 record audit accepts B only")
    if "status" in run:
        require(run["status"] in ("recorded", "completed"), "Run was not completed")
    if "returncode" in run:
        require(run["returncode"] == 0, "Cannot certify a failed solver record")
    if "timed_out" in run:
        require(run["timed_out"] is False, "Cannot certify a killed process")

    paths = {field: workspace_path(root, profile[field])
             for field in ("csv_path", "summary_path", "start_path")}
    hashes = {field: sha(path) for field, path in paths.items()}
    require(hashes["csv_path"] == run["csv_sha256"], "CSV hash mismatch")
    require(hashes["summary_path"] == run["summary_sha256"], "Summary hash mismatch")
    require(hashes["start_path"] == profile["start_sha256"], "Start hash mismatch")
    summary = json.loads(paths["summary_path"].read_text())
    require(summary == run["summary"], "Saved and manifest summaries differ")
    require(summary["mode"] == "phase18_k2_trajectory" and summary["policy"] == "B",
            "Unexpected solver mode or policy")
    require((summary["w1"], summary["w2"], summary["convention"]) == (20, 25, 0),
            "Unexpected phase18 geometry or convention")
    require(summary["lengths"] == [615, 160], "Unexpected ciphertext lengths")
    width = summary["w2"]
    start = read_key(paths["start_path"].read_text(), width, separator=None)
    require(list(start) == summary["initial_numeric"], "Summary initial key differs")
    require(summary["call_limit"] == profile["max_calls"] and
            summary["sweep_limit"] == profile["max_sweeps"], "Limit differs from profile")
    require(profile["max_calls"] >= 1 and profile["max_sweeps"] >= 1,
            "Invalid profile budget")

    moves_path = workspace_path(root, profile.get("moves_path", DEFAULT_MOVES_PATH))
    moves_doc = json.loads(moves_path.read_text())
    moves = moves_doc["moves"]
    require(moves_doc["width"] == width, "Move catalogue width differs")
    require(len(moves) == summary["source_moves"] == 16649, "Move catalogue size differs")
    require(len({tuple(move["p"]) for move in moves}) == len(moves),
            "Duplicate movements in the source catalogue")
    for index, move in enumerate(moves, 1):
        require(move["index"] == index and sorted(move["p"]) == list(range(width)),
                "Move index or mapping is invalid")
    hashes["moves_path"] = sha(moves_path)
    if "moves_sha256" in profile:
        require(hashes["moves_path"] == profile["moves_sha256"], "Moves hash differs")

    denominator = summary["denominator"]
    rows = sum(length // summary["w1"] for length in summary["lengths"])
    require(isinstance(denominator, int) and denominator > 0,
            "Exact denominator is not a positive integer")
    require(summary["scale"] > 0 and
            denominator == summary["scale"] * rows * summary["w1"],
            "Denominator differs from declared geometry and model scale")
    require(summary["checked_absolute_numerator_bound"] >= 0, "Invalid numerator bound")

    def improves(candidate, base):
        return (candidate - base) * 10**12 > denominator

    state, value, count = start, None, 0
    archive, seen, accepts, sweeps = [], {}, [], []
    first_sample = last_sample = None

    def register(row):
        nonlocal count, archive, first_sample, last_sample
        count += 1
        require(int(row["call"]) == count, "CSV call sequence has a gap or duplicate")
        require(count <= profile["max_calls"], "CSV exceeds profile call budget")
        candidate = read_key(row["candidate_numeric"], width)
        numerator = int(row["numerator"])
        require(abs(numerator) <= summary["checked_absolute_numerator_bound"],
                "Saved numerator exceeds the declared bound")
        require(candidate not in seen or seen[candidate] == numerator,
                "Identical key has inconsistent saved numerators")
        seen[candidate] = numerator
        before = tuple(archive)
        if not any(key == candidate for _, key in archive):
            archive = sorted(archive + [(numerator, candidate)],
                             key=lambda item: (-item[0], item[1]))[:5]
        for field in ("archive_changed", "improves_base", "accepted_immediate"):
            require(row[field] in ("0", "1"), "CSV boolean field is invalid")
        require((row["archive_changed"] == "1") == (before != tuple(archive)),
                "CSV archive_changed differs from reconstructed top5")
        sampled = sample_record(row, candidate, numerator)
        if first_sample is None:
            first_sample = sampled
        last_sample = sampled
        return candidate, numerator

    with paths["csv_path"].open(newline="") as stream:
        reader = csv.DictReader(stream)
        require(reader.fieldnames == FIELDS, "Unexpected CSV schema")
        first = next(reader, None)
        if first is not None:
            require(int(first["sweep"]) == int(first["move_index"]) == 0 and
                    int(first["move_kind"]) == -1, "Missing initial scored row")
            candidate, value = register(first)
            require(candidate == read_key(first["base_numeric"], width) == state,
                    "Initial scored key differs from supplied start")
            require(int(first["base_numerator"]) == value and
                    first["improves_base"] == first["accepted_immediate"] == "0",
                    "Initial row score or acceptance differs")

        for sweep_number, group in groupby(reader, key=lambda row: int(row["sweep"])):
            require(value is not None, "Sweep appeared before initial scoring")
            require(sweep_number == len(sweeps) + 1 <= profile["max_sweeps"],
                    "Sweep order or budget differs")
            require(not sweeps or (sweeps[-1]["complete"] and
                    not sweeps[-1]["convergence_observed"]),
                    "Solver continued after a partial or converged sweep")
            sweep_start, sweep_value, start_call = state, value, count
            best_key, best_num, best_call, best_index = state, value, 0, 0
            proposals = 0
            for row in group:
                proposals += 1
                index = int(row["move_index"])
                require(index == proposals <= len(moves), "Source order differs")
                move = moves[index - 1]
                require(int(row["move_kind"]) == move["kind"], "Movement kind differs")
                require(read_key(row["base_numeric"], width) == sweep_start and
                        int(row["base_numerator"]) == sweep_value,
                        "B proposal does not use the fixed sweep anchor")
                candidate, num = register(row)
                require(candidate == tuple(sweep_start[j] for j in move["p"]),
                        "Saved candidate differs from the source movement")
                require((row["improves_base"] == "1") == improves(num, sweep_value),
                        "Saved improvement differs from rational EPS decision")
                require(row["accepted_immediate"] == "0", "B accepted an immediate proposal")
                # Strict comparison retains the earliest source movement on ties.
                if num > best_num:
                    best_key, best_num, best_call, best_index = candidate, num, count, index

            require(proposals > 0, "Empty sweep was recorded")
            complete = proposals == len(moves)
            accepted = complete and improves(best_num, sweep_value)
            if accepted:
                accepts.append({"call": count, "selected_call": best_call,
                                "sweep": sweep_number, "move_index": best_index,
                                "from_numeric": list(state), "to_numeric": list(best_key),
                                "from_numerator": value, "to_numerator": best_num})
                state, value = best_key, best_num
            sweeps.append({"sweep": sweep_number, "start_call": start_call,
                           "end_call": count, "proposals": proposals, "complete": complete,
                           "start_numeric": list(sweep_start), "final_numeric": list(state),
                           "start_numerator": sweep_value, "final_numerator": value,
                           "improvement_accepted": accepted, "selected_call": best_call,
                           "selected_move_index": best_index, "selected_numerator": best_num,
                           "convergence_observed": complete and not accepted,
                           "partial_best_admitted": False})

    marker_count = run["backend_marker_calls"]
    require(isinstance(marker_count, int) and not isinstance(marker_count, bool),
            "backend_marker_calls must be the integer exact-call count")
    require(count == summary["calls"] == summary["backend_exact_calls"] == marker_count,
            "CSV, summary, and backend-marker call counts differ")
    require(summary["backend_legacy_calls"] == 0, "Legacy scorer was used")
    require(summary["initial_scored"] is bool(count), "initial_scored differs from rows")
    require(summary["final_numeric"] == list(state) and summary["final_numerator"] == value,
            "Final key or numerator differs from reconstructed B state")
    require(summary["archive"] == [dict(rank=index + 1, numerator=num, numeric=list(key))
                                  for index, (num, key) in enumerate(archive)],
            "Final archive differs from reconstructed top5")
    require(summary["visited_unique"] == len(seen), "Distinct visited-key count differs")
    require(summary["accept_events"] == accepts and summary["accepted_changes"] == len(accepts),
            "Acceptance events differ from reconstructed full-sweep B selection")
    require(summary["sweep_events"] == sweeps, "Sweep events differ from reconstructed B route")
    full = sum(event["complete"] for event in sweeps)
    partial = len(sweeps) - full
    converged = any(event["convergence_observed"] for event in sweeps)
    require(summary["full_sweeps"] == full and summary["partial_sweeps"] == partial,
            "Full/partial sweep counters differ")
    require(summary["convergence_observed"] is converged, "Convergence flag differs")
    require(partial <= 1 and (not partial or not sweeps[-1]["complete"]),
            "Partial sweep was not terminal")

    seconds_limit = profile.get("soft_seconds", 30)
    require(summary["seconds_limit"] == seconds_limit, "Soft time limit differs")
    for field in ("seconds", "setup_seconds", "score_seconds", "soft_excess_seconds"):
        require(math.isfinite(summary[field]) and summary[field] >= 0, "Invalid duration")
    require(summary["setup_seconds"] + summary["score_seconds"] <= summary["seconds"],
            "Setup and scoring duration exceed the complete route duration")
    if "process_seconds" in run:
        require(summary["seconds"] <= run["process_seconds"], "Duration exceeds process receipt")
    require(summary["soft_excess_seconds"] == max(0, summary["seconds"] - seconds_limit),
            "Soft time excess differs")
    require(summary["time_limit_reached"] is (summary["seconds"] >= seconds_limit),
            "Time-limit flag differs from saved duration")
    at_call_limit = count >= profile["max_calls"]
    require(summary["call_limit_reached"] is at_call_limit, "Call-limit flag differs")
    stop = summary["stop_reason"]
    require(stop in ("call_limit", "time_limit", "converged", "sweep_limit"),
            "Unknown termination reason")
    if at_call_limit:
        require(stop == "call_limit", "Call-limit priority differs")
    if stop == "call_limit":
        require(at_call_limit, "Call-limit termination lacks the call limit")
    elif stop == "time_limit":
        require(summary["time_limit_reached"] and not at_call_limit,
                "Time termination differs from recorded limits")
    elif stop == "converged":
        require(converged and not at_call_limit, "Convergence termination lacks a stable sweep")
    elif stop == "sweep_limit":
        require(full == profile["max_sweeps"] and not converged and not at_call_limit,
                "Sweep-limit termination differs from reconstructed route")

    literal_markers_checked = False
    if "calls_path" in run or "calls_sha256" in run:
        require("calls_path" in run and "calls_sha256" in run, "Incomplete marker-file metadata")
        trace = workspace_path(root, run["calls_path"])
        hashes["calls_path"] = sha(trace)
        require(hashes["calls_path"] == run["calls_sha256"], "Backend-marker file hash differs")
        marks = 0
        with trace.open() as stream:
            for line in stream:
                marks += 1
                require(line.rstrip("\r\n") == f"@calls 0 {marks}",
                        "Backend-marker sequence differs or contains unexpected output")
        require(marks == count, "Literal backend-marker count differs")
        literal_markers_checked = True

    return {"status": "passed_saved_record_replay", "rows_checked": count,
            "distinct_keys": len(seen), "accepted_changes": len(accepts),
            "full_sweeps": full, "partial_sweeps": partial,
            "convergence_observed": converged, "stop_reason": stop,
            "literal_markers_checked": literal_markers_checked,
            "hashes": hashes, "numeric_samples": [first_sample, last_sample],
            "new_IDP_calls": 0, "new_solver_runs": 0, "rng_draws": 0,
            "truth_read": False, "target_compared": False}


def numeric_samples(profile, run, root):
    """Return initial/last already-paid samples; no scoring or new proposals.

    This convenience call audits once. A caller that already used audit_profile
    should instead consume its returned numeric_samples to avoid a second replay.
    Missing samples are None. Duplicate first/last samples remain duplicated;
    a later numerical reference evaluator must charge both if it evaluates both.
    """
    return audit_profile(profile, run, root)["numeric_samples"]

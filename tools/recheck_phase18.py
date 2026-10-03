"""Read-only phase18 hashes, saved receipts and summary cross-checks.

No CSV row replay, scoring, RNG, solver/imported scientific code or network.
Uses the completed manifest/audit schema; the final export test is pending.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path

PLAN_SHA256 = "97b8d8ef0c90cf58c2787410cf62a6193ee6ab3fe0d7ac91d9512fa4e095b717"
BASELINE_COUNT = 1081
BASELINE_SHA256 = "4ad68132838f5ca9f0f0a6727b5444b2c057052fcca74d99aa104eb425346ad4"
CRYPTO = "work/phase18_crypto/"
AUD = "work/phase18_root/"
REVIEW = "work/phase18_review/"
INVENTORY = "provenance/phase18_source_inventory.jsonl"
UPDATE = "provenance/phase18_update.json"
ARCHIVE = "provenance/phase18_file_hashes.json"
LOCAL_ONLY = {
    AUD + "seed_reservation.json", AUD + "frozen_before.json",
    CRYPTO + "trajectory", CRYPTO + "generate",
}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def safe(root, relative):
    need(isinstance(relative, str) and relative and
         not Path(relative).is_absolute() and ".." not in Path(relative).parts,
         "Unsafe relative path: " + repr(relative))
    path = (root / relative).resolve()
    need(path.is_relative_to(root), "Path escapes export: " + relative)
    return path


def load(root, relative):
    return json.loads(safe(root, relative).read_text(encoding="utf-8"))


def perm(values, width, label):
    need(isinstance(values, list) and len(values) == width and
         all(type(v) is int for v in values) and sorted(values) == list(range(width)),
         "Invalid permutation: " + label)


def inverse(values):
    out = [0] * len(values)
    for i, value in enumerate(values):
        out[value] = i
    return out


def check_inventory(root):
    entries = [json.loads(line) for line in safe(root, INVENTORY).read_text().splitlines() if line]
    by_source = {}
    included = {}
    for entry in entries:
        source = entry["source_path"]
        safe(root, source)
        need(source not in by_source, "Duplicate inventory source: " + source)
        need(isinstance(entry.get("sha256"), str) and len(entry["sha256"]) == 64,
             "Missing source hash: " + source)
        by_source[source] = entry
        kind = entry["disposition"]
        need(kind in ("included", "referenced_only", "excluded"), "Unknown disposition")
        if kind == "included":
            target = entry["repository_path"]
            need(target not in included, "Duplicate destination: " + target)
            path = safe(root, target)
            need(path.is_file() and path.stat().st_size == entry["bytes"] and
                 digest(path) == entry["sha256"], "Copy hash/size mismatch: " + target)
            need(not any(p in ("__pycache__", ".repro") for p in Path(target).parts) and
                 not target.endswith((".pyc", ".o", ".dylib", ".so", ".exe")),
                 "Compiled/cache file selected: " + target)
            included[target] = entry["sha256"]
        else:
            need(entry.get("reason"), "Reference/exclusion lacks reason: " + source)
    for name in LOCAL_ONLY:
        need(name in by_source and by_source[name]["disposition"] == "referenced_only",
             "Required private/binary reference absent: " + name)
        need(not safe(root, name).exists(), "Local-only resource copied: " + name)
    update = load(root, UPDATE)
    need(update["new_inventory_entries"] == len(entries), "Inventory count differs")
    need(update["new_included_files"] == len(included), "Included count differs")
    need(update["new_referenced_files"] == sum(e["disposition"] == "referenced_only" for e in entries),
         "Reference count differs")
    need(digest(safe(root, ARCHIVE)) == BASELINE_SHA256, "Archived checksum bytes differ")
    prior = load(root, ARCHIVE)
    current = load(root, "provenance/file_hashes.json")
    need(len(prior) == BASELINE_COUNT, "Baseline checksum count differs")
    allowed = set(update["allowed_current_document_changes"])
    need(len(allowed) == 3 and allowed <= {
        "README.md", "docs/STATUS.md", "docs/CONTEXT_FOR_CLAUDE.md",
        "docs/REPRODUCIBILITY.md", "docs/SOURCES.md"}, "Current-document exception differs")
    need(set(prior) <= set(current), "Prior checksum entries removed")
    for name, value in prior.items():
        if name not in allowed:
            need(current[name] == value, "Prior checksum digest changed: " + name)
    additions = set(update["new_manifest_paths"])
    need(set(current) == set(prior) | additions, "Unexpected manifest addition/removal")
    need(set(included) <= additions, "Included copy absent from new paths")
    for name, value in included.items():
        need(current[name] == value, "Included copy differs from current checksum")
    return by_source, included, update


def resources(root, plan, by_source):
    for name, value in plan["resources"].items():
        path = safe(root, name)
        if path.is_file():
            need(digest(path) == value, "Resource hash differs: " + name)
        else:
            entry = by_source.get(name)
            need(entry and entry["disposition"] == "referenced_only" and
                 entry["sha256"] == value and entry.get("reason"),
                 "Missing resource lacks exact reference: " + name)


def recorded_zero(obj, fields, label):
    for name in fields:
        need(obj[name] == 0, "Unexpected new work in " + label + ": " + name)


def check(root):
    inventory, included, update = check_inventory(root)
    plan_path, manifest_path = CRYPTO + "plan.json", CRYPTO + "manifest.json"
    ph, mh = digest(safe(root, plan_path)), digest(safe(root, manifest_path))
    need(ph == PLAN_SHA256, "Final prospective plan differs")
    plan, manifest = load(root, plan_path), load(root, manifest_path)
    resources(root, plan, inventory)
    seed_note = load(root, "work/phase18_publication/seed_audit_public_summary.json")
    need(seed_note["source_sha256"] == plan["resources"][AUD + "seed_reservation.json"] and
         seed_note["prior_use_hits_count"] == 0 and
         seed_note["case_seeds"] == [c["plant_seed"] for c in plan["cases"]] and
         seed_note["start_seeds"] == [s for c in plan["cases"] for s in c["start_seeds"]],
         "Safe seed-audit summary differs from fixed resources")
    need(plan["geometry"] == {"w1": 20, "w2": 25, "lengths": [615, 160], "convention": 0},
         "Geometry differs")
    need(manifest["status"] == "completed" and manifest["protected_unchanged"] is True and
         manifest["plan_sha256"] == ph, "Completed fixed execution required")
    need(manifest["deadline_monotonic"] == manifest["started_monotonic"] + 600 and
         manifest["deadline_unix"] == manifest["started_at_unix"] + 600 and
         manifest["started_at_unix"] <= manifest["ended_at_unix"] <= manifest["deadline_unix"],
         "Saved global wall/monotonic guard differs")
    need(manifest["disk_observed_bytes"] <= plan["execution_guard"]["disk_bytes"], "Disk ceiling exceeded")
    gate = load(root, AUD + "audit_approval.json")
    need(gate["root_approved"] is True and gate["independent_approved"] is True and
         gate["plan_sha256"] == ph and gate["resources"] == plan["resources"], "Pre-truth gate differs")
    root_pre = load(root, AUD + "root_preapproval.json")
    ind_pre = load(root, REVIEW + "preapproval.json")
    need(root_pre["status"] == "passed_before_truth" and root_pre["root_approved"] is True and
         ind_pre["status"] == "approved_before_truth" and ind_pre["independent_approved"] is True,
         "Matching pre-truth approvals required")
    for record in (root_pre, ind_pre):
        need(record["plan_sha256"] == ph and record["resources"] == plan["resources"] and
             record["RNG_calls"] == record["IDP_calls"] == 0 and record["truth_generated"] is False,
             "Preapproval scope/resource binding differs")
    need(gate["root_receipt_sha256"] == digest(safe(root, AUD + "root_preapproval.json")) and
         gate["independent_receipt_sha256"] == digest(safe(root, REVIEW + "preapproval.json")),
         "Gate preapproval hash differs")
    truth = [json.loads(line) for line in safe(root, manifest["truth_path"]).read_text().splitlines() if line]
    need(manifest["truth_path"] == "work/phase18_truth/truth.jsonl" and
         digest(safe(root, manifest["truth_path"])) == manifest["truth_sha256"], "Truth binding differs")
    case_map = {c["case_id"]: c for c in manifest["cases"]}
    truth_map = {c["case_id"]: c for c in truth}
    need(len(case_map) == len(truth_map) == len(plan["cases"]) == 4 and
         set(case_map) == set(truth_map) == {c["case_id"] for c in plan["cases"]}, "Case layout differs")
    need(manifest["distinct_keypairs"] == manifest["distinct_plaintexts"] == 4, "Distinct-case receipt differs")
    for planned in plan["cases"]:
        cid = planned["case_id"]
        t, c = truth_map[cid], case_map[cid]
        for name in ("language_model", "plant_seed", "sample_position"):
            need(c[name] == t[name] == planned[name], "Reserved case field differs")
        perm(t["true_k1"], 20, cid); perm(t["true_k2"], 25, cid)
        need(len(c["ciphertext_files"]) == 2, "Ciphertext denominator differs")
        for item in c["ciphertext_files"]:
            need(digest(safe(root, item["path"])) == item["sha256"], "Ciphertext hash differs")
    need(len({(tuple(t["true_k1"]), tuple(t["true_k2"])) for t in truth}) == 4 and
         len({tuple(t["plaintext_sha256"]) for t in truth}) == 4, "Distinct synthetic cases differ")
    attempts = manifest["generation_attempts"]
    need(len(attempts) == 12, "Generation-attempt denominator differs")
    for a in attempts:
        need(a["status"] == "completed" and a["returncode"] == 0 and a["guard_stop"] is None,
             "Generation failure or repeat")
        for kind in ("stdout", "stderr"):
            need(digest(safe(root, a[kind + "_path"])) == a[kind + "_sha256"], "Generation receipt hash differs")

    root_audit = load(root, AUD + "records_root.json")
    independent = load(root, REVIEW + "records_independent.json")
    numeric = load(root, AUD + "numeric_attempt.json")
    for record in (root_audit, independent, numeric):
        need(record["status"] == "passed" and record["manifest_sha256"] == mh, "Postrun gate differs")
    need(root_audit["source_sha256"] == plan["resources"][CRYPTO + "audit_records.py"] and
         independent["source_sha256"] == plan["resources"][REVIEW + "independent_records.py"] and
         independent["plan_sha256"] == ph and
         numeric["source_sha256"] == plan["resources"][CRYPTO + "experiment.py"], "Audit source binding differs")
    recorded_zero(root_audit, ("new_IDP",), "root records")
    recorded_zero(independent, ("new_IDP", "new_solver_runs", "rng_draws"), "independent records")
    need(root_audit["truth_read"] is independent["truth_read"] is numeric["truth_read"] is False and
         independent["target_compared"] is False, "Pre-target audit scope differs")
    need(independent["audit_seconds"] <= independent["audit_limit_seconds"] == 120, "Independent audit guard differs")
    need(numeric["legacy_calls_started"] == numeric["new_searches"] == 0 and
         numeric["exact_calls_started"] <= plan["ceilings"]["reference_IDP"], "Numeric-reference cost differs")
    target_gate = load(root, AUD + "target_gate.json")
    need(target_gate["root_approved"] is target_gate["independent_approved"] is True and
         target_gate["manifest_sha256"] == mh and target_gate["plan_sha256"] == ph, "Target gate differs")
    need(target_gate["target_comparison_attempts_authorized"] == 1 and
         target_gate["new_IDP_authorized"] == 0 and
         target_gate["independent_conformity_sha256"] == digest(safe(root, REVIEW + "target_conformity.json")),
         "External evaluation authorization differs")
    for field, relative in (("records_root_sha256", AUD + "records_root.json"),
                            ("records_independent_sha256", REVIEW + "records_independent.json"),
                            ("numeric_sha256", AUD + "numeric_attempt.json")):
        need(target_gate[field] == digest(safe(root, relative)), "Target gate receipt hash differs")
    evaluation = load(root, CRYPTO + "evaluation.json")
    need(evaluation["status"] == "evaluated" and evaluation["manifest_sha256"] == mh and
         evaluation["plan_sha256"] == ph and evaluation["truth_sha256"] == manifest["truth_sha256"],
         "Evaluation binding differs")
    recorded_zero(evaluation, ("new_IDP", "new_searches"), "evaluation")
    need(evaluation["cases"] == truth, "Evaluation truth metadata differs")
    profiles, runs, evs = manifest["profiles"], manifest["runs"], evaluation["profiles"]
    need(len(profiles) == len(runs) == len(evs) == len(root_audit["profiles"]) == len(independent["profiles"]) == 12,
         "Expected twelve completed routes and two audited sets")
    need(len({p["profile_id"] for p in profiles}) == 12, "Duplicate profile")
    expected_layout = [(c["case_id"], "main", "random" + str(i)) for c in plan["cases"] for i in (1, 2)]
    expected_layout += [(c["case_id"], "positive_control", "h2") for c in plan["cases"]]
    need([(p["case_id"], p["category"], p["start_name"]) for p in profiles] == expected_layout,
         "Planned case/main/control order differs")
    ra = {p["profile_id"]: p for p in root_audit["profiles"]}
    ia = {p["profile_id"]: p for p in independent["profiles"]}
    main, positive, initial_keys, expected_numeric = [], [], set(), []
    for p, run, e in zip(profiles, runs, evs):
        pid, cid = p["profile_id"], p["case_id"]
        need(pid == run["profile_id"] == e["profile_id"] and cid == run["case_id"] == e["case_id"],
             "Profile/run/evaluation order differs")
        category = p["category"]
        need(category in ("main", "positive_control") and p["policy"] == "B" and
             p["privileged"] == (category == "positive_control"), "Policy/privilege differs")
        need(p["model_path"] == "work/phase5_language/" + case_map[cid]["language_model"] + "/model.bin",
             "Profile model differs")
        limits = plan["main_limits" if category == "main" else "positive_limits"]
        for name, value in limits.items():
            need(p[name] == value, "Pre-fixed profile limit differs")
        need(run["status"] == "completed" and run["returncode"] == 0 and run["guard_stop"] is None and
             run["cost_uncertain"] is False and run["legacy_calls"] == 0 and
             run["marker_fragments"] == [], "Incomplete/uncertain route")
        summary = load(root, p["summary_path"])
        need(summary == run["summary"], "Standalone summary differs")
        for field in ("csv", "summary", "calls"):
            # Hash bytes only; never parse CSV rows or marker lines.
            need(digest(safe(root, p[field + "_path"])) == run[field + "_sha256"], "Trajectory hash differs")
        need(digest(safe(root, p["stdout_path"])) == run["stdout_sha256"], "Process stdout hash differs")
        calls = summary["calls"]
        need(0 < calls <= p["max_calls"] and summary["backend_exact_calls"] == calls and
             summary["backend_legacy_calls"] == 0 and
             run["backend_marker_calls"] == run["complete_marker_prefix"] ==
             run["exact_calls_started_lower"] == run["exact_calls_started_upper"] == calls,
             "Exact ledger/summary costs differ")
        need(ra[pid]["status"] == "passed_saved_record_replay" and ia[pid]["status"] == "passed" and
             ra[pid]["literal_markers_checked"] is True and ia[pid]["literal_backend_markers"] == calls,
             "Saved audits lack matching marker count")
        for a in (ra[pid], ia[pid]):
            need(a["rows_checked"] == calls and a["distinct_keys"] == summary["visited_unique"], "Audit totals differ")
            for field in ("full_sweeps", "partial_sweeps", "accepted_changes", "convergence_observed", "stop_reason"):
                need(a[field] == summary[field], "Audited summary field differs")
            for field, value in a["hashes"].items():
                path = CRYPTO + "moves.json" if field == "moves_path" else p[field]
                need(digest(safe(root, path)) == value, "Audited file hash differs")
        recorded_zero(ra[pid], ("new_IDP_calls", "new_solver_runs", "rng_draws"), "root route")
        recorded_zero(ia[pid], ("new_IDP", "new_solver_runs"), "independent route")
        need(ra[pid]["truth_read"] is ra[pid]["target_compared"] is ia[pid]["truth_read"] is False and
             ra[pid]["numeric_samples"] == ia[pid]["numeric_samples"], "Audited sample/scope differs")
        for sample in ra[pid]["numeric_samples"]:
            if sample is None:
                expected_numeric.append(dict(profile_id=pid, sample_unavailable=True, reference_IDP=0))
            else:
                expected_numeric.append(dict(profile_id=pid, call=sample["call"], numerator=sample["numerator"]))
        start = list(map(int, safe(root, p["start_path"]).read_text().split()))
        perm(start, 25, pid)
        need(digest(safe(root, p["start_path"])) == p["start_sha256"], "Start hash differs")
        need(summary["initial_numeric"] == start and summary["initial_scored"] is True and
             summary["policy"] == "B" and summary["w1"] == 20 and summary["w2"] == 25 and
             summary["lengths"] == [615, 160] and summary["convention"] == 0 and
             summary["source_moves"] == 16649, "Summary geometry/initial state differs")
        target = inverse(truth_map[cid]["true_k2"])
        if category == "main":
            planned = next(c for c in plan["cases"] if c["case_id"] == cid)
            need(p["start_name"] in ("random1", "random2") and
                 p["start_seed"] == planned["start_seeds"][int(p["start_name"][-1]) - 1], "Start seed differs")
            generation = load(root, CRYPTO + "generation/" + cid + "_start" + p["start_name"][-1] + ".json")
            need(generation["seed"] == p["start_seed"] and generation["numeric"] == start, "Saved initial key differs")
            initial_keys.add(tuple(start)); main.append(e)
        else:
            swapped = list(target); swapped[0], swapped[1] = swapped[1], swapped[0]
            need(p["start_name"] == "h2" and p["start_seed"] is None and start == swapped, "Privileged control differs")
            positive.append(e)
        for field in ("category", "start_name", "start_seed", "privileged"):
            need(e[field] == p[field], "External profile metadata differs")
        need(e["initial_hamming"] == sum(a != b for a, b in zip(start, target)), "Initial Hamming differs")
        perm(summary["final_numeric"], 25, pid)
        archive = summary["archive"]
        need(len(archive) <= 5 and len({tuple(v["numeric"]) for v in archive}) == len(archive), "Distinct top5 differs")
        for i, item in enumerate(archive, 1):
            perm(item["numeric"], 25, pid)
            need(item["rank"] == i and type(item["numerator"]) is int, "Archive schema differs")
        need(archive == sorted(archive, key=lambda v: (-v["numerator"], v["numeric"])), "Archive order differs")
        rank = next((i for i, v in enumerate(archive, 1) if v["numeric"] == target), None)
        need(e["final_archive_target_rank"] == rank and e["target_final_top5"] == (rank is not None) and
             e["final_current_is_target"] == (summary["final_numeric"] == target), "Final target metric differs")
        adopted = [a["call"] for a in summary["accept_events"] if a["to_numeric"] == target]
        first_adopt = 1 if start == target and calls else min(adopted) if adopted else None
        need(e["first_adoption_call"] == first_adopt, "First adoption differs from saved events")
        for field in ("visited_unique", "full_sweeps", "partial_sweeps", "accepted_changes", "convergence_observed", "stop_reason", "seconds"):
            need(e[field] == summary[field], "External summary field differs")
        need(e["exact_calls"] == calls and math.isfinite(e["seconds"]) and e["seconds"] >= 0,
             "External time/cost differs")
        # These descriptors require rows. Validate recorded coherence, not a new replay.
        for flag, field in (("target_ever_scored", "first_target_call"), ("target_ever_top5", "first_target_top5_call")):
            value = e[field]
            need(e[flag] == (value is not None) and (value is None or type(value) is int and 1 <= value <= calls),
                 "Recorded first-target descriptor inconsistent")
        need(not e["target_final_top5"] or e["target_ever_top5"], "Final target absent from ever-top5 receipt")
        need(not e["target_ever_top5"] or e["target_ever_scored"], "Top5 target never scored")
        minimum = e["minimum_scored_hamming"]
        need(type(minimum) is int and 0 <= minimum <= e["initial_hamming"] <= 25 and
             (minimum == 0) == e["target_ever_scored"], "Recorded minimum-Hamming descriptor inconsistent")
    need(len(main) == 8 and len(positive) == 4 and profiles[:8] == [p for p in profiles if p["category"] == "main"],
         "Nested-main/separate-control denominators differ")
    totals = dict(main_profiles=8, main_cases=4,
                  main_final_top5=sum(e["target_final_top5"] for e in main),
                  main_ever_scored=sum(e["target_ever_scored"] for e in main),
                  main_final_current=sum(e["final_current_is_target"] for e in main),
                  positive_profiles=4,
                  positive_final_top5=sum(e["target_final_top5"] for e in positive),
                  positive_final_current=sum(e["final_current_is_target"] for e in positive),
                  main_IDP=sum(e["exact_calls"] for e in main),
                  positive_IDP=sum(e["exact_calls"] for e in positive),
                  reference_IDP=numeric["exact_calls_started"], mock_callbacks=59)
    totals["total_IDP"] = totals["main_IDP"] + totals["positive_IDP"] + totals["reference_IDP"]
    need(evaluation["totals"] == totals and evaluation["initial_distinct_main_keys"] == len(initial_keys),
         "External aggregate differs")
    need(numeric["results"] == expected_numeric and numeric["exact_calls_started"] ==
         sum("sample_unavailable" not in r for r in expected_numeric), "Already-paid numerical-reference samples differ")
    need(manifest["main_exact_calls"] == independent["main_calls"] == totals["main_IDP"] <= plan["ceilings"]["main_IDP"] and
         manifest["positive_exact_calls"] == independent["positive_calls"] == totals["positive_IDP"] <= plan["ceilings"]["positive_IDP"] and
         totals["total_IDP"] <= plan["ceilings"]["total_IDP"], "Aggregate IDP ledger differs")
    controls = load(root, CRYPTO + "control_results.json")
    need(controls == plan["controls_preparation"] and controls["mock_callback_calls"] == 59 and
         controls["actual_exact_IDP_calls_all_attempts"] == controls["actual_legacy_IDP_calls_all_attempts"] == 0,
         "Separate mock/actual controls differ")
    # Final receipt schema is explicit in the new publication update, never guessed.
    bindings = update["receipt_bindings"]
    need({b["path"] for b in bindings} >= {
        AUD + "execution_launch_receipt.json", AUD + "evaluation_receipt.json", AUD + "closeout_receipt.json"},
        "Required launch/evaluation/closeout bindings absent")
    need(update["result_totals"] == totals, "Publication result totals differ")
    for binding in bindings:
        need(binding["equals"] or binding["hash_fields"], "Empty receipt binding")
        record = load(root, binding["path"])
        for field, expected in binding["equals"].items():
            need(record[field] == expected, "Final receipt field differs: " + binding["path"] + ": " + field)
        for field, relative in binding["hash_fields"].items():
            need(record[field] == digest(safe(root, relative)), "Final receipt hash differs: " + binding["path"])
    launch = load(root, AUD + "execution_launch_receipt.json")
    need(launch["status"] == "completed" and launch["attempt"] == launch["maximum_attempts"] == 1 and
         launch["returncode"] == 0 and launch["plan_sha256"] == ph and launch["truth_before_launch"] is False and
         launch["new_IDP_before_launch"] == 0 and launch["runs"] == 12 and
         launch["main_IDP"] == totals["main_IDP"] and launch["positive_IDP"] == totals["positive_IDP"] and
         launch["requested_at_unix"] <= manifest["started_at_unix"] and
         launch["manifest_started_at_unix"] == manifest["started_at_unix"] and
         launch["manifest_ended_at_unix"] == manifest["ended_at_unix"], "Launch receipt differs")
    eval_receipt = load(root, AUD + "evaluation_receipt.json")
    need(eval_receipt["status"] == "completed_unique_target_comparison" and
         eval_receipt["totals"] == totals, "Evaluation receipt differs")
    recorded_zero(eval_receipt, ("new_IDP", "new_RNG", "new_searches"), "evaluation receipt")
    for field, relative in (("evaluation_sha256", CRYPTO + "evaluation.json"),
                            ("manifest_sha256", manifest_path), ("plan_sha256", plan_path),
                            ("target_gate_sha256", AUD + "target_gate.json")):
        need(eval_receipt[field] == digest(safe(root, relative)), "Evaluation receipt hash differs")
    closeout = load(root, AUD + "closeout_receipt.json")
    preservation = load(root, AUD + "protected_preservation.json")
    need(closeout["status"] == "scientific_completed_audited_closed" and closeout["totals"] == totals and
         closeout["solver_trajectories"] == 12 and closeout["failed_solver_trajectories"] == 0 and
         closeout["RNG_invocations"] == len(attempts) == 12 and closeout["scientific_reference_attempts"] == 1 and
         closeout["reference_IDP"] == totals["reference_IDP"] and
         closeout["post_outcome_scoring_extensions"] == 0, "Scientific closeout differs")
    for relative, value in closeout["hashes"].items():
        need(digest(safe(root, relative)) == value, "Scientific closeout hash differs: " + relative)
    need(preservation["status"] == "passed" and preservation["prior_files_changed"] == preservation["new_IDP"] == 0 and
         preservation["prior_files_checked"] == closeout["protected_prior_files"] == 3569 and
         preservation["baseline_sha256"] == plan["resources"][AUD + "frozen_before.json"],
         "Recorded private-baseline preservation differs")
    review = safe(root, REVIEW + "results_review.txt").read_text()
    need(digest(safe(root, "outputs/Sentinel_BLUME_fase18_2026-10-03.txt")) in review,
         "Content review lacks exact report-version hash")
    results_review = load(root, REVIEW + "results_metadata_crosscheck.json")
    need(results_review["status"] == "saved_metadata_crosscheck_passed" and
         results_review["totals"] == totals and results_review["profiles_checked"] == 12 and
         results_review["case_key_pairs_distinct"] == 4 and
         results_review["main_initial_keys_distinct"] == len(initial_keys), "Independent metadata review differs")
    recorded_zero(results_review, ("new_IDP", "new_RNG", "CSV_rows_read_this_review"), "results metadata review")
    for field, relative in (("evaluation_sha256", CRYPTO + "evaluation.json"),
                            ("evaluator_sha256", CRYPTO + "evaluate_external.py"),
                            ("target_gate_sha256", AUD + "target_gate.json")):
        need(results_review[field] == digest(safe(root, relative)), "Independent results-review hash differs")
    frozen = load(root, AUD + "frozen_science.json")
    need(frozen["status"] == "scientific_closed_frozen" and frozen["selected_files"] == len(frozen["hashes"]) and
         frozen["report_sha256"] == digest(safe(root, frozen["report_path"])), "Scientific freeze differs")
    for relative, value in frozen["hashes"].items():
        path = safe(root, relative)
        if path.is_file():
            need(digest(path) == value, "Frozen scientific bytes differ: " + relative)
        else:
            entry = inventory.get(relative)
            need(entry and entry["disposition"] == "referenced_only" and entry["sha256"] == value,
                 "Frozen local-only reference differs: " + relative)
    return {"status": "passed_metadata_and_hashes", "profiles": 12, "cases": 4,
            "recorded_totals": totals, "included_copies_checked": len(included),
            "new_IDP_calls": 0, "new_solver_runs": 0, "rng_draws": 0,
            "CSV_rows_replayed": 0,
            "scope": "Summary/metadata checks; row-dependent descriptors rely on two source-bound saved-record audits and sealed external evaluation."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    print(json.dumps(check(args.root.resolve()), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

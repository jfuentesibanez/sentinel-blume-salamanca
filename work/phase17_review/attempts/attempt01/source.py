#!/usr/bin/env python3
"""Independent phase 17 record audit; never imports the analyst or any scorer.

Prepared before execution. Reads only the fixed ten inputs, plan, approvals and
completed phase 17 outputs. Replays stored proposals, decisions and witnesses.
No objective values are computed. Every attempted audit is preserved separately.
"""
import csv
import hashlib
import json
from pathlib import Path
import signal
import time

PLAN_HASH = "c3c81e29da5e0d54dbd42706e4feeb4414324d091d2d9cd3a759fe114f42036f"
ANALYST_HASH = "28bebca8650461b807612f2b2aef9c2c54a0b9edd89eac8782e689e569b02232"
ROOT = Path(__file__).resolve().parents[2]


def insist(value, text):
    if not value:
        raise AssertionError(text)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(relative):
    return json.loads((ROOT / relative).read_text())


def ratio(value, den):
    return {"numerator": value, "denominator": den, "descriptive_float": value / den}


def key(text):
    out = tuple(map(int, text.split(":")))
    insist(len(out) == 25 and set(out) == set(range(25)), "CSV permutation")
    return out


def read_rows(path):
    out = []
    with (ROOT / path).open(newline="") as handle:
        for n, raw in enumerate(csv.DictReader(handle), 1):
            row = {name: int(raw[name]) for name in
                   ("call", "sweep", "move_index", "move_kind", "base_numerator", "numerator",
                    "improves_base", "accepted_immediate", "archive_changed")}
            row["base"] = key(raw["base_numeric"])
            row["candidate"] = key(raw["candidate_numeric"])
            insist(row["call"] == n, "Sequential calls")
            insist(all(row[name] in (0, 1) for name in
                       ("improves_base", "accepted_immediate", "archive_changed")), "Binary flags")
            out.append(row)
    return out


def ev(row, path, den):
    return {"csv_path": path, "call": row["call"], "sweep": row["sweep"],
            "move_index": row["move_index"], "move_kind": row["move_kind"],
            "base_numeric": list(row["base"]), "candidate_numeric": list(row["candidate"]),
            "base_numerator": row["base_numerator"], "numerator": row["numerator"],
            "margin_above_base": ratio(row["numerator"] - row["base_numerator"], den),
            "improves_base": bool(row["improves_base"]),
            "accepted_immediate": bool(row["accepted_immediate"])}


def subset(actual, expected, label):
    for field, value in expected.items():
        insist(actual[field] == value, label + ": " + field)


def replay(rows, summary, moves, policy, all_scores):
    """Group by saved sweep boundaries, independently replay both policies."""
    den = summary["denominator"]
    insist(den == 6375342080, "Frozen denominator")
    insist(summary["calls"] == summary["backend_exact_calls"] == len(rows), "Exact calls")
    insist(summary["backend_legacy_calls"] == summary["partial_sweeps"] == 0, "No legacy/partial")
    current = tuple(summary["initial_numeric"])
    value = rows[0]["numerator"]
    insist(rows[0]["candidate"] == rows[0]["base"] == current, "Initial key")
    insist(rows[0]["base_numerator"] == value, "Initial value")
    insist((rows[0]["call"], rows[0]["sweep"], rows[0]["move_index"], rows[0]["move_kind"])
           == (1, 0, 0, -1), "Initial marker")
    insist(not rows[0]["improves_base"] and not rows[0]["accepted_immediate"], "Initial flags")
    archive, visited, accepts = {}, set(), []

    def record(row):
        k, num = row["candidate"], row["numerator"]
        insist(all_scores.setdefault(k, num) == num, "Repeated key score")
        visited.add(k)
        old = sorted(archive.items(), key=lambda item: (-item[1], item[0]))
        archive[k] = num
        ordered = sorted(archive.items(), key=lambda item: (-item[1], item[0]))[:5]
        archive.clear()
        archive.update(ordered)
        insist(bool(row["archive_changed"]) == (old != ordered), "Archive flag")

    record(rows[0])
    previous_end = 1
    for sweep in summary["sweep_events"]:
        stop = sweep["end_call"]
        block = rows[previous_end:stop]
        insist(sweep["start_call"] == previous_end and len(block) == 16649, "Complete block")
        initial, initial_num = current, value
        start_accepts = len(accepts)
        for index, row in enumerate(block, 1):
            base, base_num = (current, value) if policy == "A" else (initial, initial_num)
            insist(row["sweep"] == sweep["sweep"] and row["move_index"] == index, "Move order")
            insist(row["move_kind"] == moves[index - 1]["kind"], "Move kind")
            insist(row["base"] == base and row["base_numerator"] == base_num, "Policy base")
            insist(row["candidate"] == tuple(base[p] for p in moves[index - 1]["p"]),
                   "Destination-to-source direction")
            better = (row["numerator"] - base_num) * 10**12 > den
            insist(bool(row["improves_base"]) == better, "Exact EPS")
            insist(bool(row["accepted_immediate"]) == (better and policy == "A"), "Accept flag")
            record(row)
            if better and policy == "A":
                accepts.append({"call": row["call"], "selected_call": row["call"],
                                "sweep": sweep["sweep"], "move_index": index,
                                "from_numeric": list(current), "to_numeric": list(row["candidate"]),
                                "from_numerator": value, "to_numerator": row["numerator"]})
                current, value = row["candidate"], row["numerator"]
        best = max(block, key=lambda r: (r["numerator"], -r["move_index"]))
        selection = best if policy == "B" and best["numerator"] > initial_num else None
        if selection and (selection["numerator"] - initial_num) * 10**12 > den:
            accepts.append({"call": stop, "selected_call": selection["call"],
                            "sweep": sweep["sweep"], "move_index": selection["move_index"],
                            "from_numeric": list(current), "to_numeric": list(selection["candidate"]),
                            "from_numerator": value, "to_numerator": selection["numerator"]})
            current, value = selection["candidate"], selection["numerator"]
        changed = len(accepts) > start_accepts
        insist(sweep == {"sweep": sweep["sweep"], "start_call": previous_end, "end_call": stop,
                        "proposals": 16649, "complete": True, "start_numeric": list(initial),
                        "final_numeric": list(current), "start_numerator": initial_num,
                        "final_numerator": value, "improvement_accepted": changed,
                        "selected_call": selection["call"] if selection else 0,
                        "selected_move_index": selection["move_index"] if selection else 0,
                        "selected_numerator": selection["numerator"] if selection else initial_num,
                        "convergence_observed": not changed, "partial_best_admitted": False},
               "Sweep close")
        previous_end = stop
    insist(previous_end == len(rows), "All rows covered")
    insist(accepts == summary["accept_events"], "Accept events")
    insist(current == tuple(summary["final_numeric"]) and value == summary["final_numerator"], "Final")
    insist(summary["accepted_changes"] == len(accepts), "Accept count")
    insist(summary["full_sweeps"] == len(summary["sweep_events"]), "Full sweeps")
    insist(summary["convergence_observed"] == any(e["convergence_observed"] for e in summary["sweep_events"]),
           "Convergence flag separate")
    insist(summary["visited_unique"] == len(visited), "Unique count")
    insist(summary["archive"] == [{"rank": i, "numerator": n, "numeric": list(k)} for i, (k, n)
                                  in enumerate(sorted(archive.items(), key=lambda item: (-item[1], item[0])), 1)],
           "Final top5")


def check_pair(selection, actual, moves, external):
    paths = selection["profiles"]
    rows = {p: read_rows(paths[p]["csv_path"]) for p in ("A", "B")}
    summaries = {p: load(paths[p]["summary_path"]) for p in ("A", "B")}
    scores = {}
    for p in ("A", "B"):
        replay(rows[p], summaries[p], moves, p, scores)
    a, b = summaries["A"], summaries["B"]
    den = a["denominator"]
    insist(rows["A"][0]["candidate"] == rows["B"][0]["candidate"], "Same start")
    insist(rows["A"][0]["numerator"] == rows["B"][0]["numerator"], "Same start score")
    init = rows["A"][0]["numerator"]
    subset(actual, {"case_id": selection["case_id"], "perturbation": selection["perturbation"],
                    "denominator": den, "initial_numerator": init,
                    "CSV_rows_checked": sum(map(len, rows.values())),
                    "distinct_saved_keys_checked_across_pair": len(scores)}, "Pair")
    for p in ("A", "B"):
        first = summaries[p]["accept_events"][0]
        subset(actual["first_decisions"][p],
               {"summary_path": paths[p]["summary_path"], "csv_path": paths[p]["csv_path"],
                "move_index": first["move_index"], "sweep": first["sweep"],
                "evaluated_call": first["selected_call"], "adoption_call": first["call"],
                "from_numeric": first["from_numeric"], "to_numeric": first["to_numeric"],
                "numerator": first["to_numerator"], "margin_above_initial": ratio(first["to_numerator"] - init, den)},
               "First decision " + p)
    prefix = a["accept_events"][0]["call"]
    for ar, br in zip(rows["A"][:prefix], rows["B"][:prefix]):
        insist({k: v for k, v in ar.items() if k not in ("accepted_immediate", "archive_changed")}
               == {k: v for k, v in br.items() if k not in ("accepted_immediate", "archive_changed")}, "Shared prefix")
    subset(actual["initial_comparable_prefix"], {"rows_including_initial": prefix,
           "last_common_scored_candidate_call": prefix, "first_policy_adoption_divergence_call": prefix,
           "bases_candidates_saved_scores_equal": True, "subsequent_rows_not_aligned_by_move_index": True}, "Prefix")
    states = [{"state_index": 0, "numeric": list(rows["B"][0]["candidate"]),
               "numerator": rows["B"][0]["numerator"], "evaluated_call": 1,
               "adoption_call": 1, "origin": "scored_initial"}]
    for i, accepted in enumerate(b["accept_events"], 1):
        states.append({"state_index": i, "numeric": accepted["to_numeric"], "numerator": accepted["to_numerator"],
                       "evaluated_call": accepted["selected_call"], "adoption_call": accepted["call"], "origin": "accepted_current"})
    currents = {tuple(a["initial_numeric"]): [{"call": 1, "origin": "initial"}]}
    for accepted in a["accept_events"]:
        currents.setdefault(tuple(accepted["to_numeric"]), []).append({"call": accepted["call"], "origin": "accepted_current"})
    visits = []
    for state in states:
        k = tuple(state["numeric"])
        matches = [ev(r, paths["A"]["csv_path"], den) for r in rows["A"] if r["candidate"] == k]
        visits.append({"B_current_state": state, "A_candidate_visit_count": len(matches),
                       "A_first_candidate_visit_call": matches[0]["call"] if matches else None,
                       "A_candidate_visits": matches, "A_current_state_occurrences": currents.get(k, []),
                       "A_ever_current": k in currents})
    insist(actual["B_current_states_and_A_visits"] == visits, "All B visits/current distinction")
    stable = [e for e in a["sweep_events"] if e["complete"] and not e["improvement_accepted"]
              and e["convergence_observed"] and e["start_numeric"] == e["final_numeric"] == a["final_numeric"]
              and e["start_numerator"] == e["final_numerator"] == a["final_numerator"]]
    insist(len(stable) == 1 and stable[0] == a["sweep_events"][-1], "Unique final stable sweep")
    close = stable[0]
    neighbors = rows["A"][close["start_call"]:close["end_call"]]
    insist(len(neighbors) == 16649 and [r["move_index"] for r in neighbors] == list(range(1, 16650)), "Coverage")
    final, final_num = tuple(a["final_numeric"]), a["final_numerator"]
    insist(all(r["base"] == final and r["base_numerator"] == final_num and not r["accepted_immediate"]
               for r in neighbors), "Stable fixed base")
    nums = [r["numerator"] for r in neighbors]
    unique = {r["candidate"]: r["numerator"] for r in neighbors}
    best_num = max(nums)

    def counts(values):
        return {"greater": sum(v > final_num for v in values), "equal": sum(v == final_num for v in values),
                "lower": sum(v < final_num for v in values)}

    stable_expected = {"csv_path": paths["A"]["csv_path"], "sweep_event": close,
                       "final_numeric": list(final), "final_numerator": final_num,
                       "proposal_count": len(neighbors), "unique_neighbor_count": len(unique),
                       "counts_by_proposal": counts(nums), "counts_by_unique_neighbor": counts(unique.values()),
                       "best_neighbor_numerator": best_num, "best_neighbor_margin_above_final": ratio(best_num - final_num, den),
                       "best_neighbor_evidence": [ev(r, paths["A"]["csv_path"], den) for r in neighbors if r["numerator"] == best_num],
                       "all_first_source_steps_strictly_lower": all(n < final_num for n in nums),
                       "has_equal_score_first_steps": any(n == final_num for n in nums)}
    subset(actual["stable_final_A_neighborhood"], stable_expected, "Final neighborhood")
    joins, shared = [], []
    for state in states:
        index = state["state_index"]
        firsts = [r for r in neighbors if list(r["candidate"]) == state["numeric"]]
        if tuple(state["numeric"]) == final:
            firsts = [None] + firsts
        for first in firsts:
            keys, values = [list(final)], [final_num]
            edges = []
            if first is not None:
                insist(first["numerator"] == state["numerator"], "Join score")
                keys.append(list(first["candidate"])); values.append(first["numerator"])
                edges.append({"origin": "final_A_recorded_proposal", "evidence": ev(first, paths["A"]["csv_path"], den)})
            else:
                insist(state["numerator"] == final_num, "Shared score")
            for accepted in b["accept_events"][index:]:
                insist(accepted["from_numeric"] == keys[-1] and accepted["from_numerator"] == values[-1], "Forward suffix")
                edges.append({"origin": "recorded_B_acceptance", "csv_path": paths["B"]["csv_path"], "accept_event": accepted})
                keys.append(accepted["to_numeric"]); values.append(accepted["to_numerator"])
            insist(keys[-1] == b["final_numeric"] and values[-1] == b["final_numerator"], "Witness endpoint")
            walk = {"join_B_state_index": index, "join_B_state": state,
                    "first_step_move_index": first["move_index"] if first else None,
                    "first_step_numerator": first["numerator"] if first else final_num,
                    "first_step_kind": "shared_current_no_identity_edge" if first is None else
                                       "descent" if first["numerator"] < final_num else
                                       "equal" if first["numerator"] == final_num else "increase",
                    "first_step_margin_above_A_final": ratio((first["numerator"] if first else final_num) - final_num, den),
                    "B_suffix_edges": len(b["accept_events"]) - index, "total_edges": len(edges),
                    "witness_keys": keys, "witness_numerators": values, "edges": edges,
                    "minimum_witness_numerator": min(values), "loss_below_A_final": ratio(max(0, final_num - min(values)), den),
                    "final_is_successful_B_by_saved_external_evaluation": True}
            (joins if first is not None else shared).append(walk)
    insist(len(actual["all_direct_joins"]) == len(joins), "All joins count")
    insist(len(actual["shared_current_coincidences"]) == len(shared), "Shared states count")
    for kind, walks in (("all_direct_joins", joins), ("shared_current_coincidences", shared)):
        for saved, independently in zip(actual[kind], walks):
            subset(saved, independently, kind)
    rep = min(range(len(joins)), key=lambda i: (-joins[i]["first_step_numerator"], joins[i]["total_edges"],
                    joins[i]["join_B_state_index"], joins[i]["first_step_move_index"])) if joins else None
    insist(actual["representative_direct_join_index_zero_based"] == rep, "Fixed representative")
    insist(actual["direct_join_count_by_recorded_move"] == len(joins), "Join multiplicity")
    expected_statement = "Recorded direct witness exists" if joins else "No direct witness in these recorded routes; this does not exclude other routes"
    insist(actual["witness_presence_statement"] == expected_statement, "Witness limit statement")
    metric_names = ("target_visited", "first_target_call", "target_ever_top5", "first_target_top5_call",
                    "final_archive_target_rank", "target_final_top5", "final_numeric_is_target",
                    "first_current_target_call", "exact_calls", "accepted_changes", "full_sweeps", "partial_sweeps",
                    "convergence_observed", "stop_reason", "time_limit_reached", "seconds", "score_seconds", "process_seconds")
    metrics = {}
    for p in ("A", "B"):
        selected = [e for e in external["profiles"] if e["category"] == "main" and e["case_id"] == selection["case_id"]
                    and e["perturbation"] == selection["perturbation"] and e["policy"] == p]
        insist(len(selected) == 1, "External profile unique")
        metrics[p] = {n: selected[0][n] for n in metric_names}
        insist(metrics[p]["final_numeric_is_target"] == (p == "B"), "Saved outcomes")
        insist(metrics[p]["exact_calls"] == summaries[p]["calls"], "External cost")
    insist(actual["saved_phase16_external_metrics"] == metrics, "Saved external labels only")
    representative = joins[rep] if rep is not None else None
    table = {"case_id": selection["case_id"], "perturbation": selection["perturbation"],
             "A_calls": a["calls"], "B_calls": b["calls"], "A_acceptances": a["accepted_changes"], "B_acceptances": b["accepted_changes"],
             "A_first_target_evaluated_call": metrics["A"]["first_target_call"], "B_first_target_evaluated_call": metrics["B"]["first_target_call"],
             "A_first_target_adopted_call": metrics["A"]["first_current_target_call"], "B_first_target_adopted_call": metrics["B"]["first_current_target_call"],
             "A_stop_reason": a["stop_reason"], "B_stop_reason": b["stop_reason"],
             "A_convergence_observed": a["convergence_observed"], "B_convergence_observed": b["convergence_observed"],
             "A_stable_proposals": len(neighbors), "A_stable_unique_neighbors": len(unique),
             "A_neighbors_greater": counts(nums)["greater"], "A_neighbors_equal": counts(nums)["equal"], "A_neighbors_lower": counts(nums)["lower"],
             "best_neighbor_gap_numerator": best_num - final_num, "score_denominator": den,
             "direct_join_count": len(joins), "representative_B_state_index": representative["join_B_state_index"] if representative else None,
             "representative_source_move_index": representative["first_step_move_index"] if representative else None,
             "representative_edges": representative["total_edges"] if representative else None,
             "representative_loss_numerator": representative["loss_below_A_final"]["numerator"] if representative else None}
    return {"case_id": selection["case_id"], "perturbation": selection["perturbation"],
            "rows_replayed": sum(map(len, rows.values())), "stable_counts": counts(nums),
            "stable_unique_neighbors": len(unique), "join_count": len(joins), "representative_index": rep}, table


def run():
    insist(sha(ROOT / "work/phase17_records/plan.json") == PLAN_HASH, "Plan hash")
    plan = load("work/phase17_records/plan.json")
    approval = load("work/phase17_records/audit_approval.json")
    insist(approval["root_approved"] and approval["independent_approved"], "Double approval")
    insist(approval["plan_sha256"] == PLAN_HASH and approval["source_sha256"] == ANALYST_HASH, "Bound approval")
    insist(sha(ROOT / "work/phase17_records/analyze_saved_paths.py") == ANALYST_HASH, "Analyst source hash")
    for relative, metadata in plan["inputs"].items():
        p = ROOT / relative
        insist(p.stat().st_size == metadata["bytes"] and sha(p) == metadata["sha256"], "Input hash " + relative)
    receipt = load("work/phase17_records/run_receipt.json")
    insist(receipt["status"] == "completed" and receipt["plan_sha256"] == PLAN_HASH
           and receipt["source_sha256"] == ANALYST_HASH, "Completed analysis receipt")
    for name, hashed in receipt["outputs"].items():
        insist(sha(ROOT / "work/phase17_records" / name) == hashed, "Analysis output hash")
    for name in ("new_IDP_calls", "new_truth_score_evaluations", "new_solver_trajectories", "new_searches"):
        insist(receipt[name] == 0, "Recorded zero costs")
    geometry = load("work/phase16_crypto/moves.json")
    moves = geometry["moves"]
    insist(geometry["width"] == 25 and geometry["identity_index"] == 0 and len(moves) == 16649, "Geometry")
    for i, m in enumerate(moves, 1):
        insist(m["index"] == i and len(m["p"]) == 25 and set(m["p"]) == set(range(25)), "Move permutation")
    external = load("work/phase16_crypto/evaluation.json")
    analysis = load("work/phase17_records/analysis.json")
    subset(analysis, {"phase": 17, "status": "completed_descriptive_replay", "scope": plan["scope"],
           "posthoc_outcome_selection": True, "plan_sha256": PLAN_HASH, "inputs": plan["inputs"],
           "movement_count_by_source_index": len(moves), "distinct_recorded_geometry_permutations": len({tuple(m["p"]) for m in moves}),
           "representative_rule": plan["witness_presentation"], "new_IDP_calls": 0,
           "new_truth_score_evaluations": 0, "new_solver_trajectories": 0, "new_searches": 0,
           "limits": plan["limits"], "runtime_metadata_in_separate_receipt": True}, "Analysis metadata")
    insist(len(analysis["pairs"]) == len(plan["pairs"]) == 2, "Pair count")
    results, tables = [], []
    for selection, saved in zip(plan["pairs"], analysis["pairs"]):
        result, table = check_pair(selection, saved, moves, external)
        results.append(result); tables.append(table)
    with (ROOT / "work/phase17_records/comparison.csv").open(newline="") as handle:
        reader = csv.DictReader(handle)
        insist(reader.fieldnames == list(tables[0]), "Comparison schema/order")
        saved_table = list(reader)
    expected_table = [{k: "" if v is None else str(v) for k, v in row.items()} for row in tables]
    insist(saved_table == expected_table, "Complete comparison table")
    total = sum(r["rows_replayed"] for r in results)
    insist(analysis["CSV_rows_checked"] == receipt["CSV_rows_checked"] == total, "All selected rows")
    return {"phase": 17, "status": "passed", "plan_sha256": PLAN_HASH, "analyst_source_sha256": ANALYST_HASH,
            "analysis_sha256": sha(ROOT / "work/phase17_records/analysis.json"),
            "comparison_sha256": sha(ROOT / "work/phase17_records/comparison.csv"),
            "analysis_receipt_sha256": sha(ROOT / "work/phase17_records/run_receipt.json"),
            "rows_replayed": total, "pairs": results, "new_IDP_calls": 0, "new_truth_score_evaluations": 0,
            "truth_read": False, "analyst_imported": False,
            "method": "Independent grouping and decision replay; independent joins, forward suffixes, complete witness minima, representative and CSV table."}


def main():
    destination = ROOT / "work/phase17_review"
    final = destination / "post_ejecucion_independiente.json"
    insist(not final.exists(), "Never overwrite an independent result")
    attempts = destination / "attempts"
    attempts.mkdir(exist_ok=True)
    n = 1
    while (attempts / ("attempt%02d" % n)).exists():
        n += 1
    insist(n <= 3, "At most one audit plus two preserved repairs")
    attempt = attempts / ("attempt%02d" % n)
    attempt.mkdir()
    source = Path(__file__).read_bytes()
    (attempt / "source.py").write_bytes(source)
    record = {"phase": 17, "attempt": n, "status": "started", "plan_sha256": PLAN_HASH,
              "source_sha256": hashlib.sha256(source).hexdigest(), "new_IDP_calls": 0,
              "new_truth_score_evaluations": 0, "truth_read": False, "maximum_seconds": 60,
              "started_unix": time.time()}
    (attempt / "started.json").write_text(json.dumps(record, indent=2) + "\n")
    began = time.monotonic()

    def timeout(signum, frame):
        raise TimeoutError("Independent record audit reached 60 seconds")

    signal.signal(signal.SIGALRM, timeout)
    signal.setitimer(signal.ITIMER_REAL, 60)
    try:
        result = run()
        encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
        with final.open("x") as handle:
            handle.write(encoded)
        record.update(status="passed", result_sha256=hashlib.sha256(encoded.encode()).hexdigest(),
                      rows_replayed=result["rows_replayed"])
    except Exception as failure:
        record.update(status="failed_preserved_no_automatic_retry", error_type=type(failure).__name__, error=str(failure))
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        record.update(seconds=time.monotonic() - began, ended_unix=time.time())
        (attempt / "receipt.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()

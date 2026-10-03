#!/usr/bin/env python3
"""Phase 17: descriptive replay of four already scored paths, standard library only.

Importing this module performs no I/O. compute(root) reads the fixed plan and its
ten inputs and returns {'analysis': dict, 'comparison_csv': str}, without writes.
No scorer, solver, truth file, model, ciphertext, RNG or network is used.
The CLI requires reviews bound to the plan/source hashes; its runtime receipt is
separate from deterministic results. The full local baseline is a root guard,
deliberately outside compute(), so the public replay needs only published inputs.
"""

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import signal
import sys
import time
from typing import NamedTuple


PLAN_PATH = "work/phase17_records/plan.json"
PLAN_SHA256 = "c3c81e29da5e0d54dbd42706e4feeb4414324d091d2d9cd3a759fe114f42036f"
MOVES_PATH = "work/phase16_crypto/moves.json"
EVALUATION_PATH = "work/phase16_crypto/evaluation.json"
PAIR_IDS = (("de_fold_20x25_20262401", "h8"),
            ("de_fold_20x25_20262402", "h4"))
CSV_FIELDS = ("call", "sweep", "move_index", "move_kind", "base_numerator",
              "numerator", "base_numeric", "candidate_numeric", "improves_base",
              "accepted_immediate", "archive_changed")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def packed_key(text, width):
    key = tuple(int(x) for x in text.split(":"))
    require(len(key) == width and sorted(key) == list(range(width)),
            "Recorded key is not a permutation")
    return key


def json_key(values, width):
    require(isinstance(values, list) and all(type(x) is int for x in values),
            "JSON key must contain integers")
    key = tuple(values)
    require(len(key) == width and sorted(key) == list(range(width)),
            "JSON key is not a permutation")
    return key


def exact_improvement(candidate, base, denominator):
    # Compare recorded integers only. This is not an objective evaluation.
    return (candidate - base) * 10**12 > denominator


def rational(numerator, denominator):
    require(type(numerator) is int and type(denominator) is int and denominator > 0,
            "Invalid recorded-score ratio")
    return {"numerator": numerator, "denominator": denominator,
            "descriptive_float": numerator / denominator}


class Row(NamedTuple):
    call: int
    sweep: int
    move_index: int
    move_kind: int
    base_numerator: int
    numerator: int
    base: tuple
    candidate: tuple
    improves_base: bool
    accepted_immediate: bool
    archive_changed: bool


def row_evidence(row, source, denominator):
    return {"csv_path": source, "call": row.call, "sweep": row.sweep,
            "move_index": row.move_index, "move_kind": row.move_kind,
            "base_numeric": list(row.base), "candidate_numeric": list(row.candidate),
            "base_numerator": row.base_numerator, "numerator": row.numerator,
            "margin_above_base": rational(row.numerator - row.base_numerator, denominator),
            "improves_base": row.improves_base,
            "accepted_immediate": row.accepted_immediate}


def parse_rows(data, width):
    reader = csv.DictReader(io.StringIO(data.decode("utf-8"), newline=""))
    require(tuple(reader.fieldnames or ()) == CSV_FIELDS, "CSV schema differs")
    rows = []
    for expected_call, raw in enumerate(reader, 1):
        require(None not in raw and all(value is not None for value in raw.values()),
                "Incomplete or overlong CSV row")
        numbers = [int(raw[name]) for name in CSV_FIELDS[:6]]
        require(numbers[0] == expected_call, "CSV calls are not consecutive")
        flags = [int(raw[name]) for name in CSV_FIELDS[8:]]
        require(all(flag in (0, 1) for flag in flags), "CSV flag is not binary")
        rows.append(Row(*numbers, packed_key(raw["base_numeric"], width),
                        packed_key(raw["candidate_numeric"], width),
                        *(bool(flag) for flag in flags)))
    require(bool(rows), "Selected CSV has no scored initial state")
    return rows


def registered_score(scores, key, numerator):
    previous = scores.setdefault(key, numerator)
    require(previous == numerator, "Same key has inconsistent saved integer scores")


def event(call, selected_call, sweep, move_index, old_key, old_num, new_key, new_num):
    return {"call": call, "selected_call": selected_call, "sweep": sweep,
            "move_index": move_index, "from_numeric": list(old_key),
            "to_numeric": list(new_key), "from_numerator": old_num,
            "to_numerator": new_num}


def validate_profile(rows, summary, policy, moves, pair_scores):
    """Replay recorded moves/decisions; never score any key or create new proposals."""
    width = len(rows[0].candidate)
    denominator = summary["denominator"]
    require(type(denominator) is int and denominator > 0, "Invalid denominator")
    require(summary["policy"] == policy and summary["w2"] == width,
            "Summary policy/width mismatch")
    require(summary["source_moves"] == len(moves), "Movement count mismatch")
    require(summary["initial_scored"] is True, "Missing initial score")
    require(summary["calls"] == summary["backend_exact_calls"] == len(rows),
            "Recorded call count mismatch")
    require(summary["backend_legacy_calls"] == 0, "Unexpected legacy calls")
    require(summary["partial_sweeps"] == 0, "Selected paths must have complete sweeps")
    current = json_key(summary["initial_numeric"], width)
    value = rows[0].numerator
    first = rows[0]
    require((first.call, first.sweep, first.move_index, first.move_kind) == (1, 0, 0, -1),
            "Initial row metadata mismatch")
    require(first.base == first.candidate == current and first.base_numerator == value,
            "Initial row key/score mismatch")
    require(not first.improves_base and not first.accepted_immediate,
            "Initial row cannot be an improvement/acceptance")
    archive = []
    visited = set()

    def offer(row):
        registered_score(pair_scores, row.candidate, row.numerator)
        visited.add(row.candidate)
        before = list(archive)
        if not any(key == row.candidate for _, key in archive):
            archive.append((row.numerator, row.candidate))
            archive.sort(key=lambda item: (-item[0], item[1]))
            del archive[5:]
        require(row.archive_changed == (archive != before), "Archive-change flag mismatch")

    offer(first)
    previous_end = 1
    generated_accepts = []
    observed_convergence = False
    for expected_sweep, saved in enumerate(summary["sweep_events"], 1):
        require(saved["sweep"] == expected_sweep and saved["start_call"] == previous_end,
                "Sweep order/start mismatch")
        end = saved["end_call"]
        require(type(end) is int and previous_end < end <= len(rows), "Invalid sweep endpoint")
        sweep_rows = rows[previous_end:end]
        require(saved["complete"] is True and len(sweep_rows) == len(moves)
                and saved["proposals"] == len(moves), "Incomplete selected sweep")
        start, start_num = current, value
        require(json_key(saved["start_numeric"], width) == start
                and saved["start_numerator"] == start_num, "Sweep starting state mismatch")
        best, best_num, best_call, best_move = start, start_num, 0, 0
        accepted_this_sweep = False
        for index, row in enumerate(sweep_rows, 1):
            move = moves[index - 1]
            require(row.sweep == expected_sweep and row.move_index == index
                    and row.move_kind == move["kind"], "Recorded movement order mismatch")
            base, base_num = (current, value) if policy == "A" else (start, start_num)
            require(row.base == base and row.base_numerator == base_num, "Recorded base mismatch")
            require(row.candidate == tuple(base[i] for i in move["p"]),
                    "Recorded candidate is not moved(base,p)")
            improvement = exact_improvement(row.numerator, base_num, denominator)
            require(row.improves_base == improvement, "Recorded EPS comparison differs")
            require(row.accepted_immediate == (policy == "A" and improvement),
                    "Immediate-acceptance flag mismatch")
            offer(row)
            if policy == "A" and improvement:
                generated_accepts.append(event(row.call, row.call, expected_sweep, index,
                                               current, value, row.candidate, row.numerator))
                current, value = row.candidate, row.numerator
                accepted_this_sweep = True
            if policy == "B" and row.numerator > best_num:
                # Strict greater preserves the first source index when scores tie.
                best, best_num, best_call, best_move = row.candidate, row.numerator, row.call, index
        if policy == "B" and exact_improvement(best_num, start_num, denominator):
            generated_accepts.append(event(end, best_call, expected_sweep, best_move,
                                           current, value, best, best_num))
            current, value = best, best_num
            accepted_this_sweep = True
        convergence = not accepted_this_sweep
        observed_convergence |= convergence
        expected_close = {"sweep": expected_sweep, "start_call": previous_end,
                          "end_call": end, "proposals": len(moves), "complete": True,
                          "start_numeric": list(start), "final_numeric": list(current),
                          "start_numerator": start_num, "final_numerator": value,
                          "improvement_accepted": accepted_this_sweep,
                          "selected_call": best_call, "selected_move_index": best_move,
                          "selected_numerator": best_num,
                          "convergence_observed": convergence, "partial_best_admitted": False}
        require(saved == expected_close, "Saved sweep closure differs from recorded decisions")
        previous_end = end
    require(previous_end == len(rows), "CSV rows lie outside saved sweeps")
    require(summary["accept_events"] == generated_accepts, "Saved accept events differ")
    require(summary["accepted_changes"] == len(generated_accepts), "Acceptance count mismatch")
    require(summary["full_sweeps"] == len(summary["sweep_events"]), "Sweep count mismatch")
    require(summary["convergence_observed"] == observed_convergence, "Convergence flag mismatch")
    require(json_key(summary["final_numeric"], width) == current
            and summary["final_numerator"] == value, "Final current state mismatch")
    expected_archive = [{"rank": rank, "numerator": num, "numeric": list(key)}
                        for rank, (num, key) in enumerate(archive, 1)]
    require(summary["archive"] == expected_archive and summary["visited_unique"] == len(visited),
            "Saved archive/unique-visit count mismatch")


def recorded_b_states(rows, summary):
    states = [{"state_index": 0, "numeric": list(rows[0].candidate),
               "numerator": rows[0].numerator, "evaluated_call": 1,
               "adoption_call": 1, "origin": "scored_initial"}]
    for index, accepted in enumerate(summary["accept_events"], 1):
        selected = rows[accepted["selected_call"] - 1]
        require(list(selected.candidate) == accepted["to_numeric"]
                and selected.numerator == accepted["to_numerator"], "B event has no selected row")
        states.append({"state_index": index, "numeric": accepted["to_numeric"],
                       "numerator": accepted["to_numerator"],
                       "evaluated_call": accepted["selected_call"],
                       "adoption_call": accepted["call"], "origin": "accepted_current"})
    require(len({tuple(state["numeric"]) for state in states}) == len(states),
            "Accepted B current states unexpectedly repeat")
    return states


def first_decision(accepted, summary_path, csv_path, initial_numerator, denominator):
    return {"summary_path": summary_path, "csv_path": csv_path,
            "move_index": accepted["move_index"], "sweep": accepted["sweep"],
            "evaluated_call": accepted["selected_call"], "adoption_call": accepted["call"],
            "from_numeric": accepted["from_numeric"], "to_numeric": accepted["to_numeric"],
            "numerator": accepted["to_numerator"],
            "margin_above_initial": rational(accepted["to_numerator"] - initial_numerator,
                                               denominator)}


def stable_neighborhood(rows, summary, source, moves):
    final = tuple(summary["final_numeric"])
    final_num = summary["final_numerator"]
    events = [entry for entry in summary["sweep_events"]
              if entry["complete"] is True and entry["improvement_accepted"] is False
              and entry["convergence_observed"] is True
              and tuple(entry["start_numeric"]) == tuple(entry["final_numeric"]) == final
              and entry["start_numerator"] == entry["final_numerator"] == final_num]
    require(len(events) == 1 and events[0] == summary["sweep_events"][-1],
            "There is no unique last stable A sweep")
    closed = events[0]
    neighbors = rows[closed["start_call"]:closed["end_call"]]
    require(len(neighbors) == len(moves)
            and [row.move_index for row in neighbors] == list(range(1, len(moves) + 1)),
            "Stable A sweep does not cover source indices once")
    require(all(row.base == final and row.base_numerator == final_num
                and not row.accepted_immediate for row in neighbors),
            "Stable A neighborhood does not have the final fixed base")
    distinct = {}
    for row in neighbors:
        registered_score(distinct, row.candidate, row.numerator)
    proposal_counts = {"greater": 0, "equal": 0, "lower": 0}
    unique_counts = dict(proposal_counts)
    for row in neighbors:
        label = "greater" if row.numerator > final_num else "equal" if row.numerator == final_num else "lower"
        proposal_counts[label] += 1
    for num in distinct.values():
        label = "greater" if num > final_num else "equal" if num == final_num else "lower"
        unique_counts[label] += 1
    require(proposal_counts["greater"] == 0, "Stable final A has a strictly higher saved neighbor")
    best = max(row.numerator for row in neighbors)
    result = {"csv_path": source, "sweep_event": closed,
              "final_numeric": list(final), "final_numerator": final_num,
              "proposal_count": len(neighbors), "unique_neighbor_count": len(distinct),
              "counts_by_proposal": proposal_counts, "counts_by_unique_neighbor": unique_counts,
              "best_neighbor_numerator": best,
              "best_neighbor_margin_above_final": rational(best - final_num, summary["denominator"]),
              "best_neighbor_evidence": [row_evidence(row, source, summary["denominator"])
                                         for row in neighbors if row.numerator == best],
              "all_first_source_steps_strictly_lower": proposal_counts["lower"] == len(neighbors),
              "has_equal_score_first_steps": proposal_counts["equal"] > 0,
              "interpretation_limit": "Only this complete recorded one-step neighborhood; no deeper plateau or barrier coverage."}
    return result, neighbors


def witnessed_route(a_final, a_num, join_state, first_row, b_states, b_summary,
                    a_source, b_source, denominator):
    index = join_state["state_index"]
    keys = [list(a_final)]
    numerators = [a_num]
    edges = []
    if first_row is not None:
        require(tuple(join_state["numeric"]) == first_row.candidate
                and join_state["numerator"] == first_row.numerator, "Join score/key mismatch")
        keys.append(list(first_row.candidate))
        numerators.append(first_row.numerator)
        edges.append({"origin": "final_A_recorded_proposal",
                      "evidence": row_evidence(first_row, a_source, denominator)})
    else:
        require(tuple(join_state["numeric"]) == a_final and join_state["numerator"] == a_num,
                "Shared-current score/key mismatch")
    for accepted in b_summary["accept_events"][index:]:
        require(accepted["from_numeric"] == keys[-1]
                and accepted["from_numerator"] == numerators[-1], "B suffix is not forward-contiguous")
        edges.append({"origin": "recorded_B_acceptance", "csv_path": b_source,
                      "accept_event": accepted})
        keys.append(accepted["to_numeric"])
        numerators.append(accepted["to_numerator"])
    require(keys[-1] == b_summary["final_numeric"]
            and numerators[-1] == b_summary["final_numerator"], "Witness does not reach recorded B final")
    minimum = min(numerators)
    return {"join_B_state_index": index, "join_B_state": join_state,
            "first_step_move_index": None if first_row is None else first_row.move_index,
            "first_step_numerator": a_num if first_row is None else first_row.numerator,
            "first_step_kind": "shared_current_no_identity_edge" if first_row is None else
                               "descent" if first_row.numerator < a_num else
                               "equal" if first_row.numerator == a_num else "increase",
            "first_step_margin_above_A_final": rational((a_num if first_row is None else first_row.numerator) - a_num,
                                                          denominator),
            "B_suffix_edges": len(b_summary["accept_events"]) - index,
            "total_edges": len(edges), "witness_keys": keys, "witness_numerators": numerators,
            "edges": edges, "minimum_witness_numerator": minimum,
            "loss_below_A_final": rational(max(0, a_num - minimum), denominator),
            "final_is_successful_B_by_saved_external_evaluation": True,
            "limit": "Finite recorded witness only, not a shortest or globally least-loss route."}


def external_metrics(evaluation, case_id, perturbation, policy, summary):
    selected = [entry for entry in evaluation["profiles"]
                if entry["category"] == "main" and entry["case_id"] == case_id
                and entry["perturbation"] == perturbation and entry["policy"] == policy]
    require(len(selected) == 1, "External evaluation profile is not unique")
    saved = selected[0]
    for name in ("exact_calls", "full_sweeps", "partial_sweeps", "accepted_changes",
                 "convergence_observed", "stop_reason", "time_limit_reached"):
        expected = summary["calls"] if name == "exact_calls" else summary[name]
        require(saved[name] == expected, "External/summarized metadata differ: " + name)
    require(saved["final_numeric_is_target"] is (policy == "B"),
            "Selected external outcomes differ from the posthoc plan")
    fields = ("target_visited", "first_target_call", "target_ever_top5", "first_target_top5_call",
              "final_archive_target_rank", "target_final_top5", "final_numeric_is_target",
              "first_current_target_call", "exact_calls", "accepted_changes", "full_sweeps",
              "partial_sweeps", "convergence_observed", "stop_reason", "time_limit_reached",
              "seconds", "score_seconds", "process_seconds")
    return {name: saved[name] for name in fields}


def compare_pair(pair, inputs, moves, evaluation):
    profiles = pair["profiles"]
    summaries = {policy: json.loads(inputs[paths["summary_path"]])
                 for policy, paths in profiles.items()}
    width = summaries["A"]["w2"]
    denominator = summaries["A"]["denominator"]
    require(summaries["B"]["denominator"] == denominator and summaries["B"]["w2"] == width,
            "Paired denominators/widths differ")
    rows = {policy: parse_rows(inputs[paths["csv_path"]], width)
            for policy, paths in profiles.items()}
    pair_scores = {}
    for policy in ("A", "B"):
        validate_profile(rows[policy], summaries[policy], policy, moves, pair_scores)
    require(rows["A"][0].candidate == rows["B"][0].candidate
            and rows["A"][0].numerator == rows["B"][0].numerator, "Paired initials differ")
    first_a, first_b = summaries["A"]["accept_events"][0], summaries["B"]["accept_events"][0]
    initial_num = rows["A"][0].numerator
    last_prefix = first_a["call"]
    require(last_prefix <= len(rows["B"]), "B lacks comparable initial prefix")
    for a, b in zip(rows["A"][:last_prefix], rows["B"][:last_prefix]):
        require((a.call, a.sweep, a.move_index, a.move_kind, a.base_numerator,
                 a.numerator, a.base, a.candidate, a.improves_base) ==
                (b.call, b.sweep, b.move_index, b.move_kind, b.base_numerator,
                 b.numerator, b.base, b.candidate, b.improves_base),
                "Scored initial prefix differs before/at first A acceptance")
    require(rows["A"][last_prefix - 1].accepted_immediate
            and not rows["B"][last_prefix - 1].accepted_immediate,
            "First immediate acceptance is not the recorded policy divergence")
    decisions = {policy: first_decision(summaries[policy]["accept_events"][0],
                                       profiles[policy]["summary_path"], profiles[policy]["csv_path"],
                                       initial_num, denominator) for policy in ("A", "B")}
    b_states = recorded_b_states(rows["B"], summaries["B"])
    current_a = {tuple(summaries["A"]["initial_numeric"]): [{"call": 1, "origin": "initial"}]}
    for accepted in summaries["A"]["accept_events"]:
        current_a.setdefault(tuple(accepted["to_numeric"]), []).append(
            {"call": accepted["call"], "origin": "accepted_current"})
    state_lookup = {tuple(state["numeric"]): state["state_index"] for state in b_states}
    visits = {index: [] for index in range(len(b_states))}
    for row in rows["A"]:
        index = state_lookup.get(row.candidate)
        if index is not None:
            visits[index].append(row_evidence(row, profiles["A"]["csv_path"], denominator))
    b_state_visits = []
    for state in b_states:
        recorded = visits[state["state_index"]]
        b_state_visits.append({"B_current_state": state, "A_candidate_visit_count": len(recorded),
                               "A_first_candidate_visit_call": recorded[0]["call"] if recorded else None,
                               "A_candidate_visits": recorded,
                               "A_current_state_occurrences": current_a.get(tuple(state["numeric"]), []),
                               "A_ever_current": tuple(state["numeric"]) in current_a})
    stable, neighbors = stable_neighborhood(rows["A"], summaries["A"], profiles["A"]["csv_path"], moves)
    joins, shared = [], []
    a_final = tuple(summaries["A"]["final_numeric"])
    a_num = summaries["A"]["final_numerator"]
    for state in b_states:
        if tuple(state["numeric"]) == a_final:
            shared.append(witnessed_route(a_final, a_num, state, None, b_states, summaries["B"],
                                          profiles["A"]["csv_path"], profiles["B"]["csv_path"], denominator))
        for row in neighbors:
            if row.candidate == tuple(state["numeric"]):
                joins.append(witnessed_route(a_final, a_num, state, row, b_states, summaries["B"],
                                             profiles["A"]["csv_path"], profiles["B"]["csv_path"], denominator))
    joins.sort(key=lambda route: (route["join_B_state_index"], route["first_step_move_index"]))
    representative_index = None
    if joins:
        representative_index = min(range(len(joins)), key=lambda index: (
            -joins[index]["first_step_numerator"], joins[index]["total_edges"],
            joins[index]["join_B_state_index"], joins[index]["first_step_move_index"]))
    metrics = {policy: external_metrics(evaluation, pair["case_id"], pair["perturbation"], policy,
                                       summaries[policy]) for policy in ("A", "B")}
    return {"case_id": pair["case_id"], "perturbation": pair["perturbation"],
            "denominator": denominator, "initial_numerator": initial_num,
            "first_decisions": decisions,
            "initial_comparable_prefix": {"rows_including_initial": last_prefix,
                                           "last_common_scored_candidate_call": last_prefix,
                                           "first_policy_adoption_divergence_call": last_prefix,
                                           "bases_candidates_saved_scores_equal": True,
                                           "subsequent_rows_not_aligned_by_move_index": True},
            "B_current_states_and_A_visits": b_state_visits,
            "stable_final_A_neighborhood": stable,
            "direct_join_count_by_recorded_move": len(joins), "all_direct_joins": joins,
            "shared_current_coincidences": shared,
            "representative_direct_join_index_zero_based": representative_index,
            "witness_presence_statement": "Recorded direct witness exists" if joins else
                "No direct witness in these recorded routes; this does not exclude other routes",
            "saved_phase16_external_metrics": metrics,
            "distinct_saved_keys_checked_across_pair": len(pair_scores),
            "CSV_rows_checked": sum(len(profile_rows) for profile_rows in rows.values())}


def comparison_table(pairs):
    fields = ["case_id", "perturbation", "A_calls", "B_calls", "A_acceptances", "B_acceptances",
              "A_first_target_evaluated_call", "B_first_target_evaluated_call",
              "A_first_target_adopted_call", "B_first_target_adopted_call",
              "A_stop_reason", "B_stop_reason", "A_convergence_observed", "B_convergence_observed",
              "A_stable_proposals", "A_stable_unique_neighbors", "A_neighbors_greater",
              "A_neighbors_equal", "A_neighbors_lower", "best_neighbor_gap_numerator",
              "score_denominator", "direct_join_count", "representative_B_state_index",
              "representative_source_move_index", "representative_edges", "representative_loss_numerator"]
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for pair in pairs:
        a, b = (pair["saved_phase16_external_metrics"][policy] for policy in ("A", "B"))
        stable = pair["stable_final_A_neighborhood"]
        rep_index = pair["representative_direct_join_index_zero_based"]
        rep = None if rep_index is None else pair["all_direct_joins"][rep_index]
        writer.writerow({"case_id": pair["case_id"], "perturbation": pair["perturbation"],
                         "A_calls": a["exact_calls"], "B_calls": b["exact_calls"],
                         "A_acceptances": a["accepted_changes"], "B_acceptances": b["accepted_changes"],
                         "A_first_target_evaluated_call": a["first_target_call"],
                         "B_first_target_evaluated_call": b["first_target_call"],
                         "A_first_target_adopted_call": a["first_current_target_call"],
                         "B_first_target_adopted_call": b["first_current_target_call"],
                         "A_stop_reason": a["stop_reason"], "B_stop_reason": b["stop_reason"],
                         "A_convergence_observed": a["convergence_observed"],
                         "B_convergence_observed": b["convergence_observed"],
                         "A_stable_proposals": stable["proposal_count"],
                         "A_stable_unique_neighbors": stable["unique_neighbor_count"],
                         "A_neighbors_greater": stable["counts_by_proposal"]["greater"],
                         "A_neighbors_equal": stable["counts_by_proposal"]["equal"],
                         "A_neighbors_lower": stable["counts_by_proposal"]["lower"],
                         "best_neighbor_gap_numerator": stable["best_neighbor_margin_above_final"]["numerator"],
                         "score_denominator": pair["denominator"], "direct_join_count": len(pair["all_direct_joins"]),
                         "representative_B_state_index": None if rep is None else rep["join_B_state_index"],
                         "representative_source_move_index": None if rep is None else rep["first_step_move_index"],
                         "representative_edges": None if rep is None else rep["total_edges"],
                         "representative_loss_numerator": None if rep is None else rep["loss_below_A_final"]["numerator"]})
    return buffer.getvalue()


def compute(root):
    """Return deterministic aggregation of fixed saved inputs; never write files."""
    root = Path(root)
    plan_data = (root / PLAN_PATH).read_bytes()
    require(digest(plan_data) == PLAN_SHA256, "Fixed phase17 plan hash differs")
    plan = json.loads(plan_data)
    require(plan["phase"] == 17 and [(p["case_id"], p["perturbation"]) for p in plan["pairs"]]
            == list(PAIR_IDS), "Selection differs from the fixed posthoc plan")
    allowed = {MOVES_PATH, EVALUATION_PATH}
    for pair in plan["pairs"]:
        require(set(pair["profiles"]) == {"A", "B"}, "Expected paired A/B profiles")
        for policy, profile in pair["profiles"].items():
            stem = f"work/phase16_crypto/trajectories/{pair['case_id']}_{pair['perturbation']}_{policy}"
            require(profile == {"csv_path": stem + ".csv", "summary_path": stem + ".json"},
                    "Input path differs from selected profile")
            allowed.update(profile.values())
    require(set(plan["inputs"]) == allowed and len(allowed) == 10, "Input allowlist differs")
    inputs = {}
    for relative in sorted(allowed):
        data = (root / relative).read_bytes()
        expected = plan["inputs"][relative]
        require(len(data) == expected["bytes"] and digest(data) == expected["sha256"],
                "Saved input hash/size differs: " + relative)
        inputs[relative] = data
    geometry = json.loads(inputs[MOVES_PATH])
    width = geometry["width"]
    require(width == 25 and geometry["identity_index"] == 0, "Geometry width/identity differs")
    moves = geometry["moves"]
    require(len(moves) == 16649, "Frozen source geometry has unexpected size")
    for index, move in enumerate(moves, 1):
        require(move["index"] == index and type(move["kind"]) is int, "Geometry index/kind differs")
        move["p"] = json_key(move["p"], width)
    evaluation = json.loads(inputs[EVALUATION_PATH])
    require(evaluation["status"] == "completed" or evaluation["status"] == "passed"
            or evaluation["status"] == "evaluated", "Saved evaluation status is not complete")
    pairs = [compare_pair(pair, inputs, moves, evaluation) for pair in plan["pairs"]]
    analysis = {"phase": 17, "status": "completed_descriptive_replay",
                "scope": plan["scope"], "posthoc_outcome_selection": True,
                "plan_sha256": PLAN_SHA256, "inputs": plan["inputs"],
                "movement_count_by_source_index": len(moves),
                "distinct_recorded_geometry_permutations": len({move["p"] for move in moves}),
                "pairs": pairs, "representative_rule": plan["witness_presentation"],
                "new_IDP_calls": 0, "new_truth_score_evaluations": 0,
                "new_solver_trajectories": 0, "new_searches": 0,
                "CSV_rows_checked": sum(pair["CSV_rows_checked"] for pair in pairs),
                "limits": plan["limits"],
                "runtime_metadata_in_separate_receipt": True}
    return {"analysis": analysis, "comparison_csv": comparison_table(pairs)}


def write_new(path, data):
    # x mode enforces the no-overwrite rule even if another process races us.
    with path.open("xb") as handle:
        handle.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    root = args.root.resolve()
    destination = root / "work/phase17_records"
    source_data = Path(__file__).read_bytes()
    source_hash = digest(source_data)
    plan_data = (root / PLAN_PATH).read_bytes()
    plan_hash = digest(plan_data)
    require(plan_hash == PLAN_SHA256, "Plan changed before CLI execution")
    approval = json.loads((destination / "audit_approval.json").read_bytes())
    require(approval.get("root_approved") is True and approval.get("independent_approved") is True
            and approval.get("plan_sha256") == PLAN_SHA256
            and approval.get("source_sha256") == source_hash, "Double approval does not bind this code/plan")
    outputs = [destination / name for name in ("analysis.json", "comparison.csv", "run_receipt.json")]
    require(not any(path.exists() for path in outputs), "Existing outputs must not be overwritten")
    attempts = destination / "attempts"
    attempts.mkdir(exist_ok=True)
    index = 1
    while (attempts / f"attempt{index:02d}").exists():
        index += 1
    require(index <= 1 + json.loads(plan_data)["costs"]["maximum_repair_attempts"],
            "The fixed plan permits one initial attempt and at most two repair attempts")
    attempt_dir = attempts / f"attempt{index:02d}"
    attempt_dir.mkdir()
    write_new(attempt_dir / "source.py", source_data)
    receipt = {"phase": 17, "attempt": index, "status": "started",
               "source_sha256": source_hash, "plan_sha256": PLAN_SHA256,
               "approval_sha256": digest((destination / "audit_approval.json").read_bytes()),
               "new_IDP_calls": 0, "new_truth_score_evaluations": 0,
               "new_solver_trajectories": 0, "new_searches": 0,
               "maximum_analysis_seconds": 60, "start_unix": time.time()}
    write_new(attempt_dir / "started.json", (json.dumps(receipt, indent=2) + "\n").encode())
    began = time.monotonic()
    timer_active = False

    def deadline(signum, frame):
        raise TimeoutError("Analysis reached the fixed 60 second limit")

    try:
        # compute() remains portable and free of a clock. CLI uses its own timer.
        require(hasattr(signal, "SIGALRM") and hasattr(signal, "setitimer"),
                "CLI needs a Unix timer; portable public helpers may call compute(root) directly")
        signal.signal(signal.SIGALRM, deadline)
        signal.setitimer(signal.ITIMER_REAL, 60)
        timer_active = True
        result = compute(root)
        analysis_data = (json.dumps(result["analysis"], indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
        table_data = result["comparison_csv"].encode()
        write_new(outputs[0], analysis_data)
        write_new(outputs[1], table_data)
        receipt.update(status="completed", seconds=time.monotonic() - began,
                       end_unix=time.time(), CSV_rows_checked=result["analysis"]["CSV_rows_checked"],
                       outputs={"analysis.json": digest(analysis_data), "comparison.csv": digest(table_data)})
    except Exception as exc:
        receipt.update(status="failed_preserved_no_automatic_retry", seconds=time.monotonic() - began,
                       end_unix=time.time(), error_type=type(exc).__name__, error=str(exc),
                       existing_output_hashes={path.name: digest(path.read_bytes())
                                               for path in outputs[:2] if path.exists()})
        raise
    finally:
        if timer_active:
            signal.setitimer(signal.ITIMER_REAL, 0)
        receipt_data = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
        write_new(attempt_dir / "receipt.json", receipt_data)
        if receipt["status"] == "completed":
            write_new(outputs[2], receipt_data)
    print(json.dumps({"status": receipt["status"], "CSV_rows_checked": receipt["CSV_rows_checked"],
                      "new_IDP_calls": 0, "outputs": receipt["outputs"]}, sort_keys=True))


if __name__ == "__main__":
    main()

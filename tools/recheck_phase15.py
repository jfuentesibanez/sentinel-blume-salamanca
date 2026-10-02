"""Read-only, standard-library replay of the complete phase 15 public export.

Reconstructs keys and synthetic ciphertexts, then checks recorded scores,
counters, flags and local ranks. It never scores a candidate, imports a legacy
verifier, executes a solver, regenerates RNG keys or writes any file.
"""
import argparse
import csv
import hashlib
import json
import math
import struct
from fractions import Fraction
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[1]
CSV_FIELDS = [
    'index', 'kind', 'legacy', 'exact_numerator', 'legacy_improves_anchor',
    'exact_improves_anchor', 'legacy_edges', 'exact_edges', 'legacy_forced',
    'exact_forced', 'matrix_max_abs_diff',
]
GEOMETRY_HASH = '11fade65c2c64b718fd4cf91b61a6df6b7ab6182b1183ca857fc2fc643f5c9ff'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def within(root, relative):
    require(not Path(relative).is_absolute(), f'Expected relative export path: {relative}')
    result = (root / relative).resolve()
    require(result.is_relative_to(root), f'Path outside export: {relative}')
    return result


def permutation(key, width, label):
    require(len(key) == width and all(type(v) is int for v in key)
            and sorted(key) == list(range(width)), f'Invalid permutation: {label}')


def inverse(key):
    out = [0] * len(key)
    for index, column in enumerate(key):
        out[column] = index
    return tuple(out)


def enc(text, key):
    return ''.join(text[column::len(key)] for column in key)


def close(recorded, computed, label):
    require(isinstance(recorded, (int, float)) and math.isfinite(recorded)
            and math.isclose(recorded, computed, rel_tol=1e-12, abs_tol=1e-15),
            f'Float metadata mismatch: {label}: {recorded!r} != {computed!r}')


def started_trace(path, alternating):
    """Each flushed marker charges a backend invocation before entry."""
    legacy = exact = count = 0
    with path.open(encoding='utf-8') as stream:
        for line in stream:
            fields = line.strip().split()
            require(len(fields) == 3 and fields[0] == '@calls', f'Unexpected trace line: {path}')
            current = tuple(map(int, fields[1:]))
            require(current in ((legacy + 1, exact), (legacy, exact + 1)),
                    f'Skipped/repeated backend marker: {path}:{count + 1}')
            if alternating:
                expected = (legacy + 1, exact) if count % 2 == 0 else (legacy, exact + 1)
                require(current == expected, f'Unexpected main backend order: {path}:{count + 1}')
            legacy, exact = current
            count += 1
    return legacy, exact, count


def edge_sequence(text, forced, width, label):
    edges = tuple(map(int, text.split(':')))
    require(len(edges) == width and all(0 <= edge < width * width for edge in edges),
            f'Invalid greedy edge list: {label}')
    require(len({edge // width for edge in edges}) == width
            and len({edge % width for edge in edges}) == width,
            f'Repeated greedy endpoint: {label}')
    diagonals = [index for index, edge in enumerate(edges) if edge // width == edge % width]
    require(forced in (0, 1) and len(diagonals) == forced
            and (not diagonals or diagonals == [width - 1]), f'Forced edge mismatch: {label}')
    return edges


def model_scale(path):
    """Decode binary32 coefficients only; this is not an IDP calculation."""
    with path.open('rb') as stream:
        data = stream.read(676 * 4)
    require(len(data) == 676 * 4, f'Truncated model: {path}')
    values = struct.unpack('<676f', data)
    require(all(math.isfinite(value) for value in values), f'Nonfinite model: {path}')
    return math.lcm(*(value.as_integer_ratio()[1] for value in values))


def main(root):
    root = root.resolve()
    phase = root / 'work/phase15_crypto'
    manifest = load(phase / 'manifest.json')
    evaluation = load(phase / 'evaluation.json')
    guard = load(phase / 'no_truth_verification.json')
    plan = load(phase / 'plan12.json')
    sealed = load(phase / 'sealed_design.json')
    manifest_hash = sha(phase / 'manifest.json')
    require(manifest['status'] == 'completed' and manifest['completed'] is True
            and manifest['protected_unchanged'] is True, 'Main profiles are not completed records')
    require(guard['status'] == 'passed' and guard['manifest_sha256'] == manifest_hash,
            'Missing/mismatched external-evaluation guard')
    require(evaluation['status'] == 'evaluated' and evaluation['manifest_sha256'] == manifest_hash,
            'Evaluation belongs to a different manifest')
    require(evaluation['new_legacy_calls'] == evaluation['new_exact_calls'] == 0,
            'Evaluation claims extra scorer calls')
    require(manifest['truth_sha256'] == evaluation['truth_sha256'] == sha(phase / 'truth.jsonl'),
            'Truth hash mismatch')
    require(manifest['plan_sha256'] == sha(phase / 'plan12.json')
            and sealed['plan_sha256'] == manifest['plan_sha256'], 'Plan hash mismatch')
    approval = manifest['audit_approval']
    require(approval['root_approved'] is True and approval['independent_approved'] is True
            and approval['plan_sha256'] == manifest['plan_sha256'], 'Double approval missing')
    require(manifest['protected_before'] == manifest['protected_after'], 'Recorded prior-file hashes changed')
    require(manifest['cases'] == sealed['cases'] and manifest['profiles'] == sealed['profiles'],
            'Sealed case/profile definitions changed')
    require(manifest['resources'] == plan['resources'] == sealed['resources'], 'Recorded resource lists changed')
    # Public exports omit original compiled binaries. Check retained resources;
    # omitted files must be accounted for in the export inventory when available.
    inventory_file = root / 'provenance/phase15_source_inventory.jsonl'
    inventory = {}
    if inventory_file.exists():
        inventory = {entry['source_path']: entry for entry in
                     (json.loads(line) for line in inventory_file.read_text().splitlines())}
    omitted_resources = []
    for relative, digest in manifest['resources'].items():
        path = within(root, 'work/phase15_crypto/' + relative)
        if path.exists():
            require(sha(path) == digest, f'Retained resource changed: {relative}')
        else:
            entry = inventory.get('work/phase15_crypto/' + relative)
            require(entry is not None and entry['disposition'] == 'referenced_only'
                    and entry['sha256'] == digest, f'Unaccounted missing resource: {relative}')
            omitted_resources.append(relative)
    for item in manifest['models_and_holdouts']:
        require(sha(within(root, item['path'])) == item['sha256'], f'Model/holdout hash mismatch: {item["path"]}')

    geometry = load(phase / 'moves.json')
    moves = geometry['moves']
    require(geometry['width'] == 25 and geometry['identity_index'] == 0 and len(moves) == 16649,
            'Unexpected source geometry')
    pmap = {0: tuple(range(25))}
    kinds = {0: -1}
    for index, move in enumerate(moves, 1):
        require(move['index'] == index and move['kind'] in (0, 1, 2), 'Movement index/type mismatch')
        permutation(move['p'], 25, f'move {index}')
        pmap[index] = tuple(move['p'])
        kinds[index] = move['kind']
    require(len(set(pmap.values())) == 16650, 'Duplicate/identity source move')
    encoded = json.dumps(sorted(pmap.values()), separators=(',', ':')).encode()
    require(hashlib.sha256(encoded).hexdigest() == GEOMETRY_HASH, 'Frozen source geometry changed')
    require(geometry['legacy_calls'] == geometry['exact_calls'] == 0, 'Geometry claims scorer calls')

    truth_rows = [json.loads(line) for line in (phase / 'truth.jsonl').read_text().splitlines()]
    truths = {row['case_id']: row for row in truth_rows}
    cases = {case['case_id']: case for case in manifest['cases']}
    profiles = manifest['profiles']
    runs = {(run['case_id'], run['anchor_label']): run for run in manifest['runs']}
    evaluated = {(row['case_id'], row['anchor_label']): row for row in evaluation['profiles']}
    require(len(truth_rows) == len(truths) == len(cases) == 4, 'Expected four distinct cases')
    require(len(profiles) == len(manifest['runs']) == len(runs) == len(evaluation['profiles']) == len(evaluated) == 12,
            'Expected twelve distinct profiles/runs/evaluations')
    require(set(cases) == set(truths) == set(evaluation['cases']), 'Case ID mismatch')
    expected_ids = {(case_id, label) for case_id in cases for label in ('true', 'native', 'omitted')}
    require(set(runs) == set(evaluated) == expected_ids
            and {(p['case_id'], p['anchor_label']) for p in profiles} == expected_ids,
            'Profile ID mismatch')
    targets = {}; keypairs = set(); offsets = set(); scales = {}; generated_ciphertexts = 0
    for identifier, truth in truths.items():
        case = cases[identifier]
        require(case['language_model'] == truth['language_model'] and case['plant_seed'] == truth['plant_seed'],
                f'Case/truth model or seed mismatch: {identifier}')
        permutation(truth['true_k1'], 20, identifier + ' K1')
        permutation(truth['true_k2'], 25, identifier + ' K2')
        targets[identifier] = inverse(truth['true_k2'])
        keypairs.add((tuple(truth['true_k1']), tuple(truth['true_k2'])))
        offsets.add(truth['sample_position'])
        folder = root / 'work/phase5_language' / truth['language_model']
        body = ''.join(c.lower() for c in (folder / 'holdout.txt').read_text() if c.isascii() and c.isalpha())
        position = truth['sample_position']
        require(type(position) is int and 0 <= position <= len(body) - 775, 'Invalid planted offset')
        plaintexts = [body[position:position + 615], body[position + 615:position + 775]]
        saved_case = evaluation['cases'][identifier]
        for field in ('language_model', 'plant_seed', 'sample_position', 'true_k1', 'true_k2'):
            require(saved_case[field] == truth[field], f'Evaluated case metadata mismatch: {identifier} {field}')
        require(saved_case['plaintext_sha256'] == [hashlib.sha256(text.encode()).hexdigest() for text in plaintexts],
                'Plaintext hash mismatch')
        require(len(case['ciphertext_files']) == len(case['ciphertext_paths']) == 2, 'Expected two ciphertexts')
        for item, recorded_path, plaintext in zip(case['ciphertext_files'], case['ciphertext_paths'], plaintexts):
            path = within(root, item['path']);require(item['path'] == recorded_path and sha(path) == item['sha256'], 'Ciphertext hash/path mismatch')
            require(path.read_text().strip().lower() == enc(enc(plaintext, truth['true_k1']), truth['true_k2']),
                    f'Synthetic ciphertext mismatch: {identifier}')
            generated_ciphertexts += 1
        scales[identifier] = model_scale(folder / 'model.bin')

    # Obtain the recorded true-state score only; do not invoke an objective.
    true_scores = {}
    for profile in profiles:
        if profile['anchor_label'] != 'true':
            continue
        with within(root, profile['csv_path']).open(newline='') as stream:
            first = next(csv.DictReader(stream), None)
        if first is not None:
            require(int(first['index']) == 0, 'True profile lacks state zero')
            true_scores[profile['case_id']] = (int(first['exact_numerator']), float(first['legacy']))

    totals = {'legacy_calls': 0, 'exact_calls': 0, 'idp_equivalent_calls': 0,
              'improvement_decision_discrepancies': 0, 'greedy_edge_discrepancies': 0,
              'legacy_seconds': 0.0, 'exact_seconds': 0.0, 'process_seconds': 0.0}
    case_keys = {identifier: set() for identifier in cases}
    all_keys = set(); all_complete = True; rows_checked = traces_checked = 0
    for profile in profiles:
        identifier, label = profile['case_id'], profile['anchor_label']
        context = identifier + '/' + label
        run, saved = runs[identifier, label], evaluated[identifier, label]
        summary_path = within(root, profile['summary_path']);csv_path = within(root, profile['csv_path'])
        require(sha(summary_path) == run['summary_sha256'] and sha(csv_path) == run['csv_sha256'], 'CSV/summary hash mismatch: ' + context)
        summary = load(summary_path);require(summary == run['summary'], 'Embedded summary changed: ' + context)
        anchor_path = within(root, profile['anchor_path'])
        require(sha(anchor_path) == profile['anchor_sha256'], 'Anchor hash mismatch: ' + context)
        anchor = tuple(map(int, anchor_path.read_text().split()));permutation(anchor, 25, context + ' anchor')
        require(list(anchor) == summary['anchor_numeric'], 'Anchor/summary mismatch: ' + context)
        expected_anchor = list(targets[identifier]);swap = None if label == 'true' else ([0, 1] if label == 'native' else [1, 24])
        require(profile['swap'] == swap, 'Anchor swap rule changed: ' + context)
        if swap:
            a, b = swap;expected_anchor[a], expected_anchor[b] = expected_anchor[b], expected_anchor[a]
        require(anchor == tuple(expected_anchor), 'Anchor is not the prescribed privileged perturbation: ' + context)
        require(summary['mode'] == 'static' and summary['anchor_updated'] is False and summary['w1'] == 20
                and summary['w2'] == 25 and summary['convention'] == 0 and summary['lengths'] == [615, 160]
                and summary['source_moves'] == 16649 and summary['requested_states'] == 16650,
                'Static configuration mismatch: ' + context)
        denominator = summary['idp_denominator'];scale = scales[identifier]
        require(summary['scale'] == scale == (1 << summary['denominator_shift']), 'Model scale mismatch: ' + context)
        nrows = summary['states_completed']
        require(0 <= nrows <= 16650 and denominator == (scale * 760 if nrows else 0), 'Normalizer mismatch: ' + context)
        require(run['returncode'] == 0 and run['timed_out'] is False and run['status'] == 'recorded', 'Failed run presented as completed: ' + context)
        calls_path = within(root, run['calls_path']);require(sha(calls_path) == run['calls_sha256'], 'Calls trace hash mismatch: ' + context)
        legacy_started, exact_started, markers = started_trace(calls_path, alternating=True)
        require(legacy_started == exact_started == nrows == summary['legacy_calls'] == summary['exact_calls']
                and legacy_started == run['legacy_calls_started'] and exact_started == run['exact_calls_started']
                and summary['idp_equivalent_calls'] == markers == 2 * nrows, 'Backend cost mismatch: ' + context)
        traces_checked += markers
        records = [];seen = set();score_error = matrix_error = 0.0;decision_diffs = edge_diffs = 0
        with csv_path.open(newline='') as stream:
            reader = csv.DictReader(stream);require(reader.fieldnames == CSV_FIELDS, 'CSV schema mismatch: ' + context)
            for index, raw in enumerate(reader):
                require(int(raw['index']) == index and int(raw['kind']) == kinds.get(index), 'Movement index/type mismatch: ' + context)
                numeric = tuple(anchor[p] for p in pmap[index]);require(numeric not in seen, 'Duplicate key inside profile: ' + context)
                seen.add(numeric);all_keys.add(numeric);case_keys[identifier].add(numeric)
                legacy = float(raw['legacy']);numerator = int(raw['exact_numerator'])
                require(math.isfinite(legacy), 'Nonfinite saved legacy score: ' + context)
                legacy_edges = edge_sequence(raw['legacy_edges'], int(raw['legacy_forced']), 20, context)
                exact_edges = edge_sequence(raw['exact_edges'], int(raw['exact_forced']), 20, context)
                require(raw['legacy_improves_anchor'] in ('0', '1') and raw['exact_improves_anchor'] in ('0', '1'), 'Invalid improvement flag: ' + context)
                if index == 0:
                    base_legacy, base_num = legacy, numerator
                li = legacy > base_legacy + 1e-12;ei = (numerator - base_num) * 10**12 > denominator
                require(li == bool(int(raw['legacy_improves_anchor'])) and ei == bool(int(raw['exact_improves_anchor'])), 'EPS improvement mismatch: ' + context)
                me = float(raw['matrix_max_abs_diff']);require(math.isfinite(me) and me >= 0, 'Invalid matrix-error metadata')
                matrix_error = max(matrix_error, me);score_error = max(score_error, abs(legacy - float(numerator) / denominator))
                decision_diffs += li != ei;edge_diffs += legacy_edges != exact_edges
                hamming = sum(a != b for a, b in zip(numeric, targets[identifier]))
                records.append({'index': index, 'numeric': numeric, 'hamming': hamming, 'legacy': legacy,
                                'exact_numerator': numerator, 'legacy_improves': li, 'exact_improves': ei})
        require(len(records) == len(seen) == nrows, 'CSV row count mismatch: ' + context)
        require(summary['improvement_decision_discrepancies'] == decision_diffs
                and summary['greedy_edge_discrepancies'] == edge_diffs, 'Discrepancy totals mismatch: ' + context)
        close(summary['max_score_absolute_difference'], score_error, context + ' score error')
        close(summary['max_matrix_absolute_difference'], matrix_error, context + ' matrix error')
        complete = nrows == 16650 and summary['stop_reason'] == 'complete';all_complete &= complete
        require(summary['stop_reason'] in ('complete', 'time_cut') and ((nrows == 16650) == (summary['stop_reason'] == 'complete')),
                'Complete/cut contradiction: ' + context)
        for field in ('setup_seconds', 'legacy_seconds', 'exact_seconds', 'seconds', 'soft_excess_seconds'):
            require(math.isfinite(summary[field]) and summary[field] >= 0, 'Invalid timing: ' + context)
        require(summary['seconds_limit'] == 30, 'Soft time rule changed')
        close(summary['soft_excess_seconds'], max(0.0, summary['seconds'] - 30), context + ' excess')
        if not complete:
            require(summary['seconds'] >= 30, 'Time cut reported before soft limit')
        require(math.isfinite(run['process_seconds']) and run['process_seconds'] >= summary['seconds'], 'Process/core timing contradiction')
        expected_fields = {'complete': complete, 'rows_scored': nrows, 'unique_keys_inside_profile': len(seen),
                           'anchor_hamming': 0 if label == 'true' else 2, 'legacy_calls': nrows, 'exact_calls': nrows,
                           'stop_reason': summary['stop_reason'], 'denominator': denominator,
                           'decision_discrepancies': decision_diffs, 'greedy_edge_discrepancies': edge_diffs,
                           'target_evaluated_in_observed_profile': targets[identifier] in seen, 'target_is_anchor': label == 'true'}
        require(saved['privileged'] is True and saved['unknown_key_recovery_test'] is False,
                'Privileged diagnostic mislabeled as unknown-key recovery')
        for field, expected in expected_fields.items():
            require(saved[field] == expected, f'Evaluation mismatch: {context} {field}')
        for field in ('legacy_seconds', 'exact_seconds', 'setup_seconds', 'seconds', 'max_score_absolute_difference', 'max_matrix_absolute_difference'):
            close(saved[field], summary[field], context + ' ' + field)
        close(saved['process_seconds'], run['process_seconds'], context + ' process seconds')
        for backend, score in (('legacy', 'legacy'), ('exact', 'exact_numerator')):
            ranked = sorted(records, key=lambda row: (-row[score], row['numeric']))
            rank = next((i + 1 for i, row in enumerate(ranked) if row['numeric'] == targets[identifier]), None)
            top5 = [{'index': row['index'], 'numeric': list(row['numeric']), 'hamming': row['hamming'],
                     'legacy': row['legacy'], 'exact_numerator': row['exact_numerator']} for row in ranked[:5]]
            expected = {'target_rank_in_observed': rank, 'target_local_rank': rank if complete else None,
                        'target_top5_in_observed': rank is not None and rank <= 5, 'target_selected_in_observed': rank == 1,
                        'top5': top5, 'strict_improvements_over_anchor': sum(row[backend + '_improves'] for row in records)}
            for field, value in expected.items():
                require(saved[backend][field] == value, f'Lex ranking/target contradiction: {context} {backend} {field}')
        if records:
            distance = 0 if label == 'true' else 2
            improvement_hamming = {'closer': sum(row['exact_improves'] and row['hamming'] < distance for row in records),
                                  'same': sum(row['exact_improves'] and row['hamming'] == distance for row in records),
                                  'farther': sum(row['exact_improves'] and row['hamming'] > distance for row in records)}
            require(saved['exact_improvement_hamming'] == improvement_hamming, 'Hamming-improvement mismatch')
        if identifier in true_scores:
            tn, tl = true_scores[identifier]
            require(saved['true_exact_numerator'] == tn and saved['true_legacy'] == tl, 'True-state reference mismatch')
            for row in records:
                if row['numeric'] == targets[identifier]:
                    require(row['exact_numerator'] == tn and row['legacy'] == tl, 'Same target key has different saved score')
            exact_vs = {'superior': sum(row['exact_numerator'] > tn for row in records),
                        'equal': sum(row['exact_numerator'] == tn for row in records),
                        'inferior': sum(row['exact_numerator'] < tn for row in records)}
            legacy_vs = {'superior': sum(row['legacy'] > tl + 1e-12 for row in records),
                         'equal_within_epsilon': sum(abs(row['legacy'] - tl) <= 1e-12 for row in records),
                         'inferior': sum(row['legacy'] < tl - 1e-12 for row in records)}
            require(saved['exact_neighbors_vs_truth'] == exact_vs and saved['legacy_neighbors_vs_truth'] == legacy_vs,
                    'Observed-state/true-score classification mismatch')
            if records:
                close(saved['true_minus_best_exact'], float(Fraction(tn - max(row['exact_numerator'] for row in records), denominator)), context + ' true minus best')
        require(label != 'omitted' or targets[identifier] not in seen, 'Omitted swap unexpectedly a native one-step correction')
        if complete and label != 'omitted':
            require(targets[identifier] in seen, 'Prescribed native correction/true state missing')
        rows_checked += nrows
        totals['legacy_calls'] += nrows;totals['exact_calls'] += nrows;totals['idp_equivalent_calls'] += 2 * nrows
        totals['improvement_decision_discrepancies'] += decision_diffs;totals['greedy_edge_discrepancies'] += edge_diffs
        totals['legacy_seconds'] += summary['legacy_seconds'];totals['exact_seconds'] += summary['exact_seconds'];totals['process_seconds'] += run['process_seconds']

    require(manifest['all_profiles_complete'] == all_complete, 'Manifest complete-panel flag mismatch')
    require(manifest['legacy_calls'] == totals['legacy_calls'] <= 199800
            and manifest['exact_calls'] == totals['exact_calls'] <= 199800
            and traces_checked == totals['idp_equivalent_calls'] <= 399600, 'Principal cost contradiction')
    totals.update(all_profiles_complete=bool(all_complete), distinct_numeric_keys_across_cases=len(all_keys),
                  distinct_numeric_keys_per_case={case: len(keys) for case, keys in case_keys.items()},
                  distinct_case_key_combinations=sum(len(keys) for keys in case_keys.values()),
                  distinct_planted_keypairs=len(keypairs), distinct_plaintext_offsets=len(offsets))
    for field, value in totals.items():
        if isinstance(value, float):
            close(evaluation['totals'][field], value, 'total ' + field)
        else:
            require(evaluation['totals'][field] == value, 'Evaluation total mismatch: ' + field)
    controls = load(phase / 'control_results.json');control_calls = 0
    for attempt_path in sorted((phase / 'control_attempts').glob('attempt*.json')):
        attempt = load(attempt_path)
        require(sha(phase / 'control_attempts' / f'output{attempt["attempt"]}.jsonl') == attempt['output_sha256'], 'Control output hash mismatch')
        calls = within(root, 'work/phase15_crypto/' + attempt['stderr_path'])
        require(sha(calls) == attempt['calls_sha256'], 'Control marker hash mismatch')
        legacy, exact, markers = started_trace(calls, alternating=False)
        require(legacy == attempt['legacy_calls'] and exact == attempt['exact_calls'] and markers == attempt['idp_equivalent_calls'], 'Control cost mismatch')
        control_calls += markers
    require(control_calls == controls['idp_equivalent_calls_all_attempts'], 'All-attempt control costs differ')
    audit_path = root / 'work/phase15_root/post_run_audit.json'
    audit_calls = None
    if audit_path.exists():
        audit = load(audit_path)
        require(audit['passed'] is True and audit['manifest_sha256'] == manifest_hash
                and audit['rows_replayed'] == rows_checked and audit['all_profiles_complete'] == all_complete,
                'Saved fuller-audit metadata contradiction')
        audit_calls = audit['audit_IDP_equivalent_calls']
        require(audit_calls == sum(audit['audit_backend_calls'].values()), 'Saved audit cost contradiction')
    result = {'status': 'passed', 'synthetic_ciphertexts_regenerated': generated_ciphertexts,
              'profiles_checked': 12, 'rows_replayed': rows_checked, 'backend_started_markers_checked': traces_checked,
              'recorded_principal_IDP_equivalent_calls': totals['idp_equivalent_calls'],
              'recorded_artificial_control_IDP_equivalent_calls': control_calls,
              'recorded_main_audit_IDP_equivalent_calls': audit_calls,
              'all_profiles_complete': bool(all_complete), 'distinct_planted_keypairs': len(keypairs),
              'distinct_numeric_keys_per_case': totals['distinct_numeric_keys_per_case'],
              'improvement_decision_discrepancies': totals['improvement_decision_discrepancies'],
              'greedy_edge_discrepancies': totals['greedy_edge_discrepancies'], 'accounted_omitted_resources': omitted_resources,
              'new_IDP_calls': 0, 'new_searches': 0,
              'limits': 'Saved-score/key/ranking/cost consistency only. No mathematical rescoring, RNG regeneration, replay of every greedy selection, search, or historical decipherment. Anchors are privileged.'}
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT, help='Root of the completed public export')
    arguments = parser.parse_args()
    try:
        main(arguments.root)
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit(json.dumps({'status': 'failed', 'error_type': type(error).__name__,
                                    'error': str(error), 'new_IDP_calls': 0, 'new_searches': 0}, indent=2))

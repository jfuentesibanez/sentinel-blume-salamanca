"""Read-only, standard-library replay of the completed phase 16 export.

Checks recorded keys, policy events, scores, costs and synthetic target metrics.
No objective evaluation, solver, RNG regeneration, network access or file writes.
Prepared before execution: final manifests and evaluation remain untested.
"""
import argparse
import csv
import hashlib
import json
import math
import struct
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[1]
ROOT = DEFAULT_ROOT
GEOMETRY_HASH = '11fade65c2c64b718fd4cf91b61a6df6b7ab6182b1183ca857fc2fc643f5c9ff'
CSV_FIELDS = [
    'call', 'sweep', 'move_index', 'move_kind', 'base_numerator', 'numerator',
    'base_numeric', 'candidate_numeric', 'improves_base', 'accepted_immediate',
    'archive_changed',
]
REPLAY_SOURCE_SHA256 = '4199647757123900bcf922373c23d39a4a4ce1049d2a10fe4be6999661957f2a'
EVALUATION_SCHEMA_SOURCE_SHA256 = 'f05f2482123feff69c58258c91c6bac758f700bed266d43fb86fc5e125d77cf9'


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


def within(relative):
    require(isinstance(relative, str) and not Path(relative).is_absolute(),
            f'Expected relative export path: {relative!r}')
    path = (ROOT / relative).resolve()
    require(path.is_relative_to(ROOT), f'Path outside export: {relative}')
    return path


def permutation(values, width, label):
    require(isinstance(values, (list, tuple)) and len(values) == width
            and all(type(v) is int for v in values)
            and sorted(values) == list(range(width)), f'Invalid permutation: {label}')


def inverse(values):
    out = [0] * len(values)
    for index, column in enumerate(values):
        out[column] = index
    return tuple(out)


def enc(text, values):
    return ''.join(text[column::len(values)] for column in values)


def close(recorded, expected, label):
    require(isinstance(recorded, (int, float)) and math.isfinite(recorded)
            and math.isclose(recorded, expected, rel_tol=1e-12, abs_tol=1e-15),
            f'Float metadata mismatch: {label}')


def model_scale(path):
    with path.open('rb') as stream:
        data = stream.read(676 * 4)
    require(len(data) == 676 * 4, f'Truncated model: {path}')
    values = struct.unpack('<676f', data)
    require(all(math.isfinite(value) for value in values), 'Nonfinite model coefficient')
    return math.lcm(*(value.as_integer_ratio()[1] for value in values))


# These four routines are copied as source, without importing the root audit.
# The charging/writing functions and the direct mathematical scorer are absent.
def key(text):
    result = tuple(map(int, text.split(':')))
    assert len(result) == 25 and sorted(result) == list(range(25))
    return result

def improves(candidate, base, denominator):
    return (candidate - base) * 10**12 > denominator

def accept_event(call, selected, sweep, move, old_key, old_num, new_key, new_num):
    return {'call': call, 'selected_call': selected, 'sweep': sweep,
            'move_index': move, 'from_numeric': list(old_key),
            'to_numeric': list(new_key), 'from_numerator': old_num,
            'to_numerator': new_num}

def replay(profile, run, moves):
    csv_path, summary_path = ROOT / profile['csv_path'], ROOT / profile['summary_path']
    assert sha(csv_path) == run['csv_sha256'] and sha(summary_path) == run['summary_sha256']
    summary = load(summary_path)
    assert summary == run['summary']
    assert run['status'] == 'recorded' and run['returncode'] == 0 and not run['timed_out']
    assert summary['w1'] == 20 and summary['w2'] == 25 and summary['lengths'] == [615, 160]
    assert summary['convention'] == 0 and summary['source_moves'] == 16649
    start = tuple(map(int, (ROOT / profile['start_path']).read_text().split()))
    assert sorted(start) == list(range(25)) and list(start) == summary['initial_numeric']
    policy, denominator = profile['policy'], summary['denominator']
    assert policy == summary['policy'] and denominator > 0
    assert summary['backend_legacy_calls'] == 0 and summary['calls'] <= profile['max_calls']
    assert summary['call_limit'] == profile['max_calls'] and summary['sweep_limit'] == profile['max_sweeps']
    assert all(event['proposals'] > 0 for event in summary['sweep_events']), 'Empty sweeps are not started'
    events = {event['end_call']: event for event in summary['sweep_events']}
    assert len(events) == len(summary['sweep_events'])
    state, value = start, None
    seen, archive, accepts, sweep_checks = {}, {}, [], []
    first = last = None
    count = 0
    active_sweep = 0
    sweep_start = start
    sweep_num = None
    sweep_start_call = 0
    best_num = None
    best_key = start
    best_call = best_move = proposals = 0
    improvement_accepted = False
    with csv_path.open() as stream:
        for row in csv.DictReader(stream):
            count += 1
            assert int(row['call']) == count
            sweep, index, num = int(row['sweep']), int(row['move_index']), int(row['numerator'])
            base, candidate = key(row['base_numeric']), key(row['candidate_numeric'])
            base_num = int(row['base_numerator'])
            if count == 1:
                assert sweep == index == 0 and int(row['move_kind']) == -1
                assert base == candidate == state and base_num == num
                expected_improvement = expected_accept = False
                value = num
            else:
                if sweep != active_sweep:
                    assert sweep == active_sweep + 1 and index == 1
                    active_sweep = sweep
                    sweep_start, sweep_num, sweep_start_call = state, value, count - 1
                    best_num, best_key, best_call, best_move = value, state, 0, 0
                    proposals, improvement_accepted = 0, False
                proposals += 1
                assert index == proposals and index <= len(moves)
                move = moves[index - 1]
                assert int(row['move_kind']) == move['kind']
                expected_base = state if policy == 'A' else sweep_start
                expected_num = value if policy == 'A' else sweep_num
                assert base == expected_base and base_num == expected_num
                assert candidate == tuple(base[p] for p in move['p'])
                expected_improvement = improves(num, base_num, denominator)
                expected_accept = policy == 'A' and expected_improvement
                if expected_accept:
                    accepts.append(accept_event(count, count, sweep, index, state, value, candidate, num))
                    state, value, improvement_accepted = candidate, num, True
                if policy == 'B' and num > best_num:
                    best_num, best_key, best_call, best_move = num, candidate, count, index
            assert bool(int(row['improves_base'])) == expected_improvement
            assert bool(int(row['accepted_immediate'])) == expected_accept
            assert candidate not in seen or seen[candidate] == num
            seen[candidate] = num
            before = dict(archive)
            archive[candidate] = num
            archive = dict(sorted(archive.items(), key=lambda item: (-item[1], item[0]))[:5])
            assert bool(int(row['archive_changed'])) == (before != archive)
            selected = {'call': count, 'numeric': candidate, 'numerator': num}
            if first is None:
                first = selected
            last = selected
            if count in events:
                event = events[count]
                complete = proposals == len(moves)
                if complete and policy == 'B' and improves(best_num, sweep_num, denominator):
                    accepts.append(accept_event(count, best_call, sweep, best_move, state, value, best_key, best_num))
                    state, value, improvement_accepted = best_key, best_num, True
                expected_event = {'sweep': sweep, 'start_call': sweep_start_call,
                    'end_call': count, 'proposals': proposals, 'complete': complete,
                    'start_numeric': list(sweep_start), 'final_numeric': list(state),
                    'start_numerator': sweep_num, 'final_numerator': value,
                    'improvement_accepted': improvement_accepted,
                    'selected_call': best_call, 'selected_move_index': best_move,
                    'selected_numerator': best_num,
                    'convergence_observed': complete and not improvement_accepted,
                    'partial_best_admitted': False}
                assert event == expected_event, (event, expected_event)
                sweep_checks.append(expected_event)
    assert count == summary['calls'] == summary['backend_exact_calls']
    assert len(seen) == summary['visited_unique']
    assert list(state) == summary['final_numeric'] and value == summary['final_numerator']
    assert accepts == summary['accept_events'] and len(accepts) == summary['accepted_changes']
    assert sweep_checks == summary['sweep_events']
    assert sum(e['complete'] for e in sweep_checks) == summary['full_sweeps']
    assert sum(not e['complete'] for e in sweep_checks) == summary['partial_sweeps']
    assert any(e['convergence_observed'] for e in sweep_checks) == summary['convergence_observed']
    expected_archive = [{'rank': rank, 'numerator': num, 'numeric': list(numeric)}
                        for rank, (numeric, num) in enumerate(archive.items(), 1)]
    assert summary['archive'] == expected_archive
    assert bool(count) == summary['initial_scored']
    assert summary['call_limit_reached'] == (count >= profile['max_calls'])
    if summary['stop_reason'] == 'converged':
        assert summary['convergence_observed']
    if summary['stop_reason'] == 'call_limit':
        assert summary['call_limit_reached']
    if summary['stop_reason'] == 'sweep_limit':
        assert summary['full_sweeps'] == profile['max_sweeps']
    trace_path = ROOT / run['calls_path']
    assert sha(trace_path) == run['calls_sha256']
    trace_count = 0
    with trace_path.open() as stream:
        for line in stream:
            trace_count += 1
            assert line.strip() == f'@calls 0 {trace_count}'
    assert trace_count == count
    assert run['exact_calls_started'] == count and run['legacy_calls_started'] == 0
    return summary, first, last, {'rows_replayed': count, 'distinct_numeric_keys': len(seen),
                                  'accepted_changes': len(accepts), 'policy': policy}


def target_metrics(profile, run, summary, target):
    """Reconstruct external synthetic metrics from saved rows; never score."""
    archive = {}
    visited = set()
    first_target = first_top5 = minimum_hamming = None
    with within(profile['csv_path']).open(newline='') as stream:
        reader = csv.DictReader(stream)
        require(reader.fieldnames == CSV_FIELDS, 'Unexpected trajectory CSV schema')
        for count, row in enumerate(reader, 1):
            require(int(row['call']) == count, 'Target replay call sequence changed')
            numeric, numerator = key(row['candidate_numeric']), int(row['numerator'])
            visited.add(numeric)
            distance = sum(a != b for a, b in zip(numeric, target))
            minimum_hamming = distance if minimum_hamming is None else min(minimum_hamming, distance)
            if numeric == target and first_target is None:
                first_target = count
            archive[numeric] = numerator
            archive = dict(sorted(archive.items(), key=lambda item: (-item[1], item[0]))[:5])
            if target in archive and first_top5 is None:
                first_top5 = count
    archive_keys = list(archive)
    rank = archive_keys.index(target) + 1 if target in archive else None
    initial = tuple(summary['initial_numeric'])
    accepted_target = [event['call'] for event in summary['accept_events']
                       if tuple(event['to_numeric']) == target]
    first_current = 1 if summary['initial_scored'] and initial == target else (
        min(accepted_target) if accepted_target else None)
    current_states = [initial] if summary['initial_scored'] else []
    current_states += [tuple(event['to_numeric']) for event in summary['accept_events']]
    return {
        **{field: profile[field] for field in ('case_id', 'category', 'perturbation', 'policy')},
        'privileged': True,
        'unknown_key_recovery_test': False,
        'initial_hamming': sum(a != b for a, b in zip(initial, target)),
        'target_visited': target in visited,
        'first_target_call': first_target,
        'target_ever_top5': first_top5 is not None,
        'first_target_top5_call': first_top5,
        'final_archive_target_rank': rank,
        'target_final_top5': rank is not None,
        'final_numeric_is_target': tuple(summary['final_numeric']) == target,
        'first_current_target_call': first_current,
        'observed_minimum_hamming': minimum_hamming,
        'minimum_current_hamming': min(sum(a != b for a, b in zip(state, target))
            for state in current_states) if current_states else None,
        'exact_calls': summary['calls'],
        'visited_unique': len(visited),
        **{field: summary[field] for field in ('full_sweeps', 'partial_sweeps', 'accepted_changes',
            'convergence_observed', 'stop_reason', 'time_limit_reached', 'call_limit_reached',
            'seconds', 'score_seconds', 'setup_seconds')},
        'process_seconds': run['process_seconds'],
    }


def check_resources(manifest):
    inventory_path = ROOT / 'provenance/phase16_source_inventory.jsonl'
    inventory = {}
    if inventory_path.exists():
        entries = [json.loads(line) for line in inventory_path.read_text().splitlines() if line.strip()]
        inventory = {entry['source_path']: entry for entry in entries}
        require(len(entries) == len(inventory), 'Duplicate phase 16 inventory source')
        for entry in entries:
            require(entry['disposition'] in ('included', 'referenced_only'), 'Unknown inventory disposition')
            if entry['disposition'] == 'included':
                path = within(entry['repository_path'])
                require(path.is_file() and sha(path) == entry['sha256'] and path.stat().st_size == entry['bytes'],
                        f'Included phase 16 file differs: {entry["repository_path"]}')
    omitted = []
    for relative, digest in manifest['resources'].items():
        source = 'work/phase16_crypto/' + relative
        path = within(source)
        if path.exists():
            require(path.is_file() and sha(path) == digest, f'Retained resource differs: {relative}')
        else:
            entry = inventory.get(source)
            require(entry is not None and entry['disposition'] == 'referenced_only'
                    and entry['sha256'] == digest and bool(entry.get('reason')),
                    f'Unaccounted omitted resource: {relative}')
            omitted.append(relative)
    for item in manifest['models_and_holdouts']:
        require(sha(within(item['path'])) == item['sha256'], 'Model/holdout hash differs')
    return omitted


def check_controls():
    phase = ROOT / 'work/phase16_crypto'
    controls = load(phase / 'control_results.json')
    require(controls['status'] == 'passed' and controls['truth_generated'] is False
            and controls['main_runs'] == 0, 'Policy controls missing or outside artificial scope')
    legacy = exact = attempts = 0
    for attempt_path in sorted((phase / 'control_attempts').glob('attempt*.json')):
        attempt = load(attempt_path)
        number = attempt['attempt']
        output = phase / 'control_attempts' / f'output{number}.jsonl'
        trace = phase / 'control_attempts' / f'calls{number}.log'
        require(sha(output) == attempt['output_sha256'] and sha(trace) == attempt['trace_sha256'],
                'Mock-control output/trace hash changed')
        require(not trace.read_text().strip(), 'Mock controls entered a real backend')
        require(attempt['actual_legacy_IDP_calls'] == attempt['actual_exact_IDP_calls'] == 0,
                'Mock controls declare real IDP calls')
        rows = [json.loads(line) for line in output.read_text().splitlines() if line.strip()]
        if attempt['status'] == 'passed':
            require(attempt['returncode'] == 0 and attempt['timed_out'] is False and rows
                    and rows[-1] == attempt['fixture_record'], 'Passed fixture receipt contradiction')
            fixture = rows[-1]
            require(fixture['status'] == 'passed' and fixture['new_exact_IDP_calls'] == 0
                    and fixture['new_legacy_IDP_calls'] == 0 and fixture['truth_read'] is False
                    and fixture['truth_generated'] is False, 'Mock fixture scope/cost changed')
        legacy += attempt['actual_legacy_IDP_calls']
        exact += attempt['actual_exact_IDP_calls']
        attempts += 1
    require(attempts > 0 and legacy == controls['actual_legacy_IDP_calls_all_attempts'] == 0
            and exact == controls['actual_exact_IDP_calls_all_attempts'] == 0,
            'All-attempt mock-control cost changed')
    latest = controls['latest_attempt']
    require(latest == load(phase / 'control_attempts' / f'attempt{latest["attempt"]}.json'),
            'Latest control receipt mismatch')
    require(controls['policy_fixtures'] == latest['fixture_record']['policy_fixtures'],
            'Fixture count changed')
    return {'attempts': attempts, 'recorded_legacy_IDP_calls': legacy, 'recorded_exact_IDP_calls': exact,
            'policy_fixtures': controls['policy_fixtures']}


def verify_evaluation(evaluation, reconstructed, cases, totals):
    """Check the current evaluate_external.py schema without importing it."""
    require(evaluation['status'] == 'evaluated' and evaluation['new_exact_IDP_calls'] == 0
            and evaluation['new_legacy_IDP_calls'] == 0, 'External evaluation entered a scorer')
    expected_cases = {}
    for identifier, truth in cases['truths'].items():
        expected_cases[identifier] = {field: truth[field] for field in
            ('language_model', 'plant_seed', 'sample_position', 'true_k1', 'true_k2')}
        expected_cases[identifier]['plaintext_sha256'] = cases['plaintext_hashes'][identifier]
    require(evaluation['cases'] == expected_cases, 'Evaluated synthetic case metadata differs')
    require(evaluation['profiles'] == reconstructed, 'Evaluated trajectory metric differs from saved replay')
    groups = {}
    paired = {}
    for result in reconstructed:
        name = f'{result["category"]}_{result["perturbation"]}_{result["policy"]}'
        group = groups.setdefault(name, {'profiles': 0, 'target_visited': 0, 'target_ever_top5': 0,
            'target_final_top5': 0, 'target_final_current': 0, 'exact_calls': 0,
            'time_limit_reached_profiles': 0, 'time_stop_profiles': 0, 'converged_profiles': 0, 'full_sweeps': 0})
        group['profiles'] += 1
        for label, field in (('target_visited', 'target_visited'), ('target_ever_top5', 'target_ever_top5'),
            ('target_final_top5', 'target_final_top5'), ('target_final_current', 'final_numeric_is_target'),
            ('time_limit_reached_profiles', 'time_limit_reached'), ('converged_profiles', 'convergence_observed')):
            group[label] += int(result[field])
        group['time_stop_profiles'] += int(result['stop_reason'] == 'time_limit')
        group['exact_calls'] += result['exact_calls']
        group['full_sweeps'] += result['full_sweeps']
        if result['category'] == 'main':
            pair = paired.setdefault((result['case_id'], result['perturbation']), {})
            pair[result['policy']] = result
    require(len(paired) == 8 and all(set(pair) == {'A', 'B'} for pair in paired.values()),
            'Expected eight complete policy pairs')
    contrasts = []
    for (identifier, perturbation), pair in paired.items():
        a, b = pair['A'], pair['B']
        contrasts.append({'case_id': identifier, 'perturbation': perturbation,
            'time_limit_in_pair': a['time_limit_reached'] or b['time_limit_reached'],
            'A_minus_B_target_visited': int(a['target_visited']) - int(b['target_visited']),
            'A_minus_B_final_target': int(a['final_numeric_is_target']) - int(b['final_numeric_is_target']),
            'A_minus_B_final_archive_target': int(a['target_final_top5']) - int(b['target_final_top5']),
            'A_minus_B_actual_calls': a['exact_calls'] - b['exact_calls']})
    require(evaluation['groups'] == groups and evaluation['paired_contrasts'] == contrasts,
            'Evaluated group or paired-policy metrics differ')
    expected_totals = {field: totals[field] for field in ('main_exact_calls', 'positive_exact_calls',
        'distinct_planted_keypairs', 'distinct_plaintext_offsets')}
    expected_totals.update(process_seconds=sum(result['process_seconds'] for result in reconstructed),
                           new_exact_IDP_calls=0, new_legacy_IDP_calls=0, new_searches=0)
    require(evaluation['totals'] == expected_totals, 'Evaluated totals differ')


def main(root):
    global ROOT
    require(__debug__, 'Run without Python -O: the copied replay assertions must remain enabled')
    ROOT = root.resolve()
    phase = ROOT / 'work/phase16_crypto'
    manifest = load(phase / 'manifest.json')
    plan = load(phase / 'plan20.json')
    sealed = load(phase / 'sealed_design.json')
    guard = load(phase / 'no_truth_verification.json')
    evaluation = load(phase / 'evaluation.json')
    manifest_hash = sha(phase / 'manifest.json')
    require(manifest['status'] == 'completed' and manifest['completed'] is True
            and manifest['protected_unchanged'] is True, 'Requires a completed phase 16 panel')
    require(manifest['plan_sha256'] == sealed['plan_sha256'] == sha(phase / 'plan20.json'),
            'Plan hash mismatch')
    require(manifest['truth_sha256'] == sha(phase / 'truth.jsonl'), 'Synthetic truth hash mismatch')
    require(evaluation['manifest_sha256'] == manifest_hash
            and evaluation['truth_sha256'] == manifest['truth_sha256'], 'Evaluation input hashes differ')
    require(manifest['protected_before'] == manifest['protected_after'] == plan['protected_before'],
            'Recorded prior-file hashes changed')
    require(manifest['baseline_sha256'] == sealed['baseline_sha256'] == plan['baseline_sha256'],
            'Protected-baseline metadata changed')
    baseline_path = ROOT / 'work/phase16_root/frozen_before.json'
    if baseline_path.exists():
        require(sha(baseline_path) == plan['baseline_sha256'], 'Protected-baseline hash differs')
        baseline = load(baseline_path)
        require(baseline['hashes'] == plan['protected_before']
                and baseline['count'] == len(baseline['hashes']), 'Protected-baseline set differs')
    require(manifest['resources'] == plan['resources'] == sealed['resources']
            and manifest['models_and_holdouts'] == plan['models_and_holdouts'] == sealed['models_and_holdouts'],
            'Resource metadata changed after plan')
    require(manifest['cases'] == sealed['cases'] and manifest['profiles'] == sealed['profiles'],
            'Sealed inputs changed')
    approval = load(phase / 'audit_approval.json')
    require(approval == manifest['audit_approval'] == sealed['audit_approval']
            and approval['root_approved'] is True and approval['independent_approved'] is True
            and approval['plan_sha256'] == manifest['plan_sha256'], 'Double approval mismatch')
    require(approval['new_truth_generated_before_approval'] is False
            and approval['main_IDP_calls_before_approval'] == 0, 'Approval chronology/scope differs')
    for kind in ('root', 'independent'):
        require(sha(within(approval[f'{kind}_review_path'])) == approval[f'{kind}_review_sha256'],
                f'{kind} approved review hash differs')
    require(guard['status'] == 'passed' and guard['manifest_sha256'] == manifest_hash,
            'External evaluation lacks the matching passed guard')
    require(guard['plan_sha256'] == manifest['plan_sha256'] and guard['profiles_checked'] == 20
            and guard['new_IDP_calls'] == guard['new_exact_IDP_calls'] == guard['new_legacy_IDP_calls'] == 0
            and guard['truth_read'] is False and guard['plaintext_read'] is False
            and guard['target_compared'] is False, 'Record guard scope/input mismatch')
    require(plan['phase'] == 16 and plan['expected_cases'] == 4 and plan['expected_profiles'] == 20
            and plan['expected_main_trajectories'] == 16 and plan['expected_positive_controls'] == 4
            and plan['widths'] == [20, 25] and plan['lengths'] == [615, 160]
            and plan['convention'] == 0 and plan['source_moves'] == 16649,
            'Unexpected approved design')
    require(plan['main_call_limit'] == 49948 and plan['main_max_sweeps'] == 3
            and plan['main_calls_max'] == 799168 and plan['positive_call_limit'] == 16650
            and plan['positive_max_sweeps'] == 1 and plan['positive_calls_max'] == 66600
            and plan['soft_seconds'] == 30 and plan['hard_process_seconds'] == 40
            and plan['retries'] == 0 and plan['cache'] is False,
            'Approved caps or stopping scope changed')
    omitted = check_resources(manifest)
    geometry = load(phase / 'moves.json')
    moves = geometry['moves']
    require(len(moves) == 16649, 'Source move count changed')
    permutations = [tuple(range(25))]
    for index, move in enumerate(moves, 1):
        require(move['index'] == index and move['kind'] in (0, 1, 2), 'Move index/type changed')
        permutation(move['p'], 25, f'move {index}')
        permutations.append(tuple(move['p']))
    require(len(set(permutations)) == 16650 and hashlib.sha256(
        json.dumps(sorted(permutations), separators=(',', ':')).encode()).hexdigest() == GEOMETRY_HASH,
        'Frozen source geometry changed')
    truths_list = [json.loads(line) for line in (phase / 'truth.jsonl').read_text().splitlines() if line.strip()]
    truths = {item['case_id']: item for item in truths_list}
    cases = {case['case_id']: case for case in manifest['cases']}
    require(len(truths_list) == len(truths) == len(cases) == 4 and set(cases) == set(truths),
            'Expected four distinct synthetic cases')
    require(len(manifest['cases']) == len(plan['cases']) == 4, 'Plan case count mismatch')
    for planned, case in zip(plan['cases'], manifest['cases']):
        require(all(case[field] == value for field, value in planned.items()), 'Case changed after plan')
    targets = {}
    scales = {}
    plaintext_hashes = {}
    keypairs = set()
    offsets = set()
    seeds = set()
    ciphertexts_checked = 0
    for identifier, case in cases.items():
        truth = truths[identifier]
        require(truth['language_model'] == case['language_model'] and truth['plant_seed'] == case['plant_seed'],
                'Case/truth seed or model mismatch')
        permutation(truth['true_k1'], 20, identifier + ' K1')
        permutation(truth['true_k2'], 25, identifier + ' K2')
        targets[identifier] = inverse(truth['true_k2'])
        keypairs.add((tuple(truth['true_k1']), tuple(truth['true_k2'])))
        seeds.add(truth['plant_seed'])
        offsets.add(truth['sample_position'])
        folder = ROOT / 'work/phase5_language' / case['language_model']
        body = ''.join(c.lower() for c in (folder / 'holdout.txt').read_text()
                       if c.isascii() and c.isalpha())
        position = truth['sample_position']
        require(type(position) is int and 0 <= position <= len(body) - 775, 'Invalid holdout offset')
        plaintexts = [body[position:position + 615], body[position + 615:position + 775]]
        plaintext_hashes[identifier] = [hashlib.sha256(text.encode()).hexdigest() for text in plaintexts]
        require(len(case['ciphertext_files']) == len(case['ciphertext_paths']) == 2, 'Expected two ciphertexts')
        for item, recorded, plaintext in zip(case['ciphertext_files'], case['ciphertext_paths'], plaintexts):
            path = within(item['path'])
            require(item['path'] == recorded and sha(path) == item['sha256'], 'Ciphertext hash/path mismatch')
            require(path.read_text().strip().lower() == enc(enc(plaintext, truth['true_k1']), truth['true_k2']),
                    'Synthetic ciphertext regeneration mismatch')
            ciphertexts_checked += 1
        scales[identifier] = model_scale(folder / 'model.bin')
    require(len(seeds) == 4, 'Planting seeds are not four distinct values')

    profiles = manifest['profiles']
    runs = manifest['runs']
    identifiers = lambda item: (item['case_id'], item['category'], item['perturbation'], item['policy'])
    expected_ids = {(case, 'main', perturb, policy) for case in cases
                    for perturb in ('h4', 'h8') for policy in ('A', 'B')}
    expected_ids |= {(case, 'positive_control', 'positive', 'B') for case in cases}
    require(len(profiles) == len(runs) == len(plan['profiles']) == 20
            and set(map(identifiers, profiles)) == set(map(identifiers, runs)) == expected_ids,
            'Profile IDs mismatch')
    audit = load(ROOT / 'work/phase16_root/post_run_audit.json')
    require(audit['status'] == 'passed' and audit['manifest_sha256'] == manifest_hash
            and audit['truth_read'] is False and audit['target_comparisons'] == 0
            and audit['profiles_checked'] == len(audit['checks']) == 20
            and audit['legacy_reference_calls_started'] == 0, 'Matching numerical audit missing')
    numerical = guard['separate_root_numerical_audit']
    require(numerical['status'] == 'passed' and numerical['attempts'] == 1
            and numerical['legacy_IDP_calls'] == 0
            and sha(within(numerical['path'])) == numerical['sha256'], 'Guard numerical-audit reference differs')
    audit_receipt_path = within(numerical['receipt_path'])
    require(sha(audit_receipt_path) == numerical['receipt_sha256'], 'Numerical-audit receipt hash differs')
    audit_receipt = load(audit_receipt_path)
    require(audit_receipt['status'] == 'passed' and audit_receipt['attempt'] == 1
            and audit_receipt['returncode'] == 0 and audit_receipt['timed_out'] is False
            and audit_receipt['legacy_reference_calls_started'] == 0,
            'Numerical-audit attempt scope differs')
    independent = guard['independent_records_audit']
    require(sha(within(independent['path'])) == independent['sha256']
            and sha(within(independent['receipt_path'])) == independent['receipt_sha256']
            and independent['new_IDP_calls'] == 0, 'Independent-record audit reference differs')
    reconstructed = []
    rows_checked = audit_cost = main_calls = positive_calls = 0
    stops = {}
    for planned, profile, run, checked in zip(plan['profiles'], profiles, runs, audit['checks']):
        require(all(profile[field] == value for field, value in planned.items()), 'Profile changed after plan')
        require(identifiers(profile) == identifiers(run) == identifiers(checked), 'Profile/run/audit order mismatch')
        for field in ('csv_path', 'summary_path', 'start_path'):
            within(profile[field])
        within(run['calls_path'])
        require(run['status'] == 'recorded' and run['returncode'] == 0 and run['timed_out'] is False,
                'Failed process presented as completed')
        start_path = within(profile['start_path'])
        require(sha(start_path) == profile['start_sha256'], 'Privileged start hash changed')
        start = list(map(int, start_path.read_text().split()))
        expected = list(targets[profile['case_id']])
        pairs = [(0, 1), (2, 3), (4, 5), (6, 7)]
        nswaps = {'positive': 1, 'h4': 2, 'h8': 4}[profile['perturbation']]
        for a, b in pairs[:nswaps]:
            expected[a], expected[b] = expected[b], expected[a]
        require(start == expected, 'Start is not the prescribed privileged perturbation')
        summary, first, last, result = replay(profile, run, moves)
        require(summary['mode'] == 'privileged_k2_trajectory' and summary['w1'] == 20
                and summary['w2'] == 25 and summary['lengths'] == [615, 160]
                and summary['convention'] == 0 and summary['source_moves'] == 16649
                and summary['seconds_limit'] == 30, 'Trajectory configuration mismatch')
        require(summary['scale'] == scales[profile['case_id']]
                and summary['denominator'] == 760 * summary['scale'], 'Model scale/normalizer changed')
        cap = 49948 if profile['category'] == 'main' else 16650
        nsweeps = 3 if profile['category'] == 'main' else 1
        require(profile['max_calls'] == cap and profile['max_sweeps'] == nsweeps,
                'Category budget differs')
        require(run['exact_calls_started'] == summary['calls'] and run['legacy_calls_started'] == 0,
                'Persisted backend calls differ')
        require(summary['stop_reason'] in ('call_limit', 'time_limit', 'converged', 'sweep_limit'),
                'Unexpected stop reason')
        for field in ('seconds', 'setup_seconds', 'score_seconds', 'soft_excess_seconds'):
            require(math.isfinite(summary[field]) and summary[field] >= 0, 'Invalid timing metadata')
        require(math.isfinite(run['process_seconds']) and run['process_seconds'] >= summary['seconds'],
                'Process/core timing contradiction')
        close(summary['soft_excess_seconds'], max(0.0, summary['seconds'] - 30), 'soft excess')
        require(summary['time_limit_reached'] == (summary['seconds'] >= 30), 'Time flag mismatch')
        if summary['stop_reason'] == 'time_limit':
            require(summary['time_limit_reached'], 'Time stop precedes recorded soft limit')
        selected = [state['call'] for state in (first, last) if state is not None]
        require(checked['direct_reference_scored_calls'] == selected
                and all(checked[field] == result[field] for field in result), 'Saved fuller audit replay differs')
        audit_cost += len(selected)
        rows_checked += summary['calls']
        if profile['category'] == 'main':
            main_calls += summary['calls']
        else:
            positive_calls += summary['calls']
        stops[summary['stop_reason']] = stops.get(summary['stop_reason'], 0) + 1
        reconstructed.append(target_metrics(profile, run, summary, targets[profile['case_id']]))
    require(rows_checked == main_calls + positive_calls == manifest['total_exact_calls']
            and main_calls == manifest['main_exact_calls'] <= 799168
            and positive_calls == manifest['positive_exact_calls'] <= 66600,
            'Principal/control trajectory cost contradiction')
    require(audit_cost == audit['exact_reference_calls_started'] <= 40
            and rows_checked == audit['rows_replayed'], 'Saved numerical-audit cost contradiction')
    require(audit_cost == numerical['exact_IDP_calls'] == audit_receipt['exact_reference_calls_started'],
            'Numerical-audit receipt/guard costs differ')
    controls = check_controls()
    require(guard['main_rows_checked'] == main_calls and guard['positive_rows_checked'] == positive_calls
            and guard['rows_checked'] == guard['markers_checked'] == rows_checked
            and guard['paired_starts_checked'] == 8 and guard['launcher_parse_failure_IDP_calls'] == 0
            and guard['synthetic_control_actual_IDP_calls'] == 0
            and guard['total_known_phase16_IDP_calls'] == rows_checked + audit_cost,
            'Record guard cost/row counts differ')
    totals = {'main_exact_calls': main_calls, 'positive_exact_calls': positive_calls,
              'total_exact_calls': rows_checked, 'distinct_planted_keypairs': len(keypairs),
              'distinct_plaintext_offsets': len(offsets), 'distinct_plant_seeds': len(seeds)}
    verify_evaluation(evaluation, reconstructed,
                      {'truths': truths, 'plaintext_hashes': plaintext_hashes}, totals)
    print(json.dumps({'status': 'passed', 'profiles_checked': 20,
        'main_trajectories': 16, 'scientific_positive_controls': 4,
        'rows_replayed': rows_checked, 'backend_started_markers_checked': rows_checked,
        'synthetic_ciphertexts_regenerated': ciphertexts_checked,
        'recorded_main_exact_calls': main_calls, 'recorded_positive_exact_calls': positive_calls,
        'recorded_numerical_audit_exact_calls': audit_cost,
        'recorded_mock_control_IDP_calls': controls['recorded_exact_IDP_calls'],
        'recorded_total_IDP_calls': rows_checked + audit_cost,
        'stop_reasons': stops, 'accounted_omitted_resources': omitted,
        'new_IDP_calls': 0, 'new_solver_trajectories': 0,
        'scope': 'Recorded-data replay only; all starts privileged.',
        'limits': 'No mathematical rescoring, RNG key recreation, historical attack or unknown-key recovery.'}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT,
                        help='Root of the completed public export')
    arguments = parser.parse_args()
    try:
        main(arguments.root)
    except (OSError, ValueError, KeyError, TypeError, AssertionError) as error:
        raise SystemExit(json.dumps({'status': 'failed', 'error_type': type(error).__name__,
            'error': str(error), 'new_IDP_calls': 0, 'new_solver_trajectories': 0}, indent=2))

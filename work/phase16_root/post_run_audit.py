"""Replay privileged trajectories without targets; score two recorded states/run.

The exact reference enumerates every feasible pair of offsets directly. This is
an audit, not a search. Every reference entry is persisted before calculating.
"""
from pathlib import Path
import csv
import hashlib
import json
import struct
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
PHASE = ROOT / 'work/phase16_crypto'
CHARGED = 0


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return json.loads(path.read_text())


def key(text):
    result = tuple(map(int, text.split(':')))
    assert len(result) == 25 and sorted(result) == list(range(25))
    return result


def improves(candidate, base, denominator):
    return (candidate - base) * 10**12 > denominator


def charge():
    global CHARGED
    CHARGED += 1
    assert CHARGED <= 40
    (HERE / 'audit_progress.json').write_text(json.dumps({
        'status': 'running', 'exact_reference_calls_started': CHARGED,
        'cost_rule': 'Charged before entering the direct exact backend, including interrupted entries.',
        'new_searches': 0}) + '\n')


def undo_second(cipher, numeric):
    width = len(numeric)
    rows, remainder = divmod(len(cipher), width)
    output = [None] * len(cipher)
    cursor = 0
    for column in sorted(range(width), key=numeric.__getitem__):
        for row in range(rows + (column < remainder)):
            output[row * width + column] = cipher[cursor]
            cursor += 1
    assert cursor == len(cipher) and all(x is not None for x in output)
    return output


def exact_matrix_direct(text, width, table, scale):
    rows, remainder = divmod(len(text), width)
    offsets = [range(max(0, c - (width - remainder)), min(c, remainder) + 1)
               for c in range(width)]
    matrix = [-1000000 * scale] * (width * width)
    for a in range(width):
        for b in range(width):
            if a != b:
                matrix[a * width + b] = max(
                    sum(table[text[a * rows + x + r] * 26 + text[b * rows + y + r]]
                        for r in range(rows)) for x in offsets[a] for y in offsets[b])
    return matrix


def direct_score(ciphertexts, numeric, table, scale):
    charge()
    intermediate = [undo_second(c, numeric) for c in ciphertexts]
    matrices = [exact_matrix_direct(t, 20, table, scale) for t in intermediate]
    matrix = [sum(m[z] for m in matrices) for z in range(400)]
    rows = sum(len(c) // 20 for c in ciphertexts)
    used_a, used_b = set(), set()
    total = 0
    for _ in range(20):
        best = x = y = None
        for a in range(20):
            if a in used_a:
                continue
            for b in range(20):
                if b in used_b or a == b:
                    continue
                if best is None or matrix[a * 20 + b] > best:
                    best, x, y = matrix[a * 20 + b], a, b
        if x is None:
            x = next(a for a in range(20) if a not in used_a)
            y = next(b for b in range(20) if b not in used_b)
            best = -7 * rows * scale
        total += best
        used_a.add(x)
        used_b.add(y)
    return total


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


def main():
    started = time.monotonic()
    assert not (HERE / 'post_run_audit.json').exists(), 'No retry of completed audit'
    # Exclusive latch also forbids restarting after failure or abrupt termination.
    with (HERE / 'audit_started.json').open('x') as stream:
        json.dump({'status': 'started', 'started_at_unix': time.time(),
                   'audit_source_sha256': sha(Path(__file__)),
                   'exact_reference_calls_started': 0,
                   'attempt': 1, 'maximum_attempts': 1}, stream)
    manifest = load(PHASE / 'manifest.json')
    assert manifest['status'] == 'completed' and manifest['completed']
    assert sha(PHASE / 'plan20.json') == manifest['plan_sha256']
    assert len(manifest['profiles']) == len(manifest['runs']) == 20
    moves = load(PHASE / 'moves.json')['moves']
    assert len(moves) == 16649
    cases = {case['case_id']: case for case in manifest['cases']}
    checks = []
    initial_scores = {}
    for profile, run in zip(manifest['profiles'], manifest['runs']):
        assert all(profile[field] == run[field] for field in ('case_id', 'category', 'perturbation', 'policy'))
        summary, first, last, result = replay(profile, run, moves)
        if first is not None and profile['category'] == 'main':
            label = (profile['case_id'], profile['perturbation'])
            observed = (first['numeric'], first['numerator'])
            assert label not in initial_scores or initial_scores[label] == observed
            initial_scores[label] = observed
        case = cases[profile['case_id']]
        model_path = ROOT / 'work/phase5_language' / case['language_model'] / 'model.bin'
        model = struct.unpack('<676f', model_path.read_bytes()[:2704])
        scale = summary['scale']
        table = []
        for f in model:
            numerator, divisor = f.as_integer_ratio()
            assert scale % divisor == 0
            table.append(numerator * (scale // divisor))
        ciphertexts = [[ord(c) - 65 for c in (ROOT / path).read_text().strip()]
                       for path in case['ciphertext_paths']]
        assert summary['denominator'] == scale * sum(len(c) // 20 for c in ciphertexts) * 20
        selected = [s for s in (first, last) if s is not None]
        for state in selected:
            assert direct_score(ciphertexts, state['numeric'], table, scale) == state['numerator']
        result.update(case_id=profile['case_id'], category=profile['category'],
                      perturbation=profile['perturbation'],
                      direct_reference_scored_calls=[s['call'] for s in selected])
        checks.append(result)
    assert CHARGED == sum(len(c['direct_reference_scored_calls']) for c in checks)
    assert sum(c['rows_replayed'] for c in checks) == manifest['total_exact_calls']
    result = {'status': 'passed', 'manifest_sha256': sha(PHASE / 'manifest.json'),
        'truth_read': False, 'target_comparisons': 0, 'new_searches': 0,
        'profiles_checked': len(checks), 'rows_replayed': sum(c['rows_replayed'] for c in checks),
        'exact_reference_calls_started': CHARGED, 'legacy_reference_calls_started': 0,
        'audit_policy': 'Initial and last recorded candidate per profile; duplicate selections charged. Direct feasible-pair enumeration reference.',
        'checks': checks, 'seconds': time.monotonic() - started}
    (HERE / 'post_run_audit.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()

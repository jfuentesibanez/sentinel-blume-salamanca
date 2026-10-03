"""Independent streaming replay of phase18 records; no objective or truth input.

Written prospectively, before data generation. Run only after sealed execution.
Imports stdlib only; does not import the runner, scorer or root record auditor.
The original and final charged rows are returned as samples, never evaluated.
The saved-record audit has its own fixed 120-second limit and zero IDP. It may
occur after the scientific execution clock expires; it cannot authorise scores.
"""
from pathlib import Path
import csv
import hashlib
import json
import math
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'work/phase18_crypto'
REVIEW = Path(__file__).resolve().parent
FIELDS = ['call', 'sweep', 'move_index', 'move_kind', 'base_numerator',
          'numerator', 'base_numeric', 'candidate_numeric', 'improves_base',
          'accepted_immediate', 'archive_changed']


def need(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def load(path):
    return json.loads(path.read_text())


def safe(path, directory=HERE):
    result = (ROOT / path).resolve()
    need(result.is_relative_to(directory.resolve()), 'Path outside allowed new-record directory')
    return result


def integer(value):
    need(type(value) is int, 'Expected an integer, not a boolean or float')
    return value


def key(value, separator=':'):
    result = tuple(map(int, value.split(separator) if separator else value.split()))
    need(len(result) == 25 and sorted(result) == list(range(25)), 'Invalid numeric permutation')
    return result


def fresh_json(path, data):
    # Exclusive creation preserves every started/failed attempt; no replacement.
    with path.open('x') as stream:
        stream.write(json.dumps(data, ensure_ascii=False, indent=2) + '\n')


def deadline(manifest):
    need(time.monotonic() < manifest['_record_audit_deadline'],
         'Independent 120-second read-audit limit exhausted')


def replay(profile, run, moves, manifest):
    need(profile['policy'] == 'B' and run['profile_id'] == profile['profile_id'], 'Profile mismatch')
    need(run['status'] == 'completed' and run['returncode'] == 0 and
         run['guard_stop'] is None, 'Failed or guard-stopped route cannot pass')
    for field in ('case_id', 'category'):
        need(run[field] == profile[field], 'Run/profile category differs')
    paths = {name: safe(profile[name]) for name in ('start_path', 'csv_path', 'summary_path', 'calls_path')}
    hashes = {name: digest(path) for name, path in paths.items()}
    need(hashes['start_path'] == profile['start_sha256'], 'Start hash differs')
    need(hashes['csv_path'] == run['csv_sha256'] and
         hashes['summary_path'] == run['summary_sha256'], 'Result hash differs')
    need(run['calls_path'] == profile['calls_path'] and
         hashes['calls_path'] == run['calls_sha256'], 'Marker path/hash differs')
    s = load(paths['summary_path'])
    need(s == run['summary'], 'Summary file and manifest differ')
    need(s['mode'] == 'phase18_k2_trajectory' and s['policy'] == 'B', 'Wrong solver mode')
    need((s['w1'], s['w2'], s['convention'], s['lengths']) == (20, 25, 0, [615, 160]),
         'Unexpected dimensions or convention')
    need(s['source_moves'] == len(moves) == 16649, 'Movement count differs')
    need(s['call_limit'] == profile['max_calls'] and s['sweep_limit'] == profile['max_sweeps'] and
         s['seconds_limit'] == profile['soft_seconds'], 'Profile limits differ')
    current = key(paths['start_path'].read_text(), None)
    need(s['initial_numeric'] == list(current), 'Initial key differs')
    scale, den = integer(s['scale']), integer(s['denominator'])
    need(scale > 0 and den == scale * (615 // 20 + 160 // 20) * 20, 'Invalid exact denominator')
    bound = integer(s['checked_absolute_numerator_bound'])
    need(bound >= 0, 'Invalid declared numerator bound')
    value, count, sweep = None, 0, None
    seen, top, events, changes, samples = {}, {}, [], [], [None, None]

    def close_sweep():
        nonlocal current, value, sweep
        if sweep is None:
            return
        complete = sweep['proposals'] == len(moves)
        accepted = complete and (sweep['best_num'] - sweep['base_num']) * 10**12 > den
        if accepted:
            changes.append(dict(call=count, selected_call=sweep['best_call'],
                                sweep=sweep['number'], move_index=sweep['best_index'],
                                from_numeric=list(current), to_numeric=list(sweep['best_key']),
                                from_numerator=value, to_numerator=sweep['best_num']))
            current, value = sweep['best_key'], sweep['best_num']
        events.append(dict(sweep=sweep['number'], start_call=sweep['start_call'], end_call=count,
                           proposals=sweep['proposals'], complete=complete,
                           start_numeric=list(sweep['base']), final_numeric=list(current),
                           start_numerator=sweep['base_num'], final_numerator=value,
                           improvement_accepted=accepted, selected_call=sweep['best_call'],
                           selected_move_index=sweep['best_index'], selected_numerator=sweep['best_num'],
                           convergence_observed=complete and not accepted, partial_best_admitted=False))
        sweep = None

    with paths['csv_path'].open(newline='') as stream:
        reader = csv.DictReader(stream)
        need(reader.fieldnames == FIELDS, 'CSV schema differs')
        for row in reader:
            if count % 256 == 0:
                deadline(manifest)
            n, sn, ix = int(row['call']), int(row['sweep']), int(row['move_index'])
            need(n == count + 1 and n <= profile['max_calls'], 'Call sequence or cap differs')
            candidate, base = key(row['candidate_numeric']), key(row['base_numeric'])
            num, base_num = int(row['numerator']), int(row['base_numerator'])
            need(abs(num) <= bound and abs(base_num) <= bound, 'Numerator exceeds bound')
            for boolean in ('improves_base', 'accepted_immediate', 'archive_changed'):
                need(row[boolean] in ('0', '1'), 'Invalid CSV boolean')
            need(row['accepted_immediate'] == '0', 'B used immediate acceptance')
            if n == 1:
                need((sn, ix, int(row['move_kind'])) == (0, 0, -1), 'Missing initial row')
                need(candidate == base == current and num == base_num and row['improves_base'] == '0',
                     'Initial row differs from supplied start')
                value = num
            else:
                if sweep is None or sn != sweep['number']:
                    close_sweep()
                    need(sn == len(events) + 1 <= profile['max_sweeps'], 'Sweep order/cap differs')
                    need(not events or (events[-1]['complete'] and not events[-1]['convergence_observed']),
                         'Route continued after partial or stable sweep')
                    sweep = dict(number=sn, base=current, base_num=value, start_call=count,
                                 proposals=0, best_key=current, best_num=value, best_call=0, best_index=0)
                sweep['proposals'] += 1
                need(ix == sweep['proposals'] <= len(moves), 'Source movement order differs')
                mv = moves[ix - 1]
                need(int(row['move_kind']) == mv['kind'] and base == sweep['base'] and
                     base_num == sweep['base_num'], 'Move kind or fixed anchor differs')
                need(candidate == tuple(base[j] for j in mv['p']), 'Candidate is not the recorded source move')
                need((row['improves_base'] == '1') == ((num - base_num) * 10**12 > den),
                     'Exact strict EPS decision differs')
                if num > sweep['best_num']:
                    sweep.update(best_key=candidate, best_num=num, best_call=n, best_index=ix)
            count = n
            need(candidate not in seen or seen[candidate] == num, 'Repeated key changed numerator')
            seen[candidate] = num
            old = list(top.items())
            top[candidate] = num
            top = dict(sorted(top.items(), key=lambda item: (-item[1], item[0]))[:5])
            need((row['archive_changed'] == '1') == (old != list(top.items())), 'Archive change differs')
            sample = dict(call=n, sweep=sn, move_index=ix, numeric=list(candidate), numerator=num)
            if samples[0] is None:
                samples[0] = sample
            samples[1] = sample
        close_sweep()

    marks = 0
    with paths['calls_path'].open() as stream:
        for line in stream:
            if marks % 1024 == 0:
                deadline(manifest)
            marks += 1
            need(line.rstrip('\r\n') == f'@calls 0 {marks}', 'Literal backend marker sequence differs')
    need(count == marks == integer(run['backend_marker_calls']) == integer(s['calls']) ==
         integer(s['backend_exact_calls']), 'CSV/marker/summary counts differ')
    need(s['backend_legacy_calls'] == run['legacy_calls'] == 0, 'Legacy calls occurred')
    need(s['initial_scored'] is bool(count), 'Initial-scored flag differs')
    need(s['final_numeric'] == list(current) and s['final_numerator'] == value, 'Final state differs')
    archive = [dict(rank=i + 1, numerator=num, numeric=list(k)) for i, (k, num) in enumerate(top.items())]
    need(s['archive'] == archive and s['visited_unique'] == len(seen), 'Final archive/unique count differs')
    need(s['accept_events'] == changes and s['accepted_changes'] == len(changes), 'Accepted events differ')
    need(s['sweep_events'] == events, 'Sweep events differ')
    full = sum(event['complete'] for event in events)
    partial = len(events) - full
    stable = any(event['convergence_observed'] for event in events)
    need(s['full_sweeps'] == full and s['partial_sweeps'] == partial and
         s['convergence_observed'] is stable, 'Sweep/convergence counters differ')
    need(partial <= 1 and (not partial or not events[-1]['complete']), 'Partial sweep is not terminal')
    for field in ('seconds', 'setup_seconds', 'score_seconds', 'soft_excess_seconds'):
        need(math.isfinite(s[field]) and s[field] >= 0, 'Invalid duration')
    need(s['setup_seconds'] + s['score_seconds'] <= s['seconds'] and
         s['seconds'] <= run['process_seconds'], 'Durations are inconsistent')
    need(s['soft_excess_seconds'] == max(0, s['seconds'] - profile['soft_seconds']), 'Soft excess differs')
    need(s['time_limit_reached'] is (s['seconds'] >= profile['soft_seconds']), 'Time-limit flag differs')
    at_cap = count == profile['max_calls']
    need(s['call_limit_reached'] is at_cap, 'Call-limit flag differs')
    stop = s['stop_reason']
    need(stop in ('call_limit', 'time_limit', 'converged', 'sweep_limit'), 'Unknown stop reason')
    if at_cap or stop == 'call_limit':
        need(at_cap and stop == 'call_limit', 'Call-limit priority differs')
    elif stop == 'time_limit':
        need(s['time_limit_reached'], 'Time stop without time reached')
    elif stop == 'converged':
        need(stable, 'Convergence stop without stable sweep')
    else:
        need(full == profile['max_sweeps'] and not stable, 'Sweep-limit stop differs')
    deadline(manifest)
    return dict(profile_id=profile['profile_id'], category=profile['category'], status='passed',
                rows_checked=count, literal_backend_markers=marks, distinct_keys=len(seen),
                full_sweeps=full, partial_sweeps=partial, accepted_changes=len(changes),
                convergence_observed=stable, stop_reason=stop, hashes=hashes,
                numeric_samples=samples, new_IDP=0, new_solver_runs=0, truth_read=False)


def main():
    output, attempt = REVIEW / 'records_independent.json', REVIEW / 'records_independent_attempt.json'
    need(not output.exists() and not attempt.exists(), 'No replacement or repeat audit attempt')
    source_hash = digest(Path(__file__))
    started = time.time()
    began = time.monotonic()
    fresh_json(attempt, dict(status='started', source_sha256=source_hash, started_at_unix=started,
                             truth_read=False, new_IDP=0, new_solver_runs=0))
    results, mh, ph = [], None, None
    try:
        mp, pp = HERE / 'manifest.json', HERE / 'plan.json'
        m, plan = load(mp), load(pp)
        m['_record_audit_deadline'] = began + 120
        mh, ph = digest(mp), digest(pp)
        need(m['status'] == 'completed' and m['protected_unchanged'] is True, 'Execution not completed/frozen')
        need(m['plan_sha256'] == ph, 'Manifest plan hash differs')
        relative_source = str(Path(__file__).resolve().relative_to(ROOT))
        need(plan['resources'][relative_source] == source_hash, 'Auditor source not sealed by plan')
        gate = load(ROOT / 'work/phase18_root/audit_approval.json')
        need(gate['root_approved'] is True and gate['independent_approved'] is True and
             gate['plan_sha256'] == ph and gate['resources'] == plan['resources'], 'Pre-truth gate differs')
        deadline(m)
        profiles, runs = m['profiles'], m['runs']
        need(len(profiles) == len(runs) == 12, 'Expected exactly twelve profiles and runs')
        need(len({p['profile_id'] for p in profiles}) == 12, 'Duplicate profile identity')
        cases = {c['case_id'] for c in m['cases']}
        need(len(cases) == len(m['cases']) == 4, 'Expected four distinct cases')
        planned_cases = {c['case_id']: c for c in plan['cases']}
        need(cases == set(planned_cases), 'Manifest cases differ from prospective plan')
        main_profiles = [p for p in profiles if p['category'] == 'main']
        controls = [p for p in profiles if p['category'] == 'positive_control']
        need(len(main_profiles) == 8 and len(controls) == 4, 'Category denominators differ')
        need(profiles == main_profiles + controls, 'Positive controls precede a main route')
        for category, names, limit_field, privileged in (
                ('main', {'random1', 'random2'}, 'main_limits', False),
                ('positive_control', {'h2'}, 'positive_limits', True)):
            for cid in cases:
                ps = [p for p in profiles if p['category'] == category and p['case_id'] == cid]
                need(len(ps) == len(names) and {p['start_name'] for p in ps} == names, 'Case/profile layout differs')
                for p in ps:
                    need(p['privileged'] is privileged and p['policy'] == 'B', 'Category privilege/policy differs')
                    case = planned_cases[cid]
                    expected_seed = case['start_seeds'][int(p['start_name'][-1]) - 1] if category == 'main' else None
                    need(p['start_seed'] == expected_seed, 'Start stream differs from prospective plan')
                    need(p['model_path'] == f'work/phase5_language/{case["language_model"]}/model.bin',
                         'Profile uses an unexpected model')
                    for field, expected in plan[limit_field].items():
                        need(p[field] == expected, 'Profile budget differs from prospective plan')
        move_path = HERE / 'moves.json'
        need(digest(move_path) == plan['resources'][str(move_path.relative_to(ROOT))], 'Moves hash differs')
        doc = load(move_path)
        moves = doc['moves']
        need(doc['width'] == 25 and len(moves) == 16649, 'Unexpected source catalogue')
        need(len({tuple(v['p']) for v in moves}) == len(moves), 'Duplicate source permutations')
        for i, v in enumerate(moves, 1):
            need(v['index'] == i and sorted(v['p']) == list(range(25)), 'Invalid indexed movement')
        for c in m['cases']:
            need(c['language_model'] == planned_cases[c['case_id']]['language_model'], 'Case model differs')
            need(len(c['ciphertext_files']) == 2, 'Expected two ciphertext files')
            for item in c['ciphertext_files']:
                need(digest(safe(item['path'])) == item['sha256'], 'Ciphertext hash differs')
        for p, r in zip(profiles, runs):
            case = next(c for c in m['cases'] if c['case_id'] == p['case_id'])
            expected_command = [str(HERE / 'trajectory'), str(ROOT / p['model_path']),
                                *[str(ROOT / item['path']) for item in case['ciphertext_files']],
                                str(ROOT / p['start_path']), '20', '25', 'B', str(p['max_calls']),
                                str(p['max_sweeps']), str(p['soft_seconds']), str(ROOT / p['csv_path']),
                                str(ROOT / p['summary_path'])]
            need(r['command'] == expected_command and
                 Path(r['cwd']).resolve() == (HERE / 'solver_workspace').resolve(), 'Solver input command/cwd differs')
            results.append(replay(p, r, moves, m))
        main_calls = sum(r['rows_checked'] for r in results if r['category'] == 'main')
        positive_calls = sum(r['rows_checked'] for r in results if r['category'] == 'positive_control')
        need(main_calls == m['main_exact_calls'] <= plan['ceilings']['main_IDP'] and
             positive_calls == m['positive_exact_calls'] <= plan['ceilings']['positive_IDP'], 'Aggregate costs differ')
        need(digest(mp) == mh and digest(pp) == ph and digest(Path(__file__)) == source_hash,
             'Manifest, plan or auditor changed during replay')
        deadline(m)
        fresh_json(output, dict(status='passed', manifest_sha256=mh, plan_sha256=ph,
                                source_sha256=source_hash, profiles=results, main_calls=main_calls,
                                positive_calls=positive_calls, started_at_unix=started,
                                ended_at_unix=time.time(), audit_limit_seconds=120,
                                audit_seconds=time.monotonic() - began,
                                truth_read=False, target_compared=False,
                                new_IDP=0, new_solver_runs=0, rng_draws=0))
        print(json.dumps(dict(status='passed', profiles=12, rows_checked=main_calls + positive_calls, new_IDP=0)))
    except BaseException as exc:
        fresh_json(REVIEW / 'records_independent_failure.json',
                   dict(status='failed_no_retry', source_sha256=source_hash, error=repr(exc),
                        manifest_sha256=mh, plan_sha256=ph,
                        completed_profiles=len(results), ended_at_unix=time.time(),
                        truth_read=False, new_IDP=0, new_solver_runs=0))
        raise


if __name__ == '__main__':
    main()

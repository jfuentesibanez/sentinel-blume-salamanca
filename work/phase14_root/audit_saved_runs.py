"""Independently audit phase14 logs without opening planted truth or running a solver."""
from pathlib import Path
import ast
import hashlib
import json
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
PHASE = ROOT / 'work/phase14_crypto'

def inverse(key):
    return [key.index(i) for i in range(len(key))]

def distance(left, right):
    assert len(left) == len(right)
    return sum(a != b for a, b in zip(left, right))

def main():
    tree = ast.parse((ROOT/'work/phase11_crypto/evaluate_external.py').read_text())
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                 and n.name in {'dec', 'independent_idp'}]
    assert {n.name for n in functions} == {'dec', 'independent_idp'}
    scope = {'np': np}
    exec(compile(ast.Module(body=functions, type_ignores=[]), 'pure_idp', 'exec'), scope)
    score_idp = scope['independent_idp']
    rows = [json.loads(s) for s in (PHASE/'search_outputs.jsonl').read_text().splitlines()]
    assert len(rows) == 32
    tables = {}; ciphertexts = {}; cached = {}; identities = set()
    checks = {'rows': 0, 'archive_scores': 0, 'offers': 0, 'parent_choices': 0,
              'climbs': 0, 'perturbations': 0, 'archive_events': 0,
              'pre_checkpoint_equalities': 0, 'common_checkpoint_pools': 0}
    max_error = 0.0

    def score(row, numeric, recorded):
        nonlocal max_error
        cid = row['case_id']; name = row['language_model']
        if name not in tables:
            tables[name] = np.frombuffer((ROOT/'work/phase5_language'/name/'model.bin').read_bytes(),
                                        dtype='<f4', count=676).astype(np.float64)
        if cid not in ciphertexts:
            ciphertexts[cid] = [(PHASE/'ciphertexts'/f'{cid}_T{i}.txt').read_text().strip().lower()
                               for i in (1, 2)]
        cache_key = (cid, tuple(numeric))
        if cache_key not in cached:
            cached[cache_key] = score_idp(ciphertexts[cid], inverse(numeric), row['w1'], tables[name])
        error = abs(cached[cache_key] - recorded)
        max_error = max(max_error, error)
        assert error < 1e-8, (cid, numeric, error)

    for row in rows:
        identity = (row['case_id'], row['round'], row['local_proposal_cap'], row['checkpoint_merge'])
        assert identity not in identities
        identities.add(identity)
        assert row['method'] == 'checkpoint_population'
        assert (row['w1'], row['w2'], row['lengths']) == (20, 25, [615, 160])
        assert row['local_proposal_cap'] in (5000, 33298)
        assert row['periodic_refreshes'] == 0 and row['checkpoint_starts'] <= 1
        assert row['checkpoint_at'] == 50000 and row['target_objective_calls'] == 100000
        assert 0 <= row['objective_calls'] <= 100000 and row['seconds_limit'] == 30
        assert row['objective_calls'] == sum(row[k] for k in
            ('random_pool_calls', 'left_to_right_swap_calls', 'hill_climb_calls', 'perturbation_calls'))
        climbs = [c for c in row['operation_traces'] if c['kind'] == 'hill_climb']
        assert row['objective_calls'] == sum(p['calls'] for p in row['preparations']) + sum(
            c['calls'] for c in climbs) + row['perturbation_calls']
        assert not any(k.startswith(('true_', 'truth_')) for k in row)
        if 'evaluations' in row['cut_cause']:
            assert row['objective_calls'] == 100000

        for a in row['archive']:
            assert sorted(a['k2']) == list(range(25))
            score(row, inverse(a['k2']), a['idp']); checks['archive_scores'] += 1
        assert len({tuple(a['k2']) for a in row['archive']}) == len(row['archive']) <= 5

        offers = {e['event_number']: e for e in row['offer_metadata']}
        assert len(offers) == len(row['population_events'])
        assert set(offers) == set(range(1, len(offers)+1))
        state = []; next_id = 1
        actions = sorted([(e['sequence'], 'offer', e) for e in row['population_events']]
                         + [(p['sequence'], 'parent', p) for p in row['parent_choices']])
        assert [a[0] for a in actions] == list(range(1, len(actions)+1))
        for _, kind, action in actions:
            assert action['objective_calls'] < 100000
            if kind == 'parent':
                selected = min(state, key=lambda m: (m['uses'], -m['idp'], m['numeric']))
                assert action['selected_id'] == selected['id']
                assert action['uses_before'] == selected['uses']
                state = [dict(m) for m in state]
                selected = next(m for m in state if m['id'] == action['selected_id'])
                selected['uses'] += 1
                assert action['uses_after'] == selected['uses']
                assert action['population_after_use'] == state
                checks['parent_choices'] += 1
                continue
            exact = offers[action['number']]
            assert exact['sequence'] == action['sequence'] and exact['before'] == state
            numeric = exact['candidate_numeric']; value = exact['candidate_idp']
            assert sorted(numeric) == list(range(25)); score(row, numeric, value)
            distances = [distance(numeric, m['numeric']) for m in state]
            neighbors = [m for m, d in zip(state, distances) if d < 10]
            assert distances == action['distances_before']
            assert [m['id'] for m in neighbors] == action['close_neighbor_ids']
            new = None
            if neighbors:
                if all(value > m['idp'] + 1e-12 for m in neighbors):
                    decision = 'replace_close_neighbors'
                    state = [m for m in state if m['id'] not in action['close_neighbor_ids']]
                    new = {'id': next_id, 'numeric': numeric, 'idp': value,
                           'uses': max(m['uses'] for m in neighbors)}
                else:
                    decision = 'reject_close_neighbor_score'
            elif len(state) < 5:
                decision = 'append_diverse'
                new = {'id': next_id, 'numeric': numeric, 'idp': value, 'uses': 0}
            else:
                worst = min(state, key=lambda m: (m['idp'], [-x for x in m['numeric']]))
                if value > worst['idp'] + 1e-12:
                    decision = 'replace_worst_diverse'
                    assert action['replaced_worst_id'] == worst['id']
                    state = [m for m in state if m['id'] != worst['id']]
                    new = {'id': next_id, 'numeric': numeric, 'idp': value, 'uses': 0}
                else:
                    decision = 'reject_worst_score'
            if new:
                next_id += 1; state.append(new)
            state.sort(key=lambda m: (-m['idp'], m['numeric']))
            assert action['decision'] == decision and exact['after'] == state
            assert len(state) <= 5
            assert all(distance(a['numeric'], b['numeric']) >= 10
                       for i, a in enumerate(state) for b in state[i+1:])
            checks['offers'] += 1
        assert row['final_population'] == state
        assert not any(e['origin'] == 'checkpoint_prepared_survivor'
                       for e in row['population_events']) or row['checkpoint_merge']

        for c in climbs:
            assert c['calls_after'] - c['calls_before'] == c['calls'] <= row['local_proposal_cap']
            if c['stop_reason'] == 'cap_local':
                assert c['calls'] == row['local_proposal_cap']
            if c['stop_reason'] == 'checkpoint':
                assert c['calls_after'] == 50000 and not c['global_cut']
            if c['convergence_observed']:
                assert c['complete_sweeps'] >= 1 and c['last_sweep_proposals'] == 16649
                assert not c['last_sweep_improved']
            score(row, c['initial_numeric'], c['initial_idp'])
            score(row, c['final_numeric'], c['final_idp']); checks['climbs'] += 1
        assert sum(c['calls'] for c in climbs) == row['hill_climb_calls']
        for k in row['perturbation_traces']:
            positions = k['positions']; changed = k['base_numeric'][:]
            assert len(set(positions)) == len(positions) == 10
            for i in range(0, 10, 2):
                changed[positions[i]], changed[positions[i+1]] = changed[positions[i+1]], changed[positions[i]]
            assert changed == k['perturbed_numeric'] and distance(changed, k['base_numeric']) == 10
            if k['scored']:
                score(row, changed, k['idp'])
            checks['perturbations'] += 1
        assert sum(k['scored'] for k in row['perturbation_traces']) == row['perturbation_calls']

        previous = []; archive_keys = set()
        for e in row['archive_events']:
            assert e['k2'] == inverse(e['numeric'])
            score(row, e['numeric'], e['idp'])
            entries = e['archive_after']
            assert entries == sorted(entries, key=lambda a: (-a['idp'], a['numeric']))
            assert len({tuple(a['numeric']) for a in entries}) == len(entries) <= 5
            assert e['numeric'] not in [a['numeric'] for a in previous]
            expected = previous + [{'numeric': e['numeric'], 'idp': e['idp']}]
            expected.sort(key=lambda a: (-a['idp'], a['numeric']))
            assert expected[:5] == entries
            assert entries[e['entered_rank']-1]['numeric'] == e['numeric']
            previous = entries; archive_keys.add(tuple(e['numeric']))
            checks['archive_events'] += 1
        assert [inverse(a['numeric']) for a in previous] == [a['k2'] for a in row['archive']]
        checks['rows'] += 1

    groups = {}
    for row in rows:
        groups.setdefault((row['case_id'], row['round']), []).append(row)
    assert len(groups) == 8
    for group in groups.values():
        assert len(group) == 4
        pools = []
        for cap in (5000, 33298):
            pair = [r for r in group if r['local_proposal_cap'] == cap]
            assert len(pair) == 2 and {r['checkpoint_merge'] for r in pair} == {True, False}
            if all(r['pre_checkpoint'] is not None for r in pair):
                assert pair[0]['pre_checkpoint'] == pair[1]['pre_checkpoint']
                checks['pre_checkpoint_equalities'] += 1
        for row in group:
            for p in row['preparations']:
                assert p['calls_after'] - p['calls_before'] == p['calls']
                assert p['calls'] == p['random_pool_calls'] + p['swap_calls']
                if p['completed']:
                    assert p['calls'] == 7000 and len(p['random_keys']) == 1000 and len(p['survivors']) == 20
                if p['stage'] == 'checkpoint_pool' and p['completed']:
                    pools.append((p['random_keys'], p['survivors'], p['rng_before'], p['rng_after']))
            if row['checkpoint_completed']:
                assert row['checkpoint_trace']['main_rng_unchanged']
        if len(pools) == 4:
            assert all(p == pools[0] for p in pools)
            checks['common_checkpoint_pools'] += 1
    result = {'passed': True, 'scope': 'independent saved-log replay and numerical scores; no truth or solver invocation',
              'checks': checks, 'distinct_scores_recomputed': len(cached),
              'maximum_absolute_score_error': max_error,
              'score_tolerance': 1e-8, 'new_searches': 0,
              'limitations': ['Archive completeness over unlogged rejected proposals rests on source audit and invariant controls.',
                              'Numerical score tolerance is larger than admission epsilon; decision replay uses exact17digit solver metadata.']}
    (ROOT/'work/phase14_root/post_run_audit.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()

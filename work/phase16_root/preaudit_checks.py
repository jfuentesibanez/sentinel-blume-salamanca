"""Pre-truth design/resource/integer-bound checks. Zero IDP and key generation."""
from pathlib import Path
import hashlib
import json
import math
import struct
import ast

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
PHASE = ROOT / 'work/phase16_crypto'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return json.loads(path.read_text())


def main():
    assert not any((PHASE / name).exists() for name in
                   ('truth.jsonl', 'sealed_design.json', 'manifest.json', 'ciphertexts', 'starts'))
    plan = load(PHASE / 'plan20.json')
    assert plan['status'] == 'draft_for_double_audit_no_truth_no_trajectories'
    assert plan['widths'] == [20, 25] and plan['lengths'] == [615, 160] and plan['convention'] == 0
    assert plan['main_calls_max'] == 16 * (1 + 3 * 16649) == 799168
    assert plan['positive_calls_max'] == 4 * (1 + 16649) == 66600
    assert plan['combined_trajectory_calls_max'] == 865768
    assert plan['post_run_audit']['exact_reference_calls_max'] == 40
    assert plan['soft_seconds'] == 30 and plan['hard_process_seconds'] == 40
    assert plan['truth_evaluations_extra'] == 0 and plan['retries'] == 0 and plan['cache'] is False
    assert len(plan['cases']) == 4 and len(plan['profiles']) == 20
    expected_cases = [('de_fold', 20262401), ('de_fold', 20262402),
                      ('fr_fold', 20262403), ('fr_fold', 20262404)]
    assert [(c['language_model'], c['plant_seed']) for c in plan['cases']] == expected_cases
    for category, count, cap, sweeps in [('main', 16, 49948, 3), ('positive_control', 4, 16650, 1)]:
        profiles = [p for p in plan['profiles'] if p['category'] == category]
        assert len(profiles) == count
        assert all(p['max_calls'] == cap and p['max_sweeps'] == sweeps for p in profiles)
    assert all(p['category'] == 'main' for p in plan['profiles'][:16])
    assert all(p['category'] == 'positive_control' for p in plan['profiles'][16:])
    for case in plan['cases']:
        profiles = [p for p in plan['profiles'] if p['case_id'] == case['case_id']]
        assert len(profiles) == 5
        for perturbation in ['h4', 'h8']:
            pair = [p for p in profiles if p['perturbation'] == perturbation]
            assert {p['policy'] for p in pair} == {'A', 'B'}
            assert pair[0]['start_path'] == pair[1]['start_path']
        for p in profiles:
            assert len(p['command']) == 13
            assert p['command'][5:10] == ['20', '25', p['policy'], str(p['max_calls']), str(p['max_sweeps'])]
            assert p['command'][10] == '30'
    for relative, expected in plan['resources'].items():
        assert sha(PHASE / relative) == expected, relative
    baseline = load(HERE / 'frozen_before.json')
    assert baseline['count'] == len(baseline['hashes']) == 2793
    assert plan['baseline_sha256'] == sha(HERE / 'frozen_before.json')
    assert plan['protected_before'] == baseline['hashes']
    for relative, expected in baseline['hashes'].items():
        assert sha(ROOT / relative) == expected, relative
    old = ROOT / 'work/phase15_crypto/static_landscape.cpp'
    assert sha(old) == '4552eafdc98cc4e3d075ed8b092945510d4eb1ff67a31dfa1e30e8662f85ed4a'
    body = old.read_text()
    sections = [body[body.index('struct Dyadic '):body.index('struct Legacy ')],
                body[body.index('struct Exact '):body.index('Legacy legacy_trace')],
                body[body.index('std::vector<int64_t> exact_matrix'):body.index('void validate(')]]
    expected_header = '#pragma once\n// Exact phase15 fragments, unchanged. See build_record.json and attribution.\n' + ''.join(sections)
    assert (PHASE / 'exact_scorer.h').read_text() == expected_header
    build, controls = load(PHASE / 'build_record.json'), load(PHASE / 'control_results.json')
    assert build['exact_fragments_sha256'] == [hashlib.sha256(s.encode()).hexdigest() for s in sections]
    assert sha(PHASE / 'trajectory.cpp') == build['source_sha256'] == controls['source_sha256']
    assert sha(PHASE / 'trajectory') == build['binary_sha256'] == controls['binary_sha256']
    assert controls['status'] == 'passed' and controls['policy_fixtures'] >= 11
    assert controls['actual_exact_IDP_calls_all_attempts'] == controls['actual_legacy_IDP_calls_all_attempts'] == 0
    assert controls['truth_generated'] is False and controls['main_runs'] == 0
    attempts = [load(p) for p in sorted((PHASE / 'control_attempts').glob('attempt*.json'))]
    assert all(a['actual_exact_IDP_calls'] == a['actual_legacy_IDP_calls'] == 0 for a in attempts)
    assert sha(PHASE / 'generate_keys.cpp') == sha(ROOT / 'work/phase15_crypto/generate_keys.cpp')
    assert sha(PHASE / 'moves.json') == sha(ROOT / 'work/phase15_crypto/moves.json')
    moves = load(PHASE / 'moves.json')['moves']
    assert len(moves) == 16649
    pair_indices = []
    for a, b in [(0, 1), (2, 3), (4, 5), (6, 7)]:
        p = list(range(25)); p[a], p[b] = p[b], p[a]
        pair_indices.append(next(m['index'] for m in moves if m['p'] == p))
    prior = load(PHASE / 'seed_audit.json')
    assert prior['status'] == 'passed_no_prior_use' and not prior['structured_prior_seed_uses']
    old_models = {m['path']: m['sha256'] for m in load(ROOT / 'work/phase15_crypto/plan12.json')['models_and_holdouts']}
    model_checks = []
    for item in plan['models_and_holdouts']:
        assert old_models[item['path']] == item['sha256'] == sha(ROOT / item['path'])
        if not item['path'].endswith('model.bin'):
            continue
        values = struct.unpack('<676f', (ROOT / item['path']).read_bytes()[:2704])
        assert all(math.isfinite(v) for v in values)
        scale = math.lcm(*(v.as_integer_ratio()[1] for v in values))
        table = [v.as_integer_ratio()[0] * (scale // v.as_integer_ratio()[1]) for v in values]
        bound = max(max(abs(n) for n in table), 7 * scale) * 760
        assert max(bound, 1000000 * scale * 2) < 2**63
        assert (2 * bound) * 10**12 < 2**127
        model_checks.append({'path': item['path'], 'scale': scale, 'absolute_numerator_bound': bound,
                             'minimum_exact_score_step': f'1/{760 * scale}'})
    for path in [HERE / 'post_run_audit.py', HERE / 'run_post_audit.py']:
        ast.parse(path.read_text())
    result = {'status': 'passed_before_truth', 'plan_sha256': sha(PHASE / 'plan20.json'),
        'protected_files': 2793, 'resources_checked': len(plan['resources']),
        'exact_fragments_byte_identical': True, 'native_pair_move_indices': pair_indices,
        'control_attempts': len(attempts), 'new_IDP_calls': 0, 'new_keys_generated': 0,
        'model_bound_checks': model_checks,
        'root_post_audit_source_sha256': sha(HERE / 'post_run_audit.py'),
        'root_post_audit_wrapper_sha256': sha(HERE / 'run_post_audit.py')}
    (HERE / 'preaudit_checks.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()

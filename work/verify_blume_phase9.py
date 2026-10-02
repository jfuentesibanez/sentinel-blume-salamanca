"""Root verification of phase9, without running or importing its solver/evaluator."""
from collections import Counter
from pathlib import Path
import hashlib
import json
import numpy as np
from phase9_idp_diagnostic import idp, decrypt

ROOT = Path(__file__).resolve().parent.parent
HERE = ROOT / 'work/phase9_crypto'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def load(path):
    return json.loads(path.read_text())

def lines(path):
    return [json.loads(l) for l in path.read_text().splitlines()]

def encrypt(text, key):
    return ''.join(text[c::len(key)] for c in key)

def inverse(key):
    result = [0] * len(key)
    for position, value in enumerate(key):
        result[value] = position
    return result

def close(a, b):
    assert abs(a-b) < 1e-7, (a, b)

manifest = load(HERE/'manifest.json')
assert manifest['completed'] and manifest['protected_unchanged']
assert manifest['predefined_seeds'] == [20261901, 20261902]
assert manifest['keys_disclosed'] is False and manifest['widths_disclosed']
assert manifest['protected_before'] == manifest['protected_after']
assert len(manifest['protected_before']) == 222
for record in manifest['protected_before']:
    assert sha(ROOT/record['path']) == record['sha256']
for filename, field in [('k2_search', 'solver_sha256'), ('k2_search.cpp', 'solver_source_sha256'),
                        ('run_comparison.py', 'runner_sha256'), ('search_outputs.jsonl', 'log_sha256'),
                        ('truth.jsonl', 'truth_sha256')]:
    assert sha(HERE/filename) == manifest[field]
assert len(manifest['cases']) == 8 and len(manifest['runs']) == 32
assert all(run['started_at_unix'] >= manifest['cases_sealed_at_unix'] and run['status'] == 'completed'
           for run in manifest['runs'])
truths = {t['case_id']:t for t in lines(HERE/'truth.jsonl')}
rows = lines(HERE/'search_outputs.jsonl')
evaluation = {(r['case_id'], r['method'], r['round']):r
              for r in lines(HERE/'external_evaluation.jsonl')}
assert len(rows) == len(evaluation) == 32 and len(truths) == 8
scores_checked = kicks_checked = cipher_checks = 0
totals = {method:{'archive_hits_in_rounds':0, 'objective_calls':0, 'seconds':0, 'cases':set()}
          for method in ('restart','ils')}
no_hit_better_truth = 0
memo = {}
for case in manifest['cases']:
    identifier = case['case_id']; truth = truths[identifier]
    model_dir = ROOT/'work/phase5_language'/case['language_model']
    provenance = load(model_dir/'provenance.json')
    assert sha(model_dir/'model.bin') == provenance['model_sha256']
    assert sha(model_dir/'holdout.txt') == provenance['holdout_sha256']
    body = ''.join(c.lower() for c in (model_dir/'holdout.txt').read_text() if c.isascii() and c.isalpha())
    p = truth['sample_position']; plaintexts = [body[p:p+615], body[p+615:p+775]]
    ciphertexts = []
    for entry, plain in zip(case['ciphertext_files'], plaintexts):
        path = ROOT/entry['path']; assert sha(path) == entry['sha256']
        cipher = path.read_text().strip().lower()
        assert cipher == encrypt(encrypt(plain, truth['true_k1']), truth['true_k2'])
        ciphertexts.append(np.array([ord(c)-97 for c in cipher], dtype=np.int64)); cipher_checks += 1
    bigrams = np.fromfile(model_dir/'model.bin', dtype='<f4', count=676).astype(np.float64)
    def measured(key):
        tag = (identifier, tuple(key))
        if tag not in memo:
            memo[tag] = idp(ciphertexts, key, case['w1'], bigrams)
        return memo[tag]
    true_score = measured(truth['true_k2'])
    case_rows = [row for row in rows if row['case_id'] == identifier]
    assert {(r['method'],r['round']) for r in case_rows} == {('restart',0),('ils',0),('restart',1),('ils',1)}
    assert len(case_rows) == 4
    for planned in case['commands']:
        command = planned['command']
        assert len(command) == 11 and command[1] == planned['method']
        assert command[5:8] == [str(case['w1']),str(case['w2']),str(planned['search_seed'])]
        assert command[8:] == ['100000','30',str(planned['round'])]
    for row in case_rows:
        key = (identifier,row['method'],row['round']); ext = evaluation[key]
        assert row['mode'] == 'ciphertext_only_k2' and row['messages_scored'] == 2
        assert row['lengths'] == [615,160] and row['convention'] == 0
        assert not any(k.startswith(('true_', 'truth_')) for k in row)
        assert row['objective_calls'] == row['target_objective_calls'] == 100000
        assert row['seconds'] < row['seconds_limit'] == 30 and row['cut_cause'] == 'evaluations'
        assert 0 <= row['setup_seconds'] <= row['seconds']
        assert row['objective_calls'] == sum(row[k] for k in ('random_pool_calls','left_to_right_swap_calls','hill_climb_calls','perturbation_calls'))
        traces = row['operation_traces']; kicks = row['perturbation_traces']
        assert sum(t['calls'] for t in traces) + row['perturbation_calls'] == row['objective_calls']
        assert len(kicks) == row['perturbations_attempted']
        assert sum(k['scored'] for k in kicks) == row['perturbations_scored'] == row['perturbation_calls']
        assert len([t for t in traces if t['kind']=='initialization']) == row['restart_starts']
        assert sum(t['completed'] for t in traces if t['kind']=='initialization') == row['restart_completions']
        assert len([t for t in traces if t['kind']=='hill_climb']) == row['climb_starts']
        assert sum(t['completed'] for t in traces if t['kind']=='hill_climb') == row['climb_completions']
        assert sum(t['calls'] for t in traces if t['kind']=='hill_climb') == row['hill_climb_calls']
        for trace in traces:
            if trace['kind'] == 'initialization' and trace['completed']:
                assert trace['calls'] == 1000 + 20*case['w2']*(case['w2']-1)//2
        for kick in kicks:
            positions = kick['positions']; before = kick['base_numeric']; after = kick['perturbed_numeric']
            assert len(positions) == len(set(positions)) == 6
            expected = before.copy()
            for a,b in zip(positions[::2], positions[1::2]):
                expected[a], expected[b] = expected[b], expected[a]
            assert expected == after and sorted(after) == list(range(case['w2']))
            assert sum(a!=b for a,b in zip(before,after)) == kick['hamming_distance'] == 6
            if kick['scored']:
                close(kick['idp'], measured(inverse(after)))
            kicks_checked += 1
        archive = row['archive']
        assert len(archive) == 5 and len({tuple(a['k2']) for a in archive}) == 5
        assert [a['rank'] for a in archive] == [1,2,3,4,5]
        assert [a['idp'] for a in archive] == sorted((a['idp'] for a in archive), reverse=True)
        for candidate in archive:
            assert sorted(candidate['k2']) == list(range(case['w2']))
            close(candidate['idp'], measured(candidate['k2'])); scores_checked += 1
        true_ranks = [a['rank'] for a in archive if a['k2'] == truth['true_k2']]
        assert ext['true_k2_ranks'] == true_ranks
        assert ext['true_k2_in_archive'] == bool(true_ranks)
        close(ext['true_k2_idp_external'], true_score)
        close(ext['best_archive_idp'], archive[0]['idp'])
        better = true_score > max(a['idp'] for a in archive) + 1e-7
        assert ext['true_idp_greater_than_all'] == better
        if not true_ranks:
            assert better; no_hit_better_truth += 1
        total = totals[row['method']]
        total['archive_hits_in_rounds'] += int(bool(true_ranks))
        total['objective_calls'] += row['objective_calls']; total['seconds'] += row['seconds']
        if true_ranks:
            total['cases'].add(identifier)
assert totals['restart']['archive_hits_in_rounds'] == 3 and totals['ils']['archive_hits_in_rounds'] == 4
assert totals['restart']['cases'] == totals['ils']['cases'] and len(totals['restart']['cases']) == 2
assert no_hit_better_truth == 25
summary = load(HERE/'summary.json')
for method, total in totals.items():
    assert total['objective_calls'] == summary['total_calls_by_method'][method] == 1600000
    close(total['seconds'], summary['total_seconds_by_method'][method])
    total['cases'] = sorted(total['cases'])

result = {'passed':True, 'scope':'Independent saved-result audit; no search rerun and no K1 test',
          'pairs':8,'rows':32,'ciphertexts_reconstructed':cipher_checks,
          'archive_scores_checked':scores_checked,'perturbations_checked':kicks_checked,
          'true_scores_higher_in_all_rows_without_key':no_hit_better_truth,
          'totals':totals,'protected_previous_crypto_files':222,
          'script_sha256':sha(Path(__file__)),
          'limits':['K2-only trial, known widths, same literary corpora, new seeds.',
                    'Equal IDP call counts do not establish equal CPU cost.',
                    'Only saved candidates and perturbations were rescored; all proposals are not logged.',
                    'No historical plaintext, key or language finding.']}
(ROOT/'work/phase9_root_verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(result,ensure_ascii=False,indent=2))

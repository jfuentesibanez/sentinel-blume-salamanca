"""Root audit of saved phase-8 evidence. Does not import or run the solver."""
from collections import Counter
from pathlib import Path
import hashlib
import json
import math
import struct

ROOT = Path(__file__).resolve().parent.parent
CRYPTO = ROOT / 'work/phase8_crypto'
HISTORY = ROOT / 'work/history/phase8-ptt'

def read_json(path):
    return json.loads(path.read_text())

def read_lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()]

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def permutation(length, key):
    """Map ciphertext positions to plaintext positions, without column strings."""
    assert sorted(key) == list(range(len(key)))
    return [position for column in key for position in range(column, length, len(key))]

def encrypt(text, key):
    return ''.join(text[i] for i in permutation(len(text), key))

def decrypt(text, key):
    output = [''] * len(text)
    for cipher_position, plain_position in enumerate(permutation(len(text), key)):
        output[plain_position] = text[cipher_position]
    return ''.join(output)

def double_decrypt(ciphertexts, k1, k2):
    return [decrypt(decrypt(text, k2), k1) for text in ciphertexts]

def score(messages, trigram):
    terms = []
    for message in messages:
        letters = [ord(c) - ord('a') for c in message]
        terms.extend(trigram[a * 676 + b * 26 + c]
                     for a, b, c in zip(letters, letters[1:], letters[2:]))
    return math.fsum(terms) / len(terms)

def close(a, b):
    assert abs(a - b) < 1e-7, (a, b)

manifest = read_json(CRYPTO / 'comparison_manifest.json')
assert manifest['completed'] and not manifest['keys_disclosed']
assert manifest['convention'] == 0 and manifest['key_widths_disclosed']
assert manifest['protected_before'] == manifest['protected_after']
assert len(manifest['protected_before']) == 187
for entry in manifest['protected_before']:
    assert digest(ROOT / entry['path']) == entry['sha256']
for filename, expected in manifest['source_hashes'].items():
    assert digest(CRYPTO / filename) == expected
assert digest(CRYPTO / 'planted_truth.jsonl') == manifest['truth_sha256']
assert digest(CRYPTO / 'solver_outputs.jsonl') == manifest['solver_output_sha256']
assert manifest['cases_sealed_before_solver_at_unix'] <= manifest['ended_at_unix']
assert len(manifest['cases']) == len(manifest['runs']) == 8
assert all(run['status'] == 'completed' and run['rows'] == 2 for run in manifest['runs'])

resource_count = 0
for entry in read_json(CRYPTO / 'RESOURCE_HASHES.json')['files']:
    assert digest(CRYPTO / entry['path']) == entry['sha256']
    resource_count += 1
for filename, expected in read_json(HISTORY / 'resource-hashes.json').items():
    assert digest(ROOT / filename) == expected
    resource_count += 1
history_baseline = read_json(HISTORY / 'phase7-protected-baseline.json')
for filename, expected in history_baseline.items():
    assert digest(ROOT / filename) == expected

tables, holdouts = {}, {}
for name in manifest['models']:
    folder = ROOT / 'work/phase5_language' / name
    provenance = read_json(folder / 'provenance.json')
    assert digest(folder / 'model.bin') == provenance['model_sha256']
    assert digest(folder / 'holdout.txt') == provenance['holdout_sha256']
    raw = (folder / 'model.bin').read_bytes()
    tables[name] = struct.unpack_from('<17576f', raw, 676 * 4)
    holdouts[name] = ''.join(c.lower() for c in (folder / 'holdout.txt').read_text()
                             if c.isascii() and c.isalpha())

truths = {r['case_id']: r for r in read_lines(CRYPTO / 'planted_truth.jsonl')}
rows = read_lines(CRYPTO / 'solver_outputs.jsonl')
assert len(rows) == 16 and len(truths) == 8
external = {(r['case_id'], r['policy']): r
            for r in read_lines(CRYPTO / 'external_evaluation.jsonl')}
assert len(external) == 16
successes, totals, returned_presence = {}, {}, {}
trace_checks, cipher_checks, text_checks = 0, 0, 0
causes = Counter()
for case in manifest['cases']:
    identifier = case['case_id']
    truth = truths[identifier]
    assert len(case['command']) == 13
    assert case['command'][1] == str(ROOT / 'work/phase5_language' / case['language_model'] / 'model.bin')
    assert case['command'][4:7] == [str(case['w1']), str(case['w2']), str(case['search_seed'])]
    assert case['command'][7:] == ['3', '5', '3', '2000000', '300000', '2000000']
    pos = truth['sample_position']
    body = holdouts[case['language_model']]
    originals = [body[pos:pos+615], body[pos+615:pos+775]]
    ciphertexts = []
    for entry, plain in zip(case['ciphertext_files'], originals):
        path = ROOT / entry['path']
        assert digest(path) == entry['sha256']
        cipher = path.read_text().strip().lower()
        assert encrypt(encrypt(plain, truth['true_k1']), truth['true_k2']) == cipher
        ciphertexts.append(cipher)
        cipher_checks += 1
    paired = [r for r in rows if r['case_id'] == identifier]
    assert len(paired) == 2 and {r['policy'] for r in paired} == {'single', 'pool5'}
    assert paired[0]['rounds'] == paired[1]['rounds']
    ranks = [{'round': rd['round'], 'ranks': [item['rank'] for item in rd['pool']
              if item['k2'] == truth['true_k2']]}
             for rd in paired[0]['rounds']]
    ranks = [r for r in ranks if r['ranks']]
    returned_presence[identifier] = bool(ranks)
    for row in paired:
        policy = row['policy']
        assert row['mode'] == 'ciphertext_only_comparison'
        assert row['messages_scored'] == 2 and row['lengths'] == [615, 160]
        assert row['search_seed'] == case['search_seed']
        traces = row['candidate_traces']
        best = max(traces, key=lambda trace: trace['final_q3'])
        assert (row['k1'], row['k2'], row['selected_round'], row['selected_pool_rank']) == (
            best['k1'], best['final_k2'], best['round'], best['pool_rank'])
        close(row['q3'], best['final_q3'])
        shared_cost = shared_time = dependent_cost = initial_scores = 0
        for rd in row['rounds']:
            candidates = rd['pool']
            assert 1 <= len(candidates) <= 5
            assert len({tuple(c['k2']) for c in candidates}) == len(candidates)
            assert [c['rank'] for c in candidates] == list(range(1, len(candidates)+1))
            assert [c['idp'] for c in candidates] == sorted((c['idp'] for c in candidates), reverse=True)
            stage = rd['k2_stage']
            assert stage['evaluations'] == sum(rd[k] for k in ('pool_evaluations', 'swap_evaluations', 'hill_evaluations'))
            assert stage['evaluations'] <= stage['evaluations_limit'] == 300000
            assert stage['seconds_limit'] == 5
            shared_cost += stage['evaluations']; shared_time += stage['seconds']
            selected = [t for t in traces if t['round'] == rd['round']]
            n = 1 if policy == 'single' else len(candidates)
            assert len(selected) == n
            assert [t['pool_rank'] for t in selected] == list(range(1, n+1))
            for kind in ('k1_stage', 'final_k2_stage'):
                assert sum(t[kind]['evaluations_limit'] for t in selected) <= 2000000
                close(sum(t[kind]['seconds_limit'] for t in selected), 3)
            for trace in selected:
                candidate = candidates[trace['pool_rank']-1]
                assert trace['start_k2'] == candidate['k2'] and trace['pool_idp'] == candidate['idp']
                for key_field, score_field in [('start_k2', 'after_k1_q3'), ('final_k2', 'final_q3')]:
                    decoded = double_decrypt(ciphertexts, trace['k1'], trace[key_field])
                    close(score(decoded, tables[row['language_model']]), trace[score_field])
                    trace_checks += 1
                for kind in ('k1_stage', 'final_k2_stage'):
                    stage = trace[kind]
                    assert stage['evaluations'] == stage['feature_evaluations'] + stage['q_evaluations']
                    assert stage['evaluations'] <= stage['evaluations_limit']
                    assert 0 <= stage['setup_seconds'] <= stage['seconds']
                    assert stage['cut'] == (stage['cause'] != 'algorithm_finished')
                    assert stage['cut'] == (stage['cut_phase'] != 'none')
                    if stage['cause'] in ('evaluations', 'evaluations_and_wall_time'):
                        assert stage['evaluations'] == stage['evaluations_limit']
                    if stage['cause'] in ('wall_time', 'evaluations_and_wall_time'):
                        assert stage['seconds'] >= stage['seconds_limit']
                    causes[(policy, kind, stage['cause'])] += 1
                    dependent_cost += stage['evaluations']
                    initial_scores += stage['initial_q_evaluations']
        close(shared_time, row['k2_cache_charged_seconds'])
        assert shared_cost == row['k2_cache_charged_evaluations']
        assert dependent_cost == row['dependent_evaluations']
        assert initial_scores == row['dependent_initial_q_evaluations']
        assert shared_cost + dependent_cost == row['charged_total_evaluations']
        close(shared_time + row['dependent_seconds'], row['charged_total_seconds'])
        decoded = double_decrypt(ciphertexts, row['k1'], row['k2'])
        close(score(decoded, tables[row['language_model']]), row['q3'])
        assert [encrypt(encrypt(t, row['k1']), row['k2']) for t in decoded] == ciphertexts
        text_checks += 2
        exact = decoded == originals
        check = external[(identifier, policy)]
        assert check['exact_both_plaintexts'] == exact
        assert check['exact_k1'] == (row['k1'] == truth['true_k1'])
        assert check['exact_k2'] == (row['k2'] == truth['true_k2'])
        assert check['correct_letters'] == [sum(a == b for a, b in zip(p, q)) for p, q in zip(originals, decoded)]
        assert check['true_k2_in_pool'] == ranks
        close(check['truth_q3'], score(originals, tables[row['language_model']]))
        successes[(identifier, policy)] = exact
        value = totals.setdefault(policy, {'exact': 0, 'charged_seconds': 0, 'recorded_proposals': 0})
        value['exact'] += int(exact)
        value['charged_seconds'] += row['charged_total_seconds']
        value['recorded_proposals'] += row['charged_total_evaluations']

assert totals['single']['exact'] == totals['pool5']['exact'] == 2
assert all(successes[(i, 'single')] == successes[(i, 'pool5')] for i in truths)
failed = [i for i in truths if not successes[(i, 'single')]]
assert len(failed) == 6 and all(not returned_presence[i] for i in failed)
summary = read_json(CRYPTO / 'comparison_summary.json')
for policy, value in totals.items():
    close(value['charged_seconds'], summary['total_charged_seconds_by_policy'][policy])
    assert value['recorded_proposals'] == summary['total_charged_evaluations_by_policy'][policy]

def strip_times(item):
    if isinstance(item, dict):
        return {k: strip_times(v) for k, v in item.items()
                if k not in {'seconds', 'setup_seconds', 'dependent_seconds',
                             'charged_total_seconds', 'k2_cache_charged_seconds'}}
    if isinstance(item, list):
        return [strip_times(v) for v in item]
    return item

repeat1 = read_lines(CRYPTO / 'isolation_check/repeat1.jsonl')
repeat2 = read_lines(CRYPTO / 'isolation_check/repeat2.jsonl')
assert strip_times(repeat1) == strip_times(repeat2)
assert read_json(CRYPTO / 'isolation_check.json')['passed']

record = read_json(HISTORY / 'record-15003-registratur1937.json')
metadata = '\n'.join(c.get('text', '') for c in record['content'])
for term in ('P-00 C_2522_06', '1937', 'Registratur- und Archivdienst', 'Deutsch', 'In den Lesesaal bestellbar'):
    assert term in metadata

result = {
    'passed': True, 'scope': 'Independent reconstruction and accounting from saved phase-8 evidence; no solver rerun',
    'paired_cases': 8, 'rows': 16, 'ciphertexts_reconstructed': cipher_checks,
    'returned_plaintexts_reconstructed': text_checks, 'candidate_score_checks': trace_checks,
    'policy_totals': totals, 'same_two_successes': True,
    'failed_pairs_without_true_k2_in_returned_pools': failed,
    'crypto_protected_files': 187, 'history_protected_files': len(history_baseline),
    'phase8_resources_hashed': resource_count, 'isolation_saved_outputs_identical_without_times': True,
    'history_catalog_metadata_checked': 'P-00 C_2522_06, 1937; contents not read',
    'limits': ['Known widths and one transposition convention; synthetic literary controls only.',
               'Proposal counters omit initial scoring calls; equal maximum caps are not equal actual costs.',
               'Returned pools do not record every visited key; absence means not returned, not never visited.',
               'No historical plaintext, key, language identification or numeric registry-plan interpretation.'],
    'verification_script_sha256': digest(Path(__file__)),
}
(ROOT / 'work/phase8_root_verification.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
print(json.dumps(result, ensure_ascii=False, indent=2))

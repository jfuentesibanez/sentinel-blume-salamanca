"""Read-only numerical check of the recorded phase14 pilot; never runs a solver."""
from pathlib import Path
from collections import Counter, defaultdict
import ast
import hashlib
import json
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
PHASE = ROOT / 'work/phase14_crypto'

def main():
    tree = ast.parse((ROOT/'work/phase11_crypto/evaluate_external.py').read_text())
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name in {'enc', 'dec', 'independent_idp'}]
    assert {node.name for node in functions} == {'enc', 'dec', 'independent_idp'}
    scope = {'np': np}
    exec(compile(ast.Module(body=functions, type_ignores=[]), 'pure_idp', 'exec'), scope)
    enc, idp = scope['enc'], scope['independent_idp']
    rows = [json.loads(line) for line in (PHASE/'search_outputs.jsonl').read_text().splitlines()]
    truth = {r['case_id']: r for r in map(json.loads, (PHASE/'truth.jsonl').read_text().splitlines())}
    evaluation = json.loads((PHASE/'evaluation.json').read_text())
    assert len(rows) == 32 and len(truth) == 4
    tables, texts, counts, paired = {}, {}, Counter(), defaultdict(list)
    checked, max_error = 0, 0.0
    for cid, t in truth.items():
        name = t['language_model']; folder = ROOT/'work/phase5_language'/name
        tables[name] = np.frombuffer((folder/'model.bin').read_bytes(), dtype='<f4', count=676).astype(np.float64)
        body = ''.join(c.lower() for c in (folder/'holdout.txt').read_text() if c.isascii() and c.isalpha())
        pos = t['sample_position']
        plains = [body[pos:pos+615], body[pos+615:pos+775]]
        texts[cid] = [enc(enc(p, t['true_k1']), t['true_k2']) for p in plains]
        for i, text in enumerate(texts[cid], 1):
            assert (PHASE/'ciphertexts'/f'{cid}_T{i}.txt').read_text().strip().lower() == text
    for row in rows:
        cid = row['case_id']; t = truth[cid]
        assert row['objective_calls'] <= 100000
        assert row['objective_calls'] == sum(row[k] for k in (
            'random_pool_calls', 'left_to_right_swap_calls', 'hill_climb_calls', 'perturbation_calls'))
        assert not any(k.startswith(('true_', 'truth_')) for k in row)
        for a in row['archive']:
            error = abs(idp(texts[cid], a['k2'], 20, tables[t['language_model']]) - a['idp'])
            assert error < 1e-8
            checked += 1; max_error = max(max_error, error)
        hit = any(a['k2'] == t['true_k2'] for a in row['archive'])
        counts[row['arm']+'_top5'] += int(hit)
        counts[row['arm']+'_rank1'] += int(bool(row['archive']) and row['archive'][0]['k2'] == t['true_k2'])
        paired[(cid, row['round'], row['local_proposal_cap'])].append(row)
    assert dict(counts) == evaluation['summary']
    prefix_checks = 0
    for pair in paired.values():
        assert len(pair) == 2
        if all(r['pre_checkpoint'] is not None for r in pair):
            assert pair[0]['pre_checkpoint'] == pair[1]['pre_checkpoint']; prefix_checks += 1
    assert hashlib.sha256((PHASE/'search_outputs.jsonl').read_bytes()).hexdigest() == evaluation['log_sha256']
    print(json.dumps({'status': 'passed', 'recorded_runs': len(rows), 'synthetic_cases': len(truth),
        'archive_scores_recomputed': checked, 'maximum_absolute_score_error': max_error,
        'recorded_recoveries': dict(counts), 'paired_prefix_checks': prefix_checks,
        'new_searches': 0, 'scope': 'Saved inputs, archive scores and counts; not a full source/operation audit or historical decipherment.'}, indent=2))

if __name__ == '__main__':
    main()

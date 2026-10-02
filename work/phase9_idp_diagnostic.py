"""External, independent IDP diagnostic on the already saved phase-8 pools.

Truth is used only here, after the searches. This program does not invoke a
solver or modify phase-8 artifacts. Direct enumeration of feasible boundary
pairs replaces the C++ implementation's incremental sums.
"""
from pathlib import Path
import hashlib
import json
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
PHASE8 = ROOT / 'work/phase8_crypto'
DEST = ROOT / 'work/phase9_idp_diagnostic'

def load_lines(path):
    return [json.loads(s) for s in path.read_text().splitlines()]

def decrypt(ciphertext, key):
    plain = np.empty(len(ciphertext), dtype=np.int64)
    offset = 0
    for column in key:
        positions = np.arange(column, len(ciphertext), len(key))
        plain[positions] = ciphertext[offset:offset+len(positions)]
        offset += len(positions)
    assert offset == len(ciphertext)
    return plain

def idp(ciphertexts, key, width, bigrams):
    matrix = np.zeros((width, width), dtype=np.float64)
    total_rows = 0
    for ciphertext in ciphertexts:
        intermediate = decrypt(ciphertext, key)
        rows, rem = divmod(len(intermediate), width)
        total_rows += rows
        windows = np.lib.stride_tricks.sliding_window_view(intermediate, rows)
        for a in range(width):
            left = windows[a*rows+max(0, a-(width-rem)):a*rows+min(a, rem)+1]
            for b in range(width):
                if a == b:
                    matrix[a,b] -= 1e6
                    continue
                right = windows[b*rows+max(0, b-(width-rem)):b*rows+min(b, rem)+1]
                indices = left[:,None,:] * 26 + right[None,:,:]
                matrix[a,b] += bigrams[indices].sum(axis=2).max()
    used_left, used_right, selected = set(), set(), []
    for _ in range(width):
        best = None
        for a in range(width):
            if a in used_left:
                continue
            for b in range(width):
                if b in used_right or a == b:
                    continue
                if best is None or matrix[a,b] > best[0]:
                    best = (float(matrix[a,b]), a, b)
        if best is None:
            a = next(i for i in range(width) if i not in used_left)
            b = next(i for i in range(width) if i not in used_right)
            best = (-7.0 * total_rows, a, b)
        value, a, b = best
        used_left.add(a); used_right.add(b); selected.append(value)
    return sum(selected) / (total_rows * width)

def main():
    DEST.mkdir(exist_ok=True)
    manifest = json.loads((PHASE8/'comparison_manifest.json').read_text())
    truths = {r['case_id']: r for r in load_lines(PHASE8/'planted_truth.jsonl')}
    rows = {r['case_id']: r for r in load_lines(PHASE8/'solver_outputs.jsonl') if r['policy'] == 'single'}
    protected = json.loads((PHASE8/'RESOURCE_HASHES.json').read_text())['files']
    models, results, score_checks = {}, [], 0
    for case in manifest['cases']:
        model_name = case['language_model']
        if model_name not in models:
            models[model_name] = np.fromfile(ROOT/'work/phase5_language'/model_name/'model.bin',
                                           dtype='<f4', count=676).astype(np.float64)
        table = models[model_name]
        ciphertexts = [np.array([ord(c)-97 for c in (ROOT/f['path']).read_text().strip().lower()],
                                dtype=np.int64) for f in case['ciphertext_files']]
        truth = truths[case['case_id']]
        true_score = idp(ciphertexts, truth['true_k2'], case['w1'], table)
        memo, pool_scores = {}, []
        for rd in rows[case['case_id']]['rounds']:
            for candidate in rd['pool']:
                key = tuple(candidate['k2'])
                if key not in memo:
                    memo[key] = idp(ciphertexts, key, case['w1'], table)
                measured = memo[key]
                assert abs(measured-candidate['idp']) < 1e-7, (case['case_id'], measured, candidate['idp'])
                score_checks += 1
                pool_scores.append(measured)
        best = max(pool_scores)
        results.append({'case_id':case['case_id'], 'true_k2_idp':true_score,
                        'best_returned_pool_idp':best, 'true_minus_best':true_score-best,
                        'true_k2_in_returned_pool':tuple(truth['true_k2']) in memo,
                        'distinct_returned_candidates':len(memo)})
    for entry in protected:
        assert hashlib.sha256((PHASE8/entry['path']).read_bytes()).hexdigest() == entry['sha256']
    output = {'date':'2026-10-02', 'scope':'External diagnosis of frozen phase8, not a new recovery trial',
              'independent_method':'Direct feasible-boundary Cartesian products and greedy directed neighbour assignment',
              'saved_candidate_score_checks':score_checks, 'previous_files_unchanged':len(protected),
              'results':results, 'limits':['Eight synthetic cases, known widths and conv0.',
              'Comparison with returned pools only; not the global IDP landscape.',
              'Greedy IDP is a relaxed bigram score, not an inferred first key or plaintext.',
              'No historical cipher or language conclusion.'],
              'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (DEST/'diagnostic.json').write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(output,ensure_ascii=False,indent=2))

if __name__ == '__main__':
    main()

"""Post-hoc geometry of already scored static states. Zero new IDP/search."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
PHASE = ROOT / 'work/phase15_crypto'

def main():
    evaluation = json.loads((PHASE / 'evaluation.json').read_text())
    moves = json.loads((PHASE / 'moves.json').read_text())['moves']
    index_of = {tuple(m['p']): m['index'] for m in moves}
    records = []
    for profile in evaluation['profiles']:
        if profile['anchor_label'] != 'omitted':
            continue
        case = evaluation['cases'][profile['case_id']]
        target = [case['true_k2'].index(i) for i in range(25)]
        best = profile['exact']['top5'][0]
        lookup = {value: i for i, value in enumerate(best['numeric'])}
        correction = tuple(lookup[value] for value in target)
        native = correction in index_of
        assert sum(a != b for a, b in zip(best['numeric'], target)) == best['hamming']
        records.append({'case_id': profile['case_id'], 'first_move_index': best['index'],
                        'best_neighbor_hamming': best['hamming'],
                        'remaining_wrong_positions': [i for i, (a, b) in enumerate(zip(best['numeric'], target)) if a != b],
                        'native_correction_exists': native,
                        'second_move_index': index_of.get(correction),
                        'target_exact_minus_best_neighbor': profile['true_minus_best_exact'],
                        'first_step_improves_exact': profile['exact']['strict_improvements_over_anchor'] > 0,
                        'second_step_improves_exact': native and profile['true_minus_best_exact'] > 0,
                        'scores_source': 'First step: best saved omitted-profile state. Second step: target score already saved in true-anchor profile, not a new evaluation.'})
    result = {'scope': 'Post-hoc reading of fixed pre-scored states and source geometry; not preregistered as a primary metric.',
              'evaluation_sha256': hashlib.sha256((PHASE / 'evaluation.json').read_bytes()).hexdigest(),
              'new_IDP_calls': 0, 'new_searches': 0, 'records': records,
              'limits': 'No trajectory executed. Does not show that the phase14 first-improvement search chooses this path, or that a random start reaches these anchors.'}
    (HERE / 'saved_paths_posthoc.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))

if __name__ == '__main__':
    main()

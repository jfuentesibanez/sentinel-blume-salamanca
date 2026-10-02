"""Independent geometry and binary32 lattice checks; zero IDP evaluations."""
from pathlib import Path
import ast
import hashlib
import json
import math
import struct

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent

def main():
    source = ROOT / 'work/phase4_crypto/check_source_moves.py'
    module = ast.parse(source.read_text())
    function = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'literal_source')
    scope = {}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), scope)
    identity = tuple(range(25))
    moves = scope['literal_source'](25)
    assert identity in moves and len(moves) == 16650
    present, missing = [], []
    for a in range(25):
        for b in range(a + 1, 25):
            target = list(identity)
            target[a], target[b] = target[b], target[a]
            (present if tuple(target) in moves else missing).append([a, b])
    assert missing == [[a, 24] for a in range(1, 23)]
    for a, b in missing:
        target = list(identity)
        target[a], target[b] = target[b], target[a]
        first = list(identity)
        first[0], first[a] = first[a], first[0]
        second = tuple(first[target[i]] for i in range(25))
        assert tuple(first) in moves and second in moves
        assert tuple(first[second[i]] for i in range(25)) == tuple(target)
    encoded = json.dumps(sorted(moves), separators=(',', ':')).encode()
    digest = hashlib.sha256(encoded).hexdigest()
    earlier = json.loads((ROOT / 'work/phase15_design/cobertura_swaps_independiente.json').read_text())
    assert digest == earlier['neighbourhood_sha256_including_identity']
    models = []
    denominator = 1 << 23
    normalizer = (615 // 20 + 160 // 20) * 20
    for name in ('de_fold', 'fr_fold'):
        path = ROOT / 'work/phase5_language' / name / 'model.bin'
        bigrams = struct.unpack('<676f', path.read_bytes()[:676 * 4])
        numerators = []
        for value in bigrams:
            numerator, divisor = value.as_integer_ratio()
            assert denominator % divisor == 0
            numerators.append(numerator * (denominator // divisor))
        assert math.gcd(*numerators) == 1
        bound = max(abs(n) for n in numerators) * normalizer
        assert bound < 2**63 and bound * 10**12 < 2**127
        assert max(bigrams) <= 0
        models.append({'model': name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                       'bigram_count': len(bigrams), 'common_denominator': denominator,
                       'gcd_numerators': 1, 'absolute_total_bound': bound,
                       'int64_sum_bound_passed': True, 'int128_epsilon_bound_passed': True})
    result = {'passed': True, 'source_geometry_hash': digest, 'source_moves': len(moves) - 1,
              'present_single_swaps': len(present), 'missing_single_swaps': missing,
              'missing_swap_graph_distance': 2, 'models': models,
              'normalizer': normalizer, 'exact_score_lattice_spacing': 1 / (denominator * normalizer),
              'lattice_spacing_over_epsilon': 10**12 / (denominator * normalizer),
              'new_IDP_calls': 0, 'new_truth_generated': False, 'new_searches': 0,
              'interpretation': 'One-step omissions do not disconnect the graph. Nonzero exact score differences exceed epsilon; legacy float arithmetic may still change comparisons.'}
    (HERE / 'static_review.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))

if __name__ == '__main__':
    main()

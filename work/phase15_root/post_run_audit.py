"""Replay fixed-anchor CSVs and independently score two states per profile.

Not a search. New audit backend calls (legacy + exact) are explicitly counted.
The integer reference enumerates every feasible pair of offsets directly.
"""
from pathlib import Path
import csv
import hashlib
import json
import struct
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
PHASE = ROOT / 'work/phase15_crypto'
AUDIT_COST = {'legacy': 0, 'exact': 0}

def charge(backend):
    AUDIT_COST[backend] += 1
    (HERE / 'audit_progress.json').write_text(json.dumps({
        'status': 'running', 'audit_backend_calls': AUDIT_COST,
        'audit_IDP_equivalent_calls': sum(AUDIT_COST.values()),
        'cost_rule': 'Charged on entering each independent backend, including an interrupted call.'}) + '\n')

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

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
    offsets = [range(max(0, c - (width - remainder)), min(c, remainder) + 1) for c in range(width)]
    matrix = [-1000000 * scale] * (width * width)
    for a in range(width):
        for b in range(width):
            if a == b:
                continue
            matrix[a * width + b] = max(
                sum(table[text[a * rows + x + r] * 26 + text[b * rows + y + r]] for r in range(rows))
                for x in offsets[a] for y in offsets[b])
    return matrix

def legacy_matrix_sliding(text, width, table):
    rows, remainder = divmod(len(text), width)
    lo = [max(0, c - (width - remainder)) for c in range(width)]
    hi = [min(c, remainder) for c in range(width)]
    matrix = [-1000000.0] * (width * width)
    for a in range(width):
        for b in range(width):
            if a == b:
                continue
            best = -1e100
            for d in range(lo[b] - hi[a], hi[b] - lo[a] + 1):
                low, high = max(lo[a], lo[b] - d), min(hi[a], hi[b] - d)
                if low > high:
                    continue
                p, q = a * rows + low, b * rows + d + low
                score = sum(table[text[p + r] * 26 + text[q + r]] for r in range(rows))
                best = max(best, score)
                for _ in range(low + 1, high + 1):
                    difference = table[text[p + rows] * 26 + text[q + rows]] - table[text[p] * 26 + text[q]]
                    rounded = struct.unpack('<f', struct.pack('<f', difference))[0]
                    score += rounded
                    p += 1
                    q += 1
                    best = max(best, score)
            matrix[a * width + b] = best
    return matrix

def greedy(matrix, width, rows, scale):
    total = 0
    used_a, used_b, edges = set(), set(), []
    forced = 0
    for _ in range(width):
        best, x, y = None, None, None
        for a in range(width):
            if a in used_a:
                continue
            for b in range(width):
                if b in used_b or a == b:
                    continue
                value = matrix[a * width + b]
                if best is None or value > best:
                    best, x, y = value, a, b
        if x is None:
            x = next(a for a in range(width) if a not in used_a)
            y = next(b for b in range(width) if b not in used_b)
            best = -7 * rows * scale
            forced += 1
        total += best
        used_a.add(x)
        used_b.add(y)
        edges.append(x * width + y)
    return total, edges, forced

def main():
    started = time.monotonic()
    manifest = json.loads((PHASE / 'manifest.json').read_text())
    assert manifest['completed'] and manifest['protected_unchanged']
    assert len(manifest['profiles']) == len(manifest['runs']) == 12
    assert sha(PHASE / 'plan12.json') == manifest['plan_sha256']
    moves = json.loads((PHASE / 'moves.json').read_text())['moves']
    assert len(moves) == 16649
    cases = {c['case_id']: c for c in manifest['cases']}
    total_rows = 0
    reference_calls = AUDIT_COST
    checks = []
    all_complete = True
    for profile in manifest['profiles']:
        run = next(r for r in manifest['runs'] if (r['case_id'], r['anchor_label']) == (profile['case_id'], profile['anchor_label']))
        csv_path = ROOT / profile['csv_path']
        summary_path = ROOT / profile['summary_path']
        assert sha(csv_path) == run['csv_sha256'] and sha(summary_path) == run['summary_sha256']
        summary = json.loads(summary_path.read_text())
        assert summary == run['summary']
        anchor = [int(x) for x in (ROOT / profile['anchor_path']).read_text().split()]
        assert anchor == summary['anchor_numeric'] and sorted(anchor) == list(range(25))
        rows = list(csv.DictReader(csv_path.open()))
        assert len(rows) == summary['states_completed']
        assert summary['legacy_calls'] == summary['exact_calls'] == len(rows)
        all_complete &= summary['stop_reason'] == 'complete' and len(rows) == 16650
        total_rows += len(rows)
        denominator = summary['idp_denominator']
        base_num = int(rows[0]['exact_numerator'])
        base_legacy = float(rows[0]['legacy'])
        discrepancies = 0
        edge_discrepancies = 0
        seen = set()
        for index, row in enumerate(rows):
            assert int(row['index']) == index
            assert int(row['kind']) == (-1 if index == 0 else moves[index - 1]['kind'])
            numeric = tuple(anchor if index == 0 else (anchor[p] for p in moves[index - 1]['p']))
            assert numeric not in seen
            seen.add(numeric)
            legacy_improves = float(row['legacy']) > base_legacy + 1e-12
            exact_improves = (int(row['exact_numerator']) - base_num) * 10**12 > denominator
            assert legacy_improves == bool(int(row['legacy_improves_anchor']))
            assert exact_improves == bool(int(row['exact_improves_anchor']))
            discrepancies += legacy_improves != exact_improves
            edge_discrepancies += row['legacy_edges'] != row['exact_edges']
            for field in ('legacy_edges', 'exact_edges'):
                edges = [int(x) for x in row[field].split(':')]
                assert len(edges) == 20
                assert len({e // 20 for e in edges}) == len({e % 20 for e in edges}) == 20
        assert discrepancies == summary['improvement_decision_discrepancies']
        assert edge_discrepancies == summary['greedy_edge_discrepancies']
        # Fixed audit policy: anchor and highest exact-scoring non-anchor state.
        best = max(rows[1:], key=lambda r: (int(r['exact_numerator']), -int(r['index'])))
        case = cases[profile['case_id']]
        model_path = ROOT / 'work/phase5_language' / case['language_model'] / 'model.bin'
        table = struct.unpack('<676f', model_path.read_bytes()[:676 * 4])
        scale = summary['scale']
        exact_table = []
        for value in table:
            numerator, divisor = value.as_integer_ratio()
            assert scale % divisor == 0
            exact_table.append(numerator * (scale // divisor))
        ciphertexts = [[ord(c) - 65 for c in (ROOT / p).read_text().strip()] for p in case['ciphertext_paths']]
        nr = sum(len(c) // 20 for c in ciphertexts)
        assert denominator == scale * nr * 20
        for selected in (rows[0], best):
            index = int(selected['index'])
            numeric = anchor if index == 0 else [anchor[p] for p in moves[index - 1]['p']]
            intermediate = [undo_second(c, numeric) for c in ciphertexts]
            charge('exact')
            matrices = [exact_matrix_direct(i, 20, exact_table, scale) for i in intermediate]
            exact_sum = [sum(m[z] for m in matrices) for z in range(400)]
            numerator, edges, forced = greedy(exact_sum, 20, nr, scale)
            assert numerator == int(selected['exact_numerator'])
            assert edges == [int(x) for x in selected['exact_edges'].split(':')]
            assert forced == int(selected['exact_forced'])
            charge('legacy')
            legacy_matrices = [legacy_matrix_sliding(i, 20, table) for i in intermediate]
            legacy_sum = [sum(m[z] for m in legacy_matrices) for z in range(400)]
            total, legacy_edges, legacy_forced = greedy(legacy_sum, 20, nr, 1)
            assert total / (nr * 20) == float(selected['legacy'])
            assert legacy_edges == [int(x) for x in selected['legacy_edges'].split(':')]
            assert legacy_forced == int(selected['legacy_forced'])
        checks.append({'case_id': profile['case_id'], 'anchor': profile['anchor_label'],
                       'rows_replayed': len(rows), 'independent_scored_indices': [0, int(best['index'])],
                       'improvement_discrepancies': discrepancies, 'edge_discrepancies': edge_discrepancies,
                       'distinct_numeric_keys_in_profile': len(seen)})
    assert total_rows == manifest['legacy_calls'] == manifest['exact_calls']
    result = {'passed': True, 'all_profiles_complete': bool(all_complete), 'profiles': len(checks),
              'rows_replayed': total_rows, 'checks': checks, 'audit_backend_calls': reference_calls,
              'audit_IDP_equivalent_calls': sum(reference_calls.values()), 'new_searches': 0,
              'audit_policy': 'Fixed-anchor replay of every row; independent scoring of anchor and highest exact-scoring non-anchor per profile. Integer matrix uses direct offset enumeration, not sliding.',
              'manifest_sha256': sha(PHASE / 'manifest.json'), 'truth_sha256': sha(PHASE / 'truth.jsonl'),
              'seconds': time.monotonic() - started}
    (HERE / 'post_run_audit.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))

if __name__ == '__main__':
    began = time.monotonic()
    attempts = HERE / 'audit_attempts'
    attempts.mkdir(exist_ok=True)
    attempt = len(list(attempts.glob('attempt*.json'))) + 1
    try:
        main()
    except BaseException as error:
        failure = {'status': 'failed', 'attempt': attempt,
                   'audit_backend_calls': AUDIT_COST,
                   'audit_IDP_equivalent_calls': sum(AUDIT_COST.values()),
                   'seconds': time.monotonic() - began, 'error_type': type(error).__name__,
                   'error': str(error), 'source_sha256': sha(Path(__file__))}
        (attempts / f'attempt{attempt}.json').write_text(json.dumps(failure, indent=2) + '\n')
        (attempts / f'post_run_audit_attempt{attempt}.py').write_bytes(Path(__file__).read_bytes())
        raise
    receipt = {'status': 'passed', 'attempt': attempt,
               'audit_backend_calls': AUDIT_COST,
               'audit_IDP_equivalent_calls': sum(AUDIT_COST.values()),
               'seconds': time.monotonic() - began, 'source_sha256': sha(Path(__file__))}
    (attempts / f'attempt{attempt}.json').write_text(json.dumps(receipt, indent=2) + '\n')

"""Independent checks of logged synthetic results; no historical attack."""
from pathlib import Path
import hashlib
import json
import struct

ROOT = Path(__file__).resolve().parent.parent
HERE = ROOT / 'work/phase7_crypto'
manifest = json.loads((HERE / 'full_language_manifest.json').read_text())
assert manifest['completed'] and not manifest['historical_attack']
assert manifest['widths_disclosed'] and not manifest['keys_disclosed']
assert len(manifest['runs']) == 8
assert all(r['status'] == 'completed' and r['rows'] == 2 for r in manifest['runs'])
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(HERE / 'full_language_controls.jsonl') == manifest['log_sha256']
assert manifest['files_before'] == manifest['files_after']
for item in manifest['files_before']:
    assert sha(ROOT / item['path']) == item['sha256'], item['path']

rows = [json.loads(line) for line in (HERE / 'full_language_controls.jsonl').read_text().splitlines()]
expected = {(m, w1, w2, seed, n) for m in manifest['models']
            for w1, w2 in manifest['bands'] for seed in manifest['seeds'] for n in (1, 2)}
assert len(rows) == 16
assert {(r['language_model'], r['w1'], r['w2'], r['plant_seed'], r['messages_scored']) for r in rows} == expected

def encrypt(text, key):
    return ''.join(text[column::len(key)] for column in key)

def decrypt(text, key):
    columns = {}
    position = 0
    for column in key:
        length = len(range(column, len(text), len(key)))
        columns[column] = text[position:position + length]
        position += length
    assert position == len(text)
    return ''.join(columns[i % len(key)][i // len(key)] for i in range(len(text)))

def score(messages, table, n):
    total = count = 0
    for text in messages:
        for i in range(len(text) - n + 1):
            code = 0
            for char in text[i:i+n]:
                code = code * 26 + ord(char) - ord('a')
            total += table[code]
            count += 1
    return total / count

tables = {}
holdouts = {}
for model in manifest['models']:
    folder = ROOT / 'work/phase5_language' / model
    raw = (folder / 'model.bin').read_bytes()
    offset = 0
    tables[model] = {}
    for n in (2, 3, 4):
        size = 26**n
        tables[model][n] = struct.unpack_from('<%df' % size, raw, offset)
        offset += size * 4
    assert offset == len(raw)
    holdouts[model] = (folder / 'holdout.txt').read_text().strip()

paired = {}
scores_checked = 0
for row in rows:
    assert row['mode'] == 'full' and row['variant'] == 'source'
    assert not row['oracle_k2_disclosed'] and not row['negative']
    assert row['outer_rounds'] == 3 and row['lengths'] == [615, 160]
    for k, w in [('k1', 'w1'), ('true_k1', 'w1'), ('k2', 'w2'), ('true_k2', 'w2')]:
        assert sorted(row[k]) == list(range(row[w]))
    pair = (row['w1'], row['w2'], row['plant_seed'])
    truth_keys = (row['true_k1'], row['true_k2'])
    assert pair not in paired or paired[pair] == truth_keys
    paired[pair] = truth_keys
    start = row['sample_position']
    body = holdouts[row['language_model']]
    truth = [body[start:start+615], body[start+615:start+775]]
    assert [len(x) for x in truth] == [615, 160]
    cipher = [encrypt(encrypt(x, row['true_k1']), row['true_k2']) for x in truth]
    recovered = [decrypt(decrypt(x, row['k2']), row['k1']) for x in cipher]
    assert [encrypt(encrypt(x, row['k1']), row['k2']) for x in recovered] == cipher
    assert row['reencryption_consistency']
    assert row['exact_k1'] == (row['k1'] == row['true_k1'])
    assert row['exact_k2'] == (row['k2'] == row['true_k2'])
    assert row['stage_exact_k2'] == (row['stage_k2'] == row['true_k2'])
    assert row['exact_both_plaintexts'] == (recovered == truth)
    assert row['correct_letters'] == [sum(a == b for a, b in zip(x, y)) for x, y in zip(recovered, truth)]
    nmsg = row['messages_scored']
    for n in (3, 4):
        assert abs(score(recovered[:nmsg], tables[row['language_model']][n], n) - row['q' + str(n)]) < 1e-7
        assert abs(score(truth[:nmsg], tables[row['language_model']][n], n) - row['truth_q' + str(n)]) < 1e-7
        scores_checked += 2

result = {'passed': True, 'rows_checked': len(rows), 'synthetic_plaintexts_reconstructed': 2 * len(rows),
          'scores_recomputed': scores_checked, 'protected_inputs_unchanged': len(manifest['files_before']),
          'historical_attack': False, 'widths_disclosed': True, 'keys_disclosed': False,
          'truth_separation_review': 'source_full receives ciphertext, widths, model, independent search seed and budgets. True keys/plaintexts are used by plant() and post-solver evaluation only.',
          'limitations': 'Small paired controls, one literary corpus per language, known widths, no new language-specific negative controls. This does not validate a decipherment of BLUME.'}
(ROOT / 'work/phase7_root_verification.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
print(json.dumps(result, ensure_ascii=False))

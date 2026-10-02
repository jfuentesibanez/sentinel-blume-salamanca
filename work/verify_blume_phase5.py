from pathlib import Path
import hashlib, json, math, struct

ROOT = Path(__file__).resolve().parent.parent
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def data(rel): return json.loads((ROOT / rel).read_text())
def check_files(records):
    for rec in records:
        assert sha(ROOT / rec['path']) == rec['sha256'], rec['path']
    return len(records)

hist = ROOT / 'work/history/phase5-archive'
resource_hashes = data('work/history/phase5-archive/phase5-resource-hashes.json')
for path, digest in resource_hashes.items(): assert sha(ROOT / path) == digest, path
protected = data('work/history/phase5-archive/protected-phase4-baseline.json')
if isinstance(protected, dict) and 'files' in protected: protected = protected['files']
if isinstance(protected, dict): protected = [{'path': p, 'sha256': s} for p,s in protected.items()]
protected_count = check_files(protected)

manifest = data('work/phase5_language/oracle_controls_manifest.json')
language_file_count = check_files(manifest['files'])
assert manifest['completed'] and len(manifest['runs']) == 12
assert all(x['status'] == 'completed' and x['rows'] == 2 for x in manifest['runs'])
assert sha(ROOT / 'work/phase5_language/oracle_controls.jsonl') == manifest['log_sha256']
rows = [json.loads(line) for line in (ROOT / 'work/phase5_language/oracle_controls.jsonl').read_text().splitlines()]
assert len(rows) == 24
tables = {}
for model in manifest['models']:
    folder = ROOT / 'work/phase5_language' / model
    provenance = json.loads((folder / 'provenance.json').read_text())
    assert sha(folder / 'model.bin') == provenance['model_sha256']
    assert sha(folder / 'holdout.txt') == provenance['holdout_sha256']
    raw = (folder / 'model.bin').read_bytes(); offset = 0; tables[model] = {}
    for n in (2,3,4):
        count = 26**n; values = struct.unpack_from('<%df' % count, raw, offset); offset += count * 4
        assert all(math.isfinite(x) and x <= 0 for x in values)
        assert abs(sum(10**x for x in values) - 1) < 1e-5
        tables[model][n] = values
    assert offset == len(raw)

# Explicit row and column layout, separate from the C++ scoring routines.
def enc(text, key):
    width = len(key)
    return ''.join(text[column::width] for column in key)
def dec(text, key):
    width = len(key); columns = {}; offset = 0
    for column in key:
        length = len(range(column, len(text), width))
        columns[column] = text[offset:offset+length]; offset += length
    assert offset == len(text)
    return ''.join(columns[i % width][i // width] for i in range(len(text)))
def score(messages, table, n):
    total = 0; count = 0
    for text in messages:
        for i in range(len(text)-n+1):
            code = 0
            for char in text[i:i+n]: code = code * 26 + ord(char)-97
            total += table[code]; count += 1
    return total/count

independent_plaintext_checks = 0
for row in rows:
    assert row['mode'] == 'oracle' and row['oracle_k2_disclosed'] and not row['negative']
    assert row['exact_k1'] and row['exact_k2'] and row['exact_both_plaintexts']
    assert row['correct_letters'] == [615,160] and not row['budget_expired']
    assert row['k1'] == row['true_k1'] and row['k2'] == row['true_k2']
    assert sorted(row['k1']) == list(range(row['w1']))
    assert sorted(row['k2']) == list(range(row['w2']))
    holdout = (ROOT / 'work/phase5_language' / row['language_model'] / 'holdout.txt').read_text()
    start = row['sample_position']
    truth = [holdout[start:start+615], holdout[start+615:start+775]]
    assert [len(x) for x in truth] == [615,160]
    ciphertexts = [enc(enc(x,row['true_k1']),row['true_k2']) for x in truth]
    recovered = [dec(dec(x,row['k2']),row['k1']) for x in ciphertexts]
    assert recovered == truth
    for n in (3,4):
        independent = score(recovered[:row['messages_scored']], tables[row['language_model']][n], n)
        assert abs(independent - row['q'+str(n)]) < 1e-7
        assert abs(independent - row['truth_q'+str(n)]) < 1e-7
    independent_plaintext_checks += 2

crypto_rows = []
for filename in ('conditioned_diagnostic.jsonl', 'walk_conditioned_diagnostic.jsonl'):
    crypto_rows += [json.loads(x) for x in (ROOT / 'work/phase5_crypto' / filename).read_text().splitlines()]
assert len(crypto_rows) == 4
crypto_file_count = 0
for filename in ('conditioned_diagnostic_manifest.json', 'walk_conditioned_diagnostic_manifest.json'):
    crypto_file_count += check_files(data('work/phase5_crypto/' + filename)['files'])
for row in crypto_rows:
    events = row.get('states', row.get('events'))
    assert sum(x['idp_evals'] for x in events) == row['idp_evals']
    assert row['k2'] == row['start_k2'] and not row['exact_k2']
    assert row['idp_evals'] <= row['idp_eval_limit']
    bests = [x.get('global_best_idp', x.get('best_idp')) for x in events]
    assert all(a <= b+1e-10 for a,b in zip(bests, bests[1:]))
    if row['policy'] != 'source':
        assert row['idp_evals'] == 150000 and row['termination'] == 'max_evaluations'
    assert row['seconds'] < 15

result = {'passed': True, 'scope': 'Independent accounting, hashes, model probabilities, logged keys and exact synthetic plaintext scores; no historical decipherment validated',
          'protected_prior_files_unchanged': protected_count, 'archive_resource_hashes':len(resource_hashes),
          'language_manifest_file_hashes':language_file_count, 'language_processes':12, 'language_oracle_rows':24,
          'independently_reconstructed_synthetic_plaintexts':independent_plaintext_checks, 'crypto_manifest_file_hashes':crypto_file_count,
          'conditioned_diagnostic_policies':4, 'historical_attack':False}
(ROOT / 'work/phase5_root_verification.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result))

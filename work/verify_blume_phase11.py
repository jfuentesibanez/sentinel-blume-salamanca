"""Read-only audit of saved phase11 controls and results. No search or helper run."""
from pathlib import Path
from collections import Counter
import hashlib, json
import numpy as np
from phase9_idp_diagnostic import idp

ROOT = Path(__file__).resolve().parent.parent
HERE = ROOT / 'work/phase11_crypto'
def load(path): return json.loads(path.read_text())
def rows(path): return [json.loads(s) for s in path.read_text().splitlines()]
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def encrypt(text, key): return ''.join(text[i::len(key)] for i in key)
def close(a, b): assert abs(a-b) < 1e-8, (a, b)

manifest = load(HERE/'manifest.json')
sealed = load(HERE/'sealed_design.json')
assert sha(HERE/'sealed_design.json') == '13f76031eb50be4716cde031964f5bcc5459e55ecd5d6912ffbb8f2c602afede'
assert manifest['completed'] and manifest['protected_unchanged']
assert manifest['protected_before'] == manifest['protected_after']
assert len(manifest['protected_before']) == 282
for record in manifest['protected_before']:
    assert sha(ROOT/record['path']) == record['sha256']
for key, value in sealed.items():
    if key not in ('runs', 'status'):
        assert manifest[key] == value, key
assert sealed['status'] == 'sealed_not_run' and sealed['runs'] == []
assert manifest['predefined_seeds'] == [20262101,20262102]
assert manifest['models'] == ['de_fold','fr_fold']
assert manifest['bands'] == [[12,15],[20,25]]
assert manifest['widths_disclosed'] and not manifest['keys_disclosed']
for name, field in [('capped_population_search','solver_sha256'),
                    ('capped_population_search.cpp','solver_source_sha256'),
                    ('run_comparison.py','runner_sha256'),
                    ('truth.jsonl','truth_sha256'),('search_outputs.jsonl','log_sha256')]:
    assert sha(HERE/name) == manifest[field]
for kind in ('source','binary'):
    assert sha(ROOT/manifest['frozen_baseline'][kind+'_path']) == manifest['frozen_baseline'][kind+'_sha256']
source = (ROOT/manifest['frozen_baseline']['source_path']).read_bytes()
assert source.count(b'int main(int argc,char**argv)') == 1
prefix = source[:source.index(b'int main(int argc,char**argv)')]
assert len(prefix) == 8540 and (HERE/'phase10_frozen_classes.h').read_bytes() == prefix
assert len(manifest['runs']) == 32 and len(manifest['cases']) == 8
assert all(r['status']=='completed' and r['started_at_unix'] >= manifest['cases_sealed_at_unix'] for r in manifest['runs'])
assert [r['command'] for r in manifest['runs']] == [r['command'] for c in manifest['cases'] for r in c['commands']]
resource_manifest = load(HERE/'RESOURCE_HASHES.json')
for record in resource_manifest['resources']:
    path = HERE/record['path']
    assert sha(path)==record['sha256'] and path.stat().st_size==record['bytes']
assert len(resource_manifest['resources']) == resource_manifest['resource_count_excluding_this_file'] == 35

truths = {t['case_id']:t for t in rows(HERE/'truth.jsonl')}
outputs = rows(HERE/'search_outputs.jsonl')
evaluated = {(r['case_id'],r['method'],r['round']):r for r in rows(HERE/'external_evaluation.jsonl')}
summary = load(HERE/'summary.json')
assert len(truths)==8 and len(outputs)==len(evaluated)==32
counts = Counter()
totals = {m:{'hits':0,'cases':set(),'calls':0,'seconds':0.0} for m in ('population','cap5000')}
failed_margins = []
score_error = 0.0
for case in manifest['cases']:
    name=case['case_id']; truth=truths[name]
    folder=ROOT/'work/phase5_language'/case['language_model']
    provenance=load(folder/'provenance.json')
    assert sha(folder/'model.bin')==provenance['model_sha256']
    assert sha(folder/'holdout.txt')==provenance['holdout_sha256']
    body=''.join(c.lower() for c in (folder/'holdout.txt').read_text() if c.isascii() and c.isalpha())
    pos=truth['sample_position']; plains=[body[pos:pos+615],body[pos+615:pos+775]]
    assert list(map(len,plains)) == [615,160]
    assert sorted(truth['true_k1']) == list(range(case['w1']))
    assert sorted(truth['true_k2']) == list(range(case['w2']))
    ciphertexts=[]
    for record, plain in zip(case['ciphertext_files'],plains):
        path=ROOT/record['path']; assert sha(path)==record['sha256']
        cipher=path.read_text().strip().lower()
        assert cipher==encrypt(encrypt(plain,truth['true_k1']),truth['true_k2'])
        ciphertexts.append(np.array([ord(c)-97 for c in cipher],dtype=np.int64))
        counts['ciphertexts_regenerated_without_helper']+=1
    table=np.fromfile(folder/'model.bin',dtype='<f4',count=676).astype(np.float64)
    true_score=idp(ciphertexts,truth['true_k2'],case['w1'],table)
    counts['true_k2_scores']+=1
    group=[r for r in outputs if r['case_id']==name]
    assert {(r['method'],r['round']) for r in group} == {(m,r) for m in ('population','cap5000') for r in (0,1)}
    assert [(r['method'],r['round']) for r in case['commands']] == [('population',0),('cap5000',0),('cap5000',1),('population',1)]
    for plan in case['commands']:
        command=plan['command']; assert len(command)==11 and command[1]==plan['method']
        seed=((case['plant_seed']^0xb7e151628aed2a6b)+plan['round']*0x9e3779b97f4a7c15)&((1<<64)-1)
        assert plan['search_seed']==seed
        assert command[5:]==[str(case['w1']),str(case['w2']),str(seed),'100000','30',str(plan['round'])]
        assert all('truth' not in part for part in command)
    for index in (0,1):
        pair=[r for r in group if r['round']==index]
        assert pair[0]['population_events'][:20] == pair[1]['population_events'][:20]
        counts['paired_initializations']+=1
    for row in group:
        assert row['mode']=='ciphertext_only_k2' and row['lengths']==[615,160]
        assert row['convention']==0 and row['messages_scored']==2
        assert not any(k.startswith(('truth_','true_')) for k in row)
        assert row['objective_calls']==row['target_objective_calls']==100000
        assert row['cut_cause']=='evaluations' and row['seconds']<row['seconds_limit']==30
        assert row['objective_calls']==sum(row[k] for k in ('random_pool_calls','left_to_right_swap_calls','hill_climb_calls','perturbation_calls'))
        archive=row['archive']; assert len(archive)==5 and len({tuple(c['k2']) for c in archive})==5
        measured=[]
        for candidate in archive:
            assert sorted(candidate['k2'])==list(range(case['w2']))
            score=idp(ciphertexts,candidate['k2'],case['w1'],table)
            close(score,candidate['idp']); score_error=max(score_error,abs(score-candidate['idp']))
            measured.append(score); counts['archive_scores']+=1
        hit_ranks=[i+1 for i,c in enumerate(archive) if c['k2']==truth['true_k2']]
        check=evaluated[(name,row['method'],row['round'])]
        assert check['true_k2_ranks']==hit_ranks and check['true_k2_in_archive']==bool(hit_ranks)
        assert check['true_k2_best']==(1 in hit_ranks)
        close(check['true_k2_idp_external'],true_score)
        close(check['best_archive_idp'],max(measured))
        close(check['true_minus_best_idp'],true_score-max(measured))
        greater = true_score > max(measured)+1e-8
        assert check['true_idp_greater_than_all']==greater
        if not hit_ranks:
            assert greater
            failed_margins.append(true_score-max(measured))
        else:
            assert hit_ranks==[1] and case['language_model']=='de_fold' and [case['w1'],case['w2']]==[12,15]
            totals[row['method']]['hits']+=1; totals[row['method']]['cases'].add(name)
        totals[row['method']]['calls']+=row['objective_calls']; totals[row['method']]['seconds']+=row['seconds']
        counts['rows']+=1
for method,value in totals.items():
    assert value['hits']==summary['archive_hits_by_method'][method]
    assert len(value['cases'])==summary['cases_with_any_archive_hit_by_method'][method]
    assert value['calls']==summary['total_calls_by_method'][method]==1600000
    close(value['seconds'],summary['total_seconds_by_method'][method])
assert totals['population']['hits']==2 and totals['cap5000']['hits']==3
assert len(failed_margins)==summary['true_idp_greater_than_all_rows']==27
result={'status':'passed','phase':11,'scope':'Saved controls, frozen models, truth, commands and 160 returned archive scores. Independent movement/admission audit is separate.',
        'searches_rerun':0,'helpers_rerun':0,'counts':dict(counts),'protected_prior_crypto_files':282,
        'new_crypto_resources_verified':35,'max_archive_idp_error':score_error,
        'archive_hits':{m:v['hits'] for m,v in totals.items()},
        'pairs_with_hits':{m:len(v['cases']) for m,v in totals.items()},
        'failed_true_score_margin_range':[min(failed_margins),max(failed_margins)],
        'model_limit':'One literary holdout per language, known widths, shared keys, no historical plaintext.',
        'resource_hash_manifest_sha256':sha(HERE/'RESOURCE_HASHES.json'),
        'manifest_sha256':sha(HERE/'manifest.json'),'saved_results_sha256':sha(HERE/'search_outputs.jsonl')}
(ROOT/'work/phase11_root_verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(result,ensure_ascii=False))

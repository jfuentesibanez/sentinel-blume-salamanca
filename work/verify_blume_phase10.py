"""Independent phase10 saved-result audit. Does not import a solver or evaluator."""
from pathlib import Path
from collections import Counter
import hashlib, json
import numpy as np
from phase9_idp_diagnostic import idp

ROOT=Path(__file__).resolve().parent.parent
HERE=ROOT/'work/phase10_crypto'
def load(p): return json.loads(p.read_text())
def rows(p): return [json.loads(s) for s in p.read_text().splitlines()]
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def inverse(key): return [key.index(i) for i in range(len(key))]
def encrypt(text,key): return ''.join(text[i::len(key)] for i in key)
def close(a,b): assert abs(a-b)<1e-7, (a,b)
def distance(a,b): return sum(x!=y for x,y in zip(a,b))
def preferred(m): return (-m['idp'], m['numeric'])

manifest=load(HERE/'manifest.json')
assert manifest['completed'] and manifest['protected_unchanged']
assert manifest['predefined_seeds']==[20262001,20262002]
assert manifest['widths_disclosed'] and not manifest['keys_disclosed']
assert manifest['protected_before']==manifest['protected_after']
assert len(manifest['protected_before'])==252
for x in manifest['protected_before']: assert sha(ROOT/x['path'])==x['sha256']
for name,field in [('population_search','solver_sha256'),('population_search.cpp','solver_source_sha256'),
                   ('run_comparison.py','runner_sha256'),('truth.jsonl','truth_sha256'),('search_outputs.jsonl','log_sha256')]:
    assert sha(HERE/name)==manifest[field]
for kind in ('source','binary'):
    assert sha(ROOT/manifest['frozen_baseline'][kind+'_path'])==manifest['frozen_baseline'][kind+'_sha256']
assert len(manifest['cases'])==8 and len(manifest['runs'])==32
assert all(x['status']=='completed' and x['started_at_unix']>=manifest['cases_sealed_at_unix'] for x in manifest['runs'])
truths={x['case_id']:x for x in rows(HERE/'truth.jsonl')}
outputs=rows(HERE/'search_outputs.jsonl')
assert len(outputs)==32 and len(truths)==8
summary=load(HERE/'summary.json')
evaluated={(x['case_id'],x['method'],x['round']):x for x in rows(HERE/'external_evaluation.jsonl')}
assert len(evaluated)==32
counts=Counter()
totals={m:{'round_hits':0,'calls':0,'seconds':0.0,'cases':set()} for m in ('restart','population')}
failed_margins=[]

for case in manifest['cases']:
    name=case['case_id']; truth=truths[name]
    folder=ROOT/'work/phase5_language'/case['language_model']
    provenance=load(folder/'provenance.json')
    assert sha(folder/'model.bin')==provenance['model_sha256']
    assert sha(folder/'holdout.txt')==provenance['holdout_sha256']
    body=''.join(c.lower() for c in (folder/'holdout.txt').read_text() if c.isascii() and c.isalpha())
    pos=truth['sample_position']; plains=[body[pos:pos+615],body[pos+615:pos+775]]
    ciphertexts=[]
    for entry,plain in zip(case['ciphertext_files'],plains):
        path=ROOT/entry['path']; assert sha(path)==entry['sha256']
        cipher=path.read_text().strip().lower()
        assert cipher==encrypt(encrypt(plain,truth['true_k1']),truth['true_k2'])
        ciphertexts.append(np.array([ord(c)-97 for c in cipher],dtype=np.int64))
        counts['ciphertexts']+=1
    table=np.fromfile(folder/'model.bin',dtype='<f4',count=676).astype(np.float64)
    cache={}
    def measured(key):
        tag=tuple(key)
        if tag not in cache: cache[tag]=idp(ciphertexts,key,case['w1'],table)
        return cache[tag]
    def population_valid(state):
        assert len(state)<=5 and len({x['id'] for x in state})==len(state)
        assert len({tuple(x['numeric']) for x in state})==len(state)
        assert state==sorted(state,key=preferred)
        for i,left in enumerate(state):
            assert sorted(left['numeric'])==list(range(case['w2'])) and left['uses']>=0
            close(left['idp'],measured(inverse(left['numeric'])))
            for right in state[i+1:]: assert distance(left['numeric'],right['numeric'])>=threshold
    true_score=measured(truth['true_k2'])
    group=[x for x in outputs if x['case_id']==name]
    assert {(x['method'],x['round']) for x in group}=={(m,r) for m in ('restart','population') for r in (0,1)}
    assert len(group)==4
    assert [(x['method'],x['round']) for x in case['commands']]==[('restart',0),('population',0),('population',1),('restart',1)]
    for plan in case['commands']:
        cmd=plan['command']; assert len(cmd)==11 and cmd[1]==plan['method']
        assert cmd[5:8]==[str(case['w1']),str(case['w2']),str(plan['search_seed'])]
        assert cmd[8:]==['100000','30',str(plan['round'])]
    for round_index in (0,1):
        pair=[x for x in group if x['round']==round_index]
        close(pair[0]['operation_traces'][0]['best_idp'],pair[1]['operation_traces'][0]['best_idp'])
        assert pair[0]['operation_traces'][0]['calls']==pair[1]['operation_traces'][0]['calls']
    for row in group:
        counts['rows']+=1
        assert row['mode']=='ciphertext_only_k2' and row['lengths']==[615,160]
        assert row['convention']==0 and row['messages_scored']==2
        assert not any(k.startswith(('truth_','true_')) for k in row)
        assert row['objective_calls']==row['target_objective_calls']==100000
        assert row['cut_cause']=='evaluations' and row['seconds']<row['seconds_limit']==30
        assert 0<=row['setup_seconds']<=row['seconds']
        assert row['objective_calls']==sum(row[k] for k in ('random_pool_calls','left_to_right_swap_calls','hill_climb_calls','perturbation_calls'))
        traces=row['operation_traces']; kicks=row['perturbation_traces']
        assert sum(x['calls'] for x in traces)+row['perturbation_calls']==row['objective_calls']
        assert sum(x['kind']=='initialization' for x in traces)==row['restart_starts']
        assert sum(x['completed'] for x in traces if x['kind']=='initialization')==row['restart_completions']
        assert sum(x['kind']=='hill_climb' for x in traces)==row['climb_starts']
        assert sum(x['completed'] for x in traces if x['kind']=='hill_climb')==row['climb_completions']
        for x in traces:
            if x['kind']=='initialization' and x['completed']:
                assert x['calls']==1000+20*case['w2']*(case['w2']-1)//2
        assert len(kicks)==row['perturbations_attempted']
        assert sum(x['scored'] for x in kicks)==row['perturbations_scored']==row['perturbation_calls']
        threshold=(2*case['w2']+4)//5
        changed=2*((threshold+1)//2)
        for kick in kicks:
            positions=kick['positions']; assert len(positions)==len(set(positions))==changed
            expected=kick['base_numeric'].copy()
            for a,b in zip(positions[::2],positions[1::2]): expected[a],expected[b]=expected[b],expected[a]
            assert expected==kick['perturbed_numeric']
            assert distance(expected,kick['base_numeric'])==kick['hamming_distance']==changed
            if kick['scored']: close(kick['idp'],measured(inverse(expected)))
            counts['perturbations']+=1
        if row['method']=='restart': assert not kicks
        else:
            assert row['population_minimum_distance']==threshold
            state=[]; next_id=1
            actions=sorted([(x['sequence'],'admit',x) for x in row['population_events']]+[(x['sequence'],'parent',x) for x in row['parent_choices']])
            assert [x[0] for x in actions]==list(range(1,len(actions)+1))
            for _,kind,action in actions:
                if kind=='parent':
                    parent=min(state,key=lambda x:(x['uses'],-x['idp'],x['numeric']))
                    assert action['selected_id']==parent['id'] and action['uses_before']==parent['uses']
                    state=[dict(x) for x in state]
                    selected=next(x for x in state if x['id']==parent['id']); selected['uses']+=1
                    assert action['uses_after']==selected['uses'] and state==action['population_after_use']
                    counts['parent_choices']+=1
                else:
                    assert action['before']==state
                    key=action['candidate_numeric']; score=action['candidate_idp']
                    close(score,measured(inverse(key))); counts['admission_scores']+=1
                    distances=[distance(key,x['numeric']) for x in state]
                    assert distances==action['distances_before']
                    neighbors=[x for x,d in zip(state,distances) if d<threshold]
                    assert [x['id'] for x in neighbors]==action['close_neighbor_ids']
                    new=None; replaced=-1
                    if neighbors:
                        if all(score>x['idp']+1e-12 for x in neighbors):
                            decision='replace_close_neighbors'
                            state=[x for x in state if x['id'] not in action['close_neighbor_ids']]
                            new={'id':next_id,'numeric':key,'idp':score,'uses':max(x['uses'] for x in neighbors)}
                        else: decision='reject_close_neighbor_score'
                    elif len(state)<5:
                        decision='append_diverse'; new={'id':next_id,'numeric':key,'idp':score,'uses':0}
                    else:
                        worst=min(state,key=lambda x:(x['idp'],[-v for v in x['numeric']]))
                        if score>worst['idp']+1e-12:
                            decision='replace_worst_diverse'; replaced=worst['id']
                            state=[x for x in state if x['id']!=worst['id']]
                            new={'id':next_id,'numeric':key,'idp':score,'uses':0}
                        else: decision='reject_worst_score'
                    assert decision==action['decision'] and replaced==action['replaced_worst_id']
                    if new: state.append(new); next_id+=1
                    state.sort(key=preferred)
                    assert state==action['after']; counts['population_events']+=1
                population_valid(state)
            assert state==row['final_population']
            assert len(row['parent_choices'])==len(kicks)
            for choice,kick in zip(row['parent_choices'],kicks):
                assert choice['selected_id']==kick['parent_id']
                assert next(x for x in choice['population_after_use'] if x['id']==choice['selected_id'])['numeric']==kick['base_numeric']
            origins=Counter(x['origin'] for x in row['population_events'])
            assert origins['prepared_survivor']==20*row['restart_completions']
            assert origins['offspring_local_optimum']==row['offspring_completed']
            assert origins['initial_local_optimum']+row['offspring_completed']==row['climb_completions']
            assert len(row['refresh_traces'])==row['population_refreshes']==row['offspring_completed']//4
            for refresh in row['refresh_traces']:
                assert refresh['offspring_completed']==4*refresh['number'] and refresh['mode']=='merge_same_rule'
                if refresh['completed']:
                    offered=row['population_events'][refresh['first_admission_event']-1:refresh['last_admission_event']]
                    assert len(offered)==20 and all(x['origin']=='prepared_survivor' for x in offered)
                    assert offered[0]['before']==refresh['before'] and offered[-1]['after']==refresh['after']
                    assert [(x['candidate_idp'],x['candidate_numeric']) for x in offered]==sorted([(x['candidate_idp'],x['candidate_numeric']) for x in offered],key=lambda t:(-t[0],t[1]))
                else: assert refresh['before']==refresh['after']
                counts['refreshes']+=1
        archive=row['archive']
        assert len(archive)==5 and len({tuple(x['k2']) for x in archive})==5
        for candidate in archive:
            assert sorted(candidate['k2'])==list(range(case['w2']))
            close(candidate['idp'],measured(candidate['k2'])); counts['archive_scores']+=1
        ranks=[x['rank'] for x in archive if x['k2']==truth['true_k2']]
        ext=evaluated[(name,row['method'],row['round'])]
        assert ext['true_k2_ranks']==ranks and ext['true_k2_in_archive']==bool(ranks)
        close(ext['true_k2_idp_external'],true_score)
        close(ext['best_archive_idp'],archive[0]['idp'])
        assert ext['true_idp_greater_than_all']==(true_score>archive[0]['idp']+1e-7)
        if not ranks: failed_margins.append(true_score-archive[0]['idp'])
        total=totals[row['method']]
        total['round_hits']+=bool(ranks); total['calls']+=row['objective_calls']; total['seconds']+=row['seconds']
        if ranks: total['cases'].add(name)
for method,total in totals.items():
    assert total['calls']==summary['total_calls_by_method'][method]==1600000
    assert total['round_hits']==summary['archive_hits_by_method'][method]
    assert len(total['cases'])==summary['cases_with_any_archive_hit_by_method'][method]
    close(total['seconds'],summary['total_seconds_by_method'][method])
    total['cases']=sorted(total['cases'])
assert sum(x>1e-7 for x in failed_margins)==summary['true_idp_greater_than_all_rows']
result={'passed':True,'scope':'Independent score and population replay; no solver rerun, K1 or historical test',
        'counts':dict(counts),'totals':totals,'protected_previous_crypto_files':252,
        'failure_margin_min':min(failed_margins),'failure_margin_max':max(failed_margins),
        'failed_rounds':len(failed_margins),'failed_rounds_truth_scores_higher':sum(x>1e-7 for x in failed_margins),
        'script_sha256':sha(Path(__file__)),
        'limits':['Only logged states and saved candidates checked, not every proposal.',
                  'Hamming diversity does not establish independent search basins.',
                  'Known widths, shared keys and one literary corpus per language.',
                  'No historical plaintext, key or language finding.']}
(ROOT/'work/phase10_root_verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(result,ensure_ascii=False,indent=2))

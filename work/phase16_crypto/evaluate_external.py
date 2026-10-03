"""Target metrics only AFTER both post-run audits; saved logs, no new scoring."""
from pathlib import Path
from collections import defaultdict
import csv,hashlib,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent.parent
PAIRS=((0,1),(2,3),(4,5),(6,7))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def inverse(key):
    out=[0]*len(key)
    for i,x in enumerate(key):out[x]=i
    return tuple(out)
def enc(text,key):return ''.join(text[c::len(key)]for c in key)
def main():
    if(HERE/'evaluation.json').exists():raise SystemExit('No replacement of external evaluation')
    m=json.loads((HERE/'manifest.json').read_text());guard=json.loads((HERE/'no_truth_verification.json').read_text())
    assert m['status']=='completed'and m['completed']and m['protected_unchanged']and len(m['runs'])==len(m['profiles'])==20
    assert guard['status']=='passed'and guard['manifest_sha256']==sha(HERE/'manifest.json')
    assert sha(HERE/'truth.jsonl')==m['truth_sha256']
    ts={t['case_id']:t for t in map(json.loads,(HERE/'truth.jsonl').read_text().splitlines())};cases={c['case_id']:c for c in m['cases']};assert len(ts)==len(cases)==4
    truth_keys={};case_metrics={}
    for identifier,t in ts.items():
        assert sorted(t['true_k1'])==list(range(20))and sorted(t['true_k2'])==list(range(25));truth_keys[identifier]=inverse(t['true_k2'])
        body=''.join(c.lower()for c in(ROOT/'work/phase5_language'/t['language_model']/'holdout.txt').read_text()if c.isascii()and c.isalpha());pos=t['sample_position']
        plain=[body[pos:pos+615],body[pos+615:pos+775]];assert list(map(len,plain))==[615,160]
        cipher=[enc(enc(text,t['true_k1']),t['true_k2'])for text in plain]
        for item,value in zip(cases[identifier]['ciphertext_files'],cipher):assert sha(ROOT/item['path'])==item['sha256']and(ROOT/item['path']).read_text().strip().lower()==value
        case_metrics[identifier]={'language_model':t['language_model'],'plant_seed':t['plant_seed'],'sample_position':pos,
            'true_k1':t['true_k1'],'true_k2':t['true_k2'],'plaintext_sha256':[hashlib.sha256(text.encode()).hexdigest()for text in plain]}
    results=[];groups=defaultdict(lambda:{'profiles':0,'target_visited':0,'target_ever_top5':0,'target_final_top5':0,'target_final_current':0,'exact_calls':0,'time_limit_reached_profiles':0,'time_stop_profiles':0,'converged_profiles':0,'full_sweeps':0})
    paired=defaultdict(dict)
    for profile,run in zip(m['profiles'],m['runs']):
        assert all(profile[k]==run[k]for k in('case_id','category','perturbation','policy'))
        target=truth_keys[profile['case_id']];s=run['summary'];assert sha(ROOT/profile['csv_path'])==run['csv_sha256']and sha(ROOT/profile['summary_path'])==run['summary_sha256']
        assert sha(ROOT/profile['start_path'])==profile['start_sha256']
        initial=tuple(map(int,(ROOT/profile['start_path']).read_text().split()));expected=list(target);npairs={'positive':1,'h4':2,'h8':4}[profile['perturbation']]
        for a,b in PAIRS[:npairs]:expected[a],expected[b]=expected[b],expected[a]
        assert initial==tuple(expected)and s['initial_numeric']==list(initial)and sum(x!=y for x,y in zip(initial,target))==npairs*2
        first_target=first_archive=None;count=0;seen=set();archive={};minimum=npairs*2
        with(ROOT/profile['csv_path']).open()as stream:
            for row in csv.DictReader(stream):
                count+=1;assert int(row['call'])==count
                numeric=tuple(map(int,row['candidate_numeric'].split(':')));assert sorted(numeric)==list(range(25))
                num=int(row['numerator']);seen.add(numeric);minimum=min(minimum,sum(a!=b for a,b in zip(numeric,target)))
                if numeric==target and first_target is None:first_target=count
                archive[numeric]=num;archive=dict(sorted(archive.items(),key=lambda item:(-item[1],item[0]))[:5])
                if target in archive and first_archive is None:first_archive=count
        assert count==s['calls']==s['backend_exact_calls'] and s['backend_legacy_calls']==0 and len(seen)==s['visited_unique']
        expected_archive=[{'rank':i+1,'numerator':num,'numeric':list(key)}for i,(key,num)in enumerate(archive.items())];assert expected_archive==s['archive']
        rank=next((i+1 for i,key in enumerate(archive)if key==target),None)
        accepted_target=[a['call']for a in s['accept_events']if tuple(a['to_numeric'])==target]
        first_current=1 if s['initial_scored']and initial==target else(min(accepted_target)if accepted_target else None)
        current_states=[initial]if s['initial_scored']else[];current_states +=[tuple(a['to_numeric'])for a in s['accept_events']]
        result={k:profile[k]for k in('case_id','category','perturbation','policy')};result.update(
            privileged=True,unknown_key_recovery_test=False,initial_hamming=npairs*2,target_visited=first_target is not None,first_target_call=first_target,
            target_ever_top5=first_archive is not None,first_target_top5_call=first_archive,final_archive_target_rank=rank,target_final_top5=rank is not None,
            final_numeric_is_target=tuple(s['final_numeric'])==target,first_current_target_call=first_current,
            observed_minimum_hamming=minimum if count else None,minimum_current_hamming=min(sum(a!=b for a,b in zip(key,target))for key in current_states)if current_states else None,
            exact_calls=count,visited_unique=len(seen),full_sweeps=s['full_sweeps'],partial_sweeps=s['partial_sweeps'],accepted_changes=s['accepted_changes'],
            convergence_observed=s['convergence_observed'],stop_reason=s['stop_reason'],time_limit_reached=s['time_limit_reached'],call_limit_reached=s['call_limit_reached'],
            seconds=s['seconds'],score_seconds=s['score_seconds'],setup_seconds=s['setup_seconds'],process_seconds=run['process_seconds'])
        assert not result['final_numeric_is_target']or result['target_visited'];assert not result['target_final_top5']or result['target_ever_top5']
        results.append(result);group=groups[f'{profile["category"]}_{profile["perturbation"]}_{profile["policy"]}'];group['profiles']+=1
        for label,field in(('target_visited','target_visited'),('target_ever_top5','target_ever_top5'),('target_final_top5','target_final_top5'),('target_final_current','final_numeric_is_target'),('time_limit_reached_profiles','time_limit_reached'),('converged_profiles','convergence_observed')):group[label]+=int(result[field])
        group['time_stop_profiles']+=int(result['stop_reason']=='time_limit')
        group['exact_calls']+=count;group['full_sweeps']+=s['full_sweeps']
        if profile['category']=='main':paired[profile['case_id'],profile['perturbation']][profile['policy']]=result
    assert len(results)==20 and len(paired)==8 and all(set(p)=={'A','B'} for p in paired.values())
    contrasts=[]
    for(identifier,perturb),policies in paired.items():
        a,b=policies['A'],policies['B'];contrasts.append({'case_id':identifier,'perturbation':perturb,'time_limit_in_pair':a['time_limit_reached']or b['time_limit_reached'],
            'A_minus_B_target_visited':int(a['target_visited'])-int(b['target_visited']),
            'A_minus_B_final_target':int(a['final_numeric_is_target'])-int(b['final_numeric_is_target']),
            'A_minus_B_final_archive_target':int(a['target_final_top5'])-int(b['target_final_top5']),
            'A_minus_B_actual_calls':a['exact_calls']-b['exact_calls']})
    total={'main_exact_calls':sum(r['exact_calls']for r in results if r['category']=='main'),'positive_exact_calls':sum(r['exact_calls']for r in results if r['category']=='positive_control'),
        'distinct_planted_keypairs':len({(tuple(t['true_k1']),tuple(t['true_k2']))for t in ts.values()}),'distinct_plaintext_offsets':len({t['sample_position']for t in ts.values()}),
        'process_seconds':sum(r['process_seconds']for r in results),'new_exact_IDP_calls':0,'new_legacy_IDP_calls':0,'new_searches':0}
    assert total['main_exact_calls']==m['main_exact_calls']and total['positive_exact_calls']==m['positive_exact_calls']
    output={'status':'evaluated','scope':'Privileged trajectories, exact K2 only; main/control outcomes separate','cases':case_metrics,'profiles':results,'groups':dict(groups),'paired_contrasts':contrasts,'totals':total,
        'truth_sha256':m['truth_sha256'],'manifest_sha256':sha(HERE/'manifest.json'),'new_exact_IDP_calls':0,'new_legacy_IDP_calls':0,
        'limits':'4cases/4planting seeds/2literary proxies. Two starts and two policies are paired, not16independent cases. No recovery from random starts, global basin/optimality claim, replication of shuffled source HC, retrospective cause, K1/plaintext or BLUME solution. No target score evaluated outside saved logs.'}
    (HERE/'evaluation.json').write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n');print(json.dumps({'groups':dict(groups),'totals':total},indent=2))
if __name__=='__main__':main()

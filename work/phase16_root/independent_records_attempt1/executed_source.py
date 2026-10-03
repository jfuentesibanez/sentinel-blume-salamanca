"""Independent saved-record replay. No target, plaintext or objective scoring."""
from pathlib import Path
from itertools import groupby
from collections import Counter
import csv,hashlib,json,math,time
ROOT=Path(__file__).resolve().parents[2]
HERE=ROOT/'work/phase16_crypto';AUDIT=Path(__file__).resolve().parent
PLAN='6613573bf1216923452b44982f7af1c4d7db21dd6400a3cbce3c9e11f9da9d9a'
PRE='41f19b0080be9f22d168b72bc9fe7f05cb5248441aa48bbbfc7813427a753a87'
ROOT_SOURCE='4199647757123900bcf922373c23d39a4a4ce1049d2a10fe4be6999661957f2a'
ROOT_WRAPPER='5bd8f2344a9becac2e2a32c7d4c8a2b926289bd78a32a48735a47f590e14beaf'
FIELDS=['call','sweep','move_index','move_kind','base_numerator','numerator','base_numeric','candidate_numeric','improves_base','accepted_immediate','archive_changed']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def key(text):
    k=tuple(map(int,text.split(':')));assert sorted(k)==list(range(25));return k
def event(call,selected,sweep,index,old,old_num,new,new_num):
    return dict(call=call,selected_call=selected,sweep=sweep,move_index=index,from_numeric=list(old),to_numeric=list(new),from_numerator=old_num,to_numerator=new_num)
def main():
    began=time.monotonic();dest=HERE/'no_truth_verification.json'
    assert not dest.exists() and not(HERE/'evaluation.json').exists()
    manifest_sha=sha(HERE/'manifest.json');m=load(HERE/'manifest.json');p=load(HERE/'plan20.json');sealed=load(HERE/'sealed_design.json')
    assert m['status']=='completed' and m['completed'] and m['protected_unchanged']
    assert sha(HERE/'plan20.json')==m['plan_sha256']==sealed['plan_sha256']==PLAN
    assert sha(AUDIT/'pre_ejecucion_independiente.txt')==PRE
    approval=load(HERE/'audit_approval.json')
    assert approval['root_approved'] is True and approval['independent_approved'] is True and approval['plan_sha256']==PLAN
    for prefix in('root','independent'):
        assert sha(ROOT/approval[prefix+'_review_path'])==approval[prefix+'_review_sha256']
    assert m['audit_approval']==sealed['audit_approval']==approval
    assert m['truth_sha256']==sealed['truth_sha256'] # Metadata only; truth file never opened.
    for name,digest in p['resources'].items():assert sha(HERE/name)==digest
    baseline=load(AUDIT/'frozen_before.json');assert sha(AUDIT/'frozen_before.json')==p['baseline_sha256']
    assert baseline['hashes']==p['protected_before']==m['protected_before']==m['protected_after']
    for name,digest in baseline['hashes'].items():assert sha(ROOT/name)==digest
    for item in p['models_and_holdouts']:assert sha(ROOT/item['path'])==item['sha256']
    for field in p:
        if field not in('status','runs','cases','profiles'):assert m[field]==sealed[field]==p[field],field
    assert m['cases']==sealed['cases'] and m['profiles']==sealed['profiles']
    assert len(m['profiles'])==len(m['runs'])==20 and len(m['cases'])==4
    for case,original in zip(m['cases'],p['cases']):
        assert {k:case[k]for k in original}==original
        for item,path,length in zip(case['ciphertext_files'],case['ciphertext_paths'],(615,160)):
            assert item['path']==path and sha(ROOT/path)==item['sha256']
            text=(ROOT/path).read_text().strip();assert len(text)==length and all('A'<=c<='Z'for c in text)
    for profile,original in zip(m['profiles'],p['profiles']):
        assert {k:profile[k]for k in original}==original and sha(ROOT/profile['start_path'])==profile['start_sha256']
    moves=load(HERE/'moves.json')['moves'];assert len(moves)==16649
    assert len({tuple(move['p'])for move in moves})==16649
    for i,move in enumerate(moves,1):assert move['index']==i and sorted(move['p'])==list(range(25))
    cross_scores={c['case_id']:{}for c in m['cases']};initial_inputs={};paired_initial_scores={}
    checks=[];all_rows=all_markers=main_calls=positive_calls=0
    stop_counts=Counter();convergences=partials=time_stops=deadlines=0
    for profile,run in zip(m['profiles'],m['runs']):
        assert all(profile[k]==run[k]for k in('case_id','category','perturbation','policy'))
        assert run['status']=='recorded' and run['returncode']==0 and run['timed_out'] is False
        assert sha(ROOT/profile['csv_path'])==run['csv_sha256'] and sha(ROOT/profile['summary_path'])==run['summary_sha256']
        s=load(ROOT/profile['summary_path']);assert s==run['summary']
        start=tuple(map(int,(ROOT/profile['start_path']).read_text().split()));assert sorted(start)==list(range(25)) and list(start)==s['initial_numeric']
        label=(profile['case_id'],profile['perturbation']);assert label not in initial_inputs or initial_inputs[label]==start;initial_inputs[label]=start
        assert s['mode']=='privileged_k2_trajectory' and s['policy']==profile['policy']
        assert(s['w1'],s['w2'],s['convention'])==(20,25,0)and s['lengths']==[615,160]and s['source_moves']==16649
        assert s['call_limit']==profile['max_calls']and s['sweep_limit']==profile['max_sweeps']and s['calls']<=profile['max_calls']
        den=s['denominator'];assert s['scale']==8388608 and den==8388608*760
        improve=lambda new,old:(new-old)*10**12>den
        state=start;value=None;count=0;archive=[];seen={};accepts=[];sweeps=[]
        def register(row):
            nonlocal count,archive
            count+=1;assert int(row['call'])==count
            k=key(row['candidate_numeric']);num=int(row['numerator']);assert abs(num)<=s['checked_absolute_numerator_bound']
            for history in(seen,cross_scores[profile['case_id']]):
                assert k not in history or history[k]==num;history[k]=num
            before=tuple(archive)
            if not any(old_key==k for old_num,old_key in archive):archive=sorted(archive+[(num,k)],key=lambda item:(-item[0],item[1]))[:5]
            assert row['archive_changed']in('0','1')and(row['archive_changed']=='1')==(before!=tuple(archive))
            for field in('improves_base','accepted_immediate'):assert row[field]in('0','1')
            return k,num
        with(ROOT/profile['csv_path']).open(newline='')as stream:
            reader=csv.DictReader(stream);assert reader.fieldnames==FIELDS
            first=next(reader,None)
            if first is not None:
                assert int(first['sweep'])==int(first['move_index'])==0 and int(first['move_kind'])==-1
                candidate,value=register(first);assert candidate==key(first['base_numeric'])==state and int(first['base_numerator'])==value
                assert first['improves_base']==first['accepted_immediate']=='0'
                if profile['category']=='main':
                    observed=(state,value);assert label not in paired_initial_scores or paired_initial_scores[label]==observed;paired_initial_scores[label]=observed
            for sweep_number,group in groupby(reader,key=lambda row:int(row['sweep'])):
                assert sweep_number==len(sweeps)+1 and sweep_number<=profile['max_sweeps']
                sweep_start=state;sweep_num=value;start_call=count
                best_key,best_num,best_call,best_index=state,value,0,0;changed=False;proposals=0
                for row in group:
                    proposals+=1;index=int(row['move_index']);assert index==proposals<=16649
                    move=moves[index-1];assert int(row['move_kind'])==move['kind']
                    base=state if profile['policy']=='A'else sweep_start;base_num=value if profile['policy']=='A'else sweep_num
                    assert key(row['base_numeric'])==base and int(row['base_numerator'])==base_num
                    candidate,num=register(row);assert candidate==tuple(base[j]for j in move['p'])
                    improves=improve(num,base_num);assert(row['improves_base']=='1')==improves
                    immediate=profile['policy']=='A'and improves;assert(row['accepted_immediate']=='1')==immediate
                    if immediate:
                        accepts.append(event(count,count,sweep_number,index,state,value,candidate,num));state,value=candidate,num;changed=True
                    if profile['policy']=='B'and num>best_num:best_key,best_num,best_call,best_index=candidate,num,count,index
                complete=proposals==16649;assert proposals>0
                if complete and profile['policy']=='B'and improve(best_num,sweep_num):
                    accepts.append(event(count,best_call,sweep_number,best_index,state,value,best_key,best_num));state,value=best_key,best_num;changed=True
                sweeps.append(dict(sweep=sweep_number,start_call=start_call,end_call=count,proposals=proposals,complete=complete,start_numeric=list(sweep_start),final_numeric=list(state),start_numerator=sweep_num,final_numerator=value,improvement_accepted=changed,selected_call=best_call,selected_move_index=best_index,selected_numerator=best_num,convergence_observed=complete and not changed,partial_best_admitted=False))
        assert count==s['calls']==s['backend_exact_calls']==run['exact_calls_started'] and s['backend_legacy_calls']==run['legacy_calls_started']==0
        assert s['initial_scored']==bool(count)and s['final_numeric']==list(state)and s['final_numerator']==value
        assert s['archive']==[{'rank':i+1,'numerator':num,'numeric':list(k)}for i,(num,k)in enumerate(archive)]
        assert s['visited_unique']==len(seen)and s['accept_events']==accepts and s['accepted_changes']==len(accepts)and s['sweep_events']==sweeps
        assert s['full_sweeps']==sum(e['complete']for e in sweeps)and s['partial_sweeps']==sum(not e['complete']for e in sweeps)
        assert s['convergence_observed']==any(e['convergence_observed']for e in sweeps)
        assert s['partial_sweeps']<=1 and(not s['partial_sweeps']or not sweeps[-1]['complete'])
        assert s['seconds_limit']==30 and all(math.isfinite(s[k])and s[k]>=0 for k in('seconds','setup_seconds','score_seconds','soft_excess_seconds'))
        assert s['setup_seconds']+s['score_seconds']<=s['seconds']<=run['process_seconds']
        assert s['soft_excess_seconds']==max(0,s['seconds']-30)and s['time_limit_reached']==(s['seconds']>=30)
        assert s['call_limit_reached']==(count>=profile['max_calls'])
        stop=s['stop_reason'];assert stop in('call_limit','time_limit','converged','sweep_limit')
        if s['call_limit_reached']:assert stop=='call_limit'
        if stop=='call_limit':assert s['call_limit_reached']
        if stop=='time_limit':assert s['time_limit_reached']and not s['call_limit_reached']
        if stop=='converged':assert s['convergence_observed']and not s['call_limit_reached']
        if stop=='sweep_limit':assert s['full_sweeps']==profile['max_sweeps']and not s['convergence_observed']and not s['call_limit_reached']
        trace=ROOT/run['calls_path'];assert sha(trace)==run['calls_sha256'];markers=0
        with trace.open()as stream:
            for line in stream:markers+=1;assert line.strip()==f'@calls 0 {markers}'
        assert markers==count and run['stdout']==''
        all_rows+=count;all_markers+=markers;stop_counts[stop]+=1;convergences+=s['convergence_observed'];partials+=s['partial_sweeps'];time_stops+=stop=='time_limit';deadlines+=s['time_limit_reached']
        if profile['category']=='main':main_calls+=count
        else:assert profile['category']=='positive_control';positive_calls+=count
        checks.append({k:profile[k]for k in('case_id','category','perturbation','policy') }|{'rows_checked':count,'distinct_keys_in_profile':len(seen),'accepted_changes':len(accepts),'full_sweeps':s['full_sweeps'],'partial_sweeps':s['partial_sweeps'],'stop_reason':stop,'convergence_observed':s['convergence_observed']})
    assert main_calls==m['main_exact_calls']<=799168 and positive_calls==m['positive_exact_calls']<=66600
    assert all_rows==all_markers==m['total_exact_calls']==main_calls+positive_calls
    launch=load(AUDIT/'main_launch_receipt.json');assert launch['status']=='completed'and launch['attempt']==launch['maximum_attempts']==1 and launch['returncode']==0 and not launch['timed_out']
    assert launch['plan_sha256']==PLAN and launch['manifest_sha256']==manifest_sha and launch['sealed_manifest_sha256']==sha(HERE/'sealed_design.json')and launch['launcher_sha256']==sha(AUDIT/'main_launcher.py')
    assert launch['exact_calls_started']==all_rows and launch['legacy_calls_started']==0
    assert sha(AUDIT/'main_stdout.jsonl')==launch['stdout_sha256']and sha(AUDIT/'main_stderr.txt')==launch['stderr_sha256']
    printed=[json.loads(line)for line in(AUDIT/'main_stdout.jsonl').read_text().splitlines()];assert printed==[{k:v for k,v in run.items()if k not in('stdout','summary')}for run in m['runs']]
    persisted={i['file']:i for i in launch['persisted_call_logs']};assert len(persisted)==20
    assert set(persisted)=={run['calls_path']for run in m['runs']}
    for run in m['runs']:
        item=persisted[run['calls_path']];assert item['sha256']==run['calls_sha256']and item['legacy_started']==0and item['exact_started']==run['exact_calls_started']
    parse=load(AUDIT/'main_launcher_parse_failure.json');assert parse['script_code_executed']is False and parse['main_processes_started']==parse['new_IDP_calls']==parse['panel_attempts_before_repair']==0 and parse['sealed_data_changed']is False
    numerical=load(AUDIT/'post_run_audit.json');receipt=load(AUDIT/'audit_attempts/attempt1.json')
    assert sha(AUDIT/'post_run_audit.py')==ROOT_SOURCE and sha(AUDIT/'run_post_audit.py')==ROOT_WRAPPER
    assert numerical['status']=='passed'and numerical['manifest_sha256']==manifest_sha and numerical['rows_replayed']==all_rows and numerical['profiles_checked']==20
    assert numerical['truth_read']is False and numerical['target_comparisons']==numerical['legacy_reference_calls_started']==0
    assert numerical['exact_reference_calls_started']<=40
    assert receipt['status']=='passed'and receipt['attempt']==receipt['maximum_attempts']==1 and receipt['returncode']==0 and not receipt['timed_out']and receipt['hard_timeout_seconds']==40
    assert receipt['source_sha256']==ROOT_SOURCE and receipt['wrapper_sha256']==ROOT_WRAPPER and receipt['exact_reference_calls_started']==numerical['exact_reference_calls_started']and receipt['legacy_reference_calls_started']==0
    assert receipt['result_sha256']==sha(AUDIT/'post_run_audit.json')and len(list((AUDIT/'audit_attempts').glob('attempt*.json')))==1
    for name,field in(('stdout1.txt','stdout_sha256'),('stderr1.txt','stderr_sha256')):assert sha(AUDIT/'audit_attempts'/name)==receipt[field]
    assert receipt['progress_sha256']==sha(AUDIT/'audit_progress.json')
    assert sha(HERE/'manifest.json')==manifest_sha and sha(HERE/'plan20.json')==PLAN and sha(AUDIT/'pre_ejecucion_independiente.txt')==PRE and not(HERE/'evaluation.json').exists()
    result={'status':'passed','manifest_sha256':manifest_sha,'plan_sha256':PLAN,'scope':'Independent grouped-sweep replay of all saved proposals, archives, acceptance events, keys, counters and hashes; no scorer or target comparison','profiles_checked':20,'main_rows_checked':main_calls,'positive_rows_checked':positive_calls,'rows_checked':all_rows,'markers_checked':all_markers,'resources_checked':23,'protected_files_checked':2793,'models_holdouts_hashes_checked':4,'paired_starts_checked':8,'stop_counts':dict(stop_counts),'convergence_flags':convergences,'partial_sweeps':partials,'time_stop_profiles':time_stops,'time_limit_reached_profiles':deadlines,'cross_profile_same_case_score_consistency':True,'distinct_keys_per_case':{k:len(v)for k,v in cross_scores.items()},'new_IDP_calls':0,'new_exact_IDP_calls':0,'new_legacy_IDP_calls':0,'truth_read':False,'plaintext_read':False,'target_compared':False,'preaudit_preserved_sha256':PRE,'main_launcher_receipt_sha256':sha(AUDIT/'main_launch_receipt.json'),'launcher_parse_failure_IDP_calls':0,'separate_root_numerical_audit':{'path':'work/phase16_root/post_run_audit.json','sha256':sha(AUDIT/'post_run_audit.json'),'receipt_path':'work/phase16_root/audit_attempts/attempt1.json','receipt_sha256':sha(AUDIT/'audit_attempts/attempt1.json'),'status':'passed','exact_IDP_calls':numerical['exact_reference_calls_started'],'legacy_IDP_calls':0,'attempts':1},'profiles':checks,'audit_script_sha256':sha(Path(__file__)),'seconds':time.monotonic()-began}
    local=AUDIT/'post_records_check_independiente.json';assert not local.exists();local.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items()if k!='profiles'},ensure_ascii=False,indent=2))
if __name__=='__main__':main()

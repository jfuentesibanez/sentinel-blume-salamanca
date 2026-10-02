"""Audit saved fixed-anchor records; no target comparison and no scorer calls."""
from pathlib import Path
from collections import Counter
import csv,hashlib,json,math,struct,time
ROOT=Path(__file__).resolve().parents[2]
HERE=ROOT/'work/phase15_crypto'
AUDIT=Path(__file__).resolve().parent
SHA_PLAN='a3e3fb8e7cb4b212cad95a4d4d1f5d6b79ea44035f383489b0837433afc54128'
SHA_PRE='75af88f71071a82a19d9201e418ef59acf2ec6691ff52a451b989c959d042576'
PRIOR=('crypto','phase2_crypto','phase3_crypto','phase4_crypto','phase5_crypto','phase5_language','phase7_crypto','phase8_crypto','phase9_crypto','phase10_crypto','phase11_crypto','phase14_crypto')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def main():
    began=time.monotonic()
    destination=HERE/'no_truth_verification.json'
    assert not destination.exists(),'Refusing to overwrite audit guard'
    assert not (HERE/'evaluation.json').exists(),'Target evaluation must follow this audit'
    assert sha(AUDIT/'pre_ejecucion_independiente.txt')==SHA_PRE
    manifest_sha=sha(HERE/'manifest.json')
    plan=load(HERE/'plan12.json');manifest=load(HERE/'manifest.json');sealed=load(HERE/'sealed_design.json')
    assert sha(HERE/'plan12.json')==SHA_PLAN==manifest['plan_sha256']==sealed['plan_sha256']
    assert manifest['completed'] and manifest['protected_unchanged'] and manifest['all_profiles_complete'] and manifest['status']=='completed'
    assert len(manifest['runs'])==len(manifest['profiles'])==12 and len(manifest['cases'])==4
    for name,declared in plan['resources'].items():assert sha(HERE/name)==declared,name
    for item in plan['models_and_holdouts']:assert sha(ROOT/item['path'])==item['sha256']
    current={str(p.relative_to(ROOT)):sha(p) for folder in PRIOR for p in sorted((ROOT/'work'/folder).rglob('*')) if p.is_file()}
    assert current==plan['protected_before']==manifest['protected_before']
    for key in plan:
        if key not in ('status','runs','cases','profiles'):
            assert manifest[key]==sealed[key]==plan[key],key
    assert manifest['cases']==sealed['cases'] and manifest['profiles']==sealed['profiles']
    for case,original in zip(manifest['cases'],plan['cases']):
        assert {k:case[k] for k in original}==original
        assert len(case['ciphertext_files'])==2
        for item,path,length in zip(case['ciphertext_files'],case['ciphertext_paths'],(615,160)):
            assert item['path']==path and sha(ROOT/path)==item['sha256']
            ciphertext=(ROOT/path).read_text().strip()
            assert len(ciphertext)==length and all('A'<=c<='Z' for c in ciphertext)
    for profile,original in zip(manifest['profiles'],plan['profiles']):
        assert {k:profile[k] for k in original}==original
        assert sha(ROOT/profile['anchor_path'])==profile['anchor_sha256']
    geometry=load(HERE/'moves.json')['moves']
    assert len(geometry)==16649
    assert len({tuple(m['p']) for m in geometry})==16649
    for index,m in enumerate(geometry,1):
        assert m['index']==index and sorted(m['p'])==list(range(25)) and m['p']!=list(range(25))
    assert Counter(m['kind'] for m in geometry)=={0:6924,1:953,2:8772}
    model_bound={}
    for model in ('de_fold','fr_fold'):
        values=struct.unpack('<676f',(ROOT/'work/phase5_language'/model/'model.bin').read_bytes()[:676*4])
        numerators=[]
        for value in values:
            assert math.isfinite(value)
            n,d=value.as_integer_ratio();assert 8388608%d==0
            numerators.append(n*(8388608//d))
        model_bound[model]=max(max(map(abs,numerators)),7*8388608)*760
    results=[];total_rows=total_markers=total_decisions=total_edges=0
    max_score_difference=max_matrix_difference=0.0
    for index,(profile,run) in enumerate(zip(manifest['profiles'],manifest['runs'])):
        assert (run['case_id'],run['anchor_label'])==(profile['case_id'],profile['anchor_label'])
        assert run['status']=='recorded' and run['returncode']==0 and run['timed_out'] is False
        for path_field,hash_field in (('csv_path','csv_sha256'),('summary_path','summary_sha256')):
            assert sha(ROOT/profile[path_field])==run[hash_field]
        summary=load(ROOT/profile['summary_path']);assert summary==run['summary']
        anchor=tuple(map(int,(ROOT/profile['anchor_path']).read_text().split()))
        assert sorted(anchor)==list(range(25)) and list(anchor)==summary['anchor_numeric']
        assert summary['mode']=='static' and summary['anchor_updated'] is False
        assert (summary['w1'],summary['w2'],summary['convention'])==(20,25,0)
        assert summary['lengths']==[615,160] and summary['source_moves']==16649
        assert summary['requested_states']==summary['states_completed']==summary['legacy_calls']==summary['exact_calls']==16650
        assert summary['idp_equivalent_calls']==33300 and summary['stop_reason']=='complete'
        assert summary['scale']==8388608 and summary['denominator_shift']==23 and summary['idp_denominator']==8388608*760
        model=next(c['language_model'] for c in manifest['cases'] if c['case_id']==profile['case_id'])
        assert summary['checked_absolute_numerator_bound']==model_bound[model]
        assert summary['seconds_limit']==30 and summary['soft_excess_seconds']==0
        timings=[summary[k] for k in ('setup_seconds','legacy_seconds','exact_seconds','seconds')]
        assert all(math.isfinite(t) and t>=0 for t in timings)
        assert sum(timings[:3])<=timings[3]<30
        assert math.isfinite(run['process_seconds']) and run['process_seconds']>=timings[3]
        calls_path=ROOT/run['calls_path'];assert sha(calls_path)==run['calls_sha256']
        markers=[]
        for line in calls_path.read_text().splitlines():
            assert line.startswith('@calls '),line
            parts=line.split();assert len(parts)==3
            markers.append(tuple(map(int,parts[1:])))
        assert len(markers)==33300
        for state in range(1,16651):
            assert markers[2*state-2]==(state,state-1)
            assert markers[2*state-1]==(state,state)
        assert run['legacy_calls_started']==run['exact_calls_started']==16650
        assert run['stdout']==''
        total_markers+=len(markers)
        seen=set();rows=decisions=edges_changed=0;observed_score_max=observed_matrix_max=0.0
        den=summary['idp_denominator'];base_legacy=None;base_num=None
        with (ROOT/profile['csv_path']).open(newline='') as stream:
            reader=csv.DictReader(stream);assert reader.fieldnames==plan['csv_columns']
            for i,row in enumerate(reader):
                assert int(row['index'])==i and int(row['kind'])==(-1 if i==0 else geometry[i-1]['kind'])
                key=anchor if i==0 else tuple(anchor[j] for j in geometry[i-1]['p'])
                assert sorted(key)==list(range(25)) and key not in seen;seen.add(key)
                legacy=float(row['legacy']);num=int(row['exact_numerator']);matrix_error=float(row['matrix_max_abs_diff'])
                assert math.isfinite(legacy) and math.isfinite(matrix_error) and matrix_error>=0
                assert abs(num)<=summary['checked_absolute_numerator_bound']
                if i==0:base_legacy,base_num=legacy,num
                assert row['legacy_improves_anchor'] in ('0','1') and row['exact_improves_anchor'] in ('0','1')
                li=legacy>base_legacy+1e-12;ei=(num-base_num)*10**12>den
                assert li==(row['legacy_improves_anchor']=='1') and ei==(row['exact_improves_anchor']=='1')
                decisions+=li!=ei
                score_error=abs(legacy-num/den)
                observed_score_max=max(observed_score_max,score_error);observed_matrix_max=max(observed_matrix_max,matrix_error)
                traces=[]
                for backend in ('legacy','exact'):
                    trace=[int(s) for s in row[backend+'_edges'].split(':')]
                    assert len(trace)==20 and all(0<=e<400 for e in trace)
                    assert len({e//20 for e in trace})==len({e%20 for e in trace})==20
                    forced=int(row[backend+'_forced']);assert forced in (0,1)
                    diagonals=[j for j,e in enumerate(trace) if e//20==e%20]
                    assert diagonals==([19] if forced else [])
                    traces.append(trace)
                edges_changed+=traces[0]!=traces[1];rows+=1
        assert rows==len(seen)==16650
        assert decisions==summary['improvement_decision_discrepancies'] and edges_changed==summary['greedy_edge_discrepancies']
        assert observed_score_max==summary['max_score_absolute_difference']
        assert observed_matrix_max==summary['max_matrix_absolute_difference']
        total_rows+=rows;total_decisions+=decisions;total_edges+=edges_changed
        max_score_difference=max(max_score_difference,observed_score_max);max_matrix_difference=max(max_matrix_difference,observed_matrix_max)
        results.append({'profile_index':index,'case_id':profile['case_id'],'anchor_label':profile['anchor_label'],'states_checked':rows,'distinct_keys_in_profile':len(seen),'markers_checked':len(markers),'improvement_decision_discrepancies':decisions,'greedy_edge_discrepancies':edges_changed,'max_score_absolute_difference':observed_score_max,'max_matrix_absolute_difference':observed_matrix_max,'process_seconds':run['process_seconds'],'legacy_seconds':summary['legacy_seconds'],'exact_seconds':summary['exact_seconds']})
    assert total_rows==manifest['legacy_calls']==manifest['exact_calls']==199800
    assert total_markers==399600 and manifest['all_profiles_complete']
    numerical=load(AUDIT/'post_run_audit.json');receipt=load(AUDIT/'audit_attempts/attempt1.json')
    assert numerical['passed'] and numerical['manifest_sha256']==manifest_sha and numerical['rows_replayed']==199800 and numerical['all_profiles_complete']
    assert numerical['audit_backend_calls']=={'legacy':24,'exact':24} and numerical['audit_IDP_equivalent_calls']==48
    assert receipt['status']=='passed' and receipt['audit_backend_calls']=={'legacy':24,'exact':24} and receipt['audit_IDP_equivalent_calls']==48
    assert sha(AUDIT/'post_run_audit.py')==receipt['source_sha256']
    assert len(list((AUDIT/'audit_attempts').glob('attempt*.json')))==1
    assert sha(HERE/'manifest.json')==manifest_sha and sha(HERE/'plan12.json')==SHA_PLAN
    assert sha(AUDIT/'pre_ejecucion_independiente.txt')==SHA_PRE
    assert not (HERE/'evaluation.json').exists()
    result={'status':'passed','manifest_sha256':manifest_sha,'plan_sha256':SHA_PLAN,'scope':'Saved CSV, markers, geometry, flags, timings and hashes; no target comparison or objective scoring','profiles_checked':12,'all_profiles_complete':True,'rows_checked':total_rows,'backend_markers_checked':total_markers,'principal_legacy_calls':199800,'principal_exact_calls':199800,'principal_IDP_equivalent_calls':399600,'time_cuts':0,'failed_profiles':0,'resources_checked':len(plan['resources']),'protected_files_checked':len(current),'model_holdout_hashes_checked':4,'new_IDP_calls':0,'new_legacy_calls':0,'new_exact_calls':0,'truth_read':False,'plaintext_read':False,'target_compared':False,'preaudit_preserved_sha256':SHA_PRE,'improvement_decision_discrepancies':total_decisions,'greedy_edge_discrepancies':total_edges,'max_score_absolute_difference':max_score_difference,'max_matrix_absolute_difference':max_matrix_difference,'profiles':results,'separate_root_numerical_audit':{'path':'work/phase15_root/post_run_audit.json','sha256':sha(AUDIT/'post_run_audit.json'),'status':'passed','audit_legacy_calls':24,'audit_exact_calls':24,'audit_IDP_equivalent_calls':48,'attempts':1,'failed_attempts':0,'receipt_sha256':sha(AUDIT/'audit_attempts/attempt1.json')},'audit_script_sha256':sha(Path(__file__)),'seconds':time.monotonic()-began}
    destination.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='profiles'},ensure_ascii=False,indent=2))
if __name__=='__main__':main()

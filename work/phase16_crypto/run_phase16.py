"""Plan/audit first. External truth and trajectories only after double approval."""
from pathlib import Path
import argparse,hashlib,json,subprocess,time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent.parent
CASES=(('de_fold',20262401),('de_fold',20262402),('fr_fold',20262403),('fr_fold',20262404))
PAIRS=((0,1),(2,3),(4,5),(6,7));BASELINE=ROOT/'work/phase16_root/frozen_before.json'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,v):p.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n')
def enc(text,key):return ''.join(text[c::len(key)] for c in key)
def inverse(key):
    out=[0]*len(key)
    for i,x in enumerate(key):out[x]=i
    return out
def protected():
    baseline=json.loads(BASELINE.read_text());out={path:sha(ROOT/path) for path in baseline['hashes']}
    assert len(out)==baseline['count']==2793 and out==baseline['hashes']
    return out
def resources():
    names=('trajectory.cpp','trajectory','exact_scorer.h','generate_keys.cpp','generate_keys','moves.json','build.py','build_record.json','check_controls.py','control_results.json','run_phase16.py','evaluate_external.py','IMPLEMENTATION_DECISIONS.txt','LEEME.txt','ATTRIBUTION.txt','LICENSE-CrypTool-2.txt','seed_audit.json')
    out={name:sha(HERE/name) for name in names}
    for p in sorted((HERE/'control_attempts').glob('*')):
        if p.is_file():out[str(p.relative_to(HERE))]=sha(p)
    return out
def prior_use_audit():
    baseline=json.loads(BASELINE.read_text());seeds={s for _,s in CASES};mentions=[];path_mentions=[];structured_hits=[];checked_records=[]
    allowed='work/phase15_root/next_diagnostic_review.txt'
    for path,digest in baseline['hashes'].items():
        file=ROOT/path;body=file.read_bytes();assert hashlib.sha256(body).hexdigest()==digest
        for seed in seeds:
            if str(seed).encode() in body:mentions.append({'path':path,'seed':seed})
            if str(seed) in path:path_mentions.append({'path':path,'seed':seed})
        if file.suffix not in ('.json','.jsonl'):continue
        try:
            if file.suffix=='.json':records=[json.loads(body)]
            else:records=[json.loads(line) for line in body.splitlines() if line.strip()]
        except (UnicodeDecodeError,json.JSONDecodeError):continue
        checked_records.append({'path':path,'sha256':digest,'records':len(records)})
        def visit(v,where=''):
            if isinstance(v,dict):
                for key,item in v.items():
                    if 'seed' in key.lower() and isinstance(item,int) and item in seeds:structured_hits.append((path,where+'.'+key,item))
                    if 'seed' in key.lower() and isinstance(item,list):
                        for x in item:
                            if isinstance(x,int) and x in seeds:structured_hits.append((path,where+'.'+key,x))
                    visit(item,where+'.'+key)
            elif isinstance(v,list):
                for i,item in enumerate(v):visit(item,where+f'[{i}]')
        for record in records:visit(record)
    assert not structured_hits and not path_mentions and all(m['path']==allowed for m in mentions),(structured_hits,path_mentions,mentions)
    result={'status':'passed_no_prior_use','planting_seeds':sorted(seeds),'baseline_sha256':sha(BASELINE),'baseline_files_checked':baseline['count'],
        'content_mentions':mentions,'prior_case_path_mentions':path_mentions,'structured_prior_seed_uses':structured_hits,'json_jsonl_records_checked':checked_records,
        'only_allowed_concept_mention':allowed,'no_truth_generated':True,'new_IDP_calls':0}
    save(HERE/'seed_audit.json',result);return result
def plan():
    if (HERE/'sealed_design.json').exists():raise SystemExit('No plan edits after seal')
    build=json.loads((HERE/'build_record.json').read_text());controls=json.loads((HERE/'control_results.json').read_text())
    assert controls['status']=='passed' and controls['actual_exact_IDP_calls_all_attempts']==controls['actual_legacy_IDP_calls_all_attempts']==0
    assert sha(HERE/'trajectory.cpp')==build['source_sha256']==controls['source_sha256'] and sha(HERE/'trajectory')==build['binary_sha256']==controls['binary_sha256']
    assert sha(HERE/'exact_scorer.h')==build['exact_header_sha256']==controls['exact_header_sha256']
    moves=json.loads((HERE/'moves.json').read_text())['moves'];assert len(moves)==16649
    mappings={tuple(m['p']) for m in moves}
    for a,b in PAIRS:
        p=list(range(25));p[a],p[b]=p[b],p[a];assert tuple(p) in mappings
    seed_check=prior_use_audit()
    p={'phase':16,'date':'2026-10-03','status':'draft_for_double_audit_no_truth_no_trajectories',
       'scope':'Privileged exact-K2 trajectories, not ciphertext-only recovery. No K1, random-pool test or historical BLUME.',
       'expected_cases':4,'expected_main_trajectories':16,'expected_positive_controls':4,'expected_profiles':20,
       'widths':[20,25],'lengths':[615,160],'convention':0,'source_moves':16649,'source_order':'Frozen construction order, no shuffle/RNG of traversal',
       'policies':{'A':'source-order immediate-update sweep: accept strict exact improvement and continue current sweep',
                   'B':'fixed-anchor best-improvement sweep: choose greatest numerator, first source index on tie; accept only after entire sweep'},
       'acceptance':'(candidate_num-base_num)*10^12 > denominator; exact rational1/10^12, same binary32 objective copied fromphase15',
       'archive':'Every scored initial/proposal offered BEFORE stopping; distinct numeric; numerator descending then numeric lexicographic; repeated proposals always charged',
       'visited':'Every scored initial and proposal; distinct count separate from calls; no target recognition in program',
       'perturbation_rule':{'pairs':[list(x) for x in PAIRS],'h4_first_pairs':2,'h8_first_pairs':4,'positive_first_pairs':1,'native_pair_membership_checked':True,
                            'distance':'Hamming exactly4/8/2; graph distance only bounded above2/4/1; no score-dependent positions'},
       'main_call_limit':49948,'main_max_sweeps':3,'main_calls_max':799168,
       'positive_call_limit':16650,'positive_max_sweeps':1,'positive_calls_max':66600,'combined_trajectory_calls_max':865768,
       'soft_seconds':30,'hard_process_seconds':40,'cache':False,'retries':0,'truth_evaluations_extra':0,
       'terminal_rule':'At complete sweep, B acceptance and convergence flag observed BEFORE checking global limits. Partial B never accepts. Stop cause prioritycall_limit>time_limit>converged>sweep_limit; independent convergence flag.',
       'empty_sweep':'No sweep event/partial count if cut before first proposal; avoid repeated end_call.',
       'positive_controls':'Scientific outcomes, not success asserts or a gate; separate denominator/category; run after16main, no resampling or tuning',
       'metrics_external_primary':['target_visited_including_initial','first_target_call','target_final_top5','final_archive_target_rank','final_numeric_is_target'],
       'metrics_external_secondary':['target_ever_top5','first_target_top5_call','first_current_target_call','observed_minimum_hamming','minimum_current_hamming',
                                     'visited_unique','full_sweeps','partial_sweeps','accepted_changes','convergence_observed','stop_reason',
                                     'call_limit_reached','time_limit_reached','time_limit_reached_profiles','time_stop_profiles','actual_exact_calls','setup/score/total/process_seconds',
                                     'distinct_planted_keypairs','distinct_plaintext_offsets','paired A_minus_B visited/final/archive/calls with time-limit flag'],
       'gap_rule':'No extra true-key scoring. True score gaps only if already present in saved proposals; current evaluator does not add any gap metric.',
       'post_run_audit':{'exact_reference_calls_max':40,'sampling':'Initial and last evaluated per each20profiles, repeats charged',
                         'backend':'Independent Python direct feasible-offset pairs, no sliding; one attempt/hard40s, no target'},
       'order_rule':'Main by case,h4/h8; A/B order alternates(case_index+perturbation_index)%2; four positive B controls afterwards',
       'time_accounting':'Score timer includes undo2+exact scorer; overallclock includes setup and per-proposal flushed CSV/counter logging; equal caps do not mean equal actual CPU/calls',
       'limits':'4new cases,4distinct planting seeds,2proxies. Key/text independence counted externally, no general basin/rate, source algorithm replication, causal retrospective failure explanation or historical solution.',
       'build':build,'controls':controls,'prior_seed_audit':seed_check,'resources':resources(),'protected_before':protected(),'baseline_sha256':sha(BASELINE),
       'models_and_holdouts':[{'path':str(q.relative_to(ROOT)),'sha256':sha(q)} for model in ('de_fold','fr_fold') for q in(ROOT/'work/phase5_language'/model/'model.bin',ROOT/'work/phase5_language'/model/'holdout.txt')],
       'cases':[],'profiles':[],'runs':[],'planned_at_unix':time.time()}
    for index,(model,seed) in enumerate(CASES):
        identifier=f'{model}_20x25_{seed}';ct=[HERE/'ciphertexts'/f'{identifier}_T{n}.txt' for n in(1,2)]
        p['cases'].append({'case_id':identifier,'language_model':model,'plant_seed':seed,'ciphertext_paths':[str(q.relative_to(ROOT)) for q in ct]})
        for perturb_i,perturb in enumerate(('h4','h8')):
            for policy in(('A','B') if(index+perturb_i)%2==0 else('B','A')):
                p['profiles'].append(profile_definition(identifier,model,ct,'main',perturb,policy,49948,3))
    for model,seed in CASES:
        identifier=f'{model}_20x25_{seed}';ct=[HERE/'ciphertexts'/f'{identifier}_T{n}.txt' for n in(1,2)]
        p['profiles'].append(profile_definition(identifier,model,ct,'positive_control','positive','B',16650,1))
    assert len(p['profiles'])==20
    save(HERE/'plan20.json',p);print(json.dumps({'status':p['status'],'plan_sha256':sha(HERE/'plan20.json'),'profiles':20,'protected_files':len(p['protected_before']),'main_calls_max':799168,'positive_calls_max':66600,'audit_calls_max':40}))
def profile_definition(identifier,model,ct,category,perturb,policy,cap,sweeps):
    start=HERE/'starts'/f'{identifier}_{perturb}.txt';csv=HERE/'trajectories'/f'{identifier}_{perturb}_{policy}.csv';summary=csv.with_suffix('.json')
    return{'case_id':identifier,'category':category,'perturbation':perturb,'policy':policy,'max_calls':cap,'max_sweeps':sweeps,
        'start_path':str(start.relative_to(ROOT)),'csv_path':str(csv.relative_to(ROOT)),'summary_path':str(summary.relative_to(ROOT)),
        'command':[str(HERE/'trajectory'),str(ROOT/'work/phase5_language'/model/'model.bin'),*map(str,ct),str(start),'20','25',policy,str(cap),str(sweeps),'30',str(csv),str(summary)]}
def approval(plan):
    a=json.loads((HERE/'audit_approval.json').read_text())
    assert a['root_approved'] is True and a['independent_approved'] is True and a['plan_sha256']==sha(HERE/'plan20.json')
    assert resources()==plan['resources'] and protected()==plan['protected_before'] and sha(BASELINE)==plan['baseline_sha256']
    return a
def seal():
    if(HERE/'manifest.json').exists()or(HERE/'truth.jsonl').exists():raise SystemExit('No replacement ofphase16')
    m=json.loads((HERE/'plan20.json').read_text());a=approval(m);assert not m['runs']
    for item in m['models_and_holdouts']:assert sha(ROOT/item['path'])==item['sha256']
    for name in('ciphertexts','starts','trajectories'):(HERE/name).mkdir(exist_ok=True)
    truths=[]
    for case in m['cases']:
        body=''.join(c.lower() for c in(ROOT/'work/phase5_language'/case['language_model']/'holdout.txt').read_text()if c.isascii()and c.isalpha())
        t=json.loads(subprocess.check_output([str(HERE/'generate_keys'),str(case['plant_seed']),str(len(body)),'20','25'],text=True));pos=t['sample_position']
        plain=[body[pos:pos+615],body[pos+615:pos+775]];assert list(map(len,plain))==[615,160]
        assert sorted(t['true_k1'])==list(range(20))and sorted(t['true_k2'])==list(range(25))
        cipher=[enc(enc(q,t['true_k1']),t['true_k2'])for q in plain];case['ciphertext_files']=[]
        for path,value in zip(case['ciphertext_paths'],cipher):
            q=ROOT/path;q.write_text(value.upper()+'\n');case['ciphertext_files'].append({'path':path,'sha256':sha(q)})
        numeric=inverse(t['true_k2']);starts={}
        for label,count in(('positive',1),('h4',2),('h8',4)):
            key=numeric.copy()
            for x,y in PAIRS[:count]:key[x],key[y]=key[y],key[x]
            assert sorted(key)==list(range(25))and sum(x!=y for x,y in zip(key,numeric))==2*count
            q=HERE/'starts'/f'{case["case_id"]}_{label}.txt';q.write_text(' '.join(map(str,key))+'\n');starts[label]=sha(q)
        for profile in m['profiles']:
            if profile['case_id']==case['case_id']:profile['start_sha256']=starts[profile['perturbation']]
        truths.append({'case_id':case['case_id'],'language_model':case['language_model'],'plant_seed':case['plant_seed'],**t})
    (HERE/'truth.jsonl').write_text(''.join(json.dumps(t,separators=(',',':'))+'\n'for t in truths))
    m.update(status='sealed_not_run',truth_sha256=sha(HERE/'truth.jsonl'),audit_approval=a,plan_sha256=sha(HERE/'plan20.json'),sealed_at_unix=time.time())
    save(HERE/'sealed_design.json',m);save(HERE/'manifest.json',m);print(json.dumps({'status':m['status'],'truth_sha256':m['truth_sha256']}))
def run():
    m=json.loads((HERE/'manifest.json').read_text());assert m==json.loads((HERE/'sealed_design.json').read_text())and m['status']=='sealed_not_run'and not m['runs']
    approval(json.loads((HERE/'plan20.json').read_text()));assert sha(HERE/'truth.jsonl')==m['truth_sha256']
    for item in m['models_and_holdouts']:assert sha(ROOT/item['path'])==item['sha256']
    for case in m['cases']:
        for item in case['ciphertext_files']:assert sha(ROOT/item['path'])==item['sha256']
    for profile in m['profiles']:assert sha(ROOT/profile['start_path'])==profile['start_sha256']
    for profile in m['profiles']:
        assert not(ROOT/profile['csv_path']).exists()and not(ROOT/profile['summary_path']).exists();began=time.monotonic();timed=False
        try:r=subprocess.run(profile['command'],capture_output=True,text=True,timeout=40)
        except subprocess.TimeoutExpired as e:
            timed=True;r=subprocess.CompletedProcess([],124,(e.stdout or b'').decode()if isinstance(e.stdout,bytes)else(e.stdout or ''),(e.stderr or b'').decode()if isinstance(e.stderr,bytes)else(e.stderr or ''))
        path=(ROOT/profile['summary_path']).with_suffix('.calls.log');path.write_text(r.stderr)
        marks=[list(map(int,s.split()[1:]))for s in r.stderr.splitlines()if s.startswith('@calls ')];counts=marks[-1]if marks else[0,0]
        record={k:profile[k]for k in('case_id','category','perturbation','policy')};record.update(returncode=r.returncode,timed_out=timed,stdout=r.stdout,calls_path=str(path.relative_to(ROOT)),calls_sha256=sha(path),exact_calls_started=counts[1],legacy_calls_started=counts[0],process_seconds=time.monotonic()-began)
        if r.returncode:
            record['status']='failed'
            for field in('csv_path','summary_path'):
                q=ROOT/profile[field]
                if q.exists():record[field+'_persisted_sha256']=sha(q)
            m['runs'].append(record);m['status']='failed_no_retry';save(HERE/'manifest.json',m);raise SystemExit(json.dumps(record))
        s=json.loads((ROOT/profile['summary_path']).read_text());assert s['policy']==profile['policy']and s['call_limit']==profile['max_calls']and s['sweep_limit']==profile['max_sweeps']
        assert s['mode']=='privileged_k2_trajectory' and s['convention']==0 and s['source_moves']==16649 and s['seconds_limit']==30
        assert s['backend_legacy_calls']==counts[0]==0 and s['calls']==s['backend_exact_calls']==counts[1]<=profile['max_calls']
        record.update(status='recorded',csv_sha256=sha(ROOT/profile['csv_path']),summary_sha256=sha(ROOT/profile['summary_path']),summary=s)
        m['runs'].append(record);save(HERE/'manifest.json',m);print(json.dumps({k:v for k,v in record.items()if k not in('stdout','summary')}),flush=True)
    assert len(m['runs'])==20
    main=sum(r['summary']['calls']for r in m['runs']if r['category']=='main');positive=sum(r['summary']['calls']for r in m['runs']if r['category']=='positive_control')
    assert main<=799168 and positive<=66600
    m.update(status='completed',completed=True,main_exact_calls=main,positive_exact_calls=positive,total_exact_calls=main+positive,protected_after=protected(),protected_unchanged=True,ended_at_unix=time.time())
    assert m['protected_after']==m['protected_before'];save(HERE/'manifest.json',m)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=('plan','seal','run'));a=p.parse_args();{'plan':plan,'seal':seal,'run':run}[a.action]()

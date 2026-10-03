"""Prospective phase18 preparation, one execution, independent numeric checks.

No phase16 entrypoint is run. prepare does not invoke RNG or scoring.
execute is gated on two approvals of exact plan/code hashes. No retries.
"""
from pathlib import Path
import csv, hashlib, importlib.util, json, os, re, struct, subprocess, sys, time
if sys.flags.optimize:raise RuntimeError('Assertions required: no Python optimization flags')
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
AUD=ROOT/'work/phase18_root'
REVIEW=ROOT/'work/phase18_review'
TRUTH=ROOT/'work/phase18_truth'
CASE_SEEDS=[20262801,20262802,20262803,20262804]
START_SEEDS=[831004001,831004002,831004003,831004004,831004005,831004006,831004007,831004008]
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb')as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def load(p):return json.loads(Path(p).read_text())
def save(p,d):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
 tmp=p.with_name(p.name+'.tmp');tmp.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n');tmp.replace(p)
def rel(p):return str(Path(p).relative_to(ROOT))
def inverse(k):return [k.index(i)for i in range(len(k))]
def enc(t,k):return ''.join(t[c::len(k)]for c in k)
def normalize(p):return ''.join(c.lower()for c in Path(p).read_text()if c.isascii()and c.isalpha())
def frozen_resources():
 paths=[p for p in HERE.rglob('*')if p.is_file()and p.suffix in('.py','.cpp','.h','.json','.jsonl','.log','.txt')and p.name not in('plan.json','manifest.json')and '__pycache__'not in p.parts]
 paths += [HERE/'trajectory',HERE/'generate',ROOT/'work/phase4_crypto/source_moves.h',ROOT/'work/phase3_crypto/ict_search.h',ROOT/'work/crypto/double_search.cpp',AUD/'segment_reservation.json',AUD/'review_segment_method.txt',AUD/'reservation_root_crosscheck.txt',AUD/'seed_reservation.json',AUD/'frozen_before.json',AUD/'generator_build.json',REVIEW/'independent_records.py']
 paths += [ROOT/f'work/phase5_language/{lang}/{name}'for lang in('de_fold','fr_fold')for name in('model.bin','holdout.txt')]
 return {rel(p):sha(p)for p in paths}
def verify_map(d):
 for path,value in d.items():assert (ROOT/path).is_file()and sha(ROOT/path)==value,path
def old_files():
 result={}
 for top in ['work','outputs','sentinel-blume-salamanca']:
  for p in (ROOT/top).rglob('*'):
   if not p.is_file()or any(x in p.parts for x in('.git','__pycache__','.repro','node_modules')):continue
   r=rel(p)
   if r.startswith(('work/phase18_','sentinel-blume-salamanca/.repro'))or r=='work/OVERNIGHT_STATE.json' or r.endswith('.tmp'):continue
   result[r]=sha(p)
 return result
def prepare():
 assert not (HERE/'plan.json').exists(),'No replacement plan'
 AUD.mkdir(parents=True,exist_ok=True)
 assert (AUD/'segment_reservation.json').exists()
 reservation=load(AUD/'segment_reservation.json')
 # Compile RNG helper only; no invocation and no generated permutations.
 cmd=['/usr/bin/clang++','-std=c++17','-O3',str(HERE/'generate.cpp'),'-o',str(HERE/'generate')]
 began=time.monotonic();r=subprocess.run(cmd,capture_output=True,text=True)
 save(AUD/'generator_build.json',dict(command=cmd,returncode=r.returncode,seconds=time.monotonic()-began,stdout=r.stdout,stderr=r.stderr,source_sha256=sha(HERE/'generate.cpp'),rng_executions=0,IDP_calls=0))
 assert r.returncode==0
 # Prior-use seed audit: integer/string values under seed-bearing field names,
 # paths and source literals. Numeric scores/CSV values are not seed evidence.
 wanted=set(CASE_SEEDS+START_SEEDS);hits=[];catalog=[]
 def walk(v,path,field=''):
  if isinstance(v,dict):
   for k,x in v.items():walk(x,path,field+'.'+k)
  elif isinstance(v,list):
   for i,x in enumerate(v):walk(x,path,field+f'[{i}]')
  elif 'seed'in field.lower():
   catalog.append(dict(path=path,field=field,value=v))
   if str(v)in map(str,wanted):hits.append(dict(path=path,field=field,value=v))
 scanned=[]
 for p in (ROOT/'work').rglob('*'):
  if not p.is_file()or 'phase18'in str(p)or '__pycache__'in p.parts:continue
  if p.suffix in('.json','.jsonl'):
   try:
    if p.suffix=='.json':walk(load(p),rel(p))
    else:
     for i,line in enumerate(p.read_text().splitlines()):walk(json.loads(line),rel(p),f'line{i}')
    scanned.append(dict(path=rel(p),sha256=sha(p)))
   except (ValueError,UnicodeError):continue
  if p.suffix in('.py','.cpp'):
   body=p.read_text(errors='replace')
   for seed in wanted:
    if re.search(r'(?<!\d)'+str(seed)+r'(?!\d)',body):hits.append(dict(path=rel(p),source_literal=seed))
  for seed in wanted:
   if re.search(r'(?<!\d)'+str(seed)+r'(?!\d)',p.name):hits.append(dict(path=rel(p),filename_seed=seed))
 assert not hits,hits
 save(AUD/'seed_reservation.json',dict(status='reserved_before_truth',case_seeds=CASE_SEEDS,start_seeds=START_SEEDS,prior_use_hits=hits,scanned_metadata=scanned,prior_seed_fields=catalog,scope='All parseable prior work JSON/JSONL seed fields, work source literals and filenames; not incidental numerators. New independent streams, no target-derived arithmetic. No RNG called.'))
 before=old_files();save(AUD/'frozen_before.json',dict(files=before,count=len(before),excluded='phase18 directories, mutable OVERNIGHT_STATE, git, pycache, .repro',new_IDP=0))
 cases=[]
 # Reservation has four windows in fixed DE,DE,FR,FR order; adapter validates schema.
 windows=[]
 for lang in('de_fold','fr_fold'):
  item=reservation['reservations'][lang];assert sha(ROOT/item['holdout']['holdout_path'])==item['holdout']['holdout_sha256']
  for w in item['reserved_windows']:
   start,end=w['interval_half_open'];assert end-start==775 and end<=item['holdout']['normalized_length']
   assert all(end<=a or start>=b for a,b in item['prior_excluded_union'])
   windows.append(dict(language_model=lang,start=start,end=end))
 assert len(windows)==4
 for i,(window,seed)in enumerate(zip(windows,CASE_SEEDS)):
  lang=window['language_model'];assert lang==('de_fold'if i<2 else'fr_fold')
  offset=window['start'];assert window['end']==offset+775
  cases.append(dict(case_id=f'{lang}_20x25_{seed}',input_id=f'case{i+1:02d}',language_model=lang,plant_seed=seed,sample_position=offset,window=window,start_seeds=START_SEEDS[2*i:2*i+2]))
 plan=dict(status='prospective_executable_requires_double_approval',question='Can fixed-neighborhood B recover exact K2 from uniform independent starts on four new synthetic cases within the fixed cap?',
  authorization='Human: Vamos con el descifrado, 2026-10-03',cases=cases,geometry=dict(w1=20,w2=25,lengths=[615,160],convention=0),
  objective='Frozen integer binary32 IDP; rational EPS1e-12; no new training. Known widths, convention and literary language models. K2 only.',
  starts='Two std::shuffle(identity25, mt19937_64(separate reserved literal seed)) per case. No truth input to start generator, no rejection/redraw, no scoring before search. Uniform algorithm; deterministic pseudorandom, not physical IID.',
  policy='B: entire fixed source neighborhood of16649; accept best strict improvement only if complete; first source-order tie; no shuffle, restart, cache, population or partial admission.',
  main_profiles=8,positive_profiles=4,main_limits=dict(max_calls=166491,max_sweeps=10,soft_seconds=30,hard_seconds=40),
  positive_limits=dict(max_calls=16650,max_sweeps=1,soft_seconds=30,hard_seconds=40),positive='One privileged native swap positions0,1 on inverse(trueK2), Hamming2, per case; separate denominator. Run after all main, without outcome-based gating.',
  archive='All scored proposals offered, distinct top5 descending numerator then numeric lexicographic; repeats charged.',
  metrics_primary='Exact trueK2 final distinct top5 archive, 8 nested starts on4cases, not8 independent cases; no language rates.',
  metrics_secondary=['ever scored','first scored call','first adoption call','final current equality','final archive rank','calls','unique visited','full/partial sweeps','accepted changes','convergence flag versus physical stop_reason','initial and minimum visited Hamming measured only externally afterward, not graph distance'],
  numeric_reference=dict(max_calls=24,samples='initial and last evaluated proposal per12profiles; duplicates charged; direct offset enumeration, no targets or new trajectories'),
  ceilings=dict(main_IDP=1331928,positive_IDP=66600,reference_IDP=24,total_IDP=1398552,mock_callbacks=200,actual_mocks_already=59),
  execution_guard=dict(global_seconds=600,start='Immediately before first truth generation attempt after double gate; persisted monotonic deadline and wall deadline, either can stop, never restarted',disk_bytes=536870912,disk_scope='All regular files under phase18_crypto/root/review/truth including failed outputs and logs; 1MiB reserved for terminal receipts; poll0.05s while child active, overshoot observed and reported',failure='First technical failure or ceiling violation stops whole attempt; no rerun, substitute, score extension or clock reset'),
  run_order='Four cases in DE,DE,FR,FR order, two independent starts each; then four positive controls in case order. External truth evaluation only after root and independent saved-record audits by hash.',
  interpretation='Exploratory diagnostic synthetic K2 only with known geometry/model/convention; old literary corpora already descriptively analyzed. Reserved plant windows are disjoint from documented prior planting; two adjacent windows per language/work, not IID new corpora. Neither success nor failure decrypts BLUME, recoversK1, proves impossibility or explains phase14. No modification of frozen old phases.',
  independence_audit='Saved-record independent review: fixed120s, zero IDP, may run after600s scientific deadline without reopening scores. Its code is frozen before truth.',
  controls_preparation=load(HERE/'control_results.json'),resources=frozen_resources())
 save(HERE/'plan.json',plan)
 print(json.dumps(dict(status='prepared_no_truth',plan_sha256=sha(HERE/'plan.json'),cases=cases,protected_files=len(before),RNG_calls=0,IDP_calls=0)))
def data_bytes():
 return sum(p.stat().st_size for d in(HERE,AUD,REVIEW,TRUTH)if d.exists()for p in d.rglob('*')if p.is_file())
def guard(m):
 if time.time()>=m['deadline_unix']or time.monotonic()>=m['deadline_monotonic']:raise RuntimeError('global600s ceiling reached')
 if data_bytes()>536870912-1048576:raise RuntimeError('disk guard including1MiB receipt reserve reached')
def child(cmd,out,err,m,hard,cwd=None):
 guard(m);began=time.monotonic();out=Path(out);err=Path(err);out.parent.mkdir(parents=True,exist_ok=True)
 with out.open('wb')as f,err.open('wb')as e:
  p=subprocess.Popen(cmd,stdout=f,stderr=e,cwd=cwd);reason=None
  while p.poll()is None:
   if time.monotonic()-began>=hard:reason='hard_process_seconds'
   elif time.time()>=m['deadline_unix']or time.monotonic()>=m['deadline_monotonic']:reason='global600s'
   elif data_bytes()>536870912-1048576:reason='disk_guard'
   if reason:p.kill();break
   time.sleep(.05)
  rc=p.wait()
  if reason is None:
   if time.time()>=m['deadline_unix']or time.monotonic()>=m['deadline_monotonic']:reason='global600s_after_child'
   elif data_bytes()>536870912-1048576:reason='disk_guard_after_child'
   elif time.monotonic()-began>=hard:reason='hard_process_seconds_after_child'
 record=dict(command=cmd,cwd=cwd,returncode=rc,guard_stop=reason,seconds=time.monotonic()-began,stdout_path=rel(out),stderr_path=rel(err),stdout_sha256=sha(out),stderr_sha256=sha(err),disk_observed_bytes=data_bytes())
 return record
def marker_count(p,max_calls):
 count=0;issues=[]
 with Path(p).open()as f:
  for line in f:
   if line.startswith('@calls '):
    match=re.fullmatch(r'@calls 0 (\d+)\n',line)
    if not issues and match and int(match[1])==count+1:count+=1
    else:issues.append(line)
   elif line.startswith('@'):issues.append(line)
 return dict(complete_marker_prefix=count,backend_marker_calls=count if not issues else None,cost_uncertain=bool(issues),exact_calls_started_lower=count,exact_calls_started_upper=count if not issues else max_calls,marker_fragments=issues)
def execute():
 assert not(HERE/'manifest.json').exists(),'Only one execution attempt'
 plan=load(HERE/'plan.json');approval=load(AUD/'audit_approval.json')
 assert approval['root_approved']and approval['independent_approved']and approval['plan_sha256']==sha(HERE/'plan.json')
 assert approval['resources']==plan['resources'];verify_map(plan['resources']);verify_map(load(AUD/'frozen_before.json')['files'])
 m=dict(status='started',plan_sha256=sha(HERE/'plan.json'),started_at_unix=time.time(),cases=[],profiles=[],generation_attempts=[],runs=[],reference_calls_started=0,truth_evaluated=False)
 m['started_monotonic']=time.monotonic();m['deadline_monotonic']=m['started_monotonic']+600;m['deadline_unix']=m['started_at_unix']+600;save(HERE/'manifest.json',m)
 try:
  truths=[];profiles=[]
  for case in plan['cases']:
   guard(m);cid=case['case_id'];out=TRUTH/'generation'/f'{cid}_plant.json';err=out.with_suffix('.stderr.txt')
   # Receipt started before RNG invocation, retained even on failure.
   attempt=dict(case_id=cid,mode='plant',seed=case['plant_seed'],status='started');m['generation_attempts'].append(attempt);save(HERE/'manifest.json',m)
   record=child([str(HERE/'generate'),'plant',str(case['plant_seed'])],out,err,m,5);attempt.update(record,status='completed'if record['returncode']==0 and not record['guard_stop']else'failed');save(HERE/'manifest.json',m)
   assert attempt['status']=='completed',attempt
   planted=load(out);k1,k2=planted['k1'],planted['k2'];assert sorted(k1)==list(range(20))and sorted(k2)==list(range(25))
   body=normalize(ROOT/f'work/phase5_language/{case["language_model"]}/holdout.txt');pos=case['sample_position'];plain=[body[pos:pos+615],body[pos+615:pos+775]];assert list(map(len,plain))==[615,160]
   ct=[]
   for j,text in enumerate(plain,1):
    p=HERE/'ciphertexts'/f'{case["input_id"]}_T{j}.txt';p.parent.mkdir(exist_ok=True);p.write_text(enc(enc(text,k1),k2)+'\n');ct.append(dict(path=rel(p),sha256=sha(p)))
   truth=dict(case_id=cid,language_model=case['language_model'],plant_seed=case['plant_seed'],sample_position=pos,true_k1=k1,true_k2=k2,plaintext_sha256=[hashlib.sha256(t.encode()).hexdigest()for t in plain]);truths.append(truth)
   c=dict(case, ciphertext_files=ct);m['cases'].append(c)
   for j,seed in enumerate(case['start_seeds'],1):
    out=HERE/'generation'/f'{cid}_start{j}.json';err=out.with_suffix('.stderr.txt');attempt=dict(case_id=cid,mode='start',seed=seed,status='started');m['generation_attempts'].append(attempt);save(HERE/'manifest.json',m)
    r=child([str(HERE/'generate'),'start',str(seed)],out,err,m,5);attempt.update(r,status='completed'if r['returncode']==0 and not r['guard_stop']else'failed');save(HERE/'manifest.json',m);assert attempt['status']=='completed'
    initial=load(out)['numeric'];assert sorted(initial)==list(range(25));profiles.append(make_profile(c,'main',f'random{j}',initial,seed,plan['main_limits']))
  assert len({(tuple(t['true_k1']),tuple(t['true_k2']))for t in truths})==4,'No substitution on planted collision'
  assert len({tuple(t['plaintext_sha256'])for t in truths})==4,'No substitution on text collision'
  for c,t in zip(m['cases'],truths):
   start=inverse(t['true_k2']);start[0],start[1]=start[1],start[0];profiles.append(make_profile(c,'positive_control','h2',start,None,plan['positive_limits']))
  TRUTH.mkdir(exist_ok=True);p=TRUTH/'truth.jsonl';p.write_text(''.join(json.dumps(t)+'\n'for t in truths));m.update(status='sealed',profiles=profiles,truth_path=rel(p),truth_sha256=sha(p),distinct_keypairs=4,distinct_plaintexts=4);save(HERE/'manifest.json',m)
  for profile in profiles:
   guard(m);c=next(c for c in m['cases']if c['case_id']==profile['case_id']);csv_path=ROOT/profile['csv_path'];csv_path.parent.mkdir(exist_ok=True)
   cmd=[str(HERE/'trajectory'),str(ROOT/profile['model_path']),*[str(ROOT/x['path'])for x in c['ciphertext_files']],str(ROOT/profile['start_path']),'20','25','B',str(profile['max_calls']),str(profile['max_sweeps']),str(profile['soft_seconds']),str(csv_path),str(ROOT/profile['summary_path'])]
   run=dict(profile_id=profile['profile_id'],case_id=profile['case_id'],category=profile['category'],status='started');m['runs'].append(run);save(HERE/'manifest.json',m)
   workspace=HERE/'solver_workspace';workspace.mkdir(exist_ok=True)
   r=child(cmd,ROOT/profile['stdout_path'],ROOT/profile['calls_path'],m,profile['hard_seconds'],cwd=str(workspace));run.update(r,process_seconds=r['seconds'],calls_path=profile['calls_path'],calls_sha256=sha(ROOT/profile['calls_path']))
   run.update(marker_count(ROOT/profile['calls_path'],profile['max_calls']));run['legacy_calls']=0
   if r['returncode']!=0 or r['guard_stop']:
    # A kill/exception may occur between backend charge and marker flush.
    # Preserve the observed prefix and a conservative pre-fixed cap upper bound.
    run.update(cost_uncertain=run['complete_marker_prefix']<profile['max_calls'],exact_calls_started_upper=profile['max_calls'],backend_marker_calls=None)
   run['status']='completed'if r['returncode']==0 and not r['guard_stop']and not run['cost_uncertain']else'failed';save(HERE/'manifest.json',m);assert run['status']=='completed',run
   s=load(ROOT/profile['summary_path']);assert s['calls']==s['backend_exact_calls']==run['backend_marker_calls']<=profile['max_calls']and s['backend_legacy_calls']==0
   run.update(summary=s,csv_sha256=sha(csv_path),summary_sha256=sha(ROOT/profile['summary_path']));save(HERE/'manifest.json',m)
  m.update(status='completed',ended_at_unix=time.time(),main_exact_calls=sum(r['backend_marker_calls']for r in m['runs']if r['category']=='main'),positive_exact_calls=sum(r['backend_marker_calls']for r in m['runs']if r['category']=='positive_control'),disk_observed_bytes=data_bytes())
  verify_map(plan['resources']);verify_map(load(AUD/'frozen_before.json')['files']);m['protected_unchanged']=True;save(HERE/'manifest.json',m)
 except BaseException as e:
  if m['runs']:
   last=m['runs'][-1]
   if last['status']!='completed'or 'summary'not in last:
    p=next(p for p in m['profiles']if p['profile_id']==last['profile_id']);prefix=last.get('complete_marker_prefix',0)
    last.update(status='failed',cost_uncertain=prefix<p['max_calls'],backend_marker_calls=None,exact_calls_started_lower=prefix,exact_calls_started_upper=p['max_calls'])
  m.update(status='failed_closed_no_retry',error=repr(e),ended_at_unix=time.time(),disk_observed_bytes=data_bytes());save(HERE/'manifest.json',m);raise
 print(json.dumps({k:m[k]for k in('status','main_exact_calls','positive_exact_calls','disk_observed_bytes','started_at_unix','ended_at_unix')}))
def make_profile(c,category,start_name,key,seed,limits):
 pid=c['input_id']+'_'+start_name+'_B';p=HERE/'starts'/f'{pid}.txt';p.parent.mkdir(exist_ok=True);p.write_text(' '.join(map(str,key))+'\n')
 base=HERE/'trajectories'/pid
 return dict(profile_id=pid,case_id=c['case_id'],category=category,start_name=start_name,start_seed=seed,privileged=category!='main',policy='B',model_path=f'work/phase5_language/{c["language_model"]}/model.bin',start_path=rel(p),start_sha256=sha(p),csv_path=rel(base.with_suffix('.csv')),summary_path=rel(base.with_suffix('.json')),calls_path=rel(base.with_suffix('.calls.log')),stdout_path=rel(base.with_suffix('.stdout.txt')),**limits)
def numeric_reference():
 assert not(AUD/'numeric_attempt.json').exists(),'No second numeric attempt'
 m=load(HERE/'manifest.json');assert m['status']=='completed'
 samples=load(AUD/'records_root.json');assert samples['manifest_sha256']==sha(HERE/'manifest.json')and samples['status']=='passed'
 save(AUD/'numeric_attempt.json',dict(status='started',started_unix=time.time(),manifest_sha256=sha(HERE/'manifest.json'),exact_calls_started=0,source_sha256=sha(Path(__file__))))
 # Frozen phase16 direct matrix/greedy reference copied into NEW reference module;
 # not its old main entrypoint. No truth or target read.
 from numeric_reference import score, load_table
 results=[];charged=0
 try:
  for result in samples['profiles']:
   p=next(p for p in m['profiles']if p['profile_id']==result['profile_id']);case=next(c for c in m['cases']if c['case_id']==p['case_id']);cts=[[ord(x)-97 for x in (ROOT/t['path']).read_text().strip()]for t in case['ciphertext_files']];table,scale=load_table(ROOT/p['model_path'])
   for sample in result['numeric_samples']:
    if sample is None:
     results.append(dict(profile_id=p['profile_id'],sample_unavailable=True,reference_IDP=0));continue
    guard(m);charged+=1;assert charged<=24
    save(AUD/'numeric_progress.json',dict(exact_calls_started=charged,profile_id=p['profile_id'],sample_call=sample['call'],charged_before_backend=True))
    observed=score(cts,sample['numeric'],table,scale,lambda:guard(m));assert observed==sample['numerator'],(p['profile_id'],sample,observed)
    results.append(dict(profile_id=p['profile_id'],call=sample['call'],numerator=observed))
  guard(m)
  save(AUD/'numeric_attempt.json',dict(status='passed',ended_unix=time.time(),manifest_sha256=sha(HERE/'manifest.json'),exact_calls_started=charged,legacy_calls_started=0,results=results,truth_read=False,new_searches=0,source_sha256=sha(Path(__file__))))
 except BaseException as e:
  save(AUD/'numeric_attempt.json',dict(status='failed_closed_no_retry',exact_calls_started=charged,error=repr(e),manifest_sha256=sha(HERE/'manifest.json')));raise
 print(json.dumps(dict(status='passed',reference_IDP=charged)))
def records():
 assert not(AUD/'records_root.json').exists(),'No replacement record audit'
 m=load(HERE/'manifest.json');assert m['status']=='completed'
 from audit_records import audit_profile
 results=[]
 for p,r in zip(m['profiles'],m['runs']):
  assert p['profile_id']==r['profile_id'];result=audit_profile(p,r,ROOT);result['profile_id']=p['profile_id'];results.append(result)
 save(AUD/'records_root.json',dict(status='passed',manifest_sha256=sha(HERE/'manifest.json'),profiles=results,truth_read=False,new_IDP=0,source_sha256=sha(HERE/'audit_records.py')))
 print(json.dumps(dict(status='passed',profiles=len(results),IDP=0)))
if __name__=='__main__':
 {'prepare':prepare,'execute':execute,'records':records,'numeric':numeric_reference}[sys.argv[1]]()

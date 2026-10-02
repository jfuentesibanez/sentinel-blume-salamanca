"""Privileged static diagnosis: plan, two approvals, seal truth, then 12 profiles."""
from pathlib import Path
import argparse,hashlib,json,subprocess,time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent.parent
MODELS=('de_fold','fr_fold');SEEDS=(20262301,20262302)
ANCHORS=(('true',None),('native',(0,1)),('omitted',(1,24)))
PRIOR=('crypto','phase2_crypto','phase3_crypto','phase4_crypto','phase5_crypto','phase5_language','phase7_crypto','phase8_crypto','phase9_crypto','phase10_crypto','phase11_crypto','phase14_crypto')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,v):p.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n')
def enc(text,key):return ''.join(text[c::len(key)] for c in key)
def inverse(key):
    out=[0]*len(key)
    for i,v in enumerate(key):out[v]=i
    return out
def protected():return {str(p.relative_to(ROOT)):sha(p) for folder in PRIOR for p in sorted((ROOT/'work'/folder).rglob('*')) if p.is_file()}
def resources():
    names=('static_landscape.cpp','static_landscape','generate_keys.cpp','generate_keys','build.py','build_record.json','check_controls.py','control_results.json','uniform_fixture.bin','moves.json','run_phase15.py','evaluate_external.py','IMPLEMENTATION_DECISIONS.txt','LEEME.txt','ATTRIBUTION.txt','LICENSE-CrypTool-2.txt')
    result={name:sha(HERE/name) for name in names}
    for p in sorted((HERE/'control_attempts').glob('*')):
        if p.is_file():result[str(p.relative_to(HERE))]=sha(p)
    return result
def seeds_unused():
    records=[];hits=[]
    for p in sorted((ROOT/'work').glob('**/manifest.json')):
        if p.is_relative_to(HERE) or 'repo_share' in p.parts:continue
        # Only archived project phases count; draft design mentions do not.
        if not any(part in PRIOR for part in p.parts):continue
        d=json.loads(p.read_text());records.append({'path':str(p.relative_to(ROOT)),'sha256':sha(p)})
        def visit(v,path=''):
            if isinstance(v,dict):
                for k,x in v.items():
                    if 'seed' in k.lower() and isinstance(x,int) and x in SEEDS:hits.append((str(p),path+'.'+k,x))
                    if 'seed' in k.lower() and isinstance(x,list):
                        for seed in x:
                            if isinstance(seed,int) and seed in SEEDS:hits.append((str(p),path+'.'+k,seed))
                    visit(x,path+'.'+k)
            elif isinstance(v,list):
                for i,x in enumerate(v):visit(x,path+f'[{i}]')
        visit(d)
    if hits:raise RuntimeError(f'Seeds previously used: {hits}')
    return {'planting_seeds':list(SEEDS),'previous_use':False,'checked_manifests':records}
def plan():
    if (HERE/'sealed_design.json').exists():raise SystemExit('Cannot edit sealed design')
    build=json.loads((HERE/'build_record.json').read_text());checks=json.loads((HERE/'control_results.json').read_text())
    assert build['source_sha256']==sha(HERE/'static_landscape.cpp') and build['binary_sha256']==sha(HERE/'static_landscape')
    assert checks['status']=='passed' and checks['source_sha256']==build['source_sha256'] and checks['binary_sha256']==build['binary_sha256']
    result={'phase':15,'date':'2026-10-03','status':'draft_for_double_audit_no_truth_no_main',
        'scope':'PRIVILEGED STATIC K2 landscape; program receives anchors derived from truth, including true key; no target label comparison or search',
        'models':list(MODELS),'planting_seeds':list(SEEDS),'expected_cases':4,'expected_profiles':12,'lengths':[615,160],'widths':[20,25],'convention':0,
        'anchor_rule':'numeric=inverse(true_k2); native swaps numeric positions(0,1); omitted swaps(1,24), zero-based',
        'neighbor_rule':'State index0 plus16649 frozen source_moves in construction order; each move applied to unchanged anchor; no shuffle/update/search',
        'expected_states_per_profile':16650,'expected_states_total':199800,'principal_legacy_calls_max':199800,'principal_exact_calls_max':199800,'principal_idp_equivalent_calls_max':399600,
        'soft_seconds_per_profile':30,'process_timeout_seconds':40,'time_cut_rule':'Clock starts before model/input/moves construction. Check before each paired score; finish both backends of begun state, report excess; no rerun/extension',
        'legacy':'Frozen matrix() includes binary32 subtraction before double accumulation; traced greedy selection preserves strict > and row-major tie',
        'exact':'Same676binary32 entries as reduced dyadics at common denominator; integer matrix/greedy/floor; checkedint64 score/storage bounds; __int128 epsilon comparison',
        'epsilon_reference':'Exact rational1/10^12; legacy retains frozen double1e-12; report differences rather than tuning',
        'score_normalization':'scale*sum(floor(length/w1))*w1; scale detected per model; numerators may coincide for different keys',
        'csv_columns':['index','kind','legacy','exact_numerator','legacy_improves_anchor','exact_improves_anchor','legacy_edges','exact_edges','legacy_forced','exact_forced','matrix_max_abs_diff'],
        'edge_representation':'a*w1+b in greedy selection order; x:y:z CSV field; forced last edge retained at floor-7*rows_total',
        'duplicates':'No duplicate keys inside a profile. Overlap between anchors/cases is charged per backend, not cached; external evaluator reports unique keys separately',
        'local_selection':'IDP descending, numeric lexicographic tie; target comparison external; true anchor itself is not counted as unknown-key recovery',
        'truth_separation':'Generation and target evaluation are external; C++ is intentionally privileged because it receives planted-key-derived anchors. It receives no true_k1 or separate target labels/key to compare',
        'interpretation_limits':'Four paired cases, two planting seeds, unchanged literary proxy corpora; same seeds across languages may produce identical keypairs, counted externally. Local ranks/signal and arithmetic only, not basin/recovery rate from random starts, full attack, cipher-language test, or BLUME',
        'build':build,'controls':checks,'seed_audit':seeds_unused(),'resources':resources(),'protected_before':protected(),
        'models_and_holdouts':[{'path':str(p.relative_to(ROOT)),'sha256':sha(p)} for model in MODELS for p in (ROOT/'work/phase5_language'/model/'model.bin',ROOT/'work/phase5_language'/model/'holdout.txt')],
        'cases':[],'profiles':[],'runs':[],'planned_at_unix':time.time()}
    for i,(model,seed) in enumerate((m,s) for m in MODELS for s in SEEDS):
        identifier=f'{model}_20x25_{seed}';ct=[HERE/'ciphertexts'/f'{identifier}_T{n}.txt' for n in (1,2)]
        result['cases'].append({'case_id':identifier,'language_model':model,'plant_seed':seed,'ciphertext_paths':[str(p.relative_to(ROOT)) for p in ct]})
        # Alternate anchor order; all backends are always legacy then exact.
        ordered=ANCHORS if i%2==0 else tuple(reversed(ANCHORS))
        for label,swap in ordered:
            anchor=HERE/'anchors'/f'{identifier}_{label}.txt';csv=HERE/'landscapes'/f'{identifier}_{label}.csv';summary=HERE/'landscapes'/f'{identifier}_{label}.json'
            cmd=[str(HERE/'static_landscape'),'static',str(ROOT/'work/phase5_language'/model/'model.bin'),*map(str,ct),str(anchor),'20','25',str(csv),str(summary),'30','16650']
            result['profiles'].append({'case_id':identifier,'anchor_label':label,'swap':swap,'anchor_path':str(anchor.relative_to(ROOT)),'csv_path':str(csv.relative_to(ROOT)),'summary_path':str(summary.relative_to(ROOT)),'command':cmd})
    assert len(result['profiles'])==12
    save(HERE/'plan12.json',result);print(json.dumps({'status':result['status'],'plan_sha256':sha(HERE/'plan12.json'),'profiles':12,'protected_files':len(result['protected_before']),'idp_max':399600}))
def approval(plan):
    record=json.loads((HERE/'audit_approval.json').read_text())
    assert record['root_approved'] is True and record['independent_approved'] is True and record['plan_sha256']==sha(HERE/'plan12.json')
    assert resources()==plan['resources'] and protected()==plan['protected_before']
    return record
def seal():
    if (HERE/'manifest.json').exists() or (HERE/'truth.jsonl').exists():raise SystemExit('Refusing to overwrite phase15')
    manifest=json.loads((HERE/'plan12.json').read_text());approved=approval(manifest)
    assert not manifest['runs'] and manifest['status']=='draft_for_double_audit_no_truth_no_main'
    for item in manifest['models_and_holdouts']:assert sha(ROOT/item['path'])==item['sha256']
    for name in ('ciphertexts','anchors','landscapes'):(HERE/name).mkdir(exist_ok=True)
    truth=[]
    for case in manifest['cases']:
        text=''.join(c.lower() for c in (ROOT/'work/phase5_language'/case['language_model']/'holdout.txt').read_text() if c.isascii() and c.isalpha())
        t=json.loads(subprocess.check_output([str(HERE/'generate_keys'),str(case['plant_seed']),str(len(text)),'20','25'],text=True));pos=t['sample_position']
        plain=[text[pos:pos+615],text[pos+615:pos+775]];assert list(map(len,plain))==[615,160]
        for key,width in ((t['true_k1'],20),(t['true_k2'],25)):assert sorted(key)==list(range(width))
        ciphertext=[enc(enc(p,t['true_k1']),t['true_k2']) for p in plain];case['ciphertext_files']=[]
        for path,value in zip(case['ciphertext_paths'],ciphertext):
            file=ROOT/path;file.write_text(value.upper()+'\n');case['ciphertext_files'].append({'path':path,'sha256':sha(file)})
        true_numeric=inverse(t['true_k2'])
        for profile in manifest['profiles']:
            if profile['case_id']!=case['case_id']:continue
            numeric=true_numeric.copy()
            if profile['swap']:
                a,b=profile['swap'];numeric[a],numeric[b]=numeric[b],numeric[a]
            assert sum(x!=y for x,y in zip(numeric,true_numeric))==(2 if profile['swap'] else 0)
            file=ROOT/profile['anchor_path'];file.write_text(' '.join(map(str,numeric))+'\n');profile['anchor_sha256']=sha(file)
        truth.append({'case_id':case['case_id'],'language_model':case['language_model'],'plant_seed':case['plant_seed'],**t})
    (HERE/'truth.jsonl').write_text(''.join(json.dumps(t,separators=(',',':'))+'\n' for t in truth))
    manifest.update(status='sealed_not_run',truth_sha256=sha(HERE/'truth.jsonl'),plan_sha256=sha(HERE/'plan12.json'),audit_approval=approved,sealed_at_unix=time.time())
    save(HERE/'sealed_design.json',manifest);save(HERE/'manifest.json',manifest);print(json.dumps({'status':manifest['status'],'truth_sha256':manifest['truth_sha256']}))
def run():
    manifest=json.loads((HERE/'manifest.json').read_text());assert manifest==json.loads((HERE/'sealed_design.json').read_text())
    assert manifest['status']=='sealed_not_run' and not manifest['runs'];approval(json.loads((HERE/'plan12.json').read_text()))
    assert sha(HERE/'truth.jsonl')==manifest['truth_sha256']
    for item in manifest['models_and_holdouts']:assert sha(ROOT/item['path'])==item['sha256']
    for case in manifest['cases']:
        for item in case['ciphertext_files']:assert sha(ROOT/item['path'])==item['sha256']
    for profile in manifest['profiles']:assert sha(ROOT/profile['anchor_path'])==profile['anchor_sha256']
    for profile in manifest['profiles']:
        for field in ('csv_path','summary_path'):assert not (ROOT/profile[field]).exists()
        started=time.monotonic();timed_out=False
        try:proc=subprocess.run(profile['command'],capture_output=True,text=True,timeout=40)
        except subprocess.TimeoutExpired as e:
            timed_out=True
            proc=subprocess.CompletedProcess([],124,(e.stdout or b'').decode() if isinstance(e.stdout,bytes) else (e.stdout or ''),(e.stderr or b'').decode() if isinstance(e.stderr,bytes) else (e.stderr or ''))
        calls_path=(ROOT/profile['summary_path']).with_suffix('.calls.log');calls_path.write_text(proc.stderr)
        marks=[list(map(int,line.split()[1:])) for line in proc.stderr.splitlines() if line.startswith('@calls ')]
        charged=marks[-1] if marks else [0,0]
        record={'case_id':profile['case_id'],'anchor_label':profile['anchor_label'],'returncode':proc.returncode,'timed_out':timed_out,'calls_path':str(calls_path.relative_to(ROOT)),'calls_sha256':sha(calls_path),'legacy_calls_started':charged[0],'exact_calls_started':charged[1],'stdout':proc.stdout,'process_seconds':time.monotonic()-started}
        if proc.returncode:
            record['status']='failed'
            for field in ('csv_path','summary_path'):
                file=ROOT/profile[field]
                if file.exists():record[field+'_persisted_sha256']=sha(file)
            manifest['runs'].append(record);manifest['status']='failed_no_retry';save(HERE/'manifest.json',manifest);raise SystemExit(json.dumps(record))
        s=json.loads((ROOT/profile['summary_path']).read_text());assert s['anchor_updated'] is False and s['convention']==0 and s['source_moves']==16649 and s['requested_states']==16650
        assert 0<=s['states_completed']<=16650 and s['legacy_calls']==s['exact_calls']==s['states_completed']
        assert charged==[s['legacy_calls'],s['exact_calls']]
        record.update(status='recorded',csv_sha256=sha(ROOT/profile['csv_path']),summary_sha256=sha(ROOT/profile['summary_path']),summary=s)
        manifest['runs'].append(record);save(HERE/'manifest.json',manifest);print(json.dumps({k:v for k,v in record.items() if k!='stdout'}),flush=True)
    assert len(manifest['runs'])==12
    manifest.update(status='completed',completed=True,protected_after=protected());assert manifest['protected_after']==manifest['protected_before']
    manifest.update(protected_unchanged=True,all_profiles_complete=all(r['summary']['states_completed']==16650 and r['summary']['stop_reason']=='complete' for r in manifest['runs']),ended_at_unix=time.time(),legacy_calls=sum(r['summary']['legacy_calls'] for r in manifest['runs']),exact_calls=sum(r['summary']['exact_calls'] for r in manifest['runs']))
    assert manifest['legacy_calls']<=199800 and manifest['exact_calls']<=199800
    save(HERE/'manifest.json',manifest)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=('plan','seal','run'));a=p.parse_args();{'plan':plan,'seal':seal,'run':run}[a.action]()

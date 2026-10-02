"""Plan first; require a separate audit approval before sealing or running 32 searches."""
from pathlib import Path
import argparse,hashlib,json,subprocess,time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent.parent
MODELS=('de_fold','fr_fold');SEEDS=(20262201,20262202);MASK=(1<<64)-1
ARMS={'A':(5000,False),'B':(5000,True),'C':(33298,False),'D':(33298,True)}
ORDERS=(('A','B','D','C'),('B','C','A','D'),('C','D','B','A'),('D','A','C','B'))
SOLVER=HERE/'checkpoint_population_search'
PROTECTED=('crypto','phase2_crypto','phase3_crypto','phase4_crypto','phase5_crypto','phase5_language','phase7_crypto','phase8_crypto','phase9_crypto','phase10_crypto','phase11_crypto')
PREVIOUS_DESIGNS=('phase12_claude/crypto_propuesta.txt','phase13_claude/crypto_decisiones_preimplementacion.txt','phase13_claude/crypto_revision_interna.txt','phase13_claude/crypto_comparativa_claude.txt')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,value):path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
def enc(text,key):return ''.join(text[c::len(key)] for c in key)
def protected_hashes():
    paths=[p for name in PROTECTED for p in sorted((ROOT/'work'/name).rglob('*')) if p.is_file()]
    paths += [ROOT/'work'/name for name in PREVIOUS_DESIGNS]
    return [{'path':str(p.relative_to(ROOT)),'sha256':sha(p)} for p in paths]
def resources():
    names=('checkpoint_population_search.cpp','sha256.h','phase10_frozen_classes.h','checkpoint_population_search','build_solver.py','build_record.json','run_comparison.py','IMPLEMENTATION_DECISIONS.txt','validate_no_truth.py','evaluate_external.py','invariant_checks.cpp','check_invariants.py','invariant_checks','invariant_results.json','invariant_outputs.jsonl','last_score_fixture.cpp','check_last_score.py','last_score_fixture','last_score_results.json','last_score_outputs.jsonl','invariant_attempt1/failure_record.json','invariant_inputs/uniform_model.bin')
    return {name:sha(HERE/name) for name in names}
def already_used_seeds():
    # Only executed experiment manifests count as previous validation cases.
    checked=[];used=[]
    for folder in PROTECTED:
        file=ROOT/'work'/folder/'manifest.json'
        if not file.exists():continue
        data=json.loads(file.read_text());checked.append({'path':str(file.relative_to(ROOT)),'sha256':sha(file)})
        for case in data.get('cases',[]):
            for field in ('plant_seed','planted_seed','seed'):
                if case.get(field) in SEEDS:used.append({'path':str(file),'case':case,'field':field})
        for seed in data.get('predefined_seeds',[]):
            if seed in SEEDS:used.append({'path':str(file),'predefined_seed':seed})
    if used:raise RuntimeError(f'Proposed planting seeds already present: {used}')
    return {'checked':checked,'planting_seeds':list(SEEDS),'found_previous_use':False,'design_mentions_are_not_runs':True}
def plan():
    if (HERE/'sealed_design.json').exists():raise SystemExit('Cannot change a sealed design')
    build=json.loads((HERE/'build_record.json').read_text())
    checks=json.loads((HERE/'invariant_results.json').read_text())
    assert checks['status']=='passed' and sha(SOLVER)==build['solver_sha256']
    assert checks['solver_source_sha256']==sha(HERE/'checkpoint_population_search.cpp')
    supplemental=json.loads((HERE/'last_score_results.json').read_text());assert supplemental['status']=='passed'
    result={'phase':'14','date':'2026-10-03','status':'draft_for_audit_no_truth_no_main_runs',
        'scope':'Synthetic K2 only; known widths20x25; no K1/historical search',
        'models':list(MODELS),'planting_seeds':list(SEEDS),'rounds':[0,1],'arms':{k:{'local_cap':v[0],'checkpoint_merge':v[1]} for k,v in ARMS.items()},
        'expected_cases':4,'expected_rows':32,'lengths':[615,160],'convention':0,'widths':[20,25],
        'target_calls':100000,'soft_seconds':30,'checkpoint_at':50000,'preparation_complete_calls':7000,
        'source_move_count':16649,'periodic_refreshes':0,
        'order_rule':'Williams rows A B D C / B C A D / C D B A / D A C B, selected by (case_index+2*round)%4',
        'search_seed_rule':'((plant_seed XOR0xb7e151628aed2a6b)+round*0x9e3779b97f4a7c15) modulo2^64',
        'checkpoint_seed_rule':'search_seed XOR0x6a09e667f3bcc909; independent std::mt19937_64 uint64_t',
        'terminal_priority':'global > checkpoint > cap; convergence_observed independent; never admit after global cut',
        'pool_rule':'Generate/score without admission; initial20 offers all arms; checkpoint20 offers only ON after complete pool and while no global cut',
        'counting':'All IDP invocations through score() + frozen evaluate(); both preparations/perturbations/hill calls count. No truth or uncharged oracle evaluations.',
        'archive':'Top5 across all scored proposals; distinct numeric; IDP descending then numeric lexicographic; entries/reentries logged; K2=inverse(numeric)',
        'inheritance':'Frozen phase10 admission and uses; new17digit metadata for replay; checkpoint ancestry is audit metadata only',
        'time_analysis':'Keep all runs in raw totals. Same-cap fusion contrasts with a wall-time cut reported separately, not interpreted as isolated fusion effect.',
        'inference_limits':'Four paired synthetic cases, two rounds, active common pool; cap effect conditional on checkpoint. No general recovery rate/cipher-language exclusion.',
        'truth_isolation':'Truth generation external AFTER code audit, before searches; solver commands contain only model/ciphertexts/widths/search_seed/budgets/round/cap/merge/checkpoint',
        'build':build,'invariant_summary':checks,'last_score_fixture_summary':supplemental,'pre_audit_objective_calls_including_failed_attempt':17626+checks['objective_calls']+supplemental['objective_calls'],'resources':resources(),'protected_before':protected_hashes(),'seed_audit':already_used_seeds(),
        'models_and_holdouts':[{'path':str(p.relative_to(ROOT)),'sha256':sha(p)} for name in MODELS for p in (ROOT/'work/phase5_language'/name/'model.bin',ROOT/'work/phase5_language'/name/'holdout.txt')],
        'cases':[],'runs':[],'planned_at_unix':time.time()}
    for index,(model,seed) in enumerate((m,s) for m in MODELS for s in SEEDS):
        identifier=f'{model}_20x25_{seed}';paths=[HERE/'ciphertexts'/f'{identifier}_T{number}.txt' for number in (1,2)];commands=[]
        for round_index in (0,1):
            search_seed=((seed^0xb7e151628aed2a6b)+round_index*0x9e3779b97f4a7c15)&MASK
            for arm in ORDERS[(index+2*round_index)%4]:
                local,merge=ARMS[arm]
                command=[str(SOLVER),str(ROOT/'work/phase5_language'/model/'model.bin'),*map(str,paths),'20','25',str(search_seed),'100000','30',str(round_index),str(local),str(int(merge)),'50000']
                commands.append({'arm':arm,'local_cap':local,'checkpoint_merge':merge,'round':round_index,'search_seed':search_seed,'command':command})
        result['cases'].append({'case_id':identifier,'language_model':model,'plant_seed':seed,'w1':20,'w2':25,'ciphertext_paths':[str(p.relative_to(ROOT)) for p in paths],'commands':commands})
    assert sum(len(c['commands']) for c in result['cases'])==32
    save(HERE/'plan32.json',result)
    print(json.dumps({'status':result['status'],'planned_commands':32,'protected_files':len(result['protected_before']),'plan_sha256':sha(HERE/'plan32.json')}))
def approval(plan):
    record=json.loads((HERE/'audit_approval.json').read_text())
    assert record['approved'] is True and record['plan_sha256']==sha(HERE/'plan32.json')
    assert plan['resources']==resources() and plan['protected_before']==protected_hashes()
    return record
def seal():
    if (HERE/'manifest.json').exists() or (HERE/'truth.jsonl').exists():raise SystemExit('Refusing to overwrite phase14')
    manifest=json.loads((HERE/'plan32.json').read_text());approved=approval(manifest)
    assert manifest['status']=='draft_for_audit_no_truth_no_main_runs' and not manifest['runs']
    (HERE/'ciphertexts').mkdir(exist_ok=True);truths=[]
    for case in manifest['cases']:
        text=''.join(c.lower() for c in (ROOT/'work/phase5_language'/case['language_model']/'holdout.txt').read_text() if c.isascii() and c.isalpha())
        helper=[str(ROOT/'work/phase7_crypto/regenerate_planted_keys'),str(case['plant_seed']),str(len(text)),'20','25']
        truth=json.loads(subprocess.check_output(helper,text=True));position=truth['sample_position']
        plains=[text[position:position+615],text[position+615:position+775]]
        assert list(map(len,plains))==[615,160]
        ciphertexts=[enc(enc(p,truth['true_k1']),truth['true_k2']) for p in plains]
        files=[]
        for path,cipher in zip(case['ciphertext_paths'],ciphertexts):
            file=ROOT/path;file.write_text(cipher.upper()+'\n');files.append({'path':path,'sha256':sha(file)})
        case['ciphertext_files']=files
        truths.append({'case_id':case['case_id'],'language_model':case['language_model'],'plant_seed':case['plant_seed'],'w1':20,'w2':25,**truth})
    (HERE/'truth.jsonl').write_text(''.join(json.dumps(t,separators=(',',':'))+'\n' for t in truths))
    manifest.update(status='sealed_not_run',truth_sha256=sha(HERE/'truth.jsonl'),cases_sealed_at_unix=time.time(),audit_approval=approved,plan_sha256=sha(HERE/'plan32.json'))
    save(HERE/'sealed_design.json',manifest);save(HERE/'manifest.json',manifest)
    print(json.dumps({'status':manifest['status'],'planned_commands':32,'truth_sha256':manifest['truth_sha256']}))
def run_sealed():
    manifest=json.loads((HERE/'manifest.json').read_text());sealed=json.loads((HERE/'sealed_design.json').read_text())
    assert manifest==sealed and manifest['status']=='sealed_not_run' and not manifest['runs']
    approval(json.loads((HERE/'plan32.json').read_text()))
    assert sha(HERE/'truth.jsonl')==manifest['truth_sha256']
    for item in manifest['models_and_holdouts']:
        assert sha(ROOT/item['path'])==item['sha256']
    for case in manifest['cases']:
        for item in case['ciphertext_files']:assert sha(ROOT/item['path'])==item['sha256']
    with (HERE/'search_outputs.jsonl').open('x') as output:
        for case in manifest['cases']:
            for planned in case['commands']:
                began=time.monotonic();run={'case_id':case['case_id'],**{k:v for k,v in planned.items() if k!='command'},'command':planned['command'],'started_at_unix':time.time()}
                proc=subprocess.run(planned['command'],capture_output=True,text=True,check=True,timeout=40)
                assert len(proc.stdout.splitlines())==1;row=json.loads(proc.stdout)
                assert row['local_proposal_cap']==planned['local_cap'] and row['checkpoint_merge']==planned['checkpoint_merge']
                assert row['round']==planned['round'] and row['search_seed']==planned['search_seed']
                assert row['checkpoint_at']==50000 and row['target_objective_calls']==100000 and row['objective_calls']<=100000 and row['seconds_limit']==30
                assert not any(k.startswith(('truth_','true_')) for k in row)
                row.update(case_id=case['case_id'],language_model=case['language_model'],arm=planned['arm'])
                output.write(json.dumps(row,separators=(',',':'))+'\n');output.flush()
                run.update(status='completed',process_seconds=time.monotonic()-began,stderr=proc.stderr)
                manifest['runs'].append(run);save(HERE/'manifest.json',manifest)
                print(json.dumps({k:v for k,v in run.items() if k not in ('command','stderr')}),flush=True)
    manifest['protected_after']=protected_hashes();assert manifest['protected_after']==manifest['protected_before']
    manifest.update(status='completed',completed=True,protected_unchanged=True,log_sha256=sha(HERE/'search_outputs.jsonl'),ended_at_unix=time.time())
    save(HERE/'manifest.json',manifest)
    from validate_no_truth import main as check_completed_records
    check_completed_records()
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=('plan','seal','run-sealed'));args=parser.parse_args()
    {'plan':plan,'seal':seal,'run-sealed':run_sealed}[args.action]()

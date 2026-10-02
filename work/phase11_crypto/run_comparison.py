"""Seal fresh paired cases, then run only the sealed 32 K2-only searches."""
from pathlib import Path
import argparse,hashlib,json,subprocess,time

HERE=Path(__file__).resolve().parent;ROOT=HERE.parent.parent
MODELS=('de_fold','fr_fold');BANDS=((12,15),(20,25));SEEDS=(20262101,20262102)
METHODS=('population','cap5000');MASK=(1<<64)-1
BASE=ROOT/'work/phase10_crypto/population_search';VARIANT=HERE/'capped_population_search'
PROTECTED=('crypto','phase2_crypto','phase3_crypto','phase4_crypto','phase5_crypto','phase5_language','phase7_crypto','phase8_crypto','phase9_crypto','phase10_crypto')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,value):path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
def enc(text,key):return ''.join(text[c::len(key)] for c in key)
def protected_hashes():
 return [{'path':str(p.relative_to(ROOT)),'sha256':sha(p)} for name in PROTECTED for p in sorted((ROOT/'work'/name).rglob('*')) if p.is_file()]

def prepare():
 mf=HERE/'manifest.json'
 if mf.exists():raise SystemExit('Refusing to overwrite phase11 manifest')
 build=json.loads((HERE/'build_record.json').read_text())
 assert sha(BASE)==build['frozen_binary_sha256'] and sha(VARIANT)==build['solver_sha256']
 source=ROOT/build['frozen_source_path'];body=source.read_bytes();prefix=body[:body.index(b'int main(int argc,char**argv)')]
 assert (HERE/'phase10_frozen_classes.h').read_bytes()==prefix
 protected=protected_hashes();assert len(protected)==282
 manifest={'phase':'11','date':'2026-10-02','scope':'K2 only; no K1 or BLUME attack',
  'models':list(MODELS),'bands':[list(x) for x in BANDS],'predefined_seeds':list(SEEDS),'rounds':[0,1],
  'methods':list(METHODS),'method_order':'Round0 population then cap5000; round1 cap5000 then population. Alternated before outcomes.',
  'expected_pairs':8,'expected_rows':32,'lengths':[615,160],'convention':0,'messages_scored':2,
  'widths_disclosed':True,'keys_disclosed':False,'objective_calls_per_round':100000,'seconds_protection_per_round':30,
  'local_proposal_cap':5000,'source_move_counts':{'15':2840,'25':16649},
  'objective':'Frozen full-range greedy IDP: idp(undo2(ciphertext,inverse(numeric),0),w1,0,model,-1,true)',
  'counting':'Every IDP invocation counts, including1000-key pools, left-to-right swaps, hill-climb proposals and perturbations. No IDP cache or uncounted initial score.',
  'shared_initialization':'1000 random numeric keys, retain best20; one left-to-right pair-swap pass per retained key; both policies begin their first climb at the best survivor with identical search seed.',
  'baseline':'Exact frozen phase10 population binary, no rerouting through the variant or recompiled baseline. Full source climb, refresh after4converged offspring.',
  'variant':'Exact frozen source movements/objective/preparation/admission/parent-choice/perturbation classes. Each source climb, including first, stops after at most5000 proposals. No tuning after outcomes.',
  'convergence':'Only a complete shuffled movement sweep with no strict improvement is converged. A locally capped climb is partial even if its incomplete last sweep has no improvement. AtW2=25,5000<16649 so no variant climb can complete its first sweep.',
  'local_cut':'cap_local never sets the global cut flag or cause; its partial candidate is offered under the same admission rule, including the initial climb. Such a candidate is never labelled a complete local optimum.',
  'global_cut':'Before a next proposal, exhausted global evaluation/time limits take priority over the local cap. No terminal initial/offspring candidate is admitted after global_cut, preserving baseline behavior. Every scored proposal remains eligible for output top5. Started offspring is processed and partial even if globally interrupted; admission_event=-1 and offered=false. If refresh is due after global_cut, log pending without starting it.',
  'refresh':'Variant refresh after every4offspring processed, including converged, locally capped, rejected and globally interrupted climbs. Initial climb is never offspring. Refresh only while global cut is false; same1000+20-swap preparation and same merge/admission rule. This changes refresh frequency as well as per-parent search effort.',
  'population_admission':'Up to5 parents, minimum numeric Hamming ceil(0.4*W2)=6/10. Close means distance below threshold. Improve every close neighbor strictly by1e-12 to replace them; usage=max replaced usage. If no close neighbor, append if fewer than5 else improve worst strictly; new diverse usage0. Sort IDP descending then numeric lexicographic. No truth selection.',
  'parent_rule':'Least-used, tie IDP descending/numeric lexicographic; increment usage on selection, even if child later cuts. Perturbation3/5 disjoint swaps changes exactly6/10positions.',
  'archive':'Separate from parent population. Best up to5 distinct numeric keys by IDP across every evaluated proposal; ties numeric lexicographic. No distance filter; may cluster.',
  'truth_isolation':'Truth is generated and sealed outside the solver before first search. Commands accept only method, model, two ciphertexts, widths, search seed, total budgets and round. Evaluation external after all search commands.',
  'cost_limit':'Equal objective-call ceilings do not imply equal CPU time. Actual objective calls, setup, operations, internal elapsed and process elapsed logged.30s is soft, checked before evaluations; source-move construction starts inside clock. Preparation and logging costs are inside elapsed time.',
  'comparison_limit':'Paired population versus cap5000 on these8new cases. The variant changes effort allocation AND refresh frequency; no attribution solely to diversity. No cross-phase recovery-rate comparison.',
  'corpus_limit':'One literary work per language; disjoint training/holdout; known widths and shared keys. No1937commercial corpus, no language/cipher exclusion.',
  'protected_before':protected,'build':build,
  'solver_sha256':sha(VARIANT),'solver_source_sha256':sha(HERE/'capped_population_search.cpp'),
  'frozen_baseline':{'source_path':str(source.relative_to(ROOT)),'source_sha256':sha(source),'binary_path':str(BASE.relative_to(ROOT)),'binary_sha256':sha(BASE)},
  'runner_sha256':sha(Path(__file__)),'cases':[],'runs':[],'started_at_unix':time.time()}
 save(mf,manifest);(HERE/'ciphertexts').mkdir(exist_ok=True);truths=[]
 for model in MODELS:
  folder=ROOT/'work/phase5_language'/model;body=''.join(c.lower() for c in (folder/'holdout.txt').read_text() if c.isascii() and c.isalpha())
  for w1,w2 in BANDS:
   for seed in SEEDS:
    identifier=f'{model}_{w1}x{w2}_{seed}'
    helper=[str(ROOT/'work/phase7_crypto/regenerate_planted_keys'),str(seed),str(len(body)),str(w1),str(w2)]
    truth=json.loads(subprocess.check_output(helper,text=True));pos=truth['sample_position'];texts=[body[pos:pos+615],body[pos+615:pos+775]]
    assert list(map(len,texts))==[615,160]
    ciphertexts=[enc(enc(t,truth['true_k1']),truth['true_k2']) for t in texts]
    paths=[HERE/'ciphertexts'/f'{identifier}_T{n}.txt' for n in (1,2)]
    for path,text in zip(paths,ciphertexts):path.write_text(text.upper()+'\n')
    truths.append({'case_id':identifier,'language_model':model,'plant_seed':seed,'w1':w1,'w2':w2,**truth})
    commands=[]
    for round_index in (0,1):
     search_seed=((seed^0xb7e151628aed2a6b)+round_index*0x9e3779b97f4a7c15)&MASK
     for method in (METHODS if round_index==0 else tuple(reversed(METHODS))):
      binary=BASE if method=='population' else VARIANT
      command=[str(binary),method,str(folder/'model.bin'),*map(str,paths),str(w1),str(w2),str(search_seed),'100000','30',str(round_index)]
      commands.append({'method':method,'round':round_index,'search_seed':search_seed,'command':command})
    manifest['cases'].append({'case_id':identifier,'language_model':model,'plant_seed':seed,'w1':w1,'w2':w2,
     'ciphertext_files':[{'path':str(p.relative_to(ROOT)),'sha256':sha(p)} for p in paths],'commands':commands})
 (HERE/'truth.jsonl').write_text(''.join(json.dumps(t,separators=(',',':'))+'\n' for t in truths))
 manifest['truth_sha256']=sha(HERE/'truth.jsonl');manifest['cases_sealed_at_unix']=time.time();manifest['status']='sealed_not_run'
 save(mf,manifest);save(HERE/'sealed_design.json',manifest)
 print(json.dumps({'status':manifest['status'],'cases':8,'planned_searches':32,'protected_files':len(protected),'truth_sha256':manifest['truth_sha256']},ensure_ascii=False))

def run_sealed():
 mf=HERE/'manifest.json';manifest=json.loads(mf.read_text());sealed=json.loads((HERE/'sealed_design.json').read_text())
 assert manifest==sealed and manifest['status']=='sealed_not_run' and not manifest['runs']
 assert sha(Path(__file__))==manifest['runner_sha256']
 assert protected_hashes()==manifest['protected_before']
 assert sha(VARIANT)==manifest['solver_sha256'] and sha(HERE/'capped_population_search.cpp')==manifest['solver_source_sha256']
 assert sha(HERE/'truth.jsonl')==manifest['truth_sha256']
 for case in manifest['cases']:
  for item in case['ciphertext_files']:assert sha(ROOT/item['path'])==item['sha256']
 with (HERE/'search_outputs.jsonl').open('x') as out:
  for case in manifest['cases']:
   for planned in case['commands']:
    began=time.monotonic();run={'case_id':case['case_id'],'method':planned['method'],'round':planned['round'],'command':planned['command'],'started_at_unix':time.time()}
    proc=subprocess.run(planned['command'],capture_output=True,text=True,check=True,timeout=40)
    lines=proc.stdout.splitlines();assert len(lines)==1;row=json.loads(lines[0])
    assert row['method']==planned['method'] and row['round']==planned['round']
    assert row['objective_calls']<=100000 and row['target_objective_calls']==100000
    assert not any(k.startswith('truth_') or k.startswith('true_') for k in row)
    row.update(case_id=case['case_id'],language_model=case['language_model']);out.write(json.dumps(row,separators=(',',':'))+'\n');out.flush()
    run.update(status='completed',wall_seconds=time.monotonic()-began);manifest['runs'].append(run);save(mf,manifest)
    print(json.dumps({k:v for k,v in run.items() if k!='command'}),flush=True)
 manifest['protected_after']=protected_hashes();assert manifest['protected_before']==manifest['protected_after']
 manifest['protected_unchanged']=True;manifest['log_sha256']=sha(HERE/'search_outputs.jsonl');manifest['completed']=True
 manifest['status']='completed';manifest['ended_at_unix']=time.time();save(mf,manifest)

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('action',choices=('prepare','run-sealed'));args=parser.parse_args()
 prepare() if args.action=='prepare' else run_sealed()

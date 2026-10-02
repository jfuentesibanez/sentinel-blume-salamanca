"""Seal eight fresh pairs and population rules before K2-only comparison."""
from pathlib import Path
import hashlib,json,subprocess,time

HERE=Path(__file__).resolve().parent;ROOT=HERE.parent.parent
MODELS=('de_fold','fr_fold');BANDS=((12,15),(20,25));SEEDS=(20262001,20262002)
METHODS=('restart','population');MASK=(1<<64)-1
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,value):path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
def enc(text,key):return ''.join(text[c::len(key)] for c in key)
mf=HERE/'manifest.json'
if mf.exists():raise SystemExit('Refusing to overwrite prior phase10 run')
protected=[]
for name in ('crypto','phase2_crypto','phase3_crypto','phase4_crypto','phase5_crypto','phase5_language','phase7_crypto','phase8_crypto','phase9_crypto'):
 protected+=sorted(p for p in (ROOT/'work'/name).rglob('*') if p.is_file())
manifest={'phase':'10','date':'2026-10-02','scope':'K2 only; no K1 or BLUME attack',
 'models':list(MODELS),'bands':[list(x) for x in BANDS],'predefined_seeds':list(SEEDS),'rounds':[0,1],
 'methods':list(METHODS),'method_order':'Round0 restart then population; round1 population then restart. Alternated before outcomes.',
 'expected_pairs':8,'expected_rows':32,'lengths':[615,160],'convention':0,'messages_scored':2,
 'widths_disclosed':True,'keys_disclosed':False,'objective_calls_per_round':100000,'seconds_protection_per_round':30,
 'objective':'Frozen full-range greedy IDP: idp(undo2(ciphertext,inverse(numeric),0),w1,0,model,-1,true)',
 'counting':'Every IDP invocation counts, including1000-key initial pools, left-to-right swaps, hill-climb proposals and perturbations. No IDP cache or uncounted initial score.',
 'initialization':'1000 random numeric keys, retain best20; one left-to-right pair-swap pass per retained key; source hill climb from the best survivor. Exactly one climb per restart unit, unlike phase8.',
 'restart':'Repeat complete initialization plus source hill climb until objective or protection budget cuts.',
 'population':'Up to5 parents; numeric Hamming distance at least ceil(0.4*W2), fixed6/10. Initial20 survivors offered in descending IDP then numeric lexicographic order; greedy diverse admission. First climb from best prepared seed. Then least-used parent, tie IDP/lexicographic; usage incremented on selection, even if child search cuts. Perturbation3/5 disjoint swaps changing6/10positions, then source climb. After4completed offspring, prepare20 new survivors and merge under same admission rule.',
 'population_admission':'Close means distance below threshold. Replace all close neighbors only if candidate score improves every neighbor strictly by1e-12; new usage=max neighbor usage. If no close neighbor, append when fewer than5, otherwise replace worst only on strict IDP improvement; new diverse member usage0. Sort population by IDP then numeric key after admission. No changed thresholds or ground-truth selection.',
 'population_archive_separate':'Output archive remains best5 distinct keys by IDP across ALL evaluated proposals, without distance filtering; population is a separate set of parents.',
 'diversity_limit':'Hamming between numeric permutations is a reproducible proxy, not proven independence of search basins. Min distance may merge parents and leave fewer than5; large-key budgets may explore few children.',
 'archive':'Best up to5 distinct keys by IDP across every evaluated proposal; score ties ordered by numeric key; no record of all proposals is retained.',
 'cost_limit':'Same objective-call maxima do not imply same CPU time. Actual elapsed time, setup, cuts and operation counts logged. Time cutoff is checked before score calls and is soft.',
 'comparison_limit':'Compare restart vs population on new phase10 pairs. Do not infer improvement by comparing recovery rates across different phase9/10 seeds.',
 'corpus_limit':'One literary work per language; disjoint training/holdout; known widths and shared keys. No language-specific negative controls.',
 'protected_before':[{'path':str(p.relative_to(ROOT)),'sha256':sha(p)} for p in protected],
 'solver_sha256':sha(HERE/'population_search'),'solver_source_sha256':sha(HERE/'population_search.cpp'),
 'frozen_baseline':{'source_path':'work/phase9_crypto/k2_search.cpp','source_sha256':sha(ROOT/'work/phase9_crypto/k2_search.cpp'),'binary_path':'work/phase9_crypto/k2_search','binary_sha256':sha(ROOT/'work/phase9_crypto/k2_search')},
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
     command=[str(HERE/'population_search'),method,str(folder/'model.bin'),*map(str,paths),str(w1),str(w2),str(search_seed),'100000','30',str(round_index)]
     commands.append({'method':method,'round':round_index,'search_seed':search_seed,'command':command})
   manifest['cases'].append({'case_id':identifier,'language_model':model,'plant_seed':seed,'w1':w1,'w2':w2,
    'ciphertext_files':[{'path':str(p.relative_to(ROOT)),'sha256':sha(p)} for p in paths],'commands':commands})
(HERE/'truth.jsonl').write_text(''.join(json.dumps(t,separators=(',',':'))+'\n' for t in truths));manifest['truth_sha256']=sha(HERE/'truth.jsonl')
manifest['cases_sealed_at_unix']=time.time();save(mf,manifest)
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
manifest['protected_after']=[{'path':str(p.relative_to(ROOT)),'sha256':sha(p)} for p in protected]
assert manifest['protected_before']==manifest['protected_after'];manifest['protected_unchanged']=True
manifest['log_sha256']=sha(HERE/'search_outputs.jsonl');manifest['completed']=True;manifest['ended_at_unix']=time.time();save(mf,manifest)

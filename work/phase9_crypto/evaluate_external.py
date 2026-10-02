"""K2-only evaluation after search. Direct boundary enumeration, not C++ recurrence."""
from pathlib import Path
from collections import Counter
import hashlib,json,subprocess
import numpy as np

HERE=Path(__file__).resolve().parent;ROOT=HERE.parent.parent
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,value):path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
def enc(text,key):return ''.join(text[c::len(key)] for c in key)
def dec(text,key):
 columns={};offset=0
 for column in key:
  count=len(range(column,len(text),len(key)));columns[column]=text[offset:offset+count];offset+=count
 assert offset==len(text)
 return ''.join(columns[i%len(key)][i//len(key)] for i in range(len(text)))

def independent_idp(ciphertexts,key,width,table):
 total_matrix=np.zeros((width,width),dtype=np.float64);rows_total=0
 for ciphertext in ciphertexts:
  intermediate=np.array([ord(c)-97 for c in dec(ciphertext,key)],dtype=np.int64)
  rows,remainder=divmod(len(intermediate),width);rows_total+=rows
  blocks=[]
  for column in range(width):
   low=max(0,column-(width-remainder));high=min(column,remainder)
   blocks.append(np.stack([intermediate[column*rows+offset:column*rows+offset+rows] for offset in range(low,high+1)]))
  matrix=np.full((width,width),-1e6,dtype=np.float64)
  for left in range(width):
   for right in range(width):
    if left!=right:
     products=blocks[left][:,None,:]*26+blocks[right][None,:,:]
     matrix[left,right]=np.max(table[products].sum(axis=2))
  total_matrix+=matrix
 available_rows=np.ones(width,dtype=bool);available_columns=np.ones(width,dtype=bool)
 total=0.0
 for _ in range(width):
  allowed=available_rows[:,None]&available_columns[None,:]&~np.eye(width,dtype=bool)
  if allowed.any():
   masked=np.where(allowed,total_matrix,-np.inf);left,right=np.unravel_index(np.argmax(masked),masked.shape);value=masked[left,right]
  else:
   left=np.flatnonzero(available_rows)[-1];right=np.flatnonzero(available_columns)[-1];value=-7.0*rows_total
  total+=float(value);available_rows[left]=False;available_columns[right]=False
 return total/(rows_total*width)

manifest=json.loads((HERE/'manifest.json').read_text());assert manifest['completed'] and manifest['protected_unchanged']
assert manifest['predefined_seeds']==[20261901,20261902] and len(manifest['cases'])==8 and len(manifest['runs'])==32
assert manifest['protected_before']==manifest['protected_after']
for item in manifest['protected_before']:assert sha(ROOT/item['path'])==item['sha256']
assert sha(HERE/'k2_search')==manifest['solver_sha256'];assert sha(HERE/'k2_search.cpp')==manifest['solver_source_sha256']
assert sha(HERE/'run_comparison.py')==manifest['runner_sha256'];assert sha(HERE/'truth.jsonl')==manifest['truth_sha256']
assert sha(HERE/'search_outputs.jsonl')==manifest['log_sha256']
assert all(x['status']=='completed' and x['started_at_unix']>=manifest['cases_sealed_at_unix'] for x in manifest['runs'])
truths={x['case_id']:x for x in map(json.loads,(HERE/'truth.jsonl').read_text().splitlines())}
rows=list(map(json.loads,(HERE/'search_outputs.jsonl').read_text().splitlines()));assert len(rows)==32 and len(truths)==8
tables={};ciphertexts={};case_metadata={x['case_id']:x for x in manifest['cases']}
for case in manifest['cases']:
 name=case['language_model'];folder=ROOT/'work/phase5_language'/name
 if name not in tables:tables[name]=np.frombuffer((folder/'model.bin').read_bytes(),dtype='<f4',count=676).astype(np.float64)
 body=''.join(c.lower() for c in (folder/'holdout.txt').read_text() if c.isascii() and c.isalpha());truth=truths[case['case_id']]
 regenerated=json.loads(subprocess.check_output([str(ROOT/'work/phase7_crypto/regenerate_planted_keys'),str(case['plant_seed']),str(len(body)),str(case['w1']),str(case['w2'])],text=True))
 for field in ('sample_position','true_k1','true_k2'):assert truth[field]==regenerated[field]
 pos=truth['sample_position'];texts=[body[pos:pos+615],body[pos+615:pos+775]]
 generated=[enc(enc(text,truth['true_k1']),truth['true_k2']) for text in texts]
 for file,text in zip(case['ciphertext_files'],generated):
  assert sha(ROOT/file['path'])==file['sha256'];assert (ROOT/file['path']).read_text().strip().lower()==text
 ciphertexts[case['case_id']]=generated

cache={};evaluations=[];perturbation_checks=0;score_checks=0;identities=set()
def external_score(case_id,key):
 cache_key=(case_id,tuple(key))
 if cache_key not in cache:
  case=case_metadata[case_id];cache[cache_key]=independent_idp(ciphertexts[case_id],key,case['w1'],tables[case['language_model']])
 return cache[cache_key]
for row in rows:
 case=case_metadata[row['case_id']];truth=truths[row['case_id']]
 identity=(row['case_id'],row['method'],row['round']);assert identity not in identities;identities.add(identity)
 assert row['mode']=='ciphertext_only_k2' and row['messages_scored']==2 and row['convention']==0
 assert not any(k.startswith('true_') or k.startswith('truth_') for k in row)
 expected=next(x for x in case['commands'] if x['method']==row['method'] and x['round']==row['round'])
 assert row['search_seed']==expected['search_seed']
 assert row['target_objective_calls']==100000 and row['objective_calls']<=100000
 assert row['objective_calls']==sum(row[k] for k in ('random_pool_calls','left_to_right_swap_calls','hill_climb_calls','perturbation_calls'))
 assert row['objective_calls']==sum(x['calls'] for x in row['operation_traces'])+row['perturbation_calls']
 assert row['cut_cause'] in ('evaluations','wall_time','evaluations_and_wall_time')
 if 'evaluations' in row['cut_cause']:assert row['objective_calls']==100000
 if 'wall_time' in row['cut_cause']:assert row['seconds']>=30
 assert row['seconds_limit']==30 and 0<=row['setup_seconds']<=row['seconds']
 archive=row['archive'];keys=[tuple(x['k2']) for x in archive];assert 1<=len(keys)<=5 and len(set(keys))==len(keys)
 assert [x['rank'] for x in archive]==list(range(1,len(keys)+1))
 assert [x['idp'] for x in archive]==sorted((x['idp'] for x in archive),reverse=True)
 for candidate in archive:
  assert sorted(candidate['k2'])==list(range(case['w2']))
  assert abs(external_score(case['case_id'],candidate['k2'])-candidate['idp'])<1e-7;score_checks+=1
 for kick in row['perturbation_traces']:
  positions=kick['positions'];assert len(positions)==len(set(positions))==6
  base=kick['base_numeric'];changed=base[:]
  for pair in range(3):changed[positions[2*pair]],changed[positions[2*pair+1]]=changed[positions[2*pair+1]],changed[positions[2*pair]]
  assert changed==kick['perturbed_numeric'] and kick['hamming_distance']==6
  assert sum(a!=b for a,b in zip(base,changed))==6;perturbation_checks+=1
 assert len(row['perturbation_traces'])==row['perturbations_attempted']
 assert sum(x['scored'] for x in row['perturbation_traces'])==row['perturbations_scored']==row['perturbation_calls']
 if row['method']=='restart':assert row['perturbation_calls']==0
 true_idp=external_score(case['case_id'],truth['true_k2'])
 ranks=[x['rank'] for x in archive if x['k2']==truth['true_k2']]
 evaluations.append({'case_id':row['case_id'],'language_model':row['language_model'],'w1':row['w1'],'w2':row['w2'],
  'method':row['method'],'round':row['round'],'true_k2_in_archive':bool(ranks),'true_k2_ranks':ranks,
  'true_k2_best':1 in ranks,'true_k2_idp_external':true_idp,'best_archive_idp':archive[0]['idp'],
  'true_minus_best_idp':true_idp-archive[0]['idp'],'true_idp_greater_than_all':true_idp>archive[0]['idp']+1e-7,
  'objective_calls':row['objective_calls'],'seconds':row['seconds'],'cut_cause':row['cut_cause']})
cells=[]
for name in manifest['models']:
 for w1,w2 in manifest['bands']:
  for method in manifest['methods']:
   subset=[x for x in evaluations if x['language_model']==name and x['w1']==w1 and x['w2']==w2 and x['method']==method];assert len(subset)==4
   cells.append({'language_model':name,'w1':w1,'w2':w2,'method':method,'rows':4,
    'true_k2_in_archive':sum(x['true_k2_in_archive'] for x in subset),'true_k2_best':sum(x['true_k2_best'] for x in subset),
    'true_idp_greater_than_all':sum(x['true_idp_greater_than_all'] for x in subset),
    'objective_calls':sum(x['objective_calls'] for x in subset),'seconds':sum(x['seconds'] for x in subset)})
paired=[]
for case_id in truths:
 for round_index in (0,1):
  group=[x for x in evaluations if x['case_id']==case_id and x['round']==round_index];assert len(group)==2
  restart=next(x for x in group if x['method']=='restart');ils=next(x for x in group if x['method']=='ils')
  paired.append({'case_id':case_id,'round':round_index,'restart_true_k2':restart['true_k2_in_archive'],'ils_true_k2':ils['true_k2_in_archive'],
   'ils_minus_restart_best_idp':ils['best_archive_idp']-restart['best_archive_idp'],'ils_minus_restart_seconds':ils['seconds']-restart['seconds'],
   'same_objective_calls':ils['objective_calls']==restart['objective_calls']})
summary={'phase':'9','pairs':8,'rows':32,'k2_only':True,'historical_attack':False,'cells':cells,'paired_rounds':paired,
 'archive_hits_by_method':{m:sum(x['true_k2_in_archive'] for x in evaluations if x['method']==m) for m in manifest['methods']},
 'cases_with_any_archive_hit_by_method':{m:sum(any(x['true_k2_in_archive'] for x in evaluations if x['case_id']==c and x['method']==m) for c in truths) for m in manifest['methods']},
 'total_calls_by_method':{m:sum(x['objective_calls'] for x in evaluations if x['method']==m) for m in manifest['methods']},
 'total_seconds_by_method':{m:sum(x['seconds'] for x in evaluations if x['method']==m) for m in manifest['methods']},
 'cut_causes':dict(Counter(x['cut_cause'] for x in evaluations)),
 'true_idp_greater_than_all_rows':sum(x['true_idp_greater_than_all'] for x in evaluations),
 'limit':'Small paired K2-only pilot with known widths and one literary corpus per language. Objective calls equal does not imply equal CPU cost. No K1 recovery, language or BLUME exclusion.'}
(HERE/'external_evaluation.jsonl').write_text(''.join(json.dumps(x,separators=(',',':'))+'\n' for x in evaluations));save(HERE/'summary.json',summary)
verification={'passed':True,'rows_checked':32,'archive_idp_scores_checked':score_checks,'distinct_idp_computations':len(cache),
 'six_position_perturbations_checked':perturbation_checks,'protected_files_checked':len(manifest['protected_before']),
 'protected_phase8_files_checked':sum(x['path'].startswith('work/phase8_crypto/') for x in manifest['protected_before']),
 'protected_unchanged':True,'all_calls_metered_source_review':'Every objective call passes Search.evaluate; no truth object or score argument in solver.',
 'independent_idp':'Direct Cartesian enumeration of feasible offset blocks with NumPy, followed by greedy row/column assignment; no incremental C++ sums.',
 'artifact_sha256':{name:sha(HERE/name) for name in ('k2_search.cpp','k2_search','run_comparison.py','evaluate_external.py','manifest.json','truth.jsonl','search_outputs.jsonl','external_evaluation.jsonl','summary.json')}}
save(HERE/'verification.json',verification)
print(json.dumps({'verification':verification,'summary':summary},ensure_ascii=False))

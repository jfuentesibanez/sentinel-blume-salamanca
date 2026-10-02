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
assert manifest['predefined_seeds']==[20262001,20262002] and len(manifest['cases'])==8 and len(manifest['runs'])==32
assert manifest['protected_before']==manifest['protected_after']
for item in manifest['protected_before']:assert sha(ROOT/item['path'])==item['sha256']
assert sha(HERE/'population_search')==manifest['solver_sha256'];assert sha(HERE/'population_search.cpp')==manifest['solver_source_sha256']
for kind in ('source','binary'):
 assert sha(ROOT/manifest['frozen_baseline'][kind+'_path'])==manifest['frozen_baseline'][kind+'_sha256']
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

cache={};evaluations=[];perturbation_checks=0;score_checks=0;identities=set();population_events_checked=0;parent_choices_checked=0;population_score_checks=0;population_candidate_scores_checked=0;perturbation_scores_checked=0
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
  expected_distance=2*(((2*case['w2']+4)//5+1)//2)
  positions=kick['positions'];assert len(positions)==len(set(positions))==expected_distance
  base=kick['base_numeric'];changed=base[:]
  for pair in range(expected_distance//2):changed[positions[2*pair]],changed[positions[2*pair+1]]=changed[positions[2*pair+1]],changed[positions[2*pair]]
  assert changed==kick['perturbed_numeric'] and kick['hamming_distance']==expected_distance
  assert sum(a!=b for a,b in zip(base,changed))==expected_distance;perturbation_checks+=1
  if kick['scored']:
   key=[changed.index(position) for position in range(case['w2'])]
   assert abs(external_score(case['case_id'],key)-kick['idp'])<1e-7;perturbation_scores_checked+=1
 assert len(row['perturbation_traces'])==row['perturbations_attempted']
 assert sum(x['scored'] for x in row['perturbation_traces'])==row['perturbations_scored']==row['perturbation_calls']
 if row['method']=='restart':assert row['perturbation_calls']==0
 if row['method']=='population':
  minimum=(2*case['w2']+4)//5;assert row['population_minimum_distance']==minimum
  def distance(left,right):return sum(a!=b for a,b in zip(left,right))
  def verify_population(population):
   global population_score_checks
   assert len(population)<=5 and len({x['id'] for x in population})==len(population)
   assert len({tuple(x['numeric']) for x in population})==len(population)
   assert population==sorted(population,key=lambda x:(-x['idp'],x['numeric']))
   for i,left in enumerate(population):
    assert sorted(left['numeric'])==list(range(case['w2'])) and left['uses']>=0
    key=[left['numeric'].index(position) for position in range(case['w2'])]
    assert abs(external_score(case['case_id'],key)-left['idp'])<1e-7;population_score_checks+=1
    for right in population[i+1:]:assert distance(left['numeric'],right['numeric'])>=minimum
  state=[];actions=sorted([(x['sequence'],'admit',x) for x in row['population_events']]+[(x['sequence'],'parent',x) for x in row['parent_choices']])
  assert [x[0] for x in actions]==list(range(1,len(actions)+1))
  for _,kind,action in actions:
   if kind=='parent':
    expected=min(state,key=lambda x:(x['uses'],-x['idp'],x['numeric']))
    assert action['selected_id']==expected['id'] and action['uses_before']==expected['uses']
    state=[dict(x) for x in state];selected=next(x for x in state if x['id']==expected['id']);selected['uses']+=1
    assert action['uses_after']==selected['uses'] and state==action['population_after_use'];parent_choices_checked+=1
   else:
    assert action['before']==state
    candidate_key=[action['candidate_numeric'].index(position) for position in range(case['w2'])]
    assert abs(external_score(case['case_id'],candidate_key)-action['candidate_idp'])<1e-7;population_candidate_scores_checked+=1
    distances=[distance(action['candidate_numeric'],x['numeric']) for x in state]
    assert action['distances_before']==distances
    neighbors=[x for x,d in zip(state,distances) if d<minimum]
    assert action['close_neighbor_ids']==[x['id'] for x in neighbors]
    expected_state=[dict(x) for x in state];new_member=None
    if neighbors:
     if all(action['candidate_idp']>x['idp']+1e-12 for x in neighbors):
      decision='replace_close_neighbors';expected_state=[x for x in expected_state if x['id'] not in action['close_neighbor_ids']]
      new_member={'numeric':action['candidate_numeric'],'idp':action['candidate_idp'],'uses':max(x['uses'] for x in neighbors)}
     else:decision='reject_close_neighbor_score'
    elif len(state)<5:
     decision='append_diverse';new_member={'numeric':action['candidate_numeric'],'idp':action['candidate_idp'],'uses':0}
    else:
     worst=min(state,key=lambda x:(x['idp'],[-value for value in x['numeric']]))
     if action['candidate_idp']>worst['idp']+1e-12:
      decision='replace_worst_diverse';assert action['replaced_worst_id']==worst['id']
      expected_state=[x for x in expected_state if x['id']!=worst['id']]
      new_member={'numeric':action['candidate_numeric'],'idp':action['candidate_idp'],'uses':0}
     else:decision='reject_worst_score'
    assert decision==action['decision']
    if new_member:
     additions=[x for x in action['after'] if x['id'] not in {p['id'] for p in state}];assert len(additions)==1
     new_member['id']=additions[0]['id'];expected_state.append(new_member)
    expected_state.sort(key=lambda x:(-x['idp'],x['numeric']))
    assert expected_state==action['after'];state=expected_state;population_events_checked+=1
   verify_population(state)
  assert state==row['final_population'];assert len(row['parent_choices'])==row['perturbations_attempted']
  for choice,kick in zip(row['parent_choices'],row['perturbation_traces']):
   assert choice['selected_id']==kick['parent_id']
   selected=next(x for x in choice['population_after_use'] if x['id']==choice['selected_id'])
   assert selected['numeric']==kick['base_numeric']
  first_group=row['population_events'][:20]
  assert len(first_group)==20 and all(x['origin']=='prepared_survivor' for x in first_group)
  assert [x['candidate_idp'] for x in first_group]==sorted((x['candidate_idp'] for x in first_group),reverse=True)
  assert len(row['refresh_traces'])==row['population_refreshes']==row['offspring_completed']//4
  for refresh in row['refresh_traces']:
   assert refresh['offspring_completed']==refresh['number']*4 and refresh['mode']=='merge_same_rule'
   if refresh['completed']:
    group=row['population_events'][refresh['first_admission_event']-1:refresh['last_admission_event']]
    assert len(group)==20 and all(x['origin']=='prepared_survivor' for x in group)
    assert [x['candidate_idp'] for x in group]==sorted((x['candidate_idp'] for x in group),reverse=True)
    assert group[0]['before']==refresh['before'] and group[-1]['after']==refresh['after']
   else:assert refresh['before']==refresh['after']
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
  restart=next(x for x in group if x['method']=='restart');population=next(x for x in group if x['method']=='population')
  paired.append({'case_id':case_id,'round':round_index,'restart_true_k2':restart['true_k2_in_archive'],'population_true_k2':population['true_k2_in_archive'],
   'population_minus_restart_best_idp':population['best_archive_idp']-restart['best_archive_idp'],'population_minus_restart_seconds':population['seconds']-restart['seconds'],
   'same_objective_calls':population['objective_calls']==restart['objective_calls']})
summary={'phase':'10','pairs':8,'rows':32,'k2_only':True,'historical_attack':False,'cells':cells,'paired_rounds':paired,
 'archive_hits_by_method':{m:sum(x['true_k2_in_archive'] for x in evaluations if x['method']==m) for m in manifest['methods']},
 'cases_with_any_archive_hit_by_method':{m:sum(any(x['true_k2_in_archive'] for x in evaluations if x['case_id']==c and x['method']==m) for c in truths) for m in manifest['methods']},
 'total_calls_by_method':{m:sum(x['objective_calls'] for x in evaluations if x['method']==m) for m in manifest['methods']},
 'total_seconds_by_method':{m:sum(x['seconds'] for x in evaluations if x['method']==m) for m in manifest['methods']},
 'cut_causes':dict(Counter(x['cut_cause'] for x in evaluations)),
 'true_idp_greater_than_all_rows':sum(x['true_idp_greater_than_all'] for x in evaluations),
 'limit':'Small paired K2-only pilot with known widths and one literary corpus per language. Objective calls equal does not imply equal CPU cost. No K1 recovery, language or BLUME exclusion.'}
summary['total_process_wall_seconds_by_method']={m:sum(x['wall_seconds'] for x in manifest['runs'] if x['method']==m) for m in manifest['methods']}
summary['population_diagnostics']=[]
for row in rows:
 if row['method']!='population':continue
 final=row['final_population'];archive=row['archive']
 population_distances=[sum(a!=b for a,b in zip(x['numeric'],y['numeric'])) for i,x in enumerate(final) for y in final[i+1:]]
 archive_distances=[sum(a!=b for a,b in zip(x['k2'],y['k2'])) for i,x in enumerate(archive) for y in archive[i+1:]]
 true_key=truths[row['case_id']]['true_k2']
 summary['population_diagnostics'].append({'case_id':row['case_id'],'round':row['round'],
  'threshold':row['population_minimum_distance'],'final_population_size':len(final),
  'final_population_min_distance':min(population_distances) if population_distances else None,
  'output_archive_min_distance':min(archive_distances) if archive_distances else None,
  'parent_choices':len(row['parent_choices']),'offspring_completed':row['offspring_completed'],
  'refreshes':row['population_refreshes'],'admissions':len(row['population_events']),
  'rejections':sum(x['decision'].startswith('reject') for x in row['population_events']),
  'true_k2_in_final_population':any([member['numeric'].index(k) for k in range(row['w2'])]==true_key for member in final)})
(HERE/'external_evaluation.jsonl').write_text(''.join(json.dumps(x,separators=(',',':'))+'\n' for x in evaluations));save(HERE/'summary.json',summary)
verification={'passed':True,'rows_checked':32,'archive_idp_scores_checked':score_checks,'distinct_idp_computations':len(cache),
 'disjoint_swap_perturbations_checked':perturbation_checks,'population_admission_events_checked':population_events_checked,
 'parent_choices_checked':parent_choices_checked,'population_state_score_checks':population_score_checks,
 'population_candidate_scores_checked':population_candidate_scores_checked,'perturbation_scores_checked':perturbation_scores_checked,
 'protected_files_checked':len(manifest['protected_before']),
 'protected_phase9_files_checked':sum(x['path'].startswith('work/phase9_crypto/') for x in manifest['protected_before']),
 'protected_unchanged':True,'all_calls_metered_source_review':'Every objective call passes Search.evaluate; no truth object or score argument in solver.',
 'independent_idp':'Direct Cartesian enumeration of feasible offset blocks with NumPy, followed by greedy row/column assignment; no incremental C++ sums.',
 'artifact_sha256':{name:sha(HERE/name) for name in ('population_search.cpp','population_search','run_comparison.py','evaluate_external.py','manifest.json','truth.jsonl','search_outputs.jsonl','external_evaluation.jsonl','summary.json')}}
save(HERE/'verification.json',verification)
print(json.dumps({'verification':verification,'summary':summary},ensure_ascii=False))

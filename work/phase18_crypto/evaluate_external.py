"""One target comparison of sealed data AFTER independent saved-record audits.

No objective evaluations, no new trajectories, no outcome-dependent searches.
"""
from pathlib import Path
import csv,hashlib,json
from experiment import ROOT,HERE,AUD,REVIEW,TRUTH,sha,load,save,normalize,enc,inverse,verify_map
def main():
 assert not(HERE/'evaluation.json').exists(),'No replacement evaluation'
 m=load(HERE/'manifest.json');plan=load(HERE/'plan.json');ms=sha(HERE/'manifest.json')
 assert m['status']=='completed'and m['protected_unchanged']and len(m['runs'])==len(m['profiles'])==12
 gates=[load(AUD/'records_root.json'),load(REVIEW/'records_independent.json'),load(AUD/'numeric_attempt.json')]
 assert all(g['status']=='passed'and g['manifest_sha256']==ms for g in gates)
 gate=load(AUD/'target_gate.json')
 assert gate['root_approved']and gate['independent_approved']and gate['manifest_sha256']==ms and gate['plan_sha256']==sha(HERE/'plan.json')
 assert gate['records_root_sha256']==sha(AUD/'records_root.json')and gate['records_independent_sha256']==sha(REVIEW/'records_independent.json')and gate['numeric_sha256']==sha(AUD/'numeric_attempt.json')
 assert m['truth_path']==str((TRUTH/'truth.jsonl').relative_to(ROOT));truth_path=ROOT/m['truth_path']
 assert sha(truth_path)==m['truth_sha256'];verify_map(plan['resources'])
 truth={t['case_id']:t for t in map(json.loads,truth_path.read_text().splitlines())};cases={c['case_id']:c for c in m['cases']}
 assert len(truth)==len(cases)==4
 for cid,t in truth.items():
  body=normalize(ROOT/f'work/phase5_language/{t["language_model"]}/holdout.txt');pos=t['sample_position'];plain=[body[pos:pos+615],body[pos+615:pos+775]]
  assert t['plaintext_sha256']==[hashlib.sha256(s.encode()).hexdigest()for s in plain]
  for text,item in zip(plain,cases[cid]['ciphertext_files']):assert sha(ROOT/item['path'])==item['sha256']and(ROOT/item['path']).read_text().strip()==enc(enc(text,t['true_k1']),t['true_k2'])
 results=[]
 for p,r in zip(m['profiles'],m['runs']):
  assert p['profile_id']==r['profile_id'];s=r['summary'];target=tuple(inverse(truth[p['case_id']]['true_k2']));initial=tuple(map(int,(ROOT/p['start_path']).read_text().split()));assert sha(ROOT/p['start_path'])==p['start_sha256']
  if p['category']=='main':
   generation=load(HERE/'generation'/f'{p["case_id"]}_start{p["start_name"][-1]}.json');assert generation['seed']==p['start_seed']and tuple(generation['numeric'])==initial
  else:
   expected=list(target);expected[0],expected[1]=expected[1],expected[0];assert initial==tuple(expected)
  assert sha(ROOT/p['csv_path'])==r['csv_sha256']and sha(ROOT/p['summary_path'])==r['summary_sha256']
  archive={};visited=set();first=first_top=None;minimum=25;count=0
  with(ROOT/p['csv_path']).open()as f:
   for row in csv.DictReader(f):
    count+=1;k=tuple(map(int,row['candidate_numeric'].split(':')));num=int(row['numerator']);visited.add(k);minimum=min(minimum,sum(a!=b for a,b in zip(k,target)))
    if k==target and first is None:first=count
    archive[k]=num;archive=dict(sorted(archive.items(),key=lambda x:(-x[1],x[0]))[:5])
    if target in archive and first_top is None:first_top=count
  assert count==s['calls']and len(visited)==s['visited_unique']
  expected=[dict(rank=i+1,numerator=n,numeric=list(k))for i,(k,n)in enumerate(archive.items())];assert expected==s['archive']
  adopted=[a['call']for a in s['accept_events']if tuple(a['to_numeric'])==target]
  first_adopt=1 if initial==target and count else(min(adopted)if adopted else None)
  rank=next((i+1 for i,k in enumerate(archive)if k==target),None)
  result={k:p[k]for k in('profile_id','case_id','category','start_name','start_seed','privileged')};result.update(target_final_top5=rank is not None,final_archive_target_rank=rank,target_ever_scored=first is not None,first_target_call=first,target_ever_top5=first_top is not None,first_target_top5_call=first_top,first_adoption_call=first_adopt,final_current_is_target=tuple(s['final_numeric'])==target,initial_hamming=sum(a!=b for a,b in zip(initial,target)),minimum_scored_hamming=minimum if count else None,exact_calls=count,visited_unique=len(visited),full_sweeps=s['full_sweeps'],partial_sweeps=s['partial_sweeps'],accepted_changes=s['accepted_changes'],convergence_observed=s['convergence_observed'],stop_reason=s['stop_reason'],seconds=s['seconds'])
  results.append(result)
 main_profiles=[r for r in results if r['category']=='main'];positives=[r for r in results if r['category']=='positive_control'];assert len(main_profiles)==8 and len(positives)==4
 totals=dict(main_profiles=8,main_cases=4,main_final_top5=sum(r['target_final_top5']for r in main_profiles),main_ever_scored=sum(r['target_ever_scored']for r in main_profiles),main_final_current=sum(r['final_current_is_target']for r in main_profiles),positive_profiles=4,positive_final_top5=sum(r['target_final_top5']for r in positives),positive_final_current=sum(r['final_current_is_target']for r in positives),main_IDP=m['main_exact_calls'],positive_IDP=m['positive_exact_calls'],reference_IDP=gates[2]['exact_calls_started'],mock_callbacks=59)
 totals['total_IDP']=totals['main_IDP']+totals['positive_IDP']+totals['reference_IDP'];assert totals['total_IDP']<=1398552
 save(HERE/'evaluation.json',dict(status='evaluated',manifest_sha256=ms,plan_sha256=sha(HERE/'plan.json'),truth_sha256=m['truth_sha256'],totals=totals,profiles=results,cases=list(truth.values()),initial_distinct_main_keys=len({tuple(load(HERE/'generation'/f'{p["case_id"]}_start{p["start_name"][-1]}.json')['numeric'])for p in m['profiles']if p['category']=='main'}),scope='8 random starts nested on4 new synthetic cases, four privileged positives separate. Known widths/model/convention. ExactK2 only, noK1/plaintext or historical decrypt. Not language rates, superiority or global impossibility. Hamming not movement-graph distance.',new_IDP=0,new_searches=0))
 print(json.dumps(totals))
if __name__=='__main__':main()

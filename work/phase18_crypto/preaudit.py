"""Root static/resource audit, before truth. No RNG, solver, or IDP calls."""
import ast,json,struct,sys
from pathlib import Path
from experiment import ROOT,HERE,AUD,REVIEW,TRUTH,sha,load,save,verify_map
def main():
 assert not(HERE/'manifest.json').exists()and not(TRUTH/'truth.jsonl').exists()
 plan=load(HERE/'plan.json');verify_map(plan['resources']);verify_map(load(AUD/'frozen_before.json')['files'])
 assert plan['ceilings']['total_IDP']==8*166491+4*16650+24==1398552
 assert plan['main_profiles']==8 and plan['positive_profiles']==4
 assert plan['main_limits']==dict(max_calls=166491,max_sweeps=10,soft_seconds=30,hard_seconds=40)
 assert plan['positive_limits']==dict(max_calls=16650,max_sweeps=1,soft_seconds=30,hard_seconds=40)
 assert [c['plant_seed']for c in plan['cases']]==[20262801,20262802,20262803,20262804]
 starts=[s for c in plan['cases']for s in c['start_seeds']];assert starts==list(range(831004001,831004009))and len(set(starts))==8
 seeds=load(AUD/'seed_reservation.json');assert not seeds['prior_use_hits']
 assert [c['sample_position']for c in plan['cases']]==[2242,3017,0,775]
 controls=load(HERE/'control_results.json');assert controls['status']=='passed'and controls['mock_callback_calls']==59 and controls['policy_fixtures']==16
 assert controls['actual_exact_IDP_calls_all_attempts']==controls['actual_legacy_IDP_calls_all_attempts']==0
 build=load(HERE/'build_record.json');assert build['binary_sha256']==sha(HERE/'trajectory')and build['source_sha256']==sha(HERE/'trajectory.cpp')and build['core_byte_identical_to_phase16']
 new=(HERE/'trajectory.cpp').read_text();old=(ROOT/'work/phase16_crypto/trajectory.cpp').read_text();extract=lambda s:s[s.index('struct Core {'):s.index('\nint trajectory_main')]
 assert extract(new)==extract(old)and sha(HERE/'exact_scorer.h')==sha(ROOT/'work/phase16_crypto/exact_scorer.h')
 assert sha(HERE/'moves.json')==sha(ROOT/'work/phase16_crypto/moves.json')
 models=[]
 for lang in('de_fold','fr_fold'):
  p=ROOT/f'work/phase5_language/{lang}/model.bin';weights=struct.unpack('<676f',p.read_bytes()[:2704]);scale=max(f.as_integer_ratio()[1]for f in weights)
  assert scale<=2**62;models.append(dict(language=lang,scale=scale,denominator=scale*38*20,sha256=sha(p),no_scores_evaluated=True))
 for p in HERE.glob('*.py'):ast.parse(p.read_text())
 save(AUD/'root_preapproval.json',dict(status='passed_before_truth',root_approved=True,plan_sha256=sha(HERE/'plan.json'),resources=plan['resources'],models=models,RNG_calls=0,IDP_calls=0,truth_generated=False,source_sha256=sha(Path(__file__)),mock_callbacks_preparation=59,limits='Root reviewed source and gates; independent approval still required. No statistical claims about frozen literary corpus or pseudorandom seeds.'))
 print(json.dumps(dict(status='root_preapproval_passed',plan_sha256=sha(HERE/'plan.json'),IDP=0,RNG=0)))
if __name__=='__main__':main()

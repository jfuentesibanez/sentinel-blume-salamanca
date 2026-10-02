"""Small pre-audit controls with a uniform model and periodic text, without truth."""
from pathlib import Path
import hashlib,json,math,struct,subprocess,time
HERE=Path(__file__).resolve().parent
SCENARIOS=('sha','pair_short_off','pair_short_on','pair_long_off','pair_long_on','global_all_tie','checkpoint_cap_tie','cap_only','sweep_checkpoint','sweep_global','perturbation_checkpoint','time_before_first','expired_offer','invalid_offers')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    for name in ('invariant_results.json','invariant_outputs.jsonl'):
        if (HERE/name).exists():raise SystemExit('Refusing to overwrite invariant records; review before rerunning')
    folder=HERE/'invariant_inputs';folder.mkdir(exist_ok=True)
    model=folder/'uniform_model.bin'
    with model.open('wb') as output:
        for size in (26**2,26**3,26**4):output.write(struct.pack('<f',-math.log10(size))*size)
    binary=HERE/'invariant_checks';command=['/usr/bin/clang++','-std=c++17','-O3',str(HERE/'invariant_checks.cpp'),'-o',str(binary)]
    began=time.monotonic();subprocess.run(command,check=True);build_seconds=time.monotonic()-began
    rows={};costs=[]
    with (HERE/'invariant_outputs.jsonl').open('x') as output:
        for scenario in SCENARIOS:
            began=time.monotonic();proc=subprocess.run([str(binary),scenario,str(model)],capture_output=True,text=True,check=True,timeout=15)
            elapsed=time.monotonic()-began
            row=json.loads(proc.stdout);row['control_scenario']=scenario;row['control_process_seconds']=elapsed;rows[scenario]=row
            output.write(json.dumps(row,separators=(',',':'))+'\n')
            costs.append({'scenario':scenario,'objective_calls':row['objective_calls'],'process_seconds':elapsed})
    for kind in ('short','long'):
        off=rows[f'pair_{kind}_off'];on=rows[f'pair_{kind}_on']
        assert off['pre_checkpoint']==on['pre_checkpoint']
        assert off['archive']==on['archive'] # Uniform scores reject every new full-parent offer.
        for stage in ('initial_pool','checkpoint_pool'):
            a=next(p for p in off['preparations'] if p['stage']==stage);b=next(p for p in on['preparations'] if p['stage']==stage)
            assert a['random_keys']==b['random_keys'] and a['survivors']==b['survivors'] and a['rng_before']==b['rng_before'] and a['rng_after']==b['rng_after']
        assert off['checkpoint_trace']['offers']==0 and on['checkpoint_trace']['offers']==20
    checkpoints=[next(p for p in rows[name]['preparations'] if p['stage']=='checkpoint_pool') for name in SCENARIOS if name.startswith('pair_')]
    assert all(p['random_keys']==checkpoints[0]['random_keys'] and p['survivors']==checkpoints[0]['survivors'] for p in checkpoints)
    for name,row in rows.items():
        if name=='sha':continue
        assert row['objective_calls']==sum(row[k] for k in ('random_pool_calls','left_to_right_swap_calls','hill_climb_calls','perturbation_calls'))
        assert row['objective_calls']<=row['target_objective_calls']
        assert len(row['archive'])<=5 and len({tuple(a['k2']) for a in row['archive']})==len(row['archive'])
        for candidate in row['archive']:assert sorted(candidate['k2'])==list(range(6))
        assert len(row['offer_metadata'])==len(row['population_events'])
        assert row['periodic_refreshes']==0
    result={'status':'passed','controls':len(SCENARIOS),'objective_calls':sum(x['objective_calls'] for x in costs),'main_searches':0,
        'truth_used':False,'historical_ciphertexts_used':False,'uniform_model_sha256':sha(model),
        'control_source_sha256':sha(HERE/'invariant_checks.cpp'),'control_binary_sha256':sha(binary),
        'solver_source_sha256':sha(HERE/'checkpoint_population_search.cpp'),'sha256_helper_sha256':sha(HERE/'sha256.h'),
        'outputs_sha256':sha(HERE/'invariant_outputs.jsonl'),'build_seconds':build_seconds,'costs':costs,
        'limits':'Small geometry3x6 and uniform score validate state/count invariants, not recovery or exact20x25 checkpoints.'}
    (HERE/'invariant_results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()

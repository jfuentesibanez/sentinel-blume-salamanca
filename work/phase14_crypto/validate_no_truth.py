"""Compare recorded32-run factorial states without reading any truth or scoring keys."""
from pathlib import Path
from collections import defaultdict
import hashlib,json,math
HERE=Path(__file__).resolve().parent
def verify(rows,plan):
    assert len(rows)==32
    groups=defaultdict(list);identities=set();archive_entries=0;converged=0
    for row in rows:
        identity=(row['case_id'],row['round'],row['arm']);assert identity not in identities;identities.add(identity)
        groups[(row['case_id'],row['round'])].append(row)
        assert row['objective_calls']==sum(row[k] for k in ('random_pool_calls','left_to_right_swap_calls','hill_climb_calls','perturbation_calls'))<=100000
        assert row['objective_calls']==sum(p['calls'] for p in row['preparations'])+sum(p['calls'] for p in row['operation_traces'])+row['perturbation_calls']
        assert row['periodic_refreshes']==0 and row['checkpoint_starts']<=1
        assert len(row['offer_metadata'])==len(row['population_events'])
        previous=[];last_call=0
        for event in row['archive_events']:
            assert event['objective_calls']>last_call;last_call=event['objective_calls']
            candidate={'numeric':event['numeric'],'idp':event['idp']}
            assert sorted(candidate['numeric'])==list(range(25)) and math.isfinite(candidate['idp'])
            assert not any(x['numeric']==candidate['numeric'] for x in previous)
            expected=sorted(previous+[candidate],key=lambda x:(-x['idp'],x['numeric']))[:5]
            assert expected==event['archive_after'] and expected[event['entered_rank']-1]==candidate
            assert event['k2']==[candidate['numeric'].index(i) for i in range(25)]
            previous=expected;archive_entries+=1
        assert len(row['archive'])==len(previous)
        for inherited,precise in zip(row['archive'],previous):
            assert inherited['k2']==[precise['numeric'].index(i) for i in range(25)]
            assert abs(inherited['idp']-precise['idp'])<1e-8
        for trace in row['operation_traces']:
            assert trace['kind']=='hill_climb' and trace['calls']<=row['local_proposal_cap']
            assert trace['source_move_count']==16649
            assert trace['calls']==(trace['sweeps']-1)*16649+trace['last_sweep_proposals'] if trace['sweeps'] else trace['calls']==0
            if trace['stop_reason']=='cap_local':assert trace['calls']==row['local_proposal_cap'] and not trace['global_cut']
            if trace['stop_reason']=='checkpoint':assert trace['calls_after']==50000 and not trace['global_cut']
            if trace['convergence_observed']:
                assert trace['last_sweep_proposals']==16649 and not trace['last_sweep_improved'];converged+=1
        for pool in row['preparations']:
            assert pool['calls']==pool['random_pool_calls']+pool['swap_calls']
            assert len(pool['random_keys'])==pool['random_pool_calls']
            if pool['completed']:assert pool['calls']==7000 and len(pool['survivors'])==20
    paired_prefixes=0;partial_prefixes=0;pool_prefix_comparisons=0;full_pool_comparisons=0;timed_fusion_pairs=[]
    for identity,arms in groups.items():
        assert len(arms)==4 and {r['arm'] for r in arms}==set(plan['arms'])
        for cap in (5000,33298):
            pair=[r for r in arms if r['local_proposal_cap']==cap];assert len(pair)==2 and {r['checkpoint_merge'] for r in pair}=={False,True}
            if all(r['pre_checkpoint'] is not None for r in pair):assert pair[0]['pre_checkpoint']==pair[1]['pre_checkpoint'];paired_prefixes+=1
            else:partial_prefixes+=1
            if any('wall_time' in r['cut_cause'] for r in pair):timed_fusion_pairs.append({'case_id':identity[0],'round':identity[1],'local_cap':cap})
        for stage in ('initial_pool','checkpoint_pool'):
            pools=[p for r in arms for p in r['preparations'] if p['stage']==stage]
            for p in pools[1:]:
                common=min(len(p['random_keys']),len(pools[0]['random_keys']))
                assert p['random_keys'][:common]==pools[0]['random_keys'][:common];pool_prefix_comparisons+=1
            completed=[p for p in pools if p['completed']]
            for p in completed[1:]:assert p['survivors']==completed[0]['survivors'];full_pool_comparisons+=1
    return {'status':'passed','rows':32,'paired_prefixes_checked':paired_prefixes,'pairs_without_two_complete_prefixes':partial_prefixes,
            'random_pool_prefix_comparisons':pool_prefix_comparisons,'complete_pool_comparisons':full_pool_comparisons,
            'archive_entries_replayed':archive_entries,'observed_convergences':converged,'fusion_pairs_with_time_cut':timed_fusion_pairs,
            'truth_read':False,'new_objective_calls':0,'limits':'Archive entries/state replay and equality checks only; not full operation audit, independent IDP evaluation, recovery or proof of fairness under time cuts.'}
def main():
    manifest=json.loads((HERE/'manifest.json').read_text());assert manifest['completed'] and len(manifest['runs'])==32
    rows=[json.loads(line) for line in (HERE/'search_outputs.jsonl').read_text().splitlines()]
    result=verify(rows,manifest)
    result['log_sha256']=hashlib.sha256((HERE/'search_outputs.jsonl').read_bytes()).hexdigest()
    output=HERE/'no_truth_verification.json'
    if output.exists():raise SystemExit('Refusing to overwrite comparison checks')
    output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()

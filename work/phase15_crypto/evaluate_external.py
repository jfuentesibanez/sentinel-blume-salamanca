"""Compare target keys AFTER static records have passed a separate truth-free audit.

Reads saved scores only: no new IDP, no search, no reference scorer execution.
"""
from pathlib import Path
from collections import Counter
from fractions import Fraction
import csv,hashlib,json,math
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent.parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def inverse(key):
    result=[0]*len(key)
    for i,v in enumerate(key):result[v]=i
    return result
def enc(text,key):return ''.join(text[c::len(key)] for c in key)
def main():
    if (HERE/'evaluation.json').exists():raise SystemExit('Refusing to overwrite evaluation')
    manifest=json.loads((HERE/'manifest.json').read_text())
    assert manifest['completed'] and manifest['protected_unchanged'] and len(manifest['runs'])==12
    audit=json.loads((HERE/'no_truth_verification.json').read_text());assert audit['status']=='passed'
    assert audit['manifest_sha256']==sha(HERE/'manifest.json')
    assert sha(HERE/'truth.jsonl')==manifest['truth_sha256']
    moves=json.loads((HERE/'moves.json').read_text())['moves'];assert len(moves)==16649
    pmap={0:list(range(25)),**{m['index']:m['p'] for m in moves}}
    truths={t['case_id']:t for t in map(json.loads,(HERE/'truth.jsonl').read_text().splitlines())}
    cases={c['case_id']:c for c in manifest['cases']}
    true_numeric={};case_rows={};all_profiles=[];profiles_by_case={};all_keys=set();unique_case_keys={}
    for identifier,t in truths.items():
        assert sorted(t['true_k1'])==list(range(20)) and sorted(t['true_k2'])==list(range(25))
        true_numeric[identifier]=tuple(inverse(t['true_k2']))
        body=''.join(c.lower() for c in (ROOT/'work/phase5_language'/t['language_model']/'holdout.txt').read_text() if c.isascii() and c.isalpha());pos=t['sample_position']
        plains=[body[pos:pos+615],body[pos+615:pos+775]];assert list(map(len,plains))==[615,160]
        generated=[enc(enc(p,t['true_k1']),t['true_k2']) for p in plains]
        for item,cipher in zip(cases[identifier]['ciphertext_files'],generated):assert sha(ROOT/item['path'])==item['sha256'] and (ROOT/item['path']).read_text().strip().lower()==cipher
        case_rows[identifier]={'language_model':t['language_model'],'plant_seed':t['plant_seed'],'sample_position':pos,'true_k1':t['true_k1'],'true_k2':t['true_k2'],'plaintext_sha256':[hashlib.sha256(p.encode()).hexdigest() for p in plains]}
    runs={(r['case_id'],r['anchor_label']):r for r in manifest['runs']}
    for profile in manifest['profiles']:
        run=runs[profile['case_id'],profile['anchor_label']];summary=run['summary'];assert sha(ROOT/profile['csv_path'])==run['csv_sha256'] and sha(ROOT/profile['summary_path'])==run['summary_sha256']
        identifier=profile['case_id'];target=true_numeric[identifier]
        assert sha(ROOT/profile['anchor_path'])==profile['anchor_sha256']
        anchor=tuple(map(int,(ROOT/profile['anchor_path']).read_text().split()))
        expected=list(target)
        if profile['swap']:
            a,b=profile['swap'];expected[a],expected[b]=expected[b],expected[a]
        assert anchor==tuple(expected) and tuple(summary['anchor_numeric'])==anchor
        rows=[];den=summary['idp_denominator'];keys=set()
        with (ROOT/profile['csv_path']).open() as f:
            for index,row in enumerate(csv.DictReader(f)):
                assert int(row['index'])==index
                numeric=tuple(anchor[i] for i in pmap[index]);assert numeric not in keys;keys.add(numeric);all_keys.add(numeric)
                num=int(row['exact_numerator']);legacy=float(row['legacy']);assert math.isfinite(legacy)
                rows.append({'index':index,'numeric':numeric,'exact_numerator':num,'legacy':legacy,
                    'hamming':sum(x!=y for x,y in zip(numeric,target)),
                    'edge_discrepancy':row['legacy_edges']!=row['exact_edges'],
                    'matrix_max_abs_diff':float(row['matrix_max_abs_diff']),
                    'legacy_improves':bool(int(row['legacy_improves_anchor'])),'exact_improves':bool(int(row['exact_improves_anchor']))})
        assert len(rows)==summary['states_completed']
        unique_case_keys.setdefault(identifier,set()).update(keys)
        if rows:
            base=rows[0]
            for row in rows:
                assert row['legacy_improves']==(row['legacy']>base['legacy']+1e-12)
                assert row['exact_improves']==((row['exact_numerator']-base['exact_numerator'])*10**12>den)
        complete=len(rows)==16650 and summary['stop_reason']=='complete'
        item={'case_id':identifier,'anchor_label':profile['anchor_label'],'privileged':True,'complete':complete,
            'rows_scored':len(rows),'unique_keys_inside_profile':len(keys),'anchor_hamming':sum(x!=y for x,y in zip(anchor,target)),
            'legacy_calls':summary['legacy_calls'],'exact_calls':summary['exact_calls'],'stop_reason':summary['stop_reason'],
            'legacy_seconds':summary['legacy_seconds'],'exact_seconds':summary['exact_seconds'],'setup_seconds':summary['setup_seconds'],'seconds':summary['seconds'],'process_seconds':run['process_seconds'],
            'denominator':den,'max_score_absolute_difference':summary['max_score_absolute_difference'],'max_matrix_absolute_difference':summary['max_matrix_absolute_difference'],
            'decision_discrepancies':sum(r['legacy_improves']!=r['exact_improves'] for r in rows),'greedy_edge_discrepancies':sum(r['edge_discrepancy'] for r in rows),
            'target_evaluated_in_observed_profile':target in keys,'target_is_anchor':anchor==target,
            'unknown_key_recovery_test':False,'selection_rule':'IDP descending; numeric lexicographic tie; exact rank uses integer numerator'}
        for backend,score in [('legacy','legacy'),('exact','exact_numerator')]:
            ranked=sorted(rows,key=lambda r:(-r[score],r['numeric']))
            rank=next((i+1 for i,r in enumerate(ranked) if r['numeric']==target),None)
            top5=[{k:r[k] for k in ('index','numeric','hamming','legacy','exact_numerator')} for r in ranked[:5]]
            item[backend]={'target_rank_in_observed':rank,'target_local_rank':rank if complete else None,'target_top5_in_observed':rank is not None and rank<=5,
                'target_selected_in_observed':rank==1,'top5':top5,'strict_improvements_over_anchor':sum(r[backend+'_improves'] for r in rows)}
        if rows:
            item['exact_improvement_hamming']={label:sum(r['exact_improves'] and pred(r['hamming']) for r in rows) for label,pred in
                [('closer',lambda h:h<item['anchor_hamming']),('same',lambda h:h==item['anchor_hamming']),('farther',lambda h:h>item['anchor_hamming'])]}
        all_profiles.append(item);profiles_by_case.setdefault(identifier,[]).append((item,rows))
    for identifier,entries in profiles_by_case.items():
        truth_rows=next(rows for item,rows in entries if item['anchor_label']=='true')
        if not truth_rows:
            case_rows[identifier]['truth_score_missing_after_time_cut']=True;continue
        tn=truth_rows[0]['exact_numerator'];tl=truth_rows[0]['legacy']
        for item,rows in entries:
            den=item['denominator']
            item['true_exact_numerator']=tn;item['true_legacy']=tl
            item['exact_neighbors_vs_truth']={'superior':sum(r['exact_numerator']>tn for r in rows),'equal':sum(r['exact_numerator']==tn for r in rows),'inferior':sum(r['exact_numerator']<tn for r in rows)}
            item['legacy_neighbors_vs_truth']={'superior':sum(r['legacy']>tl+1e-12 for r in rows),'equal_within_epsilon':sum(abs(r['legacy']-tl)<=1e-12 for r in rows),'inferior':sum(r['legacy']<tl-1e-12 for r in rows)}
            if rows:
                best=max(r['exact_numerator'] for r in rows)
                item['true_minus_best_exact']=float(Fraction(tn-best,den))
    totals={'idp_equivalent_calls':sum(p['legacy_calls']+p['exact_calls'] for p in all_profiles),
        'legacy_calls':manifest['legacy_calls'],'exact_calls':manifest['exact_calls'],
        'legacy_seconds':sum(p['legacy_seconds'] for p in all_profiles),'exact_seconds':sum(p['exact_seconds'] for p in all_profiles),
        'process_seconds':sum(p['process_seconds'] for p in all_profiles),'all_profiles_complete':manifest['all_profiles_complete'],
        'distinct_numeric_keys_across_cases':len(all_keys),'distinct_numeric_keys_per_case':{k:len(v) for k,v in unique_case_keys.items()},
        'distinct_case_key_combinations':sum(len(v) for v in unique_case_keys.values()),
        'distinct_planted_keypairs':len({(tuple(t['true_k1']),tuple(t['true_k2'])) for t in truths.values()}),
        'distinct_plaintext_offsets':len({t['sample_position'] for t in truths.values()}),
        'improvement_decision_discrepancies':sum(p['decision_discrepancies'] for p in all_profiles),
        'greedy_edge_discrepancies':sum(p['greedy_edge_discrepancies'] for p in all_profiles)}
    result={'status':'evaluated','scope':'Privileged static landscape, no search and no unknown-key recovery rate','cases':case_rows,'profiles':all_profiles,'totals':totals,
        'new_legacy_calls':0,'new_exact_calls':0,'truth_sha256':manifest['truth_sha256'],'manifest_sha256':sha(HERE/'manifest.json'),
        'limits':'4 cases with2 seeds and unchanged proxy corpora; no evidence of attraction from random starts, cause of phase14failure, global optimality, plaintext/K1 or BLUME solution.'}
    (HERE/'evaluation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');print(json.dumps(totals,indent=2))
if __name__=='__main__':main()

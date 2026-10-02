"""External evaluation only AFTER all32 searches; truth never enters the solver."""
from pathlib import Path
from collections import Counter,defaultdict
import ast,hashlib,json
import numpy as np
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent.parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    output=HERE/'evaluation.json'
    if output.exists():raise SystemExit('Refusing to overwrite external evaluation')
    manifest=json.loads((HERE/'manifest.json').read_text())
    assert manifest['completed'] and len(manifest['runs'])==32 and manifest['protected_unchanged']
    assert sha(HERE/'truth.jsonl')==manifest['truth_sha256'] and sha(HERE/'search_outputs.jsonl')==manifest['log_sha256']
    assert json.loads((HERE/'no_truth_verification.json').read_text())['status']=='passed'
    # Mathematical definitions only. No legacy top-level verifier code executes.
    source=ROOT/'work/phase11_crypto/evaluate_external.py';tree=ast.parse(source.read_text())
    functions=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in {'enc','dec','independent_idp'}]
    assert {n.name for n in functions}=={'enc','dec','independent_idp'}
    scope={'np':np};exec(compile(ast.Module(body=functions,type_ignores=[]),str(source),'exec'),scope)
    enc=scope['enc'];idp=scope['independent_idp']
    truths={t['case_id']:t for t in map(json.loads,(HERE/'truth.jsonl').read_text().splitlines())}
    cases={c['case_id']:c for c in manifest['cases']};tables={};texts={};true_scores={}
    for identifier,t in truths.items():
        folder=ROOT/'work/phase5_language'/t['language_model'];model=t['language_model']
        if model not in tables:tables[model]=np.frombuffer((folder/'model.bin').read_bytes(),dtype='<f4',count=676).astype(np.float64)
        body=''.join(c.lower() for c in (folder/'holdout.txt').read_text() if c.isascii() and c.isalpha());pos=t['sample_position']
        for field,width in (('true_k1',20),('true_k2',25)):assert sorted(t[field])==list(range(width))
        generated=[enc(enc(p,t['true_k1']),t['true_k2']) for p in (body[pos:pos+615],body[pos+615:pos+775])]
        assert list(map(len,generated))==[615,160]
        for item,text in zip(cases[identifier]['ciphertext_files'],generated):assert sha(ROOT/item['path'])==item['sha256'] and (ROOT/item['path']).read_text().strip().lower()==text
        texts[identifier]=generated;true_scores[identifier]=idp(generated,t['true_k2'],20,tables[model])
    recorded=[json.loads(line) for line in (HERE/'search_outputs.jsonl').read_text().splitlines()];evaluations=[];summary=Counter();scores=0;max_error=0.0;paired=defaultdict(dict)
    for row in recorded:
        identifier=row['case_id'];truth=truths[identifier];table=tables[truth['language_model']];recomputed=[]
        for candidate in row['archive']:
            value=idp(texts[identifier],candidate['k2'],20,table);error=abs(value-candidate['idp']);assert error<1e-8
            scores+=1;max_error=max(max_error,error);recomputed.append(value)
        rank=next((a['rank'] for a in row['archive'] if a['k2']==truth['true_k2']),None)
        entries=[e for e in row['archive_events'] if e['k2']==truth['true_k2']]
        first=min(entries,key=lambda e:e['objective_calls']) if entries else None
        result={'case_id':identifier,'arm':row['arm'],'round':row['round'],'local_cap':row['local_proposal_cap'],'checkpoint_merge':row['checkpoint_merge'],
            'top5_recovery':rank is not None,'rank1_recovery':rank==1,'true_k2_rank':rank,'true_idp':true_scores[identifier],
            'best_archive_idp':max(recomputed) if recomputed else None,'true_minus_best_idp':true_scores[identifier]-max(recomputed) if recomputed else None,
            'first_top5_entry':first,'first_entry_from_pool':first is not None and first['stage'] in ('initial_pool','checkpoint_pool'),
            'first_entry_direct_checkpoint_pool':first is not None and first['stage']=='checkpoint_pool',
            'first_entry_after_checkpoint_from_checkpoint_parent':first is not None and first['objective_calls']>57000 and first['checkpoint_ancestry'] and first['stage']!='checkpoint_pool',
            'objective_calls':row['objective_calls'],'seconds':row['seconds'],'cut_cause':row['cut_cause'],'checkpoint_completed':row['checkpoint_completed'],
            'post_checkpoint_parent_choices':sum(p['objective_calls']>=57000 for p in row['parent_choices']),
            'limits':'First top5 entry, not first evaluation; recorded ancestry is not a causal effect.'}
        evaluations.append(result);summary[row['arm']+'_top5']+=int(rank is not None);summary[row['arm']+'_rank1']+=int(rank==1);paired[(identifier,row['round'])][row['arm']]=result
    contrasts=[]
    for (identifier,round_index),arms in paired.items():
        for treatment,control,label in (('B','A','fusion_cap5000'),('D','C','fusion_cap33298'),('C','A','cap_without_fusion'),('D','B','cap_with_fusion')):
            a=arms[treatment];b=arms[control];contrasts.append({'case_id':identifier,'round':round_index,'contrast':label,'treatment':treatment,'control':control,
                'top5_difference':int(a['top5_recovery'])-int(b['top5_recovery']),
                'time_cut_in_pair':any('wall_time' in x['cut_cause'] for x in (a,b)),
                'both_checkpoints_complete':a['checkpoint_completed'] and b['checkpoint_completed']})
    assert len(evaluations)==32
    result={'status':'evaluated','rows':evaluations,'paired_contrasts':contrasts,'summary':dict(summary),'archive_scores_recomputed':scores,
        'max_score_error':max_error,'truth_sha256':manifest['truth_sha256'],'log_sha256':manifest['log_sha256'],
        'formula_source_sha256':sha(source),'limits':'4fresh paired cases,2rounds; K2 only, known widths, literary proxy models; no statistical winner, cipher/language exclusion, K1 or historical attack.'}
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k not in ('rows','paired_contrasts')},indent=2))
if __name__=='__main__':main()

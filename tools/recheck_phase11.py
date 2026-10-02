"""Numerical recheck of archived phase11 scores, with no search or legacy side effects."""
from pathlib import Path
from collections import Counter
import ast
import json
import numpy as np

ROOT=Path(__file__).resolve().parents[1]
PHASE=ROOT/'work/phase11_crypto'

def main():
    # Load only the three pure mathematical functions; do not execute the legacy
    # verifier's top-level file checks, subprocess calls or output writes.
    source=PHASE/'evaluate_external.py'
    tree=ast.parse(source.read_text())
    functions=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in {'enc','dec','independent_idp'}]
    assert {n.name for n in functions}=={'enc','dec','independent_idp'}
    scope={'np':np};exec(compile(ast.Module(body=functions,type_ignores=[]),str(source),'exec'),scope)
    enc=scope['enc'];idp=scope['independent_idp']
    truths={t['case_id']:t for t in map(json.loads,(PHASE/'truth.jsonl').read_text().splitlines())}
    manifest=json.loads((PHASE/'manifest.json').read_text());cases={c['case_id']:c for c in manifest['cases']}
    models={};ciphertexts={}
    for name,t in truths.items():
        folder=ROOT/'work/phase5_language'/t['language_model']
        if t['language_model'] not in models:
            models[t['language_model']]=np.frombuffer((folder/'model.bin').read_bytes(),dtype='<f4',count=676).astype(np.float64)
        text=''.join(c.lower() for c in (folder/'holdout.txt').read_text() if c.isascii() and c.isalpha())
        for key in ['true_k1','true_k2']: assert sorted(t[key])==list(range(len(t[key])))
        start=t['sample_position'];plain=[text[start:start+615],text[start+615:start+775]]
        generated=[enc(enc(p,t['true_k1']),t['true_k2']) for p in plain]
        for f,cipher in zip(cases[name]['ciphertext_files'],generated):
            assert (ROOT/f['path']).read_text().strip().lower()==cipher
        ciphertexts[name]=generated
    count=0;max_error=0.0;hits=Counter();failed_true_above=0
    runs=list(map(json.loads,(PHASE/'search_outputs.jsonl').read_text().splitlines()))
    for r in runs:
        t=truths[r['case_id']];table=models[t['language_model']];texts=ciphertexts[r['case_id']]
        values=[]
        for a in r['archive']:
            value=idp(texts,a['k2'],t['w1'],table);error=abs(value-a['idp'])
            assert error<1e-8,(r['case_id'],r['method'],r['round'],a['rank'],error)
            count+=1;max_error=max(max_error,error);values.append(value)
        found=any(a['k2']==t['true_k2'] for a in r['archive'])
        hits[r['method']]+=int(found)
        true_score=idp(texts,t['true_k2'],t['w1'],table)
        failed_true_above+=int(not found and true_score>max(values)+1e-8)
    assert count==160 and len(runs)==32 and len(truths)==8
    assert dict(hits)=={'population':2,'cap5000':3} and failed_true_above==27
    print(json.dumps({'status':'passed','synthetic_ciphertexts_regenerated':16,
        'archive_idp_scores_recomputed':count,'maximum_absolute_error':max_error,
        'failed_rounds_true_k2_above_archive':failed_true_above,'recoveries':dict(hits),
        'new_searches':0,'limits':'Recorded sealed keys used; no RNG regeneration, full operation audit or historical attack.'},indent=2))

if __name__=='__main__': main()

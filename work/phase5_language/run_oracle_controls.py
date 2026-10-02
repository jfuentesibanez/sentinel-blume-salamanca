from pathlib import Path
import hashlib,json,math,struct,subprocess,time

HERE=Path(__file__).resolve().parent;ROOT=HERE.parent.parent
PYTHONSOURCE=HERE/'prepare_languages.py'
models=['de_fold','de_digraph','fr_fold']
files=['work/phase3_crypto/phase3.cpp','work/phase3_crypto/ict_search.h','work/crypto/double_search.cpp','work/phase3_crypto/phase3','work/phase5_language/prepare_languages.py','work/phase5_language/run_oracle_controls.py']
for name in models:
    files+=['work/phase5_language/'+name+'/'+x for x in ('model.bin','holdout.txt','provenance.json')]
manifest={'date':'2026-10-01','mode':'K1 oracle only; true K2 explicitly disclosed','seeds':[20261401,20261402],'bands':[[12,15],[20,25]],'models':models,'messages_scored':[1,2],'same_seed_note':'Each seed shares keys across models/bands of same widths; comparisons are paired, not independent. Orthography models derive from the same German work.','restarts':8,'k1_seconds':3,'fresh_full_attack':False,'negative_controls':'No negatives in this small model smoke; earlier phase3 K1 negative controls are separate.','files':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in files],'runs':[],'model_array_checks':{}}
for name in models:
    data=(HERE/name/'model.bin').read_bytes();offset=0;checks=[]
    for n in (2,3,4):
        count=26**n;values=struct.unpack_from('<%df'%count,data,offset);offset+=count*4
        total=sum(10**v for v in values)
        assert all(math.isfinite(v) and v<=0 for v in values)
        assert abs(total-1)<1e-5
        checks.append({'n':n,'count':count,'probability_sum':total})
    assert offset==len(data)
    manifest['model_array_checks'][name]=checks
mf=HERE/'oracle_controls_manifest.json';out=HERE/'oracle_controls.jsonl'
mf.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
with out.open('w') as f:
    for name in models:
        for w1,w2 in manifest['bands']:
            for seed in manifest['seeds']:
                cmd=[str(ROOT/'work/phase3_crypto/phase3'),'oracle',str(HERE/name/'model.bin'),str(HERE/name/'holdout.txt'),str(w1),str(w2),str(seed),'8','3','3']
                begin=time.monotonic();p=subprocess.run(cmd,check=True,capture_output=True,text=True,timeout=26)
                rows=[json.loads(x) for x in p.stdout.splitlines()];assert len(rows)==2
                for x in rows:
                    x['language_model']=name
                    assert x['mode']=='oracle' and x['oracle_k2_disclosed']
                    assert x['reencryption_consistency']
                    f.write(json.dumps(x,separators=(',',':'))+'\n')
                f.flush();manifest['runs'].append({'model':name,'w1':w1,'w2':w2,'seed':seed,'status':'completed','rows':2,'wall_seconds':time.monotonic()-begin,'command':cmd});mf.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
manifest['log_sha256']=hashlib.sha256(out.read_bytes()).hexdigest();manifest['completed']=True
mf.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
rows=[json.loads(x) for x in out.read_text().splitlines()]
result={'rows':len(rows),'oracle_k2_disclosed':True,'historical_attack':False,'summary':[{'model':name,'exact_775_letters':sum(x['exact_both_plaintexts'] for x in rows if x['language_model']==name),'denominator':sum(x['language_model']==name for x in rows),'budget_expired':sum(x['budget_expired'] for x in rows if x['language_model']==name)} for name in models]}
(HERE/'oracle_summary.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))

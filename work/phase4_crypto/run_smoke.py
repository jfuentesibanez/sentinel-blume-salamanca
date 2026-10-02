import argparse,hashlib,json,pathlib,subprocess,time
HERE=pathlib.Path(__file__).resolve().parent;ROOT=HERE.parent.parent
parser=argparse.ArgumentParser();parser.add_argument('--negative',action='store_true');parser.add_argument('--seed',type=int,default=20261201);parser.add_argument('--count',type=int,default=2);args=parser.parse_args()
tag='negative' if args.negative else 'positive'; outfile=HERE/f'smoke_{tag}.jsonl'; manifestfile=HERE/f'smoke_{tag}_manifest.json'
paths=['work/phase4_crypto/phase4.cpp','work/phase4_crypto/source_moves.h','work/phase4_crypto/phase4','work/phase3_crypto/phase3.cpp','work/phase3_crypto/ict_search.h','work/crypto/double_search.cpp','work/crypto/model_es.bin','work/crypto/holdout_es.txt','work/crypto/holdout_proxy.txt']
manifest={'data_mode':'synthetic; never BLUME','hypothesis':'irregular columnar double transposition, conv0, shared keys','variants':['old','source'],'seeds':list(range(args.seed,args.seed+args.count)),'corpora':['prose','proxy'] if not args.negative else ['proxy'],'bands':[[12,15],[20,25]],'lengths':[615,160],'restarts':8,'outer_rounds':3,'k1_seconds_per_round':3,'k2_seconds_per_round':5,'max_idp_evals_per_round':300000,'max_k1_evals_per_round':2000000,'max_final_k2_evals_per_round':2000000,'negative':args.negative,'selection':'q3 only; no planted truth used by either solver','note':'Matched time budgets, not guaranteed matched evaluation counts. Same seed across corpora shares keys. Shuffle is std::shuffle, not original CrypTool successive random swaps. Full old imports frozen phase3 implementation.'}
manifest['files']=[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in paths]
manifest['started_at_unix']=time.time();manifest['runs']=[];manifestfile.write_text(json.dumps(manifest,indent=2)+'\n')
with outfile.open('w') as out:
 for corpus in (['proxy'] if args.negative else ['prose','proxy']):
  holdout=ROOT/'work/crypto'/('holdout_proxy.txt' if corpus=='proxy' else 'holdout_es.txt')
  for w1,w2 in [[12,15],[20,25]]:
   for seed in range(args.seed,args.seed+args.count):
    for variant in ['old','source']:
     cmd=[str(HERE/'phase4'),variant,str(ROOT/'work/crypto/model_es.bin'),str(holdout),str(w1),str(w2),str(seed),'8','3','5']+(['negative'] if args.negative else [])
     start=time.time();run={'corpus':corpus,'w1':w1,'w2':w2,'seed':seed,'variant':variant,'command':cmd}
     try:
      proc=subprocess.run(cmd,check=True,text=True,capture_output=True,timeout=90)
      rows=[json.loads(x) for x in proc.stdout.splitlines()];assert len(rows)==2
      for row in rows: row['corpus']=corpus;out.write(json.dumps(row,separators=(',',':'))+'\n')
      out.flush();run.update(status='completed',rows=len(rows),wall_seconds=time.time()-start)
     except subprocess.TimeoutExpired as err:
      run.update(status='timeout',wall_seconds=time.time()-start,stdout=(err.stdout or b'').decode() if isinstance(err.stdout,bytes) else err.stdout)
     except Exception as err: run.update(status='error',wall_seconds=time.time()-start,error=str(err))
     manifest['runs'].append(run);manifestfile.write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(run),flush=True)
manifest['ended_at_unix']=time.time();manifestfile.write_text(json.dumps(manifest,indent=2)+'\n')

#!/usr/bin/env python3
"""Bounded pilot, exact 615+160, shared keys, independent RNG streams."""
import argparse, json, pathlib, subprocess, time
ROOT=pathlib.Path(__file__).resolve().parent
ap=argparse.ArgumentParser();ap.add_argument('--budget',type=float,default=390);ap.add_argument('--steps',type=int,default=10000);ap.add_argument('--restarts',type=int,default=4);args=ap.parse_args()
started=time.monotonic();out=ROOT/'controls.jsonl';status=[]
with out.open('w') as f:
 for width in ((8,10),(10,12),(12,15),(15,20),(20,25)):
  for corpus in ('holdout_es.txt','holdout_proxy.txt'):
   for seed in (20261001,20261002,20261003):
    left=args.budget-(time.monotonic()-started)
    if left<=0:
     status.append({'width':width,'corpus':corpus,'seed':seed,'status':'not_run_budget'});continue
    cmd=[str(ROOT/'double_search'),'control',str(ROOT/'model_es.bin'),str(ROOT/corpus),*map(str,width),str(seed),str(args.restarts),str(args.steps),'0','-1','1']
    try:
     p=subprocess.run(cmd,text=True,capture_output=True,timeout=left)
     for line in p.stdout.splitlines():
      d=json.loads(line);d['control_corpus']=corpus;f.write(json.dumps(d)+'\n');f.flush()
      print(json.dumps({k:d[k] for k in ('control_corpus','w1','w2','seed','messages_scored','seconds','correct_letters','exact_k1','exact_k2')}),flush=True)
     status.append({'width':width,'corpus':corpus,'seed':seed,'status':'completed' if p.returncode==0 else 'failed','stderr':p.stderr,'command':cmd})
    except subprocess.TimeoutExpired as e:
     if e.stdout:
      for line in e.stdout.decode().splitlines():
       d=json.loads(line);d['control_corpus']=corpus;f.write(json.dumps(d)+'\n');f.flush()
     status.append({'width':width,'corpus':corpus,'seed':seed,'status':'timeout_budget','command':cmd})
(ROOT/'control_manifest.json').write_text(json.dumps({'budget_seconds':args.budget,'elapsed_seconds':time.monotonic()-started,'commands':status},indent=2)+'\n')

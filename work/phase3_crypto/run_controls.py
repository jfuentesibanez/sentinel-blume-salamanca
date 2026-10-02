#!/usr/bin/env python3
"""Bounded synthetic controls. No historical ciphertext input or truth injection.

Arguments: MODE START COUNT [SECONDS] [CORPUS] [NEGATIVE]
Each planted pair is evaluated using message1 alone and both messages jointly.
"""
import hashlib, json, pathlib, subprocess, sys, time

ROOT=pathlib.Path(__file__).resolve().parents[2]
HERE=pathlib.Path(__file__).resolve().parent
mode=sys.argv[1]
start,count=map(int,sys.argv[2:4])
sec=float(sys.argv[4]) if len(sys.argv)>4 else 3
corpus=sys.argv[5] if len(sys.argv)>5 else 'prose'
negative=len(sys.argv)>6 and sys.argv[6]=='negative'
if mode not in ('oracle','full') or corpus not in ('prose','proxy'):
    raise SystemExit('MODE oracle/full; CORPUS prose/proxy')
holdout=ROOT/'work/crypto'/('holdout_es.txt' if corpus=='prose' else 'holdout_proxy.txt')
label=f'{mode}_{corpus}_{start}_{count}'+('_negative' if negative else '')
out=HERE/(label+'.jsonl')
if out.exists():
    raise SystemExit(f'refusing to overwrite {out}')
commands=[]
began=time.monotonic()
with out.open('x') as f:
    for w1,w2 in ((12,15),(20,25)):
        for seed in range(start,start+count):
            args=[str(HERE/'phase3'),mode,str(ROOT/'work/crypto/model_es.bin'),str(holdout),str(w1),str(w2),str(seed),'8',str(sec),'5']
            if negative: args+=['negative']
            commands.append(args)
            # One CLI invocation scores both single and joint. Full mode has
            # three outer rounds, each with K2, K1 and final-K2 budgets.
            timeout=2*(3*(5+2*sec) if mode=='full' else sec)+20
            raw=subprocess.check_output(args,text=True,timeout=timeout)
            for line in raw.splitlines():
                row=json.loads(line)
                row['corpus']=corpus
                f.write(json.dumps(row,ensure_ascii=False)+'\n')
            f.flush()
            print(json.dumps({'band':[w1,w2],'seed':seed,'mode':mode,'corpus':corpus,'negative':negative,'elapsed':round(time.monotonic()-began,2)}),flush=True)
manifest={'scope':'synthetic only; exact 615+160; widths given; convention0','mode':mode,'corpus':corpus,'negative':negative,'commands':commands,'process_timeout_seconds':timeout,'wall_seconds':time.monotonic()-began,'sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (HERE/'ict_search.h',HERE/'phase3.cpp',HERE/'phase3',ROOT/'work/crypto/double_search.cpp',holdout,ROOT/'work/crypto/model_es.bin',out)}}
(HERE/(label+'_manifest.json')).write_text(json.dumps(manifest,indent=2)+'\n')

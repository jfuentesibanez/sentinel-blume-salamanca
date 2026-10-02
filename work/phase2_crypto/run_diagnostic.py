import hashlib,json,pathlib,subprocess,time
ROOT=pathlib.Path(__file__).resolve().parent;BASE=ROOT.parent/'crypto'
allrows=[json.loads(s) for s in (BASE/'controls.jsonl').read_text().splitlines()]
selected=[d for d in allrows if d['messages_scored']==2 and (d['w1'],d['w2']) in ((12,15),(20,25))]
commands=[];start=time.monotonic()
with (ROOT/'oracle_diagnostics.jsonl').open('w') as f:
 for d in selected:
  cmd=[str(ROOT/'oracle_diagnostic'),str(BASE/'model_es.bin'),str(BASE/d['control_corpus']),str(d['w1']),str(d['w2']),str(d['seed']),'4','10000','1000',','.join(map(str,d['k2']))]
  p=subprocess.run(cmd,capture_output=True,text=True,timeout=110,check=True)
  for s in p.stdout.splitlines():
   row=json.loads(s);row['corpus']=d['control_corpus'];f.write(json.dumps(row)+'\n');f.flush();print(json.dumps(row),flush=True)
  commands.append({'command':cmd,'source_control_seed':d['seed'],'corpus':d['control_corpus']})
(ROOT/'diagnostic_manifest.json').write_text(json.dumps({'kind':'oracle stage diagnostic on synthetic controls only','elapsed_seconds':time.monotonic()-start,'true_keys_access':'Conditional oracle objectives explicitly disclose one planted key; original solve is never invoked with truth. No BLUME runs.','commands':commands,'base_source_sha256':hashlib.sha256((BASE/'double_search.cpp').read_bytes()).hexdigest()},indent=2)+'\n')

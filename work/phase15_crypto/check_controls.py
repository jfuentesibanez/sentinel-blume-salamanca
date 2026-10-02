"""Artificial fixtures only; preserve attempts and charge every backend call."""
from pathlib import Path
import csv,hashlib,json,struct,subprocess,time
HERE=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    if (HERE/'sealed_design.json').exists():raise SystemExit('Sealed design: no controls')
    attempts=HERE/'control_attempts';attempts.mkdir(exist_ok=True)
    number=len(list(attempts.glob('attempt*.json')))+1
    model=HERE/'uniform_fixture.bin'
    if not model.exists():model.write_bytes(struct.pack('<676f',*([-2.0]*676))+bytes((17576+456976)*4))
    started=time.monotonic();timed_out=False
    try:proc=subprocess.run([str(HERE/'static_landscape'),'selftest',str(model)],capture_output=True,text=True,timeout=30)
    except subprocess.TimeoutExpired as e:
        timed_out=True
        proc=subprocess.CompletedProcess([],124,(e.stdout or b'').decode() if isinstance(e.stdout,bytes) else (e.stdout or ''),(e.stderr or b'').decode() if isinstance(e.stderr,bytes) else (e.stderr or ''))
    (attempts/f'output{number}.jsonl').write_text(proc.stdout);(attempts/f'calls{number}.log').write_text(proc.stderr)
    rows=[]
    for line in proc.stdout.splitlines():
        try:rows.append(json.loads(line))
        except json.JSONDecodeError:pass
    final=rows[-1] if rows else {}
    marks=[list(map(int,line.split()[1:])) for line in proc.stderr.splitlines() if line.startswith('@calls ')]
    charged=marks[-1] if marks else [0,0]
    if 'legacy_calls' in final:assert charged==[final['legacy_calls'],final['exact_calls']]
    value={'attempt':number,'returncode':proc.returncode,'stderr_path':str((attempts/f'calls{number}.log').relative_to(HERE)),'seconds':time.monotonic()-started,'timed_out':timed_out,
        'source_sha256':sha(HERE/'static_landscape.cpp'),'binary_sha256':sha(HERE/'static_landscape'),
        'idp_equivalent_calls':sum(charged),'legacy_calls':charged[0],
        'exact_calls':charged[1],'status':final.get('status','failed'),'output_sha256':sha(attempts/f'output{number}.jsonl'),'calls_sha256':sha(attempts/f'calls{number}.log')}
    (attempts/f'attempt{number}.json').write_text(json.dumps(value,indent=2)+'\n')
    if proc.returncode or final.get('status')!='passed':raise SystemExit(json.dumps(value))
    # Geometry is independent of truth, with no objective evaluations.
    geometry=subprocess.check_output([str(HERE/'static_landscape'),'geometry'],text=True)
    (HERE/'moves.json').write_text(geometry);moves=json.loads(geometry)['moves'];identity=list(range(25))
    keys=[identity]+[x['p'] for x in moves]
    assert len(keys)==16650 and len({tuple(x) for x in keys})==16650
    digest=hashlib.sha256(json.dumps(sorted(keys),separators=(',',':')).encode()).hexdigest()
    assert digest=='11fade65c2c64b718fd4cf91b61a6df6b7ab6182b1183ca857fc2fc643f5c9ff'
    results={'status':'passed','idp_equivalent_calls_all_attempts':sum(json.loads(p.read_text())['idp_equivalent_calls'] for p in attempts.glob('attempt*.json')),
        'latest_attempt':value,'frozen_geometry_hash':digest,'geometry_idp_calls':0,'moves_sha256':sha(HERE/'moves.json'),
        'source_sha256':sha(HERE/'static_landscape.cpp'),'binary_sha256':sha(HERE/'static_landscape'),
        'truth_read':False,'truth_generated':False,'main_runs':0}
    (HERE/'control_results.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results,indent=2))
if __name__=='__main__':main()

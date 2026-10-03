"""Run mock-callback policy controls only; preserve every attempt, no IDP/truth."""
from pathlib import Path
import hashlib,json,subprocess,time
HERE=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    if (HERE/'sealed_design.json').exists():raise SystemExit('No controls after seal')
    directory=HERE/'control_attempts';directory.mkdir(exist_ok=True)
    number=len(list(directory.glob('attempt*.json')))+1;started=time.monotonic();timed_out=False
    try:p=subprocess.run([str(HERE/'trajectory'),'policy-controls'],capture_output=True,text=True,timeout=30)
    except subprocess.TimeoutExpired as e:
        timed_out=True;p=subprocess.CompletedProcess([],124,(e.stdout or b'').decode() if isinstance(e.stdout,bytes) else(e.stdout or ''),(e.stderr or b'').decode() if isinstance(e.stderr,bytes) else(e.stderr or ''))
    output=directory/f'output{number}.jsonl';trace=directory/f'calls{number}.log';output.write_text(p.stdout);trace.write_text(p.stderr)
    marks=[list(map(int,s.split()[1:])) for s in p.stderr.splitlines() if s.startswith('@calls ')];charged=marks[-1] if marks else[0,0]
    row=json.loads(p.stdout.splitlines()[-1]) if p.stdout.splitlines() else{}
    record={'attempt':number,'returncode':p.returncode,'timed_out':timed_out,'seconds':time.monotonic()-started,
        'source_sha256':sha(HERE/'trajectory.cpp'),'binary_sha256':sha(HERE/'trajectory'),'exact_header_sha256':sha(HERE/'exact_scorer.h'),
        'status':row.get('status','failed'),'actual_legacy_IDP_calls':charged[0],'actual_exact_IDP_calls':charged[1],
        'output_sha256':sha(output),'trace_sha256':sha(trace),'fixture_record':row}
    (directory/f'attempt{number}.json').write_text(json.dumps(record,indent=2)+'\n')
    if p.returncode or record['status']!='passed' or sum(charged):raise SystemExit(json.dumps(record))
    result={'status':'passed','source_sha256':sha(HERE/'trajectory.cpp'),'binary_sha256':sha(HERE/'trajectory'),
        'exact_header_sha256':sha(HERE/'exact_scorer.h'),'policy_fixtures':row['policy_fixtures'],
        'actual_exact_IDP_calls_all_attempts':sum(json.loads(f.read_text())['actual_exact_IDP_calls'] for f in directory.glob('attempt*.json')),
        'actual_legacy_IDP_calls_all_attempts':sum(json.loads(f.read_text())['actual_legacy_IDP_calls'] for f in directory.glob('attempt*.json')),
        'scorer_validation_reused':'Phase15 frozen exact functions and its passed artificial controls; no new scoring',
        'truth_generated':False,'main_runs':0,'latest_attempt':record}
    (HERE/'control_results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()

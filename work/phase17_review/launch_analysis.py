"""Single externally timed launch after bound approvals; no scoring in wrapper."""
from pathlib import Path
import datetime
import hashlib
import json
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
PHASE = ROOT / 'work/phase17_records'

def main():
    approval = json.loads((PHASE / 'audit_approval.json').read_text())
    source = PHASE / 'analyze_saved_paths.py'
    assert hashlib.sha256(source.read_bytes()).hexdigest() == approval['source_sha256']
    assert approval['root_approved'] and approval['independent_approved']
    target = HERE / 'launch_receipt1.json'
    assert not target.exists(), 'External launch receipt exists; no automatic rerun'
    with (HERE / 'launch_started1.json').open('x') as stream:
        json.dump({'at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   'plan_sha256': approval['plan_sha256'], 'source_sha256': approval['source_sha256'],
                   'hard_seconds': 60, 'new_IDP_calls': 0}, stream, indent=2)
    began = time.monotonic()
    command = [sys.executable, str(source), '--root', str(ROOT)]
    timed_out = False
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
        code, out, err = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        code = None
        out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else exc.stdout or ''
        err = exc.stderr.decode() if isinstance(exc.stderr, bytes) else exc.stderr or ''
    seconds = time.monotonic() - began
    (HERE / 'launch_stdout1.txt').write_text(out)
    (HERE / 'launch_stderr1.txt').write_text(err)
    receipt = {'status': 'completed' if code == 0 else 'failed_preserved', 'attempt': 1,
               'command': command, 'returncode': code, 'timed_out': timed_out,
               'hard_seconds': 60, 'seconds': seconds, 'source_sha256': approval['source_sha256'],
               'plan_sha256': approval['plan_sha256'], 'new_IDP_calls': 0,
               'new_solver_trajectories': 0, 'stdout_sha256': hashlib.sha256(out.encode()).hexdigest(),
               'stderr_sha256': hashlib.sha256(err.encode()).hexdigest()}
    target.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))
    if code != 0:
        raise SystemExit(1)

if __name__ == '__main__':
    main()

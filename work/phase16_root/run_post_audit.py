"""One hard-bounded audit attempt, preserving started calls on failure."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def decoded(value):
    return value.decode(errors='replace') if isinstance(value, bytes) else (value or '')


def main():
    attempts = HERE / 'audit_attempts'
    attempts.mkdir(exist_ok=True)
    receipt = attempts / 'attempt1.json'
    with receipt.open('x') as stream:
        json.dump({'status': 'started', 'attempt': 1, 'maximum_attempts': 1,
                   'hard_timeout_seconds': 40,
                   'source_sha256': sha(HERE / 'post_run_audit.py'),
                   'wrapper_sha256': sha(Path(__file__)),
                   'started_at_unix': time.time()}, stream)
    record = json.loads(receipt.read_text())
    started = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run([sys.executable, str(HERE / 'post_run_audit.py')],
                              capture_output=True, text=True, timeout=40)
    except subprocess.TimeoutExpired as error:
        timed_out = True
        proc = subprocess.CompletedProcess([], 124, decoded(error.stdout), decoded(error.stderr))
    (attempts / 'stdout1.txt').write_text(proc.stdout)
    (attempts / 'stderr1.txt').write_text(proc.stderr)
    progress = HERE / 'audit_progress.json'
    charged = json.loads(progress.read_text())['exact_reference_calls_started'] if progress.exists() else 0
    result = HERE / 'post_run_audit.json'
    passed = proc.returncode == 0 and result.exists() and json.loads(result.read_text())['status'] == 'passed'
    record.update(status='passed' if passed else 'failed_no_retry', returncode=proc.returncode,
                  timed_out=timed_out, seconds=time.monotonic() - started,
                  exact_reference_calls_started=charged, legacy_reference_calls_started=0,
                  stdout_sha256=sha(attempts / 'stdout1.txt'), stderr_sha256=sha(attempts / 'stderr1.txt'),
                  new_searches=0)
    if result.exists():
        record['result_sha256'] = sha(result)
    if progress.exists():
        record['progress_sha256'] = sha(progress)
    save(receipt, record)
    print(json.dumps(record))
    if not passed:
        raise SystemExit(proc.returncode or 1)


if __name__ == '__main__':
    main()

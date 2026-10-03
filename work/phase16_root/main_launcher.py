"""Execute the sealed panel once, retaining launcher outputs and call charges."""
from pathlib import Path
import datetime
import hashlib
import json
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
PHASE = ROOT / 'work/phase16_crypto'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    manifest = json.loads((PHASE / 'manifest.json').read_text())
    assert manifest['status'] == 'sealed_not_run' and not manifest['runs']
    assert sha(PHASE / 'plan20.json') == manifest['plan_sha256']
    receipt = HERE / 'main_launch_receipt.json'
    record = {'status': 'started', 'attempt': 1, 'maximum_attempts': 1,
              'plan_sha256': manifest['plan_sha256'],
              'sealed_manifest_sha256': sha(PHASE / 'manifest.json'),
              'launcher_sha256': sha(Path(__file__)),
              'started_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'outer_hard_seconds': 850, 'per_process_hard_seconds': 40}
    with receipt.open('x') as stream:
        json.dump(record, stream, indent=2)
    started = time.monotonic()
    timed_out = False
    with (HERE / 'main_stdout.jsonl').open('x') as output, (HERE / 'main_stderr.txt').open('x') as errors:
        try:
            proc = subprocess.run([sys.executable, str(PHASE / 'run_phase16.py'), 'run'],
                                  stdout=output, stderr=errors, timeout=850)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc = subprocess.CompletedProcess([], 124)
    counts = []
    for path in sorted((PHASE / 'trajectories').glob('*.calls.log')):
        markers = [list(map(int, line.split()[1:])) for line in path.read_text().splitlines()
                   if line.startswith('@calls ')]
        counts.append({'file': str(path.relative_to(ROOT)), 'sha256': sha(path),
                       'legacy_started': markers[-1][0] if markers else 0,
                       'exact_started': markers[-1][1] if markers else 0})
    manifest = json.loads((PHASE / 'manifest.json').read_text())
    record.update(status='completed' if proc.returncode == 0 and manifest.get('completed') else 'failed_no_retry',
                  returncode=proc.returncode, timed_out=timed_out, seconds=time.monotonic() - started,
                  manifest_sha256=sha(PHASE / 'manifest.json'),
                  stdout_sha256=sha(HERE / 'main_stdout.jsonl'), stderr_sha256=sha(HERE / 'main_stderr.txt'),
                  persisted_call_logs=counts,
                  exact_calls_started=sum(item['exact_started'] for item in counts),
                  legacy_calls_started=sum(item['legacy_started'] for item in counts))
    receipt.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({key: value for key, value in record.items() if key != 'persisted_call_logs'}))
    if proc.returncode:
        raise SystemExit(proc.returncode)


if __name__ == '__main__':
    main()

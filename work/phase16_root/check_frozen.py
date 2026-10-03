"""Check every pre-phase16 protected file, without scores or searches."""
from pathlib import Path
import hashlib
import json
import datetime

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def main():
    baseline = json.loads((HERE / 'frozen_before.json').read_text())
    errors = []
    for relative, expected in baseline['hashes'].items():
        path = ROOT / relative
        if not path.is_file():
            errors.append({'path': relative, 'error': 'missing'})
        elif hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            errors.append({'path': relative, 'error': 'changed'})
    result = {
        'checked_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'status': 'passed' if not errors else 'failed',
        'protected_files': len(baseline['hashes']),
        'baseline_sha256': hashlib.sha256((HERE / 'frozen_before.json').read_bytes()).hexdigest(),
        'errors': errors,
        'new_IDP_calls': 0,
        'new_searches': 0,
    }
    (HERE / 'frozen_after.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    if errors:
        raise SystemExit(1)


if __name__ == '__main__':
    main()

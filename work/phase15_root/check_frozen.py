"""Hash earlier research without importing or running any experimental code."""
from pathlib import Path
import argparse
import hashlib
import json
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
REPO = ROOT / 'sentinel-blume-salamanca'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('record', 'verify'))
    args = parser.parse_args()
    baseline = HERE / 'frozen_before.json'
    if args.action == 'record':
        assert not baseline.exists(), 'Refusing to replace an earlier baseline'
        paths = set()
        for name in ('source_inventory.jsonl', 'phase14_source_inventory.jsonl'):
            for line in (REPO / 'provenance' / name).read_text().splitlines():
                entry = json.loads(line)
                path = ROOT / entry['source_path']
                if path.is_file():
                    paths.add(path)
        result = {'recorded_at_utc': datetime.now(timezone.utc).isoformat(),
                  'files': {str(p.relative_to(ROOT)): sha(p) for p in sorted(paths)},
                  'objective_calls': 0}
        baseline.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'status': 'recorded', 'files': len(paths), 'objective_calls': 0}))
        return
    recorded = json.loads(baseline.read_text())
    missing, changed = [], []
    for name, digest in recorded['files'].items():
        path = ROOT / name
        if not path.is_file():
            missing.append(name)
        elif sha(path) != digest:
            changed.append(name)
    result = {'checked_at_utc': datetime.now(timezone.utc).isoformat(),
              'files': len(recorded['files']), 'missing': missing, 'changed': changed,
              'passed': not missing and not changed, 'objective_calls': 0}
    (HERE / 'frozen_after.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    if not result['passed']:
        raise SystemExit(1)

if __name__ == '__main__':
    main()

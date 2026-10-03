"""Copy the closed phase17 selection without altering earlier research.

Own notes/code/results are included. Raw external search responses stay local.
This script does not score, replay trajectories, build solvers or use the network.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / 'sentinel-blume-salamanca'
BASE = '9cb73e9d8775d785903aee29661986ef41cf4bfd'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def new_file(path, data):
    assert not path.exists(), path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main():
    preserved = REPO / 'provenance/phase16_file_hashes.json'
    new_file(preserved, (REPO / 'provenance/file_hashes.json').read_bytes())
    receipt = json.loads((ROOT / 'work/phase17_publication/draft_receipt.json').read_text())
    for name in receipt['draft_paths']:
        current = REPO / name
        draft = ROOT / 'work/phase17_publication/entry_drafts' / name
        assert digest(current) == receipt['original_public_sha256'][name], name
        assert digest(draft) == receipt['draft_sha256'][name], name
        current.write_bytes(draft.read_bytes())
    selected = []
    for folder in ('work/phase17_records', 'work/phase17_review', 'work/phase17_history'):
        selected.extend(p for p in (ROOT / folder).rglob('*') if p.is_file())
    selected.extend(ROOT / name for name in (
        'outputs/Sentinel_BLUME_fase17_2026-10-03.txt',
        'work/phase17_publication/checklist_selection.txt',
        'work/phase17_publication/helper_preparation.txt',
        'work/phase17_publication/helper_preparation_final.json',
        'work/phase17_publication/helper_review_independiente.txt',
        'work/phase17_publication/report_review.txt',
        'work/phase17_publication/recheck_phase17.py',
        'work/phase17_publication/export_phase17.py'))
    entries = []
    for source in sorted(set(selected)):
        assert source.is_file(), source
        relative = source.relative_to(ROOT).as_posix()
        entry = {'source_path': relative, 'sha256': digest(source),
                 'bytes': source.stat().st_size}
        if source.name.startswith('web_') and relative.startswith('work/phase17_history/'):
            entry.update(disposition='referenced_only',
                         reason='External search response body; kept local, not redistributable project prose.')
        else:
            assert source.suffix not in ('.png', '.jpg', '.pdf', '.pyc'), source
            destination = 'tools/recheck_phase17.py' if relative == 'work/phase17_publication/recheck_phase17.py' else relative
            new_file(REPO / destination, source.read_bytes())
            assert digest(REPO / destination) == entry['sha256']
            entry.update(disposition='included', repository_path=destination)
        entries.append(entry)
    new_file(REPO / 'provenance/phase17_source_inventory.jsonl',
             ''.join(json.dumps(e, ensure_ascii=False, separators=(',', ':')) + '\n' for e in entries).encode())
    included = sum(e['disposition'] == 'included' for e in entries)
    update = {'date': '2026-10-03', 'research_through_phase': 17, 'baseline_commit': BASE,
              'new_inventory_entries': len(entries), 'new_included_files': included,
              'new_referenced_files': len(entries) - included,
              'selected_existing_paths': 4, 'outcome_selected_pairs': 2,
              'existing_CSV_rows_processed': 183143,
              'new_IDP_calls': 0, 'new_truth_score_evaluations': 0,
              'new_solver_trajectories': 0, 'new_searches': 0,
              'original_research_files_edited': 0,
              'scope': 'Post hoc descriptive saved-log reading, two selected failures and paired B paths; bounded BOE web-index route. Phase16 and earlier research frozen; current entry documents and verification tools updated.'}
    new_file(REPO / 'provenance/phase17_update.json',
             (json.dumps(update, ensure_ascii=False, indent=2) + '\n').encode())
    print(json.dumps({'status': 'copied_closed_selection', **update}, indent=2))


if __name__ == '__main__':
    main()

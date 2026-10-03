"""Read-only verification of the closed direct Gazeta query, standard library only.

Checks published hashes, own receipts and counters. Does not require or read
referenced external HTML, search responses, OCR text, PDF or PNG files. Does not
execute historical scripts, fetch URLs, run scorers/solvers or touch phase17 CSVs.
"""
import argparse
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

DEFAULT_ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'work/primary_history_20261003/'
INVENTORY = 'provenance/gazeta_20261003_source_inventory.jsonl'
UPDATE = 'provenance/gazeta_20261003_update.json'
BASELINE_SHA256 = '9b35b54c9eb067397d2c543d0ec8e57f30cdf7103382a420c579e7f41dc85672'
FIXED = {
    'plan.json': '66864673109746bc21c22aeaa4bd6901c5484cdf1178f8b67a44e27a9562756d',
    'form_stage_plan.json': 'd12fb50ffdcd2df475a89888fdebd3f661a0f29592c9a8771af8c750017441fa',
    'form_stage_review.txt': '02cf5de1467b26a646e87e2bc40f4d708d81b9b5cdbfa87557e1fc31b3dd5722',
    'review_final.txt': '459d4f6c785cdf587d2210e295a96027f16ccec5562a4e11e6750d278d8ec0b3',
    'read_observed_form.py': 'd5d3685afaade08317d6dd328c6e1c0712ddbaead5161149af6c262111e66100',
    'query_observed_form.py': '045614ab5f1d4108af305f75bade04e8d8ded502afc7543ad829815bbc52c31e',
    'query2_control.py': '903ce0c72745aeaa1323c77b2efd4f03e92fe9ef7b17be6992db7403faafab5c',
}
EXTERNAL = {'homepage_web_response.json', 'gazeta_form_web_response.json',
    'collection_raw.html', 'form_raw.html', 'query1_raw.html', 'query2_raw.html',
    'control_original.pdf', 'control_external_text.txt', 'control-page-1.png',
    'control-page-2.png', 'control_records.json', 'observed_controls.json'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def within(root, relative):
    require(isinstance(relative, str) and not Path(relative).is_absolute(), 'Expected relative export path')
    path = (root / relative).resolve()
    require(path.is_relative_to(root), 'Path outside public export')
    return path


def load(root, relative):
    return json.loads(within(root, relative).read_text(encoding='utf-8'))


def stamp(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(parsed.utcoffset() == timedelta(0), 'Receipt time is not UTC')
    return parsed


def main(root):
    root = root.resolve()
    entries = [json.loads(s) for s in within(root, INVENTORY).read_text().splitlines() if s.strip()]
    sources = {e['source_path']: e for e in entries}
    require(len(sources) == len(entries), 'Duplicate inventory source')
    included = [e for e in entries if e['disposition'] == 'included']
    referenced = [e for e in entries if e['disposition'] == 'referenced_only']
    require(len(included) + len(referenced) == len(entries), 'Unknown publication disposition')
    require(len({e['repository_path'] for e in included}) == len(included), 'Duplicate destination')
    for entry in included:
        require(entry['source_path'] not in {PREFIX + name for name in EXTERNAL},
                'External body/extraction was copied instead of referenced')
        path = within(root, entry['repository_path'])
        require(path.is_file() and sha(path) == entry['sha256']
                and path.stat().st_size == entry['bytes'], 'Included resource hash/size differs')
    for entry in referenced:
        require(bool(entry.get('reason')), 'Referenced-only resource lacks a reason')
    own_names = {'plan.json', 'form_stage_plan.json', 'form_stage_review.txt', 'review_final.txt',
        'access_started.json', 'navigation_receipt.json', 'form_access_receipt.json',
        'query1_receipt.json', 'query2_receipt.json', 'control_receipt.json',
        'control_read_receipt.json', 'ledger.json', 'resultado_directo_gazeta.txt',
        'read_observed_form.py', 'query_observed_form.py', 'query2_control.py',
        'preflight_attempts/attempt01_receipt.json', 'preflight_attempts/attempt01_source.py'}
    required_own = {PREFIX + name for name in own_names} | {
        'work/primary_history_20261003_publication/root_approval.json'}
    require(all(relative in sources and sources[relative]['disposition'] == 'included'
                and sources[relative]['repository_path'] == relative for relative in required_own),
            'Required own plan/source/report/receipt omitted from export inventory')
    for name in EXTERNAL:
        require(PREFIX + name in sources and sources[PREFIX + name]['disposition'] == 'referenced_only',
                'External source is not accounted for by reference')
    for name, digest in FIXED.items():
        require(sha(within(root, PREFIX + name)) == digest, 'Fixed plan/source/review differs: ' + name)
    baseline = within(root, 'provenance/phase17_file_hashes.json')
    require(sha(baseline) == BASELINE_SHA256, 'Phase17 checksum was not preserved byte for byte')
    update = load(root, UPDATE)
    require(update['new_inventory_entries'] == len(entries)
            and update['new_included_files'] == len(included)
            and update['new_referenced_files'] == len(referenced)
            and update['new_IDP_calls'] == 0 and update['new_solver_trajectories'] == 0,
            'Publication update counts/scope differ')
    approval = load(root, 'work/primary_history_20261003_publication/root_approval.json')
    require(approval['status'] == 'closed_own_notes_root_approved'
            and approval['new_IDP_calls'] == approval['new_UI_attempts'] == 0
            and approval['original_scientific_files_changed'] == 0
            and approval['independent_review_path'] == PREFIX + 'review_final.txt'
            and approval['report_path'] == PREFIX + 'resultado_directo_gazeta.txt'
            and sha(within(root, approval['independent_review_path'])) == approval['independent_review_sha256']
            and sha(within(root, approval['report_path'])) == approval['report_sha256'],
            'Root approval does not bind the final own report and independent review')
    get = lambda name: load(root, PREFIX + name)
    plan = get('plan.json')
    stage = get('form_stage_plan.json')
    access = get('access_started.json')
    nav = get('navigation_receipt.json')
    form = get('form_access_receipt.json')
    first, control = get('query1_receipt.json'), get('query2_receipt.json')
    original, read = get('control_receipt.json'), get('control_read_receipt.json')
    ledger = get('ledger.json')
    preflight = get('preflight_attempts/attempt01_receipt.json')
    require(plan['root_approved'] is True and stage['root_approved'] is True,
            'Saved plans lack root approval')
    require(plan['limits']['new_IDP_calls'] == plan['limits']['new_solver_trajectories'] == 0
            and all(plan['limits'][field] == 0 for field in ('UI_attempts', 'contacts', 'purchases', 'accounts')),
            'Plan permits activity outside the historical query scope')
    require(nav['status'] == 'navigation_stage_closed_at_fixed_limit'
            and nav['interface_openings'] == nav['observable_web_requests'] == nav['web_tool_calls'] == 2
            and nav['direct_queries'] == nav['original_documents_opened'] == 0,
            'Initial navigation was not closed at two observed openings')
    require(form['status'] == 'public_form_read_no_queries_submitted'
            and form['own_HTTP_attempts'] == form['form_stage_HTML_GETs'] == len(form['requests']) == 2
            and form['direct_queries'] == 0, 'Separate form-stage counters differ')
    deadline = stamp(stage['limits']['latest_stop_utc'])
    lower_bound = stamp(access['first_external_access_time_lower_bound_utc'])
    require(deadline == stamp(access['latest_stop_at_utc'])
            and deadline - lower_bound == timedelta(minutes=15), 'Global clock was extended')
    require(stage['limits']['direct_queries_across_both_stages'] == 2
            and stage['limits']['first_page_records_read_max'] == 20,
            'Query/metadata caps differ from the stage plan')
    expected_fields = {'campo[4]': 'DOC', 'operador[4]': 'and', 'campo[8]': 'FPU',
        'dato[8][0]': '1936-01-01', 'dato[8][1]': '1938-12-31', 'operador[8]': 'and',
        'page_hits': '50', 'sort_field[0]': 'FPU', 'sort_order[0]': 'desc',
        'sort_field[1]': 'REF', 'sort_order[1]': 'asc', 'accion': 'Buscar'}
    requests = list(form['requests']) + [first, control, original]
    for request in requests:
        require(stamp(request['started_at_utc']) < deadline, 'HTTP request began beyond the saved deadline')
        require(request.get('HTTP_status', request.get('status')) == 200
                and request['requested_url'] == request['final_url'], 'Saved HTTP response failed/redirected')
        url = urlsplit(request['requested_url'])
        require(url.scheme == 'https' and url.hostname == 'www.boe.es', 'Unexpected source endpoint')
    require([r['requested_url'] for r in form['requests']] ==
            ['https://www.boe.es/diario_gazeta/', 'https://www.boe.es/buscar/gazeta.php'],
            'Form access differs from the observed official href')
    for index, (receipt, term) in enumerate(((first, 'BLUME'), (control, 'Salamanca')), 1):
        fields = expected_fields | {'dato[4]': term}
        require(receipt['query_index'] == index and receipt['term'] == term
                and receipt['fields'] == fields
                and receipt['publication_dates'] == ['1936-01-01', '1938-12-31']
                and receipt['own_HTTP_attempts'] == 1, 'Query field/filter/term differs')
        url = urlsplit(receipt['requested_url'])
        require(url.path == '/buscar/gazeta.php'
                and parse_qs(url.query, keep_blank_values=True) == {k: [v] for k, v in fields.items()},
                'Requested URL disagrees with the saved query fields')
    require(ledger['status'] == 'bounded_direct_query_closed'
            and ledger['BLUME_response'] == 'No documents satisfying submitted criteria'
            and ledger['web_tool_requests_observed'] == 2 and ledger['own_HTTP_requests'] == len(requests) == 5
            and ledger['interface_reads_total'] == 4 and ledger['direct_queries'] == 2
            and ledger['original_documents'] == 1 and ledger['PNG_pages_rendered'] == 2
            and ledger['control_result_declared_total'] == 2471
            and ledger['control_page_delivered_records'] == 50
            and ledger['control_metadata_read_records'] == 20
            and ledger['publication_dates_submitted'] == ['1936-01-01', '1938-12-31']
            and stamp(ledger['root_closed_at_utc']) < deadline, 'Final own-ledger counters/scope differ')
    for name, record in ledger['external_response_files_local'].items():
        entry = sources[PREFIX + name]
        require(entry['disposition'] == 'referenced_only' and entry['sha256'] == record['sha256']
                and entry['bytes'] == record['bytes'], 'External hash reference differs from own ledger')
    pairs = [('collection_raw.html', form['requests'][0]), ('form_raw.html', form['requests'][1]),
             ('query1_raw.html', first), ('query2_raw.html', control), ('control_original.pdf', original)]
    for name, receipt in pairs:
        recorded = ledger['external_response_files_local'][name]
        require(receipt['sha256'] == recorded['sha256'] and receipt['bytes'] == recorded['bytes'],
                'HTTP receipt differs from external hash reference')
    require(original['selected_control_record_index'] == read['record_index'] == 19
            and original['own_HTTP_attempts'] == 1
            and original['requested_url'] == 'https://www.boe.es/datos/pdfs/BOE//1938/175/A03079-03080.pdf'
            and read['status'] == 'two_control_pages_read_visually'
            and read['source_sha256'] == original['sha256']
            and read['reference'] == 'BOE-A-1938-14911' and read['PDF_pages'] == read['PNG_pages_rendered'] == 2
            and read['printed_pages'] == [3079, 3080] and read['Salamanca_verified_in_body'] is True
            and read['network_requests_for_read'] == 0 and stamp(read['read_at_utc']) < deadline,
            'Control selection/visual-read receipt differs')
    require(preflight['status'] == 'local_preflight_guard_failed_before_network'
            and preflight['own_HTTP_attempts'] == preflight['direct_queries'] == 0
            and ledger['local_preflight_failures'] == 1 and ledger['local_preflight_HTTP_requests'] == 0
            and sha(within(root, PREFIX + 'preflight_attempts/attempt01_source.py')) == preflight['source_sha256'],
            'Preserved local failure differs or is charged as an HTTP query')
    for item in [access, nav, form, first, control, original, read, ledger, preflight]:
        require(item['new_IDP_calls'] == 0, 'History receipt records new IDP')
        if 'UI_attempts' in item:
            require(item['UI_attempts'] == 0, 'History receipt records UI actions')
    print(json.dumps({'status': 'passed', 'addition': 'gazeta_20261003',
        'included_hashes_checked': len(included), 'referenced_resources_not_read': len(referenced),
        'web_tool_requests_observed': 2, 'own_HTTP_requests': 5, 'interface_reads': 4,
        'direct_queries': 2, 'control_declared_results': 2471, 'received_records': 50,
        'metadata_records_read': 20, 'original_documents': 1, 'visual_pages': 2,
        'new_IDP_calls': 0, 'new_solver_trajectories': 0, 'new_network_requests': 0,
        'phase17_CSVs_replayed': 0,
        'scope': 'Own recorded query fields, counters and receipt integrity; no new source/OCR reading.',
        'limits': 'Approximate text search; no BLUME identification, corpus-absence or OCR-sensitivity claim.'}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args()
    try:
        main(args.root)
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit(json.dumps({'status': 'failed', 'error': str(error),
            'new_IDP_calls': 0, 'new_network_requests': 0, 'phase17_CSVs_replayed': 0}, indent=2))

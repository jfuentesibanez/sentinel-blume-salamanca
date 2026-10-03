"""Submit the fixed first query using only controls observed in the saved form."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode, urljoin
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent
DEADLINE = datetime.fromisoformat('2026-10-03T02:29:44+00:00')


def main():
    metadata = json.loads((ROOT / 'observed_controls.json').read_text())
    forms = [f for f in metadata['forms'] if f['attributes'].get('method') == 'GET']
    assert len(forms) == 1
    form = forms[0]
    controls = {c['attributes']['name']: c['attributes'] for c in form['controls']
                if c['tag'] in ('input', 'select') and 'name' in c['attributes']}
    params = {'campo[4]': 'DOC', 'dato[4]': 'BLUME', 'operador[4]': 'and',
              'campo[8]': 'FPU', 'dato[8][0]': '1936-01-01', 'dato[8][1]': '1938-12-31',
              'operador[8]': 'and', 'page_hits': '50', 'sort_field[0]': 'FPU',
              'sort_order[0]': 'desc', 'sort_field[1]': 'REF', 'sort_order[1]': 'asc', 'accion': 'Buscar'}
    assert all(name in controls for name in params)
    assert controls['campo[4]']['value'] == 'DOC' and controls['campo[8]']['value'] == 'FPU'
    assert controls['dato[8][0]']['type'] == controls['dato[8][1]']['type'] == 'date'
    raw = (ROOT / 'form_raw.html').read_text()
    assert '1836 y 1959' in raw and 'resultados aproximados' in raw
    action = urljoin(metadata['form_url'], form['attributes']['action'])
    assert action == metadata['form_url']
    receipt_path = ROOT / 'query1_receipt.json'
    assert not receipt_path.exists() and datetime.now(timezone.utc) < DEADLINE
    url = action + '?' + urlencode(params)
    receipt = {'query_index': 1, 'term': 'BLUME', 'scope': 'Observed Texto/DOC, approximate historical text search1836–1959; not independently verified OCR completeness.',
               'publication_dates': ['1936-01-01', '1938-12-31'], 'fields': params,
               'requested_url': url, 'started_at_utc': datetime.now(timezone.utc).isoformat(),
               'own_HTTP_attempts': 1, 'new_IDP_calls': 0, 'UI_attempts': 0}
    try:
        with urlopen(url, timeout=15) as response:
            data = response.read()
            receipt.update(HTTP_status=response.status, final_url=response.url,
                           bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        assert receipt['HTTP_status'] == 200
        (ROOT / 'query1_raw.html').write_bytes(data)
        receipt['status'] = 'response_saved_not_yet_interpreted'
    except Exception as error:
        receipt.update(status='failed_no_retry', error_type=type(error).__name__, error=str(error))
        raise
    finally:
        receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps(receipt, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()

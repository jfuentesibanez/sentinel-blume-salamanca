"""Run the preselected Salamanca response control after a zero BLUME response."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode, urlparse
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent
DEADLINE = datetime.fromisoformat('2026-10-03T02:29:44+00:00')


def main():
    first = json.loads((ROOT / 'query1_receipt.json').read_text())
    assert first['HTTP_status'] == 200 and first['term'] == 'BLUME'
    assert 'No se han encontrado documentos que satisfagan sus criterios' in (ROOT / 'query1_raw.html').read_text()
    params = dict(first['fields']); params['dato[4]'] = 'Salamanca'
    assert all(params[k] == v for k, v in first['fields'].items() if k != 'dato[4]')
    form_url = json.loads((ROOT / 'observed_controls.json').read_text())['form_url']
    assert urlparse(form_url).hostname == 'www.boe.es'
    path = ROOT / 'query2_receipt.json'
    assert not path.exists() and datetime.now(timezone.utc) < DEADLINE
    receipt = {'query_index': 2, 'term': 'Salamanca', 'role': 'Fixed response control after zero results; not an identity search or complete OCR validation.',
               'fields': params, 'publication_dates': first['publication_dates'],
               'requested_url': form_url + '?' + urlencode(params),
               'started_at_utc': datetime.now(timezone.utc).isoformat(), 'own_HTTP_attempts': 1,
               'new_IDP_calls': 0, 'UI_attempts': 0}
    try:
        with urlopen(receipt['requested_url'], timeout=15) as response:
            data = response.read()
            receipt.update(HTTP_status=response.status, final_url=response.url,
                           bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        assert receipt['HTTP_status'] == 200
        (ROOT / 'query2_raw.html').write_bytes(data)
        receipt['status'] = 'control_response_saved_not_yet_interpreted'
    except Exception as error:
        receipt.update(status='failed_no_retry', error_type=type(error).__name__, error=str(error))
        raise
    finally:
        path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps(receipt, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()

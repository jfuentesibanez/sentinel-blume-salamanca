"""Read two observed public HTML interfaces; submit no queries."""
import hashlib
import json
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent
DEADLINE = datetime.fromisoformat('2026-10-03T02:29:44+00:00')


class Parser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.anchors = []
        self.forms = []
        self.anchor = None
        self.form = None
    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == 'a':
            self.anchor = {'attributes': attributes, 'text': ''}
        if tag == 'form':
            self.form = {'attributes': attributes, 'controls': []}
            self.forms.append(self.form)
        if self.form is not None and tag in ('input', 'select', 'textarea', 'button', 'option', 'label'):
            self.form['controls'].append({'tag': tag, 'attributes': attributes})
    def handle_data(self, data):
        if self.anchor is not None:
            self.anchor['text'] += data
    def handle_endtag(self, tag):
        if tag == 'a' and self.anchor is not None:
            self.anchor['text'] = ' '.join(self.anchor['text'].split())
            self.anchors.append(self.anchor)
            self.anchor = None
        if tag == 'form':
            self.form = None


def main():
    approval = ROOT / 'form_stage_review.txt'
    assert approval.is_file() and hashlib.sha256(approval.read_bytes()).hexdigest() == '02cf5de1467b26a646e87e2bc40f4d708d81b9b5cdbfa87557e1fc31b3dd5722'
    assert 'favorable a esta etapa separada' in approval.read_text()
    assert not (ROOT / 'form_access_receipt.json').exists()
    requests = []
    def fetch(url, name):
        assert len(requests) < 2 and datetime.now(timezone.utc) < DEADLINE
        assert urlparse(url).scheme == 'https' and urlparse(url).hostname == 'www.boe.es'
        item = {'requested_url': url, 'started_at_utc': datetime.now(timezone.utc).isoformat(), 'query_submitted': False}
        requests.append(item)
        try:
            with urlopen(url, timeout=15) as response:
                data = response.read()
                item.update(status=response.status, final_url=response.url, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            assert item['status'] == 200
            path = ROOT / name
            assert not path.exists()
            path.write_bytes(data)
            parser = Parser(); parser.feed(data.decode('utf-8'))
            return parser
        except Exception as error:
            item.update(error_type=type(error).__name__, error=str(error))
            raise
    status = 'failed_no_queries'
    form_url = None
    try:
        collection = fetch('https://www.boe.es/diario_gazeta/', 'collection_raw.html')
        anchors = [a for a in collection.anchors if a['text'].casefold() == 'consulta de gazeta']
        assert len(anchors) == 1, 'Observed consultation anchor not uniquely recovered'
        href = anchors[0]['attributes']['href']
        form_url = urljoin('https://www.boe.es/diario_gazeta/', href)
        form = fetch(form_url, 'form_raw.html')
        parsed = {'collection_consultation_anchor': anchors[0], 'form_url': form_url,
                  'forms': form.forms, 'form_anchors': form.anchors}
        (ROOT / 'observed_controls.json').write_text(json.dumps(parsed, ensure_ascii=False, indent=2) + '\n')
        status = 'public_form_read_no_queries_submitted'
    finally:
        receipt = {'status': status, 'requests': requests, 'own_HTTP_attempts': len(requests),
                   'form_stage_HTML_GETs': len(requests), 'form_url': form_url,
                   'redirect_internal_requests': 'Not counted separately by urllib; requested and final URLs recorded.',
                   'direct_queries': 0, 'new_IDP_calls': 0, 'UI_attempts': 0}
        (ROOT / 'form_access_receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps(receipt, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()

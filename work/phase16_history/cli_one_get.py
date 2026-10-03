from pathlib import Path
import urllib.request, urllib.error, datetime, json, hashlib, socket
out=Path(__file__).resolve().parent
url='https://archive.org/advancedsearch.php?q=%22German%20Foreign%20Office%22&fl%5B%5D=identifier&fl%5B%5D=title&fl%5B%5D=description&rows=50&page=1&output=json'
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
request={'url':url,'method':'GET','timeout_seconds':20,'redirects_followed':0,'cookies':False,'authentication':False,'body_limit_bytes':4*1024*1024,'query':'"German Foreign Office"','request_number':3,'reason':'One direct public catalogue GET after web wrapper returned not accessible without a real HTTP status. Root-authorized bounded clarification; no new query, no item opening.'}
(out/'cli_request.json').write_text(json.dumps(request,ensure_ascii=False,indent=2)+'\n')
receipt={'started_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'request':request,'network_get_attempts':1,'status':None,'body_read':False,'outcome':None}
body=b''
try:
    opener=urllib.request.build_opener(NoRedirect())
    resp=opener.open(urllib.request.Request(url,method='GET'),timeout=20)
    receipt['status']=resp.status
    receipt['content_type']=resp.headers.get('Content-Type')
    receipt['content_length']=resp.headers.get('Content-Length')
    body=resp.read(4*1024*1024+1)
    receipt['body_truncated']=len(body)>4*1024*1024
    body=body[:4*1024*1024]
    receipt['body_read']=True
    receipt['outcome']='HTTP response received'
except urllib.error.HTTPError as e:
    receipt['status']=e.code
    receipt['content_type']=e.headers.get('Content-Type')
    body=e.read(4*1024*1024+1)
    receipt['body_truncated']=len(body)>4*1024*1024
    body=body[:4*1024*1024]
    receipt['body_read']=True
    receipt['outcome']='HTTP error response received; no redirect or retry followed'
except Exception as e:
    receipt['outcome']='Transport failure; no HTTP status or response body'
    receipt['error_type']=type(e).__name__
    receipt['error']=str(e)
if body:
    (out/'cli_response_body.bin').write_bytes(body)
    receipt['body_bytes']=len(body)
    receipt['body_sha256']=hashlib.sha256(body).hexdigest()
    if receipt.get('status')==200 and not receipt.get('body_truncated'):
        try:
            payload=json.loads(body)
            response=payload.get('response',{})
            docs=response.get('docs',[])
            summary={'numFound':response.get('numFound'),'docs_returned':len(docs),'first_docs':docs[:10],'item_pages_opened':0}
            (out/'cli_catalogue_summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
            receipt['json_parsed']=True
            receipt['numFound']=response.get('numFound')
            receipt['docs_returned']=len(docs)
        except Exception as e:
            receipt['json_parsed']=False
            receipt['parse_error_type']=type(e).__name__
receipt['finished_at_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
(out/'cli_receipt.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(receipt,ensure_ascii=False,indent=2))

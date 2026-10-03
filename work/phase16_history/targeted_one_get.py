from pathlib import Path
import urllib.request, urllib.error, json, hashlib, datetime
out=Path(__file__).resolve().parent
plan=json.loads((out/'targeted_query_plan.json').read_text())
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None
receipt={'started_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'plan_sha256':hashlib.sha256((out/'targeted_query_plan.json').read_bytes()).hexdigest(),'url':plan['url'],'method':'GET','attempts':1,'redirects_followed':0,'cookies':False,'authentication':False,'status':None,'body_read':False}
body=b''
try:
    resp=urllib.request.build_opener(NoRedirect()).open(urllib.request.Request(plan['url'],method='GET'),timeout=20)
    receipt.update({'status':resp.status,'content_type':resp.headers.get('Content-Type')})
    body=resp.read(4194305);receipt['body_truncated']=len(body)>4194304;body=body[:4194304];receipt['body_read']=True
except urllib.error.HTTPError as e:
    receipt.update({'status':e.code,'content_type':e.headers.get('Content-Type')});body=e.read(4194305);receipt['body_truncated']=len(body)>4194304;body=body[:4194304];receipt['body_read']=True
except Exception as e:receipt.update({'error_type':type(e).__name__,'error':str(e)})
if body:
    (out/'targeted_response_body.bin').write_bytes(body);receipt.update({'body_bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest()})
    if receipt.get('status')==200 and not receipt.get('body_truncated'):
        try:
            data=json.loads(body);response=data.get('response',{});docs=response.get('docs',[])
            summary={'numFound':response.get('numFound'),'docs_returned':len(docs),'docs':docs,'item_objects_opened':0}
            (out/'targeted_catalogue_summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
            receipt.update({'json_parsed':True,'numFound':response.get('numFound'),'docs_returned':len(docs)})
        except Exception as e:receipt.update({'json_parsed':False,'parse_error_type':type(e).__name__})
receipt['finished_at_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();(out/'targeted_receipt.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(receipt,ensure_ascii=False,indent=2))

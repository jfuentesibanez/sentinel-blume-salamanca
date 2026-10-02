"""Verify preserved evidence and package phase11 provenance. No searches or contacts."""
from pathlib import Path
import hashlib, json

ROOT=Path(__file__).resolve().parent.parent
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def load(path): return json.loads(path.read_text())
def save(path,value): path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
counts={}
for relative in ['work/phase11_crypto/RESOURCE_HASHES.json',
                 'work/history/phase11-adap-documentos/resource-hashes.json',
                 'work/history/phase11-adap-buscador/resource-hashes.json',
                 'work/history/phase11-oswald-madrid/resource-hashes.json',
                 'work/source/phase11-public-state/resource-hashes.json']:
    path=ROOT/relative; manifest=load(path)
    entries=manifest.get('resources')
    if entries is None: entries=[dict(path=name,**record) for name,record in manifest['files'].items()]
    for entry in entries:
        file=path.parent/entry['path']
        assert sha(file)==entry['sha256'] and file.stat().st_size==entry['bytes'],str(file)
    counts[relative]=len(entries)
history=load(ROOT/'work/history/phase11-adap-documentos/protected-baseline.json')
assert len(history)==849
for relative,digest in history.items(): assert sha(ROOT/relative)==digest,relative
crypto=load(ROOT/'work/phase11_crypto/manifest.json')
assert len(crypto['protected_before'])==282
for entry in crypto['protected_before']: assert sha(ROOT/entry['path'])==entry['sha256']
assert sha(ROOT/'outputs/Sentinel_BLUME_fase10_2026-10-02.txt')=='7794757b179e4018c598b29119b727106a0f792bc613dc3d13a551069050981d'
prior_path=ROOT/'outputs/Sentinel_BLUME_fase10_2026-10-02_procedencia.json'
assert sha(prior_path)=='cd09cbe6e2fcf9f163ca03308086730a621412a35e94ab6b83d2287092680024'
prior=load(prior_path)
for relative,digest in prior['evidence_files'].items(): assert sha(ROOT/relative)==digest,relative
canonical=load(ROOT/'outputs/blume_sentinel/verification.json')['messages']
for message in canonical:
    path=ROOT/'work/source'/message['file']
    normalized=''.join(path.read_text().split()).upper()
    assert sha(path)==message['sha256_raw_file']
    assert hashlib.sha256(normalized.encode()).hexdigest()==message['sha256_normalized']
    assert len(normalized)==message['length']
root_audit=load(ROOT/'work/phase11_root_verification.json')
independent=load(ROOT/'work/phase11_independent_audit.json')
assert root_audit['status']=='passed' and independent['passed']
assert root_audit['saved_results_sha256']==independent['search_log_sha256']==sha(ROOT/'work/phase11_crypto/search_outputs.jsonl')
assert independent['sealed_design_sha256']==sha(ROOT/'work/phase11_crypto/sealed_design.json')
hist_ledger=load(ROOT/'work/history/phase11-adap-documentos/ledger.json')
assert hist_ledger['budgets']['visual_scans_here']==35
assert hist_ledger['budgets']['fully_read_numbered_documents']==10
assert hist_ledger['budgets']['additional_primary_pieces_or_comments']==4
assert hist_ledger['access']['root_viewer_queries']==2
assert 'libra esterlina' in next(d for d in hist_ledger['documents'] if d['number']==208)['fact']
emails=load(ROOT/'outputs/Sentinel_BLUME_estado_correos_fase11_2026-10-02.json')
assert len(emails['threads'])==4 and all(len(t['messages'])==1 and t['messages'][0]['label_ids']==['SENT'] for t in emails['threads'])
assert emails['query_result']['message_ids']==[]
report=ROOT/'outputs/Sentinel_BLUME_fase11_2026-10-02.txt'
result={'phase':11,'passed':True,'new_resource_counts_excluding_manifests':counts,
        'previous_historical_files_preserved':849,'previous_crypto_files_preserved':282,
        'previous_phase10_evidence_files_preserved':len(prior['evidence_files']),
        'previous_phase10_report_and_provenance_preserved':True,'canonical_ciphertexts_preserved':2,
        'root_crypto_check_passed':True,'independent_crypto_check_passed':True,
        'history_visual_documents':10,'history_visual_scans':35,'additional_primary_pieces':4,
        'root_visual_cotejo':[180,187,213],
        'report_sha256':sha(report),'contacts':0,'new_searches_after_sealed32':0,
        'limits':'No verified BLUME plaintext, key or recipient identity. Provenance verifies saved evidence, not historical hypotheses.'}
final_audit=ROOT/'work/phase11_final_artifact_verification.json';save(final_audit,result)
evidence=[
 'work/phase11_crypto/RESOURCE_HASHES.json','work/phase11_crypto/manifest.json',
 'work/phase11_crypto/summary.json','work/phase11_crypto/verification.json',
 'work/phase11_pre_search_root_review.json','work/phase11_independent_audit.json',
 'work/phase11_root_verification.json','work/verify_blume_phase11.py',
 'work/phase11_final_artifact_verification.json','work/close_blume_phase11.py',
 'work/history/phase11-adap-documentos/resource-hashes.json',
 'work/history/phase11-adap-documentos/ledger.json','work/history/phase11-adap-documentos/resultado.txt',
 'work/history/phase11-adap-buscador/resource-hashes.json',
 'work/history/phase11-oswald-madrid/resource-hashes.json',
 'work/source/phase11-public-state/resource-hashes.json',
 'outputs/Sentinel_BLUME_estado_correos_fase11_2026-10-02.json']
provenance={'project':'Sentinel — BLUME SALAMANCA','phase':11,'date':'2026-10-02',
 'report':{'path':str(report.relative_to(ROOT)),'sha256':sha(report)},
 'historical_status':'No verified historical plaintext, key or recipient identity.',
 'history':{'source':hist_ledger['source'],'permalink':hist_ledger['permalink'],
            'document_numbers':[d['number'] for d in hist_ledger['documents']],
            'fully_read_documents':10,'additional_primary_pieces':4,'visual_scans':35,
            'new_viewer_queries':2,'root_independent_visual_cotejo':[180,187,213],
            'limit':'Edited facsimile1951, not full original archive files. Printed film/frame references not converted to current PAAA signatures.'},
 'crypto':{'scope':'Synthetic K2-only; known widths, shared keys; no K1 or historical attack.',
           'seeds':[20262101,20262102],'paired_cases':8,'rounds_per_method':16,
           'hits':root_audit['archive_hits'],'cases_with_any_hit':root_audit['pairs_with_hits'],
           'calls_per_method':1600000,'limit':'All hits German12x15. No French or20x25 recovery. Local cap and refresh frequency change together. Literary controls are not1937commercial plaintext.'},
 'emails':{'account':'javier@ncompany.es','read_threads':4,'targeted_query_results':0,
           'scope':'No replies in the four project threads or targeted query. No general mailbox claim.'},
 'source_integrity':result,
 'evidence_files':{p:sha(ROOT/p) for p in evidence},
 'external_actions':{'emails_sent':0,'comments_posted':0,'accounts_created':0,'orders':0,'payments':0,'automations':0},
 'next_steps_status':'Search original Bernhardt/Hisma correspondence and convert film references; design next long-key control pilot separating cap and refresh changes. Neither executed by this closure.'}
output=ROOT/'outputs/Sentinel_BLUME_fase11_2026-10-02_procedencia.json';save(output,provenance)
assert load(output)['report']['sha256']==sha(report)
assert all(sha(ROOT/p)==digest for p,digest in load(output)['evidence_files'].items())
print(json.dumps({'passed':True,'report':str(report),'report_sha256':sha(report),'provenance_sha256':sha(output),'counts':counts},ensure_ascii=False))

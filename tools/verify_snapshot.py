"""Read-only verification of the selected public export, not a solver run."""
from pathlib import Path
from collections import Counter
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    checksums = json.loads((ROOT/'provenance/file_hashes.json').read_text())
    missing=[]; changed=[]
    for name,digest in checksums.items():
        p=ROOT/name
        if not p.is_file(): missing.append(name)
        elif sha(p)!=digest: changed.append(name)
    if missing or changed:
        raise SystemExit(json.dumps({'missing':missing,'changed':changed},indent=2))
    entries=[json.loads(s) for s in (ROOT/'provenance/source_inventory.jsonl').read_text().splitlines()]
    snapshot=json.loads((ROOT/'provenance/snapshot.json').read_text())
    assert len(entries)==snapshot['inventory_entries']
    assert dict(Counter(e['disposition'] for e in entries))==snapshot['dispositions']
    for e in entries:
        if e['disposition'] in ('included','duplicate'):
            assert sha(ROOT/e['repository_path'])==e['sha256'],e['source_path']
    expected={
        'ct1':(615,'d442e136d63bfc066c20374e2b454ca5581b164e940b307d5600d0d463df943e',
               'e266615d92019276513c1b7656f10c4f1a3d1e8eb739d28fd481ae337a434c55'),
        'ct2':(160,'d2cdadbefb0bef2fbcdcf83bf6de1b104583e166f14f0a3d2b545024b3188df0',
               '8fd5cfb82fc3c39fe0ee007b19ada7e74b4ae7747cd9b794d36dce101e17a644'),
    }
    for name,(length,raw_digest,normalized_digest) in expected.items():
        p=ROOT/'work/source'/f'{name}.txt';text=p.read_text()
        assert sha(p)==raw_digest and len(text)==length
        assert hashlib.sha256(text.upper().encode('ascii')).hexdigest()==normalized_digest
    t1=(ROOT/'work/source/ct1.txt').read_text().upper()
    groups=[t1[i:i+5] for i in range(0,len(t1),5)]
    assert [groups[i-1] for i in [38,48,122,113]]==['SOLRS','ACCEL','FTULX','RBEEP']
    truth={r['case_id']:r for r in map(json.loads,(ROOT/'work/phase11_crypto/truth.jsonl').read_text().splitlines())}
    runs=list(map(json.loads,(ROOT/'work/phase11_crypto/search_outputs.jsonl').read_text().splitlines()))
    hits=Counter();calls=Counter()
    for r in runs:
        assert r['mode']=='ciphertext_only_k2' and r['objective_calls']==100000
        assert not any(k.startswith(('true_','truth_')) for k in r)
        hits[r['method']]+=int(any(a['k2']==truth[r['case_id']]['true_k2'] for a in r['archive']))
        calls[r['method']]+=r['objective_calls']
    assert len(runs)==32 and len(truth)==8
    assert dict(hits)=={'population':2,'cap5000':3}
    assert dict(calls)=={'population':1600000,'cap5000':1600000}
    update=json.loads((ROOT/'provenance/phase14_update.json').read_text())
    added=[json.loads(s) for s in (ROOT/'provenance/phase14_source_inventory.jsonl').read_text().splitlines()]
    assert len(added)==update['new_inventory_entries']
    assert sum(e['disposition']=='included' for e in added)==update['new_included_files']
    for e in added:
        if e['disposition']=='included':
            assert sha(ROOT/e['repository_path'])==e['sha256'],e['source_path']
    phase14=ROOT/'work/phase14_crypto'
    truth14={r['case_id']:r for r in map(json.loads,(phase14/'truth.jsonl').read_text().splitlines())}
    runs14=list(map(json.loads,(phase14/'search_outputs.jsonl').read_text().splitlines()))
    evaluation=json.loads((phase14/'evaluation.json').read_text())
    hits14=Counter();calls14=Counter()
    for r in runs14:
        assert r['objective_calls']==100000 and r['periodic_refreshes']==0
        assert not any(k.startswith(('true_','truth_')) for k in r)
        hits14[r['arm']]+=int(any(a['k2']==truth14[r['case_id']]['true_k2'] for a in r['archive']))
        calls14[r['arm']]+=r['objective_calls']
    assert len(runs14)==32 and len(truth14)==4
    assert dict(hits14)=={'A':0,'B':0,'C':0,'D':0}
    assert all(v==800000 for v in calls14.values())
    assert sum(calls14.values())==update['main_objective_calls']==3200000
    assert sha(phase14/'search_outputs.jsonl')==evaluation['log_sha256']
    assert sha(phase14/'truth.jsonl')==evaluation['truth_sha256']
    update15=json.loads((ROOT/'provenance/phase15_update.json').read_text())
    added15=[json.loads(s) for s in (ROOT/'provenance/phase15_source_inventory.jsonl').read_text().splitlines()]
    assert len(added15)==update15['new_inventory_entries']
    assert sum(e['disposition']=='included' for e in added15)==update15['new_included_files']
    for e in added15:
        if e['disposition']=='included':
            assert sha(ROOT/e['repository_path'])==e['sha256'],e['source_path']
    phase15=ROOT/'work/phase15_crypto'
    manifest15=json.loads((phase15/'manifest.json').read_text())
    evaluation15=json.loads((phase15/'evaluation.json').read_text())
    assert manifest15['completed'] and manifest15['all_profiles_complete']
    assert len(manifest15['runs'])==12 and manifest15['legacy_calls']==manifest15['exact_calls']==199800
    assert evaluation15['totals']['idp_equivalent_calls']==399600
    assert evaluation15['manifest_sha256']==sha(phase15/'manifest.json')
    assert evaluation15['new_legacy_calls']==evaluation15['new_exact_calls']==0
    assert evaluation15['totals']['distinct_planted_keypairs']==2
    update16=json.loads((ROOT/'provenance/phase16_update.json').read_text())
    added16=[json.loads(s) for s in (ROOT/'provenance/phase16_source_inventory.jsonl').read_text().splitlines()]
    assert len(added16)==update16['new_inventory_entries']
    assert sum(e['disposition']=='included' for e in added16)==update16['new_included_files']
    assert sum(e['disposition']=='referenced_only' for e in added16)==update16['new_referenced_files']
    for e in added16:
        if e['disposition']=='included':
            p=ROOT/e['repository_path']
            assert sha(p)==e['sha256'] and p.stat().st_size==e['bytes'],e['source_path']
    phase16=ROOT/'work/phase16_crypto'
    manifest16=json.loads((phase16/'manifest.json').read_text())
    evaluation16=json.loads((phase16/'evaluation.json').read_text())
    guard16=json.loads((phase16/'no_truth_verification.json').read_text())
    assert manifest16['completed'] and manifest16['status']=='completed'
    assert len(manifest16['runs'])==20 and manifest16['main_exact_calls']==732572
    assert manifest16['positive_exact_calls']==66600 and manifest16['total_exact_calls']==799172
    assert evaluation16['manifest_sha256']==guard16['manifest_sha256']==sha(phase16/'manifest.json')
    assert guard16['status']=='passed' and guard16['total_known_phase16_IDP_calls']==update16['known_total_IDP_calls']==799212
    assert evaluation16['totals']['distinct_planted_keypairs']==4
    hits16=Counter()
    for p in evaluation16['profiles']:
        if p['category']=='main':
            assert p['privileged'] and not p['unknown_key_recovery_test']
            hits16[p['policy']]+=int(p['final_numeric_is_target'])
    assert dict(hits16)=={'A':6,'B':8}
    update17=json.loads((ROOT/'provenance/phase17_update.json').read_text())
    added17=[json.loads(s) for s in (ROOT/'provenance/phase17_source_inventory.jsonl').read_text().splitlines()]
    assert len(added17)==update17['new_inventory_entries']
    assert sum(e['disposition']=='included' for e in added17)==update17['new_included_files']
    assert sum(e['disposition']=='referenced_only' for e in added17)==update17['new_referenced_files']
    for e in added17:
        if e['disposition']=='included':
            p=ROOT/e['repository_path']
            assert sha(p)==e['sha256'] and p.stat().st_size==e['bytes'],e['source_path']
    phase17=ROOT/'work/phase17_records'
    analysis17=json.loads((phase17/'analysis.json').read_text())
    receipt17=json.loads((phase17/'run_receipt.json').read_text())
    approval17=json.loads((phase17/'audit_approval.json').read_text())
    audit17=json.loads((ROOT/'work/phase17_review/post_ejecucion_independiente.json').read_text())
    assert approval17['root_approved'] and approval17['independent_approved']
    assert analysis17['posthoc_outcome_selection'] and analysis17['CSV_rows_checked']==183143
    assert receipt17['outputs']['analysis.json']==sha(phase17/'analysis.json')
    assert receipt17['outputs']['comparison.csv']==sha(phase17/'comparison.csv')
    assert audit17['status']=='passed' and audit17['rows_replayed']==183143
    assert audit17['analysis_sha256']==sha(phase17/'analysis.json')
    for field in ('new_IDP_calls','new_truth_score_evaluations','new_solver_trajectories','new_searches'):
        assert analysis17[field]==receipt17[field]==0
    assert update17['new_IDP_calls']==update17['new_solver_trajectories']==0
    print(json.dumps({'status':'passed','hashed_repository_files':len(checksums),
        'original_inventory_entries':len(entries),'canonical_ciphertexts':'match',
        'phase11_rows':len(runs),'phase11_archive_recoveries':dict(hits),
        'phase14_rows':len(runs14),'phase14_archive_recoveries':dict(hits14),
        'phase15_static_profiles':len(manifest15['runs']),
        'phase15_recorded_principal_backend_calls':399600,
        'phase16_main_privileged_trajectories':16,
        'phase16_main_exact_K2_recoveries':dict(hits16),
        'phase16_recorded_total_IDP_calls':799212,
        'phase17_existing_CSV_rows':183143,
        'phase17_selected_saved_paths':4,
        'phase17_new_IDP_calls':0,
        'new_searches':0,'scope':'selected export integrity and recorded recovery counts'},indent=2))

if __name__=='__main__': main()

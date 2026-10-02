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
    print(json.dumps({'status':'passed','hashed_repository_files':len(checksums),
        'original_inventory_entries':len(entries),'canonical_ciphertexts':'match',
        'phase11_rows':len(runs),'phase11_archive_recoveries':dict(hits),
        'phase14_rows':len(runs14),'phase14_archive_recoveries':dict(hits14),
        'new_searches':0,'scope':'selected export integrity and recorded recovery counts'},indent=2))

if __name__=='__main__': main()

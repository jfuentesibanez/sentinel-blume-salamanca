#!/usr/bin/env python3
"""Summarize frozen authoritative controls, verifying source version hashes."""
import collections, hashlib, json, pathlib, platform, subprocess, sys

HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parents[1]
names=[
    'oracle_prose_20261101_25',
    'oracle_proxy_20261101_25',
    'oracle_prose_20261131_5_negative',
    'full_prose_20261011_5',
    'full_proxy_20261011_3',
    'full_prose_20261081_3_negative',
]
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def describe(rows):
    return {
        'searches':len(rows),
        'exact_k1':sum(d['exact_k1'] for d in rows),
        'exact_k2':sum(d['exact_k2'] for d in rows),
        'exact_both_plaintexts_775':sum(d['exact_both_plaintexts'] for d in rows),
        'budget_expired':sum(d['budget_expired'] for d in rows),
        'reencryption_consistent':sum(d['reencryption_consistency'] for d in rows),
        'internal_seconds_sum':sum(d['seconds'] for d in rows),
        'feature_evals_sum':sum(d['feature_evals'] for d in rows),
        'q_evals_sum':sum(d['q_evals'] for d in rows),
        'idp_evals_sum':sum(d['idp_evals'] for d in rows),
        'q4_min':min(d['q4'] for d in rows),
        'q4_max':max(d['q4'] for d in rows),
        'truth_q4_min':min(d['truth_q4'] for d in rows),
        'truth_q4_max':max(d['truth_q4'] for d in rows),
        'truth_idp_above_selected_stage_k2':sum(d['true_k2_idp']>d['stage_k2_idp']+1e-9 for d in rows) if rows[0]['mode']=='full' else None,
    }
rows=[]; manifests=[]
for name in names:
    data=HERE/(name+'.jsonl'); manifest_path=HERE/(name+'_manifest.json')
    part=[json.loads(s) for s in data.read_text().splitlines()]
    manifest=json.loads(manifest_path.read_text())
    original_main=ROOT/'work/phase3_crypto/phase3.cpp'
    main_source=HERE/('phase3.cpp' if part[0]['mode']=='oracle' else 'phase3_full_validated.cpp')
    # Never rewrite the original manifests. Their old path resolves to the
    # snapshot if CLI oracle/metadata changed after the full-control run.
    for rel,value in manifest['sha256'].items():
        if rel.endswith('/phase3'): continue # recorded Mac binary not needed
        p=main_source if rel==str(original_main.relative_to(ROOT)) else ROOT/rel
        if sha(p)!=value: raise ValueError(f'hash mismatch: {name} {rel}')
    rows+=part
    manifests.append({'file':manifest_path.name,'sha256':sha(manifest_path),'data_file':data.name,'data_sha256':sha(data),'main_source_snapshot':main_source.name,'main_source_sha256':sha(main_source),'process_timeout_seconds':manifest.get('process_timeout_seconds',35),'wall_seconds':manifest['wall_seconds'],'records':len(part),'completed':True})

groups=collections.defaultdict(list)
for d in rows:
    groups[d['mode'],d['negative'],d['corpus'],d['w1'],d['w2'],d['messages_scored']].append(d)
group_rows=[]
for (mode,negative,corpus,w1,w2,messages),part in sorted(groups.items()):
    group_rows.append({'mode':mode,'negative':negative,'corpus':corpus,'w1':w1,'w2':w2,'messages_scored':messages,'seeds':sorted(d['plant_seed'] for d in part),'final_ngram':3,**describe(part)})
totals=[]
for mode in ('oracle','full'):
    for negative in (False,True):
        for messages in (1,2):
            part=[d for d in rows if d['mode']==mode and d['negative']==negative and d['messages_scored']==messages]
            totals.append({'mode':mode,'negative':negative,'messages_scored':messages,**describe(part)})

source_files=['ict_search.h','phase3.cpp','phase3_full_validated.cpp','run_controls.py','summarize.py','METHOD.txt','README.txt','geometry_check.json']
summary={
    'date':'2026-10-01','status':'bounded synthetic calibration completed; no historical attack',
    'historical_ciphertexts_used':False,'known_widths':[[12,15],[20,25]],'lengths':[615,160],'convention':0,'final_ngram':3,
    'control_pair_counts':{'oracle_positive':100,'oracle_negative':10,'full_positive':16,'full_negative':6},
    'search_counts':{'oracle_positive':200,'oracle_negative':20,'full_positive':32,'full_negative':12},
    'oracle_truth_access':'synthetic K2 is disclosed explicitly; K1 and plaintext are not solver inputs',
    'full_truth_access':'no key or plaintext truth enters solve_phase3; truth is used only outside for metrics',
    'full_version_note':'phase3_full_validated.cpp matches original full manifests; final main only changes oracle final_ngram/RNG salt and printed final_ngram; full branch is identical',
    'pilot_note':'full is exploratory with some seeds previously observed during development; no confirmatory success-rate claim',
    'sampling_dependence':'same seeds across corpora share planted keys; holdout windows may overlap; single/joint are paired',
    'machine':{'system':platform.platform(),'machine':platform.machine(),'python':sys.version,'compiler':subprocess.check_output(['c++','--version'],text=True).splitlines()[0]},
    'code_sha256':{name:sha(HERE/name) for name in source_files},
    'dependency_sha256':{str(p.relative_to(ROOT)):sha(p) for p in (ROOT/'work/crypto/double_search.cpp',ROOT/'work/crypto/model_es.bin',ROOT/'work/crypto/holdout_es.txt',ROOT/'work/crypto/holdout_proxy.txt',ROOT/'work/crypto/model_provenance.json')},
    'manifests':manifests,'groups':group_rows,'totals':totals,
    'limit_note':'noninterruptible precompute and initial/fallback/selection scores are outside evaluation count; internal seconds excludes q3 round selection; process wall time is in manifests',
    'replication_limitations':['custom increasing thresholds','strict lexicographic plateau guard differs from source','3-partite whole-key variant is not defined by consulted source','greedy IDP forced diagonal floor inherited from baseline','Spanish literary holdout and function-word proxy are not historical telegrams'],
    'decision':'K1 conditional stage is calibrated on these data; K2 pilot remains insufficient for a long historical search; no key region excluded',
}
(HERE/'summary.json').write_text(json.dumps(summary,indent=2,ensure_ascii=False)+'\n')
print(json.dumps({'totals':totals,'manifest_hashes_verified':True},indent=2))

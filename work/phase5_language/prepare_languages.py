"""Prepare language controls, never train on historical ciphertexts.

Adds German/French n-gram models to the earlier Spanish model. The optional
unigram comparison is descriptive, conditional on pure letter permutation.
"""
from pathlib import Path
from collections import Counter
import hashlib, json, math, re, statistics, struct, unicodedata

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent.parent

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def normalize(text, digraph=False):
    text=text.lower().replace('ß','ss').replace('œ','oe').replace('æ','ae')
    if digraph:
        for a,b in [('ä','ae'),('ö','oe'),('ü','ue')]:text=text.replace(a,b)
    return ''.join(c for c in unicodedata.normalize('NFKD',text) if 'a'<=c<='z')

def body(source, opening=None):
    raw=source.read_text(encoding='utf-8-sig')
    start=re.search(r'\*\*\* START OF (?:THE|THIS) PROJECT GUTENBERG EBOOK[^\n]*\n',raw)
    end=re.search(r'\*\*\* END OF (?:THE|THIS) PROJECT GUTENBERG EBOOK',raw)
    if not start or not end:raise ValueError('Gutenberg boundaries missing')
    first=start.end()
    if opening:
        first=raw.index(opening,first)
        if first>=end.start():raise ValueError('Opening beyond end')
    return raw[first:end.start()],{'body_start_unicode_offset':first,'body_end_unicode_offset':end.start(),'opening_anchor':opening}

def model(train,path):
    with path.open('wb') as f:
        for n in (2,3,4):
            cnt=Counter(train[i:i+n] for i in range(len(train)-n+1))
            size=26**n;values=[0]*size
            for word,value in cnt.items():
                k=0
                for c in word:k=k*26+ord(c)-97
                values[k]=value
            total=sum(values)+.01*size
            f.write(struct.pack('<%df'%size,*[math.log10((x+.01)/total) for x in values]))

specs=[
    ('de_fold','22367','Die Verwandlung','Franz Kafka','Als Gregor Samsa eines Morgens',False),
    ('de_digraph','22367','Die Verwandlung','Franz Kafka','Als Gregor Samsa eines Morgens',True),
    ('fr_fold','4650',"Candide, ou l’optimisme",'Voltaire','Il y avait en Vestphalie,',False),
]
datasets={};provenance=[]
for code,num,title,author,opening,digraph in specs:
    source=HERE/f'pg{num}.txt';text,bounds=body(source,opening)
    cut=int(.8*len(text));train=normalize(text[:cut],digraph);holdout=normalize(text[cut:],digraph)
    folder=HERE/code;folder.mkdir(exist_ok=True)
    (folder/'holdout.txt').write_text(holdout)
    model(train,folder/'model.bin')
    datasets[code]=(train,holdout)
    record={'code':code,'source_url':f'https://www.gutenberg.org/cache/epub/{num}/pg{num}.txt','catalogue_url':f'https://www.gutenberg.org/ebooks/{num}','title':title,'author':author,'retrieved_date':'2026-10-01','source_sha256':sha(source),**bounds,'training':'first80% of narrative by Unicode characters; excludes Gutenberg wrapper and preceding title/publisher/editor preface','controls':'remaining20% of narrative; training and holdout do not overlap','normalization':'lowercase; ß→ss, œ→oe, æ→ae; '+('ä→ae, ö→oe, ü→ue; ' if digraph else '')+'NFKD; retain a-z; no whitespace','train_letters':len(train),'holdout_letters':len(holdout),'model_format':'orders2,3,4; complete26^n little-endian float32 log10 probabilities; .01 pseudocount per entry','model_sha256':sha(folder/'model.bin'),'holdout_sha256':sha(folder/'holdout.txt'),'corpus_limit':'One literary work, not an authentic1937 commercial-telegram corpus; punctuation and numeric material dropped; editorial inline notes remain.'}
    (folder/'provenance.json').write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n');provenance.append(record)

# Reuse frozen Spanish corpus and model without modifying them.
text,bounds=body(ROOT/'work/crypto/pg2000.txt')
cut=int(.8*len(text));datasets['es_frozen']=(normalize(text[:cut]),normalize(text[cut:]))
assert datasets['es_frozen'][1]==(ROOT/'work/crypto/holdout_es.txt').read_text()
spanish_meta=json.loads((ROOT/'work/crypto/model_provenance.json').read_text())
assert sha(ROOT/'work/crypto/model_es.bin')==spanish_meta['model_sha256']

size=min(len(x[0]) for x in datasets.values())
targets={p.name:normalize(p.read_text()) for p in (ROOT/'work/source/ct1.txt',ROOT/'work/source/ct2.txt')}
assert len(targets['ct1.txt'])==615 and len(targets['ct2.txt'])==160
targets['pair_concatenated']=targets['ct1.txt']+targets['ct2.txt']
ALPHABET='abcdefghijklmnopqrstuvwxyz'

def score(text,probs):
    counts=Counter(text)
    return {'logp_per_letter':sum(counts[c]*math.log(probs[c]) for c in ALPHABET)/len(text),'chi2':sum((counts[c]-len(text)*probs[c])**2/(len(text)*probs[c]) for c in ALPHABET),'w_count':counts['w']}

comparisons=[]
for code,(train,holdout) in datasets.items():
    counts=Counter(train[:size]);probs={c:(counts[c]+.5)/(size+13) for c in ALPHABET}
    row={'code':code,'training_letters_for_unigrams':size,'training_counts':{c:counts[c] for c in ALPHABET},'targets':{},'heldout_windows':{}}
    for target,text in targets.items():
        observed=score(text,probs);row['targets'][target]=observed
        n=len(text);windows=[score(holdout[i:i+n],probs) for i in range(0,len(holdout)-n+1,n)]
        assert windows
        values=sorted(x['chi2'] for x in windows)
        row['heldout_windows'][target]={'window_length':n,'nonoverlapping_windows':len(windows),'chi2_min':min(values),'chi2_median':statistics.median(values),'chi2_max':max(values),'chi2_empirical_fraction_at_least_target':sum(x>=observed['chi2'] for x in values)/len(values),'w_zero_windows':sum(x['w_count']==0 for x in windows),'w_min':min(x['w_count'] for x in windows),'w_max':max(x['w_count'] for x in windows),'sampling':'All non-overlapping windows in heldout final20%; adjacent windows/topic are still dependent.'}
    comparisons.append(row)

result={'date':'2026-10-01','diagnostic':'Unigram inventories only; no ciphertext order or plaintext candidate is scored. Conditional on pure permutation and documented normalization.','training_letters_balanced':size,'target_sha256':{p.name:sha(p) for p in (ROOT/'work/source/ct1.txt',ROOT/'work/source/ct2.txt')},'target_counts':{k:{c:Counter(v)[c] for c in ALPHABET} for k,v in targets.items()},'new_model_provenance':provenance,'spanish_frozen_provenance':spanish_meta,'comparisons':comparisons,'qualifications':['Does not prove transposition, plaintext language, key sharing or absence of padding/substitution.','A single literary work per new language introduces topic/author/period differences. Orthography is a tested modeling choice, not an attested1937 encryption convention.','These frequencies and window fractions are descriptive and are not posterior language probabilities or independent significance tests.','The May1938 Victor telegram is a separate authentic style example; it is neither training text nor known plaintext for January1937.','Earlier modern UD unigram comparison is preserved in work/final_language_comparison.json; this adds n-gram controls and a different sensitivity sample, not a new independent solution.'],'historical_attack_run':False}
(HERE/'language_diagnostic.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'new_models':[{'code':x['code'],'train_letters':x['train_letters'],'holdout_letters':x['holdout_letters']} for x in provenance],'balanced_unigram_letters':size,'rankings_by_logp':{target:[(x['code'],round(x['targets'][target]['logp_per_letter'],4)) for x in sorted(comparisons,key=lambda x:x['targets'][target]['logp_per_letter'],reverse=True)] for target in targets}},ensure_ascii=False))

#!/usr/bin/env python3
"""Prepare independently held-out Spanish controls; never train on targets."""
import collections, hashlib, json, math, pathlib, re, struct, unicodedata
ROOT = pathlib.Path(__file__).resolve().parent
raw = (ROOT / 'pg2000.txt').read_text(encoding='utf-8-sig')
start = re.search(r'\*\*\* START OF (?:THE|THIS) PROJECT GUTENBERG EBOOK[^\n]*\n', raw)
end = re.search(r'\*\*\* END OF (?:THE|THIS) PROJECT GUTENBERG EBOOK', raw)
if not start or not end:
    raise ValueError('Cannot identify Gutenberg body boundaries')
body = raw[start.end():end.start()]
cut = int(len(body) * .8)
train_raw, holdout_raw = body[:cut], body[cut:]
def norm(s):
    return ''.join(c for c in unicodedata.normalize('NFKD', s.lower()) if 'a' <= c <= 'z')
train, holdout = norm(train_raw), norm(holdout_raw)
# This proxy only removes common function words. It is neither an authentic
# telegram corpus nor an asserted model of these historic plaintexts.
stop = {'el','la','los','las','un','una','unos','unas','de','del','que','y','en','a','al','por','para','con'}
tele = norm(' '.join(w for w in re.findall(r'\b\w+\b', holdout_raw.lower()) if w not in stop))
(ROOT/'holdout_es.txt').write_text(holdout)
(ROOT/'holdout_proxy.txt').write_text(tele)
with (ROOT/'model_es.bin').open('wb') as f:
    for n in (2,3,4):
        cnt = collections.Counter(train[i:i+n] for i in range(len(train)-n+1))
        size = 26**n
        vals = [0] * size
        for word, count in cnt.items():
            k=0
            for c in word: k=k*26+ord(c)-97
            vals[k]=count
        alpha = .01
        total = sum(vals)+alpha*size
        f.write(struct.pack('<%df'%size, *[math.log10((v+alpha)/total) for v in vals]))
meta = {'source_url':'https://www.gutenberg.org/cache/epub/2000/pg2000.txt',
        'title':'Don Quijote de la Mancha','author':'Miguel de Cervantes Saavedra',
        'retrieved_date':'2026-10-01','source_sha256':hashlib.sha256((ROOT/'pg2000.txt').read_bytes()).hexdigest(),
        'training':'first 80% of body by Unicode character; strips Gutenberg wrapper',
        'controls':'final 20% of body; disjoint from training; prose and function-word deletion proxy',
        'normalization':'NFKD, lowercase, retain a-z only; accents stripped, ñ→n; no whitespace',
        'smoothing':'.01 count pseudocount per 26^n entry; log10 probability; orders 2,3,4',
        'train_letters':len(train),'holdout_letters':len(holdout),'proxy_letters':len(tele),
        'model_sha256':hashlib.sha256((ROOT/'model_es.bin').read_bytes()).hexdigest()}
(ROOT/'model_provenance.json').write_text(json.dumps(meta,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(meta,ensure_ascii=False))

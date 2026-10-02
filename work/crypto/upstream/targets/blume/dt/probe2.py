import struct, math, random, sys
import numpy as np
q=np.frombuffer(open('../q4_es.bin','rb').read(),dtype=np.float32)
cnt=(10.0**q.astype(np.float64)).reshape(676,676).sum(axis=1); cnt/=cnt.sum()
import sys
CLIP=float(sys.argv[3])
B2=np.round(1000*np.maximum(np.log10(np.maximum(cnt,1e-7)),CLIP)).astype(np.int64).reshape(26,26)
def colmap(n,order,w):
    rows,rem=divmod(n,w); m=[0]*n; pos=0
    for k in range(w):
        c=order[k]; L=rows+(1 if c<rem else 0)
        for r in range(L): m[r*w+c]=pos; pos+=1
    return m
def enc(pt,order,w):
    m=colmap(len(pt),order,w); ct=[0]*len(pt)
    for i,p in enumerate(pt): ct[m[i]]=p
    return ct
def undo(ct,order,w):
    m=colmap(len(ct),order,w); return [ct[m[i]] for i in range(len(ct))]
TOL=2
def idp(I,w1):
    n=len(I); rows,rem=divmod(n,w1); I=np.array(I)
    rng=[]
    for k in range(w1):
        e=k*rem/w1; lo=max(0,k-(w1-rem)); hi=min(k,rem)
        rng.append((max(lo,int(round(e))-TOL),min(hi,int(round(e))+TOL)))
    tot=0
    for k1 in range(w1):
        best=-10**9; a1,b1=rng[k1]
        for k2 in range(w1):
            if k2==k1: continue
            a2,b2=rng[k2]
            for u1 in range(a1,b1+1):
                s1=k1*rows+u1
                for u2 in range(a2,b2+1):
                    s2=k2*rows+u2
                    s=B2[I[s1:s1+rows],I[s2:s2+rows]].sum()
                    if s>best: best=s
        tot+=best
    return tot/(1000.0*w1*rows)
# C# RandPerm replica needs .NET Random; instead plant our own
txt=open('plain_es.txt').read().lower(); txt=''.join(ch for ch in txt if 'a'<=ch<='z')
pt=[ord(c)-97 for c in txt[5000:5615]]; n=615
random.seed(3)
w1,w2=int(sys.argv[1]),int(sys.argv[2])
k1=list(range(w1)); random.shuffle(k1); k2=list(range(w2)); random.shuffle(k2)
ct=enc(enc(pt,k1,w1),k2,w2)
I=undo(ct,k2,w2); print('true',round(idp(I,w1),4))
rows2,rem2=divmod(n,w2)
for nsw in [1,2,3,5,8,12]:
    vals=[]
    for t in range(6):
        k=k2[:]
        for _ in range(nsw):
            a,b=random.sample(range(w2),2); k[a],k[b]=k[b],k[a]
        vals.append(idp(undo(ct,k,w2),w1))
    print(nsw,'swaps: mean %.4f  min %.4f max %.4f'%(sum(vals)/6,min(vals),max(vals)))


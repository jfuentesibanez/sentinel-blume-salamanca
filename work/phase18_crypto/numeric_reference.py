"""Independent direct offset enumeration; only recorded initial/last proposals.

Adapted from phase16_root/post_run_audit.py. Caller charges BEFORE score.
No search, target comparison, plaintext, RNG or truth access.
"""
import struct
def load_table(path):
 data=path.read_bytes();values=struct.unpack('<'+str(len(data)//4)+'f',data)
 # ict Model stores 676 binary32 bigram weights first, then optional data.
 assert len(values)>=676
 weights=values[:676];ratios=[v.as_integer_ratio()for v in weights];scale=max(b for a,b in ratios)
 return [a*(scale//b)for a,b in ratios],scale
def undo(cipher,key):
 rows,rem=divmod(len(cipher),len(key));out=[None]*len(cipher);cursor=0
 for col in sorted(range(len(key)),key=key.__getitem__):
  for row in range(rows+(col<rem)):out[row*len(key)+col]=cipher[cursor];cursor+=1
 assert cursor==len(cipher)and None not in out;return out
def matrix(text,width,table,scale,guard):
 rows,rem=divmod(len(text),width);offsets=[range(max(0,c-(width-rem)),min(c,rem)+1)for c in range(width)];m=[-1000000*scale]*(width*width)
 for a in range(width):
  guard()
  for b in range(width):
   if a!=b:m[a*width+b]=max(sum(table[text[a*rows+x+r]*26+text[b*rows+y+r]]for r in range(rows))for x in offsets[a]for y in offsets[b])
 return m
def score(ciphertexts,key,table,scale,guard=lambda:None):
 mats=[matrix(undo(t,key),20,table,scale,guard)for t in ciphertexts];m=[sum(x[i]for x in mats)for i in range(400)];rows=sum(len(c)//20 for c in ciphertexts)
 used_a=set();used_b=set();total=0
 for _ in range(20):
  best=x=y=None
  for a in range(20):
   if a in used_a:continue
   for b in range(20):
    if b in used_b or a==b:continue
    if best is None or m[a*20+b]>best:best,x,y=m[a*20+b],a,b
  if x is None:x=next(a for a in range(20)if a not in used_a);y=next(b for b in range(20)if b not in used_b);best=-7*rows*scale
  total+=best;used_a.add(x);used_b.add(y)
 return total

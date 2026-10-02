import hashlib,json,pathlib,subprocess
HERE=pathlib.Path(__file__).resolve().parent

def literal_source(width):
    # Simulate constructor inversion AND transform assignment from original C#.
    identity=list(range(width)); result=set()
    def add(temp):
        mapping=[0]*width
        for i,x in enumerate(temp): mapping[x]=i
        candidate=[None]*width
        for i in range(width): candidate[mapping[i]]=identity[i]
        result.add(tuple(candidate))
    for length in range(width,0,-1):
        for shift in range(1,width):
            for start in range(width):
                temp=identity.copy(); affected=length+shift
                if affected<=width:
                    for i in range(affected): temp[(start+(i+shift)%affected)%width]=identity[(start+i)%width]
                add(temp)
    for shift in range(width): add(identity[width-shift:]+identity[:width-shift])
    for length in range(width//4,0,-1):
        for p1 in range(width):
            for p2 in range(p1+length,width-length):
                temp=identity.copy();temp[p2:p2+length]=identity[p1:p1+length];temp[p1:p1+length]=identity[p2:p2+length];add(temp)
    for length in range(1,4):
        for p1 in range(width-3*length):
            for p2 in range(p1+length,width-2*length):
                for p3 in range(p2+length,width-length):
                    temp=identity.copy();temp[p2:p2+length]=identity[p1:p1+length];temp[p3:p3+length]=identity[p2:p2+length];temp[p1:p1+length]=identity[p3:p3+length];add(temp)
                    temp=identity.copy();temp[p3:p3+length]=identity[p1:p1+length];temp[p1:p1+length]=identity[p2:p2+length];temp[p2:p2+length]=identity[p3:p3+length];add(temp)
    for p1 in range(width):
        for p2 in range(width):
            for p3 in range(width):
                if len({p1,p2,p3})<3: continue
                temp=identity.copy();temp[p1]=identity[p2];temp[p2]=identity[p3];temp[p3]=identity[p1];add(temp)
    return result

proc=subprocess.run([str(HERE/'geometry')],check=True,text=True,capture_output=True)
checks=[]
for line in proc.stdout.splitlines():
    row=json.loads(line); reference=literal_source(row['width']); actual={tuple(x) for x in row.pop('permutations')}
    if actual!=reference: raise AssertionError((row['width'],len(actual-reference),len(reference-actual)))
    serialized=json.dumps(sorted(actual),separators=(',',':')).encode()
    row.update(reference_count=len(reference),exact_set_match=True,phase3_moves_missing_from_source=row['phase3_moves']-(len(reference)-row['identity_count']-row['source_moves_missing_from_phase3']),neighbourhood_sha256=hashlib.sha256(serialized).hexdigest())
    checks.append(row)
result={'reference':'Literal independently written Python simulation of CrypTool constructor inversion followed by transform assignment','widths_tested':list(range(3,26)),'passed':True,'checks':checks}
(HERE/'geometry_check.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))

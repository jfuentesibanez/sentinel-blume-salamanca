"""Supplemental6-IDP state fixture, without truth or historical ciphertexts."""
from pathlib import Path
import hashlib,json,subprocess,time
HERE=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    if (HERE/'last_score_results.json').exists():raise SystemExit('Refusing to overwrite fixture results')
    source=HERE/'last_score_fixture.cpp';binary=HERE/'last_score_fixture'
    command=['/usr/bin/clang++','-std=c++17','-O3',str(source),'-o',str(binary)]
    began=time.monotonic();subprocess.run(command,check=True);build_seconds=time.monotonic()-began
    records=[]
    with (HERE/'last_score_outputs.jsonl').open('x') as output:
        for mode in ('cap','checkpoint','global'):
            began=time.monotonic();proc=subprocess.run([str(binary),mode,str(HERE/'invariant_inputs/uniform_model.bin')],capture_output=True,text=True,check=True,timeout=10)
            row=json.loads(proc.stdout);row.update(fixture=mode,process_seconds=time.monotonic()-began)
            output.write(json.dumps(row,separators=(',',':'))+'\n');records.append({'fixture':mode,'objective_calls':row['objective_calls'],'process_seconds':row['process_seconds']})
    result={'status':'passed','controls':3,'objective_calls':sum(x['objective_calls'] for x in records),'truth_used':False,'main_searches':0,
        'fixture':'Uniform model and artificially lowered incumbent score verify last-proposal state update, not recovery or IDP validity',
        'source_sha256':sha(source),'binary_sha256':sha(binary),'outputs_sha256':sha(HERE/'last_score_outputs.jsonl'),'build_seconds':build_seconds,'costs':records}
    (HERE/'last_score_results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()

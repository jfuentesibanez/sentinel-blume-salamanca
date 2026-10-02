"""Build new local binaries; never overwrite frozen sources/results or run a search."""
from pathlib import Path
import hashlib
import json
import os
import shlex
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]
def main():
    compiler=shlex.split(os.environ.get('CXX','c++'))
    if not compiler or not shutil.which(compiler[0]):
        raise SystemExit('A C++17 compiler is required; set CXX or install one.')
    out=ROOT/'.repro/bin';out.mkdir(parents=True,exist_ok=True)
    targets={
        'phase10_population':ROOT/'work/phase10_crypto/population_search.cpp',
        'phase11_cap5000':ROOT/'work/phase11_crypto/capped_population_search.cpp',
        'phase14_checkpoint':ROOT/'work/phase14_crypto/checkpoint_population_search.cpp',
        'phase15_static_landscape':ROOT/'work/phase15_crypto/static_landscape.cpp',
        'phase7_regenerate_keys':ROOT/'work/phase7_crypto/regenerate_planted_keys.cpp',
    }
    records=[]
    for name,source in targets.items():
        destination=out/name
        command=compiler+['-std=c++17','-O3',str(source),'-o',str(destination)]
        subprocess.run(command,check=True)
        records.append({'source':str(source.relative_to(ROOT)),
            'new_binary':str(destination.relative_to(ROOT)),
            'sha256':hashlib.sha256(destination.read_bytes()).hexdigest(),'command':command})
    record={'new_searches':0,'replaced_frozen_files':0,'builds':records}
    (ROOT/'.repro/build_record.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))

if __name__=='__main__': main()

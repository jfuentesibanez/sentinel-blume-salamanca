"""Build static diagnosis and external planting helper; no truth or IDP."""
from pathlib import Path
import hashlib,json,subprocess,time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent.parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    if (HERE/'sealed_design.json').exists():raise SystemExit('Sealed design: no rebuild')
    helper=ROOT/'work/phase7_crypto/regenerate_planted_keys.cpp'
    (HERE/'generate_keys.cpp').write_bytes(helper.read_bytes())
    start=time.monotonic();commands=[]
    for source,binary in [('static_landscape.cpp','static_landscape'),('generate_keys.cpp','generate_keys')]:
        command=['/usr/bin/clang++','-std=c++17','-O3',str(HERE/source),'-o',str(HERE/binary)]
        subprocess.run(command,check=True);commands.append(command)
    macros=subprocess.check_output(['/usr/bin/clang++','-std=c++17','-dM','-E','-x','c++','-'],input='#include <random>\n',text=True)
    deps=['work/crypto/double_search.cpp','work/phase3_crypto/ict_search.h','work/phase4_crypto/source_moves.h']
    value={'compiler_commands':commands,'compiler_version':subprocess.check_output(['/usr/bin/clang++','--version'],text=True),
        'standard_library_macros':[line for line in macros.splitlines() if line.startswith(('#define _LIBCPP_VERSION ','#define __GLIBCXX__ '))],
        'source_sha256':sha(HERE/'static_landscape.cpp'),'binary_sha256':sha(HERE/'static_landscape'),
        'helper_source_sha256':sha(HERE/'generate_keys.cpp'),'helper_binary_sha256':sha(HERE/'generate_keys'),
        'helper_frozen_original_sha256':sha(helper),'frozen_dependencies':{p:sha(ROOT/p) for p in deps},
        'seconds':time.monotonic()-start,'idp_calls':0,'truth_generated':False}
    (HERE/'build_record.json').write_text(json.dumps(value,indent=2)+'\n')
    print(json.dumps(value,indent=2))
if __name__=='__main__':main()

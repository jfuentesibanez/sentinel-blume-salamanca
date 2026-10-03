"""Copy only the frozen exact scorer and key helper, then build; never run truth."""
from pathlib import Path
import hashlib,json,subprocess,time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent.parent
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    if (HERE/'sealed_design.json').exists():raise SystemExit('No rebuild of sealed phase16')
    frozen=ROOT/'work/phase15_crypto/static_landscape.cpp'
    assert sha(frozen)=='4552eafdc98cc4e3d075ed8b092945510d4eb1ff67a31dfa1e30e8662f85ed4a'
    body=frozen.read_text();sections=[body[body.index('struct Dyadic '):body.index('struct Legacy ')],
        body[body.index('struct Exact '):body.index('Legacy legacy_trace')],
        body[body.index('std::vector<int64_t> exact_matrix'):body.index('void validate(')]]
    (HERE/'exact_scorer.h').write_text('#pragma once\n// Exact phase15 fragments, unchanged. See build_record.json and attribution.\n'+''.join(sections))
    helper=ROOT/'work/phase15_crypto/generate_keys.cpp';(HERE/'generate_keys.cpp').write_bytes(helper.read_bytes())
    (HERE/'moves.json').write_bytes((ROOT/'work/phase15_crypto/moves.json').read_bytes())
    (HERE/'LICENSE-CrypTool-2.txt').write_bytes((ROOT/'work/phase15_crypto/LICENSE-CrypTool-2.txt').read_bytes())
    started=time.monotonic();commands=[]
    for source,binary in (('trajectory.cpp','trajectory'),('generate_keys.cpp','generate_keys')):
        command=['/usr/bin/clang++','-std=c++17','-O3',str(HERE/source),'-o',str(HERE/binary)];subprocess.run(command,check=True);commands.append(command)
    macros=subprocess.check_output(['/usr/bin/clang++','-std=c++17','-dM','-E','-x','c++','-'],input='#include <random>\n',text=True)
    result={'source_sha256':sha(HERE/'trajectory.cpp'),'binary_sha256':sha(HERE/'trajectory'),'exact_header_sha256':sha(HERE/'exact_scorer.h'),
        'frozen_exact_source_sha256':sha(frozen),'exact_fragments_sha256':[hashlib.sha256(s.encode()).hexdigest() for s in sections],
        'helper_source_sha256':sha(HERE/'generate_keys.cpp'),'helper_binary_sha256':sha(HERE/'generate_keys'),
        'frozen_dependencies':{str(p.relative_to(ROOT)):sha(p) for p in (ROOT/'work/crypto/double_search.cpp',ROOT/'work/phase3_crypto/ict_search.h',ROOT/'work/phase4_crypto/source_moves.h')},
        'compiler_commands':commands,'compiler_version':subprocess.check_output(['/usr/bin/clang++','--version'],text=True),
        'standard_library_macros':[line for line in macros.splitlines() if line.startswith(('#define _LIBCPP_VERSION ','#define __GLIBCXX__ '))],
        'seconds':time.monotonic()-started,'new_IDP_calls':0,'truth_generated':False,'main_trajectories':0}
    (HERE/'build_record.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()

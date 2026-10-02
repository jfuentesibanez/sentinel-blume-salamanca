"""Build phase14 from an exact frozen prefix; never run searches."""
from pathlib import Path
import hashlib,json,subprocess,time
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent.parent
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    source=ROOT/'work/phase10_crypto/population_search.cpp'
    assert sha(source)=='0cc750150629d24391b333541b6d76f3edc2db1735d8a17bb8b2567900a4eaec'
    frozen=ROOT/'work/phase11_crypto/phase10_frozen_classes.h'
    body=source.read_bytes();marker=b'int main(int argc,char**argv)'
    assert body.count(marker)==1
    prefix=body[:body.index(marker)]
    assert frozen.read_bytes()==prefix
    (HERE/'phase10_frozen_classes.h').write_bytes(prefix)
    command=['/usr/bin/clang++','-std=c++17','-O3',str(HERE/'checkpoint_population_search.cpp'),'-o',str(HERE/'checkpoint_population_search')]
    began=time.monotonic();subprocess.run(command,check=True)
    compiler=subprocess.check_output(['/usr/bin/clang++','--version'],text=True)
    # Query the exact compiler's header macros without evaluating any objective.
    macros=subprocess.check_output(['/usr/bin/clang++','-std=c++17','-dM','-E','-x','c++','-'],input='#include <random>\n',text=True)
    stdlib=[line for line in macros.splitlines() if line.startswith(('#define _LIBCPP_VERSION ','#define __GLIBCXX__ '))]
    record={'source_base_path':str(source.relative_to(ROOT)),'source_base_sha256':sha(source),
            'exact_prefix_sha256':sha(HERE/'phase10_frozen_classes.h'),'exact_prefix_bytes':len(prefix),
            'compiler_command':command,'compiler_version':compiler,'standard_library_macros':stdlib,
            'rng':'std::mt19937_64; uint64_t seed; inherited std::shuffle and distributions',
            'source_sha256':sha(HERE/'checkpoint_population_search.cpp'),'sha256_helper_sha256':sha(HERE/'sha256.h'),
            'solver_sha256':sha(HERE/'checkpoint_population_search'),'build_seconds':time.monotonic()-began,
            'new_objective_calls':0,'main_searches':0}
    (HERE/'build_record.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))
if __name__=='__main__':main()

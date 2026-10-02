"""Import the exact phase10 class prefix without editing the frozen source."""
from pathlib import Path
import hashlib,json,subprocess

HERE=Path(__file__).resolve().parent; ROOT=HERE.parent.parent
source=ROOT/'work/phase10_crypto/population_search.cpp'
body=source.read_bytes();marker=b'int main(int argc,char**argv)'
assert body.count(marker)==1
prefix=body[:body.index(marker)]
header=HERE/'phase10_frozen_classes.h';header.write_bytes(prefix)
assert header.read_bytes()==body[:body.index(marker)]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(source)=='0cc750150629d24391b333541b6d76f3edc2db1735d8a17bb8b2567900a4eaec'
binary=ROOT/'work/phase10_crypto/population_search'
assert sha(binary)=='7c353d7e1b5de457313ef11e25a7f30cbd446266b1463bd9fdbd38d58e946091'
command=['/usr/bin/clang++','-std=c++17','-O3',str(HERE/'capped_population_search.cpp'),'-o',str(HERE/'capped_population_search')]
subprocess.run(command,check=True)
record={'frozen_source_path':str(source.relative_to(ROOT)),'frozen_source_sha256':sha(source),
 'frozen_binary_path':str(binary.relative_to(ROOT)),'frozen_binary_sha256':sha(binary),
 'exact_prefix_bytes':len(prefix),'exact_prefix_sha256':sha(header),'exact_prefix_matches':True,
 'prefix_rule':'Every byte preceding the unique phase10 main declaration; no class or algorithm edits.',
 'compiler_command':command,'solver_source_sha256':sha(HERE/'capped_population_search.cpp'),
 'solver_sha256':sha(HERE/'capped_population_search')}
(HERE/'build_record.json').write_text(json.dumps(record,indent=2)+'\n')

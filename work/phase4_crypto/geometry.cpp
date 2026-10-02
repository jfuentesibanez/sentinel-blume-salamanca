#include "source_moves.h"
int main(){for(int w=3;w<=25;w++){
 auto src=source_moves(w,true),old=moves(w,true);std::unordered_set<std::string>oldset;for(auto&m:old){std::string s;for(int x:m.p)s+=char(x);oldset.insert(s);}
 int missing=0,identity=0;V id(w);std::iota(id.begin(),id.end(),0);
 std::cout<<"{\"width\":"<<w<<",\"permutations\":[";bool first=true;
 for(auto&m:src){V p=m.p;std::sort(p.begin(),p.end());if(p!=id)throw std::runtime_error("invalid permutation");identity+=m.p==id;std::string s;for(int x:m.p)s+=char(x);missing+=!oldset.count(s)&&m.p!=id;if(!first)std::cout<<',';first=false;std::cout<<keyjson(m.p);}
 std::cout<<"],\"phase3_moves\":"<<old.size()<<",\"source_moves_including_identity\":"<<src.size()<<",\"identity_count\":"<<identity<<",\"source_moves_missing_from_phase3\":"<<missing<<"}\n";
 }return 0;}

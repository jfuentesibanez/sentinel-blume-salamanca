#define main baseline_cli_main
#include "../crypto/double_search.cpp"
#undef main
int main(int argc,char**argv){if(argc!=3)return 2;Model m(argv[1]);V body=read(argv[2]);RNG rng(20261010);Ms ct={V(body.begin(),body.begin()+615),V(body.begin()+615,body.begin()+775)};for(auto&a:ct)std::shuffle(a.begin(),a.end(),rng);double sink=0;auto start=std::chrono::steady_clock::now();for(int i=0;i<1000;i++)sink+=idp(undo2(ct,perm(25,rng),0),20,0,m,-1,true);double seconds=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();std::cout<<"{\"mode\":\"synthetic_idp_benchmark\",\"messages\":[615,160],\"w1\":20,\"w2\":25,\"evaluations\":1000,\"seconds\":"<<seconds<<",\"milliseconds_per_evaluation\":"<<seconds<<",\"sum_to_prevent_dead_code\":"<<sink<<"}\n";}

#include "escape_search.h"
#define main phase3_frozen_cli_main
#include "../phase3_crypto/phase3.cpp"
#undef main
V keyfile(const std::string&path,int width){std::ifstream f(path);V key;int n;while(f>>n)key.push_back(n);V sorted=key;std::sort(sorted.begin(),sorted.end());V identity(width);std::iota(identity.begin(),identity.end(),0);if(sorted!=identity)throw std::runtime_error("start key is not permutation");return key;}
void eventsjson(const std::vector<Event5>&events){std::cout<<'[';for(size_t i=0;i<events.size();i++){if(i)std::cout<<',';const auto&e=events[i];std::cout<<"{\"policy\":\""<<e.policy<<"\",\"swaps\":"<<e.strength<<",\"hc_sweeps\":"<<e.sweeps<<",\"idp_evals\":"<<e.evals<<",\"start_idp\":"<<e.start<<",\"finish_idp\":"<<e.finish<<",\"global_best_idp\":"<<e.best<<",\"complete_local_optimum\":"<<tf(e.complete)<<",\"returned_to_previous_best\":"<<tf(e.returned_to_best)<<",\"improved_global_best\":"<<tf(e.improved_best)<<'}';}std::cout<<']';}
int main(int argc,char**argv){try{
 if(argc!=11)throw std::runtime_error("diagnostic MODEL HOLDOUT W1 W2 PLANT_SEED NMSG SECONDS MAXEVAL START_KEY POLICY");
 Model m(argv[1]);V body=read(argv[2]);int w1=std::stoi(argv[3]),w2=std::stoi(argv[4]),nmsg=std::stoi(argv[6]);uint64_t seed=std::stoull(argv[5]);double seconds=std::stod(argv[7]);long cap=std::stol(argv[8]);std::string policy=argv[10];
 if(body.size()<775||w1<3||w2<3||w1>160||w2>160||(nmsg!=1&&nmsg!=2)||!(seconds>0)||cap<1||(policy!="source"&&policy!="restart"&&policy!="kick"))throw std::runtime_error("invalid args");
 V start=keyfile(argv[9],w2);Planted p=plant(body,w1,w2,seed);Ms ct(p.ct.begin(),p.ct.begin()+nmsg);uint64_t search=(seed^0xb7e151628aed2a6bULL)^0x2222222222222222ULL;
 auto res=escape_from_peak(ct,w1,m,start,search,policy,cap,seconds);
 std::cout<<std::setprecision(12)<<"{\"scope\":\"conditioned_diagnostic_only\",\"policy\":\""<<policy<<"\",\"plant_seed\":"<<seed<<",\"messages_scored\":"<<nmsg<<",\"w1\":"<<w1<<",\"w2\":"<<w2<<",\"lengths\":[615,160],\"start_k2\":"<<keyjson(start)<<",\"start_idp\":"<<idp(undo2(ct,start,0),w1,0,m,-1,true)<<",\"final_idp\":"<<res.score<<",\"k2_changed\":"<<tf(res.key!=start)<<",\"k2\":"<<keyjson(res.key)<<",\"idp_eval_limit\":"<<cap<<",\"seconds_limit\":"<<seconds<<",\"idp_evals\":"<<res.evals<<",\"seconds\":"<<res.seconds<<",\"termination\":\""<<res.cause<<"\",\"exact_k2\":"<<tf(res.key==p.k2)<<",\"true_k2_idp\":"<<idp(undo2(ct,p.k2,0),w1,0,m,-1,true)<<",\"events\":";eventsjson(res.events);std::cout<<"}\n";
 return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}

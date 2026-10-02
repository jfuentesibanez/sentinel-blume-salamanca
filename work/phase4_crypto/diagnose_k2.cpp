#include "source_moves.h"
#define main phase3_frozen_cli_main
#include "../phase3_crypto/phase3.cpp"
#undef main

// Instrumentation-only copy of source K2 HC. Truth never enters this function.
K2Result diagnosed_k2(const Ms&ct,int w1,int w2,const Model&m,uint64_t seed,double seconds){
 Limits lim{seconds,300000};RNG rng(seed);auto f=[&](const V&s){return idp(undo2(ct,inverse(s),0),w1,0,m,-1,true);};std::vector<std::pair<double,V>>keys;
 for(int i=0;i<1000&&lim.allow();i++){V k=perm(w2,rng);keys.push_back({f(k),k});}
 auto sort=[&](){std::sort(keys.begin(),keys.end(),[](const auto&a,const auto&b){return a.first>b.first;});};sort();if(keys.size()>20)keys.resize(20);
 double pool_best=keys.at(0).first;
 for(auto&item:keys){V k=item.second;double cur=item.first;for(int i=0;i<w2-1&&!lim.expired;i++)for(int j=i+1;j<w2;j++){if(!lim.allow())break;V c=k;std::swap(c[i],c[j]);double v=f(c);if(v>cur+1e-12){cur=v;k=c;}}item={cur,k};}
 sort();if(keys.size()>5)keys.resize(5);double left_best=keys.at(0).first;auto mv=source_moves(w2);
 int completed=0;std::vector<int>sweeps_per_climb;V evals_per_climb;std::vector<double>climb_scores;
 for(auto&item:keys){if(lim.expired)break;V key=item.second;double cur=item.first;bool improved=true;long before=lim.used;int sweeps=0;
  while(improved&&!lim.expired){improved=false;sweeps++;std::shuffle(mv.begin(),mv.end(),rng);for(const auto&move:mv){if(!lim.allow())break;V c=moved(key,move);double v=f(c);if(v>cur+1e-12){cur=v;key=c;improved=true;}}}
  completed+=!lim.expired;sweeps_per_climb.push_back(sweeps);evals_per_climb.push_back(lim.used-before);climb_scores.push_back(cur);item={cur,key};
 }
 sort();for(auto&item:keys)item.second=inverse(item.second);
 std::cout<<std::setprecision(10)<<"{\"mode\":\"instrumented_k2_only\",\"seconds_limit\":"<<seconds<<",\"eval_limit\":300000,\"pool\":1000,\"keep\":20,\"climbs\":5,\"pool_best_idp\":"<<pool_best<<",\"left_to_right_best_idp\":"<<left_best<<",\"attempted_climbs\":"<<sweeps_per_climb.size()<<",\"completed_climbs\":"<<completed<<",\"sweeps_per_climb\":"<<keyjson(sweeps_per_climb)<<",\"idp_evals_per_climb\":"<<keyjson(evals_per_climb)<<",\"best_idp\":"<<keys.at(0).first<<",\"idp_evals\":"<<lim.used<<",\"seconds\":"<<lim.elapsed()<<",\"budget_expired\":"<<tf(lim.expired)<<",\"budget_cause\":\""<<(lim.expired?(lim.used>=300000?"max_evaluations":"wall_time"):"local_optima_completed")<<"\",\"k2\":"<<keyjson(keys.at(0).second)<<"}\n"<<std::flush;
 return {keys,lim.used,lim.elapsed(),lim.expired};
}
int main(int argc,char**argv){try{
 if(argc!=9)throw std::runtime_error("diagnose_k2 MODEL HOLDOUT W1 W2 PLANT_SEED NMSG SECONDS ROUND");
 Model m(argv[1]);V body=read(argv[2]);int w1=std::stoi(argv[3]),w2=std::stoi(argv[4]),nmsg=std::stoi(argv[6]),round=std::stoi(argv[8]);uint64_t seed=std::stoull(argv[5]);double sec=std::stod(argv[7]);
 if(body.size()<775||w1<3||w2<3||w1>160||w2>160||(nmsg!=1&&nmsg!=2)||round<0||!(sec>0))throw std::runtime_error("invalid args");
 Planted p=plant(body,w1,w2,seed);Ms used(p.ct.begin(),p.ct.begin()+nmsg);uint64_t search=(seed^0xb7e151628aed2a6bULL)+uint64_t(round)*0x9e3779b97f4a7c15ULL;
 auto r=diagnosed_k2(used,w1,w2,m,search^0x2222222222222222ULL,sec);
 std::cout<<std::setprecision(10)<<"{\"mode\":\"outside_solver_truth_comparison\",\"plant_seed\":"<<seed<<",\"round\":"<<round<<",\"messages_scored\":"<<nmsg<<",\"w1\":"<<w1<<",\"w2\":"<<w2<<",\"true_k2_idp\":"<<idp(undo2(used,p.k2,0),w1,0,m,-1,true)<<",\"exact_k2\":"<<tf(r.candidates.at(0).second==p.k2)<<",\"true_k2\":"<<keyjson(p.k2)<<"}\n";
 return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}

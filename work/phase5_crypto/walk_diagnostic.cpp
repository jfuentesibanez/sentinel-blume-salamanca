#include "escape_search.h"
#define main phase3_frozen_cli_main
#include "../phase3_crypto/phase3.cpp"
#undef main
V readkey5(const std::string&path,int w){std::ifstream f(path);V key;int n;while(f>>n)key.push_back(n);V sorted=key;std::sort(sorted.begin(),sorted.end());V id(w);std::iota(id.begin(),id.end(),0);if(sorted!=id)throw std::runtime_error("invalid start key");return key;}
struct WalkState5 {V start,finish,global;int swaps,sweeps;long evals;double startscore,finishscore,bestscore;bool complete,returned,improved;};
struct WalkResult5 {V key;double score;long evals;double seconds;std::string cause;std::vector<WalkState5>states;};

// ILS acceptance-always variant: walk among local maxima, retaining a separate
// global-best record. No truth, language threshold or supplied correct key.
WalkResult5 walk_from_peak(const Ms&ct,int w1,const Model&m,const V&start_read,uint64_t seed,long cap,double seconds){
 Budget5 budget{cap,0,seconds};RNG rng(seed);auto mv=source_moves(start_read.size());
 auto eval=[&](const V&s){return idp(undo2(ct,inverse(s),0),w1,0,m,-1,true);};
 V current=inverse(start_read);if(!budget.allow())throw std::runtime_error("no initial budget");double score=eval(current),startscore=score;
 auto initial=hill5(current,score,mv,budget,rng,eval);current=initial.key;score=initial.score;V best=current;double bestscore=score;WalkResult5 result;
 result.states.push_back({inverse(start_read),current,best,0,initial.sweeps,initial.evals+1,startscore,score,bestscore,initial.complete,current==inverse(start_read),score>startscore+1e-12});
 int iteration=0;
 while(!budget.expired()){
  V previous=current;int strength=2+iteration%3;V trial=kick5(current,strength,rng);
  if(!budget.allow())break;double firstscore=eval(trial);auto local=hill5(trial,firstscore,mv,budget,rng,eval);
  current=local.key;score=local.score;bool improved=score>bestscore+1e-12;if(improved){best=current;bestscore=score;}
  result.states.push_back({trial,current,best,strength,local.sweeps,local.evals+1,firstscore,score,bestscore,local.complete,current==previous,improved});iteration++;
 }
 result.key=inverse(best);result.score=bestscore;result.evals=budget.used;result.seconds=budget.elapsed();result.cause=budget.cause;return result;
}
int main(int argc,char**argv){try{
 if(argc!=10)throw std::runtime_error("walk_diagnostic MODEL HOLDOUT W1 W2 PLANT_SEED NMSG SECONDS MAXEVAL START_KEY");
 Model m(argv[1]);V body=read(argv[2]);int w1=std::stoi(argv[3]),w2=std::stoi(argv[4]),nmsg=std::stoi(argv[6]);uint64_t seed=std::stoull(argv[5]);double seconds=std::stod(argv[7]);long cap=std::stol(argv[8]);
 if(body.size()<775||w1<3||w2<3||w1>160||w2>160||(nmsg!=1&&nmsg!=2)||!(seconds>0)||cap<1)throw std::runtime_error("invalid arguments");
 V start=readkey5(argv[9],w2);Planted p=plant(body,w1,w2,seed);Ms ct(p.ct.begin(),p.ct.begin()+nmsg);uint64_t search=(seed^0xb7e151628aed2a6bULL)^0x2222222222222222ULL;
 auto res=walk_from_peak(ct,w1,m,start,search,cap,seconds);
 std::cout<<std::setprecision(12)<<"{\"scope\":\"conditioned_diagnostic_only\",\"policy\":\"walk\",\"plant_seed\":"<<seed<<",\"messages_scored\":"<<nmsg<<",\"w1\":"<<w1<<",\"w2\":"<<w2<<",\"lengths\":[615,160],\"start_k2\":"<<keyjson(start)<<",\"start_idp\":"<<idp(undo2(ct,start,0),w1,0,m,-1,true)<<",\"final_idp\":"<<res.score<<",\"k2_changed\":"<<tf(res.key!=start)<<",\"k2\":"<<keyjson(res.key)<<",\"idp_eval_limit\":"<<cap<<",\"seconds_limit\":"<<seconds<<",\"idp_evals\":"<<res.evals<<",\"seconds\":"<<res.seconds<<",\"termination\":\""<<res.cause<<"\",\"exact_k2\":"<<tf(res.key==p.k2)<<",\"true_k2_idp\":"<<idp(undo2(ct,p.k2,0),w1,0,m,-1,true)<<",\"states\":[";
 for(size_t i=0;i<res.states.size();i++){if(i)std::cout<<',';const auto&s=res.states[i];std::cout<<"{\"swaps\":"<<s.swaps<<",\"hc_sweeps\":"<<s.sweeps<<",\"idp_evals\":"<<s.evals<<",\"trial_k2\":"<<keyjson(inverse(s.start))<<",\"current_k2\":"<<keyjson(inverse(s.finish))<<",\"global_best_k2\":"<<keyjson(inverse(s.global))<<",\"trial_idp\":"<<s.startscore<<",\"current_idp\":"<<s.finishscore<<",\"global_best_idp\":"<<s.bestscore<<",\"complete_local_optimum\":"<<tf(s.complete)<<",\"returned_to_previous_current\":"<<tf(s.returned)<<",\"improved_global_best\":"<<tf(s.improved)<<'}';}
 std::cout<<"]}\n";return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}

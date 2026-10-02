#include "source_moves.h"
#define main phase3_frozen_cli_main
#include "../phase3_crypto/phase3.cpp"
#undef main

FullResult source_cycle(const Ms&ct,int w1,int w2,const Model&m,uint64_t seed,int restarts,double k1sec,double k2sec){
 auto start=std::chrono::steady_clock::now();FullResult r;r.k2stage=solve_k2_source(ct,w1,w2,m,seed^0x2222222222222222ULL,1000,20,5,k2sec);
 if(r.k2stage.candidates.empty())throw std::runtime_error("K2 budget ended before pool evaluation");
 V k2=r.k2stage.candidates[0].second;r.k1stage=solve_ict(undo2(ct,k2,0),w1,m,seed^0x1111111111111111ULL,restarts,k1sec,true,2000000,3);V k1=r.k1stage.key;
 Limits lim{k1sec,2000000};RNG rng(seed^0x3333333333333333ULL);auto f=[&](const V&s){return fullscore(ct,k1,inverse(s),0,m,3);};auto fin=source_hc(inverse(k2),source_moves(w2),lim,rng,f);k2=inverse(fin.second);r.final_evals=lim.used;
 r.final_expired=lim.expired;r.best={fullscore(ct,k1,k2,0,m,4),k1,k2};r.seconds=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();return r;
}
FullResult source_full(const Ms&ct,int w1,int w2,const Model&m,uint64_t seed,int restarts,double k1sec,double k2sec){
 FullResult best;double best_q3=-1e100;long feature=0,q=0,idp=0,fin=0;double sec=0;bool expired=false;
 for(int round=0;round<3;round++){
  auto r=source_cycle(ct,w1,w2,m,seed+uint64_t(round)*0x9e3779b97f4a7c15ULL,restarts,k1sec,k2sec);
  double score=fullscore(ct,r.best.k1,r.best.k2,0,m,3);
  feature+=r.k1stage.feature_evals;q+=r.k1stage.q_evals;idp+=r.k2stage.evals;fin+=r.final_evals;sec+=r.seconds;expired|=r.k1stage.expired||r.k2stage.expired||r.final_expired;
  if(score>best_q3){best_q3=score;best=r;}
 }
 best.k1stage.feature_evals=feature;best.k1stage.q_evals=q;best.k2stage.evals=idp;best.final_evals=fin;best.seconds=sec;best.final_expired=expired;best.outer_rounds=3;return best;
}

int main(int argc,char**argv){try{
 if(argc<10||argc>11)throw std::runtime_error("phase4 old/source MODEL HOLDOUT W1 W2 PLANT_SEED RESTARTS K1_SECONDS K2_SECONDS [negative]");
 std::string variant=argv[1];if(variant!="old"&&variant!="source")throw std::runtime_error("variant must be old or source");
 Model m(argv[2]);V body=read(argv[3]);int w1=std::stoi(argv[4]),w2=std::stoi(argv[5]);uint64_t seed=std::stoull(argv[6]),search_seed=seed^0xb7e151628aed2a6bULL;int restarts=std::stoi(argv[7]);double k1sec=std::stod(argv[8]),k2sec=std::stod(argv[9]);bool negative=argc>10&&std::string(argv[10])=="negative";
 if(body.size()<775||w1<3||w2<3||w1>160||w2>160||restarts<1||!(k1sec>0)||!(k2sec>0)||!std::isfinite(k1sec)||!std::isfinite(k2sec))throw std::runtime_error("invalid length, width or budget");
 if(argc>10&&!negative)throw std::runtime_error("optional flag must be negative");
 Planted p=plant(body,w1,w2,seed);
 for(int nmsg:{1,2}){
  Ms ct=p.ct;if(negative)ct=shuffled(ct,search_seed^0xccccccccccccccccULL);Ms used(ct.begin(),ct.begin()+nmsg);
  auto res=variant=="old"?solve_phase3(used,w1,w2,m,search_seed,restarts,k1sec,k2sec):source_full(used,w1,w2,m,search_seed,restarts,k1sec,k2sec);
  V k1=res.best.k1,k2=res.best.k2;Ms dec;bool encok=true;for(auto&a:ct){auto pt=crypt(a,k1,k2,0,false);encok&=crypt(pt,k1,k2,0,true)==a;dec.push_back(pt);}
  Ms decscored(dec.begin(),dec.begin()+nmsg),truth(p.pt.begin(),p.pt.begin()+nmsg);bool expired=res.k1stage.expired||res.k2stage.expired||res.final_expired;
  std::cout<<std::setprecision(10)<<"{\"mode\":\"full\",\"variant\":\""<<variant<<"\",\"oracle_k2_disclosed\":false,\"negative\":"<<tf(negative)<<",\"plant_seed\":"<<seed<<",\"search_seed\":"<<search_seed<<",\"sample_position\":"<<p.pos<<",\"messages_scored\":"<<nmsg<<",\"lengths\":[615,160],\"w1\":"<<w1<<",\"w2\":"<<w2<<",\"restarts\":"<<restarts<<",\"outer_rounds\":"<<res.outer_rounds<<",\"final_ngram\":3,\"k1_seconds_limit\":"<<k1sec<<",\"k2_seconds_limit\":"<<k2sec<<",\"feature_evals\":"<<res.k1stage.feature_evals<<",\"q_evals\":"<<res.k1stage.q_evals<<",\"idp_evals\":"<<res.k2stage.evals<<",\"final_k2_evals\":"<<res.final_evals<<",\"budget_expired\":"<<tf(expired)<<",\"seconds\":"<<res.seconds<<",\"stage_k2_idp\":"<<res.k2stage.candidates[0].first<<",\"true_k2_idp\":"<<idp(undo2(used,p.k2,0),w1,0,m,-1,true)<<",\"stage_k2\":"<<keyjson(res.k2stage.candidates[0].second)<<",\"stage_exact_k2\":"<<tf(res.k2stage.candidates[0].second==p.k2)<<",\"q3\":"<<ngram(decscored,m,3)<<",\"truth_q3\":"<<ngram(truth,m,3)<<",\"q4\":"<<ngram(decscored,m,4)<<",\"truth_q4\":"<<ngram(truth,m,4)<<",\"k1\":"<<keyjson(k1)<<",\"k2\":"<<keyjson(k2)<<",\"true_k1\":"<<keyjson(p.k1)<<",\"true_k2\":"<<keyjson(p.k2)<<",\"exact_k1\":"<<tf(k1==p.k1)<<",\"exact_k2\":"<<tf(k2==p.k2)<<",\"exact_both_plaintexts\":"<<tf(exacttext(dec,p.pt))<<",\"correct_letters\":"<<keyjson(counts(dec,p.pt))<<",\"reencryption_consistency\":"<<tf(encok)<<"}\n"<<std::flush;
 }
 return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}

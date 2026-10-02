#include "ict_search.h"

struct Planted{Ms pt,ct;V k1,k2;int pos;};
Planted plant(const V&body,int w1,int w2,uint64_t seed){RNG r(seed);int pos=r()%(body.size()-774);Ms pt={V(body.begin()+pos,body.begin()+pos+615),V(body.begin()+pos+615,body.begin()+pos+775)},ct;V k1=perm(w1,r),k2=perm(w2,r);for(auto&a:pt)ct.push_back(crypt(a,k1,k2,0,true));return {pt,ct,k1,k2,pos};}
Ms shuffled(Ms a,uint64_t seed){RNG r(seed);for(auto&t:a)std::shuffle(t.begin(),t.end(),r);return a;}
V counts(const Ms&a,const Ms&b){V c;for(size_t i=0;i<a.size();i++)c.push_back(correct(a[i],b[i]));return c;}
bool exacttext(const Ms&a,const Ms&b){return a==b;}
const char*tf(bool x){return x?"true":"false";}
void geometry_checks(const Model&m){
 RNG r(100101);int keycases=0,movecases=0;
 for(int w:{3,5,7,12,20,25}){
  auto full=moves(w,true);V identity(w);std::iota(identity.begin(),identity.end(),0);
  for(auto&x:full){V a=moved(identity,x),b=a;std::sort(b.begin(),b.end());if(b!=identity||a==identity)throw std::runtime_error("invalid move");movecases++;}
  for(int n:{160,615})for(int rep=0;rep<5;rep++){
   V pt(n);for(auto&c:pt)c=r()%26;V k=perm(w,r),s=inverse(k);if(inverse(s)!=k)throw std::runtime_error("inverse mismatch");V I=col(pt,k,true);ICT ict({I},w,m,false);auto&t=ict.tables[0];V start(w);int p=0;for(int rank=0;rank<w;rank++){start[rank]=p;p+=t.rows+(k[rank]<t.rem);}
   // Inject independently computed, planted boundary offsets only into this
   // geometry test. The solver's offset table never receives true boundaries.
   for(int i=0;i<w;i++)for(int j=0;j<w;j++)t.O[i*w+j]=((start[j]-start[i])%t.rows+t.rows)%t.rows;
   if(ict.feature(s).align!=3*w-4)throw std::runtime_error("alignment mismatch");
   if(col(I,inverse(s),false)!=pt)throw std::runtime_error("numerical convention mismatch");keycases++;
  }
 }
 std::cout<<"{\"check\":\"numeric_keys_moves_alignment\",\"key_cases\":"<<keycases<<",\"move_cases\":"<<movecases<<",\"passed\":true}\n";
}

struct FullResult {Cand best;K2Result k2stage;K1Result k1stage;long final_evals=0;bool final_expired=false;int outer_rounds=1;double seconds=0;};
FullResult solve_phase3_cycle(const Ms&ct,int w1,int w2,const Model&m,uint64_t seed,int restarts,double k1sec,double k2sec){
 auto start=std::chrono::steady_clock::now();FullResult r;r.k2stage=solve_k2_hc(ct,w1,w2,m,seed^0x2222222222222222ULL,1000,20,5,k2sec);
 if(r.k2stage.candidates.empty())throw std::runtime_error("K2 budget ended before pool evaluation");
 V k2=r.k2stage.candidates[0].second;r.k1stage=solve_ict(undo2(ct,k2,0),w1,m,seed^0x1111111111111111ULL,restarts,k1sec,true,2000000,3);V k1=r.k1stage.key;
 Limits lim{k1sec,2000000};auto f=[&](const V&s){return fullscore(ct,k1,inverse(s),0,m,3);};auto fin=complete_hc(inverse(k2),moves(w2,true),lim,f);k2=inverse(fin.second);r.final_evals=lim.used;
 r.final_expired=lim.expired;r.best={fullscore(ct,k1,k2,0,m,4),k1,k2};r.seconds=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();return r;
}
FullResult solve_phase3(const Ms&ct,int w1,int w2,const Model&m,uint64_t seed,int restarts,double k1sec,double k2sec){
 FullResult best;double best_q3=-1e100;long feature=0,q=0,idp=0,fin=0;double sec=0;bool expired=false;
 // Fixed three outer repetitions of source step5. No planted truth or a
 // corpus-specific success threshold is available to the solver.
 for(int round=0;round<3;round++){
  auto r=solve_phase3_cycle(ct,w1,w2,m,seed+uint64_t(round)*0x9e3779b97f4a7c15ULL,restarts,k1sec,k2sec);
  double score=fullscore(ct,r.best.k1,r.best.k2,0,m,3);
  feature+=r.k1stage.feature_evals;q+=r.k1stage.q_evals;idp+=r.k2stage.evals;fin+=r.final_evals;sec+=r.seconds;expired|=r.k1stage.expired||r.k2stage.expired||r.final_expired;
  if(score>best_q3){best_q3=score;best=r;}
 }
 best.k1stage.feature_evals=feature;best.k1stage.q_evals=q;best.k2stage.evals=idp;best.final_evals=fin;best.seconds=sec;best.final_expired=expired;best.outer_rounds=3;return best;
}

int main(int argc,char**argv){try{
 if(argc<3)throw std::runtime_error("phase3 check MODEL | oracle/full MODEL HOLDOUT W1 W2 PLANT_SEED RESTARTS K1_SECONDS [K2_SECONDS] [negative]");
 std::string mode=argv[1];Model m(argv[2]);if(mode=="check"){if(argc!=3)throw std::runtime_error("check takes MODEL only");geometry_checks(m);return 0;}
 if(mode!="oracle"&&mode!="full")throw std::runtime_error("mode must be check, oracle or full");
 if(argc<9||argc>11)throw std::runtime_error("incorrect argument count");
 V body=read(argv[3]);int w1=std::stoi(argv[4]),w2=std::stoi(argv[5]);uint64_t seed=std::stoull(argv[6]),search_seed=seed^0xb7e151628aed2a6bULL;int restarts=std::stoi(argv[7]);double k1sec=std::stod(argv[8]),k2sec=argc>9?std::stod(argv[9]):k1sec;bool negative=argc>10&&std::string(argv[10])=="negative";
 if(body.size()<775||w1<3||w2<3||w1>160||w2>160||restarts<1||!(k1sec>0)||!(k2sec>0)||!std::isfinite(k1sec)||!std::isfinite(k2sec))throw std::runtime_error("require >=775 holdout letters, widths 3..160, positive finite budgets and restarts");
 if(argc>10&&std::string(argv[10])!="negative")throw std::runtime_error("last argument, if supplied, must be negative");
 Planted p=plant(body,w1,w2,seed);
 for(int nmsg:{1,2}){
  Ms ct=p.ct;if(negative)ct=shuffled(ct,search_seed^0xccccccccccccccccULL);Ms used(ct.begin(),ct.begin()+nmsg);Ms dec;V k1,k2,stagek2;long feat=0,qev=0,idpev=0,finev=0;int rounds=0;bool expired=false;double sec,stageidp=0;
  if(mode=="oracle"){
   k2=p.k2;Ms I=undo2(used,k2,0);auto res=solve_ict(I,w1,m,search_seed^0x1111111111111111ULL,restarts,k1sec,true,2000000,3);k1=res.key;feat=res.feature_evals;qev=res.q_evals;expired=res.expired;sec=res.seconds;
  }else{
   auto res=solve_phase3(used,w1,w2,m,search_seed,restarts,k1sec,k2sec);k1=res.best.k1;k2=res.best.k2;feat=res.k1stage.feature_evals;qev=res.k1stage.q_evals;idpev=res.k2stage.evals;finev=res.final_evals;expired=res.k1stage.expired||res.k2stage.expired||res.final_expired;rounds=res.outer_rounds;sec=res.seconds;stageidp=res.k2stage.candidates[0].first;stagek2=res.k2stage.candidates[0].second;
  }
  bool encok=true;for(auto&a:ct){auto pt=crypt(a,k1,k2,0,false);encok&=crypt(pt,k1,k2,0,true)==a;dec.push_back(pt);}
  Ms decscored(dec.begin(),dec.begin()+nmsg),truth(p.pt.begin(),p.pt.begin()+nmsg);
  std::cout<<std::setprecision(10)<<"{\"mode\":\""<<mode<<"\",\"oracle_k2_disclosed\":"<<tf(mode=="oracle")<<",\"negative\":"<<tf(negative)<<",\"plant_seed\":"<<seed<<",\"search_seed\":"<<search_seed<<",\"sample_position\":"<<p.pos<<",\"messages_scored\":"<<nmsg<<",\"lengths\":[615,160],\"w1\":"<<w1<<",\"w2\":"<<w2<<",\"restarts\":"<<restarts<<",\"outer_rounds\":"<<rounds<<",\"final_ngram\":3,\"k1_seconds_limit\":"<<k1sec<<",\"k2_seconds_limit\":"<<k2sec<<",\"feature_evals\":"<<feat<<",\"q_evals\":"<<qev<<",\"idp_evals\":"<<idpev<<",\"final_k2_evals\":"<<finev<<",\"budget_expired\":"<<tf(expired)<<",\"seconds\":"<<sec<<",\"stage_k2_idp\":"<<stageidp<<",\"true_k2_idp\":"<<idp(undo2(used,p.k2,0),w1,0,m,-1,true)<<",\"stage_k2\":"<<keyjson(stagek2)<<",\"stage_exact_k2\":"<<tf(stagek2==p.k2)<<",\"q3\":"<<ngram(decscored,m,3)<<",\"truth_q3\":"<<ngram(truth,m,3)<<",\"q4\":"<<ngram(decscored,m,4)<<",\"truth_q4\":"<<ngram(truth,m,4)<<",\"k1\":"<<keyjson(k1)<<",\"k2\":"<<keyjson(k2)<<",\"true_k1\":"<<keyjson(p.k1)<<",\"true_k2\":"<<keyjson(p.k2)<<",\"exact_k1\":"<<tf(k1==p.k1)<<",\"exact_k2\":"<<tf(k2==p.k2)<<",\"exact_both_plaintexts\":"<<tf(exacttext(dec,p.pt))<<",\"correct_letters\":"<<keyjson(counts(dec,p.pt))<<",\"reencryption_consistency\":"<<tf(encok)<<"}\n"<<std::flush;
 }
 return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}

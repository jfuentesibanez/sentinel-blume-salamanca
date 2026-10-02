// Controlled diagnostics only. Truth is generated in this harness and never
// supplied to the unconstrained baseline solve(). No historical ciphertexts.
#define main baseline_cli_main
#include "../crypto/double_search.cpp"
#undef main

V parsekey(const std::string&s){V k;std::stringstream f(s);std::string x;while(std::getline(f,x,','))k.push_back(std::stoi(x));return k;}
int main(int argc,char**argv){try{
 if(argc!=10)throw std::runtime_error("oracle MODEL HOLDOUT W1 W2 SEED RESTARTS STEPS POOL INCUMBENT_K2_CSV");
 Model m(argv[1]);V body=read(argv[2]);int w1=std::stoi(argv[3]),w2=std::stoi(argv[4]),seed=std::stoi(argv[5]),restarts=std::stoi(argv[6]),steps=std::stoi(argv[7]),pool=std::stoi(argv[8]);V incumbent=parsekey(argv[9]);
 RNG plant_rng(seed);int pos=plant_rng()%(body.size()-774);Ms pt={V(body.begin()+pos,body.begin()+pos+615),V(body.begin()+pos+615,body.begin()+pos+775)};V truek1=perm(w1,plant_rng),truek2=perm(w2,plant_rng);Ms ct;for(auto&a:pt)ct.push_back(crypt(a,truek1,truek2,0,true));
 uint64_t search_seed=uint64_t(seed)^0x9e3779b97f4a7c15ULL;auto started=std::chrono::steady_clock::now();
 for(int msgs:{1,2}){
  Ms used(ct.begin(),ct.begin()+msgs);auto fi=[&](const V&k){return idp(undo2(used,k,0),w1,0,m,-1,true);};double trueidp=fi(truek2),incidp=fi(incumbent);RNG pool_rng(search_seed^0x1212121212121212ULL);int above=0;double maxrandom=-1e100;
  for(int i=0;i<pool;i++){double v=fi(perm(w2,pool_rng));above+=v>trueidp;maxrandom=std::max(maxrandom,v);}
  // Reproduce the baseline's stage-1 proposals, before its q4 refinement.
  RNG stage1_rng(search_seed);std::pair<double,V> best2={-1e100,{}};
  for(int rr=0;rr<restarts;rr++){auto a=anneal(perm(w2,stage1_rng),steps,stage1_rng,fi);if(a.first>best2.first)best2=a;}
  // Oracle A: K2 disclosed, solve K1 under the baseline's per-candidate budget.
  RNG a_rng(search_seed^0xaaaaaaaaaaaaaaaaULL);auto fa=[&](const V&k){return fullscore(used,k,truek2,0,m,4);};std::pair<double,V>a={-1e100,{}};
  for(int rr=0;rr<3;rr++){auto x=anneal(perm(w1,a_rng),steps*4,a_rng,fa,.05,.0005);if(x.first>a.first)a=x;}
  a=slides(a.second,steps,fa);
  // Oracle B: K1 disclosed, solve K2 directly by q4 with the same total budget.
  RNG b_rng(search_seed^0xbbbbbbbbbbbbbbbbULL);auto fb=[&](const V&k){return fullscore(used,truek1,k,0,m,4);};std::pair<double,V>b={-1e100,{}};
  for(int rr=0;rr<3;rr++){auto x=anneal(perm(w2,b_rng),steps*4,b_rng,fb,.05,.0005);if(x.first>b.first)b=x;}
  b=slides(b.second,steps,fb);
  V ca,cb;for(int i=0;i<2;i++){ca.push_back(correct(crypt(ct[i],a.second,truek2,0,false),pt[i]));cb.push_back(correct(crypt(ct[i],truek1,b.second,0,false),pt[i]));}
  std::cout<<std::setprecision(10)<<"{\"diagnostic\":\"oracle_only\",\"w1\":"<<w1<<",\"w2\":"<<w2<<",\"plant_seed\":"<<seed<<",\"search_seed\":"<<search_seed<<",\"messages_scored\":"<<msgs<<",\"idp_true_k2\":"<<trueidp<<",\"idp_actual_incumbent_k2\":"<<incidp<<",\"random_pool_size\":"<<pool<<",\"random_pool_above_true\":"<<above<<",\"rank_true_in_pool_plus_truth\":"<<1+above<<",\"idp_random_pool_max\":"<<maxrandom<<",\"idp_stage1_best\":"<<best2.first<<",\"stage1_exact_k2\":"<<(best2.second==truek2?"true":"false")<<",\"oracle_k2_to_k1_q4\":"<<a.first<<",\"oracle_k2_to_k1_exact\":"<<(a.second==truek1?"true":"false")<<",\"oracle_k2_to_k1_correct\":"<<keyjson(ca)<<",\"oracle_k1_to_k2_q4\":"<<b.first<<",\"oracle_k1_to_k2_exact\":"<<(b.second==truek2?"true":"false")<<",\"oracle_k1_to_k2_correct\":"<<keyjson(cb)<<",\"q4_truth\":"<<fullscore(used,truek1,truek2,0,m,4)<<",\"elapsed_cumulative_seconds\":"<<std::chrono::duration<double>(std::chrono::steady_clock::now()-started).count()<<"}\n"<<std::flush;
 }
 return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}

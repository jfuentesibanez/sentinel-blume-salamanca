#include "escape_search.h"
int main(){
 RNG rng(20261297);int kickcases=0;
 for(int w=3;w<=25;w++)for(int strength:{2,3,4})for(int repeat=0;repeat<100;repeat++){
  V key=perm(w,rng),changed=kick5(key,strength,rng),sorted=changed;std::sort(sorted.begin(),sorted.end());V id(w);std::iota(id.begin(),id.end(),0);
  if(sorted!=id||correct(key,changed)!=w-2*std::min(strength,w/2))throw std::runtime_error("kick is not a disjoint valid perturbation");kickcases++;
 }
 int budgetcases=0;auto mv=source_moves(7);
 for(long cap:{1,7,53,190,2000}){
  Budget5 budget{cap,0,1000};long calls=0;auto f=[&](const V&key){calls++;double score=0;for(size_t i=0;i<key.size();i++)score+=i*key[i];return score;};
  V key=perm(7,rng);if(!budget.allow())throw std::runtime_error("first evaluation blocked");double initial=f(key);auto result=hill5(key,initial,mv,budget,rng,f);
  if(calls!=budget.used||calls>cap||result.evals+1!=budget.used||result.score<initial)throw std::runtime_error("evaluation accounting or best score wrong");budgetcases++;
 }
 Budget5 empty{0,0,1000};if(empty.allow()||empty.used!=0||empty.cause!="max_evaluations")throw std::runtime_error("empty cap failed");budgetcases++;
 Budget5 expired{10,0,0};if(expired.allow()||expired.used!=0||expired.cause!="wall_time")throw std::runtime_error("time gate failed");budgetcases++;
 std::cout<<"{\"check\":\"disjoint_kicks_and_evaluation_gates\",\"kick_cases\":"<<kickcases<<",\"budget_cases\":"<<budgetcases<<",\"passed\":true}\n";return 0;
}

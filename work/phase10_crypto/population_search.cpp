// Copyright (C) CrypTool 2 Team; source movements adapted under Apache-2.0.
// Frozen phase9 restart and metering are imported unchanged.
#include "../phase4_crypto/source_moves.h"
#define main phase9_frozen_cli_main
#include "../phase9_crypto/k2_search.cpp"
#undef main

namespace phase10 {
using phase9::Key;
struct Member { long id; Key key; int uses; };
int distance(const V& a,const V& b){int d=0;for(std::size_t i=0;i<a.size();++i)d+=a[i]!=b[i];return d;}
std::string members_json(const std::vector<Member>& members){
 std::ostringstream out;out<<std::setprecision(12)<<'[';
 for(std::size_t i=0;i<members.size();++i){if(i)out<<',';const auto& m=members[i];out<<"{\"id\":"<<m.id<<",\"numeric\":"<<keyjson(m.key.numeric)<<",\"idp\":"<<m.key.score<<",\"uses\":"<<m.uses<<'}';}
 return out.str()+']';
}
struct PopulationSearch : phase9::Search {
 std::vector<Member> population;
 std::vector<std::string> events,parents,refresh_traces;
 const int minimum_distance;
 long next_id=1,action_sequence=0;
 int offspring_completed=0,refreshes=0;
 PopulationSearch(const Ms& ct,const Model& m,int w1,int w2,uint64_t s,long cap,double secs)
  :phase9::Search(ct,m,w1,w2,s,cap,secs),minimum_distance((2*w2+4)/5){}
 void validate() const {
  if(population.size()>5)throw std::runtime_error("population exceeds5");
  for(std::size_t i=0;i<population.size();++i)for(std::size_t j=i+1;j<population.size();++j)
   if(distance(population[i].key.numeric,population[j].key.numeric)<minimum_distance)throw std::runtime_error("population distance invariant");
 }
 void admit(const Key& candidate,const std::string& origin){
  auto before=population;V distances;std::vector<long> neighbors;int inherited_uses=0;bool improves_neighbors=true;
  for(const auto& member:population){int d=distance(candidate.numeric,member.key.numeric);distances.push_back(d);
   if(d<minimum_distance){neighbors.push_back(member.id);inherited_uses=std::max(inherited_uses,member.uses);if(!(candidate.score>member.key.score+1e-12))improves_neighbors=false;}}
  std::string decision;long replaced_id=-1;
  if(!neighbors.empty()){
   if(improves_neighbors){population.erase(std::remove_if(population.begin(),population.end(),[&](const Member& m){return std::find(neighbors.begin(),neighbors.end(),m.id)!=neighbors.end();}),population.end());population.push_back({next_id++,candidate,inherited_uses});decision="replace_close_neighbors";}
   else decision="reject_close_neighbor_score";
  }else if(population.size()<5){population.push_back({next_id++,candidate,0});decision="append_diverse";}
  else{
   auto worst=std::min_element(population.begin(),population.end(),[](const Member&a,const Member&b){return a.key.score<b.key.score||(a.key.score==b.key.score&&a.key.numeric>b.key.numeric);});
   if(candidate.score>worst->key.score+1e-12){replaced_id=worst->id;*worst={next_id++,candidate,0};decision="replace_worst_diverse";}else decision="reject_worst_score";
  }
  std::sort(population.begin(),population.end(),[](const Member&a,const Member&b){return phase9::preferred(a.key,b.key);});validate();
  std::ostringstream event;event<<std::setprecision(12)<<"{\"number\":"<<events.size()+1<<",\"sequence\":"<<++action_sequence<<",\"objective_calls\":"<<used<<",\"origin\":\""<<origin<<"\",\"candidate_numeric\":"<<keyjson(candidate.numeric)<<",\"candidate_idp\":"<<candidate.score<<",\"distances_before\":"<<keyjson(distances)<<",\"close_neighbor_ids\":[";
  for(std::size_t i=0;i<neighbors.size();++i){if(i)event<<',';event<<neighbors[i];}
  event<<"],\"replaced_worst_id\":"<<replaced_id<<",\"decision\":\""<<decision<<"\",\"before\":"<<members_json(before)<<",\"after\":"<<members_json(population)<<'}';events.push_back(event.str());
 }
 Key prepare(){
  ++restart_starts;const long began=used;auto clock=phase9::Clock::now();std::vector<Key> pool;
  for(int i=0;i<1000;++i){Key candidate;if(!evaluate(perm(w2,rng),candidate,"random_pool"))break;pool.push_back(candidate);std::sort(pool.begin(),pool.end(),phase9::preferred);if(pool.size()>20)pool.resize(20);}
  if(pool.empty())return {};
  for(auto& item:pool){Key current=item;for(int i=0;i<w2-1&&!cut;++i)for(int j=i+1;j<w2;++j){V candidate=current.numeric;std::swap(candidate[i],candidate[j]);Key value;if(!evaluate(candidate,value,"left_to_right_swaps"))break;if(value.score>current.score+1e-12)current=value;}item=current;}
  std::sort(pool.begin(),pool.end(),phase9::preferred);if(!cut)++restart_completions;
  std::ostringstream trace;trace<<std::setprecision(12)<<"{\"kind\":\"initialization\",\"number\":"<<restart_starts<<",\"calls\":"<<used-began<<",\"seconds\":"<<phase9::seconds(clock)<<",\"completed\":"<<(cut?"false":"true")<<",\"best_idp\":"<<pool[0].score<<'}';traces.push_back(trace.str());
  if(!cut)for(const auto& member:pool)admit(member,"prepared_survivor");
  return pool[0];
 }
 Key kick_parent(){
  if(population.empty())throw std::runtime_error("empty parent population");
  auto selected=std::min_element(population.begin(),population.end(),[](const Member&a,const Member&b){return a.uses!=b.uses?a.uses<b.uses:phase9::preferred(a.key,b.key);});
  const int before=selected->uses;const long selected_id=selected->id;Key base=selected->key;++selected->uses;
  std::ostringstream choice;choice<<std::setprecision(12)<<"{\"number\":"<<parents.size()+1<<",\"sequence\":"<<++action_sequence<<",\"objective_calls\":"<<used<<",\"selected_id\":"<<selected_id<<",\"uses_before\":"<<before<<",\"uses_after\":"<<selected->uses<<",\"population_after_use\":"<<members_json(population)<<'}';parents.push_back(choice.str());
  ++kick_attempts;const int changed=2*((minimum_distance+1)/2);V positions(w2);std::iota(positions.begin(),positions.end(),0);std::shuffle(positions.begin(),positions.end(),rng);positions.resize(changed);V candidate=base.numeric;
  for(int pair=0;pair<changed/2;++pair)std::swap(candidate[positions[2*pair]],candidate[positions[2*pair+1]]);
  if(distance(base.numeric,candidate)!=changed)throw std::runtime_error("population perturbation distance");
  Key value;bool scored=evaluate(candidate,value,"perturbation");if(scored)++kick_scored;
  std::ostringstream trace;trace<<std::setprecision(12)<<"{\"number\":"<<kick_attempts<<",\"parent_id\":"<<selected_id<<",\"positions\":"<<keyjson(positions)<<",\"base_numeric\":"<<keyjson(base.numeric)<<",\"perturbed_numeric\":"<<keyjson(candidate)<<",\"hamming_distance\":"<<changed<<",\"scored\":"<<(scored?"true":"false");if(scored)trace<<",\"idp\":"<<value.score;trace<<'}';kicks.push_back(trace.str());return value;
 }
 void run_population(){
  Key initial=prepare();if(!cut){Key local=climb(initial);if(!cut)admit(local,"initial_local_optimum");}
  while(!cut){
   Key perturbed=kick_parent();if(cut)break;Key local=climb(perturbed);if(cut)break;
   ++offspring_completed;admit(local,"offspring_local_optimum");
   if(offspring_completed%4==0){++refreshes;auto before=population;long began=used,first_event=events.size()+1;prepare();std::ostringstream trace;trace<<"{\"number\":"<<refreshes<<",\"offspring_completed\":"<<offspring_completed<<",\"objective_calls_before\":"<<began<<",\"objective_calls_after\":"<<used<<",\"completed\":"<<(cut?"false":"true")<<",\"mode\":\"merge_same_rule\",\"first_admission_event\":"<<first_event<<",\"last_admission_event\":"<<events.size()<<",\"before\":"<<members_json(before)<<",\"after\":"<<members_json(population)<<'}';refresh_traces.push_back(trace.str());}
  }
  validate();if(archive.empty()||used>maximum)throw std::runtime_error("invalid final search state");
 }
 void emit_population(int round)const{
  std::ostringstream captured;auto* saved=std::cout.rdbuf(captured.rdbuf());phase9::Search::emit("population",round);std::cout.rdbuf(saved);
  std::string base=captured.str();while(!base.empty()&&(base.back()=='\n'||base.back()=='\r'))base.pop_back();if(base.empty()||base.back()!='}')throw std::runtime_error("invalid base JSON");base.pop_back();
  std::cout<<base<<",\"population_minimum_distance\":"<<minimum_distance<<",\"offspring_completed\":"<<offspring_completed<<",\"population_refreshes\":"<<refreshes<<",\"final_population\":"<<members_json(population)<<",\"population_events\":[";
  for(std::size_t i=0;i<events.size();++i){if(i)std::cout<<',';std::cout<<events[i];}std::cout<<"],\"parent_choices\":[";for(std::size_t i=0;i<parents.size();++i){if(i)std::cout<<',';std::cout<<parents[i];}std::cout<<"],\"refresh_traces\":[";for(std::size_t i=0;i<refresh_traces.size();++i){if(i)std::cout<<',';std::cout<<refresh_traces[i];}std::cout<<"]}\n"<<std::flush;
 }
};
} //namespace phase10
int main(int argc,char**argv){try{
 if(argc!=11)throw std::runtime_error("population_search METHOD MODEL CT1 CT2 W1 W2 SEARCH_SEED CALLS SECONDS ROUND");
 std::string method=argv[1];Model model(argv[2]);Ms ct={read(argv[3]),read(argv[4])};int w1=std::stoi(argv[5]),w2=std::stoi(argv[6]);uint64_t seed=std::stoull(argv[7]);long cap=std::stol(argv[8]);double secs=std::stod(argv[9]);int round=std::stoi(argv[10]);
 if(ct[0].size()!=615||ct[1].size()!=160||w1<3||w1>160||w2<6||w2>160||cap<1||!(secs>0)||!std::isfinite(secs)||round<0||round>1)throw std::runtime_error("invalid inputs");
 if(method=="restart"){phase9::Search search(ct,model,w1,w2,seed,cap,secs);search.run(method);search.emit(method,round);}
 else if(method=="population"){phase10::PopulationSearch search(ct,model,w1,w2,seed,cap,secs);search.run_population();search.emit_population(round);}
 else throw std::runtime_error("restart or population required");return 0;
}catch(const std::exception&error){std::cerr<<error.what()<<'\n';return 1;}}

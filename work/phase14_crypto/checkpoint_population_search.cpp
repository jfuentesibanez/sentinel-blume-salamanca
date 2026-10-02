// CrypTool 2 source movements: Apache-2.0; phase10 classes imported exactly.
// New shared phase14 implementation. It never reads planted truth or searches K1.
#include "phase10_frozen_classes.h"
#include "sha256.h"
#include <map>

namespace phase14 {
using phase9::Key;
std::string quoted(const std::string& text){std::string out="\"";for(char c:text){if(c=='\\'||c=='\"')out+='\\';if(c=='\n')out+="\\n";else if(c=='\r')out+="\\r";else out+=c;}return out+'\"';}
std::string keys_json(const std::vector<Key>& values){std::ostringstream out;out<<std::setprecision(17)<<'[';for(std::size_t i=0;i<values.size();++i){if(i)out<<',';out<<"{\"numeric\":"<<keyjson(values[i].numeric)<<",\"idp\":"<<values[i].score<<'}';}return out.str()+']';}
std::string members_precise(const std::vector<phase10::Member>& members){std::ostringstream out;out<<std::setprecision(17)<<'[';for(std::size_t i=0;i<members.size();++i){if(i)out<<',';const auto& m=members[i];out<<"{\"id\":"<<m.id<<",\"numeric\":"<<keyjson(m.key.numeric)<<",\"idp\":"<<m.key.score<<",\"uses\":"<<m.uses<<'}';}return out.str()+']';}
std::string rng_state(const RNG& rng){std::ostringstream out;out<<rng;return out.str();}
struct Context { std::string stage="none";long parent=-1;bool checkpoint_ancestry=false; };
struct Outcome {Key key;std::string status,stop_reason;bool convergence_observed=false;long calls=0;int number=0;};
struct Pool {std::vector<Key> survivors;bool completed=false;};
struct CheckpointSearch : phase10::PopulationSearch {
 const long local_cap,checkpoint_at;const bool merge;
 const uint64_t checkpoint_seed;
 bool checkpoint_started=false,checkpoint_completed=false;
 int checkpoint_starts=0,offspring_processed=0,offspring_partial=0,convergences_observed=0;
 long checkpoint_pool_calls=0,checkpoint_swap_calls=0;
 Context context;std::map<long,Context> lineage;
 Sha256 score_sequence;
 std::vector<std::string> archive_events,preparations,children,offer_metadata;
 std::string pre_checkpoint="null",checkpoint_trace="null";
 CheckpointSearch(const Ms& ct,const Model& m,int w1,int w2,uint64_t s,long budget,double secs,long local,bool fuse,long boundary=50000)
  :phase10::PopulationSearch(ct,m,w1,w2,s,budget,secs),local_cap(local),checkpoint_at(boundary),merge(fuse),checkpoint_seed(s^UINT64_C(0x6a09e667f3bcc909)){}
 bool global(const std::string& phase){if(cut)return true;bool e=used>=maximum,t=phase9::seconds(start)>limit;if(e||t){cut=true;cause=e&&t?"evaluations_and_wall_time":e?"evaluations":"wall_time";terminal_phase=phase;}return cut;}
 bool checkpoint_due()const{return !checkpoint_started&&used>=checkpoint_at;}
 // Static inherited evaluate() would bypass these audit hooks. Every new path
 // calls this method explicitly; the frozen objective and call meters stay intact.
 bool score(const V& numeric,Key& result,const std::string& phase){
  if(global(phase))return false;
  const auto before=archive;
  if(!phase9::Search::evaluate(numeric,result,phase))return false;
  const uint64_t kind=phase=="random_pool"?1:phase=="left_to_right_swaps"?2:phase=="source_hill_climb"?3:4;
  score_sequence.integer(used);score_sequence.integer(kind);score_sequence.integer(numeric.size());for(int x:numeric)score_sequence.integer(x);score_sequence.floating(result.score);
  if(context.stage=="checkpoint_pool"){if(phase=="random_pool")++checkpoint_pool_calls;else if(phase=="left_to_right_swaps")++checkpoint_swap_calls;}
  bool changed=before.size()!=archive.size();for(std::size_t i=0;i<before.size()&&!changed;++i)changed=before[i].numeric!=archive[i].numeric;
  if(changed){int rank=-1;for(std::size_t i=0;i<archive.size();++i)if(archive[i].numeric==result.numeric)rank=i+1;
   if(rank<1)throw std::runtime_error("archive changed without entered candidate");
   std::ostringstream event;event<<std::setprecision(17)<<"{\"number\":"<<archive_events.size()+1<<",\"objective_calls\":"<<used<<",\"stage\":"<<quoted(context.stage)<<",\"parent_id\":"<<context.parent<<",\"checkpoint_ancestry\":"<<(context.checkpoint_ancestry?"true":"false")<<",\"entered_rank\":"<<rank<<",\"numeric\":"<<keyjson(result.numeric)<<",\"k2\":"<<keyjson(inverse(result.numeric))<<",\"idp\":"<<result.score<<",\"archive_after\":"<<keys_json(archive)<<'}';archive_events.push_back(event.str());
  }
  return true;
 }
 // Generating and scoring does not alter parents, IDs, usages or event sequence.
 Pool make_pool(RNG& generator,const std::string& stage){
  ++restart_starts;long began=used,pool_before=pool_calls,swaps_before=swap_calls;auto began_time=phase9::Clock::now();const std::string rng_before=rng_state(generator);context={stage,-1,stage=="checkpoint_pool"};
  std::vector<Key> retained,random_keys;
  for(int i=0;i<1000;++i){if(global("random_pool"))break;Key value;if(!score(perm(w2,generator),value,"random_pool"))break;random_keys.push_back(value);retained.push_back(value);std::sort(retained.begin(),retained.end(),phase9::preferred);if(retained.size()>20)retained.resize(20);}
  for(auto& item:retained){Key current=item;for(int i=0;i<w2-1&&!cut;++i)for(int j=i+1;j<w2;++j){if(global("left_to_right_swaps"))break;V proposed=current.numeric;std::swap(proposed[i],proposed[j]);Key value;if(!score(proposed,value,"left_to_right_swaps"))break;if(value.score>current.score+1e-12)current=value;}item=current;}
  std::sort(retained.begin(),retained.end(),phase9::preferred);
  const long expected=1000+20L*w2*(w2-1)/2;bool completed=pool_calls-pool_before==1000&&swap_calls-swaps_before==expected-1000;
  if(completed)++restart_completions;
  global(stage); // A final completed call can exhaust the global budget/time.
  std::ostringstream trace;trace<<std::setprecision(17)<<"{\"kind\":\"preparation\",\"stage\":"<<quoted(stage)<<",\"number\":"<<restart_starts<<",\"calls_before\":"<<began<<",\"calls_after\":"<<used<<",\"calls\":"<<used-began<<",\"expected_calls\":"<<expected<<",\"random_pool_calls\":"<<pool_calls-pool_before<<",\"swap_calls\":"<<swap_calls-swaps_before<<",\"completed\":"<<(completed?"true":"false")<<",\"global_cut\":"<<(cut?"true":"false")<<",\"seconds\":"<<phase9::seconds(began_time)<<",\"rng_before\":"<<quoted(rng_before)<<",\"rng_after\":"<<quoted(rng_state(generator))<<",\"random_keys\":"<<keys_json(random_keys)<<",\"survivors\":"<<keys_json(retained)<<'}';preparations.push_back(trace.str());
  return {retained,completed};
 }
 bool offer(const Key& candidate,const std::string& origin,const Context& provenance){
  if(global("population_admission"))return false;
  if(candidate.numeric.size()!=static_cast<std::size_t>(w2))throw std::runtime_error("offering empty/invalid candidate");
  auto sorted=candidate.numeric;std::sort(sorted.begin(),sorted.end());for(int i=0;i<w2;++i)if(sorted[i]!=i)throw std::runtime_error("offering non-permutation");
  if(!std::isfinite(candidate.score))throw std::runtime_error("offering non-finite score");
  auto before=population;phase10::PopulationSearch::admit(candidate,origin);
  for(const auto& member:population)if(std::none_of(before.begin(),before.end(),[&](const phase10::Member& p){return p.id==member.id;}))lineage[member.id]=provenance;
  std::ostringstream precise;precise<<std::setprecision(17)<<"{\"event_number\":"<<events.size()<<",\"sequence\":"<<action_sequence<<",\"objective_calls\":"<<used<<",\"origin\":"<<quoted(origin)<<",\"candidate_numeric\":"<<keyjson(candidate.numeric)<<",\"candidate_idp\":"<<candidate.score<<",\"checkpoint_ancestry\":"<<(provenance.checkpoint_ancestry?"true":"false")<<",\"before\":"<<members_precise(before)<<",\"after\":"<<members_precise(population)<<'}';offer_metadata.push_back(precise.str());return true;
 }
 std::string snapshot()const{
  Sha256 moves;for(const auto& movement:movements)for(int x:movement.p) moves.integer(x);
  std::ostringstream out;out<<"{\"objective_calls\":"<<used<<",\"score_sequence_sha256\":"<<quoted(score_sequence.hex())<<",\"rng\":"<<quoted(rng_state(rng))<<",\"movement_order_sha256\":"<<quoted(moves.hex())<<",\"archive\":"<<keys_json(archive)<<",\"population\":"<<members_precise(population)<<",\"next_id\":"<<next_id<<",\"action_sequence\":"<<action_sequence<<",\"offspring_processed\":"<<offspring_processed<<",\"climb_starts\":"<<climb_starts<<",\"climb_completions\":"<<climb_completions<<",\"parent_choices\":"<<parents.size()<<'}';return out.str();
 }
 Outcome bounded_climb(Key current,const std::string& role){
  ++climb_starts;const int number=climb_starts;const long began=used;auto clock=phase9::Clock::now();const Key initial=current;
  int sweeps=0,complete_sweeps=0;long last_proposals=0;bool last_improved=false,convergence=false;std::string reason;
  auto boundary=[&](){if(global("source_hill_climb"))return std::string("global_cut");if(checkpoint_due())return std::string("checkpoint");if(used-began>=local_cap)return std::string("cap_local");if(convergence)return std::string("converged");return std::string();};
  context.stage=role+"_climb";
  while(reason.empty()){
   reason=boundary();if(!reason.empty())break; // Never shuffle a zero-proposal sweep.
   ++sweeps;last_proposals=0;last_improved=false;std::shuffle(movements.begin(),movements.end(),rng);
   for(const auto& movement:movements){
    Key value;if(!score(moved(current.numeric,movement),value,"source_hill_climb")){reason="global_cut";break;}
    ++last_proposals;if(value.score>current.score+1e-12){current=value;last_improved=true;}
    if(last_proposals==static_cast<long>(movements.size())){++complete_sweeps;convergence=!last_improved;}
    reason=boundary();if(!reason.empty())break; // Last score updates current first.
   }
  }
  if(convergence)++convergences_observed;if(convergence&&!cut)++climb_completions;
  const std::string status=cut?"global_cut":convergence?"converged":reason=="checkpoint"?"partial_checkpoint":"cap_local";
  if(reason=="cap_local"&&(cut||used-began!=local_cap))throw std::runtime_error("local cap invariant");
  if(reason=="checkpoint"&&(cut||used!=checkpoint_at))throw std::runtime_error("checkpoint boundary invariant");
  if(convergence&&(last_proposals!=static_cast<long>(movements.size())||last_improved))throw std::runtime_error("incomplete convergence");
  std::ostringstream trace;trace<<std::setprecision(17)<<"{\"kind\":\"hill_climb\",\"number\":"<<number<<",\"role\":"<<quoted(role)<<",\"calls_before\":"<<began<<",\"calls_after\":"<<used<<",\"calls\":"<<used-began<<",\"seconds\":"<<phase9::seconds(clock)<<",\"local_proposal_cap\":"<<local_cap<<",\"sweeps\":"<<sweeps<<",\"complete_sweeps\":"<<complete_sweeps<<",\"last_sweep_proposals\":"<<last_proposals<<",\"last_sweep_improved\":"<<(last_improved?"true":"false")<<",\"source_move_count\":"<<movements.size()<<",\"status\":"<<quoted(status)<<",\"stop_reason\":"<<quoted(reason)<<",\"convergence_observed\":"<<(convergence?"true":"false")<<",\"partial\":"<<(convergence?"false":"true")<<",\"global_cut\":"<<(cut?"true":"false")<<",\"initial_numeric\":"<<keyjson(initial.numeric)<<",\"final_numeric\":"<<keyjson(current.numeric)<<",\"initial_idp\":"<<initial.score<<",\"final_idp\":"<<current.score<<'}';traces.push_back(trace.str());return {current,status,reason,convergence,used-began,number};
 }
 void checkpoint(){
  if(!checkpoint_due()||used!=checkpoint_at||checkpoint_started||global("checkpoint_start"))return;
  pre_checkpoint=snapshot();checkpoint_started=true;++checkpoint_starts;
  auto before=population;long first_event=events.size()+1;const auto main_rng_before=rng_state(rng);
  RNG separate(checkpoint_seed);auto pool=make_pool(separate,"checkpoint_pool");checkpoint_completed=pool.completed;
  if(pool.completed&&!cut&&merge)for(const auto& candidate:pool.survivors){if(global("checkpoint_admission"))break;offer(candidate,"checkpoint_prepared_survivor",{"checkpoint_pool",-1,true});}
  if(rng_state(rng)!=main_rng_before)throw std::runtime_error("checkpoint consumed main RNG");
  std::ostringstream trace;trace<<"{\"calls_before\":"<<checkpoint_at<<",\"calls_after\":"<<used<<",\"completed\":"<<(pool.completed?"true":"false")<<",\"merge_enabled\":"<<(merge?"true":"false")<<",\"offers\":"<<events.size()+1-first_event<<",\"first_admission_event\":"<<(events.size()+1>static_cast<std::size_t>(first_event)?first_event:-1)<<",\"main_rng_unchanged\":true,\"before\":"<<members_precise(before)<<",\"after\":"<<members_precise(population)<<'}';checkpoint_trace=trace.str();
 }
 Key perturb_parent(){
  if(population.empty())throw std::runtime_error("empty parents");
  auto selected=std::min_element(population.begin(),population.end(),[](const phase10::Member& a,const phase10::Member& b){return a.uses!=b.uses?a.uses<b.uses:phase9::preferred(a.key,b.key);});
  const int before=selected->uses;const long id=selected->id;const Key base=selected->key;++selected->uses;context=lineage.at(id);context.parent=id;context.stage="offspring_perturbation";
  std::ostringstream choice;choice<<"{\"number\":"<<parents.size()+1<<",\"sequence\":"<<++action_sequence<<",\"objective_calls\":"<<used<<",\"selected_id\":"<<id<<",\"uses_before\":"<<before<<",\"uses_after\":"<<selected->uses<<",\"checkpoint_ancestry\":"<<(context.checkpoint_ancestry?"true":"false")<<",\"population_after_use\":"<<members_precise(population)<<'}';parents.push_back(choice.str());
  ++kick_attempts;const int changed=2*((minimum_distance+1)/2);V positions(w2);std::iota(positions.begin(),positions.end(),0);std::shuffle(positions.begin(),positions.end(),rng);positions.resize(changed);V candidate=base.numeric;for(int pair=0;pair<changed/2;++pair)std::swap(candidate[positions[2*pair]],candidate[positions[2*pair+1]]);
  if(phase10::distance(base.numeric,candidate)!=changed)throw std::runtime_error("perturbation invariant");
  Key value;const bool scored=score(candidate,value,"perturbation");if(scored)++kick_scored;
  std::ostringstream trace;trace<<std::setprecision(17)<<"{\"number\":"<<kick_attempts<<",\"parent_id\":"<<id<<",\"objective_calls\":"<<used<<",\"positions\":"<<keyjson(positions)<<",\"base_numeric\":"<<keyjson(base.numeric)<<",\"perturbed_numeric\":"<<keyjson(candidate)<<",\"hamming_distance\":"<<changed<<",\"scored\":"<<(scored?"true":"false");if(scored)trace<<",\"idp\":"<<value.score;trace<<'}';kicks.push_back(trace.str());return value;
 }
 void terminate_candidate(const Outcome& result,const std::string& role,bool climb_started){
  const bool cut_before=cut;
  const bool offered=offer(result.key,role+(result.convergence_observed?"_local_optimum":"_"+result.status),context);
  const long event=offered?static_cast<long>(events.size()):-1;
  if(role=="offspring"){
   ++offspring_processed;if(result.status=="converged")++offspring_completed;else ++offspring_partial;
   std::ostringstream trace;trace<<std::setprecision(17)<<"{\"number\":"<<offspring_processed<<",\"perturbation_number\":"<<kick_attempts<<",\"climb_started\":"<<(climb_started?"true":"false")<<",\"climb_number\":"<<result.number<<",\"hill_calls\":"<<result.calls<<",\"status\":"<<quoted(result.status)<<",\"stop_reason\":"<<quoted(result.stop_reason)<<",\"convergence_observed\":"<<(result.convergence_observed?"true":"false")<<",\"global_cut_after_return\":"<<(cut?"true":"false")<<",\"cut_during_admission_guard\":"<<(!cut_before&&cut?"true":"false")<<",\"offered\":"<<(offered?"true":"false")<<",\"admission_event\":"<<event<<",\"parent_id\":"<<context.parent<<",\"checkpoint_ancestry\":"<<(context.checkpoint_ancestry?"true":"false")<<",\"candidate_numeric\":"<<keyjson(result.key.numeric)<<",\"candidate_idp\":"<<result.key.score<<'}';children.push_back(trace.str());
  }
 }
 void run_checkpoint_population(){
  auto pool=make_pool(rng,"initial_pool");
  if(pool.completed&&!cut){for(const auto& candidate:pool.survivors){if(global("initial_admission"))break;offer(candidate,"initial_prepared_survivor",{"initial_pool",-1,false});}if(!cut){context={"initial_climb",-1,false};auto initial=bounded_climb(pool.survivors.front(),"initial");terminate_candidate(initial,"initial",true);}}
  while(!cut){
   if(global("iteration_boundary"))break;
   if(checkpoint_due()){checkpoint();continue;}
   Key perturbed=perturb_parent();if(cut)break;
   if(global("after_perturbation")){terminate_candidate({perturbed,"perturbation_only_global_cut","global_cut",false,0,0},"offspring",false);break;}
   if(checkpoint_due()){terminate_candidate({perturbed,"perturbation_only_checkpoint","checkpoint",false,0,0},"offspring",false);continue;}
   auto result=bounded_climb(perturbed,"offspring");terminate_candidate(result,"offspring",true);
  }
  validate();if(used>maximum||checkpoint_starts>1||used!=pool_calls+swap_calls+climb_calls+kick_calls)throw std::runtime_error("metering invariant");
 }
 void emit_checkpoint(int round)const{
  std::ostringstream captured;auto* previous=std::cout.rdbuf(captured.rdbuf());phase9::Search::emit("checkpoint_population",round);std::cout.rdbuf(previous);std::string base=captured.str();while(!base.empty()&&(base.back()=='\n'||base.back()=='\r'))base.pop_back();if(base.empty()||base.back()!='}')throw std::runtime_error("invalid JSON");base.pop_back();
  std::cout<<base<<",\"local_proposal_cap\":"<<local_cap<<",\"checkpoint_merge\":"<<(merge?"true":"false")<<",\"checkpoint_at\":"<<checkpoint_at<<",\"checkpoint_seed\":"<<checkpoint_seed<<",\"checkpoint_started\":"<<(checkpoint_started?"true":"false")<<",\"checkpoint_completed\":"<<(checkpoint_completed?"true":"false")<<",\"checkpoint_starts\":"<<checkpoint_starts<<",\"checkpoint_due_at_global_cut\":"<<(checkpoint_due()?"true":"false")<<",\"checkpoint_random_pool_calls\":"<<checkpoint_pool_calls<<",\"checkpoint_swap_calls\":"<<checkpoint_swap_calls<<",\"periodic_refreshes\":0,\"population_minimum_distance\":"<<minimum_distance<<",\"source_move_count\":"<<movements.size()<<",\"offspring_processed\":"<<offspring_processed<<",\"offspring_completed\":"<<offspring_completed<<",\"offspring_partial\":"<<offspring_partial<<",\"convergences_observed\":"<<convergences_observed<<",\"score_sequence_sha256\":"<<quoted(score_sequence.hex())<<",\"pre_checkpoint\":"<<pre_checkpoint<<",\"checkpoint_trace\":"<<checkpoint_trace<<",\"final_population\":"<<members_precise(population);
  auto array=[&](const char* name,const std::vector<std::string>& entries){std::cout<<",\""<<name<<"\":[";for(std::size_t i=0;i<entries.size();++i){if(i)std::cout<<',';std::cout<<entries[i];}std::cout<<']';};
  array("preparations",preparations);array("population_events",events);array("offer_metadata",offer_metadata);array("parent_choices",parents);array("offspring_traces",children);array("archive_events",archive_events);std::cout<<"}\n"<<std::flush;
 }
};
}
#ifndef PHASE14_NO_MAIN
int main(int argc,char** argv){try{
 if(argc!=13)throw std::runtime_error("checkpoint_population_search MODEL CT1 CT2 W1 W2 SEARCH_SEED CALLS SECONDS ROUND LOCAL_CAP MERGE CHECKPOINT_AT");
 Model model(argv[1]);Ms ct={read(argv[2]),read(argv[3])};int w1=std::stoi(argv[4]),w2=std::stoi(argv[5]);uint64_t seed=std::stoull(argv[6]);long calls=std::stol(argv[7]);double secs=std::stod(argv[8]);int round=std::stoi(argv[9]);long local=std::stol(argv[10]);int merge=std::stoi(argv[11]);long checkpoint=std::stol(argv[12]);
 if(ct[0].size()!=615||ct[1].size()!=160||w1!=20||w2!=25||calls!=100000||secs!=30||round<0||round>1||(local!=5000&&local!=33298)||(merge!=0&&merge!=1)||checkpoint!=50000)throw std::runtime_error("fixed phase14 inputs/budgets required");
 phase14::CheckpointSearch search(ct,model,w1,w2,seed,calls,secs,local,merge!=0,checkpoint);search.run_checkpoint_population();search.emit_checkpoint(round);return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
#endif

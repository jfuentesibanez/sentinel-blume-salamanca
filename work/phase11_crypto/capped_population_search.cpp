// CrypTool 2 source movements: Apache-2.0; frozen classes imported exactly.
#include "phase10_frozen_classes.h"

namespace phase11 {
using phase9::Key;
struct Outcome { Key key; std::string status; int number; };
struct CappedPopulationSearch : phase10::PopulationSearch {
 static constexpr long local_cap=5000;
 int offspring_processed=0,offspring_partial=0;
 bool refresh_due_at_global_cut=false;
 std::vector<std::string> child_traces;
 CappedPopulationSearch(const Ms& ct,const Model& m,int w1,int w2,uint64_t s,long cap,double secs)
  :phase10::PopulationSearch(ct,m,w1,w2,s,cap,secs){}
 Outcome capped_climb(Key current,const std::string& role){
  ++climb_starts;const int number=climb_starts;const long began=used;
  auto clock=phase9::Clock::now();const Key initial=current;
  int sweeps=0,complete_sweeps=0;long last_sweep_proposals=0;
  bool last_sweep_improved=false;std::string status;
  while(status.empty()){
   ++sweeps;last_sweep_proposals=0;last_sweep_improved=false;
   std::shuffle(movements.begin(),movements.end(),rng);
   for(const auto& movement:movements){
    // Before a next proposal, exhausted global limits take priority over local.
    const bool eval_cut=used>=maximum,time_cut=phase9::seconds(start)>limit;
    if(eval_cut||time_cut){cut=true;cause=eval_cut&&time_cut?"evaluations_and_wall_time":eval_cut?"evaluations":"wall_time";terminal_phase="source_hill_climb";status="global_cut";break;}
    // The local limit has no effect on the global cut flag or cause.
    if(used-began>=local_cap){status="cap_local";break;}
    Key value;
    if(!evaluate(moved(current.numeric,movement),value,"source_hill_climb")){status="global_cut";break;}
    ++last_sweep_proposals;
    if(value.score>current.score+1e-12){current=value;last_sweep_improved=true;}
   }
   if(!status.empty())break;
   ++complete_sweeps;
   if(!last_sweep_improved)status="converged";
  }
  const bool converged=status=="converged";
  if(converged)++climb_completions;
  if(status=="cap_local"&&(cut||used-began!=local_cap))throw std::runtime_error("local cap changed global cut");
  if(status=="global_cut"&&!cut)throw std::runtime_error("missing global cut");
  if(converged&&last_sweep_proposals!=static_cast<long>(movements.size()))throw std::runtime_error("incomplete convergence sweep");
  std::ostringstream trace;trace<<std::setprecision(12)
   <<"{\"kind\":\"hill_climb\",\"number\":"<<number<<",\"role\":\""<<role
   <<"\",\"calls\":"<<used-began<<",\"calls_before\":"<<began<<",\"calls_after\":"<<used
   <<",\"seconds\":"<<phase9::seconds(clock)<<",\"sweeps\":"<<sweeps
   <<",\"complete_sweeps\":"<<complete_sweeps<<",\"last_sweep_proposals\":"<<last_sweep_proposals
   <<",\"last_sweep_improved\":"<<(last_sweep_improved?"true":"false")
   <<",\"source_move_count\":"<<movements.size()<<",\"local_proposal_cap\":"<<local_cap
   <<",\"status\":\""<<status<<"\",\"stop_reason\":\""<<status
   <<"\",\"converged\":"<<(converged?"true":"false")<<",\"partial\":"<<(converged?"false":"true")
   <<",\"completed\":"<<(converged?"true":"false")<<",\"global_cut\":"<<(cut?"true":"false")
   <<",\"initial_numeric\":"<<keyjson(initial.numeric)<<",\"final_numeric\":"<<keyjson(current.numeric)
   <<",\"initial_idp\":"<<initial.score<<",\"final_idp\":"<<current.score<<'}';
  traces.push_back(trace.str());return {current,status,number};
 }
 std::string origin(const std::string& role,const Outcome& outcome)const{
  return role+(outcome.status=="converged"?"_local_optimum":outcome.status=="cap_local"?"_partial_cap_local":"_partial_global_cut");
 }
 void run_capped_population(){
  Key initial=prepare();
  if(!cut){auto outcome=capped_climb(initial,"initial");if(!cut)admit(outcome.key,origin("initial",outcome));}
  while(!cut){
   Key perturbed=kick_parent();if(cut)break;
   auto outcome=capped_climb(perturbed,"offspring");
   ++offspring_processed;
   if(outcome.status=="converged")++offspring_completed;else ++offspring_partial;
   const long event_number=cut?-1:events.size()+1;
   // Preserve the baseline terminal rule: a global-cut return is not offered.
   if(!cut)admit(outcome.key,origin("offspring",outcome));
   const bool due=offspring_processed%4==0;
   const bool perform_refresh=due&&!cut;
   if(due&&cut)refresh_due_at_global_cut=true;
   std::ostringstream child;child<<std::setprecision(12)
    <<"{\"number\":"<<offspring_processed<<",\"climb_number\":"<<outcome.number
    <<",\"status\":\""<<outcome.status<<"\",\"partial\":"<<(outcome.status=="converged"?"false":"true")
    <<",\"candidate_numeric\":"<<keyjson(outcome.key.numeric)<<",\"candidate_idp\":"<<outcome.key.score
    <<",\"offered\":"<<(cut?"false":"true")<<",\"admission_event\":"<<event_number
    <<",\"refresh_due\":"<<(due?"true":"false")<<",\"refresh_started\":"<<(perform_refresh?"true":"false")
    <<",\"global_cut_after_climb\":"<<(cut?"true":"false")<<'}';
   child_traces.push_back(child.str());
   if(cut)break;
   if(perform_refresh){
    ++refreshes;auto before=population;long began=used,first_event=events.size()+1;
    prepare();std::ostringstream trace;trace
     <<"{\"number\":"<<refreshes<<",\"offspring_processed\":"<<offspring_processed
     <<",\"offspring_completed\":"<<offspring_completed<<",\"objective_calls_before\":"<<began
     <<",\"objective_calls_after\":"<<used<<",\"completed\":"<<(cut?"false":"true")
     <<",\"mode\":\"merge_same_rule\",\"first_admission_event\":"<<first_event
     <<",\"last_admission_event\":"<<events.size()<<",\"before\":"<<phase10::members_json(before)
     <<",\"after\":"<<phase10::members_json(population)<<'}';refresh_traces.push_back(trace.str());
   }
  }
  validate();if(archive.empty()||used>maximum)throw std::runtime_error("invalid final search state");
 }
 void emit_capped_population(int round)const{
  std::ostringstream captured;auto* saved=std::cout.rdbuf(captured.rdbuf());
  phase9::Search::emit("cap5000",round);std::cout.rdbuf(saved);
  std::string base=captured.str();while(!base.empty()&&(base.back()=='\n'||base.back()=='\r'))base.pop_back();
  if(base.empty()||base.back()!='}')throw std::runtime_error("invalid base JSON");base.pop_back();
  std::cout<<base<<",\"local_proposal_cap\":"<<local_cap<<",\"source_move_count\":"<<movements.size()
   <<",\"population_minimum_distance\":"<<minimum_distance<<",\"offspring_processed\":"<<offspring_processed
   <<",\"offspring_completed\":"<<offspring_completed<<",\"offspring_partial\":"<<offspring_partial
   <<",\"refresh_due_at_global_cut\":"<<(refresh_due_at_global_cut?"true":"false")
   <<",\"population_refreshes\":"<<refreshes<<",\"final_population\":"<<phase10::members_json(population)
   <<",\"population_events\":[";
  for(std::size_t i=0;i<events.size();++i){if(i)std::cout<<',';std::cout<<events[i];}
  std::cout<<"],\"parent_choices\":[";for(std::size_t i=0;i<parents.size();++i){if(i)std::cout<<',';std::cout<<parents[i];}
  std::cout<<"],\"refresh_traces\":[";for(std::size_t i=0;i<refresh_traces.size();++i){if(i)std::cout<<',';std::cout<<refresh_traces[i];}
  std::cout<<"],\"offspring_traces\":[";for(std::size_t i=0;i<child_traces.size();++i){if(i)std::cout<<',';std::cout<<child_traces[i];}
  std::cout<<"]}\n"<<std::flush;
 }
};
} // namespace phase11
int main(int argc,char**argv){try{
 if(argc!=11)throw std::runtime_error("capped_population_search cap5000 MODEL CT1 CT2 W1 W2 SEARCH_SEED CALLS SECONDS ROUND");
 if(std::string(argv[1])!="cap5000")throw std::runtime_error("cap5000 required");
 Model model(argv[2]);Ms ct={read(argv[3]),read(argv[4])};int w1=std::stoi(argv[5]),w2=std::stoi(argv[6]);
 uint64_t seed=std::stoull(argv[7]);long cap=std::stol(argv[8]);double secs=std::stod(argv[9]);int round=std::stoi(argv[10]);
 if(ct[0].size()!=615||ct[1].size()!=160||w1<3||w1>160||w2<6||w2>160||cap<1||!(secs>0)||!std::isfinite(secs)||round<0||round>1)throw std::runtime_error("invalid inputs");
 phase11::CappedPopulationSearch search(ct,model,w1,w2,seed,cap,secs);search.run_capped_population();search.emit_capped_population(round);return 0;
}catch(const std::exception&error){std::cerr<<error.what()<<'\n';return 1;}}

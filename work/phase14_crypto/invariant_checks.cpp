// Small structural controls only: uniform model + periodic input, no planted keys.
#define PHASE14_NO_MAIN
#include "checkpoint_population_search.cpp"
using phase14::CheckpointSearch;using phase14::Outcome;
void require(bool value,const char* explanation){if(!value)throw std::runtime_error(explanation);}
int main(int argc,char** argv){try{
 if(argc!=3)throw std::runtime_error("invariant_checks SCENARIO UNIFORM_MODEL");
 const std::string scenario=argv[1];Model model(argv[2]);Ms ct;for(int length:{615,160}){V text;for(int i=0;i<length;++i)text.push_back(i%26);ct.push_back(text);}
 if(scenario=="sha"){
  require(phase14::text_sha256("")=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","SHA empty");
  require(phase14::text_sha256("abc")=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","SHA abc");
  phase14::Sha256 stream;std::string a(1000,'a');for(int i=0;i<1000;++i)stream.update(a.data(),a.size());require(stream.hex()=="cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0","SHA million a");
  std::cout<<"{\"scenario\":\"sha\",\"status\":\"passed\",\"objective_calls\":0}\n";return 0;
 }
 long local=7,checkpoint=2000,budget=4000;bool merge=false;bool pair=scenario.rfind("pair_",0)==0;
 if(pair){local=scenario.find("long")!=std::string::npos?10000:7;merge=scenario.substr(scenario.size()-3)=="_on";}
 auto movements=source_moves(6);const long sweep=movements.size();
 if(scenario=="perturbation_checkpoint"){checkpoint=1300+sweep+1;budget=checkpoint+10;local=10000;}
 if(scenario=="time_before_first"){CheckpointSearch search(ct,model,3,6,991,4000,1e-12,7,false,2000);search.run_checkpoint_population();require(search.used==0&&search.cut&&search.archive.empty()&&!search.checkpoint_started,"time before first score");search.emit_checkpoint(0);return 0;}
 CheckpointSearch search(ct,model,3,6,991,budget,10,local,merge,checkpoint);
 if(pair||scenario=="perturbation_checkpoint"){
  search.run_checkpoint_population();require(search.used==budget&&search.cause=="evaluations","exact global budget");require(search.checkpoint_starts==1,"single checkpoint");
  if(pair){require(search.checkpoint_completed&&search.checkpoint_pool_calls==1000&&search.checkpoint_swap_calls==300,"completed generic small-width pool cost");require(search.pre_checkpoint!="null","prefix snapshot");}
  else{require(!search.checkpoint_completed&&search.checkpoint_pool_calls==10&&search.checkpoint_swap_calls==0,"truncated checkpoint cost");require(search.children.front().find("perturbation_only_checkpoint")!=std::string::npos,"perturbation checkpoint label");require(search.children.front().find("\"climb_started\":false")!=std::string::npos,"no climb for perturbation-only");}
  require(search.offer_metadata.size()==search.events.size(),"precise metadata coverage");search.emit_checkpoint(0);return 0;
 }
 phase9::Key initial;V identity(6);std::iota(identity.begin(),identity.end(),0);
 if(scenario=="expired_offer"){
  require(search.score(identity,initial,"random_pool"),"one initial score");
  search.start=phase9::Clock::now()-std::chrono::seconds(11);bool offered=search.offer(initial,"test",{});require(!offered&&search.events.empty()&&search.cut&&search.cause=="wall_time","offer real time guard");
 }else if(scenario=="invalid_offers"){
  require(search.score(identity,initial,"random_pool"),"one initial score");
  int caught=0;for(int kind=0;kind<3;++kind){auto bad=initial;if(kind==0)bad.numeric.clear();if(kind==1)bad.numeric[0]=bad.numeric[1];if(kind==2)bad.score=std::numeric_limits<double>::infinity();try{search.offer(bad,"invalid",{});}catch(const std::exception&){++caught;}}require(caught==3&&search.events.empty(),"invalid offer guards");
 }else{
  long calls=2;std::string expected="cap_local";
  if(scenario=="global_all_tie"){search.maximum=3;expected="global_cut";}
  if(scenario=="checkpoint_cap_tie"||scenario=="global_all_tie"){expected=scenario=="global_all_tie"?"global_cut":"checkpoint";}
  if(scenario=="sweep_checkpoint"||scenario=="sweep_global"){calls=sweep;expected=scenario=="sweep_global"?"global_cut":"checkpoint";if(scenario=="sweep_global")search.maximum=1+sweep;}
  // Const configuration requires constructing a fresh object for each boundary.
  CheckpointSearch direct(ct,model,3,6,991,search.maximum,10,calls,false,expected=="cap_local"?2000:1+calls);
  require(direct.score(identity,initial,"random_pool"),"direct initial score");const auto rng_before=direct.rng;RNG expected_rng=rng_before;auto order=direct.movements;std::shuffle(order.begin(),order.end(),expected_rng);
  auto outcome=direct.bounded_climb(initial,"initial");require(outcome.stop_reason==expected&&outcome.calls==calls,"boundary priority and exact cap");require(direct.cut==(expected=="global_cut"),"local/checkpoint do not set global cut");require(phase14::rng_state(direct.rng)==phase14::rng_state(expected_rng),"no extra shuffle after boundary");
  if(scenario.rfind("sweep_",0)==0)require(outcome.convergence_observed&&outcome.status==(expected=="global_cut"?"global_cut":"converged"),"convergence evidence at boundary");else require(!outcome.convergence_observed,"incomplete sweep cannot converge");
  direct.terminate_candidate(outcome,"initial",true);require(direct.events.size()==static_cast<std::size_t>(expected=="global_cut"?0:1),"one or zero terminal offer");
  direct.emit_checkpoint(0);return 0;
 }
 search.emit_checkpoint(0);return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}

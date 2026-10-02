// Artificial incumbent score for a control of last-proposal state propagation.
// No truth/key recovery experiment; separate from the principal solver CLI.
#define PHASE14_NO_MAIN
#include "checkpoint_population_search.cpp"
int main(int argc,char** argv){try{
 if(argc!=3)throw std::runtime_error("last_score_fixture cap/checkpoint/global UNIFORM_MODEL");
 std::string mode=argv[1];Model model(argv[2]);Ms ct;for(int length:{615,160}){V text;for(int i=0;i<length;++i)text.push_back(i%26);ct.push_back(text);}
 phase14::CheckpointSearch search(ct,model,3,6,991,mode=="global"?2:100,10,1,false,mode=="cap"?99:2);
 V key(6);std::iota(key.begin(),key.end(),0);phase9::Key initial;
 if(!search.score(key,initial,"random_pool"))throw std::runtime_error("initial score failed");
 const double real_score=initial.score;initial.score-=1.0;
 auto result=search.bounded_climb(initial,"initial");
 const std::string expected=mode=="cap"?"cap_local":mode=="checkpoint"?"checkpoint":"global_cut";
 if(result.calls!=1||search.used!=2||result.stop_reason!=expected||result.convergence_observed||result.key.score!=real_score||result.key.numeric==key)throw std::runtime_error("last scored proposal did not update incumbent");
 if(std::none_of(search.archive.begin(),search.archive.end(),[&](const phase9::Key& item){return item.numeric==result.key.numeric&&item.score==real_score;}))throw std::runtime_error("last score absent from archive");
 search.emit_checkpoint(0);return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}

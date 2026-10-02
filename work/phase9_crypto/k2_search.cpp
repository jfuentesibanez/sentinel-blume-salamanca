// Copyright (C) CrypTool 2 Team; source movements adapted under Apache-2.0.
// Phase9: objective-budgeted restart vs iterated hill climbing, ciphertext only.
#include "../phase4_crypto/source_moves.h"

namespace phase9 {
using Clock = std::chrono::steady_clock;
double seconds(Clock::time_point start) { return std::chrono::duration<double>(Clock::now()-start).count(); }
struct Key { double score = -1e100; V numeric; };
bool preferred(const Key& a, const Key& b) { return a.score != b.score ? a.score > b.score : a.numeric < b.numeric; }
struct Search {
    const Ms& ciphertext;
    const Model& model;
    int w1, w2;
    uint64_t seed;
    long maximum, used=0, pool_calls=0, swap_calls=0, climb_calls=0, kick_calls=0;
    double limit;
    Clock::time_point start=Clock::now();
    bool cut=false;
    std::string cause="none", terminal_phase="none";
    RNG rng;
    std::vector<Move> movements;
    std::vector<Key> archive;
    int restart_starts=0,restart_completions=0,climb_starts=0,climb_completions=0,kick_attempts=0,kick_scored=0,stagnation_restarts=0;
    std::vector<std::string> traces,kicks;
    double setup_seconds=0;
    Search(const Ms& ct,const Model& m,int width1,int width2,uint64_t s,long cap,double sec)
        :ciphertext(ct),model(m),w1(width1),w2(width2),seed(s),maximum(cap),limit(sec),rng(s) {
        // start precedes movement construction, which is included in the limit.
        movements=source_moves(w2); setup_seconds=seconds(start);
    }
    void remember(const Key& key) {
        for(const auto& previous:archive) if(previous.numeric==key.numeric) return;
        archive.push_back(key);std::sort(archive.begin(),archive.end(),preferred);
        if(archive.size()>5)archive.resize(5);
    }
    bool evaluate(const V& numeric,Key& result,const std::string& phase) {
        const bool eval_cut=used>=maximum, time_cut=seconds(start)>limit;
        if(eval_cut||time_cut){cut=true;cause=eval_cut&&time_cut?"evaluations_and_wall_time":eval_cut?"evaluations":"wall_time";terminal_phase=phase;return false;}
        ++used;
        result={idp(undo2(ciphertext,inverse(numeric),0),w1,0,model,-1,true),numeric};
        if(phase=="random_pool")++pool_calls;
        else if(phase=="left_to_right_swaps")++swap_calls;
        else if(phase=="source_hill_climb")++climb_calls;
        else if(phase=="perturbation")++kick_calls;
        else throw std::runtime_error("unknown objective phase");
        remember(result);return true;
    }
    Key initialize() {
        ++restart_starts;const long began=used;auto clock=Clock::now();
        std::vector<Key> pool;
        for(int i=0;i<1000;++i){Key candidate;if(!evaluate(perm(w2,rng),candidate,"random_pool"))break;
            pool.push_back(candidate);std::sort(pool.begin(),pool.end(),preferred);if(pool.size()>20)pool.resize(20);}
        if(pool.empty())return {};
        for(auto& item:pool){Key current=item;
            for(int i=0;i<w2-1&&!cut;++i)for(int j=i+1;j<w2;++j){V candidate=current.numeric;std::swap(candidate[i],candidate[j]);Key value;
                if(!evaluate(candidate,value,"left_to_right_swaps"))break;
                if(value.score>current.score+1e-12)current=value;}
            item=current;}
        std::sort(pool.begin(),pool.end(),preferred);if(!cut)++restart_completions;
        std::ostringstream trace;trace<<std::setprecision(12)<<"{\"kind\":\"initialization\",\"number\":"<<restart_starts<<",\"calls\":"<<used-began<<",\"seconds\":"<<seconds(clock)<<",\"completed\":"<<(cut?"false":"true")<<",\"best_idp\":"<<pool[0].score<<'}';traces.push_back(trace.str());
        return pool[0];
    }
    Key climb(Key current) {
        ++climb_starts;const long began=used;auto clock=Clock::now();int sweeps=0;bool improved=true;
        const double before=current.score;
        while(improved&&!cut){improved=false;++sweeps;std::shuffle(movements.begin(),movements.end(),rng);
            for(const auto& movement:movements){Key value;if(!evaluate(moved(current.numeric,movement),value,"source_hill_climb"))break;
                if(value.score>current.score+1e-12){current=value;improved=true;}}
        }
        if(!cut)++climb_completions;
        std::ostringstream trace;trace<<std::setprecision(12)<<"{\"kind\":\"hill_climb\",\"number\":"<<climb_starts<<",\"calls\":"<<used-began<<",\"seconds\":"<<seconds(clock)<<",\"sweeps\":"<<sweeps<<",\"completed\":"<<(cut?"false":"true")<<",\"initial_idp\":"<<before<<",\"final_idp\":"<<current.score<<'}';traces.push_back(trace.str());
        return current;
    }
    Key perturb(const Key& incumbent) {
        ++kick_attempts;V positions(w2);std::iota(positions.begin(),positions.end(),0);std::shuffle(positions.begin(),positions.end(),rng);positions.resize(6);
        V candidate=incumbent.numeric;for(int pair=0;pair<3;++pair)std::swap(candidate[positions[2*pair]],candidate[positions[2*pair+1]]);
        int distance=0;for(int i=0;i<w2;++i)distance+=candidate[i]!=incumbent.numeric[i];
        if(distance!=6)throw std::runtime_error("perturbation must change exactly6positions");
        Key value;bool scored=evaluate(candidate,value,"perturbation");if(scored)++kick_scored;
        std::ostringstream trace;trace<<std::setprecision(12)<<"{\"number\":"<<kick_attempts<<",\"positions\":"<<keyjson(positions)<<",\"base_numeric\":"<<keyjson(incumbent.numeric)<<",\"perturbed_numeric\":"<<keyjson(candidate)<<",\"hamming_distance\":6,\"scored\":"<<(scored?"true":"false");if(scored)trace<<",\"idp\":"<<value.score;trace<<'}';kicks.push_back(trace.str());
        return value;
    }
    void run(const std::string& method) {
        if(method=="restart"){
            while(!cut){Key initial=initialize();if(cut)break;climb(initial);}
        } else if(method=="ils") {
            Key incumbent;bool fresh=true;int failures=0;
            while(!cut){
                if(fresh){incumbent=initialize();if(cut)break;incumbent=climb(incumbent);fresh=false;failures=0;if(cut)break;}
                Key kicked=perturb(incumbent);if(cut)break;Key local=climb(kicked);if(cut)break;
                if(local.score>incumbent.score+1e-12){incumbent=local;failures=0;}
                else if(++failures>=4){fresh=true;++stagnation_restarts;}
            }
        } else throw std::runtime_error("method restart or ils");
        if(archive.empty()||used>maximum)throw std::runtime_error("invalid final archive or budget");
    }
    void emit(const std::string& method,int round) const {
        std::cout<<std::setprecision(12)<<"{\"mode\":\"ciphertext_only_k2\",\"method\":\""<<method<<"\",\"round\":"<<round<<",\"search_seed\":"<<seed<<",\"messages_scored\":2,\"lengths\":[615,160],\"convention\":0,\"w1\":"<<w1<<",\"w2\":"<<w2<<",\"target_objective_calls\":"<<maximum<<",\"objective_calls\":"<<used<<",\"random_pool_calls\":"<<pool_calls<<",\"left_to_right_swap_calls\":"<<swap_calls<<",\"hill_climb_calls\":"<<climb_calls<<",\"perturbation_calls\":"<<kick_calls<<",\"seconds\":"<<seconds(start)<<",\"setup_seconds\":"<<setup_seconds<<",\"seconds_limit\":"<<limit<<",\"cut_cause\":\""<<cause<<"\",\"terminal_phase\":\""<<terminal_phase<<"\",\"restart_starts\":"<<restart_starts<<",\"restart_completions\":"<<restart_completions<<",\"climb_starts\":"<<climb_starts<<",\"climb_completions\":"<<climb_completions<<",\"perturbations_attempted\":"<<kick_attempts<<",\"perturbations_scored\":"<<kick_scored<<",\"stagnation_restarts\":"<<stagnation_restarts<<",\"archive\":[";
        for(std::size_t i=0;i<archive.size();++i){if(i)std::cout<<',';std::cout<<"{\"rank\":"<<i+1<<",\"idp\":"<<archive[i].score<<",\"k2\":"<<keyjson(inverse(archive[i].numeric))<<'}';}
        std::cout<<"],\"operation_traces\":[";for(std::size_t i=0;i<traces.size();++i){if(i)std::cout<<',';std::cout<<traces[i];}
        std::cout<<"],\"perturbation_traces\":[";for(std::size_t i=0;i<kicks.size();++i){if(i)std::cout<<',';std::cout<<kicks[i];}std::cout<<"]}\n"<<std::flush;
    }
};
} // namespace phase9
int main(int argc,char**argv){try{
    if(argc!=11)throw std::runtime_error("k2_search METHOD MODEL CT1 CT2 W1 W2 SEARCH_SEED OBJECTIVE_CALLS SECONDS ROUND");
    std::string method=argv[1];Model model(argv[2]);Ms ciphertext={read(argv[3]),read(argv[4])};
    int w1=std::stoi(argv[5]),w2=std::stoi(argv[6]);uint64_t seed=std::stoull(argv[7]);long maximum=std::stol(argv[8]);double seconds=std::stod(argv[9]);int round=std::stoi(argv[10]);
    if(ciphertext[0].size()!=615||ciphertext[1].size()!=160||w1<3||w1>160||w2<6||w2>160||maximum<1||!(seconds>0)||!std::isfinite(seconds)||round<0||round>1)throw std::runtime_error("invalid lengths widths or budgets");
    phase9::Search search(ciphertext,model,w1,w2,seed,maximum,seconds);search.run(method);search.emit(method,round);return 0;
}catch(const std::exception&error){std::cerr<<error.what()<<'\n';return 1;}}

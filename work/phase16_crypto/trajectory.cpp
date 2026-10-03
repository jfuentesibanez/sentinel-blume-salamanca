// Privileged K2 trajectories. No target, plaintext, Hamming or success stopping.
// Only the integer scorer is executed; attribution in ATTRIBUTION.txt.
#include "../phase4_crypto/source_moves.h"
#include <cstring>
#include <climits>
#include <functional>
using Clock=std::chrono::steady_clock;
long backend_exact_calls=0;
long mock_callback_calls=0;
void charge_backend(bool legacy){
 if(legacy)throw std::runtime_error("legacy backend forbidden in phase16");
 backend_exact_calls++;std::cerr<<"@calls 0 "<<backend_exact_calls<<'\n'<<std::flush;
}
// Exact routines copied byte-for-byte from frozen phase15 by build.py.
#include "exact_scorer.h"
double elapsed(Clock::time_point began){return std::chrono::duration<double>(Clock::now()-began).count();}
void validate(const V&key,int width){V sorted=key;std::sort(sorted.begin(),sorted.end());if((int)key.size()!=width)throw std::runtime_error("initial length mismatch");for(int i=0;i<width;i++)if(sorted[i]!=i)throw std::runtime_error("initial is not a permutation");}
V read_key(const std::string&path,int width){std::ifstream f(path);if(!f)throw std::runtime_error("initial file unavailable");V key;int x;while(f>>x)key.push_back(x);if(!f.eof())throw std::runtime_error("invalid initial file");validate(key,width);return key;}
std::string packed(const V&key){std::ostringstream s;for(size_t i=0;i<key.size();i++){if(i)s<<':';s<<key[i];}return s.str();}
std::string json_strings(const std::vector<std::string>&items){std::ostringstream s;s<<'[';for(size_t i=0;i<items.size();i++){if(i)s<<',';s<<items[i];}return s.str()+']';}

struct Core {
 V current,initial;int64_t value=0,denominator;bool scored_initial=false,converged=false;
 std::vector<Move>moves;char policy;long maximum,calls=0;int sweep_limit,full_sweeps=0,partial_sweeps=0,accepts=0;
 double seconds;Clock::time_point began;std::function<int64_t(const V&)>scorer;
 std::ostream*csv;std::vector<std::pair<int64_t,V>>archive;std::unordered_set<std::string>visited;
 std::vector<std::string>accept_events,sweep_events;std::string stop="none";
 Core(V start,std::vector<Move>mv,char p,int64_t den,long cap,int sweeps,double sec,Clock::time_point clock,
      std::function<int64_t(const V&)>f,std::ostream*log=nullptr):current(start),initial(start),denominator(den),moves(std::move(mv)),policy(p),maximum(cap),sweep_limit(sweeps),seconds(sec),began(clock),scorer(f),csv(log){
  if(policy!='A'&&policy!='B')throw std::runtime_error("policy must be A or B");
  if(den<=0||maximum<1||sweeps<1||!std::isfinite(sec)||sec<=0)throw std::runtime_error("invalid core limits");
  validate(initial,initial.size());for(const auto&move:moves)validate(move.p,initial.size());
  if(csv)*csv<<"call,sweep,move_index,move_kind,base_numerator,numerator,base_numeric,candidate_numeric,improves_base,accepted_immediate,archive_changed\n"<<std::flush;
 }
 std::string cut_reason()const{
  if(calls>=maximum)return "call_limit";
  if(elapsed(began)>=seconds)return "time_limit";
  return "none";
 }
 bool offer(int64_t num,const V&key){
  std::string tag;for(int x:key)tag+=char(x);visited.insert(tag);
  auto before=archive;auto it=std::find_if(archive.begin(),archive.end(),[&](const auto&item){return item.second==key;});
  if(it!=archive.end()){if(it->first!=num)throw std::runtime_error("duplicate key changed exact score");return false;}
  archive.push_back({num,key});std::sort(archive.begin(),archive.end(),[](const auto&a,const auto&b){return a.first!=b.first?a.first>b.first:a.second<b.second;});
  if(archive.size()>5)archive.resize(5);return before!=archive;
 }
 int64_t score(const V&key){calls++;int64_t num=scorer(key);return num;}
 void row(int sweep,int move,int kind,int64_t base_num,int64_t num,const V&base,const V&candidate,bool improves,bool accepted,bool archived){
  if(csv)*csv<<calls<<','<<sweep<<','<<move<<','<<kind<<','<<base_num<<','<<num<<','<<packed(base)<<','<<packed(candidate)<<','<<int(improves)<<','<<int(accepted)<<','<<int(archived)<<'\n'<<std::flush;
 }
 void accepted(int sweep,int move,long selected_call,const V&from,int64_t old,const V&to,int64_t num){
  std::ostringstream s;s<<"{\"call\":"<<calls<<",\"selected_call\":"<<selected_call<<",\"sweep\":"<<sweep<<",\"move_index\":"<<move<<",\"from_numeric\":"<<keyjson(from)<<",\"to_numeric\":"<<keyjson(to)<<",\"from_numerator\":"<<old<<",\"to_numerator\":"<<num<<'}';accept_events.push_back(s.str());accepts++;
 }
 void run(){
  stop=cut_reason();if(stop!="none")return;
  value=score(current);scored_initial=true;bool changed=offer(value,current);row(0,0,-1,value,value,current,current,false,false,changed);
  for(int sweep=1;sweep<=sweep_limit;sweep++){
   stop=cut_reason();if(stop!="none")return;
   V start=current,best_key=current;int64_t start_num=value,best_num=value;long start_call=calls,best_call=0;int best_move=0,proposals=0;bool improved=false;
   for(size_t j=0;j<moves.size();j++){
    stop=cut_reason();if(stop!="none")break;
    V base=policy=='A'?current:start;int64_t base_num=policy=='A'?value:start_num;
    V candidate=moved(base,moves[j]);int64_t num=score(candidate);proposals++;
    bool archived=offer(num,candidate);bool improvement=exact_improves(num,base_num,denominator),immediate=false;
    if(policy=='A'&&improvement){accepted(sweep,j+1,calls,current,value,candidate,num);current=candidate;value=num;improved=immediate=true;}
    if(policy=='B'&&num>best_num){best_num=num;best_key=candidate;best_call=calls;best_move=j+1;}
    row(sweep,j+1,moves[j].kind,base_num,num,base,candidate,improvement,immediate,archived);
   }
   // A sweep starts for accounting only when at least one proposal is scored.
   // A time cut before that must not reuse the preceding sweep's end_call.
   if(proposals==0){if(stop=="none")throw std::runtime_error("empty sweep without cut");return;}
   bool complete=proposals==(int)moves.size();
   // Complete final-score processing has priority over checking global limits.
   if(complete&&policy=='B'&&exact_improves(best_num,start_num,denominator)){
    accepted(sweep,best_move,best_call,current,value,best_key,best_num);current=best_key;value=best_num;improved=true;
   }
   bool observed_convergence=complete&&!improved;converged|=observed_convergence;
   if(complete)full_sweeps++;else partial_sweeps++;
   std::ostringstream s;s<<"{\"sweep\":"<<sweep<<",\"start_call\":"<<start_call<<",\"end_call\":"<<calls<<",\"proposals\":"<<proposals<<",\"complete\":"<<(complete?"true":"false")<<",\"start_numeric\":"<<keyjson(start)<<",\"final_numeric\":"<<keyjson(current)<<",\"start_numerator\":"<<start_num<<",\"final_numerator\":"<<value<<",\"improvement_accepted\":"<<(improved?"true":"false")<<",\"selected_call\":"<<best_call<<",\"selected_move_index\":"<<best_move<<",\"selected_numerator\":"<<best_num<<",\"convergence_observed\":"<<(observed_convergence?"true":"false")<<",\"partial_best_admitted\":false}";sweep_events.push_back(s.str());
   if(!complete){if(stop=="none")throw std::runtime_error("partial sweep without cut");return;}
   stop=cut_reason();if(stop!="none")return;
   if(observed_convergence){stop="converged";return;}
  }
  stop="sweep_limit";
 }
 std::string archive_json()const{
  std::ostringstream s;s<<'[';for(size_t i=0;i<archive.size();i++){if(i)s<<',';s<<"{\"rank\":"<<i+1<<",\"numerator\":"<<archive[i].first<<",\"numeric\":"<<keyjson(archive[i].second)<<'}';}return s.str()+']';
 }
};

int trajectory_main(int argc,char**argv){
 if(argc!=13)throw std::runtime_error("trajectory MODEL CT1 CT2 INITIAL W1 W2 POLICY CALLS SWEEPS SECONDS CSV SUMMARY");
 auto began=Clock::now();Model model(argv[1]);Ms ct={read(argv[2]),read(argv[3])};int w1=std::stoi(argv[5]),w2=std::stoi(argv[6]);
 if(w1<2||w2<2)throw std::runtime_error("invalid widths");for(const auto&t:ct)if((int)t.size()<std::max(w1,w2))throw std::runtime_error("input too short");
 V initial=read_key(argv[4],w2);std::string p=argv[7];if(p!="A"&&p!="B")throw std::runtime_error("invalid policy");
 long maximum=std::stol(argv[8]);int sweeps=std::stoi(argv[9]);double seconds=std::stod(argv[10]);
 ExactModel em(model);int rows=0;for(const auto&t:ct)rows+=t.size()/w1;int64_t bound=em.bound(rows,w1,ct.size()),den=checked128(__int128(em.scale)*rows*w1);
 auto moves=source_moves(w2);std::ofstream csv(argv[11]);if(!csv)throw std::runtime_error("CSV unavailable");
 double score_seconds=0;auto score=[&](const V&key){auto start=Clock::now();auto exact=exact_trace(undo2(ct,inverse(key),0),w1,em);score_seconds+=elapsed(start);if(exact.denominator!=den)throw std::runtime_error("denominator changed");return exact.numerator;};
 Core core(initial,moves,p[0],den,maximum,sweeps,seconds,began,score,&csv);double setup=elapsed(began);core.run();csv.close();
 if(core.calls!=backend_exact_calls)throw std::runtime_error("core/backend counts differ");double duration=elapsed(began);std::ofstream output(argv[12]);if(!output)throw std::runtime_error("summary unavailable");
 output<<std::setprecision(17)<<"{\"mode\":\"privileged_k2_trajectory\",\"policy\":\""<<p<<"\",\"w1\":"<<w1<<",\"w2\":"<<w2<<",\"lengths\":["<<ct[0].size()<<','<<ct[1].size()<<"],\"convention\":0,\"source_moves\":"<<moves.size()<<",\"initial_numeric\":"<<keyjson(initial)<<",\"final_numeric\":"<<keyjson(core.current)<<",\"initial_scored\":"<<(core.scored_initial?"true":"false")<<",\"final_numerator\":"<<(core.scored_initial?std::to_string(core.value):"null")<<",\"denominator\":"<<den<<",\"scale\":"<<em.scale<<",\"checked_absolute_numerator_bound\":"<<bound<<",\"calls\":"<<core.calls<<",\"backend_exact_calls\":"<<backend_exact_calls<<",\"backend_legacy_calls\":0,\"call_limit\":"<<maximum<<",\"sweep_limit\":"<<sweeps<<",\"full_sweeps\":"<<core.full_sweeps<<",\"partial_sweeps\":"<<core.partial_sweeps<<",\"convergence_observed\":"<<(core.converged?"true":"false")<<",\"accepted_changes\":"<<core.accepts<<",\"visited_unique\":"<<core.visited.size()<<",\"stop_reason\":\""<<core.stop<<"\",\"call_limit_reached\":"<<(core.calls>=maximum?"true":"false")<<",\"time_limit_reached\":"<<(duration>=seconds?"true":"false")<<",\"seconds_limit\":"<<seconds<<",\"seconds\":"<<duration<<",\"setup_seconds\":"<<setup<<",\"score_seconds\":"<<score_seconds<<",\"soft_excess_seconds\":"<<std::max(0.0,duration-seconds)<<",\"archive\":"<<core.archive_json()<<",\"accept_events\":"<<json_strings(core.accept_events)<<",\"sweep_events\":"<<json_strings(core.sweep_events)<<"}\n";return 0;
}

int policy_controls(){
 V identity={0,1,2},p1={1,0,2},p2={0,2,1};std::vector<Move>mv={{p1,1},{p2,1}};int fixtures=0;
 auto run=[&](char policy,long cap,int sweeps,bool tie,bool flat,double seconds,Clock::time_point clock){
  auto fake=[=](const V&key)->int64_t{mock_callback_calls++;if(flat)return 0;if(key==p1)return 10;if(key==p2)return tie?10:20;if(key==V({1,2,0}))return 5;return 0;};
  Core core(identity,mv,policy,1,cap,sweeps,seconds,clock,fake);core.run();return core;
 };
 auto now=[](){return Clock::now();};
 auto a=run('A',3,1,false,false,30,now()),b=run('B',3,1,false,false,30,now());
 if(a.current!=p1||b.current!=p2||a.calls!=3||b.calls!=3||a.full_sweeps!=1||b.full_sweeps!=1)throw std::runtime_error("policy selection/control fixture");fixtures++;
 auto partial_b=run('B',2,1,false,false,30,now());if(partial_b.current!=identity||partial_b.archive[0].second!=p1||partial_b.full_sweeps||partial_b.partial_sweeps!=1||partial_b.converged||partial_b.accepts)throw std::runtime_error("B partial admission fixture");fixtures++;
 auto partial_a=run('A',2,1,false,false,30,now());if(partial_a.current!=p1||partial_a.accepts!=1||partial_a.converged||partial_a.stop!="call_limit")throw std::runtime_error("A final scored update fixture");fixtures++;
 auto tied=run('B',3,1,true,false,30,now());if(tied.current!=p1||tied.accepts!=1||tied.stop!="call_limit")throw std::runtime_error("B first-source tie fixture");fixtures++;
 auto flat=run('B',3,1,false,true,30,now());if(!flat.converged||flat.full_sweeps!=1||flat.stop!="call_limit"||flat.accepts)throw std::runtime_error("complete convergence/cap fixture");fixtures++;
 auto expired=run('A',3,1,false,false,1,now()-std::chrono::seconds(2));if(expired.calls||expired.scored_initial||expired.stop!="time_limit")throw std::runtime_error("time before initial fixture");fixtures++;
 auto duplicate=run('B',5,2,false,true,30,now());duplicate.offer(0,identity);if(duplicate.visited.size()!=3||duplicate.archive.size()!=3)throw std::runtime_error("archive unique fixture");fixtures++;
 auto mock_zero=[](const V&)->int64_t{mock_callback_calls++;return 0;};
 Core repeated(identity,{{p1,1},{p1,1},{p2,1}},'B',1,4,1,30,now(),mock_zero);repeated.run();
 if(repeated.calls!=4||repeated.visited.size()!=3||repeated.archive.size()!=3||!repeated.converged)throw std::runtime_error("repeated proposals charged fixture");fixtures++;
 V four={0,1,2,3};std::vector<Move>many;V next=four;while(std::next_permutation(next.begin(),next.end()))many.push_back({next,1});
 Core pruned(four,many,'B',1,24,1,30,now(),mock_zero);pruned.run();
 if(pruned.calls!=24||pruned.visited.size()!=24||pruned.archive.size()!=5||pruned.archive[0].second!=four)throw std::runtime_error("top5 pruning/ties fixture");
 next=four;for(int i=0;i<5;i++){if(pruned.archive[i].second!=next)throw std::runtime_error("archive lexical tie fixture");std::next_permutation(next.begin(),next.end());}fixtures++;
 auto initial_only=run('A',1,1,false,false,30,now());if(initial_only.calls!=1||!initial_only.scored_initial||initial_only.full_sweeps||initial_only.partial_sweeps||initial_only.converged||initial_only.stop!="call_limit")throw std::runtime_error("cap after initial fixture");fixtures++;
 auto timed=[&](char policy,int expire_call,bool flat,const V&expected,int full,int partial,bool converged){
  Core*running=nullptr;
  auto fake=[&](const V&key)->int64_t{mock_callback_calls++;if(running->calls==expire_call)running->began=Clock::now()-std::chrono::seconds(1000);if(flat)return 0;if(key==p1)return 10;if(key==p2)return 20;return 0;};
  Core core(identity,mv,policy,1,100,2,30,now(),fake);running=&core;core.run();
  if(core.current!=expected||core.full_sweeps!=full||core.partial_sweeps!=partial||core.converged!=converged||core.stop!="time_limit"||core.calls!=expire_call)throw std::runtime_error("callback time-boundary fixture");
  if(expire_call>1&&core.archive[0].first==0&&!flat)throw std::runtime_error("last time-cut score lost from archive");fixtures++;
 };
 timed('A',2,false,p1,0,1,false);timed('B',2,false,identity,0,1,false);
 timed('B',3,false,p2,1,0,false);timed('B',3,true,identity,1,0,true);
 timed('A',1,false,identity,0,0,false);
 if(exact_improves(1,0,1000000000000LL)||!exact_improves(2,0,1000000000000LL))throw std::runtime_error("exact EPS fixture");fixtures++;
 if(backend_exact_calls)throw std::runtime_error("mock controls called a real scorer");
 std::cout<<"{\"status\":\"passed\",\"policy_fixtures\":"<<fixtures<<",\"new_exact_IDP_calls\":0,\"new_legacy_IDP_calls\":0,\"mock_callback_calls\":"<<mock_callback_calls<<",\"truth_read\":false,\"truth_generated\":false}\n";return 0;
}
int main(int argc,char**argv){try{if(argc==2&&std::string(argv[1])=="policy-controls")return policy_controls();return trajectory_main(argc,argv);}catch(const std::exception&e){std::cerr<<e.what()<<'\n';std::cout<<"{\"status\":\"failed\",\"backend_exact_calls\":"<<backend_exact_calls<<",\"backend_legacy_calls\":0,\"mock_callback_calls\":"<<mock_callback_calls<<"}\n";return 1;}}

#pragma once
#include "../phase4_crypto/source_moves.h"

// Experimental ILS-inspired policy, not a claimed published BLUME attack.
// Primary methodological discussion: Lasry2018 §§2.3.3 and4.3.2.
struct Budget5 {
 long cap,used=0;double seconds;std::string cause;
 std::chrono::steady_clock::time_point start=std::chrono::steady_clock::now();
 bool allow(){if(used>=cap){cause="max_evaluations";return false;}if(elapsed()>=seconds){cause="wall_time";return false;}used++;return true;}
 double elapsed()const{return std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();}
 bool expired()const{return cause=="max_evaluations"||cause=="wall_time";}
};
struct Hill5 {V key;double score;long evals;int sweeps;bool complete;};
template<class F> Hill5 hill5(V key,double score,std::vector<Move>&mv,Budget5&budget,RNG&rng,F eval){
 long before=budget.used;int sweeps=0;bool improved=true;
 while(improved&&!budget.expired()){
  improved=false;sweeps++;std::shuffle(mv.begin(),mv.end(),rng);
  for(const auto&move:mv){if(!budget.allow())break;V candidate=moved(key,move);double value=eval(candidate);if(value>score+1e-12){key=candidate;score=value;improved=true;}}
 }
 return {key,score,budget.used-before,sweeps,!budget.expired()};
}
V kick5(const V&key,int swaps,RNG&rng){
 V positions(key.size());std::iota(positions.begin(),positions.end(),0);std::shuffle(positions.begin(),positions.end(),rng);V out=key;
 swaps=std::min(swaps,int(key.size()/2));for(int i=0;i<swaps;i++)std::swap(out[positions[2*i]],out[positions[2*i+1]]);return out;
}
struct Event5 {std::string policy;int strength,sweeps;long evals;double start,finish,best;bool complete,returned_to_best,improved_best;};
struct Result5 {V key;double score;long evals;double seconds;std::string cause;int initial_climbs=0;std::vector<Event5>events;};

// Diagnostic receives only ciphertexts and an observed incorrect numeric K2.
// Planted truth, plaintext and key comparison exist outside this function.
Result5 escape_from_peak(const Ms&ct,int w1,const Model&m,const V&start_read_key,uint64_t seed,const std::string&policy,long cap,double seconds){
 Budget5 budget{cap,0,seconds};RNG rng(seed);auto mv=source_moves(start_read_key.size());
 auto eval=[&](const V&s){return idp(undo2(ct,inverse(s),0),w1,0,m,-1,true);};
 V best=inverse(start_read_key);if(!budget.allow())throw std::runtime_error("budget before initial score");double bestscore=eval(best),startscore=bestscore;Result5 result;
 auto initial=hill5(best,bestscore,mv,budget,rng,eval);result.initial_climbs=1;best=initial.key;bestscore=initial.score;
 result.events.push_back({"initial",0,initial.sweeps,initial.evals+1,startscore,initial.score,bestscore,initial.complete,initial.key==inverse(start_read_key),initial.score>startscore+1e-12});
 // Avoid model scores from planted truth or success thresholds.
 if(policy=="source"&&!budget.expired())budget.cause="local_optimum";
 int iteration=0;
 while(policy!="source"&&!budget.expired()){
  V previous=best;int strength=policy=="kick"?2+iteration%3:0;
  V trial=policy=="kick"?kick5(best,strength,rng):perm(best.size(),rng);
  if(!budget.allow())break;double score=eval(trial);double initialscore=score;auto local=hill5(trial,score,mv,budget,rng,eval);
  bool better=local.score>bestscore+1e-12;if(better){bestscore=local.score;best=local.key;}
  result.events.push_back({policy,strength,local.sweeps,local.evals+1,initialscore,local.score,bestscore,local.complete,local.key==previous,better});iteration++;
 }
 result.key=inverse(best);result.score=bestscore;result.evals=budget.used;result.seconds=budget.elapsed();result.cause=budget.cause;return result;
}

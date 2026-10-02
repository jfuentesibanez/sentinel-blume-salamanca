#pragma once
#include "../phase3_crypto/ict_search.h"

// Copyright (C) CrypTool 2 Team; algorithm adapted under Apache License 2.0.
// https://www.apache.org/licenses/LICENSE-2.0
// Port of CrypTool-2 TranspositionTransformations(slides=true,swaps=true,
// inversions=false), commit bbcc87bb77f9b3f83c4ded7cb563029b0fbb081c.
// A Move stores destination->source, exactly equivalent to the original
// constructor's inverse map followed by transform(to[list[i]]=from[i]).
// Identity is omitted from search (it cannot improve a strict score).
std::vector<Move> source_moves(int w,bool include_identity=false){
 V id(w);std::iota(id.begin(),id.end(),0);std::vector<Move>out;
 std::unordered_set<std::string>seen;
 auto add=[&](const V&p,int kind){std::string tag;for(int x:p)tag+=char(x);if((include_identity||p!=id)&&seen.insert(tag).second)out.push_back({p,kind});};
 for(int len=w;len>0;len--)for(int shift=1;shift<w;shift++)for(int p1=0;p1<w;p1++){
  V p=id;int affected=len+shift;
  if(affected<=w)for(int i=0;i<affected;i++)p[(p1+(i+shift)%affected)%w]=id[(p1+i)%w];
  add(p,0);
 }
 for(int shift=0;shift<w;shift++){V p(w);for(int i=0;i<w;i++)p[(i+shift)%w]=id[i];add(p,0);}
 for(int len=w/4;len>0;len--)for(int p1=0;p1<w;p1++)for(int p2=p1+len;p2<w-len;p2++){
  V p=id;for(int i=0;i<len;i++){p[p2+i]=id[p1+i];p[p1+i]=id[p2+i];}add(p,1);
 }
 // Preserve the source's STRICT upper bounds, rather than silently repairing
 // its exclusion of blocks ending at the final position.
 for(int len=1;len<4;len++)for(int p1=0;p1<w-3*len;p1++)for(int p2=p1+len;p2<w-2*len;p2++)for(int p3=p2+len;p3<w-len;p3++){
  V p=id;for(int i=0;i<len;i++){p[p2+i]=id[p1+i];p[p3+i]=id[p2+i];p[p1+i]=id[p3+i];}add(p,2);
  p=id;for(int i=0;i<len;i++){p[p3+i]=id[p1+i];p[p1+i]=id[p2+i];p[p2+i]=id[p3+i];}add(p,2);
 }
 for(int p1=0;p1<w;p1++)for(int p2=0;p2<w;p2++)for(int p3=0;p3<w;p3++)if(p1!=p2&&p1!=p3&&p2!=p3){
  V p=id;p[p1]=id[p2];p[p2]=id[p3];p[p3]=id[p1];add(p,2);
 }
 return out;
}

// Same pool and left-to-right initialization as phase3. Only the HC
// neighbourhood and randomized sweep order change. No planted truth enters.
K2Result solve_k2_source(const Ms&ct,int w1,int w2,const Model&m,uint64_t seed,int pool,int keep,int climbs,double seconds,long maxeval=300000){
 Limits lim{seconds,maxeval};RNG rng(seed);auto f=[&](const V&s){return idp(undo2(ct,inverse(s),0),w1,0,m,-1,true);};
 std::vector<std::pair<double,V>>keys;
 for(int i=0;i<pool&&lim.allow();i++){V k=perm(w2,rng);keys.push_back({f(k),k});}
 auto sort=[&](){std::sort(keys.begin(),keys.end(),[](const auto&a,const auto&b){return a.first>b.first;});};sort();if((int)keys.size()>keep)keys.resize(keep);
 for(auto&item:keys){V k=item.second;double cur=item.first;for(int i=0;i<w2-1&&!lim.expired;i++)for(int j=i+1;j<w2;j++){if(!lim.allow())break;V c=k;std::swap(c[i],c[j]);double v=f(c);if(v>cur+1e-12){cur=v;k=c;}}item={cur,k};}
 sort();if((int)keys.size()>climbs)keys.resize(climbs);auto mv=source_moves(w2);
 for(auto&item:keys){if(lim.expired)break;V key=item.second;double cur=item.first;bool improved=true;
  while(improved&&!lim.expired){improved=false;std::shuffle(mv.begin(),mv.end(),rng);for(const auto&move:mv){if(!lim.allow())break;V c=moved(key,move);double v=f(c);if(v>cur+1e-12){cur=v;key=c;improved=true;}}}item={cur,key};
 }
 sort();for(auto&item:keys)item.second=inverse(item.second);return {keys,lim.used,lim.elapsed(),lim.expired};
}

template<class F> std::pair<double,V> source_hc(V key,std::vector<Move>mv,Limits&lim,RNG&rng,F f){
 double cur=f(key);bool improved=true;while(improved&&!lim.expired){improved=false;std::shuffle(mv.begin(),mv.end(),rng);for(const auto&move:mv){if(!lim.allow())break;V candidate=moved(key,move);double value=f(candidate);if(value>cur+1e-12){key=candidate;cur=value;improved=true;}}}return {cur,key};
}

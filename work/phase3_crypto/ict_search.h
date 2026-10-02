#pragma once
// K1 ICT reconstruction following Lasry2018 §5.3.4. Includes immutable phase1
// model/crypt primitives. See METHOD.txt for choices not specified by source.
#define main baseline_cli_main
#include "../crypto/double_search.cpp"
#undef main
#include <limits>
#include <unordered_set>

struct Move {V p;int kind;};
std::vector<Move> moves(int w,bool tripartite=false){
 std::vector<Move> out;V id(w);std::iota(id.begin(),id.end(),0);std::unordered_set<std::string>seen;
 auto add=[&](V p,int kind){std::string tag;for(int x:p)tag+=char(x);if(p!=id&&seen.insert(tag).second)out.push_back({p,kind});};
 for(int a=0;a<w;a++)for(int b=a+1;b<w;b++)for(int c=b+1;c<=w;c++){V p=id;std::rotate(p.begin()+a,p.begin()+b,p.begin()+c);add(p,0);}
 for(int len=1;len<=w/2;len++)for(int a=0;a+len<=w;a++)for(int b=a+len;b+len<=w;b++){V p=id;for(int i=0;i<len;i++)std::swap(p[a+i],p[b+i]);add(p,1);}
 // Documented variant: permutations of all 3 blocks partitioning the WHOLE
 // key. Source names 3-partite swaps without specifying their exact mapping.
 if(tripartite)for(int a=1;a<w-1;a++)for(int b=a+1;b<w;b++){
  std::array<std::pair<int,int>,3>bl={{{0,a},{a,b},{b,w}}};V order={0,1,2};do{V p;for(int k:order)for(int i=bl[k].first;i<bl[k].second;i++)p.push_back(i);add(p,2);}while(std::next_permutation(order.begin(),order.end()));}
 return out;
}
V moved(const V&a,const Move&mv){V b(a.size());for(size_t i=0;i<a.size();i++)b[i]=a[mv.p[i]];return b;}
V inverse(const V&s){V k(s.size());for(size_t c=0;c<s.size();c++)k[s[c]]=c;return k;}
struct Limits {double seconds;long maxeval,used=0;bool expired=false;std::chrono::steady_clock::time_point start=std::chrono::steady_clock::now();bool allow(){if(used>=maxeval||std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count()>seconds){expired=true;return false;}used++;return true;}double elapsed(){return std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();}};

struct AdjTable {int w,rows,rem;std::vector<double>S;V O;};
AdjTable adjacent_table(const V&I,int w,const Model&m,bool trigram){
 int rows=I.size()/w,rem=I.size()%w;AdjTable tab{w,rows,rem,std::vector<double>(w*w,-1e100),V(w*w)};V lo(w),hi(w);
 for(int k=0;k<w;k++){lo[k]=std::max(0,k-(w-rem));hi[k]=std::min(k,rem);}
 for(int i=0;i<w;i++)for(int j=0;j<w;j++)if(i!=j){double best=-1e100;int bo=0;
  for(int a=lo[i];a<=hi[i];a++)for(int b=lo[j];b<=hi[j];b++){
   int pi=i*rows+a,pj=j*rows+b;
   if(!trigram){double v=0;for(int r=0;r<rows;r++)v+=m.b[I[pi+r]*26+I[pj+r]];if(v>best){best=v;bo=((pj-pi)%rows+rows)%rows;}}
   else for(int k=0;k<w;k++)if(k!=i&&k!=j)for(int c=lo[k];c<=hi[k];c++){double v=0;int pk=k*rows+c;for(int r=0;r<rows;r++)v+=m.t[I[pi+r]*676+I[pj+r]*26+I[pk+r]];if(v>best){best=v;bo=((pj-pi)%rows+rows)%rows;}}
  }tab.S[i*w+j]=best;tab.O[i*w+j]=bo;
 }return tab;
}
struct Feature {double adj;int align;};
struct ICT {
 Ms I;int w;std::vector<AdjTable>tables;std::vector<double>sumS;const Model&m;int rows_total=0;
 ICT(const Ms&input,int width,const Model&model,bool trigram):I(input),w(width),sumS(width*width),m(model){for(auto&a:I){tables.push_back(adjacent_table(a,w,m,trigram));rows_total+=tables.back().rows;for(int z=0;z<w*w;z++)sumS[z]+=tables.back().S[z];}}
 Feature feature(const V&s)const{
  double adj=0;for(int c=0;c<w-1;c++)adj+=sumS[s[c]*w+s[c+1]];int align=0;
  for(auto&t:tables){V islong(w),prefix(w+1);for(int c=0;c<w;c++)islong[s[c]]=c<t.rem;for(int k=0;k<w;k++)prefix[k+1]=prefix[k]+islong[k];bool previous=false;
   for(int c=0;c<w-1;c++){int i=s[c],j=s[c+1],pred=((prefix[j]-prefix[i])%t.rows+t.rows)%t.rows;bool ok=pred==t.O[i*w+j];if(ok)align+=2+(previous?1:0);previous=ok;}
  }return {adj/(rows_total*(w-1)),align};
 }
 double qscore(const V&s,int ng=4)const{Ms P;V k=inverse(s);for(auto&a:I)P.push_back(col(a,k,false));return ngram(P,m,ng);}
};

struct K1Result{V key;double score=-1e100;long feature_evals=0,q_evals=0;bool expired=false;double seconds=0;};
K1Result solve_ict(const Ms&I,int w,const Model&m,uint64_t seed,int restarts,double seconds,bool trigram=true,long maxeval=2000000,int final_ngram=4){
 Limits lim{seconds,maxeval};ICT ict(I,w,m,trigram);auto mv=moves(w);RNG rng(seed);K1Result result;
 for(int restart=0;restart<restarts&&!lim.expired;restart++){
  V s=perm(w,rng);Feature cur=ict.feature(s);double adj_threshold=cur.adj;double align_threshold=0;
  // The source specifies increasing thresholds, not their numeric schedule.
  // This implementation raises them 25% toward the attained current values.
  for(int round=0;round<15&&!lim.expired;round++){
   bool cycle_improved=false;
   for(int primary=0;primary<2&&!lim.expired;primary++){
    bool improved=true;int sweeps=0;
    while(improved&&sweeps++<15&&!lim.expired){improved=false;for(auto&move:mv){if(!lim.allow())break;V cand=moved(s,move);Feature f=ict.feature(cand);result.feature_evals++;
      bool accept=primary==0?((f.adj>cur.adj+1e-12||(std::abs(f.adj-cur.adj)<1e-12&&f.align>cur.align))&&f.align>=align_threshold):((f.align>cur.align||(f.align==cur.align&&f.adj>cur.adj+1e-12))&&f.adj>=adj_threshold);
      if(accept){s=cand;cur=f;improved=cycle_improved=true;}
    }}
   }
   adj_threshold=std::max(adj_threshold,adj_threshold+.25*(cur.adj-adj_threshold));align_threshold=std::max(align_threshold,align_threshold+.25*(cur.align-align_threshold));if(!cycle_improved)break;
  }
  double q=ict.qscore(s,final_ngram);bool improved=true;
  while(improved&&!lim.expired){improved=false;for(auto&move:mv){if(!lim.allow())break;V c=moved(s,move);double v=ict.qscore(c,final_ngram);result.q_evals++;if(v>q+1e-12){q=v;s=c;improved=true;}}}
  if(q>result.score){result.score=q;result.key=inverse(s);}
 }
 if(result.key.empty()){V s=perm(w,rng);result.key=inverse(s);result.score=ict.qscore(s,final_ngram);}
 result.seconds=lim.elapsed();result.expired=lim.expired;return result;
}

template<class F> std::pair<double,V> complete_hc(V key,const std::vector<Move>&mv,Limits&lim,F f){double cur=f(key);bool improved=true;while(improved&&!lim.expired){improved=false;for(auto&move:mv){if(!lim.allow())break;V candidate=moved(key,move);double value=f(candidate);if(value>cur+1e-12){key=candidate;cur=value;improved=true;}}}return {cur,key};}
struct K2Result {std::vector<std::pair<double,V>>candidates;long evals=0;double seconds=0;bool expired=false;};
K2Result solve_k2_hc(const Ms&ct,int w1,int w2,const Model&m,uint64_t seed,int pool,int keep,int climbs,double seconds,long maxeval=300000){
 // HC moves act on source numerical keys (plaintext column -> read rank),
 // and are converted to ciphertext read order at the cryptographic boundary.
 Limits lim{seconds,maxeval};RNG rng(seed);auto f=[&](const V&s){return idp(undo2(ct,inverse(s),0),w1,0,m,-1,true);};std::vector<std::pair<double,V>>keys;
 for(int i=0;i<pool&&lim.allow();i++){V k=perm(w2,rng);keys.push_back({f(k),k});}
 auto sort=[&](){std::sort(keys.begin(),keys.end(),[](auto&a,auto&b){return a.first>b.first;});};sort();if((int)keys.size()>keep)keys.resize(keep);
 for(auto&item:keys){V k=item.second;double cur=item.first;for(int i=0;i<w2-1&&!lim.expired;i++)for(int j=i+1;j<w2;j++){if(!lim.allow())break;V c=k;std::swap(c[i],c[j]);double v=f(c);if(v>cur+1e-12){cur=v;k=c;}}item={cur,k};}
 sort();if((int)keys.size()>climbs)keys.resize(climbs);auto mv=moves(w2,true);
 for(auto&item:keys){if(lim.expired)break;item=complete_hc(item.second,mv,lim,f);}
 sort();for(auto&item:keys)item.second=inverse(item.second);return {keys,lim.used,lim.elapsed(),lim.expired};
}

// Portable calibrated double-columnar baseline. Inspired by Lasry/Kopal/Wacker
// (2014), NOT a claimed exact reproduction of the complete published attack.
// Permutations are zero-based original-column indices in ciphertext read order.
// Model binary is 26^2 + 26^3 + 26^4 little-endian IEEE float log10 probabilities.
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
using V=std::vector<int>; using Ms=std::vector<V>; using RNG=std::mt19937_64;
struct Model { std::vector<float> b,t,q; Model(const std::string& path) {
  std::ifstream f(path,std::ios::binary); if(!f) throw std::runtime_error("model unavailable");
  for(auto *p:{&b,&t,&q}) {int n=p==&b?676:p==&t?17576:456976;p->resize(n);f.read((char*)p->data(),n*4);if(!f)throw std::runtime_error("model truncated");}
 }};
V read(const std::string& path) {std::ifstream f(path);if(!f)throw std::runtime_error("input unavailable: "+path);V a;char c;while(f.get(c)){if(c>='a'&&c<='z')a.push_back(c-'a');else if(c>='A'&&c<='Z')a.push_back(c-'A');}return a;}
std::string letters(const V&a){std::string s;for(int c:a)s+=char('A'+c);return s;}
std::string keyjson(const V&a){std::ostringstream s;s<<'[';for(size_t i=0;i<a.size();i++){if(i)s<<',';s<<a[i];}return s.str()+']';}
V perm(int n,RNG&r){V a(n);std::iota(a.begin(),a.end(),0);std::shuffle(a.begin(),a.end(),r);return a;}
V col(const V&a,const V&k,bool enc){int n=a.size(),w=k.size(),rows=n/w,rem=n%w,pos=0;V b(n);for(int c:k)for(int r=0;r<rows+(c<rem);r++){int p=r*w+c;if(enc)b[pos++]=a[p];else b[p]=a[pos++];}return b;}
V crypt(const V&a,const V&k1,const V&k2,int conv,bool enc){bool inv1=conv==1||conv==2,inv2=conv==1||conv==3;return enc?col(col(a,k1,!inv1),k2,!inv2):col(col(a,k2,inv2),k1,inv1);}
Ms undo2(const Ms&ct,const V&k2,int conv){Ms out;for(auto &a:ct)out.push_back(col(a,k2,conv==1||conv==3));return out;}
double ngram(const Ms&a,const Model&m,int n){double sum=0;int count=0;const auto&tab=n==3?m.t:m.q;int mod=n==3?676:17576;for(auto &s:a){if((int)s.size()<n)continue;int code=0;for(int i=0;i<n;i++)code=26*code+s[i];sum+=tab[code];count++;for(int i=n;i<(int)s.size();i++){code=26*(code%mod)+s[i];sum+=tab[code];count++;}}return sum/count;}
double fullscore(const Ms&ct,const V&k1,const V&k2,int conv,const Model&m,int ng){Ms pt;for(auto&a:ct)pt.push_back(crypt(a,k1,k2,conv,false));return ngram(pt,m,ng);}
// Full feasible boundary ranges. tol >= 0 is an explicitly approximate option;
// unlike upstream's default ±2, this baseline defaults to the complete range.
std::vector<double> matrix(const V&I,int w,const Model&m,int tol){
 int rows=I.size()/w,rem=I.size()%w;std::vector<double>S(w*w,-1e6);V lo(w),hi(w);
 for(int k=0;k<w;k++){lo[k]=std::max(0,k-(w-rem));hi[k]=std::min(k,rem);if(tol>=0){int ex=std::lround((double)k*rem/w);lo[k]=std::max(lo[k],ex-tol);hi[k]=std::min(hi[k],ex+tol);}}
 for(int a=0;a<w;a++)for(int b=0;b<w;b++)if(a!=b){double best=-1e100;for(int d=lo[b]-hi[a];d<=hi[b]-lo[a];d++){
   int l=std::max(lo[a],lo[b]-d),h=std::min(hi[a],hi[b]-d);if(l>h)continue;
   int p=a*rows+l,q=b*rows+d+l;double s=0;for(int r=0;r<rows;r++)s+=m.b[I[p+r]*26+I[q+r]];
   best=std::max(best,s);for(int u=l+1;u<=h;u++){s+=m.b[I[p+rows]*26+I[q+rows]]-m.b[I[p]*26+I[q]];p++;q++;best=std::max(best,s);}
 }S[a*w+b]=best;}return S;
}
// Greedy one-to-one neighbours from paper §4.5.2. This relaxation may include
// cycles and inconsistent per-pair long-column offsets; it does not yield K1.
double idp(const Ms&I,int w,int conv,const Model&m,int tol,bool greedy){
 if(conv==1||conv==2){double s=0;int count=0;for(auto&a:I)for(int p=0;p+w<(int)a.size();p++){s+=m.b[a[p]*26+a[p+w]];count++;}return s/count;}
 std::vector<double>S(w*w,0);int nr=0;for(auto&a:I){auto T=matrix(a,w,m,tol);nr+=a.size()/w;for(int i=0;i<w*w;i++)S[i]+=T[i];}
 double total=0;if(!greedy){for(int a=0;a<w;a++)total+=*std::max_element(S.begin()+a*w,S.begin()+(a+1)*w);}else{
 V useda(w),usedb(w);for(int step=0;step<w;step++){double best=-1e100;int x=-1,y=-1;for(int a=0;a<w;a++)if(!useda[a])for(int b=0;b<w;b++)if(!usedb[b]&&a!=b&&S[a*w+b]>best){best=S[a*w+b];x=a;y=b;}
  // Greedy can leave only a diagonal. Permit that forced last edge at floor;
  // record the relaxation rather than pretending this is a valid column order.
  if(x<0){for(int a=0;a<w;a++)if(!useda[a])x=a;for(int b=0;b<w;b++)if(!usedb[b])y=b;best=-7.0*nr;}
  total+=best;useda[x]=usedb[y]=1;
 }}return total/(nr*w);
}
V mutate(const V&k,RNG&r){V a=k;int n=a.size(),type=r()%5,i=r()%n,j=r()%n;if(i>j)std::swap(i,j);
 if(type==0)std::swap(a[i],a[j]);
 else if(type==1){int h=r()%(n+1);if(h<i)std::rotate(a.begin()+h,a.begin()+i,a.begin()+j+1);else if(h>j+1)std::rotate(a.begin()+i,a.begin()+j+1,a.begin()+h);}
 else if(type==2){int len=1+r()%std::max(1,n/3);int x=r()%(n-len+1),y=r()%(n-len+1);if(x>y)std::swap(x,y);if(x+len<=y)for(int z=0;z<len;z++)std::swap(a[x+z],a[y+z]);}
 else if(type==3)std::reverse(a.begin()+i,a.begin()+j+1);
 else if(i>0&&j>i&&j<n){V out;out.insert(out.end(),a.begin()+j,a.end());out.insert(out.end(),a.begin()+i,a.begin()+j);out.insert(out.end(),a.begin(),a.begin()+i);a=out;}
 return a;}
struct Cand{double score=-1e100;V k1,k2;};
template<class F> std::pair<double,V> anneal(V a,int steps,RNG&r,F f,double t0=.03,double t1=.0005){double cur=f(a),best=cur;V bk=a;std::uniform_real_distribution<double>u(0,1);for(int i=0;i<steps;i++){V b=mutate(a,r);double v=f(b),T=t0*std::pow(t1/t0,(double)i/std::max(1,steps));if(v>=cur||u(r)<std::exp((v-cur)/T)){a=b;cur=v;if(v>best){best=v;bk=a;}}}return {best,bk};}
// Complete adjacent segment-slide neighbourhood; deterministic once seeded.
template<class F> std::pair<double,V> slides(V a,int budget,F f){double cur=f(a);int used=0,n=a.size();bool improved=true;while(improved&&used<budget){improved=false;V best=a;double bs=cur;for(int i=0;i<n&&used<budget;i++)for(int j=i+1;j<n&&used<budget;j++)for(int k=j+1;k<=n&&used<budget;k++){V b=a;std::rotate(b.begin()+i,b.begin()+j,b.begin()+k);double v=f(b);used++;if(v>bs){bs=v;best=b;improved=true;}}if(improved){a=best;cur=bs;}}return {cur,a};}
Cand solve(const Ms&ct,int w1,int w2,int conv,const Model&m,uint64_t seed,int restarts,int steps,int tol,bool greedy){
 RNG r(seed);std::vector<std::pair<double,V>>pool;
 auto fi=[&](const V&k){return idp(undo2(ct,k,conv),w1,conv,m,tol,greedy);};
 for(int j=0;j<restarts;j++){auto s=anneal(perm(w2,r),steps,r,fi);pool.push_back(s);}
 std::sort(pool.begin(),pool.end(),[](auto&a,auto&b){return a.first>b.first;});Cand best;
 for(int j=0;j<std::min(3,(int)pool.size());j++){
  V k2=pool[j].second;auto p2=slides(k2,steps/2,fi);k2=p2.second;
  auto fq=[&](const V&k){return fullscore(ct,k,k2,conv,m,4);};
  auto p1=anneal(perm(w1,r),steps*4,r,fq,.05,.0005);for(int rr=1;rr<3;rr++){auto x=anneal(perm(w1,r),steps*4,r,fq,.05,.0005);if(x.first>p1.first)p1=x;}
  V k1=p1.second;double sc=p1.first;
  // Alternate complete slides on both keys under actual plaintext score.
  for(int pass=0;pass<3;pass++){
    auto f1=[&](const V&k){return fullscore(ct,k,k2,conv,m,4);};auto a=slides(k1,steps,f1);k1=a.second;
    auto f2=[&](const V&k){return fullscore(ct,k1,k,conv,m,4);};auto b=slides(k2,steps,f2);k2=b.second;
    if(b.first<=sc+1e-9){sc=b.first;break;}sc=b.first;
  }if(sc>best.score)best={sc,k1,k2};
 }return best;
}
int correct(const V&a,const V&b){int n=0;for(size_t i=0;i<a.size();i++)n+=a[i]==b[i];return n;}
void roundtrip(){RNG r(123456789);int count=0;for(int n:{1,2,7,8,15,160,615})for(int w1:{2,3,8,20,25})for(int w2:{2,3,9,20,23})for(int conv=0;conv<4;conv++){V a(n);for(int&c:a)c=r()%26;auto k1=perm(w1,r),k2=perm(w2,r);if(crypt(crypt(a,k1,k2,conv,true),k1,k2,conv,false)!=a)throw std::runtime_error("roundtrip mismatch");count++;}std::cout<<"{\"roundtrip_cases\":"<<count<<",\"all_passed\":true}\n";}
int main(int argc,char**argv){try{if(argc<2)throw std::runtime_error("usage: double_search check | control MODEL HOLDOUT W1 W2 SEED RESTARTS STEPS [CONV] [TOL] [GREEDY] | solve MODEL CT1 CT2 W1 W2 SEED RESTARTS STEPS [CONV] [TOL] [GREEDY]");std::string mode=argv[1];if(mode=="check"){roundtrip();return 0;}if(mode!="control"&&mode!="solve")throw std::runtime_error("mode must be check, control or solve");bool ctl=mode=="control";int off=ctl?0:1;if(argc<9+off)throw std::runtime_error("missing arguments");Model m(argv[2]);int w1=std::stoi(argv[4+off]),w2=std::stoi(argv[5+off]),seed=std::stoi(argv[6+off]),restarts=std::stoi(argv[7+off]),steps=std::stoi(argv[8+off]);
 int conv=argc>9+off?std::stoi(argv[9+off]):0,tol=argc>10+off?std::stoi(argv[10+off]):-1;bool greedy=argc>11+off?std::stoi(argv[11+off]):true;
 if(w1<2||w2<2)throw std::runtime_error("key widths must be at least 2");if(restarts<1||steps<1)throw std::runtime_error("restarts and steps must be positive");if(conv<0||conv>3)throw std::runtime_error("convention must be 0..3");if(tol< -1)throw std::runtime_error("offset tolerance must be -1 or nonnegative");
 Ms ct,pt;V tk1,tk2;
 if(ctl){V body=read(argv[3]);if(body.size()<775)throw std::runtime_error("holdout requires at least 775 letters");RNG r(seed);int pos=r()%(body.size()-774);pt={V(body.begin()+pos,body.begin()+pos+615),V(body.begin()+pos+615,body.begin()+pos+775)};tk1=perm(w1,r);tk2=perm(w2,r);for(auto&a:pt)ct.push_back(crypt(a,tk1,tk2,conv,true));}
 else{ct={read(argv[3]),read(argv[4])};}
 for(auto&a:ct)if(a.size()<4||(size_t)w1>a.size()||(size_t)w2>a.size())throw std::runtime_error("each ciphertext must have at least 4 letters and accommodate both key widths");
 const uint64_t search_seed=uint64_t(seed)^0x9e3779b97f4a7c15ULL;
 for(int nmsg:{1,2}){Ms used(ct.begin(),ct.begin()+nmsg);auto t=std::chrono::steady_clock::now();auto best=solve(used,w1,w2,conv,m,search_seed,restarts,steps,tol,greedy);double sec=std::chrono::duration<double>(std::chrono::steady_clock::now()-t).count();bool encok=true;Ms dec;for(auto&a:ct){auto p=crypt(a,best.k1,best.k2,conv,false);encok&=crypt(p,best.k1,best.k2,conv,true)==a;dec.push_back(p);}
  std::cout<<std::setprecision(9)<<"{\"mode\":\""<<mode<<"\",\"messages_scored\":"<<nmsg<<",\"lengths\":["<<ct[0].size()<<','<<ct[1].size()<<"],\"w1\":"<<w1<<",\"w2\":"<<w2<<",\"seed\":"<<seed<<",\"search_seed\":"<<search_seed<<",\"restarts\":"<<restarts<<",\"steps_per_restart\":"<<steps<<",\"convention\":"<<conv<<",\"offset_tolerance\":"<<tol<<",\"greedy_idp\":"<<(greedy?"true":"false")<<",\"q4\":"<<best.score<<",\"seconds\":"<<sec<<",\"reencryption\":"<<(encok?"true":"false")<<",\"k1\":"<<keyjson(best.k1)<<",\"k2\":"<<keyjson(best.k2);
  if(ctl){std::cout<<",\"true_k1\":"<<keyjson(tk1)<<",\"true_k2\":"<<keyjson(tk2)<<",\"exact_k1\":"<<(tk1==best.k1?"true":"false")<<",\"exact_k2\":"<<(tk2==best.k2?"true":"false")<<",\"correct_letters\":["<<correct(dec[0],pt[0])<<','<<correct(dec[1],pt[1])<<"],\"true_q4_scored\":"<<ngram(Ms(pt.begin(),pt.begin()+nmsg),m,4);}
  std::cout<<",\"plaintexts\":[\""<<letters(dec[0])<<"\",\""<<letters(dec[1])<<"\"]}\n"<<std::flush;
 }return 0;}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}

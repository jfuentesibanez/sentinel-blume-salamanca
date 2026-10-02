// Phase 15: privileged fixed anchors; no search or target identity comparison.
// Frozen legacy matrix + CrypTool Apache-2.0 movement port; see ATTRIBUTION.txt.
#include "../phase4_crypto/source_moves.h"
#include <cstring>
#include <climits>

using Clock=std::chrono::steady_clock;
long backend_legacy_calls=0,backend_exact_calls=0;
void charge_backend(bool legacy){
 if(legacy)backend_legacy_calls++;else backend_exact_calls++;
 // Before entering a backend, preserve the invocation even after abrupt death.
 std::cerr<<"@calls "<<backend_legacy_calls<<' '<<backend_exact_calls<<'\n'<<std::flush;
}
double elapsed(Clock::time_point t){return std::chrono::duration<double>(Clock::now()-t).count();}
struct Dyadic {int64_t significand;int exponent;};
Dyadic dyadic(float f){
 uint32_t u;std::memcpy(&u,&f,4);int e=(u>>23)&255;uint32_t mant=u&0x7fffff;
 if(e==255)throw std::runtime_error("nonfinite binary32 entry");
 if(e==0&&mant==0)return {0,0};
 int exponent=e?e-127-23:-149;uint32_t s=e?(mant|0x800000):mant;
 while((s&1)==0){s>>=1;exponent++;}
 return {(u>>31)?-int64_t(s):int64_t(s),exponent};
}
int64_t checked128(__int128 v){if(v<INT64_MIN||v>INT64_MAX)throw std::runtime_error("int64 overflow");return int64_t(v);}
int64_t times_power(int64_t v,int shift){
 if(shift<0||shift>62)throw std::runtime_error("unsupported dyadic scale");
 return checked128(__int128(v)*(__int128(1)<<shift));
}
struct ExactModel {
 int shift=0;int64_t scale=1,max_abs=0;std::vector<int64_t>b;
 explicit ExactModel(const Model&m){
  if(m.b.size()!=676)throw std::runtime_error("expected 676 bigrams");
  std::vector<Dyadic>d;int exponent=0;
  for(float f:m.b){d.push_back(dyadic(f));if(d.back().significand)exponent=std::min(exponent,d.back().exponent);}
  shift=-exponent;if(shift>62)throw std::runtime_error("dyadic denominator exceeds int64 range");
  scale=int64_t(1)<<shift;
  for(auto x:d){int64_t n=x.significand?times_power(x.significand,x.exponent+shift):0;
   if(n==INT64_MIN)throw std::runtime_error("absolute bound overflow");
   b.push_back(n);max_abs=std::max(max_abs,std::abs(n));}
 }
 int64_t bound(int rows,int width,int messages)const{
  // Diagonal sentinel never selected as a regular edge; still bound its storage.
  checked128(__int128(1000000)*scale*messages);
  int64_t floor=checked128(__int128(7)*scale);
  return checked128(__int128(std::max(max_abs,floor))*rows*width);
 }
};
struct Legacy {double score;std::vector<double>matrix;V edges;int forced=0;};
struct Exact {int64_t numerator,denominator;std::vector<int64_t>matrix;V edges;int forced=0;};
Legacy legacy_trace(const Ms&I,int w,const Model&m){
 charge_backend(true);
 Legacy r; r.matrix.assign(w*w,0);int nr=0;
 for(const auto&a:I){auto T=matrix(a,w,m,-1);nr+=a.size()/w;for(int z=0;z<w*w;z++)r.matrix[z]+=T[z];}
 double total=0;V ua(w),ub(w);
 for(int step=0;step<w;step++){
  double best=-1e100;int x=-1,y=-1;
  for(int a=0;a<w;a++)if(!ua[a])for(int b=0;b<w;b++)if(!ub[b]&&a!=b&&r.matrix[a*w+b]>best){best=r.matrix[a*w+b];x=a;y=b;}
  if(x<0){for(int a=0;a<w;a++)if(!ua[a])x=a;for(int b=0;b<w;b++)if(!ub[b])y=b;best=-7.0*nr;r.forced++;}
  total+=best;ua[x]=ub[y]=1;r.edges.push_back(x*w+y);
 }
 if(nr==0)throw std::runtime_error("zero row normalizer");r.score=total/(nr*w);return r;
}
std::vector<int64_t> exact_matrix(const V&I,int w,const ExactModel&m){
 int rows=I.size()/w,rem=I.size()%w;std::vector<int64_t>S(w*w,checked128(-__int128(1000000)*m.scale));V lo(w),hi(w);
 for(int k=0;k<w;k++){lo[k]=std::max(0,k-(w-rem));hi[k]=std::min(k,rem);}
 for(int a=0;a<w;a++)for(int b=0;b<w;b++)if(a!=b){
  int64_t best=INT64_MIN;
  for(int d=lo[b]-hi[a];d<=hi[b]-lo[a];d++){
   int l=std::max(lo[a],lo[b]-d),h=std::min(hi[a],hi[b]-d);if(l>h)continue;
   int p=a*rows+l,q=b*rows+d+l;int64_t sum=0;
   for(int r=0;r<rows;r++)sum+=m.b[I[p+r]*26+I[q+r]];
   best=std::max(best,sum);
   for(int u=l+1;u<=h;u++){
    // All sums are exact integers after the checked whole-score bound.
    sum+=m.b[I[p+rows]*26+I[q+rows]]-m.b[I[p]*26+I[q]];p++;q++;best=std::max(best,sum);
   }
  }
  if(best==INT64_MIN)throw std::runtime_error("empty feasible boundary range");S[a*w+b]=best;
 }
 return S;
}
Exact exact_trace(const Ms&I,int w,const ExactModel&m){
 charge_backend(false);
 Exact r;r.matrix.assign(w*w,0);int nr=0;for(const auto&a:I)nr+=a.size()/w;
 if(nr==0)throw std::runtime_error("zero row normalizer");m.bound(nr,w,I.size());
 r.denominator=checked128(__int128(m.scale)*nr*w);
 for(const auto&a:I){auto T=exact_matrix(a,w,m);for(int z=0;z<w*w;z++)r.matrix[z]+=T[z];}
 int64_t total=0;V ua(w),ub(w);
 for(int step=0;step<w;step++){
  int64_t best=INT64_MIN;int x=-1,y=-1;
  for(int a=0;a<w;a++)if(!ua[a])for(int b=0;b<w;b++)if(!ub[b]&&a!=b&&r.matrix[a*w+b]>best){best=r.matrix[a*w+b];x=a;y=b;}
  if(x<0){for(int a=0;a<w;a++)if(!ua[a])x=a;for(int b=0;b<w;b++)if(!ub[b])y=b;best=checked128(-__int128(7)*nr*m.scale);r.forced++;}
  total+=best;ua[x]=ub[y]=1;r.edges.push_back(x*w+y);
 }
 r.numerator=total;return r;
}
bool exact_improves(int64_t candidate,int64_t initial,int64_t denominator){
 if(denominator<=0)throw std::runtime_error("nonpositive exact denominator");
 return (__int128(candidate)-initial)*1000000000000LL>denominator;
}
void validate(const V&a,int w){V sorted=a;std::sort(sorted.begin(),sorted.end());if((int)a.size()!=w)throw std::runtime_error("anchor length mismatch");for(int i=0;i<w;i++)if(sorted[i]!=i)throw std::runtime_error("anchor is not a permutation");}
V anchor_read(const std::string&path,int w){std::ifstream f(path);if(!f)throw std::runtime_error("anchor unavailable");V a;int v;while(f>>v)a.push_back(v);if(!f.eof())throw std::runtime_error("invalid anchor file");validate(a,w);return a;}
std::string packed_edges(const V&a){std::ostringstream s;for(size_t i=0;i<a.size();i++){if(i)s<<':';s<<a[i];}return s.str();}
double max_matrix_difference(const Legacy&l,const Exact&e,int64_t scale){double v=0;for(size_t i=0;i<l.matrix.size();i++)v=std::max(v,std::abs(l.matrix[i]-double(e.matrix[i])/scale));return v;}

int static_main(int argc,char**argv){
 if(argc!=12)throw std::runtime_error("static MODEL CT1 CT2 ANCHOR W1 W2 CSV SUMMARY SECONDS MAX_STATES");
 auto began=Clock::now();Model m(argv[2]);Ms ct={read(argv[3]),read(argv[4])};int w1=std::stoi(argv[6]),w2=std::stoi(argv[7]);
 double seconds=std::stod(argv[10]);int max_states=std::stoi(argv[11]);if(w1<2||w2<2||!std::isfinite(seconds)||seconds<=0||max_states<1)throw std::runtime_error("invalid limit/width");
 for(const auto&a:ct)if((int)a.size()<std::max(w1,w2))throw std::runtime_error("input too short");
 V anchor=anchor_read(argv[5],w2);auto moves=source_moves(w2);if(max_states>(int)moves.size()+1)throw std::runtime_error("states exceed fixed neighborhood");
 ExactModel em(m);int nr=0;for(const auto&a:ct)nr+=a.size()/w1;int64_t bound=em.bound(nr,w1,ct.size());
 std::ofstream csv(argv[8]);if(!csv)throw std::runtime_error("CSV unavailable");
 csv<<"index,kind,legacy,exact_numerator,legacy_improves_anchor,exact_improves_anchor,legacy_edges,exact_edges,legacy_forced,exact_forced,matrix_max_abs_diff\n"<<std::setprecision(17);
 double setup=elapsed(began),legacy_seconds=0,exact_seconds=0,max_error=0,max_matrix_error=0;
 int done=0,decisions=0,edge_changes=0;int64_t base_num=0,den=0;double base_score=0;std::string stop="complete";
 for(int index=0;index<max_states;index++){
  if(elapsed(began)>=seconds){stop="time_cut";break;}
  // Exactly one fixed-anchor proposal, never the previous best.
  V numeric=index?moved(anchor,moves[index-1]):anchor;Ms I=undo2(ct,inverse(numeric),0);
  auto t=Clock::now();Legacy l=legacy_trace(I,w1,m);legacy_seconds+=elapsed(t);
  t=Clock::now();Exact e=exact_trace(I,w1,em);exact_seconds+=elapsed(t);
  if(!std::isfinite(l.score))throw std::runtime_error("nonfinite legacy score");
  if(index==0){base_num=e.numerator;base_score=l.score;den=e.denominator;}
  if(e.denominator!=den)throw std::runtime_error("denominator changed");
  bool li=l.score>base_score+1e-12,ei=exact_improves(e.numerator,base_num,den);
  double err=std::abs(l.score-double(e.numerator)/den),me=max_matrix_difference(l,e,em.scale);
  decisions+=li!=ei;edge_changes+=l.edges!=e.edges;max_error=std::max(max_error,err);max_matrix_error=std::max(max_matrix_error,me);
  csv<<index<<','<<(index?moves[index-1].kind:-1)<<','<<l.score<<','<<e.numerator<<','<<int(li)<<','<<int(ei)<<','<<packed_edges(l.edges)<<','<<packed_edges(e.edges)<<','<<l.forced<<','<<e.forced<<','<<me<<'\n';done++;
 }
 csv.close();double sec=elapsed(began);if(done==max_states&&max_states<(int)moves.size()+1)stop="fixture_state_cap";
 std::ofstream summary(argv[9]);if(!summary)throw std::runtime_error("summary unavailable");
 summary<<std::setprecision(17)<<"{\"mode\":\"static\",\"anchor_numeric\":"<<keyjson(anchor)<<",\"w1\":"<<w1<<",\"w2\":"<<w2<<",\"convention\":0,\"lengths\":["<<ct[0].size()<<','<<ct[1].size()<<"],\"source_moves\":"<<moves.size()<<",\"requested_states\":"<<max_states<<",\"states_completed\":"<<done<<",\"legacy_calls\":"<<done<<",\"exact_calls\":"<<done<<",\"idp_equivalent_calls\":"<<2*done<<",\"anchor_updated\":false,\"denominator_shift\":"<<em.shift<<",\"scale\":"<<em.scale<<",\"idp_denominator\":"<<den<<",\"checked_absolute_numerator_bound\":"<<bound<<",\"max_score_absolute_difference\":"<<max_error<<",\"max_matrix_absolute_difference\":"<<max_matrix_error<<",\"improvement_decision_discrepancies\":"<<decisions<<",\"greedy_edge_discrepancies\":"<<edge_changes<<",\"seconds_limit\":"<<seconds<<",\"setup_seconds\":"<<setup<<",\"legacy_seconds\":"<<legacy_seconds<<",\"exact_seconds\":"<<exact_seconds<<",\"seconds\":"<<sec<<",\"soft_excess_seconds\":"<<std::max(0.0,sec-seconds)<<",\"stop_reason\":\""<<stop<<"\"}\n";
 return 0;
}

int selftest(const std::string&model_path){
 Model m(model_path);int legacy_calls=0,exact_calls=0;std::vector<std::string>names;
 auto check=[&](const std::string&name,const Ms&I,int w){
  ExactModel em(m);Legacy l=legacy_trace(I,w,m);legacy_calls++;
  charge_backend(true);double frozen=idp(I,w,0,m,-1,true);legacy_calls++;
  Exact e=exact_trace(I,w,em);exact_calls++;
  if(l.score!=frozen)throw std::runtime_error("traced legacy differs from frozen idp");
  if(name=="uniform_greedy_forced_floor"&&(e.numerator!=-55||e.denominator!=15||e.forced!=1||l.forced!=1))throw std::runtime_error("uniform floor expected value");
  if(name=="uniform_remainder_zero"&&(e.numerator!=-24||e.denominator!=12||e.forced!=0))throw std::runtime_error("uniform exact expected value");
  if(name=="float_sliding_rounding"){
   int slot=1*3+2;int64_t expected=em.b[2*26+4];
   if(e.matrix[slot]!=expected||l.matrix[slot]==double(expected)/em.scale||e.numerator!=expected-14*em.scale||e.denominator!=3*em.scale)throw std::runtime_error("sliding discrepancy/exact expected value fixture");
  }
  names.push_back(name);std::cout<<std::setprecision(17)<<"{\"fixture\":\""<<name<<"\",\"legacy\":"<<l.score<<",\"frozen_idp\":"<<frozen<<",\"exact_numerator\":"<<e.numerator<<",\"exact_denominator\":"<<e.denominator<<",\"scale\":"<<em.scale<<",\"legacy_edges\":"<<keyjson(l.edges)<<",\"exact_edges\":"<<keyjson(e.edges)<<",\"legacy_forced\":"<<l.forced<<",\"exact_forced\":"<<e.forced<<",\"matrix_max_abs_diff\":"<<max_matrix_difference(l,e,em.scale)<<"}\n";
 };
 std::fill(m.b.begin(),m.b.end(),-2.0f);check("uniform_greedy_forced_floor",{{0,1,2,3,4,5,6,7,8,9,10},{1,0,1,0,1,0,1}},3);
 check("uniform_remainder_zero",{{0,1,2,3,4,5,6,7},{1,2,3,4}},4);
 std::fill(m.b.begin(),m.b.end(),-7.0f);m.b[1*26+3]=-6.898953914642334f;m.b[2*26+4]=-2.495816469192505f;
 check("float_sliding_rounding",{{0,1,2,3,4}},3);
 float pzero=0.0f,nzero=-0.0f;auto p=dyadic(pzero),n=dyadic(nzero);if(p.significand||n.significand)throw std::runtime_error("zero fixture");
 if(dyadic(-2.5f).significand!=-5||dyadic(-2.5f).exponent!=-1)throw std::runtime_error("dyadic fixture");
 if(exact_improves(1,0,2000000000000LL)||exact_improves(1,0,1000000000000LL)||!exact_improves(2,0,1000000000000LL))throw std::runtime_error("exact epsilon fixture");
 int rejected=0;auto reject=[&](float f){auto b=m.b;m.b[0]=f;try{ExactModel em(m);}catch(const std::exception&){rejected++;}m.b=b;};
 reject(std::numeric_limits<float>::denorm_min());reject(std::numeric_limits<float>::infinity());reject(std::numeric_limits<float>::quiet_NaN());reject(std::numeric_limits<float>::max());
 if(rejected!=4)throw std::runtime_error("unsafe model not rejected");
 bool bound_rejected=false;try{ExactModel em(m);em.bound(INT_MAX,INT_MAX,2);}catch(const std::exception&){bound_rejected=true;}if(!bound_rejected)throw std::runtime_error("whole-score overflow not rejected");
 auto moves=source_moves(25);if(moves.size()!=16649)throw std::runtime_error("movement count changed");
 V id(25);std::iota(id.begin(),id.end(),0);V native=id,omitted=id;std::swap(native[0],native[1]);std::swap(omitted[1],omitted[24]);bool has_native=false,has_omitted=false;for(const auto&mv:moves){has_native|=mv.p==native;has_omitted|=mv.p==omitted;}if(!has_native||has_omitted)throw std::runtime_error("swap coverage fixture");
 std::cout<<"{\"status\":\"passed\",\"legacy_calls\":"<<legacy_calls<<",\"exact_calls\":"<<exact_calls<<",\"idp_equivalent_calls\":"<<legacy_calls+exact_calls<<",\"fixtures\":3,\"epsilon_tests\":3,\"model_rejections\":4,\"bound_rejection\":true,\"source_moves\":16649}\n";return 0;
}
int main(int argc,char**argv){try{
 if(argc>=2&&std::string(argv[1])=="static")return static_main(argc,argv);
 if(argc==3&&std::string(argv[1])=="selftest")return selftest(argv[2]);
 if(argc==2&&std::string(argv[1])=="geometry"){
  auto moves=source_moves(25);std::cout<<"{\"width\":25,\"identity_index\":0,\"moves\":[";
  for(size_t i=0;i<moves.size();i++){if(i)std::cout<<',';std::cout<<"{\"index\":"<<i+1<<",\"kind\":"<<moves[i].kind<<",\"p\":"<<keyjson(moves[i].p)<<'}';}
  std::cout<<"],\"legacy_calls\":0,\"exact_calls\":0}\n";return 0;
 }
 throw std::runtime_error("usage: static ... | selftest MODEL | geometry");
 }catch(const std::exception&e){std::cerr<<e.what()<<'\n';std::cout<<"{\"status\":\"failed\",\"legacy_calls\":"<<backend_legacy_calls<<",\"exact_calls\":"<<backend_exact_calls<<",\"idp_equivalent_calls\":"<<backend_legacy_calls+backend_exact_calls<<"}\n";return 1;}}

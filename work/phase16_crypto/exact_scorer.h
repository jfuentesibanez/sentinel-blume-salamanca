#pragma once
// Exact phase15 fragments, unchanged. See build_record.json and attribution.
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
struct Exact {int64_t numerator,denominator;std::vector<int64_t>matrix;V edges;int forced=0;};
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

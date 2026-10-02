#define main original_main
#include "double_search_bfcc0c60.cpp"
#undef main
// Reference enc builds columns by original position before applying read order.
V reference(const V&a,const V&k,bool enc){
 std::vector<V> cols(k.size());
 if(enc){for(size_t i=0;i<a.size();i++) cols[i%k.size()].push_back(a[i]);V out;for(int c:k)out.insert(out.end(),cols[c].begin(),cols[c].end());return out;}
 size_t pos=0;for(int c:k){size_t len=(a.size()+k.size()-1-c)/k.size();cols[c]=V(a.begin()+pos,a.begin()+pos+len);pos+=len;}
 V out;for(size_t i=0;i<a.size();i++)out.push_back(cols[i%k.size()][i/k.size()]);return out;
}
V refcrypt(const V&a,const V&k1,const V&k2,int c,bool enc){
 const bool d1=c==1||c==2,d2=c==1||c==3;
 if(enc){auto stage1=reference(a,k1,!d1);return reference(stage1,k2,!d2);}
 auto stage2=reference(a,k2,d2);return reference(stage2,k1,d1);
}
std::vector<double> refmatrix(const V&a,int w,const Model&m,int tol){
 int q=a.size()/w,r=a.size()%w;std::vector<double> out(w*w,-1e6);
 auto bounds=[&](int c){int l=std::max(0,c-(w-r)),h=std::min(c,r);if(tol>=0){int x=std::lround((double)c*r/w);l=std::max(l,x-tol);h=std::min(h,x+tol);}return std::pair<int,int>(l,h);};
 for(int x=0;x<w;x++)for(int y=0;y<w;y++)if(x!=y){auto bx=bounds(x),by=bounds(y);double best=-1e100;
  for(int ix=bx.first;ix<=bx.second;ix++)for(int iy=by.first;iy<=by.second;iy++){double score=0;for(int row=0;row<q;row++)score+=m.b[a[x*q+ix+row]*26+a[y*q+iy+row]];best=std::max(best,score);}out[x*w+y]=best;}
 return out;
}
int main(){RNG r(713);int tests=0;
 for(int n=1;n<=45;n++)for(int w=2;w<=12;w++){V a(n);std::iota(a.begin(),a.end(),0);V k=perm(w,r);
  for(bool enc:{false,true}){if(col(a,k,enc)!=reference(a,k,enc))throw std::runtime_error("single reference mismatch");tests++;}}
 for(int n:{160,615})for(int w1:{5,8,15,16,20,23})for(int w2:{5,8,15,16,20,23})for(int c=0;c<4;c++){V a(n);std::iota(a.begin(),a.end(),0);auto k1=perm(w1,r),k2=perm(w2,r);for(bool enc:{false,true}){if(crypt(a,k1,k2,c,enc)!=refcrypt(a,k1,k2,c,enc))throw std::runtime_error("double reference mismatch");tests++;}}
 V a(17);std::iota(a.begin(),a.end(),0);V k={2,0,3,1};std::cout<<"known_17_width4=";for(int v:col(a,k,true))std::cout<<char('A'+v);std::cout<<"\nreference_cases="<<tests<<"\n";
 Model m("work/crypto/model_es.bin");for(int n=1;n<=45;n++)for(int w=2;w<=12;w++){V s(n);for(int&v:s)v=r()%26;for(int tol:{-1,0,2}){auto mat=matrix(s,w,m,tol);if(mat.size()!=size_t(w*w))throw std::runtime_error("matrix bad size");auto ref=refmatrix(s,w,m,tol);for(size_t i=0;i<ref.size();i++)if(std::abs(mat[i]-ref[i])>1e-5)throw std::runtime_error("matrix brute mismatch");}}
 std::cout<<"matrix_reference_cases="<<45*11*3<<"\n";
}

// Separate planted-key and independent-start streams. No objective or truth inputs.
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
void print(const std::vector<int>& v){std::cout<<'[';for(size_t i=0;i<v.size();i++){if(i)std::cout<<',';std::cout<<v[i];}std::cout<<']';}
int main(int argc,char**argv){try{
 if(argc!=3)throw std::runtime_error("generate plant|start SEED");
 std::string mode=argv[1];if(mode!="plant"&&mode!="start")throw std::runtime_error("mode");
 uint64_t seed=std::stoull(argv[2]);std::mt19937_64 rng(seed);
 std::vector<int>a(20),b(25);std::iota(a.begin(),a.end(),0);std::iota(b.begin(),b.end(),0);
 if(mode=="plant")std::shuffle(a.begin(),a.end(),rng);
 std::shuffle(b.begin(),b.end(),rng);
 std::cout<<"{\"mode\":\""<<mode<<"\",\"seed\":"<<seed;
 if(mode=="plant"){std::cout<<",\"k1\":";print(a);std::cout<<",\"k2\":";}else std::cout<<",\"numeric\":";
 print(b);std::cout<<"}\n";return 0;
 }catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}

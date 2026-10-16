// Untouched mapped 81AE40 against the private environment decision tree.
// Synthetic vtables RECORD effects (including intermediate fields); they do not
// stand in for the gameplay/RNG closure of the real transition implementations.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <xmmintrin.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <vector>
#include "native_image_relocation.h"
#include "native_env.h"
#pragma fenv_access(on)
namespace e=ntw2_env;
using U=uint32_t; using B=uint8_t;
extern "C" unsigned long _tls_index;
__declspec(thread) static volatile U tlsPad[32];
static B* image; static U delta,checks,cases,rounding;
static const char* current="map";
static e::WorkerScratch work;
static e::Result observed;
static U native_queue[65536]; static uint16_t native_touched[65536];
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> static U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static B* At(U va) { return reinterpret_cast<B*>(delta+va); }
template<class T> static T Get(const void* p,U offset) { T v; std::memcpy(&v,static_cast<const B*>(p)+offset,sizeof(v)); return v; }
template<class T> static void Put(void* p,U offset,T v) { std::memcpy(static_cast<B*>(p)+offset,&v,sizeof(v)); }
static void Require(bool ok,const char* what) { ++checks; if(!ok) { std::fprintf(stderr,"FAIL [%s] %s\n",current,what); std::exit(1); } }
static void Equal(U expected,U actual,const char* what) { ++checks; if(expected!=actual) { std::fprintf(stderr,"FAIL [%s] %s expected=%08X actual=%08X\n",current,what,expected,actual); std::exit(1); } }
static U Bits(float f) { U bits; std::memcpy(&bits,&f,4); return bits; }
static void ResetFp() { unsigned short cw=static_cast<unsigned short>(0x27F|(rounding<<10)); __asm fninit
 __asm fldcw cw
 _mm_setcsr(0x1F80|(rounding<<13)); }
static void Map(const char* path) {
 FILE* f=std::fopen(path,"rb"); Require(f!=nullptr,"open image read-only");
 Require(!std::fseek(f,0,SEEK_END),"seek"); long n=std::ftell(f); std::rewind(f);
 Require(n>0 && n<256*1024*1024,"image size"); std::vector<B> bytes(static_cast<size_t>(n));
 Require(std::fread(bytes.data(),1,bytes.size(),f)==bytes.size(),"read image"); std::fclose(f);
 BCRYPT_ALG_HANDLE alg=nullptr; B digest[32];
 Require(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)==0,"SHA provider");
 Require(BCryptHash(alg,nullptr,0,bytes.data(),static_cast<ULONG>(bytes.size()),digest,32)==0,"hash image"); BCryptCloseAlgorithmProvider(alg,0);
 char hex[65]; for(U i=0;i<32;++i) std::snprintf(hex+2*i,3,"%02x",digest[i]);
 Require(!std::strcmp(hex,"13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4"),"supported Steam image");
 const auto* dos=reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
 const auto* nt=reinterpret_cast<const IMAGE_NT_HEADERS32*>(bytes.data()+dos->e_lfanew);
 Require(nt->OptionalHeader.ImageBase==0x400000,"image base");
 image=static_cast<B*>(VirtualAlloc(nullptr,nt->OptionalHeader.SizeOfImage,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE));
 Require(image!=nullptr,"map image"); delta=A(image)-0x400000;
 std::memcpy(image,bytes.data(),nt->OptionalHeader.SizeOfHeaders); const auto* sections=IMAGE_FIRST_SECTION(nt);
 for(U i=0;i<nt->FileHeader.NumberOfSections;++i) std::memcpy(image+sections[i].VirtualAddress,bytes.data()+sections[i].PointerToRawData,std::min(sections[i].SizeOfRawData,sections[i].Misc.VirtualSize));
 Require(RelocateNativeImage(image,nt->OptionalHeader.SizeOfImage,reinterpret_cast<IMAGE_NT_HEADERS32*>(image+dos->e_lfanew),delta),"relocate image");
 // Data-only scratch publication: no allocator/init detours, no .text patches.
 Put<U>(At(0x1841BB8),0,_tls_index); tlsPad[0]=0;
 Put<U>(At(0x15A3904),0,0x80000000u); Put<U>(At(0x15A391C),0,0x80000000u);
 Put<U>(At(0x15A38F4),4,65536); Put<U>(At(0x15A38F4),8,0); Put<U>(At(0x15A38F4),12,A(native_touched));
 Put<U>(At(0x15A3908),0,65536); Put<U>(At(0x15A3908),4,A(native_queue));
 for(U i=0;i<nt->FileHeader.NumberOfSections;++i) if(sections[i].Characteristics&IMAGE_SCN_MEM_EXECUTE) {
  DWORD old; Require(VirtualProtect(image+sections[i].VirtualAddress,sections[i].Misc.VirtualSize,PAGE_EXECUTE_READ,&old)!=0,"protect original code read-only");
 }
 Require(FlushInstructionCache(GetCurrentProcess(),image,nt->OptionalHeader.SizeOfImage)!=0,"flush mapping");
}
static B __fastcall Eligible(void* p,void*) { return Get<B>(p,4); }
static B __fastcall OwnerPolicy(void* p,void*) { return Get<B>(p,0x40); }
static B __fastcall Capable(void* p,void*) { return Get<B>(p,0x120); }
static U __fastcall Identity(void* p,void*) { return Get<U>(p,0x124); }
static void Record(void* p,e::EventKind kind,U target) {
 Require(observed.event_count<2,"bounded transition trace"); auto& event=observed.events[observed.event_count++]; event={};
 event.kind=kind; event.receiver=A(p); event.target=target; event.owner=Get<U>(p,0x10); event.b4=Get<B>(p,0xB4); event.b5=Get<B>(p,0xB5);
}
static void __fastcall Leave(void* p,void*) { Record(p,e::EventKind::Leave,Fn(&Leave)); }
static void __fastcall Land(void* p,void*) { Record(p,e::EventKind::Land,Fn(&Land)); }
static void __fastcall Secondary(void* p,void*) { Record(p,e::EventKind::Secondary,Fn(&Secondary)); }
static B* notification_agent;
static void __fastcall Notify(void* p,void*,const U* packet) {
 Record(notification_agent,e::EventKind::Notification,Fn(&Notify)); auto& event=observed.events[observed.event_count-1]; event.receiver=A(p);
 std::memcpy(event.args,packet,sizeof(event.args));
}
struct Point { float x,z; };
struct Fixture {
 B agent[0x140]{}, owners[3][0x48]{}, edges[3][4][0x50]{}, terrain[0x28]{}, environment[0xFF0]{};
 U agent_vt[28]{}, owner_vt[10]{}, eligible_vt[1]{}, notification_vt[3]{};
 U context[3]{},model[40]{},candidates[3]{},list[5]{},scratch[1]{},adjacency[3][4][4]{};
 float cells[32]{};
 Fixture() {
  agent_vt[0x14/4]=Fn(&Identity); agent_vt[0x50/4]=Fn(&Capable); agent_vt[0x64/4]=Fn(&Leave); agent_vt[0x68/4]=Fn(&Land); agent_vt[0x6C/4]=Fn(&Secondary);
  owner_vt[0x24/4]=Fn(&OwnerPolicy); eligible_vt[0]=Fn(&Eligible); notification_vt[2]=Fn(&Notify);
  Put<U>(agent,0,A(agent_vt)); Put<U>(agent,0x28,A(context)); context[2]=A(model); model[0x94/4]=A(environment); model[0x9C/4]=A(terrain);
  Put<U>(environment,0xFE0,A(notification_vt)); Put<U>(agent,0x124,A(agent)); Put<B>(agent,0x120,1);
  Put<float>(agent,0x54,1); Put<float>(agent,0xD4,1);
  Put<U>(terrain,0,A(cells)); Put<U>(terrain,8,2); Put<U>(terrain,0x10,1); Put<U>(terrain,0x14,3);
  Put<float>(terrain,0x1C,1); Put<float>(terrain,0x20,1); Put<float>(terrain,0x24,1);
  for(U i=0;i<16;++i) { cells[2*i]=0; cells[2*i+1]=-1; }
  list[2]=3; list[4]=A(candidates); scratch[0]=A(list);
  for(U o=0;o<3;++o) {
   candidates[o]=A(owners[o]); Put<U>(owners[o],0,A(owner_vt)); Put<U>(owners[o],8,A(edges[o][0])); Put<U>(owners[o],0x1C,A(eligible_vt)); Put<B>(owners[o],0x20,1);
   Put<uint16_t>(owners[o],0x2C,static_cast<uint16_t>(o)); Put<float>(owners[o],0x34,1);
   const float cx=static_cast<float>(o)*4; const Point points[4]={{cx-2,-2},{cx-2,2},{cx+2,2},{cx+2,-2}};
   for(U j=0;j<4;++j) { Put<U>(edges[o][j],8,A(edges[o][(j+1)%4])); Put<Point>(edges[o][j],0xC,points[j]); Put<U>(edges[o][j],0x48,A(adjacency[o][j])); }
  }
 }
 void Owner(U o) { Put<U>(agent,0x10,A(owners[o])); }
 void Position(float x,float y,float z) { Put<float>(agent,0x48,x); Put<float>(agent,0x4C,y); Put<float>(agent,0x50,z); }
 void Air(float y,float dy) { Put<B>(agent,0xB4,1); Put<float>(agent,0x4C,y); Put<float>(agent,0xD8,dy); }
 void Surface(float ground,float surface) { for(U i=0;i<16;++i) { cells[2*i]=ground; cells[2*i+1]=surface; } }
 void Adj(U o,U edge,U neighbor,U opposite) { Put<U>(edges[o][edge],0x44,1); adjacency[o][edge][0]=A(owners[neighbor]); adjacency[o][edge][1]=A(edges[neighbor][opposite]); }
};
static void Original(Fixture& f) {
 notification_agent=f.agent; observed={};
 reinterpret_cast<void(__thiscall*)(void*,void*)>(delta+0x81AE40)(f.agent,f.scratch);
}
static void Compare(Fixture& f,const char* name) {
 current=name; ++cases; ResetFp();
 B unchanged[sizeof(Fixture)]; std::memcpy(unchanged,&f,sizeof(f));
 e::AgentView a; e::Scene s; e::Capture(reinterpret_cast<e::Agent*>(f.agent),reinterpret_cast<e::Scratch*>(f.scratch),a,s);
 e::Result predicted; ResetFp(); e::Run(a,s,work,predicted); ResetFp(); Original(f);
 Equal(Get<U>(f.agent,0x10),a.owner,"owner"); Equal(Get<B>(f.agent,0xB4),a.b4,"B4"); Equal(Get<B>(f.agent,0xB5),a.b5,"B5"); Equal(observed.event_count,predicted.event_count,"event sequence length");
 Put<U>(unchanged,0x10,a.owner); Put<B>(unchanged,0xB4,a.b4); Put<B>(unchanged,0xB5,a.b5);
 Require(!std::memcmp(unchanged,&f,sizeof(f)),"only three direct agent outputs change; geometry/candidates untouched");
 for(U i=0;i<predicted.event_count;++i) {
  const auto& x=observed.events[i]; const auto& y=predicted.events[i];
  Equal(static_cast<U>(x.kind),static_cast<U>(y.kind),"event kind"); Equal(x.receiver,y.receiver,"event receiver"); Equal(x.target,y.target,"event concrete target");
  Equal(x.owner,y.owner,"owner at effect"); Equal(x.b4,y.b4,"B4 at effect"); Equal(x.b5,y.b5,"B5 at effect");
  for(U j=0;j<4;++j) Equal(x.args[j],y.args[j],"event argument bits");
 }
 Equal(0,work.count,"private FIFO drained"); Equal(0,work.touched_count,"private touched drained");
 for(U v:work.visited) Equal(0,v,"private bitmap clear");
 Equal(0,Get<U>(At(0x15A3908),8),"native FIFO drained"); Equal(0,Get<U>(At(0x15A38F4),8),"native touched drained");
}
static void Cases() {
 { Fixture f; Compare(f,"supported terrain no candidates"); }
 { Fixture f; f.list[3]=3; Compare(f,"first polygon acquisition"); }
 { Fixture f; f.list[3]=3; f.Position(4,0,0); Compare(f,"later polygon acquisition"); }
 for(B policy:{B(0),B(1),B(2)}) { Fixture f; f.list[3]=1; Put<B>(f.owners[0],0x40,policy); Put<float>(f.owners[0],0x3C,-5); Compare(f,"acquisition virtual exact-one"); }
 for(B policy:{B(0),B(1),B(2)}) { Fixture f; f.Owner(0); Put<B>(f.owners[0],0x20,policy); Compare(f,"retain predicate nonzero versus leave"); }
 { Fixture f; f.Owner(0); f.Position(3,0,0); f.Adj(0,2,1,0); f.Adj(1,0,0,2); Compare(f,"adjacent polygon exact containment"); }
 { Fixture f; f.Owner(0); f.Position(3,0,4); f.Adj(0,2,1,1); f.Adj(1,0,0,2); Compare(f,"projection fallback and cyclic adjacency"); }
 { Fixture f; f.Owner(0); f.Position(7,0,0); f.Adj(0,2,1,0); f.Adj(1,2,2,0); Compare(f,"FIFO traversal two hops"); }
 { Fixture f; f.Owner(0); f.Position(7,0,0); f.Adj(0,2,1,0); f.Adj(1,2,2,0); Put<uint16_t>(f.owners[1],0x2C,0); Compare(f,"low-u16 ID alias suppresses traversal"); }
 { Fixture f; f.Owner(0); f.Position(3,0,0); f.Adj(0,2,2,0); Put<U>(f.edges[0][2],0x44,2); f.adjacency[0][2][2]=A(f.owners[1]); f.adjacency[0][2][3]=A(f.edges[1][0]); Compare(f,"first eligible adjacency blocks later match"); }
 for(float y:{-2.0f,0.5f,0.50001f,-2.00001f}) { Fixture f; f.Owner(0); f.Position(4,y,0); f.list[3]=3; Compare(f,"fallback slope thresholds"); }
 for(float x:{-2.0f,2.0f,-2.00001f,2.00001f}) { Fixture f; f.list[3]=1; f.Position(x,0,0); Compare(f,"oriented polygon boundary"); }
 for(float dy:{-1.0f,0.0f,1.0f}) { Fixture f; f.list[3]=1; f.Air(0,dy); Compare(f,"plane crossing endpoint"); }
 { Fixture f; f.Owner(1); f.Air(20,0); Compare(f,"stale nonnull owner lands without candidate"); }
 { Fixture f; f.Air(-1,-2); Put<B>(f.agent,0xB5,1); Compare(f,"secondary flag early return"); }
 for(float surface:{-1.0f,0.0f,0.75f,0.75001f,1.0f,2.0f}) for(float dy:{-3.0f,-1.0f,0.0f,1.0f}) {
  Fixture f; f.Air(1,dy); f.Surface(0,surface); Compare(f,"terrain and secondary crossings");
 }
 for(B capable:{B(0),B(1),B(2)}) for(bool identity:{false,true}) { Fixture f; f.Air(0,-3); f.Surface(-1,1); Put<B>(f.agent,0x120,capable); if(!identity) Put<U>(f.agent,0x124,0); Compare(f,"capability exact-one and optional notification"); }
 const float nan=std::numeric_limits<float>::quiet_NaN(),inf=std::numeric_limits<float>::infinity();
 for(float value:{nan,inf,-inf,0.0f,-0.0f}) {
  { Fixture f; f.list[3]=1; Put<float>(f.owners[0],0x34,value); Compare(f,"exceptional plane denominator"); }
  { Fixture f; f.list[3]=1; f.Position(value,0,0); Compare(f,"exceptional position containment"); }
  { Fixture f; f.Air(value,-1); Compare(f,"exceptional current height"); }
  { Fixture f; f.Air(0,-1); f.Surface(value,1); Compare(f,"exceptional terrain height"); }
 }
 { Fixture f; f.Owner(0); f.Position(4,0,0); f.Adj(0,2,1,0); Put<Point>(f.edges[0][3],0xC,Get<Point>(f.edges[0][2],0xC)); Compare(f,"degenerate edge"); }
}
static void TerrainOracle() {
 current="bilinear sampler bits"; Fixture f;
 for(U i=0;i<32;++i) f.cells[i]=static_cast<float>(static_cast<int>(i)*17-200)/31.0f;
 const float coordinates[]={-100,-1.25f,-1,-0.75f,-0.5f,-0.25f,-0.0f,0,0.25f,0.5f,0.75f,1,1.25f,2,100,std::numeric_limits<float>::quiet_NaN()};
 for(float x:coordinates) for(float z:coordinates) for(bool secondary:{false,true}) {
  const Point p{x,z}; ResetFp(); const float native=reinterpret_cast<float(__thiscall*)(void*,const Point*)>(delta+(secondary?0x679C50:0x64C5F0))(f.terrain,&p);
  ResetFp(); Equal(Bits(native),Bits(e::SampleTerrain(A(f.terrain),x,z,secondary)),"terrain bits");
 }
}
static void ShadowOracle() {
 current="shadow telemetry"; e::Start({delta,71,true,true}); Fixture f; f.Air(0,-3); f.Surface(-1,1);
 ResetFp(); e::ShadowBefore(reinterpret_cast<e::Agent*>(f.agent),reinterpret_cast<e::Scratch*>(f.scratch)); Original(f); e::ShadowAfter();
 U words[32],targets[64]; e::Sample(words,targets); Equal(1,words[e::Compared],"shadow compared"); Equal(0,words[e::Mismatches],"shadow direct mismatch"); Equal(0,words[e::Faults],"shadow faults"); Equal(1,words[e::NotificationUnobserved],"live notification not claimed observed"); Equal(1,words[e::SecondaryPredicted],"secondary predicted");
 Fixture g; g.Owner(0); Put<B>(g.owners[0],0x20,0);
 e::ShadowBefore(reinterpret_cast<e::Agent*>(g.agent),reinterpret_cast<e::Scratch*>(g.scratch)); Original(g); Put<B>(g.agent,0xB5,1); e::ShadowAfter();
 e::Sample(words,targets); Equal(1,words[e::MismatchB5],"callback-expanded output visible"); Equal(1,words[e::CallbackImplied],"callback-implied occurrence"); Equal(2,words[e::FirstField],"first mismatch field");
 e::Stop(); e::Sample(words,targets); Equal(0,words[e::Enabled],"stop disabled");
}
template<U N> static B __fastcall DistinctPolicy(void*,void*) { return static_cast<B>(N); }
static void TargetOracle() {
 current="top-eight target histogram"; e::Start({delta,72,true,true});
 const U functions[]={Fn(&DistinctPolicy<0>),Fn(&DistinctPolicy<1>),Fn(&DistinctPolicy<2>),Fn(&DistinctPolicy<3>),Fn(&DistinctPolicy<4>),Fn(&DistinctPolicy<5>),Fn(&DistinctPolicy<6>),Fn(&DistinctPolicy<7>),Fn(&DistinctPolicy<8>),Fn(&DistinctPolicy<9>)};
 for(U i=0;i<10;++i) {
  Fixture f; f.list[3]=1; f.Position(100,0,0); f.owner_vt[0x24/4]=functions[i];
  for(U j=0;j<=i;++j) { e::ShadowBefore(reinterpret_cast<e::Agent*>(f.agent),reinterpret_cast<e::Scratch*>(f.scratch)); Original(f); e::ShadowAfter(); }
 }
 U words[32],targets[64]; e::Sample(words,targets);
 Equal(55,words[e::Compared],"all histogram occurrences compared"); Equal(0,words[e::Mismatches],"histogram occurrences bit exact"); Equal(0,words[e::Faults],"histogram capture faults");
 Equal(10,targets[48],"all distinct targets retained"); Equal(55,targets[51],"target observations");
 for(U rank=0;rank<8;++rank) { Equal(functions[9-rank],targets[rank*2],"top target can arrive after initial eight"); Equal(10-rank,targets[rank*2+1],"top target exact count"); }
 e::Stop(); U stopped[64]; e::Sample(words,stopped); Require(!std::memcmp(stopped,targets,sizeof(targets)),"target evidence retained after stop");
}
int main(int argc,char** argv) {
 Require(argc==2,"usage: native_env_oracle Napoleon.exe"); Map(argv[1]); e::Start({delta,1,true,true});
 current="exact activation scratch after a larger scene";
 work.Prepare(65537);
 Equal(65536,static_cast<U>(work.fifo.capacity()),"FIFO bounded by native low-u16 domain");
 Equal(65536,static_cast<U>(work.touched.capacity()),"touched list bounded by native low-u16 domain");
 work.Prepare(3);
 Equal(3,static_cast<U>(work.fifo.capacity()),"new activation releases prior large FIFO capacity");
 Equal(3,static_cast<U>(work.touched.capacity()),"new activation releases prior large touched capacity");
 for(rounding=0;rounding<4;++rounding) { Cases(); TerrainOracle(); }
 Equal(3,static_cast<U>(work.fifo.capacity()),"all native differential cases use exact owner-domain FIFO without growth");
 Equal(3,static_cast<U>(work.touched.capacity()),"low-u16 aliases and two-hop traversal use exact touched capacity");
 rounding=0; ShadowOracle(); TargetOracle(); ResetFp(); VirtualFree(image,0,MEM_RELEASE);
 std::printf("environment mapped-original oracle: %u cases, %u checks; transition trace uses synthetic recording vtables, no gameplay/RNG equivalence claim\n",cases,checks); return 0;
}

// Oracle for src/ntw2_claim_chunk.{h,cpp} (--ai-claim-chunk) on a private relocated mapping of the owned image.
//  * equivalence: with a chunk >= E the host loop (Gate) performs exactly the call sequence of the ORIGINAL 0x7524A0 bytes (claimed units in
//    order, row bytes afterwards, one post-loop 0x84B1D0(ctrl, 0)), over rows that are assigned / 0x55AB90-blocked / state 8 / state 6;
//  * the loop reloads [L+8] each iteration: a claim callback that appends a row is seen by native and host alike;
//  * the cap: with chunk N < E the host claims the first N eligible entries (a prefix of native's sequence), leaves every other row
//    byte-identical (assigned == 0), runs 0x84B1D0 once, and the next call claims the next N (continuation) with the bookkeeping counters
//    (claimed / deferred / continuations / continuation_claims / drops / untracked / max pending / max ticks) consistent;
//  * gating: chunk 0, a list other than the working list, and a thread outside the planner scope all forward to the original.
// Image-internal callees 0x55AB90 (pure getter), 0x74F430 and 0x7524A0 are original bytes; 0x74F400 (detach/append) and 0x84B1D0 are
// scripted host fakes, the controller's slot +0x70 (0x826E80) records the claimed unit. No running game or installed file is modified.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "native_image_relocation.h"
#include "ntw2_runtime.h"
#include "ntw2_claim_chunk.h"
#pragma comment(lib,"bcrypt.lib")
using U=uint32_t;
using B=unsigned char;
namespace cc=ntw2_claim_chunk;
static_assert(sizeof(void*)==4,"owned x86 oracle");
static B* image;
static U delta, checks, imageSize;
static void Require(bool ok,const char* what) { ++checks; if(!ok) { std::fprintf(stderr,"FAIL %s\n",what); std::exit(1); } }
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static B* At(U va) { return reinterpret_cast<B*>(va+delta); }
template<class T> static U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static void Put(void* p,U offset,U v) { std::memcpy(static_cast<B*>(p)+offset,&v,4); }
static U Get(const void* p,U offset) { U v; std::memcpy(&v,static_cast<const B*>(p)+offset,4); return v; }
static void Jump(U va,U target) { B* p=At(va); p[0]=0xb8; Put(p,1,target); p[5]=0xff; p[6]=0xe0; }
static void Map(const char* path) {
    FILE* f=std::fopen(path,"rb"); Require(f!=nullptr,"open owned image");
    Require(!std::fseek(f,0,SEEK_END),"seek image"); long n=std::ftell(f);
    Require(n>0 && n<256*1024*1024,"image size"); std::rewind(f);
    std::vector<B> bytes(static_cast<size_t>(n));
    Require(std::fread(bytes.data(),1,bytes.size(),f)==bytes.size(),"read image"); std::fclose(f);
    BCRYPT_ALG_HANDLE alg=nullptr; B digest[32];
    Require(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)==0,"SHA provider");
    Require(BCryptHash(alg,nullptr,0,bytes.data(),static_cast<ULONG>(bytes.size()),digest,32)==0,"SHA image");
    BCryptCloseAlgorithmProvider(alg,0);
    char hex[65]; for(U i=0;i<32;++i) std::snprintf(hex+2*i,3,"%02x",digest[i]);
    Require(!std::strcmp(hex,NTW2_IMAGE_SHA256),"supported image identity");
    auto dos=reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
    auto nt=reinterpret_cast<const IMAGE_NT_HEADERS32*>(bytes.data()+dos->e_lfanew);
    imageSize=nt->OptionalHeader.SizeOfImage;
    image=static_cast<B*>(VirtualAlloc(nullptr,imageSize,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE));
    Require(image!=nullptr,"private image mapping"); delta=A(image)-0x400000;
    std::memcpy(image,bytes.data(),nt->OptionalHeader.SizeOfHeaders);
    auto sections=IMAGE_FIRST_SECTION(nt);
    for(U i=0;i<nt->FileHeader.NumberOfSections;++i)
        std::memcpy(image+sections[i].VirtualAddress,bytes.data()+sections[i].PointerToRawData,
                    std::min(sections[i].SizeOfRawData,sections[i].Misc.VirtualSize));
    Require(RelocateNativeImage(image,imageSize,reinterpret_cast<IMAGE_NT_HEADERS32*>(image+dos->e_lfanew),delta),"relocation");
}

// ---------------------------------------------------------------------------------------------------------------------- fixture
constexpr U kMaxRows=96;
static __declspec(align(16)) B obs[0x900], unitMem[kMaxRows+4][0x200], infoMem[kMaxRows+4][0x40], objMem[kMaxRows+4][0x40];
static B rows[(kMaxRows+4)*12], list[0x10], tickA[0x10], tickB[0x80];
static U vtable[64];
static std::vector<U> sequence;     // units reaching the controller's slot +0x70, in order
static U postCalls, postCtrl, postArg;
static U appendOnFirst;             // claim callback appends this unit as a new unassigned row at the end of L (index = old count)
static U __fastcall FakeCtrl70(U,U,U unit) {
    sequence.push_back(unit);
    if(appendOnFirst && sequence.size()==1) {
        const U count=Get(list,8);
        Put(rows,count*12,appendOnFirst); Put(rows,count*12+4,0); rows[count*12+8]=0;
        Put(list,8,count+1);
    }
    return 0;
}
static U __fastcall FakeDetach(U observer,U,U row) { Put(reinterpret_cast<void*>(row),4,observer); *reinterpret_cast<B*>(row+8)=1; return 0; } // 0x74F400 minus the callbacks
static U __fastcall FakePost(U ctrl,U,U arg) { ++postCalls; postCtrl=ctrl; postArg=arg; return 0; }
struct Row { U state; bool blocked; bool assigned; };
static void SetUnit(U i,U state,bool blocked) {
    std::memset(unitMem[i],0,sizeof(unitMem[i])); std::memset(infoMem[i],0,sizeof(infoMem[i])); std::memset(objMem[i],0,sizeof(objMem[i]));
    Put(unitMem[i],0x2c,A(infoMem[i])); Put(unitMem[i],0x1f4,A(objMem[i])); Put(unitMem[i],0xb34,state);
    Put(infoMem[i],0x1c,blocked ? 1 : 0); Put(objMem[i],0x10,blocked ? 1 : 0); // 0x55AB90: info+0x1c == 1 && obj+0x10 != 0
}
static void Build(const std::vector<Row>& spec) {
    std::memset(rows,0,sizeof(rows));
    for(U i=0;i<spec.size();++i) {
        SetUnit(i,spec[i].state,spec[i].blocked);
        Put(rows,i*12,A(unitMem[i])); Put(rows,i*12+4,0); rows[i*12+8]=spec[i].assigned ? 1 : 0;
    }
    std::memset(list,0,sizeof(list)); Put(list,8,static_cast<U>(spec.size())); Put(list,0xc,A(rows));
    std::memset(obs,0,sizeof(obs));
    for(U& v:vtable) v=Fn(&FakeCtrl70);
    Put(obs+0x78,0,A(vtable)); Put(obs+0x78,8,A(tickA)); Put(tickA,8,A(tickB));
    sequence.clear(); postCalls=postCtrl=postArg=0;
}
static void SetTick(U tick) { Put(tickB,0x58,tick); }
static bool inScope=true;
static bool Scope(U) { return inScope; }
using Call=U(__fastcall*)(U,U,U);
static U Native(U observer,U l) { return reinterpret_cast<Call>(static_cast<uintptr_t>(A(At(0x7524A0))))(observer,0,l); }
static cc::Targets targets;
static U W(cc::Word w) { return cc::words[w]; }
static U Unit(U i) { return A(unitMem[i]); }
struct Outcome { std::vector<U> seq; std::vector<B> rowBytes; U post, ctrl, arg; };
static Outcome Capture(U n) { return {sequence,std::vector<B>(rows,rows+n*12),postCalls,postCtrl,postArg}; }
static bool Same(const Outcome& a,const Outcome& b) { return a.seq==b.seq && a.rowBytes==b.rowBytes && a.post==b.post && a.ctrl==b.ctrl && a.arg==b.arg; }
static void Configure(U n) { cc::Configure(n,targets); }
static U Host(U observer) { return cc::Gate(observer,0,A(list)); }

static void TestEquivalence(const std::vector<Row>& spec,const char* what) {
    Build(spec); Configure(255);
    Native(A(obs),A(list)); const Outcome native=Capture(static_cast<U>(spec.size()));
    Build(spec); Configure(255);
    Host(A(obs)); const Outcome host=Capture(static_cast<U>(spec.size()));
    Require(Same(native,host),what);
    Require(native.post==1 && native.arg==0 && native.ctrl==A(obs)+0x78,"native post-loop 0x84B1D0(obs+0x78, 0) runs once");
    Require(W(cc::WCalls)==1 && W(cc::WClaimed)==host.seq.size() && W(cc::WDeferred)==0,"E <= N: every eligible entry claimed, none deferred");
}
static void TestEquivalenceCases() {
    TestEquivalence({{0,false,false},{0,false,false},{0,false,false}},"plain rows");
    TestEquivalence({},"empty list");
    TestEquivalence({{0,false,true},{8,false,false},{0,true,false},{0,false,false},{6,false,false},{7,false,false}},"assigned/state 8/blocked rows skipped, states 6 and 7 claimed");
    TestEquivalence({{8,false,false},{8,false,false}},"no eligible row: post-loop still runs");
    {   // a claim callback appends a row: the count is reloaded every iteration in native and host alike
        std::vector<Row> spec={{0,false,false},{0,false,false}};
        appendOnFirst=Unit(10); SetUnit(10,0,false);
        Build(spec); SetUnit(10,0,false); Configure(255);
        Native(A(obs),A(list)); const Outcome native=Capture(3);
        const U nativeCount=Get(list,8);
        Build(spec); SetUnit(10,0,false); Configure(255);
        Host(A(obs)); const Outcome host=Capture(3);
        Require(Same(native,host) && nativeCount==3 && Get(list,8)==3 && host.seq.size()==3 && host.seq[2]==Unit(10),"appended row is visited (bound reloaded each iteration)");
        appendOnFirst=0;
    }
    std::printf("equivalence: host loop == original 0x7524A0 for N >= E\n");
}

static void TestCap() {
    std::vector<Row> spec(7,Row{0,false,false});
    spec[2].blocked=true; spec[4].state=8;                         // eligible: rows 0 1 3 5 6 (E = 5)
    Build(spec); Configure(255); Native(A(obs),A(list));
    const Outcome full=Capture(7);
    Require(full.seq==std::vector<U>({Unit(0),Unit(1),Unit(3),Unit(5),Unit(6)}),"fixture: native order of eligible entries");
    Build(spec); Configure(3); SetTick(100);
    Host(A(obs)); Outcome cap=Capture(7);
    Require(cap.seq==std::vector<U>({Unit(0),Unit(1),Unit(3)}),"cap 3: the first three eligible entries, in native order");
    Require(cap.post==1 && cap.arg==0 && cap.ctrl==A(obs)+0x78,"cap: post-loop runs once");
    for(U i=0;i<7;++i) {
        const bool claimed=i==0||i==1||i==3;
        Require(rows[i*12+8]==(claimed ? 1 : 0) && Get(rows,i*12+4)==(claimed ? A(obs) : 0),"claimed rows assigned, every other row byte-identical");
    }
    Require(W(cc::WCalls)==1 && W(cc::WClaimed)==3 && W(cc::WDeferred)==2 && W(cc::WContinuations)==0,"call 1 counters: claimed 3, deferred 2");
    Require((W(cc::WPacked)&0xFF)==2 && (W(cc::WPacked)>>24)==3,"max pending 2, N packed");
    // Tick 101: the same rows are offered again (the native pass rebuilds L from the unassigned rows); here L simply persists.
    SetTick(101); sequence.clear(); postCalls=0;
    Host(A(obs));
    Require(sequence==std::vector<U>({Unit(5),Unit(6)}) && postCalls==1,"call 2: the two deferred entries are claimed");
    Require(W(cc::WContinuations)==1 && W(cc::WContinuationClaims)==2 && W(cc::WDrops)==0 && W(cc::WClaimed)==3 && W(cc::WDeferred)==2,
            "continuation claims resolve the deferrals");
    Require(((W(cc::WPacked)>>8)&0xFFFF)==1,"max ticks from deferral to claim = 1");
    std::printf("cap: prefix claims, untouched leftovers, continuation counters verified\n");
}

static void TestFifo() {
    // The budget goes to the oldest deferred entries before the rows that precede them in L (a prefix cap would starve late rows
    // while earlier rows are released and offered again every tick).
    std::vector<Row> spec(6,Row{0,false,false});
    Build(spec); Configure(2); SetTick(50);
    Host(A(obs));
    Require(sequence==std::vector<U>({Unit(0),Unit(1)}) && W(cc::WDeferred)==4,"call 1: rows 0,1 claimed, 2..5 deferred");
    for(U i:{0u,1u}) { rows[i*12+8]=0; Put(rows,i*12+4,0); }       // rows 0 and 1 are released again (churn)
    SetTick(51); sequence.clear();
    Host(A(obs));
    Require(sequence==std::vector<U>({Unit(2),Unit(3)}),"call 2: the oldest deferred entries first, not rows 0 and 1");
    Require(W(cc::WDeferred)==6 && W(cc::WContinuationClaims)==2 && W(cc::WClaimed)==2,"rows 0 and 1 are new deferrals (distinct entries: deferred 6)");
    SetTick(52); sequence.clear();
    Host(A(obs));
    Require(sequence==std::vector<U>({Unit(4),Unit(5)}) && ((W(cc::WPacked)>>8)&0xFFFF)==2,"call 3: entries 4,5 after two ticks (latency 2)");
    SetTick(53); sequence.clear();
    Host(A(obs));
    Require(sequence==std::vector<U>({Unit(0),Unit(1)}) && W(cc::WContinuationClaims)==6 && W(cc::WDrops)==0 &&
            W(cc::WDeferred)==W(cc::WContinuationClaims)+W(cc::WDrops)+W(cc::WUntracked),"call 4: the released rows are claimed in their deferral order; identity holds");
    // Mixed: a pending entry that is no longer claimable does not consume the budget.
    Build(spec); Configure(2); SetTick(60); Host(A(obs));
    Put(unitMem[2],0xb34,8); SetTick(61); sequence.clear();
    Host(A(obs));
    Require(sequence==std::vector<U>({Unit(3),Unit(4)}) && W(cc::WDrops)==1,"a pending entry in state 8 is a drop; the budget goes on to the next oldest");
    std::printf("fifo: oldest deferred entries claimed first\n");
}
static void TestDrops() {
    std::vector<Row> spec(8,Row{0,false,false});
    Build(spec); Configure(2); SetTick(10);
    Host(A(obs));
    Require(W(cc::WClaimed)==2 && W(cc::WDeferred)==6,"6 deferred");
    // Next tick: entries 2 and 3 are claimed elsewhere (assigned), 4 became state 8; 5,6,7 remain pending.
    rows[2*12+8]=1; rows[3*12+8]=1; Put(unitMem[4],0xb34,8);
    SetTick(14); sequence.clear();
    Host(A(obs));
    Require(sequence==std::vector<U>({Unit(5),Unit(6)}),"call 2 claims the first two still-eligible pending entries");
    Require(W(cc::WContinuationClaims)==2 && W(cc::WDrops)==3 && W(cc::WDeferred)==6 && W(cc::WClaimed)==2,"entries 2,3,4 are revalidation drops");
    Require(((W(cc::WPacked)>>8)&0xFFFF)==4,"drop latency counted in ticks (10 -> 14)");
    SetTick(15); sequence.clear();
    Host(A(obs));
    Require(sequence==std::vector<U>({Unit(7)}) && W(cc::WContinuationClaims)==3 && W(cc::WDeferred)==6 &&
            W(cc::WDeferred)==W(cc::WContinuationClaims)+W(cc::WDrops)+W(cc::WUntracked),"identity deferred == continuation_claims + drops + untracked once nothing is pending");
    std::printf("drops: revalidation drops and the deferral identity verified\n");
}

static void TestOverflow() {
    std::vector<Row> spec(kMaxRows,Row{0,false,false});
    Build(spec); Configure(1); SetTick(1);
    Host(A(obs));
    Require(W(cc::WClaimed)==1 && W(cc::WDeferred)==kMaxRows-1 && W(cc::WUntracked)==kMaxRows-1-cc::kPending,"beyond the per-observer table: counted as untracked, never resolved");
    Require((W(cc::WPacked)&0xFF)==cc::kPending,"max pending = table size");
    // Observer table eviction: kObservers+1 distinct observers with pending entries; the least recently used record's entries become drops.
    Configure(1);
    static B observers[cc::kObservers+1][0x900];
    std::vector<Row> two(2,Row{0,false,false});
    for(U o=0;o<=cc::kObservers;++o) {
        Build(two); std::memcpy(observers[o],obs,sizeof(obs)); Put(observers[o]+0x78,0,A(vtable)); // distinct observer objects, same controller fixture
        sequence.clear(); Host(A(observers[o]));
    }
    Require(W(cc::WDeferred)==cc::kObservers+1 && W(cc::WDrops)==1,"ninth observer evicts the least recently used record (its pending entry is a drop)");
    std::printf("overflow: untracked and observer eviction verified\n");
}

static void TestGating() {
    std::vector<Row> spec(5,Row{0,false,false});
    // chunk 0: forwarded to the original.
    Build(spec); Configure(0); Host(A(obs));
    Require(sequence.size()==5 && W(cc::WCalls)==0 && postCalls==1,"chunk 0: native path, nothing counted");
    // another list: forwarded.
    static B other[0x10];
    Build(spec); Configure(2); std::memcpy(other,list,sizeof(list));
    cc::Gate(A(obs),0,A(other));
    Require(sequence.size()==5 && W(cc::WCalls)==0,"a list other than the working list is never chunked");
    // outside the planner scope: forwarded.
    Build(spec); Configure(2); inScope=false; Host(A(obs)); inScope=true;
    Require(sequence.size()==5 && W(cc::WCalls)==0,"outside the planner scope: native path");
    Build(spec); Configure(2); Host(A(obs));
    Require(sequence.size()==2 && W(cc::WCalls)==1,"in scope: chunked");
    std::printf("gating: chunk 0 / foreign list / off-scope forward to the original\n");
}

int main(int argc,char** argv) {
    if(argc!=2) { std::fprintf(stderr,"usage: native_claim_chunk_oracle Napoleon.exe\n"); return 2; }
    Map(argv[1]);
    Jump(0x74F400,Fn(&FakeDetach)); Jump(0x84B1D0,Fn(&FakePost));
    Require(FlushInstructionCache(GetCurrentProcess(),image,imageSize)!=0,"flush image");
    targets={A(At(0x7524A0)),A(At(0x55AB90)),A(At(0x74F430)),Fn(&FakePost),A(list),&Scope};
    TestEquivalenceCases(); TestCap(); TestFifo(); TestDrops(); TestOverflow(); TestGating();
    std::printf("claim chunk oracle: %u checks\n",checks);
    return 0;
}

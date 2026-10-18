// Oracle for src/ntw2_claim_once.{h,cpp} (--ai-claim-once) on a private relocated mapping of the owned image.
//  * equivalence: whenever no recompute is masked (valid memo, one tailing entry, refusals) the host loop (Gate) performs exactly the call
//    sequence of the ORIGINAL 0x7524A0 bytes: claimed units in order, row bytes afterwards, one post-loop 0x84B1D0(ctrl, 0); the loop reloads
//    [L+8] each iteration (a claim callback that appends a row is visited);
//  * masking: with a same-tick / expired / first-use memo (where native recomputes for every claimed unit) exactly one recompute runs, on the
//    last tailing entry (states 6/7 never tail); +0x724, the per-entry ring history, the claimed rows and the post-loop equal native;
//  * refusals: 0x55AD60 true, first-use latch unset, tick unreadable keep native behaviour; the original memo word is always restored;
//  * gating: off, a list other than the working list, a thread outside the planner scope forward to the original.
// Image-internal callees 0x55AB90, 0x55AD60 (pure getters), 0x74F430 and 0x7524A0 are original bytes; 0x74F400 (detach/append) and 0x84B1D0 are
// scripted host fakes and the controller slot +0x70 models 0x826E80's control flow around the 0x82F3A0 memo gate. No running game or installed file is modified.
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
#include "ntw2_claim_once.h"
#pragma comment(lib,"bcrypt.lib")
using U=uint32_t;
using B=unsigned char;
namespace co=ntw2_claim_once;
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
static B rows[(kMaxRows+4)*12], list[0x10], tickA[0x10], tickB[0x100], stateObj[0x40];
static U vtable[64];
static std::vector<U> sequence;     // units reaching the controller's slot +0x70, in order
static U postCalls, postCtrl, postArg;
static U tails;                     // placement recomputes the fake 0x826E80 performed
static U appendOnFirst;             // claim callback appends this unit as a new unassigned row at the end of L (index = old count)
// Scripted 0x826E80: the native control flow around the 0x82F3A0 memo gate (0x826E88..0x826F13, 0x82F6EE..0x82F736): states 6/7 return, the memo
// gate (!0x55AD60 && last != 0 && last != tick && last + 10 >= tick) returns the cached +0x720 without writing, otherwise +0x724 = tick and the
// tail runs (modelled: +0x720 = recompute count + 1); +0x758 = result; first use sets the latch.
static U __fastcall FakeCtrl70(U ctrl,U,U unit) {
    sequence.push_back(unit);
    if(appendOnFirst && sequence.size()==1) {
        const U count=Get(list,8);
        Put(rows,count*12,appendOnFirst); Put(rows,count*12+4,0); rows[count*12+8]=0;
        Put(list,8,count+1);
    }
    void* c=reinterpret_cast<void*>(ctrl);
    const U state=Get(reinterpret_cast<void*>(unit),0xb34);
    if(state==6 || state==7) return 0;
    { const U ring=Get(c,0x76c)+1; Put(c,0x76c,ring); Put(c,0x6b0,(ring*257)&0xFFFF); Put(c,0x704,ring%20); Put(c,0x708,ring*3); } // ring/heading history advances once per entry (native)
    const U tick=Get(tickB,0x58), last=Get(c,0x724);
    const bool blocked=reinterpret_cast<bool(__fastcall*)(U,U)>(static_cast<uintptr_t>(A(At(0x55AD60))))(A(stateObj),0);
    U result;
    if(!blocked && last && last!=tick && last+10>=tick) result=Get(c,0x720);
    else { Put(c,0x724,tick); ++tails; result=Get(c,0x76c); Put(c,0x720,result); }   // the score is a pure function of the membership (ring count proxy)
    Put(c,0x758,result);
    Put(c,0x75d,1);
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
static void Build(const std::vector<Row>& spec,U last=0,U tick=100,bool latch=true,U modelState=2) {
    std::memset(rows,0,sizeof(rows));
    for(U i=0;i<spec.size();++i) {
        SetUnit(i,spec[i].state,spec[i].blocked);
        Put(rows,i*12,A(unitMem[i])); Put(rows,i*12+4,0); rows[i*12+8]=spec[i].assigned ? 1 : 0;
    }
    std::memset(list,0,sizeof(list)); Put(list,8,static_cast<U>(spec.size())); Put(list,0xc,A(rows));
    std::memset(obs,0,sizeof(obs)); std::memset(tickB,0,sizeof(tickB)); std::memset(stateObj,0,sizeof(stateObj));
    for(U& v:vtable) v=Fn(&FakeCtrl70);
    B* ctrl=obs+0x78;
    Put(ctrl,0,A(vtable)); Put(ctrl,8,A(tickA)); Put(tickA,8,A(tickB));
    Put(tickB,0x58,tick); Put(tickB,0xb0,A(stateObj)); Put(stateObj,0x14,modelState);   // 0x55AD60: state 0 or 1 -> true (no memo)
    Put(ctrl,0x724,last); Put(ctrl,0x75d,latch ? 1 : 0);
    sequence.clear(); postCalls=postCtrl=postArg=0; tails=0;
}
static bool inScope=true;
static bool Scope(U) { return inScope; }
using Call=U(__fastcall*)(U,U,U);
static U Native(U observer,U l) { return reinterpret_cast<Call>(static_cast<uintptr_t>(A(At(0x7524A0))))(observer,0,l); }
static co::Targets targets;
static U W(co::Word w) { return co::words[w]; }
static U Unit(U i) { return A(unitMem[i]); }
static U Ctl(U off) { return Get(obs+0x78,off); }
struct Outcome { std::vector<U> seq; std::vector<B> rowBytes; U post, ctrl, arg, tails, memo, score, cache, ring; };
static Outcome Capture(U n) {
    return {sequence,std::vector<B>(rows,rows+n*12),postCalls,postCtrl,postArg,tails,Ctl(0x724),Ctl(0x758),Ctl(0x720),Ctl(0x76c)};
}
static bool Same(const Outcome& a,const Outcome& b) { return a.seq==b.seq && a.rowBytes==b.rowBytes && a.post==b.post && a.ctrl==b.ctrl && a.arg==b.arg; }
static void Configure(bool on) { co::Configure(on ? co::ModeOnce : co::ModeOff,targets); }
static U Packed(U shift,U mask) { return (W(co::WPacked)>>shift)&mask; }
static U Host(U observer) { return co::Gate(observer,0,A(list)); }
static void Run2(const std::vector<Row>& spec,U last,U tick,bool latch,U modelState,Outcome& native,Outcome& once) {
    Build(spec,last,tick,latch,modelState); Configure(true);
    Native(A(obs),A(list)); native=Capture(static_cast<U>(spec.size()));
    Build(spec,last,tick,latch,modelState); Configure(true);
    Host(A(obs)); once=Capture(static_cast<U>(spec.size()));
}

// Without a masked recompute the host loop performs exactly the call sequence of the original 0x7524A0.
static void TestEquivalence() {
    struct Case { std::vector<Row> rows; U tailing; };           // tailing = eligible entries that run the 0x82F3A0 tail (state not 6/7)
    const std::vector<Case> cases={
        {{{0,false,false},{0,false,false},{0,false,false}},3},
        {{},0},
        {{{0,false,true},{8,false,false},{0,true,false},{0,false,false},{6,false,false},{7,false,false}},1},
        {{{8,false,false},{8,false,false}},0},
        {{{0,false,false}},1}};
    for(const auto& c:cases)
        for(U last:{0u,95u,100u})                                   // 95: valid memo, 100: same tick, 0: first use
            for(bool latch:{true,false}) {
                Outcome n,o; Run2(c.rows,last,100,latch,2,n,o);
                Require(Same(n,o),"call sequence, rows and post-loop equal native");
                if(c.tailing<2 || last==95) Require(n.tails==o.tails && n.memo==o.memo && n.score==o.score && n.ring==o.ring,"nothing to mask: controller state equals native");
            }
    {   // a claim callback that appends a row is visited (bound reloaded each iteration), natively and in the host loop
        std::vector<Row> spec={{0,false,false},{0,false,false}};
        appendOnFirst=Unit(10);
        Build(spec); SetUnit(10,0,false); Configure(true);
        Native(A(obs),A(list)); const Outcome native=Capture(3); const U nativeCount=Get(list,8);
        Build(spec); SetUnit(10,0,false); Configure(true);
        Host(A(obs)); const Outcome host=Capture(3);
        Require(Same(native,host) && nativeCount==3 && Get(list,8)==3 && host.seq.size()==3 && host.seq[2]==Unit(10),"appended row is visited");
        appendOnFirst=0;
    }
    std::printf("equivalence: host loop == original 0x7524A0 call sequence\n");
}

static void TestMasking() {
    std::vector<Row> five(5,Row{0,false,false});
    // Same-tick memo (+0x724 == tick): native recomputes for every entry; once recomputes for the last entry only.
    Outcome n,o; Run2(five,100,100,true,2,n,o);
    Require(n.tails==5 && o.tails==1,"same tick: 5 native recomputes -> 1");
    Require(Same(n,o) && o.memo==100 && n.memo==100 && o.ring==n.ring && o.ring==5,"claims, rows, post-loop, +0x724 and ring history equal native");
    Require(o.score==5 && o.cache==5 && W(co::WMasked)==4 && W(co::WCallsMasked)==1 && Packed(8,0xFF)==0 && W(co::WEntries)==5 && Packed(0,0xFF)==5 && Packed(16,0xFFFF)==1,
            "the one recompute publishes +0x758/+0x720; 4 masked; one multi-entry call hashed");
    // Expired memo: native recomputes the first entry, then every same-tick entry.
    Run2(five,60,100,true,2,n,o);
    Require(n.tails==5 && o.tails==1 && o.memo==100 && n.memo==100,"expired memo: 5 -> 1, +0x724 = tick as native");
    // First use (last == 0): native recomputes every entry.
    Run2(five,0,100,true,2,n,o);
    Require(n.tails==5 && o.tails==1 && o.memo==100,"last == 0: 5 -> 1");
    // Valid memo: nothing to mask, no write, identical state.
    Run2(five,95,100,true,2,n,o);
    Require(n.tails==0 && o.tails==0 && o.memo==95 && n.memo==95 && W(co::WMasked)==0,"valid memo: untouched");
    // Trailing states 6/7 never tail: the last TAILING entry is the one that recomputes.
    std::vector<Row> mixed={{0,false,false},{0,false,false},{6,false,false},{0,false,false},{7,false,false}};
    Run2(mixed,100,100,true,2,n,o);
    Require(n.tails==3 && o.tails==1 && o.memo==100 && Same(n,o) && W(co::WMasked)==2,"states 6/7 skip the tail; one recompute on the last tailing entry");
    // Refusals: 0x55AD60 true (state 0/1), latch unset: native path, native counts.
    Run2(five,100,100,true,1,n,o);
    Require(n.tails==5 && o.tails==5 && W(co::WRefusedState)>0 && W(co::WMasked)==0,"0x55AD60 true: native recomputes kept");
    Run2(five,100,100,false,2,n,o);
    Require(n.tails==5 && o.tails==2 && W(co::WRefusedOther)==1 && o.memo==100,"latch unset: the first entry stays native (it sets the latch and recomputes), the rest masked, last recomputes");
    // A single entry or a single tailing entry is never masked.
    std::vector<Row> single={{0,false,false},{8,false,false}};
    Run2(single,100,100,true,2,n,o);
    Require(n.tails==1 && o.tails==1 && W(co::WMasked)==0,"one tailing entry: native");
    std::printf("masking: one recompute per call, state equals native; refusals native\n");
}

static void TestNoFinalTail() {
    // The predicted last tailing entry stops being eligible after the previous claim: the call masked entries but no tail ran.
    std::vector<Row> spec(3,Row{0,false,false});
    Build(spec,100,100,true,2); Configure(true);
    appendOnFirst=0;
    // Rows 1 and 2 stop being eligible as soon as row 0 is claimed (a stand-in for a callback side effect).
    struct Hook { static U __fastcall Fn70(U ctrl,U e,U unit) { if(unit==Unit(0)) { Put(rows,1*12+8,1); Put(rows,2*12+8,1); } return FakeCtrl70(ctrl,e,unit); } };
    for(U& v:vtable) v=Fn(&Hook::Fn70);
    Host(A(obs));
    Require(Packed(8,0xFF)==1 && W(co::WMasked)==1 && tails==0 && sequence.size()==1,"no tail ran after masking: counted");
    Require(Ctl(0x724)==100,"original memo restored");
    std::printf("no-final-tail: memo restored, counted\n");
}

static void TestGating() {
    std::vector<Row> spec(5,Row{0,false,false});
    Build(spec,100,100); Configure(false); Host(A(obs));
    Require(sequence.size()==5 && tails==5 && W(co::WCalls)==0 && postCalls==1,"off: native path, nothing counted");
    static B other[0x10];
    Build(spec,100,100); Configure(true); std::memcpy(other,list,sizeof(list));
    co::Gate(A(obs),0,A(other));
    Require(sequence.size()==5 && tails==5 && W(co::WCalls)==0,"a list other than the working list is never touched");
    Build(spec,100,100); Configure(true); inScope=false; Host(A(obs)); inScope=true;
    Require(sequence.size()==5 && tails==5 && W(co::WCalls)==0,"outside the planner scope: native path");
    Build(spec,100,100); Configure(true); Host(A(obs));
    Require(sequence.size()==5 && tails==1 && W(co::WCalls)==1,"in scope: all five claimed, one recompute");
    std::printf("gating: off / foreign list / off-scope forward to the original\n");
}

// Census mode runs the native recomputes (no masking) and publishes the same state hash as once mode: equal hashes over the multi-entry calls mean the
// controller state at the end of every such call (ring, heading, score cache, memo tick, published score) is identical, whatever the memo scenario.
static void TestCensus() {
    std::vector<Row> five(5,Row{0,false,false}), mixed={{0,false,false},{0,false,false},{6,false,false},{0,false,false},{7,false,false}};
    const std::vector<Row>* specs[]={&five,&mixed};
    for(const auto* spec:specs)
        for(U last:{0u,60u,95u,100u}) {
            Build(*spec,last,100); co::Configure(co::ModeCensus,targets); Host(A(obs));
            const U censusTails=tails, censusHash=W(co::WHash), censusScore=Ctl(0x758), censusMemo=Ctl(0x724), censusCache=Ctl(0x720);
            Require(W(co::WMasked)==0 && Packed(16,0xFFFF)==1,"census: nothing masked, the call is hashed");
            Build(*spec,last,100); co::Configure(co::ModeOnce,targets); Host(A(obs));
            Require(W(co::WHash)==censusHash && Ctl(0x758)==censusScore && Ctl(0x724)==censusMemo,"once: same final memo tick, same published score, same hash as the native-recompute run");
            if(last==95) Require(tails==censusTails && Ctl(0x720)==censusCache,"valid memo: nothing elided");
            else Require(tails<censusTails,"fewer recomputes than the census run");
        }
    // A different final state changes the hash (the hash is not vacuous).
    Build(five,100,100); co::Configure(co::ModeCensus,targets); Host(A(obs)); const U a=W(co::WHash);
    Build(mixed,100,100); co::Configure(co::ModeCensus,targets); Host(A(obs));
    Require(a!=W(co::WHash),"different calls hash differently");
    std::printf("census: once == native-recompute controller state (hash)\n");
}
int main(int argc,char** argv) {
    if(argc!=2) { std::fprintf(stderr,"usage: native_claim_once_oracle Napoleon.exe\n"); return 2; }
    Map(argv[1]);
    Jump(0x74F400,Fn(&FakeDetach)); Jump(0x84B1D0,Fn(&FakePost));
    Require(FlushInstructionCache(GetCurrentProcess(),image,imageSize)!=0,"flush image");
    targets={A(At(0x7524A0)),A(At(0x55AB90)),A(At(0x74F430)),Fn(&FakePost),A(At(0x55AD60)),A(list),&Scope};
    TestEquivalence(); TestMasking(); TestCensus(); TestNoFinalTail(); TestGating();
    std::printf("claim once oracle: %u checks\n",checks);
    return 0;
}

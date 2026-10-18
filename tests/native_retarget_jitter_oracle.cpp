// Oracle for src/ntw2_retarget_jitter.{h,cpp} (--brain-retarget-jitter and the 0x6671A0 host mirror) on a private relocated mapping of the owned image.
//  * flag OFF: the mirror (TrackerTick) is bit-identical to the ORIGINAL bytes of 0x6671A0 running in the private mapping with its six call sites
//    (0x6795A0, 0x63CE00, 0x553420, 0x553220, 0x6C6910, 0x662960) redirected to the same scripted fakes: return value, all 0x20 tracker bytes, the
//    target agents' +0x474 counters (the real 0x63CE00 / 0x662960 bytes run inside the fakes) and the full call trace (callee, every argument incl. the
//    zero-extended +0xC byte pushed to 0x6C6910) are compared over a randomized scenario space (valid/invalid held target, keys +0/+4/+8, cooldowns, agent ids,
//    search results);
//  * flag ON: against an independent model of the lever -- a held target found invalid with cooldown 0 and agent+0x2C & 0xF = d != 0 is cleared, +0x14 = d,
//    no search that tick (trace = valid, clear), counters losses/jittered/delay_sum; every other state (valid target, no held target = periodic or per-tick
//    clear before the tick, cooldown still running, d == 0) equals the native result;
//  * sequences (all 16 ids): the delayed search runs at tick t + d exactly once; a failed delayed search sets the native (id & 0xF) + 0x28 cooldown; a forced
//    target (0x662960) or a periodic clear (0x63CE00 on an empty tracker) inside the delay leaves the native behaviour; a periodic clear on a held valid
//    target is not a loss (immediate native search).
// No running game or installed file is modified; the image is mapped privately and its call sites patched in the private copy only.
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
#include "brain/ntw2_retarget_jitter.h"
#pragma comment(lib,"bcrypt.lib")
using U=uint32_t;
using B=unsigned char;
namespace rj=ntw2_retarget_jitter;
static_assert(sizeof(void*)==4,"owned x86 oracle");
static B* image;
static U delta, checks, imageSize;
static void Require(bool ok,const char* what) { ++checks; if(!ok) { std::fprintf(stderr,"FAIL %s\n",what); std::exit(1); } }
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static B* At(U va) { return reinterpret_cast<B*>(va+delta); }
template<class T> static U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static void Put(void* p,U offset,U v) { std::memcpy(static_cast<B*>(p)+offset,&v,4); }
static U Get(const void* p,U offset) { U v; std::memcpy(&v,static_cast<const B*>(p)+offset,4); return v; }
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
// Tracker fields (node+0x48): +0 key, +4, +8, +0xC byte, +0x10 target agent, +0x14 cooldown. Agent: +0x2C id, +0x1F0 unit (contact list = unit+0xA80).
constexpr U kTrackerBytes=0x20, kAgentBytes=0x400, kUnitBytes=0x1000, kTargetBytes=0x500, kTargets=3;
enum Fn_ : U { FValid=1, FClear, FSearch, FSecond, FThird, FAssign };
struct Event { U fn, a, b, c; bool operator==(const Event& o) const { return fn==o.fn && a==o.a && b==o.b && c==o.c; } };
static std::vector<Event> trace;
static bool scriptValid;
static U scriptFound[3];                 // results of 0x553420, 0x553220, 0x6C6910
static __declspec(align(16)) B trackerMem[kTrackerBytes], agentMem[kAgentBytes], unitMem[kUnitBytes], targetMem[kTargets][kTargetBytes];
using ClearFn=void(__fastcall*)(U,U);
using AssignFn=void(__fastcall*)(U,U,U);
// 0x6795A0 is `+0x10 != 0 && alive && reachable`: the scripted verdict only applies to a tracker that holds a target.
static bool __fastcall FakeValid(U tracker,U,U agent) { trace.push_back({FValid,tracker,agent,0}); return scriptValid && Get(reinterpret_cast<const void*>(static_cast<uintptr_t>(tracker)),0x10)!=0; }
static void __fastcall FakeClear(U tracker,U) { trace.push_back({FClear,tracker,0,0}); reinterpret_cast<ClearFn>(A(At(0x63CE00)))(tracker,0); }         // the real 0x63CE00 bytes
static U __fastcall FakeSearch(U list,U,U agent,U key) { trace.push_back({FSearch,list,agent,key}); return scriptFound[0]; }
static U __fastcall FakeSecond(U list,U,U agent,U key) { trace.push_back({FSecond,list,agent,key}); return scriptFound[1]; }
static U __fastcall FakeThird(U ecx,U,U agent,U flag) { trace.push_back({FThird,ecx,agent,flag}); return scriptFound[2]; }
static void __fastcall FakeAssign(U tracker,U,U target) { trace.push_back({FAssign,tracker,target,0}); reinterpret_cast<AssignFn>(A(At(0x662960)))(tracker,0,target); } // the real 0x662960 bytes
static void PatchCall(U site,U fake) {
    B* p=At(site); Require(p[0]==0xE8,"original call opcode at the site");
    Put(p,1,fake-(A(p)+5));
}
static void PatchOriginal() {
    PatchCall(0x6671B4,Fn(&FakeValid)); PatchCall(0x6671BF,Fn(&FakeClear)); PatchCall(0x6671DE,Fn(&FakeSearch));
    PatchCall(0x6671FA,Fn(&FakeSecond)); PatchCall(0x66720D,Fn(&FakeThird)); PatchCall(0x667219,Fn(&FakeAssign));
}
static rj::Targets MirrorTargets() { return {Fn(&FakeValid),Fn(&FakeClear),Fn(&FakeSearch),Fn(&FakeSecond),Fn(&FakeThird),Fn(&FakeAssign)}; }

struct Scenario {
    U key, second, third; U flagWord;    // tracker +0, +4, +8, +0xC (dword; the byte is the low one)
    bool held; U cooldown; U id;         // +0x10 != 0 (target 0), +0x14, agent+0x2C
    bool valid; U found[3];              // 0 = none, 1..2 = target index
    U counter[kTargets];                 // +0x474 of the three targets
};
struct Result {
    U ret; B tracker[kTrackerBytes]; U counter[kTargets]; std::vector<Event> events;
    bool operator==(const Result& o) const { return ret==o.ret && !std::memcmp(tracker,o.tracker,kTrackerBytes) && !std::memcmp(counter,o.counter,sizeof counter) && events==o.events; }
};
static U TargetAddr(U index) { return index ? A(targetMem[index]) : 0; }
static void Setup(const Scenario& s) {
    std::memset(trackerMem,0,sizeof trackerMem); std::memset(agentMem,0,sizeof agentMem); std::memset(unitMem,0,sizeof unitMem); std::memset(targetMem,0,sizeof targetMem);
    for(U i=0;i<kTargets;++i) Put(targetMem[i],0x474,s.counter[i]);
    Put(trackerMem,0,s.key); Put(trackerMem,4,s.second); Put(trackerMem,8,s.third); Put(trackerMem,0xC,s.flagWord);
    Put(trackerMem,0x10,s.held ? A(targetMem[0]) : 0); Put(trackerMem,0x14,s.cooldown);
    Put(agentMem,0x2C,s.id); Put(agentMem,0x1F0,A(unitMem));
    scriptValid=s.valid; for(U i=0;i<3;++i) scriptFound[i]=TargetAddr(s.found[i]);
    trace.clear();
}
static Result Capture(U ret) {
    Result r; r.ret=ret; std::memcpy(r.tracker,trackerMem,kTrackerBytes);
    for(U i=0;i<kTargets;++i) r.counter[i]=Get(targetMem[i],0x474);
    r.events=trace; return r;
}
static Result RunNative(const Scenario& s) {
    Setup(s);
    return Capture(reinterpret_cast<U(__fastcall*)(U,U,U)>(A(At(0x6671A0)))(A(trackerMem),0,A(agentMem)));
}
static Result RunMirror(const Scenario& s,bool jitter) {
    rj::Configure(jitter,MirrorTargets());
    Setup(s);
    return Capture(rj::TrackerTick(A(trackerMem),0,A(agentMem)));
}
static U Rng() { static U x=0x9E3779B9u; x^=x<<13; x^=x>>17; x^=x<<5; return x; }
static Scenario Random() {
    Scenario s{};
    const U shape=Rng()%8;
    s.key=(shape&1) ? 0 : (Rng()|1); s.second=(shape&2) ? 0 : (Rng()|1); s.third=(shape&4) ? 0 : (Rng()|1);
    s.flagWord=Rng();
    s.held=Rng()&1; s.cooldown=(Rng()%4==0) ? Rng()%60 : 0; s.id=(Rng()%5==0) ? (Rng()&~0xFu) : Rng();
    s.valid=Rng()%3==0; for(U i=0;i<3;++i) s.found[i]=Rng()%3;
    for(U i=0;i<kTargets;++i) s.counter[i]=1+Rng()%7;
    return s;
}

// The lever's independent model (flag ON), expressed on top of the native result.
static bool Delays(const Scenario& s,U* delay) {
    const U cooldown=s.cooldown ? s.cooldown-1 : 0;           // the native decrement
    const U d=s.id&0xF;
    *delay=d;
    return !s.valid && s.held && cooldown==0 && d!=0;
}
static Result Expected(const Scenario& s,const Result& native,U d) {
    Result e=native;
    e.events.clear(); e.events.push_back({FValid,A(trackerMem),A(agentMem),0}); e.events.push_back({FClear,A(trackerMem),0,0});
    e.ret=0; Put(e.tracker,0x10,0); Put(e.tracker,0x14,d);
    for(U i=0;i<kTargets;++i) e.counter[i]=s.counter[i]; e.counter[0]=s.counter[0]-1;
    return e;
}
static void Describe(const Scenario& s,const char* what) {
    std::fprintf(stderr,"scenario: key=%08x second=%08x third=%08x flag=%08x held=%d cd=%u id=%08x valid=%d found=%u/%u/%u (%s)\n",s.key,s.second,s.third,s.flagWord,s.held,s.cooldown,s.id,s.valid,
                 s.found[0],s.found[1],s.found[2],what);
}

// ---------------------------------------------------------------------------------------------------------------------- equivalence
static void RandomEquivalence() {
    constexpr U kScenarios=400000;
    U lostDelayed=0, lostImmediate=0, noHeld=0, validCount=0, searches[3]={}, assigns=0, cooldowns=0;
    for(U n=0;n<kScenarios;++n) {
        const Scenario s=Random();
        const Result native=RunNative(s);
        // OFF: bit-identical to the original instruction stream, counters aside.
        rj::ResetRow();
        const Result off=RunMirror(s,false);
        if(!(off==native)) { Describe(s,"OFF mismatch"); Require(false,"flag off: mirror equals the original bytes"); }
        ++checks;
        U expectLoss=(!s.valid && s.held) ? 1 : 0;
        if(rj::words[rj::WTrackerCalls]!=1 || rj::words[rj::WLosses]!=expectLoss || rj::words[rj::WJittered] || rj::words[rj::WDelaySum]) { Describe(s,"OFF census"); Require(false,"flag off: census counts calls and losses, never delays"); }
        // ON: the model.
        rj::ResetRow();
        const Result on=RunMirror(s,true);
        U d=0; const bool delayed=Delays(s,&d);
        const Result want=delayed ? Expected(s,native,d) : native;
        if(!(on==want)) { Describe(s,"ON mismatch"); Require(false,"flag on: result equals the model"); }
        ++checks;
        if(rj::words[rj::WTrackerCalls]!=1 || rj::words[rj::WLosses]!=expectLoss || rj::words[rj::WJittered]!=(delayed?1u:0u) || rj::words[rj::WDelaySum]!=(delayed?d:0u)) {
            Describe(s,"ON census"); Require(false,"flag on: census words");
        }
        ++checks;
        if(delayed) ++lostDelayed; else if(expectLoss) ++lostImmediate;
        if(!s.held) ++noHeld;
        if(s.valid) ++validCount;
        for(const Event& e:native.events) { if(e.fn==FSearch) ++searches[0]; else if(e.fn==FSecond) ++searches[1]; else if(e.fn==FThird) ++searches[2]; else if(e.fn==FAssign) ++assigns; }
        cooldowns+=Get(native.tracker,0x14)>=0x28;
    }
    std::printf("random equivalence: %u scenarios, lost+delayed %u, lost+immediate %u, no held target %u, valid %u, searches %u/%u/%u, assigns %u, fail cooldowns %u\n",
                kScenarios,lostDelayed,lostImmediate,noHeld,validCount,searches[0],searches[1],searches[2],assigns,cooldowns);
    Require(lostDelayed>10000 && lostImmediate>1000 && noHeld>10000 && validCount>10000 && searches[0]>1000 && searches[1]>1000 && searches[2]>1000 && assigns>1000 && cooldowns>1000,"scenario space coverage");
}

// ---------------------------------------------------------------------------------------------------------------------- sequences
struct Tick { U ret; std::vector<Event> events; };
static Tick StepOn(bool jitter) {
    rj::Configure(jitter,MirrorTargets()); // keep the tracker; Configure only resets the census row and the targets
    trace.clear();
    Tick t; t.ret=rj::TrackerTick(A(trackerMem),0,A(agentMem)); t.events=trace; return t;
}
static U SearchCount(const Tick& t) { U n=0; for(const Event& e:t.events) n+=e.fn==FSearch||e.fn==FSecond||e.fn==FThird; return n; }
static void SeqSetup(U id,U key,bool held) {
    Scenario s{}; s.key=key; s.second=0; s.third=0; s.held=held; s.cooldown=0; s.id=id; s.valid=false; for(U i=0;i<kTargets;++i) s.counter[i]=5;
    Setup(s);
}
static void Sequences() {
    for(U id=0x70;id<0x80;++id) {
        const U d=id&0xF;
        // S1: target lost at tick 0, the search succeeds when it runs: it runs at tick d exactly once.
        SeqSetup(id,0xAAAA0001u,true); scriptValid=false; scriptFound[0]=A(targetMem[1]);
        U searchTick=~0u, searches=0;
        for(U t=0;t<40;++t) {
            const Tick k=StepOn(true);
            if(SearchCount(k)) { searchTick=t; ++searches; Require(k.ret==A(targetMem[1]),"S1 the successful delayed search returns the new target"); scriptValid=true; }
            if(t<d) { Require(SearchCount(k)==0,"S1 no search before the delay ends"); Require(k.ret==0,"S1 target-less during the delay"); }
        }
        Require(searches==1 && searchTick==d,"S1 exactly one search at tick d");
        Require(Get(trackerMem,0x10)==A(targetMem[1]) && Get(trackerMem,0x14)==0,"S1 target assigned, cooldown 0");
        Require(Get(targetMem[0],0x474)==4 && Get(targetMem[1],0x474)==6,"S1 the old target's counter fell once, the new one's rose once");
        // S2: the delayed search fails: the native (id & 0xF) + 0x28 cooldown follows; the next search is that many ticks later.
        SeqSetup(id,0xAAAA0001u,true); scriptValid=false; scriptFound[0]=0;
        std::vector<U> ticks;
        for(U t=0;t<200;++t) { const Tick k=StepOn(true); if(SearchCount(k)) ticks.push_back(t); }
        Require(ticks.size()>=3 && ticks[0]==d && ticks[1]==d+d+0x28 && ticks[2]==d+2*(d+0x28),"S2 failed search: delay once, then the native 40..55 tick cooldown");
        // S2 flag OFF reference: the first search is immediate.
        SeqSetup(id,0xAAAA0001u,true); scriptValid=false; scriptFound[0]=0; ticks.clear();
        for(U t=0;t<200;++t) { const Tick k=StepOn(false); if(SearchCount(k)) ticks.push_back(t); }
        Require(ticks.size()>=3 && ticks[0]==0 && ticks[1]==d+0x28 && ticks[2]==2*(d+0x28)+0,"S2 flag off: immediate search then the native cooldown");
        // S3: a forced target (the step's 0x662960 before the tick) inside the delay: no search, no leftover cooldown; a later loss delays again.
        if(d>=2) {
            SeqSetup(id,0xAAAA0001u,true); scriptValid=false; scriptFound[0]=A(targetMem[1]);
            Tick k=StepOn(true); Require(SearchCount(k)==0 && Get(trackerMem,0x14)==d,"S3 delay started");
            reinterpret_cast<AssignFn>(A(At(0x662960)))(A(trackerMem),0,A(targetMem[2])); // the step's forced melee target
            Require(Get(trackerMem,0x10)==A(targetMem[2]) && Get(trackerMem,0x14)==0,"S3 the forced target clears the cooldown");
            scriptValid=true; k=StepOn(true); Require(SearchCount(k)==0 && k.ret==A(targetMem[2]),"S3 forced target kept, no search");
            scriptValid=false; k=StepOn(true); Require(SearchCount(k)==0 && Get(trackerMem,0x14)==d && k.ret==0,"S3 the next loss delays again");
        }
        // S4: a periodic clear on the EMPTY tracker inside the delay changes nothing: the delayed search still runs at tick d.
        if(d>=2) {
            SeqSetup(id,0xAAAA0001u,true); scriptValid=false; scriptFound[0]=A(targetMem[1]);
            StepOn(true);
            reinterpret_cast<ClearFn>(A(At(0x63CE00)))(A(trackerMem),0);
            U t=1; for(;t<40;++t) if(SearchCount(StepOn(true))) break;
            Require(t==d,"S4 periodic clear inside the delay leaves the delayed search tick unchanged");
        }
        // S5: a periodic clear on a HELD valid target (before the tick) is not a loss: the native immediate search runs with the flag on.
        SeqSetup(id,0xAAAA0001u,true); scriptValid=true; scriptFound[0]=A(targetMem[1]);   // valid for as long as the tracker holds the target
        reinterpret_cast<ClearFn>(A(At(0x63CE00)))(A(trackerMem),0);                         // the step's 0x677599 / 0x6775B9 clear
        rj::ResetRow(); const Tick k5=StepOn(true);
        Require(SearchCount(k5)==1 && k5.ret==A(targetMem[1]) && rj::words[rj::WLosses]==0 && rj::words[rj::WJittered]==0,"S5 periodic clear: immediate native re-search, no loss, no delay");
        // S6: never had a target (cooldown 0): immediate native search, no loss.
        SeqSetup(id,0xAAAA0001u,false); scriptValid=false; scriptFound[0]=A(targetMem[1]);
        rj::ResetRow(); const Tick k6=StepOn(true);
        Require(SearchCount(k6)==1 && rj::words[rj::WLosses]==0,"S6 no held target: immediate native search");
    }
}

int main(int argc,char** argv) {
    if(argc<2) { std::fprintf(stderr,"usage: native_retarget_jitter_oracle <Napoleon.exe>\n"); return 2; }
    Map(argv[1]);
    { const B* p=At(0x6671A0); const B expect[]={0x56,0x8B,0xF1,0x57,0x8B,0x46,0x14,0x85,0xC0,0x74,0x04,0x48,0x89,0x46,0x14}; Require(!std::memcmp(p,expect,sizeof expect),"0x6671A0 prologue is the pinned original"); }
    { const B* p=At(0x6671B4); Require(p[0]==0xE8 && p[5]==0x84 && p[6]==0xC0,"0x6795A0 call site"); }
    PatchOriginal();
    RandomEquivalence();
    Sequences();
    std::printf("native_retarget_jitter_oracle: OK (%u checks)\n",checks);
    return 0;
}

// Oracle for src/ai/ntw2_group_hold.{h,cpp} (--ai-hold-slots) on a private relocated mapping of the owned image.
//  * forwarding: in ModeOff MarkGate == the ORIGINAL 0x7C8820 bytes (unit and tactic bytes identical, no counter moves) for state x target class x member mark x category combinations;
//  * mechanism: state 4 + class-4 target + group not arrived -> eligible members re-marked 1 -> 4 (infantry mode: line/militia/... infantry only; all mode: every non-artillery member); exemptions
//    (artillery, light / skirmisher in infantry mode, melee, dead, native mark != 1); arrival latch (inside the group box / within 50 m of the front), latch reset by leaving state 4 or by a stale
//    entry (> 600 model ticks), unmeasured boxes / destinations leave the native marks, faulting member pointers are counted;
//  * redirect: InstallRedirect / RemoveRedirect patch and restore the E8 rel32 at 0x7D9223 exactly; a mismatched site is refused with no change.
// 0x7C8820 and its callee 0x55AB90 run as ORIGINAL image bytes. No running game or installed file is modified.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cmath>
#include <initializer_list>
#include <utility>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <vector>
#include "native_image_relocation.h"
#include "ntw2_runtime.h"
#include "ai/ntw2_group_hold.h"
#include "core/ntw2_guard.h"
#pragma comment(lib,"bcrypt.lib")
using U=uint32_t;
using B=unsigned char;
namespace gh=ntw2_group_hold;
static_assert(sizeof(void*)==4,"owned x86 oracle");
static B* image;
static U delta, checks, imageSize;
static void Require(bool ok,const char* what) { ++checks; if(!ok) { std::fprintf(stderr,"FAIL %s\n",what); std::exit(1); } }
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static B* At(U va) { return reinterpret_cast<B*>(va+delta); }
template<class T> static U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static void Put(void* p,U offset,U v) { std::memcpy(static_cast<B*>(p)+offset,&v,4); }
static void PutF(void* p,U offset,float v) { std::memcpy(static_cast<B*>(p)+offset,&v,4); }
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
constexpr U kMaxUnits=16;
struct Fix {
    B tactic[0x900];
    B model[0x100], mid[0x20], target[0x80], box[0x40];
    B unit[kMaxUnits][0xC00], form[kMaxUnits][0x800], cls[kMaxUnits][0x40], gun[kMaxUnits][0x40];
    U arr[kMaxUnits];
};
static __declspec(align(16)) Fix fx;
static __declspec(align(16)) B tac2[0x900];
struct M { U cat, sub, mark, live /*1 live, 0 dead via [AA0]==2, 2 dead via [2CC]==0*/, guns, melee; };
static M Inf(U mark=0,U sub=18) { return {2,sub,mark,1,0,0}; }
struct R {
    U state=4, cls=4, c4c=0, tick=1000, e0=10, bc=0; float f80c=50.0f;
    float W=100.0f, D=60.0f, dx=0.0f, dz=1000.0f; bool nullBox=false;
    float cx=0.0f, cz=0.0f, ax=1.0f, az=0.0f, fxv=0.0f, fzv=1.0f;   // box centre, axis1 (x,z), forward (x,z)
    U tickMode=0;                                                    // 1: [t+4] non-sane, 2: [[t+4]+8] non-sane
    std::vector<M> m;
};
// Group box: centre (0,0), axis1 = (1,0) (width along x), forward = (0,1) (depth along z). front point = (0,D/2). Default destination (0,1000): outside the box, 940 m from the front.
static void Build(const R& r) {
    std::memset(&fx,0,sizeof(fx)); std::memset(tac2,0,sizeof(tac2));
    B* t=fx.tactic;
    Put(t,4,r.tickMode==1 ? 0x10u : A(fx.mid)); Put(fx.mid,8,r.tickMode==2 ? 0x10u : A(fx.model)); Put(fx.model,0x58,r.tick);
    Put(t,0x40,A(fx.target)); Put(fx.target,0x48,r.cls); Put(fx.target,0x4C,r.c4c);
    Put(t,0x828,r.state); Put(t,0x7E0,r.e0); Put(t,0x7BC,r.bc); PutF(t,0x80C,r.f80c);
    PutF(t,0x7E8,r.dx); PutF(t,0x7EC,r.dz);
    Put(t,0xD8,r.nullBox ? 0u : A(fx.box));
    PutF(fx.box,8,r.cx); PutF(fx.box,0xC,r.cz); PutF(fx.box,0x14,r.W); PutF(fx.box,0x18,r.D);
    PutF(fx.box,0x1C,r.ax); PutF(fx.box,0x20,r.az); PutF(fx.box,0x24,r.fxv); PutF(fx.box,0x28,r.fzv);
    Put(t,0x6C,static_cast<U>(r.m.size())); Put(t,0x70,A(fx.arr));
    for(U i=0;i<r.m.size();++i) {
        const M& m=r.m[i]; B* u=fx.unit[i];
        Put(u,0xAA0,m.live==0 ? 2 : 0); Put(u,0x2CC,m.live==2 ? 0 : 20); Put(u,0xB34,m.mark);
        Put(fx.cls[i],0x1C,m.cat); Put(fx.cls[i],0x20,m.sub); Put(u,0x2C,A(fx.cls[i]));
        Put(fx.gun[i],0x10,m.guns); Put(u,0x1F4,A(fx.gun[i]));
        Put(u,0xADC,A(fx.form[i])); Put(fx.form[i],0x764,m.melee);
        fx.arr[i]=A(u);
    }
}
static std::vector<B> Blob() { const B* p=reinterpret_cast<const B*>(&fx); return std::vector<B>(p,p+sizeof(fx)); }
static std::vector<U> Marks(U n) { std::vector<U> v; for(U i=0;i<n;++i) v.push_back(Get(fx.unit[i],0xB34)); return v; }
static void Native(U tactic) { reinterpret_cast<void(__fastcall*)(U,U)>(static_cast<uintptr_t>(A(At(0x7C8820))))(tactic,0); }
static void Gate(U tactic) { gh::MarkGate(tactic,0); }
static U W(gh::Word w) { return gh::words[w]; }
static bool inScope=true;
static bool Scope(U) { return inScope; }
static gh::Targets targets;
static void Arm(gh::Mode mode) { gh::Configure(mode,targets); }
static std::vector<U> NativeMarks(const R& r) { Build(r); Native(A(fx.tactic)); return Marks(static_cast<U>(r.m.size())); }
static std::vector<U> GateMarks(const R& r) { Build(r); Gate(A(fx.tactic)); return Marks(static_cast<U>(r.m.size())); }
static void ExpectWords(const U (&e)[gh::kWords],const char* what) {
    for(U i=0;i<gh::kWords;++i) if(W(static_cast<gh::Word>(i))!=e[i]) { std::fprintf(stderr,"%s: word %u = %u, expected %u\n",what,i,W(static_cast<gh::Word>(i)),e[i]); Require(false,what); }
}

// ---------------------------------------------------------------------------------------------------------------------- forwarding
static void TestForwarding() {
    struct Cl { U cls, c4c; };
    const Cl classes[]={{4,0},{5,6},{5,0},{6,0},{7,0},{9,0}};
    const U marks[]={0,1,4,6,7};
    const M cats[]={{2,18,0,1,0,0},{2,17,0,1,0,0},{1,1,0,1,3,0},{0,9,0,1,0,0},{3,10,0,1,0,0}};
    Arm(gh::ModeOff); U combos=0;
    // sanity: the original marking forces armed artillery to 1 even when the posture is 4.
    { R r; r.state=3; r.cls=9; r.m={cats[2],cats[0]}; const std::vector<U> mk=NativeMarks(r); Require(mk[0]==1 && mk[1]==4,"native: artillery with guns stays 1, others take posture 4 (class 9)"); }
    for(U state:{0u,2u,3u,4u,5u})
        for(const Cl& c:classes)
            for(U base=0;base<5;++base)
                for(U rot=0;rot<5;++rot)
                    for(U variant=0;variant<3;++variant) {
                        R r; r.state=state; r.cls=c.cls; r.c4c=c.c4c; r.e0=variant==0 ? 10 : (variant==1 ? 100 : static_cast<U>(-10)); r.bc=variant&1; r.f80c=variant==2 ? 10.0f : 50.0f;
                        for(U i=0;i<6;++i) { M m=cats[(rot+i)%5]; m.mark=marks[(base+i)%5]; if(i==5 && (rot&1)) m.live=0; if(i==4 && (base&1)) m.melee=1; r.m.push_back(m); }
                        Build(r); Native(A(fx.tactic)); const std::vector<B> expect=Blob();
                        Build(r); Gate(A(fx.tactic)); const std::vector<B> got=Blob();
                        Require(expect==got,"ModeOff MarkGate == original 0x7C8820 (unit and tactic bytes)");
                        ++combos;
                    }
    for(U i=0;i<gh::kWords;++i) Require(W(static_cast<gh::Word>(i))==0,"ModeOff counts nothing");
    std::printf("forwarding: %u combinations, ModeOff == original 0x7C8820 bytes\n",combos);
}

// ---------------------------------------------------------------------------------------------------------------------- mechanism
static R MixedGroup() {
    R r;
    r.m={Inf(0,18),                  // 0 line infantry                 -> held
         {2,17,1,1,0,0},             // 1 light infantry                -> class exempt (infantry mode)
         {2,22,1,1,0,0},             // 2 skirmisher infantry           -> class exempt (infantry mode)
         {0,9,1,1,0,0},              // 3 cavalry                       -> class exempt (infantry mode)
         {3,10,1,1,0,0},             // 4 dragoons                      -> class exempt (infantry mode)
         {1,1,1,1,4,0},              // 5 artillery with guns           -> exempt in both modes
         {2,18,1,0,0,0},             // 6 dead ([AA0]==2)               -> skipped
         {2,18,6,1,0,0},             // 7 native mark 6 stays 6         -> skipped_mark
         {2,18,7,1,0,0},             // 8 native mark 7 stays 7         -> skipped_mark
         {2,18,1,1,0,1},             // 9 fighting melee                -> exempt_melee
         {2,18,4,1,0,0},             // 10 line infantry, native resets 4 -> 1 -> held
         {2,18,1,2,0,0},             // 11 dead ([2CC]==0)              -> skipped
         {1,1,1,1,0,0}};             // 12 artillery without guns       -> class exempt (category 1)
    return r;
}
static void ExpectMarks(const std::vector<U>& got,std::vector<U> expect,const char* what) { Require(got==expect,what); }
static void TestMechanism() {
    const R mixed=MixedGroup(); const U n=static_cast<U>(mixed.m.size());
    // ---- infantry mode
    Arm(gh::ModeInfantry);
    ExpectMarks(GateMarks(mixed),{4,1,1,1,1,1,1,6,7,1,4,1,1},"infantry mode: only line-type infantry re-marked 4; light, skirmisher, cavalry, dragoons, artillery, dead, 6/7, melee left");
    { const U e[gh::kWords]={1,1,1,2,6,1,0,0,1,0,2,2,n,0,0,0}; ExpectWords(e,"infantry mode first held call"); }
    // ---- all mode
    Arm(gh::ModeAll);
    ExpectMarks(GateMarks(mixed),{4,4,4,4,4,1,1,6,7,1,4,1,1},"all mode: every non-artillery eligible member re-marked 4");
    { const U e[gh::kWords]={1,1,1,6,2,1,0,0,1,0,2,2,n,0,0,0}; ExpectWords(e,"all mode first held call"); }
    // ---- native posture 4 already (class 9): members are not 1 -> untouched; held call counted, nothing marked
    { Arm(gh::ModeInfantry); R r; r.cls=9; r.m={Inf(),Inf(),Inf()};
      Require(GateMarks(r)==NativeMarks(r),"class 9 target: marks == native");
      Arm(gh::ModeInfantry); GateMarks(r);
      Require(W(gh::WHeldCalls)==1 && W(gh::WMarked)==0 && W(gh::WSkippedMark)==3,"native mark 4 is not touched (skipped_mark)"); }
    // ---- non-state-4 calls and non-class-4 targets: native marks exactly
    for(U state:{0u,2u,3u,5u}) {
        Arm(gh::ModeInfantry); R r=mixed; r.state=state; const std::vector<U> nat=NativeMarks(r);
        Require(GateMarks(r)==nat,"state != 4: native marks exactly");
        Require(W(gh::WCalls)==1 && W(gh::WState4)==0 && W(gh::WHeldCalls)==0 && W(gh::WMarked)==0 && W(gh::WArrivals)==0 && W(gh::WReleasedCalls)==0 && W(gh::WFaults)==0,"state != 4 counts only the call");
    }
    // ---- arrival latch (infantry mode)
    {
        R r; r.m={Inf(),Inf(),Inf(0,20)}; const U four[]={4,4,4}, nat[]={1,1,1};
        auto Is=[&](const std::vector<U>& v,const U* e){ return v[0]==e[0] && v[1]==e[1] && v[2]==e[2]; };
        Arm(gh::ModeInfantry);
        Require(Is(GateMarks(r),four) && W(gh::WHeldCalls)==1 && W(gh::WMarked)==3 && W(gh::WGroups)==1,"far destination: held");
        r.dx=10; r.dz=10;       // inside the box
        Require(Is(GateMarks(r),nat) && W(gh::WArrivals)==1 && W(gh::WHeldCalls)==1 && W(gh::WMarked)==3,"destination inside the group box: arrival latches, native marks");
        r.dx=0; r.dz=1000;      // moves away again while still in state 4: the latch holds
        const U relBefore=W(gh::WReleasedCalls);
        Require(Is(GateMarks(r),nat) && W(gh::WArrivals)==1 && W(gh::WHeldCalls)==1 && W(gh::WReleasedCalls)==relBefore+1 && W(gh::WState4)==3,"latched: stays native although the destination moved away");
        R s2=r; s2.state=2;     // leaving state 4 resets the latch
        Require(GateMarks(s2)==NativeMarks(s2),"state 2 call: native marks");
        Require(Is(GateMarks(r),four) && W(gh::WHeldCalls)==2 && W(gh::WArrivals)==1,"leaving state 4 reset the latch: held again");
        r.dx=0; r.dz=70;        // 40 m from the front (0,30), outside the box (|dz| > 30)
        Require(Is(GateMarks(r),nat) && W(gh::WArrivals)==2 && W(gh::WHeldCalls)==2,"destination within 50 m of the group front latches arrival");
        Require(Is(GateMarks(s2),nat),"state 2 again"); // reset
        r.dx=60; r.dz=0;        // outside the box (|dx| 60 > 50), 67 m from the front: not arrived
        Require(Is(GateMarks(r),four) && W(gh::WHeldCalls)==3 && W(gh::WArrivals)==2,"outside the box and >= 50 m from the front: not arrived");
        r.dx=0; r.dz=30+49.0f;  // 49 m from the front: arrived
        Require(Is(GateMarks(r),nat) && W(gh::WArrivals)==3,"49 m from the front arrives");
        Require(Is(GateMarks(s2),nat),"state 2 again");
        r.dx=0; r.dz=30+51.0f;  // 51 m: held
        Require(Is(GateMarks(r),four) && W(gh::WArrivals)==3,"51 m from the front is not arrived");
    }
    // ---- stale entry
    {
        R r; r.m={Inf(),Inf()}; Arm(gh::ModeInfantry);
        r.tick=1000; GateMarks(r); Require(W(gh::WHeldCalls)==1,"stale: held");
        r.dx=10; r.dz=10; GateMarks(r); Require(W(gh::WArrivals)==1,"stale: latched");
        r.dx=0; r.dz=1000; r.tick=1600; Require(GateMarks(r)==NativeMarks(r) && W(gh::WHeldCalls)==1,"600 ticks unseen is not stale: still latched");
        r.tick=2201; const std::vector<U> g=GateMarks(r);
        Require(g[0]==4 && g[1]==4 && W(gh::WHeldCalls)==2 && W(gh::WArrivals)==1,"601 ticks unseen: entry reinitialised, held again");
    }
    // ---- two tactics are tracked independently (second tactic is a byte copy sharing units / box)
    {
        R r; r.m={Inf(),Inf()}; Arm(gh::ModeInfantry); Build(r);
        std::memcpy(tac2,fx.tactic,sizeof(tac2));
        PutF(fx.tactic,0x7E8,10.0f); PutF(fx.tactic,0x7EC,10.0f);
        Gate(A(fx.tactic)); Require(W(gh::WArrivals)==1,"tactic 1 arrives");
        Gate(A(tac2)); Require(Get(fx.unit[0],0xB34)==4 && W(gh::WHeldCalls)==1 && W(gh::WGroups)==2 && W(gh::WArrivals)==1,"tactic 2 has its own latch and holds");
        { const U rel=W(gh::WReleasedCalls); Gate(A(fx.tactic)); Require(Get(fx.unit[0],0xB34)==1 && W(gh::WReleasedCalls)==rel+1,"tactic 1 stays latched"); }
    }
    // ---- unmeasured: invalid box / destination -> native marks, counted, no latch
    {
        struct Bad { const char* what; void (*mut)(R&); };
        const float nan=std::numeric_limits<float>::quiet_NaN(), inf=std::numeric_limits<float>::infinity();
        static float snan, sinf; snan=nan; sinf=inf;
        const Bad bad[]={{"W == 0",[](R& r){ r.W=0; }},{"D == 0",[](R& r){ r.D=0; }},{"W < 0",[](R& r){ r.W=-5; }},{"D < 0",[](R& r){ r.D=-1; }},
                         {"W NaN",[](R& r){ r.W=snan; }},{"D NaN",[](R& r){ r.D=snan; }},{"dest x NaN",[](R& r){ r.dx=snan; }},{"dest z inf",[](R& r){ r.dz=sinf; }},
                         {"null box",[](R& r){ r.nullBox=true; }}};
        for(const Bad& b:bad) {
            R r; r.m={Inf(),Inf(),Inf()}; b.mut(r); Arm(gh::ModeInfantry);
            Require(GateMarks(r)==NativeMarks(r),b.what);
            Require(W(gh::WCalls)==1 && W(gh::WState4)==1 && W(gh::WUnmeasured)==1 && W(gh::WHeldCalls)==0 && W(gh::WMarked)==0 && W(gh::WArrivals)==0 && W(gh::WFaults)==0,"unmeasured: native marks, counted, no hold, no latch");
            R ok; ok.m=r.m; const std::vector<U> g=GateMarks(ok);
            Require(g[0]==4 && W(gh::WHeldCalls)==1 && W(gh::WUnmeasured)==1,"a valid call after an unmeasured one holds");
        }
    }
    // ---- scope is informational
    { R r; r.m={Inf(),Inf()}; Arm(gh::ModeInfantry); inScope=false; const std::vector<U> g=GateMarks(r); inScope=true;
      Require(g[0]==4 && W(gh::WOutOfScope)==1 && W(gh::WHeldCalls)==1,"out-of-scope call is still gated and counted"); }
    std::printf("mechanism: infantry/all modes, exemptions, arrival latch, stale, unmeasured, scope\n");
}

static void __fastcall FakeMark(U,U) {}
static void Expect(std::initializer_list<std::pair<gh::Word,U>> nz,const char* what) {
    U e[gh::kWords]={}; for(const auto& p:nz) e[p.first]=p.second;
    ExpectWords(e,what);
    volatile U snap[gh::kWords]; gh::Snapshot(snap);
    for(U i=0;i<gh::kWords;++i) Require(snap[i]==gh::words[i],"Snapshot == words");
}
// A fault in the post-processing: the ORIGINAL 0x7C8820 stays the marking target (it never reads a member's formation pointer [U+0xADC]); member 1's formation points at a PAGE_NOACCESS page.
static void TestFaults() {
    B* bad=static_cast<B*>(VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_NOACCESS)); Require(bad!=nullptr,"reserve a no-access page");
    R r; r.m={Inf(),Inf(),Inf()};
    Arm(gh::ModeInfantry);
    const unsigned depth=ntw2::probeDepth;
    Build(r); Put(fx.unit[1],0xADC,A(bad)); Gate(A(fx.tactic));
    Require(Marks(3)==std::vector<U>({4,1,1}),"fault at member 1: member 0 re-marked, walk aborted, member 2 keeps the native mark");
    Require(ntw2::probeDepth==depth,"probeDepth restored after a fault");
    Expect({{gh::WCalls,1},{gh::WState4,1},{gh::WHeldCalls,1},{gh::WMarked,1},{gh::WGroups,1},{gh::WMaxMembers,3},{gh::WFaults,1}},"fault call row");
    Build(r); Gate(A(fx.tactic));
    Require(Marks(3)==std::vector<U>({4,4,4}),"healthy call after a fault re-marks everything");
    Require(ntw2::probeDepth==depth,"probeDepth unchanged by a healthy call");
    Expect({{gh::WCalls,2},{gh::WState4,2},{gh::WHeldCalls,2},{gh::WMarked,4},{gh::WGroups,1},{gh::WMaxMembers,3},{gh::WFaults,1}},"fault + healthy rows");
    VirtualFree(bad,0,MEM_RELEASE);
    std::printf("faults: SEH fault counted, partial re-mark, probeDepth restored\n");
}

// Whole-row deltas for the main paths; ResetRow keeps the latch state.
static void TestRows() {
    R r; r.m={Inf(),Inf(),Inf()}; const std::vector<U> four{4,4,4}, nat{1,1,1};
    auto Call=[](const R& x){ Build(x); Gate(A(fx.tactic)); return Marks(static_cast<U>(x.m.size())); };
    Arm(gh::ModeInfantry);
    Require(Call(r)==four,"rows: far call holds");
    Expect({{gh::WCalls,1},{gh::WState4,1},{gh::WHeldCalls,1},{gh::WMarked,3},{gh::WGroups,1},{gh::WMaxMembers,3}},"held call row");
    gh::ResetRow(); R in=r; in.dx=10; in.dz=10;
    Require(Call(in)==nat,"rows: arrival call keeps native marks");
    Expect({{gh::WCalls,1},{gh::WState4,1},{gh::WArrivals,1},{gh::WReleasedCalls,1}},"arrival call row");
    gh::ResetRow();
    Require(Call(r)==nat,"ResetRow keeps the latch: an arrived tactic stays released");
    Expect({{gh::WCalls,1},{gh::WState4,1},{gh::WReleasedCalls,1}},"latched call row after ResetRow");
    gh::ResetRow(); R s2=r; s2.state=2; Require(Call(s2)==nat,"rows: state 2 native marks");
    Expect({{gh::WCalls,1}},"state != 4 call on an existing entry: only calls");
    gh::ResetRow(); Require(Call(r)==four,"rows: held again after leaving state 4");
    Expect({{gh::WCalls,1},{gh::WState4,1},{gh::WHeldCalls,1},{gh::WMarked,3},{gh::WMaxMembers,3}},"held after reset row (no new group)");
    // a state != 4 call on an unseen tactic creates no entry
    Arm(gh::ModeInfantry); Require(Call(s2)==nat,"rows: state 2 on an unseen tactic");
    Expect({{gh::WCalls,1}},"state != 4 on an unseen tactic: no group, no table_full");
    // stale
    Arm(gh::ModeInfantry); in.tick=1000; Call(in); gh::ResetRow();
    r.tick=2000; Require(Call(r)==four,"rows: stale entry holds again");
    Expect({{gh::WCalls,1},{gh::WState4,1},{gh::WHeldCalls,1},{gh::WMarked,3},{gh::WMaxMembers,3}},"stale call row");
    r.tick=1000;
    // unmeasured: numeric invalid box, then invalid model tick paths
    { R b=r; b.W=0; Arm(gh::ModeInfantry); Require(Call(b)==nat,"rows: W == 0 native");
      Expect({{gh::WCalls,1},{gh::WState4,1},{gh::WUnmeasured,1},{gh::WGroups,1}},"unmeasured box row"); }
    for(U mode:{1u,2u}) { R b=r; b.tickMode=mode; Arm(gh::ModeInfantry); Require(Call(b)==nat,"rows: invalid model tick path native");
        Expect({{gh::WCalls,1},{gh::WState4,1},{gh::WUnmeasured,1}},"invalid model tick row (no entry)"); }
    // out of scope
    Arm(gh::ModeInfantry); inScope=false; Require(Call(r)==four,"rows: out-of-scope still held"); inScope=true;
    Expect({{gh::WCalls,1},{gh::WState4,1},{gh::WHeldCalls,1},{gh::WMarked,3},{gh::WGroups,1},{gh::WMaxMembers,3},{gh::WOutOfScope,1}},"out_of_scope row");
    std::printf("rows: whole-row deltas, ResetRow keeps latch, invalid model tick\n");
}

// Member-list paths: a non-sane member pointer is skipped (no fault), a member count above the cap (512) is truncated.
static U bigArr[1000];
static void TestMemberPaths() {
    gh::Targets t=targets; t.marking=Fn(&FakeMark);   // the original marking would dereference the non-sane pointer
    gh::Configure(gh::ModeInfantry,t);
    R r; r.m={Inf(1),Inf(1),Inf(1)};
    Build(r); fx.arr[1]=0x10; Gate(A(fx.tactic));
    Require(Marks(3)[0]==4 && Marks(3)[1]==1 && Marks(3)[2]==4,"non-sane member pointer skipped, neighbours re-marked");
    Expect({{gh::WCalls,1},{gh::WState4,1},{gh::WHeldCalls,1},{gh::WMarked,2},{gh::WGroups,1},{gh::WMaxMembers,3}},"non-sane member row (no fault)");
    Arm(gh::ModeInfantry);
    R c; c.m={Inf(0)}; Build(c);
    for(U& v:bigArr) v=A(fx.unit[0]);
    Put(fx.tactic,0x6C,1000); Put(fx.tactic,0x70,A(bigArr)); Gate(A(fx.tactic));
    Expect({{gh::WCalls,1},{gh::WState4,1},{gh::WHeldCalls,1},{gh::WMarked,1},{gh::WGroups,1},{gh::WSkippedMark,511},{gh::WMaxMembers,1000}},"member count 1000 capped at 512 (1 marked + 511 repeats)");
    std::printf("member paths: non-sane pointer skipped, count capped at 512\n");
}

// Table capacity is 512 entries: the 513th distinct state-4 tactic (same model tick, nothing stale) is not tracked and keeps the native marks.
static B bigTac[513][0x900];
static void TestTableFull() {
    R r; r.m={Inf(),Inf(),Inf()}; Build(r);
    for(U i=0;i<513;++i) std::memcpy(bigTac[i],fx.tactic,0x900);
    Arm(gh::ModeInfantry);
    for(U i=0;i<512;++i) Gate(A(bigTac[i]));
    Expect({{gh::WCalls,512},{gh::WState4,512},{gh::WHeldCalls,512},{gh::WMarked,3*512},{gh::WGroups,512},{gh::WMaxMembers,3}},"512 tactics tracked");
    gh::ResetRow(); Gate(A(bigTac[512]));
    Require(Marks(3)==std::vector<U>({1,1,1}),"513th tactic: native marks");
    Expect({{gh::WCalls,1},{gh::WState4,1},{gh::WTableFull,1}},"table_full row");
    std::printf("table: 512 tracked, 513th counts table_full\n");
}

// Arrival predicate discrimination on fresh latches: inside-box-only, inclusive edges, strict 50 m front distance, translated + rotated box.
static bool ArrivesAt(R r,float dx,float dz) {
    r.dx=dx; r.dz=dz; r.m={Inf(),Inf()}; Arm(gh::ModeInfantry);
    const std::vector<U> g=GateMarks(r); const bool arrived=W(gh::WArrivals)==1;
    Require(arrived ? (g[0]==1 && g[1]==1 && W(gh::WHeldCalls)==0) : (g[0]==4 && g[1]==4 && W(gh::WHeldCalls)==1 && W(gh::WArrivals)==0),"arrival result consistent with the marks");
    return arrived;
}
static void TestArrivalGeometry() {
    R r;                                         // centre (0,0), W 100 (x), D 60 (z), front (0,30)
    Require(ArrivesAt(r,40,-20) && ArrivesAt(r,0,0) && ArrivesAt(r,45,0),"inside the box only (> 50 m from the front) arrives");
    Require(ArrivesAt(r,50,0) && ArrivesAt(r,0,-30) && ArrivesAt(r,50,-30) && ArrivesAt(r,-50,30),"inclusive box edges arrive");
    Require(!ArrivesAt(r,50.5f,0) && !ArrivesAt(r,0,-30.5f) && !ArrivesAt(r,0,-40) && !ArrivesAt(r,-60,0),"just outside the box and far from the front: not arrived");
    Require(!ArrivesAt(r,0,80),"exactly 50 m from the front is NOT arrived (strict <)");
    Require(ArrivesAt(r,0,79.5f) && ArrivesAt(r,0,70) && ArrivesAt(r,30,50),"within 50 m of the front (outside the box) arrives");
    Require(!ArrivesAt(r,0,80.5f) && !ArrivesAt(r,40,60),"beyond 50 m of the front: not arrived");
    // translated + rotated box: centre (100,200), axis1 = (0.6,0.8), forward = (-0.8,0.6)
    R q; q.cx=100; q.cz=200; q.ax=0.6f; q.az=0.8f; q.fxv=-0.8f; q.fzv=0.6f;
    auto Local=[&](float a,float f){ return std::make_pair(q.cx+a*q.ax+f*q.fxv,q.cz+a*q.az+f*q.fzv); };
    auto In=[&](float a,float f){ const auto p=Local(a,f); return ArrivesAt(q,p.first,p.second); };
    Require(In(0,0) && In(45,-20) && In(-45,20) && In(0,-25),"rotated box: inside arrives");
    Require(!In(60,0) && !In(-60,0) && !In(0,-40) && !In(0,-45) && !In(20,-40),"rotated box: outside the box and far from the front is not arrived (axes not swapped)");
    Require(In(0,70) && In(0,79) && In(20,60),"rotated box: near the front arrives");
    Require(!In(0,85) && !In(0,90),"rotated box: beyond 50 m from the front is not arrived");
    std::printf("arrival geometry: inside-only, edges, strict 50 m, rotated box\n");
}

// ---------------------------------------------------------------------------------------------------------------------- redirect
static void TestRedirect() {
    B* site=At(gh::kCallSite); B orig[5]; std::memcpy(orig,site,5);
    Require(orig[0]==0xE8 && Get(orig,1)==0xFFFEF5F8u,"original call site 0x7D9223: E8 F8 F5 FE FF");
    Require(gh::RemoveRedirect(delta) && !std::memcmp(site,orig,5),"RemoveRedirect on an original site is a no-op returning true");
    const U gate=Fn(&gh::MarkGate);
    Require(gh::InstallRedirect(delta,gate),"InstallRedirect");
    Require(site[0]==0xE8 && Get(site,1)==gate-(A(site)+5),"E8 rel32 now targets the gate");
    B patched[5]; std::memcpy(patched,site,5);
    Require(!gh::InstallRedirect(delta,gate) && !std::memcmp(site,patched,5),"second install refused (site no longer calls 0x7C8820), no change");
    Require(gh::RemoveRedirect(delta) && !std::memcmp(site,orig,5),"RemoveRedirect restores the original 5 bytes");
    // mismatched sites: wrong opcode, wrong target
    site[0]=0x90; B bad1[5]; std::memcpy(bad1,site,5);
    Require(!gh::InstallRedirect(delta,gate) && !std::memcmp(site,bad1,5),"wrong opcode refused with no change");
    std::memcpy(site,orig,5); Put(site,1,Get(orig,1)+4); B bad2[5]; std::memcpy(bad2,site,5);
    Require(!gh::InstallRedirect(delta,gate) && !std::memcmp(site,bad2,5),"wrong rel32 refused with no change");
    std::memcpy(site,orig,5);
    Require(FlushInstructionCache(GetCurrentProcess(),image,imageSize)!=0,"flush image");
    std::printf("redirect: install / restore / mismatch refusal\n");
}

// ---------------------------------------------------------------------------------------------------------------------- cost
static double PerCallNs(void(*call)(U),U n) {
    LARGE_INTEGER f,a,b; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&a);
    for(U i=0;i<n;++i) call(A(fx.tactic));
    QueryPerformanceCounter(&b);
    return 1e9*static_cast<double>(b.QuadPart-a.QuadPart)/static_cast<double>(f.QuadPart)/n;
}
static void TestCost() {
    R r; for(U i=0;i<12;++i) r.m.push_back(Inf()); Build(r); Arm(gh::ModeInfantry);
    constexpr U n=200000;
    const double nat=PerCallNs(&Native,n), gate=PerCallNs(&Gate,n);
    Require(W(gh::WHeldCalls)==n && W(gh::WMarked)==12u*n && W(gh::WFaults)==0,"held path every call");
    std::printf("cost: native %.0f ns/call, gate (held path, 12 members) %.0f ns/call (+%.0f)\n",nat,gate,gate-nat);
}

int main(int argc,char** argv) {
    if(argc!=2) { std::fprintf(stderr,"usage: native_group_hold_oracle Napoleon.exe\n"); return 2; }
    std::setvbuf(stdout,nullptr,_IONBF,0);
    Map(argv[1]);
    Require(FlushInstructionCache(GetCurrentProcess(),image,imageSize)!=0,"flush image");
    targets={A(At(gh::kMarking)),&Scope};
    Require(At(0x7C8924)[0]==0xC3,"0x7C8924 plain ret");
    TestForwarding(); TestMechanism(); TestFaults(); TestRows(); TestMemberPaths(); TestTableFull(); TestArrivalGeometry(); TestRedirect(); TestCost();
    std::printf("group hold oracle: %u checks\n",checks);
    return 0;
}

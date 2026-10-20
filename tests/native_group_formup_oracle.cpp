// Oracle for src/ai/ntw2_group_formup.{h,cpp} (--ai-formup-gate) on a private relocated mapping of the owned image.
//  * forwarding: with the gate off (or a NULL FSM sub-object) every slot tail-calls the ORIGINAL thunk bytes 0x702A80 / 0x702B20 / 0x702A40 / 0x702AE0: same result, same native call sequence,
//    no counter moves;
//  * mirror: with the gate on and nothing to withhold (formed, waived, escape, timeout, or the native answers FALSE) the host mirror returns what the original thunk returns and calls the native
//    tests in the same order, for every scripted combination of the five native tests;
//  * gating: a native "exit" is withheld (result 0, none of the alternate tests called) while < pct of the members are within `metres` of their move-command destination, and released by
//    formed / waived ([t+0x81E] == 0) / escape ([t+0x80C] <= 140) / timeout (ticks since the enter gate ran); the formed% counts only live members under group control; members without an active
//    command count formed; non-move commands and unreadable poses count formed and 'unmeasured'; a faulting read lets the native answer through;
//  * bookkeeping: blocked entries, wait max/sum, the formed% histogram, out-of-scope calls (still gated), the enter gates reset the clock.
// Image-internal callees 0x7B5AF0, 0x7A5730, 0x7A5A80, 0x7B5640, 0x7A5C80 (tests) and 0x7B5910 / 0x7A5A30 (enter bodies) are scripted host fakes; the four thunks are original bytes. No running game or
// installed file is modified.
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
#include "ai/ntw2_group_formup.h"
#pragma comment(lib,"bcrypt.lib")
using U=uint32_t;
using B=unsigned char;
namespace gf=ntw2_group_formup;
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

// ---------------------------------------------------------------------------------------------------------------------- scripted natives
enum Tag : U { TReformExit=1, TReformAlt, TFormupExit, TFormupAlt, TFormupAlt2, TEnter2Body, TEnter3Body, TEv80=0x80, TEv84=0x84, TEv88=0x88, TEv8C=0x8C };
static std::vector<U> seq;                       // tags in call order
static bool answer[8];                           // scripted AL of TReformExit..TFormupAlt2 (index = tag)
static U __fastcall FakeReformExit(U,U) { seq.push_back(TReformExit); return answer[TReformExit]; }
static U __fastcall FakeReformAlt(U,U) { seq.push_back(TReformAlt); return answer[TReformAlt]; }
static U __fastcall FakeFormupExit(U,U) { seq.push_back(TFormupExit); return answer[TFormupExit]; }
static U __fastcall FakeFormupAlt(U,U) { seq.push_back(TFormupAlt); return answer[TFormupAlt]; }
static U __fastcall FakeFormupAlt2(U,U) { seq.push_back(TFormupAlt2); return answer[TFormupAlt2]; }
static U __fastcall FakeEnter2(U,U) { seq.push_back(TEnter2Body); return 0; }
static U __fastcall FakeEnter3(U,U) { seq.push_back(TEnter3Body); return 0; }
// Event identities: the tactic vtable slots +0x80/+0x84/+0x88/+0x8C are constant-returning stubs (plain ret).
static U __fastcall Ev80(U,U) { seq.push_back(TEv80); return 0xE80; }
static U __fastcall Ev84(U,U) { seq.push_back(TEv84); return 0xE84; }
static U __fastcall Ev88(U,U) { seq.push_back(TEv88); return 0xE88; }
static U __fastcall Ev8C(U,U) { seq.push_back(TEv8C); return 0xE8C; }
// Move command row: vt+0x38 = pose getter (the pose is the row itself; x at +0x40, z at +0x48), 0x80E9D0 = pose -> vec3 (out pointer, returns it).
static U moveVt[32], otherVt[32];
static U poseBad;                                // 1: the pose getter returns a non-sane pointer
static U __fastcall FakePose(U row,U) { return poseBad ? 0x10u : row; }
static U __fastcall FakePoseToVec(U pose,U,U out) {
    float* o=reinterpret_cast<float*>(static_cast<uintptr_t>(out));
    std::memcpy(&o[0],reinterpret_cast<const B*>(static_cast<uintptr_t>(pose))+0x40,4);
    o[1]=0.0f;
    std::memcpy(&o[2],reinterpret_cast<const B*>(static_cast<uintptr_t>(pose))+0x48,4);
    return out;
}

// ---------------------------------------------------------------------------------------------------------------------- fixture
constexpr U kMaxUnits=16;
static U tacticVt[64];
static __declspec(align(16)) B tacticMem[3][0x900], modelMem[0x100], midMem[0x20], unitMem[kMaxUnits][0xC00], formMem[kMaxUnits][0x700], unitArray[kMaxUnits*4];
struct Member { float cx, cz, dx, dz; bool order; bool move; U live; U aiState; U b42; };
static B* Tactic(U i=0) { return tacticMem[i]; }
static void BuildTactic(U which,const std::vector<Member>& members,U tick,bool waivedOff,float distance) {
    B* t=tacticMem[which];
    std::memset(t,0,sizeof(tacticMem[which]));
    Put(t,0,A(tacticVt)); Put(t,4,A(midMem)); Put(midMem,8,A(modelMem)); Put(modelMem,0x58,tick);
    t[0x81E]=waivedOff ? 0 : 1; PutF(t,0x80C,distance);
    Put(t,0x6C,static_cast<U>(members.size())); Put(t,0x70,A(unitArray));
    for(U i=0;i<members.size();++i) {
        const Member& m=members[i];
        std::memset(unitMem[i],0,sizeof(unitMem[i])); std::memset(formMem[i],0,sizeof(formMem[i]));
        Put(unitMem[i],0xAA0,m.live ? 0 : 2); Put(unitMem[i],0x2CC,m.live==2 ? 0 : 20); Put(unitMem[i],0xB34,m.aiState); unitMem[i][0xB42]=static_cast<B>(m.b42);
        Put(unitMem[i],0xADC,A(formMem[i])); PutF(formMem[i],0x644,m.cx); PutF(formMem[i],0x648,m.cz);
        if(m.order) {
            Put(unitMem[i],0x930,1); Put(unitMem[i],0x934,2);
            B* row=unitMem[i]+0x398+0x90*2;
            Put(row,0,A(m.move ? moveVt : otherVt)); PutF(row,0x40,m.dx); PutF(row,0x48,m.dz);
        }
        Put(unitArray,4*i,A(unitMem[i]));
    }
}
static std::vector<Member> Members(U formed,U unformed) {   // `formed` members at their destination, `unformed` 100 m away
    std::vector<Member> v;
    for(U i=0;i<formed;++i) v.push_back({100,100,100,110,true,true,1,0,0});
    for(U i=0;i<unformed;++i) v.push_back({100,100,100,200,true,true,1,0,0});
    return v;
}
static gf::Targets targets;
static bool inScope=true;
static bool Scope(U) { return inScope; }
static U W(gf::Word w) { return gf::words[w]; }
static void Arm(bool on,U pct=80,U metres=25,U timeout=600) { gf::Configure(on,gf::Params{pct,metres,timeout},targets); }
static U Thunk(U va,U sub) { return reinterpret_cast<U(__stdcall*)(U)>(static_cast<uintptr_t>(A(At(va))))(sub); }
static U Sub(U which=0) { return A(tacticMem[which])+0x7C; }
static void Script(bool re,bool ra,bool fe,bool fa,bool fa2) { answer[TReformExit]=re; answer[TReformAlt]=ra; answer[TFormupExit]=fe; answer[TFormupAlt]=fa; answer[TFormupAlt2]=fa2; }
static U GateTest(U state,U sub) { return state==2 ? gf::TestGate2(sub) : gf::TestGate3(sub); }
static U OrigTest(U state,U sub) { return Thunk(state==2 ? 0x702A80 : 0x702B20,sub); }

static void TestForwarding() {
    BuildTactic(0,Members(1,3),1000,false,500.0f);
    for(U state:{2u,3u})
        for(U mask=0;mask<32;++mask) {
            Script(mask&1,mask&2,mask&4,mask&8,mask&16);
            seq.clear(); const U expect=OrigTest(state,Sub()); const std::vector<U> expectSeq=seq;
            Arm(false);
            seq.clear(); const U got=GateTest(state,Sub());
            Require(got==expect && seq==expectSeq,"gate off == original thunk bytes (result and native call order)");
            for(U i=0;i<gf::kWords;++i) Require(W(static_cast<gf::Word>(i))==0,"gate off counts nothing");
        }
    Script(false,false,false,false,false); Arm(true); // a NULL tactic with a TRUE answer would fault in the original thunk itself ([esi] with esi = 0)
    seq.clear(); const U nullSub=gf::TestGate2(0); const std::vector<U> a=seq;
    seq.clear(); const U nullOrig=OrigTest(2,0);
    Require(nullSub==nullOrig && a==seq && W(gf::WEvals)==0,"NULL FSM sub-object forwards");
    for(U state:{2u,3u}) {
        Arm(false); seq.clear(); (state==2 ? gf::EnterGate2 : gf::EnterGate3)(Sub()); const std::vector<U> g=seq;
        seq.clear(); Thunk(state==2 ? 0x702A40 : 0x702AE0,Sub());
        Require(g==seq && g.size()==1 && g[0]==(state==2 ? TEnter2Body : TEnter3Body),"enter gate off == original enter thunk");
    }
    std::printf("forwarding: gate off / NULL sub-object == original thunk bytes\n");
}

static void TestMirror() {
    // Nothing to withhold: pct 0 releases every exit through "formed". The mirror must equal the original thunk for all native answer combinations.
    BuildTactic(0,Members(0,4),1000,false,500.0f);
    for(U state:{2u,3u})
        for(U mask=0;mask<32;++mask) {
            Script(mask&1,mask&2,mask&4,mask&8,mask&16);
            seq.clear(); const U expect=OrigTest(state,Sub()); const std::vector<U> expectSeq=seq;
            Arm(true,0);
            seq.clear(); const U got=GateTest(state,Sub());
            Require(got==expect && seq==expectSeq,"mirror (nothing withheld) == original thunk bytes");
        }
    // Waiver, escape and timeout also release unconditionally with 0 % formed.
    Script(true,true,true,true,true);
    BuildTactic(0,Members(0,4),1000,true,500.0f); Arm(true,100);
    for(U state:{2u,3u}) { seq.clear(); const U got=GateTest(state,Sub()); Require(got==0xE88 && seq.back()==TEv88,"waived releases"); }
    Require(W(gf::WPassWaived)==2 && W(gf::WBlocked)==0,"waived counted");
    std::printf("mirror: gate on, nothing withheld == original thunk bytes\n");
}

static void TestFormed() {
    struct C { U formed, unformed, pct; bool pass; };
    const C cases[]={{4,0,100,true},{3,1,75,true},{3,1,76,false},{3,1,80,false},{1,3,25,true},{1,3,26,false},{0,4,1,false},{0,4,0,true},{2,2,50,true},{0,0,100,true}};
    for(const C& c:cases) {
        BuildTactic(0,Members(c.formed,c.unformed),1000,false,500.0f);
        Script(true,false,true,false,false);
        for(U state:{2u,3u}) {
            Arm(true,c.pct); seq.clear(); Thunk(state==2 ? 0x702A40 : 0x702AE0,Sub()); (state==2 ? gf::EnterGate2 : gf::EnterGate3)(Sub());
            seq.clear(); const U r=GateTest(state,Sub());
            if(c.pass) Require(r==0xE88 && seq.size()==2 && seq[1]==TEv88 && W(gf::WPassFormed)==1,"formed >= pct releases the exit");
            else Require(r==0 && seq.size()==1 && seq[0]==(state==2 ? TReformExit : TFormupExit) && W(gf::WBlocked)==1 && W(gf::WBlockedEntries)==(state==2 ? 1u : 0x10000u),"formed < pct withholds the exit and calls nothing else");
        }
    }
    // Distance rule: <= metres is formed, > metres is not; metres 0 needs the exact slot.
    for(float dz:{110.0f,125.0f,125.5f}) {
        std::vector<Member> v={{100,100,100,dz,true,true,1,0,0}};
        BuildTactic(0,v,1000,false,500.0f); Script(true,false,true,false,false); Arm(true,100,25); gf::EnterGate2(Sub());
        seq.clear(); const U r=gf::TestGate2(Sub());
        Require((dz<=125.0f) == (r==0xE88),"25 m boundary is inclusive");
    }
    // Member filters: dead, no members, AI states 6/7 and [U+0xB42] members are not counted; no order / non-move order / bad pose count formed.
    {
        std::vector<Member> v={{100,100,100,300,true,true,0,0,0},{100,100,100,300,true,true,2,0,0},{100,100,100,300,true,true,1,6,0},{100,100,100,300,true,true,1,7,0},{100,100,100,300,true,true,1,0,1},
                               {100,100,100,110,true,true,1,0,0}};
        BuildTactic(0,v,1000,false,500.0f); Script(true,false,true,false,false); Arm(true,100); gf::EnterGate2(Sub());
        Require(gf::TestGate2(Sub())==0xE88 && W(gf::WPassFormed)==1 && W(gf::WHist3)==1,"dead / unassigned / state 6,7 / [U+0xB42] members are ignored (1 counted member, formed)");
    }
    {
        std::vector<Member> v={{100,100,0,0,false,false,1,0,0},{100,100,100,300,true,false,1,0,0},{100,100,100,110,true,true,1,0,0},{100,100,100,300,true,true,1,0,0}};
        BuildTactic(0,v,1000,false,500.0f); Script(true,false,true,false,false); Arm(true,75); gf::EnterGate2(Sub());
        const U r=gf::TestGate2(Sub());
        Require(r==0xE88 && W(gf::WUnmeasured)==1,"no order and non-move order count formed (3/4 = 75 %), the non-move order is unmeasured");
        poseBad=1; Arm(true,75); gf::EnterGate2(Sub()); const U r2=gf::TestGate2(Sub()); poseBad=0;
        Require(r2==0xE88 && W(gf::WUnmeasured)==3,"an unreadable pose counts formed and unmeasured (two move-order members)");
    }
    std::printf("formed%%: metres/pct thresholds, member filters, unmeasured rules\n");
}

static void TestReleases() {
    // Escape: [t+0x80C] <= 140 releases, > 140 does not.
    for(float d:{0.0f,139.9f,140.0f,140.5f,1000.0f}) {
        BuildTactic(0,Members(0,4),1000,false,d); Script(true,false,true,false,false); Arm(true,80); gf::EnterGate3(Sub());
        const U r=gf::TestGate3(Sub());
        Require((d<=140.0f) == (r==0xE88) && ((d<=140.0f) ? W(gf::WPassEscape)==1 : W(gf::WBlocked)==1),"escape distance 140 m is inclusive");
    }
    // Timeout: the clock starts at the enter gate; the exit is released exactly at enter + timeout and the wait is accounted.
    BuildTactic(0,Members(0,4),1000,false,500.0f); Script(true,false,true,false,false); Arm(true,80,25,50);
    gf::EnterGate2(Sub());
    for(U tick=1000;tick<1050;tick+=7) { Put(modelMem,0x58,tick); Require(gf::TestGate2(Sub())==0,"withheld before the timeout"); }
    Require(W(gf::WBlocked)==8 && W(gf::WBlockedEntries)==1 && W(gf::WWaitMax)==49 && W(gf::WHist0)==8,"blocked evaluations, one blocked entry, wait max 49, histogram bin 0");
    Put(modelMem,0x58,1049); Require(gf::TestGate2(Sub())==0,"tick 1049: not yet");
    Put(modelMem,0x58,1050); Require(gf::TestGate2(Sub())==0xE88 && W(gf::WPassTimeout)==1 && W(gf::WWaitSum)==50,"tick 1050: timeout releases, wait accounted");
    // A new state entry restarts the clock (same tactic object, other state).
    Put(modelMem,0x58,1060); gf::EnterGate3(Sub());
    Put(modelMem,0x58,1100); Require(gf::TestGate3(Sub())==0,"re-entry restarts the timeout clock");
    Put(modelMem,0x58,1110); Require(gf::TestGate3(Sub())==0xE88 && W(gf::WPassTimeout)==2,"state 3 times out 50 ticks after its own entry");
    // Exit tested without a seen entry: the clock starts at the first test.
    Arm(true,80,25,10); BuildTactic(1,Members(0,4),2000,false,500.0f);
    Require(gf::TestGate2(Sub(1))==0,"unseen entry blocks first");
    Put(modelMem,0x58,2009); Require(gf::TestGate2(Sub(1))==0,"unseen entry: 9 ticks");
    Put(modelMem,0x58,2010); Require(gf::TestGate2(Sub(1))==0xE88,"unseen entry: timeout counted from the first test");
    std::printf("releases: escape / timeout / re-entry\n");
}

static void TestScopeAndFaults() {
    BuildTactic(0,Members(0,4),1000,false,500.0f); Script(true,false,true,false,false); Arm(true,80);
    inScope=false; const U r=gf::TestGate2(Sub()); inScope=true;
    Require(r==0 && W(gf::WEvals)==1 && (W(gf::WFaults)>>16)==1 && (W(gf::WFaults)&0xFFFF)==0,"a call outside the think scope is still gated and counted in the high half of word 15");
    // A member pointer that faults: the native exit is let through and the fault is counted.
    B* bad=static_cast<B*>(VirtualAlloc(nullptr,4096,MEM_RESERVE,PAGE_NOACCESS)); Require(bad!=nullptr,"reserve a no-access page");
    BuildTactic(0,Members(0,4),1000,false,500.0f); Put(unitArray,0,A(bad)); Arm(true,80);
    const U r2=gf::TestGate2(Sub());
    Require(r2==0xE88 && (W(gf::WFaults)&0xFFFF)==1,"a faulting read releases the native exit and counts a fault");
    VirtualFree(bad,0,MEM_RELEASE);
    // Two tactics are tracked independently.
    Arm(true,80,25,20); BuildTactic(0,Members(0,4),3000,false,500.0f); BuildTactic(1,Members(0,4),3000,false,500.0f);
    gf::EnterGate2(Sub(0)); Put(modelMem,0x58,3010); gf::EnterGate2(Sub(1)); Put(modelMem,0x58,3020);
    Require(gf::TestGate2(Sub(0))==0xE88 && gf::TestGate2(Sub(1))==0,"per-tactic clocks");
    Require(W(gf::WBlockedEntries)==1,"one blocked entry (the second tactic); the first was released by timeout before being blocked");
    // A blocked entry released by the enemy escape or by the engine's waiver is accounted too (wait sum / max), in state 3 counted in the high half of word 7.
    Arm(true,80,25,2400); BuildTactic(0,Members(0,4),4000,false,500.0f); gf::EnterGate3(Sub(0));
    Put(modelMem,0x58,4030); Require(gf::TestGate3(Sub(0))==0,"state 3 blocked");
    Put(tacticMem[0],0x80C,0); PutF(tacticMem[0],0x80C,100.0f); Put(modelMem,0x58,4075);
    Require(gf::TestGate3(Sub(0))==0xE88 && W(gf::WPassEscape)==1 && W(gf::WWaitSum)==75 && W(gf::WWaitMax)==75 && W(gf::WBlockedEntries)==0x10000u,"escape release accounts the wait of a blocked state-3 entry");
    gf::EnterGate3(Sub(0)); Put(modelMem,0x58,4100); PutF(tacticMem[0],0x80C,500.0f); Require(gf::TestGate3(Sub(0))==0,"blocked again after re-entry");
    tacticMem[0][0x81E]=0; Put(modelMem,0x58,4110);
    Require(gf::TestGate3(Sub(0))==0xE88 && W(gf::WPassWaived)==1 && W(gf::WWaitSum)==110 && W(gf::WBlockedEntries)==0x20000u,"waiver release accounts the wait");
    std::printf("scope / faults / per-tactic clocks\n");
}
// Informational cost of one blocked evaluation (native exit TRUE, 16 member units, all with move rows; the natives are host fakes, so the engine's own test cost is excluded).
static void TestCost() {
    std::vector<Member> v; for(U i=0;i<kMaxUnits;++i) v.push_back({100,100,100,200,true,true,1,0,0});
    BuildTactic(0,v,1000,false,500.0f); Script(true,false,true,false,false); Arm(true,80,25,2400); gf::EnterGate2(Sub());
    LARGE_INTEGER f,a,b; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&a);
    constexpr U n=200000; for(U i=0;i<n;++i) Require(gf::TestGate2(Sub())==0,"blocked");
    QueryPerformanceCounter(&b);
    std::printf("cost: %.0f ns per blocked evaluation (16 members, fake natives)\n",1e9*static_cast<double>(b.QuadPart-a.QuadPart)/static_cast<double>(f.QuadPart)/n);
}

int main(int argc,char** argv) {
    if(argc!=2) { std::fprintf(stderr,"usage: native_group_formup_oracle Napoleon.exe\n"); return 2; }
    std::setvbuf(stdout,nullptr,_IONBF,0);
    Map(argv[1]);
    Jump(0x7B5AF0,Fn(&FakeReformExit)); Jump(0x7A5730,Fn(&FakeReformAlt)); Jump(0x7A5A80,Fn(&FakeFormupExit)); Jump(0x7B5640,Fn(&FakeFormupAlt)); Jump(0x7A5C80,Fn(&FakeFormupAlt2));
    Jump(0x7B5910,Fn(&FakeEnter2)); Jump(0x7A5A30,Fn(&FakeEnter3));
    Require(FlushInstructionCache(GetCurrentProcess(),image,imageSize)!=0,"flush image");
    for(U& v:tacticVt) v=Fn(&Ev88);
    tacticVt[0x80/4]=Fn(&Ev80); tacticVt[0x84/4]=Fn(&Ev84); tacticVt[0x88/4]=Fn(&Ev88); tacticVt[0x8C/4]=Fn(&Ev8C);
    moveVt[0x38/4]=Fn(&FakePose); otherVt[0x38/4]=Fn(&FakePose);
    targets={A(At(0x7B5AF0)),A(At(0x7A5730)),A(At(0x7A5A80)),A(At(0x7B5640)),A(At(0x7A5C80)),Fn(&FakePoseToVec),A(moveVt),
             A(At(0x702A80)),A(At(0x702A40)),A(At(0x702B20)),A(At(0x702AE0)),&Scope};
    // The thunks are the original bytes: assert their call structure so a different image cannot pass silently.
    static const B reformHead[]={0x56,0x8b,0x74,0x24,0x08,0x8d,0x46,0x84};
    Require(!std::memcmp(At(0x702A80),reformHead,sizeof(reformHead)) && !std::memcmp(At(0x702B20),reformHead,sizeof(reformHead)),"REFORM / MOVE_TO_FORMUP test thunk prologue");
    TestForwarding(); TestMirror(); TestFormed(); TestReleases(); TestScopeAndFaults(); TestCost();
    std::printf("group formup oracle: %u checks\n",checks);
    return 0;
}

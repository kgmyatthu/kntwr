// Oracle for src/ai/ntw2_march_slots.{h,cpp} (--ai-march-slots).
//  * engine pins (private relocated mapping of the owned image, never executed): the R2 slot 0x1325474 holds 0x581AE0; 0x581AE0 passes its dirty/cooldown flag to `call 0x576B30` at 0x581B38 and
//    refreshes through `0x584E10` every 1.0 s; 0x576B30 latches [C+0x7C], pushes -1 on the first call and [C+0x30] afterwards (ret 4); 0x584E10 ends with ret 4; 0x51A530's constructor
//    reaches `call 0x584E10` / `call 0x576B30` and the 0x8C test the contract names; 0x4B4A50 is `mov eax,[ecx+4]; ret`; 0x5373F0 derives limit = flag ^ 1 and threshold 16.0 / FLT_MAX from the flag byte;
//  * Pre: latched commands are untouched, the first execute of an AI-side unit is accepted, a human side / unknown army is refused (counted), an in-range inaccessible formation is a counted fault;
//  * Post: re-solves with the pacing word forced to 1 BEFORE the solve call, then issues with flag 1 (order solve -> issue), forwards the dirty/cooldown parameter exactly as 0x581AE0 computes it, counts
//    the solver-clone variant, and leaves a vanished / replaced / unlatched command or a faulting native alone (counted).
// The natives are stubs; no running game or installed file is modified.
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
#include <initializer_list>
#include "native_image_relocation.h"
#include "ntw2_runtime.h"
#include "ai/ntw2_march_slots.h"
#include "core/ntw2_guard.h"
#pragma comment(lib,"bcrypt.lib")
using U=uint32_t;
using B=unsigned char;
namespace ms=ntw2_march_slots;
static_assert(sizeof(void*)==4,"owned x86 oracle");
static B* image;
static U delta, checks, imageSize;
static void Require(bool ok,const char* what) { ++checks; if(!ok) { std::fprintf(stderr,"FAIL %s\n",what); std::exit(1); } }
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> static U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static B* At(U va) { return image+(va-0x400000); }
static U Rd(U va) { U v; std::memcpy(&v,At(va),4); return v; }
static void Put(void* p,U offset,U v) { std::memcpy(static_cast<B*>(p)+offset,&v,4); }
static U Get(const void* p,U offset) { U v; std::memcpy(&v,static_cast<const B*>(p)+offset,4); return v; }
static bool Bytes(U va,std::initializer_list<int> bytes) { U i=0; for(int b:bytes) { if(At(va)[i++]!=static_cast<B>(b)) return false; } return true; }
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
    image=static_cast<B*>(VirtualAlloc(nullptr,imageSize,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    Require(image!=nullptr,"private image mapping"); delta=A(image)-0x400000;
    std::memcpy(image,bytes.data(),nt->OptionalHeader.SizeOfHeaders);
    auto sections=IMAGE_FIRST_SECTION(nt);
    for(U i=0;i<nt->FileHeader.NumberOfSections;++i)
        std::memcpy(image+sections[i].VirtualAddress,bytes.data()+sections[i].PointerToRawData,
                    std::min(sections[i].SizeOfRawData,sections[i].Misc.VirtualSize));
}
// rel32 target of the E8 at `site` (preferred-base VAs).
static U CallTarget(U site) { Require(At(site)[0]==0xE8,"call opcode"); const int32_t rel=static_cast<int32_t>(Rd(site+1)); return static_cast<U>(static_cast<int32_t>(site+5)+rel); }

// ---------------------------------------------------------------------------------------------------------------------- engine pins
static void TestPins() {
    Require(Rd(0x1325474)==0x581AE0,"R2 slot holds the MOVE command execute");
    // 0x581AE0: refresh only when (elapsed > [C+0x2C] + 1.0): addss xmm0,[0x1318048] with 1.0f; 0x584E10 reached by call at 0x581B81
    Require(CallTarget(0x581B38)==0x576B30,"0x581AE0 calls 0x576B30");
    Require(CallTarget(0x581B81)==0x584E10,"0x581AE0 calls 0x584E10 (the refresh)");
    { float one; std::memcpy(&one,At(0x1318048),4); Require(one==1.0f,"refresh interval constant is 1.0 s"); }
    Require(Bytes(0x581AF0,{0x80,0x7E,0x3C,0x00}),"[C+0x3C] test before the solve decision");   // cmp byte [esi+3C],0
    Require(Bytes(0x581B16,{0x80,0xB8,0x8C,0x27,0x00,0x00,0x00}),"dirty byte [F+0x278C]");
    Require(Bytes(0x581B1F,{0x83,0xB8,0x88,0x27,0x00,0x00,0x00}),"cooldown dword [F+0x2788]");
    // 0x576B30: cmp byte [esi+7C],0 ; first call mov byte [esi+7C],1 / push -1 ; else push [esi+30] ; ret 4
    Require(Bytes(0x576B42,{0x80,0x7E,0x7C,0x00}),"0x576B30 tests the latch [C+0x7C]");
    Require(Bytes(0x576B4D,{0xC6,0x46,0x7C,0x01}),"0x576B30 sets the latch");
    Require(Bytes(0x576B51,{0x6A,0xFF}),"first call solve flag -1");
    Require(Bytes(0x576B68,{0xFF,0x76,0x30}),"later calls push [C+0x30]");
    Require(Bytes(0x576B9A,{0xC2,0x04,0x00}),"0x576B30 ret 4");
    Require(CallTarget(0x576B7D)==0x57AFC0,"0x576B30 -> 0x57AFC0");
    Require(Bytes(0x585734,{0xC2,0x04,0x00}),"0x584E10 ret 4");
    Require(Bytes(0x584E10,{0x81,0xEC,0xEC,0x00,0x00,0x00}),"0x584E10 prologue");
    Require(Bytes(0x4B4A50,{0x8B,0x41,0x04,0xC3}),"0x4B4A50 = mov eax,[ecx+4]; ret (command -> formation)");
    Require(CallTarget(0x65D7C2)==0x51A530,"0x65D740 calls the constructor 0x51A530");
}

// ---------------------------------------------------------------------------------------------------------------------- fixture
struct Fix {
    B model[0x100], world[0x100], side[2][0x40], armyArr[2][4], formation[0x2800], unit[0x1000], cmd[0x100], queue[4];
    U sideArr[2];
};
static __declspec(align(16)) Fix fx;
static U solveCmd, solveParam, solveSeen30, issueCmd, issueFlag, order, solveCalls, issueCalls, cloneCalls;
static bool solveFault;
static void __fastcall SolveStub(U ecx,U,U a) { solveCmd=ecx; solveParam=a; solveSeen30=Get(fx.cmd,0x30); solveCalls=++order; if(solveFault) *reinterpret_cast<volatile U*>(0x10000)=1; }
static void __fastcall IssueStub(U ecx,U,U a) { issueCmd=ecx; issueFlag=a; issueCalls=++order; }
static void __fastcall CloneStub(U ecx,U,U a) { ++cloneCalls; SolveStub(ecx,0,a); }
static const U kArmyA=0x41000, kArmyB=0x42000, kArmyC=0x43000;   // opaque army identities
static void Build(U army, bool latched, bool aiSide) {
    std::memset(&fx,0,sizeof(fx)); solveCmd=solveParam=solveSeen30=issueCmd=issueFlag=order=solveCalls=issueCalls=cloneCalls=0; solveFault=false;
    Put(fx.model,0xB0,A(fx.world));
    Put(fx.world,0x84,2); Put(fx.world,0x88,A(fx.sideArr));
    fx.sideArr[0]=A(fx.side[0]); fx.sideArr[1]=A(fx.side[1]);
    Put(fx.side[0],0xC,aiSide ? 0xBEEFu : 0u); Put(fx.side[0],0x20,1); Put(fx.side[0],0x24,A(fx.armyArr[0])); Put(fx.armyArr[0],0,kArmyA);
    Put(fx.side[1],0xC,aiSide ? 0u : 0xBEEFu); Put(fx.side[1],0x20,1); Put(fx.side[1],0x24,A(fx.armyArr[1])); Put(fx.armyArr[1],0,kArmyB);
    Put(fx.unit,0x1EC,army); Put(fx.formation,0x510,A(fx.unit)); Put(fx.formation,0x18,502);
    Put(fx.cmd,4,A(fx.formation)); Put(fx.cmd,0,0x1325470u); fx.cmd[0x7C]=latched ? 1 : 0; Put(fx.cmd,0x30,9);
    Put(fx.formation,0x460,1); Put(fx.formation,0x420,A(fx.cmd));
}
static U W(ms::Word w) { return ms::words[w]; }
static void Arm() { ms::Configure(ms::Targets{0,Fn(&SolveStub),Fn(&IssueStub)}); }
static void ExpectWords(const U (&e)[ms::kWords],const char* what) {
    for(U i=0;i<ms::kWords;++i) if(W(static_cast<ms::Word>(i))!=e[i]) { std::fprintf(stderr,"%s: word %u = %u, expected %u\n",what,i,W(static_cast<ms::Word>(i)),e[i]); Require(false,what); }
}

static void TestPre() {
    Arm();
    // AI unit, first execute: accepted (army A is on the AI side 0)
    Build(kArmyA,false,true); Require(ms::Pre(A(fx.cmd),A(fx.model)),"AI first execute accepted");
    { U e[ms::kWords]={1,1,0,1,0,0,0,0,0,0,0,0,0,0,0,0}; ExpectWords(e,"pre ai fresh"); }
    // latched command: refused without a count beyond calls/latched
    Build(kArmyA,true,true); Require(!ms::Pre(A(fx.cmd),A(fx.model)),"latched refused");
    { U e[ms::kWords]={2,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0}; ExpectWords(e,"pre latched"); }
    // human side: first execute counted as player_fresh, not accepted
    Build(kArmyB,false,true); Require(!ms::Pre(A(fx.cmd),A(fx.model)),"human army refused");
    { U e[ms::kWords]={3,2,1,1,1,0,0,0,0,0,0,0,0,0,0,0}; ExpectWords(e,"pre player"); }
    // unknown army: unmeasured
    Build(kArmyC,false,true); Require(!ms::Pre(A(fx.cmd),A(fx.model)),"unknown army refused");
    { U e[ms::kWords]={4,3,1,1,1,1,0,0,0,0,0,0,0,0,0,0}; ExpectWords(e,"pre unmeasured"); }
    // unit pointer below the sane range: unmeasured
    Build(kArmyA,false,true); Put(fx.formation,0x510,0x8); Require(!ms::Pre(A(fx.cmd),A(fx.model)),"insane unit refused");
    { U e[ms::kWords]={5,4,1,1,1,2,0,0,0,0,0,0,0,0,0,0}; ExpectWords(e,"pre insane unit"); }
    // in-range but inaccessible formation pointer: counted fault
    Build(kArmyA,false,true); Put(fx.cmd,4,0x20000); Require(!ms::Pre(A(fx.cmd),A(fx.model)),"faulting formation refused");
    { U e[ms::kWords]={6,4,1,1,1,2,0,0,0,0,0,0,0,0,0,1}; ExpectWords(e,"pre fault"); }
    // a model with no battle world: unmeasured
    Build(kArmyA,false,true); Put(fx.model,0xB0,0); Require(!ms::Pre(A(fx.cmd),A(fx.model)),"no world refused");
    Require(W(ms::WUnmeasured)==3,"no world counted unmeasured");
}

static void TestPost() {
    Arm();
    // normal: dirty && cooldown 0 -> parameter 1; pacing forced to 1 before the solve; issue after solve with flag 1
    Build(kArmyA,true,true); fx.formation[0x278C]=1; Put(fx.formation,0x2788,0);
    ms::Post(A(fx.cmd),0,false);
    Require(solveCmd==A(fx.cmd) && issueCmd==A(fx.cmd),"native calls target the command");
    Require(solveParam==1,"dirty && cooldown 0 -> parameter 1");
    Require(solveSeen30==1,"pacing word is 1 at the solve call (uncapped flag byte)");
    Require(issueFlag==1,"order issue flag 1 (every man)");
    Require(solveCalls==1 && issueCalls==2,"solve precedes issue");
    Require(W(ms::WResolved)==1 && W(ms::WMenSum)==502 && W(ms::WMaxMen)==502 && W(ms::WSolverClone)==0 && W(ms::WGone)==0,"post words");
    // not dirty -> parameter 0; cooldown nonzero -> parameter 0
    Build(kArmyA,true,true); fx.formation[0x278C]=1; Put(fx.formation,0x2788,5); ms::Post(A(fx.cmd),0,false); Require(solveParam==0,"cooldown -> parameter 0");
    Build(kArmyA,true,true); ms::Post(A(fx.cmd),0,false); Require(solveParam==0,"clean -> parameter 0");
    // solver clone variant: the supplied solve address runs and is counted
    Build(kArmyA,true,true); ms::Post(A(fx.cmd),Fn(&CloneStub),true);
    Require(cloneCalls==1 && solveCalls==1 && W(ms::WSolverClone)==1,"clone solve variant counted");
    const U resolved=W(ms::WResolved);
    // vanished: not the queued command
    Build(kArmyA,true,true); Put(fx.formation,0x420,0x1234); ms::Post(A(fx.cmd),0,false);
    Require(!solveCalls && !issueCalls && W(ms::WGone)==1 && W(ms::WResolved)==resolved,"replaced command left alone");
    // wrong vtable
    Build(kArmyA,true,true); Put(fx.cmd,0,0x1325428u); ms::Post(A(fx.cmd),0,false); Require(!solveCalls && W(ms::WGone)==2,"other command class left alone");
    // latch not set (execute did not run): left alone
    Build(kArmyA,false,true); ms::Post(A(fx.cmd),0,false); Require(!solveCalls && W(ms::WGone)==3,"unlatched command left alone");
    // empty queue / zero men
    Build(kArmyA,true,true); Put(fx.formation,0x460,0); ms::Post(A(fx.cmd),0,false); Require(!solveCalls && W(ms::WGone)==4,"empty queue left alone");
    Build(kArmyA,true,true); Put(fx.formation,0x18,0); ms::Post(A(fx.cmd),0,false); Require(!solveCalls && W(ms::WGone)==5,"zero men left alone");
    // a faulting native is counted, nothing further runs
    Build(kArmyA,true,true); solveFault=true; ms::Post(A(fx.cmd),0,false);
    Require(solveCalls==1 && !issueCalls && W(ms::WFaults)==1,"faulting solve counted, no issue");
    // unconfigured module does nothing
    ms::ResetRow(); ms::Configure(ms::Targets{0,0,0});
    Build(kArmyA,false,true); Require(!ms::Pre(A(fx.cmd),A(fx.model)),"unconfigured Pre refuses"); ms::Post(A(fx.cmd),0,false);
    Require(!solveCalls && W(ms::WCalls)==0,"unconfigured module is inert");
    // Snapshot copies the row
    Arm(); Build(kArmyA,true,true); ms::Post(A(fx.cmd),0,false);
    volatile U out[ms::kWords]; ms::Snapshot(out); Require(out[ms::WResolved]==1,"snapshot row");
}

int main(int argc,char** argv) {
    if(argc<2) { std::fprintf(stderr,"usage: native_march_slots_oracle <Napoleon_patched.exe>\n"); return 2; }
    Map(argv[1]);
    TestPins();
    TestPre();
    TestPost();
    std::printf("native_march_slots_oracle: %u checks passed\n",checks);
    return 0;
}

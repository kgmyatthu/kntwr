// Oracle for src/brain/ntw2_target_cull.{h,cpp} (--brain-target-cull[-shadow]) on a private relocated mapping of the owned image.
//  * Loop: the reordered mirror of 0x553590 against the ORIGINAL 0x553590 bytes on random synthetic units: same candidate pointer, same
//    *outScore bits, scratch count 0, identical static-guard call sequence; maxDist in {FLT_MAX, 100, 15, 3, 0, NaN}, flag on/off (the real
//    0x659480 cached branch), empty units / men with no candidates, duplicated candidates (first-index tie-break), equal scores, huge u32
//    c+0x474 counts (float(u32) / cvttss2si overflow), NaN positions, alive/reach results other than 0/1 (native tests AL == 1), a scratch data
//    pointer that changes on every push (re-read each iteration);
//  * Search: the mirror of 0x553420 (live and shadow) against the ORIGINAL 0x553420 bytes: same result for random contact lists (kinds 0..4,
//    entries whose id equals the target's), flag derived through 0x659480 -> vt+0x20 -> 0x6ABC80 -> +0x231 / +0xBC, empty lists; shadow publishes
//    0 mismatches and answers natively; off forwards;
//  * culling: the mirror never evaluates a predicate natively skipped candidates did not need; predicate calls are <= native and are counted.
// Image-internal callees 0x53E410, 0x5359E0, 0x659480 and 0x553590/0x553420 are original bytes.  The predicates 0x679750/0x679700, the id getters,
// the man vt+0xB4 push, 0x6ABC80 and the init-thread helpers are scripted host fakes (their purity is the proof in ntw2_target_cull.h).
// No running game or installed file is modified.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <intrin.h>
#include <bcrypt.h>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <vector>
#include "native_image_relocation.h"
#include "ntw2_runtime.h"
#include "brain/ntw2_target_cull.h"
#pragma comment(lib,"bcrypt.lib")
using U=uint32_t;
using B=unsigned char;
namespace tc=ntw2_target_cull;
static_assert(sizeof(void*)==4,"owned x86 oracle");
extern "C" unsigned long _tls_index;
static __declspec(thread) U tlsPad[16];
static B* image;
static U delta, checks, imageSize;
static void Require(bool ok,const char* what) { ++checks; if(!ok) { std::fprintf(stderr,"FAIL %s\n",what); std::exit(1); } }
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static B* At(U va) { return reinterpret_cast<B*>(va+delta); }
template<class T> static U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static void Put(void* p,U offset,U v) { std::memcpy(static_cast<B*>(p)+offset,&v,4); }
static U Get(const void* p,U offset) { U v; std::memcpy(&v,static_cast<const B*>(p)+offset,4); return v; }
static void PutF(void* p,U offset,float v) { std::memcpy(static_cast<B*>(p)+offset,&v,4); }
static U Bits(float f) { U v; std::memcpy(&v,&f,4); return v; }
static float FromBits(U v) { float f; std::memcpy(&f,&v,4); return f; }
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
constexpr U kPool=48, kMen=6, kUnits=6, kPush=8;
static __declspec(align(16)) B cand[kPool+1][0x520];       // [kPool] = the agent
static __declspec(align(16)) B man[kUnits][kMen][0x80];
static __declspec(align(16)) B unitMem[kUnits][0x300];
static U manPtr[kUnits][kMen];
static B listEntries[kUnits*16];
static B listHeader[0x20];
static U manVtable[64], idVtable[4], ownerVtable[16];
static B ownerMem[0x80], settingsMem[0x300], flagBlob[0x100], ownerBlock[0x40];
static U scratchBufA[64], scratchBufB[64];
static U pushSwap;                                          // alternate the scratch data pointer on every push
static U pushCount;
static U aliveCalls, reachCalls, guardSeq[16], guardN, guardMode, headerCalls;
static std::vector<U> aliveLog;
static U Cn(U i) { return A(cand[i]); }

// 0x679750 / 0x679700: pure scripted results (the native test is AL == 1, so values 2 / 0xFF are "false").
static B __fastcall FakeAlive(U c,U) { ++aliveCalls; aliveLog.push_back(c); return static_cast<B>(Get(reinterpret_cast<void*>(c),0x440)); }
static B __fastcall FakeReach(U c,U,U agent) { ++reachCalls; (void)agent; return static_cast<B>(Get(reinterpret_cast<void*>(c),0x444)); }
// man->vt+0xB4(&scratch): append the man's candidates; optionally move the data pointer to the other buffer (the loop re-reads it every iteration).
static U __fastcall FakePush(U self,U,U list) {
    ++pushCount;
    B* l=reinterpret_cast<B*>(list);
    U* data=pushSwap && (pushCount&1) ? scratchBufB : scratchBufA;
    Put(l,8,64); Put(l,0x10,A(data));
    U n=Get(reinterpret_cast<void*>(self),0x20), count=Get(l,0xC);
    for(U i=0;i<n;++i) data[count++]=Get(reinterpret_cast<void*>(self),0x24+4*i);
    Put(l,0xC,count);
    return 0;
}
static U __fastcall FakeId(U self,U) { return Get(reinterpret_cast<void*>(self),4); }          // object = unit+0x10: id at unit+0x14
static U __fastcall FakeOwnerVt20(U,U) { return A(ownerBlock); }                               // vt+0x20 of the 0x659480 owner
static U __fastcall FakeSettings(U,U) { return A(settingsMem); }                               // 0x6ABC80
static U __cdecl FakeHeader(U guard) { ++headerCalls; guardSeq[guardN++&15]=1; if(guardMode==1 && headerCalls==1) Put(reinterpret_cast<void*>(guard),0,0xFFFFFFFFu); return 0; }
static U __cdecl FakeAtexit(U fn) { guardSeq[guardN++&15]=2000+fn; return 0; }
static U __cdecl FakeFooter(U guard) { guardSeq[guardN++&15]=3; Put(reinterpret_cast<void*>(guard),0,0x80000000u); return 0; }

static int gPhase,gWho; static U gCase;
static U rng=0x9E3779B9u;
static U Rand() { rng^=rng<<13; rng^=rng>>17; rng^=rng<<5; return rng; }
static U Below(U n) { return n ? Rand()%n : 0; }
static bool Chance(U percent) { return Rand()%100<percent; }

static void SetupImage() {
    Jump(tc::kAlive,Fn(&FakeAlive)); Jump(tc::kReach,Fn(&FakeReach)); Jump(tc::kSettings,Fn(&FakeSettings));
    Jump(tc::kInitHeader,Fn(&FakeHeader)); Jump(tc::kAtexit,Fn(&FakeAtexit)); Jump(tc::kInitFooter,Fn(&FakeFooter));
    Put(At(tc::kTlsIndex),0,static_cast<U>(_tls_index));
    for(U i=0;i<64;++i) manVtable[i]=0;
    manVtable[0xB4/4]=Fn(&FakePush); idVtable[0]=Fn(&FakeId); ownerVtable[0x20/4]=Fn(&FakeOwnerVt20);
    tlsPad[0]=1;
}
static U TlsEpoch() { return Get(reinterpret_cast<void*>(Get(reinterpret_cast<void*>(__readfsdword(0x2C)),4*static_cast<U>(_tls_index))),8); }
static void SetGuard(U mode) { // 0: guard never above the TLS epoch; 1: slow path, this call initialises; 2: slow path, someone else did
    guardMode=mode; headerCalls=0; guardN=0; std::memset(guardSeq,0,sizeof(guardSeq));
    Put(At(tc::kGuard),0,mode==0 ? 0x80000000u : 0x7FFFFFFFu);
}
static void ResetScratch() { B* l=At(tc::kScratch); Put(l,8,64); Put(l,0xC,0); Put(l,0x10,A(scratchBufA)); }

static void InitCand(U i) {
    std::memset(cand[i],0,sizeof(cand[i]));
    Put(cand[i],0xB4,1);                                   // 0x659480 cached branch: byte +0xB4 == 1
    Put(cand[i],0x44,Below(4));
}
static void Place(U i,bool nanPos) {
    static const float grid[]={-120.f,-100.f,-15.f,-3.f,-1.f,0.f,1.f,2.f,3.f,15.f,16.f,99.f,100.f,101.f};
    for(U a=0;a<3;++a) PutF(cand[i],0x48+4*a,Chance(60) ? grid[Below(sizeof(grid)/sizeof(grid[0]))] : static_cast<float>(static_cast<int>(Below(41))-20)*0.5f);
    if(nanPos && Chance(50)) PutF(cand[i],0x48+4*Below(3),std::numeric_limits<float>::quiet_NaN());
}
static void BuildPool(bool wild) {
    for(U i=0;i<kPool;++i) {
        InitCand(i); Place(i,wild);
        static const U counts[]={0,1,2,3,5,0x7FFFFFFFu,0x80000000u,0xF0000000u,0xFFFFFFFFu};
        Put(cand[i],0x474,Chance(85) ? Below(4) : counts[Below(sizeof(counts)/sizeof(counts[0]))]);
        Put(cand[i],0x440,Chance(75) ? 1 : (Chance(50) ? 0 : (Chance(50) ? 2 : 0xFF)));
        Put(cand[i],0x444,Chance(75) ? 1 : (Chance(50) ? 0 : 2));
        Put(cand[i],0x504,Chance(70) ? Cn(i) : 0);                  // 0x659480(c).+0xC
        if(i>2 && Chance(25)) { // duplicates: same position / count / scripts -> equal scores
            const U j=Below(i); for(U off : {0x48u,0x4Cu,0x50u,0x474u,0x440u,0x444u,0x504u}) Put(cand[i],off,Get(cand[j],off));
        }
    }
    InitCand(kPool); for(U a=0;a<3;++a) PutF(cand[kPool],0x48+4*a,static_cast<float>(static_cast<int>(Below(9))-4));
    Put(cand[kPool],0xB4,1); Put(cand[kPool],0x44,Below(4));
    Put(cand[kPool],0x504,A(ownerMem));                         // the agent's 0x659480 owner
}
static void BuildUnit(U u,U id,U men,U maxPush) {
    std::memset(unitMem[u],0,sizeof(unitMem[u]));
    Put(unitMem[u],0x10,A(idVtable)); Put(unitMem[u],0x14,id);
    Put(unitMem[u],0x2CC,men); Put(unitMem[u],0x2D0,A(manPtr[u]));
    for(U m=0;m<men;++m) {
        std::memset(man[u][m],0,sizeof(man[u][m])); manPtr[u][m]=A(man[u][m]);
        const U n=Below(maxPush+1); Put(man[u][m],0x20,n); Put(man[u][m],0,A(manVtable));
        for(U k=0;k<n;++k) Put(man[u][m],0x24+4*k,Cn(Below(kPool)));
        // the man object's vtable pointer is +0 (vt+0xB4 is read through [man])
    }
}
static void ResetCounters() { aliveCalls=reachCalls=0; aliveLog.clear(); pushCount=0; }

// ---------------------------------------------------------------------------------------------------------------------- Loop
using NativeLoop=U(__stdcall*)(U,U,float,float*,U);
static U totalNativeAlive, totalMirrorAlive, totalCandidates, totalCalls;
static void LoopCase(U unitMenMax,U maxPushMax,float maxDist,bool flag,U guard,bool swap) {
    BuildPool(Chance(15));
    BuildUnit(0,7,Below(unitMenMax+1),maxPushMax);
    pushSwap=swap;
    float nativeScore=FromBits(0x7F7FFFFFu), mirrorScore=FromBits(0x7F7FFFFFu);
    const U flagWord=(flag ? 1u : 0u) | (Chance(50) ? 0xABCDEF00u : 0u);
    U nativeResult,mirrorResult,nativeAlive,nativeReach,mirrorAlive,mirrorReach,nativeGuardN,mirrorGuardN,nativeSeq[16],mirrorSeq[16];
    ResetScratch(); SetGuard(guard); ResetCounters();
    gWho=1; nativeResult=reinterpret_cast<NativeLoop>(At(tc::kLoop))(Cn(kPool),A(unitMem[0]),maxDist,&nativeScore,flagWord);
    nativeAlive=aliveCalls; nativeReach=reachCalls; nativeGuardN=guardN; std::memcpy(nativeSeq,guardSeq,sizeof(nativeSeq));
    const U nativePush=pushCount;
    Require(Get(At(tc::kScratch),0xC)==0,"native leaves the scratch list empty");
    ResetScratch(); SetGuard(guard); ResetCounters();
    gWho=2; mirrorResult=tc::Loop(Cn(kPool),A(unitMem[0]),maxDist,&mirrorScore,flagWord);
    mirrorAlive=aliveCalls; mirrorReach=reachCalls; mirrorGuardN=guardN; std::memcpy(mirrorSeq,guardSeq,sizeof(mirrorSeq));
    Require(nativeResult==mirrorResult,"loop result pointer");
    Require(Bits(nativeScore)==Bits(mirrorScore),"loop score bits");
    Require(Get(At(tc::kScratch),0xC)==0,"mirror leaves the scratch list empty");
    Require(pushCount==nativePush,"same vt+0xB4 push count");
    Require(nativeGuardN==mirrorGuardN && !std::memcmp(nativeSeq,mirrorSeq,sizeof(nativeSeq)),"same static-guard call sequence");
    Require(mirrorAlive<=nativeAlive && mirrorReach<=nativeReach,"mirror evaluates no more predicates than native");
    totalNativeAlive+=nativeAlive; totalMirrorAlive+=mirrorAlive; ++totalCalls;
}

// ---------------------------------------------------------------------------------------------------------------------- Search
using NativeSearch=U(__fastcall*)(U,U,U,U);
static tc::Targets targets;
static U W(tc::Word w) { return tc::words[w]; }
static B bigMan[540][0x80]; static U bigPtr[540];
static void SearchCase(tc::Mode mode,bool big=false) {
    BuildPool(Chance(10));
    const U targetId=1+Below(3);
    BuildUnit(0,targetId,Below(kMen+1),kPush);
    if(big) { // more candidates than the per-search cache holds: the entries fall back to the per-entry loop
        const U n=520+Below(16);
        for(U m=0;m<n;++m) {
            std::memset(bigMan[m],0,sizeof(bigMan[m])); Put(bigMan[m],0,A(manVtable)); Put(bigMan[m],0x20,8);
            for(U k=0;k<8;++k) Put(bigMan[m],0x24+4*k,Cn(Below(kPool)));
            bigPtr[m]=A(bigMan[m]);
        }
        Put(unitMem[0],0x2CC,n); Put(unitMem[0],0x2D0,A(bigPtr));
    }
    const U entries=Below(kUnits);
    std::memset(listEntries,0,sizeof(listEntries));
    for(U e=0;e<entries;++e) {
        const U u=1+e%(kUnits-1);
        BuildUnit(u,Chance(35) ? targetId : 1+Below(3),Below(3),3);
        Put(listEntries,16*e,A(unitMem[u])); Put(listEntries,16*e+4,Below(6)); Put(listEntries,16*e+8,Below(50)); listEntries[16*e+12]=Chance(50);
    }
    std::memset(listHeader,0,sizeof(listHeader)); Put(listHeader,0xC,entries); Put(listHeader,0x10,A(listEntries));
    // flag chain: agent+0x504 = owner; owner vt+0x20 != 0 -> 0x6ABC80 settings +0x231, owner+0x40 -> +0xBC
    std::memset(ownerMem,0,sizeof(ownerMem)); std::memset(settingsMem,0,sizeof(settingsMem)); std::memset(flagBlob,0,sizeof(flagBlob));
    Put(ownerMem,0,A(ownerVtable)); Put(ownerMem,0x40,A(flagBlob));
    settingsMem[0x231]=Chance(50) ? 1 : 0; flagBlob[0xBC]=Chance(50) ? 1 : 0;
    if(Chance(10)) Put(cand[kPool],0x504,0);
    pushSwap=Chance(50); const U guard=Chance(80) ? 0 : 1+Below(2);
    ResetScratch(); SetGuard(guard); ResetCounters();
    const U nativeResult=reinterpret_cast<NativeSearch>(At(tc::kSearch))(A(listHeader),0,Cn(kPool),A(unitMem[0]));
    const U nativeAlive=aliveCalls; Require(Get(At(tc::kScratch),0xC)==0,"native search leaves the scratch list empty");
    ResetScratch(); SetGuard(guard); ResetCounters(); tc::Configure(mode,targets); tc::ResetRow();
    const U r=tc::Search(A(listHeader),0,Cn(kPool),A(unitMem[0]));
    Require(r==nativeResult,"search result");
    if(mode==tc::ModeShadow) {
        Require(((W(tc::WPacked))&0x00FFFFFFu)==0,"shadow publishes no mismatch");
        Require(W(tc::WCalls)<=kUnits,"shadow compares one loop per eligible entry");
    } else Require(aliveCalls<=nativeAlive,"live search evaluates no more predicates than native");
    totalCandidates+=W(tc::WCandidates);
}

static LONG WINAPI CrashReport(EXCEPTION_POINTERS* e) {
    std::fprintf(stderr,"who=%d ecx=%08lx edx=%08lx eax=%08lx esi=%08lx edi=%08lx\n",gWho,e->ContextRecord->Ecx,e->ContextRecord->Edx,e->ContextRecord->Eax,e->ContextRecord->Esi,e->ContextRecord->Edi);
    std::fprintf(stderr,"CRASH %08lx eip=%p (image rva %#llx) addr=%p phase=%d case=%u\n",e->ExceptionRecord->ExceptionCode,e->ExceptionRecord->ExceptionAddress,
                 static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(e->ExceptionRecord->ExceptionAddress))-static_cast<unsigned long long>(A(image)),
                 e->ExceptionRecord->NumberParameters>1 ? reinterpret_cast<void*>(e->ExceptionRecord->ExceptionInformation[1]) : nullptr,gPhase,gCase);
    return EXCEPTION_EXECUTE_HANDLER;
}
int main(int argc,char** argv) {
    SetUnhandledExceptionFilter(CrashReport);
    if(argc<2) { std::fprintf(stderr,"usage: native_target_cull_oracle <Napoleon.exe>\n"); return 2; }
    Map(argv[1]); SetupImage();
    Require(TlsEpoch()!=0x7FFFFFFFu,"tls epoch distinguishes the guard modes");
    // image constants the mirror reads
    Require(Get(At(tc::kMaxFloat),0)==0x7F7FFFFFu,"0x1325DB4 is FLT_MAX");
    { double t[2]; std::memcpy(t,At(tc::kU32Table),16); Require(t[0]==0.0 && t[1]==4294967296.0,"0x1318130 unsigned correction table"); }
    targets={};
    targets.search=A(At(tc::kSearch)); targets.loop=A(At(tc::kLoop)); targets.flagState=A(At(tc::kFlagState)); targets.alive=A(At(tc::kAlive));
    targets.reach=A(At(tc::kReach)); targets.score=A(At(tc::kScore)); targets.kindDist=A(At(tc::kKindDist)); targets.settings=A(At(tc::kSettings));
    targets.scratch=A(At(tc::kScratch)); targets.guard=A(At(tc::kGuard)); targets.tlsIndex=A(At(tc::kTlsIndex));
    targets.initHeader=A(At(tc::kInitHeader)); targets.atexitFn=A(At(tc::kAtexit)); targets.atexitArg=0x12E43E0u+delta;
    targets.initFooter=A(At(tc::kInitFooter)); targets.u32Table=A(At(tc::kU32Table)); targets.maxFloat=A(At(tc::kMaxFloat));
    tc::Configure(tc::ModeLive,targets);
    const float nan=std::numeric_limits<float>::quiet_NaN(), fmax=std::numeric_limits<float>::max();
    const float dists[]={fmax,100.f,15.f,3.f,0.f,nan,1.5f,50.f};
    constexpr U kLoopCases=60000;
    gPhase=1;
    for(U i=0;i<kLoopCases;++i) { gCase=i; LoopCase(i%3?kMen:2,i%5?kPush:2,dists[Below(8)],Chance(25),Chance(85)?0:1+Below(2),Chance(50)); }
    std::printf("loop: %u cases, native predicate calls %u, mirror %u (%.1f%% culled)\n",totalCalls,totalNativeAlive,totalMirrorAlive,
                totalNativeAlive ? 100.0*(1.0-static_cast<double>(totalMirrorAlive)/totalNativeAlive) : 0.0);
    Require(totalMirrorAlive<totalNativeAlive,"the reorder culls predicate calls");
    constexpr U kSearchCases=30000;
    gPhase=2;
    for(U i=0;i<kSearchCases;++i) { gCase=i; SearchCase(i&1 ? tc::ModeLive : tc::ModeShadow); }
    for(U i=0;i<400;++i) { gCase=i; SearchCase(i&1 ? tc::ModeLive : tc::ModeShadow,true); }
    // mode off forwards to the original and publishes nothing new
    tc::Configure(tc::ModeOff,targets); tc::ResetRow(); BuildPool(false); BuildUnit(0,1,3,3); std::memset(listHeader,0,sizeof(listHeader));
    ResetScratch(); SetGuard(0);
    Require(tc::Search(A(listHeader),0,Cn(kPool),A(unitMem[0]))==0 && W(tc::WCalls)==0,"off forwards (empty list)");
    std::printf("oracle ok: %u checks, %u candidates in search cases\n",checks,totalCandidates);
    return 0;
}

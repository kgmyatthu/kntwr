// Oracle for src/ntw2_spiral.{h,cpp} (--ai-spiral-census / --ai-spiral-cap-m) on a private relocated mapping of the owned image:
//  * clone wiring: the four PS_* call groups reach the host forwarders, PS_7FCA40 still calls PS_7FCA90;
//  * spiral: the forwarder path (PS_7FCA40 -> PS_7FCA90 -> SpiralProbe) equals native 0x7FCA40 byte for byte with N = 0 (candidate
//    sequence, out record, return, x87/MXCSR), and with a cap N equals native 0x7FCA40 handed spec+0x24 = (float)N; not-found exactly
//    when the uncapped spot lies beyond radius N; the caller's spec is never written; non-sentinel maxR values are forwarded untouched;
//    candidate/ring/radius/exit counters equal an independent float model of the ring sequence;
//  * ladder: the PS_6C71D0 clone through Ladder/LadderProbe/Spiral equals native 0x6C71D0 (out, placed boxes, probe sequence) and the
//    stage (spot/clamp/ring/spiral/none) is classified; the capped no-spot path returns normally and places the ORIGINAL point;
//  * fallback: native 0x7524A0 through FallbackGate/ControllerGate counts E, the E histogram, tail/same-tick/memo and off-thread calls.
// Only image-internal callees with world dependencies are replaced by scripted host fakes (0x808040 gates, 0x7FCFF0 projection,
// 0x7F6ED0 connectivity, 0x6DA460 deployment clamp, 0x6CC730 footprint test, 0x74F400 detach, 0x84B1D0 post-loop); the spiral
// (0x7FCA40/0x7FCA90), its clamp 0x80B940 and init 0x7EAD50, the ladder 0x6C71D0, 0x6E6CC0, 0x80E9D0, 0x531E30, 0x6B3C00 and the
// fallback loop 0x7524A0/0x74F430/0x55AB90 are original bytes. No running game or installed file is modified.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>
#include <xmmintrin.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "native_image_relocation.h"
#include "clones/ntw2_clones.h"
#include "ntw2_runtime.h"
#include "ai/ntw2_spiral.h"
#pragma comment(lib,"bcrypt.lib")
#pragma fenv_access(on)
using U=uint32_t;
using B=unsigned char;
namespace sp=ntw2_spiral;
static_assert(sizeof(void*)==4,"owned x86 oracle");
extern "C" unsigned long _tls_index;
__declspec(thread) static volatile U tlsPad[32];
static B* image;
static U delta, checks;
static void Require(bool ok,const char* what) { ++checks; if(!ok) { std::fprintf(stderr,"FAIL %s\n",what); std::exit(1); } }
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static B* At(U va) { return reinterpret_cast<B*>(va+delta); }
template<class T> static U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static void Put(void* p,U offset,U v) { std::memcpy(static_cast<B*>(p)+offset,&v,4); }
static U Get(const void* p,U offset) { U v; std::memcpy(&v,static_cast<const B*>(p)+offset,4); return v; }
static U Bits(float f) { U u; std::memcpy(&u,&f,4); return u; }
static float F(U u) { float f; std::memcpy(&f,&u,4); return f; }
static void Jump(U va,U target) { B* p=At(va); p[0]=0xb8; Put(p,1,target); p[5]=0xff; p[6]=0xe0; }
static void* __cdecl Allocate(size_t bytes,void*) { void* p=std::malloc(bytes ? bytes : 1); Require(p!=nullptr,"private heap allocation"); return p; }
static void __cdecl Release(void* p) { std::free(p); }
static U imageSize;
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
    Jump(0xff7f20,Fn(&Allocate)); Jump(0xff7ef0,Fn(&Release));
    Put(At(0x1841bb8),0,_tls_index); tlsPad[0]=0;
    // Static-init guards of 0x7FCA90 / 0x808040 / 0x6C71D0 published as initialized (data only; the search objects stay zero).
    for(U guard:{0x15afda4u,0x15afca4u,0x150b6f4u}) Put(At(guard),0,0x80000000u);
}
static bool CloneCall(U clone,U offset,U& target) {
    const B* p=reinterpret_cast<const B*>(static_cast<uintptr_t>(clone+offset)); int32_t rel; std::memcpy(&rel,p+1,4);
    target=clone+offset+5+static_cast<U>(rel); return p[0]==0xE8;
}
struct __declspec(align(16)) Fx { B bytes[512]; };
static void ResetFp() { __asm { fninit } _mm_setcsr(0x1f80); }
static bool SameFp(const Fx& a,const Fx& b) { return !std::memcmp(a.bytes,b.bytes,6) && !std::memcmp(a.bytes+24,b.bytes+24,4); }

// ------------------------------------------------------------------------------------------------------------------- world
static __declspec(align(16)) B model[0x200], flagsObj[0x3000], holder[0x20], po[0x20];
static void Rects(float outer,float inner,bool innerRule) {
    std::memset(model,0,sizeof(model));
    Put(model,0x74,Bits(-outer)); Put(model,0x78,Bits(-outer)); Put(model,0x7c,Bits(outer)); Put(model,0x80,Bits(outer));
    Put(model,0x84,Bits(-inner)); Put(model,0x88,Bits(-inner)); Put(model,0x8c,Bits(inner)); Put(model,0x90,Bits(inner));
    std::memset(flagsObj,0,sizeof(flagsObj)); flagsObj[0x2db0]=innerRule ? 0 : 1; // 0x7FCAFB: flag62 = spec+0x30==1 && !byte
    Put(model,0xb0,A(flagsObj)); Put(model,0xb4,A(po));
    Put(holder,8,A(model)); Put(po,0,A(holder));
}
static bool InRect(float x,float z,U base) {
    return x>=F(Get(model,base)) && z>=F(Get(model,base+4)) && F(Get(model,base+8))>x && F(Get(model,base+12))>z;
}
// Scripted 0x808040 (thiscall: D, point, kind, &inOuter, &inInner; ret 0x14): the first admissible candidate with index >= foundAt
// succeeds; admissible = inside the outer rectangle and, for kind 1, inside the inner one (§3.5 gates 1-2).
struct Candidate { U x,z,kind; };
static std::vector<Candidate> trace;
static U foundAt;
static U __fastcall Fake808040(U,U,U,U point,U kind,U inOuter,U inInner) {
    const float x=F(Get(reinterpret_cast<void*>(point),0)), z=F(Get(reinterpret_cast<void*>(point),4));
    const bool outer=InRect(x,z,0x74), inner=InRect(x,z,0x84);
    *reinterpret_cast<B*>(inOuter)=outer; *reinterpret_cast<B*>(inInner)=inner;
    trace.push_back({Get(reinterpret_cast<void*>(point),0),Get(reinterpret_cast<void*>(point),4),kind&0xff});
    return (trace.size()-1>=foundAt && outer && (!(kind&0xff) || inner)) ? 1u : 0u;
}
// Scripted 0x7FCFF0 projection (thiscall: out, point, 0, mode, 0; ret 0x14).
static U __fastcall Fake7FCFF0(U,U,U out,U point,U,U mode,U) {
    U* o=reinterpret_cast<U*>(out); o[0]=Get(reinterpret_cast<void*>(point),0); o[1]=Bits(1.0f); o[2]=Get(reinterpret_cast<void*>(point),4); o[3]=mode; o[4]=0;
    return out;
}
static U rejectConnect;  // number of leading 0x7F6ED0 calls answering false
static U __fastcall Fake7F6ED0(U,U,U,U,U,U) { if(rejectConnect) { --rejectConnect; return 0; } return 1; }
static U clampCalls;
static U __fastcall Fake6DA460(U,U,U) { ++clampCalls; return 0; }
static std::vector<U> probeTrue; static U probeCalls;
static U __fastcall FakeProbe(U,U,U) { const U i=probeCalls++; return std::find(probeTrue.begin(),probeTrue.end(),i)!=probeTrue.end() ? 1u : 0u; }
static U __fastcall Fake74F400(U,U,U) { return 0; }
static U __fastcall Fake84B1D0(U,U,U) { return 0; }
static bool inScope=true;
static bool Scope(U) { return inScope; }

using Spiral3=U(__fastcall*)(U,U,U,U,U);
using Ladder5=U(__fastcall*)(U,U,U,U,U,U,U);
static ntw2_clone_set clones;
static sp::Targets targets;
static void Configure(U cap) { sp::Configure(true,cap,targets); }

// --------------------------------------------------------------------------------------------------------- ring model
// 0x7FCBB0..0x7FCDF6 in float: r <= 0 tests the start point once; otherwise dθ = min(step/r, π/4), θ = 0, dθ, ... while θ <= 2π - dθ
// (θ accumulated as dθ + θ); then r += step.
struct Ring { U radiusBits, size; };
static std::vector<Ring> RingModel(float startR,float step,U want) {
    std::vector<Ring> rings; volatile float r=startR; U total=0;
    const float quarter=F(0x3F490FDBu), twoPi=F(0x40C90FDBu);
    while(total<want) {
        U size=1;
        if(r>0.0f) {
            volatile float d=step/r; d=d<quarter ? d : quarter;
            volatile float lim=twoPi-d, th=0.0f; size=0;
            do { ++size; th=d+th; } while(lim>=th);
        }
        rings.push_back({r>0.0f ? Bits(r) : 0u,size}); total+=size; r=r+step;
    }
    return rings;
}
static __declspec(align(16)) B specA[0x40], specB[0x40];
static void Spec(B* s,float x,float z,float startR,U maxR,U kind) {
    std::memset(s,0,0x40);
    Put(s,0,Bits(x)); Put(s,4,Bits(z)); Put(s,8,Bits(20.0f)); Put(s,0xc,Bits(startR));
    Put(s,0x18,Bits(2.0f)); Put(s,0x1c,Bits(1.0f)); Put(s,0x20,0x1234); Put(s,0x24,maxR);
    s[0x30]=static_cast<B>(kind); Put(s,0x34,1); s[0x38]=1;
}
struct Run { std::vector<Candidate> trace; U out[5], ret; Fx fx; };
static Run RunNative(const B* spec) {
    Run run={}; trace.clear(); U out[8]={};
    ResetFp(); run.ret=reinterpret_cast<Spiral3>(At(0x7FCA40))(A(po),0,A(out),A(spec),0); _fxsave(run.fx.bytes);
    run.ret-=A(out); std::memcpy(run.out,out,20); run.trace=trace;
    Require(Get(At(0x15afca8),0)==0,"native spiral clears its search object");
    return run;
}
static Run RunForwarder(const B* spec) {
    Run run={}; trace.clear(); U out[8]={};
    ResetFp(); run.ret=sp::Spiral(A(po),0,A(out),A(spec),0); _fxsave(run.fx.bytes);
    run.ret-=A(out); std::memcpy(run.out,out,20); run.trace=trace;
    Require(Get(At(0x15afca8),0)==0,"forwarded spiral clears its search object");
    return run;
}
static bool SameRun(const Run& a,const Run& b) {
    if(a.trace.size()!=b.trace.size() || a.ret!=b.ret || std::memcmp(a.out,b.out,20) || !SameFp(a.fx,b.fx)) return false;
    for(size_t i=0;i<a.trace.size();++i)
        if(a.trace[i].x!=b.trace[i].x || a.trace[i].z!=b.trace[i].z || a.trace[i].kind!=b.trace[i].kind) return false;
    return true;
}
static U W(U i) { return sp::words[i]; }
static bool Found(const Run& r,U found) { return !r.trace.empty() && r.trace.size()-1>=found && r.out[0]==r.trace.back().x && r.out[2]==r.trace.back().z; }

static U spiralCases, cappedSeen, foundSeen, edgeSeen;
static void SpiralCase(float x,float z,float startR,bool innerRule,U found) {
    Rects(300.0f,150.0f,innerRule);
    foundAt=found; Spec(specA,x,z,startR,sp::kSpecSentinel,1);
    const Run native=RunNative(specA);
    Require(!native.trace.empty(),"fixture produces candidates");
    const bool nativeFound=native.trace.size()-1>=found &&
        InRect(F(native.trace.back().x),F(native.trace.back().z),0x74) && (!innerRule || InRect(F(native.trace.back().x),F(native.trace.back().z),0x84)) &&
        native.out[0]==native.trace.back().x && native.out[2]==native.trace.back().z;
    // N = 0: forwarder path equals native.
    Configure(0);
    B before[0x40]; std::memcpy(before,specA,0x40);
    const Run fwd=RunForwarder(specA);
    Require(SameRun(native,fwd),"N=0: forwarder path equals native 0x7FCA40 (candidates, out, return, x87/MXCSR)");
    Require(!std::memcmp(before,specA,0x40),"N=0: spec unchanged");
    const std::vector<Ring> rings=RingModel(startR,20.0f,static_cast<U>(native.trace.size()));
    U ringCount=static_cast<U>(rings.size());
    Require(W(sp::WSpiralEntries)==1 && W(sp::WSpiralCandidates)==native.trace.size() && W(sp::WSpiralRings)==ringCount,
            "census: one spiral, every candidate, rings equal the float ring model");
    Require(W(sp::WMaxRadiusMetres)==static_cast<U>(F(rings.back().radiusBits)) && W(sp::WMaxCandidates)==native.trace.size(),"census: max radius and candidates");
    Require(W(sp::WSpiralFound)==(nativeFound?1u:0u) && W(sp::WSpiralEdge)==(nativeFound?0u:1u) && W(sp::WSpiralCapped)==0,"census: N=0 exit classification");
    if(!nativeFound) Require(native.out[0]==Bits(x) && native.out[2]==Bits(z),"native not-found returns the projection of the ORIGINAL point");
    // Caps: forwarder with N on the sentinel == native with spec+0x24 = (float)N.
    for(U cap:{20u,40u,60u,100u,200u,400u}) {
        Spec(specB,x,z,startR,Bits(static_cast<float>(cap)),1);
        const Run capped=RunNative(specB);
        Configure(cap);
        std::memcpy(before,specA,0x40);
        const Run viaCap=RunForwarder(specA);
        Require(SameRun(capped,viaCap),"cap N: forwarder equals native 0x7FCA40 with maxR = N");
        Require(!std::memcmp(before,specA,0x40),"cap N: the caller's spec is never written (private copy)");
        // Prefix: every ring of radius <= N runs (the first one always), then the radius exit.
        U keep=0, last=0;
        for(size_t i=0;i<rings.size();++i) { if(i && F(rings[i].radiusBits)>static_cast<float>(cap)) break; keep+=rings[i].size; last=static_cast<U>(i); }
        const U expect=std::min<U>(keep,static_cast<U>(native.trace.size()));
        Require(capped.trace.size()==expect,"cap N: candidates are the uncapped prefix of rings with radius <= N");
        for(U i=0;i<expect;++i) Require(capped.trace[i].x==native.trace[i].x && capped.trace[i].z==native.trace[i].z,"cap N: same candidate order");
        const bool foundWithin=nativeFound && native.trace.size()<=keep;
        Require(Found(capped,found)==foundWithin,"cap N: found iff the uncapped spot lies within radius N");
        if(!foundWithin) Require(capped.out[0]==Bits(x) && capped.out[2]==Bits(z) && capped.out[1]==Bits(1.0f),"cap N: not found returns the projection of the ORIGINAL point");
        const bool cut=native.trace.size()>keep;
        Require(W(sp::WSpiralCapped)==(cut?1u:0u) && W(sp::WSpiralFound)==(foundWithin?1u:0u) && W(sp::WSpiralEdge)==((!foundWithin && !cut)?1u:0u),
                "cap N: capped exactly when the cap cut the uncapped sequence");
        Require(W(sp::WCapMetres)==cap && W(sp::WSpiralCandidates)==expect && W(sp::WSpiralRings)==std::min<U>(last+1,ringCount) &&
                W(sp::WMaxRadiusMetres)<=std::max(cap,0u),"cap N: census within the cap");
        cappedSeen+=cut; foundSeen+=foundWithin; edgeSeen+=!foundWithin && !cut;
    }
    // A positive native bound is forwarded untouched even with the cap active.
    Spec(specB,x,z,startR,Bits(60.0f),1);
    const Run sixty=RunNative(specB);
    Configure(400);
    std::memcpy(before,specB,0x40);
    Require(SameRun(sixty,RunForwarder(specB)) && !std::memcmp(before,specB,0x40),"non-sentinel maxR is forwarded untouched");
    // The forwarder does nothing while inactive or when nested.
    sp::Configure(false,200,targets);
    Require(SameRun(native,RunForwarder(specA)) && W(sp::WVersion)==0 && W(sp::WSpiralEntries)==0,"inactive: pure forwarding, nothing counted");
    ++spiralCases;
}
static void TestSpiral() {
    const U never=0xFFFFFFFFu;
    for(bool inner:{false,true})
        for(U found:{0u,3u,7u,8u,9u,30u,100u,400u,never}) {
            SpiralCase(0.0f,0.0f,20.0f,inner,found);
            SpiralCase(250.0f,-100.0f,20.0f,inner,found);
            SpiralCase(-40.5f,77.25f,20.0f,inner,found);
        }
    SpiralCase(10.0f,10.0f,0.0f,false,0);   // start-point test (r <= 0, the 0x7FCD47 call) then rings
    SpiralCase(10.0f,10.0f,0.0f,false,5);
    SpiralCase(10.0f,10.0f,0.0f,true,never);
    Require(cappedSeen>10 && foundSeen>10 && edgeSeen>=3,"case set exercises capped, found and edge exits");
    std::printf("spiral: %u cases (capped=%u found=%u edge=%u)\n",spiralCases,cappedSeen,foundSeen,edgeSeen);
}

// ---------------------------------------------------------------------------------------------------------------- ladder
static __declspec(align(16)) B C[0x100], E[0x100], Eobj[0x20], boxes[64*0x24];
static void LadderFixture(bool clamp) {
    Rects(300.0f,150.0f,false);
    std::memset(C,0,sizeof(C)); std::memset(E,0,sizeof(E)); std::memset(boxes,0,sizeof(boxes));
    Put(C,0,A(E)); Put(E,0xd0,A(Eobj)); Put(Eobj,8,A(model)); Put(E,0xd8,0x5151);
    C[0x3c]=1; C[0x3d]=clamp ? 1 : 0; C[0x3e]=0; Put(C,0x40,1); Put(C,0x44,Bits(5.0f)); // +0x44: ring step (0x6C774C), mode 1 = 5 m
    Put(C,0x48+4,64); Put(C,0x48+8,0); Put(C,0x48+0xc,A(boxes));
    probeCalls=0; clampCalls=0;
}
struct LRun { U out[5], ret, boxes, probes, box[9]; std::vector<Candidate> trace; Fx fx; };
static float P[2];
static LRun Ladder(bool native,const std::vector<U>& t,U reject,bool clamp) {
    LadderFixture(clamp); probeTrue=t; rejectConnect=reject; trace.clear();
    LRun r={}; U out[8]={};
    P[0]=12.5f; P[1]=-33.0f;
    ResetFp();
    r.ret=native ? reinterpret_cast<Ladder5>(At(0x6C71D0))(A(C),0,A(out),A(P),0x400,Bits(2.0f),Bits(1.0f))
                 : sp::Ladder(A(C),0,A(out),A(P),0x400,Bits(2.0f),Bits(1.0f));
    _fxsave(r.fx.bytes);
    r.ret-=A(out); std::memcpy(r.out,out,20); r.boxes=Get(C,0x48+8); r.probes=probeCalls; r.trace=trace;
    if(r.boxes) std::memcpy(r.box,boxes+(r.boxes-1)*0x24,0x24);
    Require(Get(At(0x150b5f8),0)==0,"ladder clears its search object");
    return r;
}
static bool SameLadder(const LRun& a,const LRun& b) {
    // Box +0xA..+0xB is never written by 0x6C71D0 (u16 heading at +8; stale stack bytes of the ladder frame), so it is masked.
    U boxA[9], boxB[9]; std::memcpy(boxA,a.box,sizeof(boxA)); std::memcpy(boxB,b.box,sizeof(boxB)); boxA[2]&=0xFFFFu; boxB[2]&=0xFFFFu;
    const bool ret=a.ret==b.ret, out=!std::memcmp(a.out,b.out,20), boxes=a.boxes==b.boxes && !std::memcmp(boxA,boxB,0x24),
               probes=a.probes==b.probes, size=a.trace.size()==b.trace.size(), fp=SameFp(a.fx,b.fx);
    if(!(ret && out && boxes && probes && size && fp)) {
        std::fprintf(stderr,"ladder mismatch: ret=%d out=%d boxes=%d probes=%d (%u/%u) trace=%d fp=%d\n",ret,out,boxes,probes,a.probes,b.probes,size,fp);
        for(U i=0;i<9;++i) std::fprintf(stderr,"  box[%u] %08x %08x\n",i,a.box[i],b.box[i]);
        return false;
    }
    for(size_t i=0;i<a.trace.size();++i) if(a.trace[i].x!=b.trace[i].x || a.trace[i].z!=b.trace[i].z) return false;
    return true;
}
static void LadderCase(const std::vector<U>& t,U reject,bool clamp,U found,U cap,U stage,const char* what) {
    foundAt=found;
    const LRun native=Ladder(true,t,reject,clamp);
    Configure(0);
    const LRun fwd=Ladder(false,t,reject,clamp);
    Require(SameLadder(native,fwd),what);
    Require(native.boxes==1,"every ladder call places exactly one box (native appends even on a spiral miss)");
    if(!cap) Require(W(sp::WLadderCalls)==1 && W(stage)==1,"ladder stage classified");
    if(cap) {
        Configure(cap);
        const LRun capped=Ladder(false,t,reject,clamp);
        Require(W(sp::WLadderCalls)==1 && W(stage)==1,"capped ladder stage classified");
        Require(capped.ret==native.ret && capped.boxes==1,"capped ladder returns normally (no assert) and places one box");
        if(stage==sp::WStageNone)
            Require(capped.out[0]==Bits(P[0]) && capped.out[2]==Bits(P[1]) && capped.out[1]==Bits(1.0f),
                    "capped no-spot path places the projection of the ORIGINAL requested point");
    }
}
static void TestLadder() {
    // Wiring of the clone chain.
    U t=0;
    const U l=clones.entries[NTW2_CLONE_PS_6C71D0], s=clones.entries[NTW2_CLONE_PS_7FCA40], s90=clones.entries[NTW2_CLONE_PS_7FCA90], o=clones.entries[NTW2_CLONE_PS_6A95A0];
    Require(CloneCall(o,0x6A994F-0x6A95A0,t) && t==Fn(&sp::Ladder),"PS_6A95A0 0x6A994F calls the Ladder forwarder");
    Require(CloneCall(o,0x6A9699-0x6A95A0,t) && t==s,"PS_6A95A0 0x6A9699 still calls PS_7FCA40");
    for(U site:{0x6C7316u,0x6C7410u,0x6C77E2u}) Require(CloneCall(l,site-0x6C71D0,t) && t==Fn(&sp::LadderProbe),"PS_6C71D0 0x6CC730 calls -> LadderProbe");
    Require(CloneCall(l,0x6C79A8-0x6C71D0,t) && t==Fn(&sp::Spiral),"PS_6C71D0 0x6C79A8 -> Spiral forwarder");
    Require(CloneCall(s,0x7FCA7A-0x7FCA40,t) && t==s90,"PS_7FCA40 calls PS_7FCA90");
    for(U site:{0x7FCC59u,0x7FCD47u}) Require(CloneCall(s90,site-0x7FCA90,t) && t==Fn(&sp::SpiralProbe),"PS_7FCA90 0x808040 calls -> SpiralProbe");
    Require(sp::kSpotReturn==0x6C731B-0x6C71D0 && !std::memcmp(reinterpret_cast<void*>(l+sp::kSpotReturn),At(0x6C731B),6) &&
            !std::memcmp(reinterpret_cast<void*>(l+sp::kClampReturn),At(0x6C7415),6) && !std::memcmp(reinterpret_cast<void*>(l+sp::kRingReturn),At(0x6C77E7),6),
            "ladder return sites are byte-identical at the same offsets in PS_6C71D0");
    targets.ladderProbe=Fn(&FakeProbe);
    const U never=0xFFFFFFFFu;
    LadderCase({0},0,true,never,0,sp::WStageSpot,"spot: forwarder ladder equals native");
    LadderCase({1},0,true,never,0,sp::WStageClamp,"clamp: forwarder ladder equals native");
    LadderCase({7},0,true,never,0,sp::WStageRing,"ring: forwarder ladder equals native");
    LadderCase({0,9},1,true,never,0,sp::WStageRing,"spot rejected by connectivity, ring later: equals native");
    LadderCase({},0,true,40,0,sp::WStageSpiral,"spiral found: forwarder ladder equals native");
    LadderCase({},0,false,40,0,sp::WStageSpiral,"no clamp stage, spiral found: equals native");
    LadderCase({},0,true,never,0,sp::WStageNone,"spiral edge (no spot): equals native");
    LadderCase({},0,true,40,20,sp::WStageNone,"capped no-spot path");
    LadderCase({},0,true,3,200,sp::WStageSpiral,"spot within the cap still found");
    Require(clampCalls>0,"the clamp stage ran");
    std::printf("ladder: stages and no-spot path verified\n");
}

// -------------------------------------------------------------------------------------------------------------- fallback
static __declspec(align(16)) B obs[0x900], units[5][0xc00], unitInfo[0x40], list[0x10], rows[5*0xc], tickA[0x10], tickB[0x80];
static U vtable[64];
static U tails;
static U __fastcall Fake826E80(U self,U,U unit) {
    const U state=Get(reinterpret_cast<void*>(unit),0xb34);
    if(state==6 || state==7 || !Get(reinterpret_cast<void*>(self),0x28)) return 0;
    const U tick=Get(tickB,0x58), last=Get(reinterpret_cast<void*>(self),0x724);
    if(last && last!=tick && last+10>=tick) return 1;
    Put(reinterpret_cast<void*>(self),0x724,tick); ++tails; return 2;
}
static void FallbackFixture(const U* flag,const U* state,U n) {
    B* ctrl=obs+0x78;
    for(U& v:vtable) v=Fn(&Fake74F400);
    vtable[0x70/4]=Fn(&sp::ControllerGate);
    Put(ctrl,0,A(vtable)); Put(ctrl,8,A(tickA)); Put(tickA,8,A(tickB)); Put(ctrl,0x28,1);
    for(U i=0;i<n;++i) {
        std::memset(units[i],0,sizeof(units[i])); Put(units[i],0x2c,A(unitInfo)); Put(units[i],0xb34,state[i]);
        Put(rows,i*0xc,A(units[i])); Put(rows,i*0xc+4,0); rows[i*0xc+8]=static_cast<B>(flag[i]);
    }
    std::memset(unitInfo,0,sizeof(unitInfo));
    Put(list,8,n); Put(list,0xc,A(rows));
}
static void TestFallback() {
    const U flag[5]={1,0,0,0,0}, state[5]={0,8,0,0,6};
    FallbackFixture(flag,state,5);
    Put(obs+0x78,0x724,0); Put(tickB,0x58,100);
    Configure(0); tails=0;
    sp::FallbackGate(A(obs),0,A(list));
    // rows 0 (flagged) and 1 (state 8) are skipped by 0x7524A0; rows 2,3 recompute (last 0 -> tick, then same tick); row 4 (state 6) skips 0x82F3A0.
    Require(W(sp::WFallbackCalls)==1 && W(sp::WEntries)==3 && W(sp::WEntries3To4)==1 && W(sp::WMaxEntries)==3,"E counted from the native loop's 0x74F430 calls");
    Require(tails==2 && W(sp::WTailRuns)==2 && W(sp::WTailSameTick)==1 && W(sp::WTailMemo)==0,"tail runs: first recompute, then one same-tick recompute");
    Put(tickB,0x58,105); tails=0;
    sp::FallbackGate(A(obs),0,A(list));
    Require(tails==0 && W(sp::WTailMemo)==2 && W(sp::WTailRuns)==2 && W(sp::WEntries3To4)==2,"memo hits within 10 ticks counted");
    Put(tickB,0x58,111); tails=0;
    sp::FallbackGate(A(obs),0,A(list));
    Require(tails==2 && W(sp::WTailRuns)==4 && W(sp::WTailSameTick)==2,"expired memo recomputes, then same tick again");
    const U allFlag[5]={1,1,1,1,1};
    FallbackFixture(allFlag,state,5);
    sp::FallbackGate(A(obs),0,A(list));
    Require(W(sp::WEntries0)==1 && W(sp::WFallbackCalls)==4,"E=0 bin");
    FallbackFixture(flag,state,5);
    inScope=false;
    sp::FallbackGate(A(obs),0,A(list));
    Require(W(sp::WFallbackCalls)==4 && W(sp::WOffThread)==1+3,"off the planner thread: forwarded, counted only as off_thread");
    inScope=true;
    sp::ControllerGate(A(obs+0x78),0,A(units[2]));
    Require(W(sp::WEntries)==9,"controller gate outside a fallback call counts nothing");
    std::printf("fallback: E/tail/memo census verified\n");
}

int main(int argc,char** argv) {
    if(argc!=2) { std::fprintf(stderr,"usage: native_spiral_oracle Napoleon.exe\n"); return 2; }
    Map(argv[1]);
    U bindings[NTW2_BIND_COUNT];
    for(U& b:bindings) b=A(At(0x6dca08)); // unreached bindings: valid image addresses, never executed here
    bindings[NTW2_BIND_PS_LADDER]=Fn(&sp::Ladder);
    bindings[NTW2_BIND_PS_LADDER_PROBE]=Fn(&sp::LadderProbe);
    bindings[NTW2_BIND_PS_SPIRAL]=Fn(&sp::Spiral);
    bindings[NTW2_BIND_PS_SPIRAL_PROBE]=Fn(&sp::SpiralProbe);
    U detail=0; Require(ntw2_build_clones(A(image),bindings,&clones,&detail)==0,"production clone source pins");
    // Scripted world callees (after the clones copied their pinned sources).
    Jump(0x808040,Fn(&Fake808040)); Jump(0x7FCFF0,Fn(&Fake7FCFF0)); Jump(0x7F6ED0,Fn(&Fake7F6ED0)); Jump(0x6DA460,Fn(&Fake6DA460));
    Jump(0x6CC730,Fn(&FakeProbe)); Jump(0x74F400,Fn(&Fake74F400)); Jump(0x84B1D0,Fn(&Fake84B1D0));
    Require(FlushInstructionCache(GetCurrentProcess(),image,imageSize)!=0,"flush image");
    targets={clones.entries[NTW2_CLONE_PS_6C71D0],clones.entries[NTW2_CLONE_PS_6CC730],clones.entries[NTW2_CLONE_PS_7FCA40],Fn(&Fake808040),
             A(At(0x7524A0)),Fn(&Fake826E80),&Scope};
    TestSpiral(); TestLadder(); TestFallback();
    std::printf("spiral cap oracle: %u checks\n",checks);
    return 0;
}

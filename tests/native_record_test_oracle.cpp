// Differential oracle for --ai-record-test-shadow / --ai-record-test (src/ai/kntwr_record_test.{h,cpp} + the alt-scope branch of
// kntwr_poly::Gate). The real 0x80DCF0 -> 0x10EC150 closure of a private relocated copy of the supported image answers the reference; the
// alternate-delegate route is modelled by a fastcall stand-in for the PS_6A99E0 clone chain that forwards to kntwr_poly::Gate exactly the way
// the clone chain's 0x7F1E5A call does (ECX = shape, stack = polygon). Asserts:
//  * Entry forwards the three stack arguments and ECX untouched, returns the callee's EAX, closes the scope, leaves FP control/status/MXCSR to the
//    callee (integer-only forwarder), and an unarmed Entry calls the ORIGINAL;
//  * inside the scope Gate accounts into the record-test row only (poly row untouched) and obeys the record-test mode: shadow answers natively and
//    compares every served call bit-for-bit (AL, x87 control/status/tag, MXCSR) with 0 mismatches, live answers with the kernel (== native AL),
//    refusals run native and are counted by reason; outside the scope the poly row and its own mode are unchanged;
//  * the two modes are independent (poly shadow + record live and the reverse), the 1-in-32 live sample is by count, the entry timing words fill.
// No running game or installed file is touched.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>
#include <xmmintrin.h>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>
#include "native_image_relocation.h"
#include "kntwr_runtime.h"
#include "ai/kntwr_planner_search.h"
#include "ai/kntwr_record_test.h"
#pragma comment(lib,"bcrypt.lib")
#pragma fenv_access(on)
using U=uint32_t;
using B=unsigned char;
static_assert(sizeof(void*)==4,"owned x86 oracle");
static B* image;
static U delta, checks;
static void Require(bool ok,const char* what) { ++checks; if(!ok) { std::fprintf(stderr,"FAIL %s\n",what); std::exit(1); } }
static B* At(U va) { return reinterpret_cast<B*>(va+delta); }
static U Bits(float f) { U u; std::memcpy(&u,&f,4); return u; }
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
    Require(!std::strcmp(hex,KNTWR_IMAGE_SHA256),"supported image identity");
    auto dos=reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
    auto nt=reinterpret_cast<const IMAGE_NT_HEADERS32*>(bytes.data()+dos->e_lfanew);
    image=static_cast<B*>(VirtualAlloc(nullptr,nt->OptionalHeader.SizeOfImage,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE));
    Require(image!=nullptr,"private image mapping"); delta=static_cast<U>(reinterpret_cast<uintptr_t>(image))-0x400000;
    std::memcpy(image,bytes.data(),nt->OptionalHeader.SizeOfHeaders);
    auto sections=IMAGE_FIRST_SECTION(nt);
    for(U i=0;i<nt->FileHeader.NumberOfSections;++i)
        std::memcpy(image+sections[i].VirtualAddress,bytes.data()+sections[i].PointerToRawData,
                    std::min(sections[i].SizeOfRawData,sections[i].Misc.VirtualSize));
    Require(RelocateNativeImage(image,nt->OptionalHeader.SizeOfImage,
        reinterpret_cast<IMAGE_NT_HEADERS32*>(image+dos->e_lfanew),delta),"relocation");
    Require(FlushInstructionCache(GetCurrentProcess(),image,nt->OptionalHeader.SizeOfImage)!=0,"flush image");
}
using Native=B(__fastcall*)(void*,void*,void*);
static Native native;
struct Vertex { U v[13]; };
static std::vector<Vertex> verts;
static U shape[18];
static const U kCsr=0x1f80u|0x20u;        // masks set, inexact already sticky (the entry guard's precondition)
static void ResetFp(U csr=kCsr) { __asm { fninit } _mm_setcsr(csr); }
static void SetShape(const float s[9],U kind=0) { std::memset(shape,0,sizeof(shape)); shape[0]=kind; for(U i=0;i<9;++i) shape[1+i]=Bits(s[i]); }
static void SetPolygon(const std::vector<std::pair<float,float>>& pts) {
    verts.assign(pts.size(),Vertex{});
    for(size_t i=0;i<pts.size();++i) {
        verts[i].v[2]=static_cast<U>(reinterpret_cast<uintptr_t>(&verts[(i+1)%pts.size()]));
        verts[i].v[3]=Bits(pts[i].first); verts[i].v[4]=Bits(pts[i].second);
    }
}
static std::mt19937 rng(777);
static float R(float lo,float hi) { return lo+(hi-lo)*(rng()&0xffffff)/16777216.0f; }
static void Star(U n,float cx,float cz,float r0,float r1,bool integers) {
    std::vector<std::pair<float,float>> p(n);
    for(U i=0;i<n;++i) {
        const float ang=6.2831853f*i/n, r=R(r0,r1);
        float x=cx+r*std::cos(ang), z=cz+r*std::sin(ang);
        x=std::floor(x*64.0f+0.5f)/64.0f; z=std::floor(z*64.0f+0.5f)/64.0f;
        if(integers) { x=std::floor(x); z=std::floor(z); }
        p[i]={x,z};
    }
    SetPolygon(p);
}
static void RandomShape(float cx,float cz,bool orthonormal,bool integers) {
    float s[9]={cx,cz,0,R(0,6),R(0,4),1,0,0,1};
    if(integers) { s[3]=std::floor(s[3]); s[4]=std::floor(s[4]); }
    const float ang=R(0,6.2831853f), c=std::cos(ang), sn=std::sin(ang);
    if(orthonormal) { s[5]=c; s[6]=sn; s[7]=-sn; s[8]=c; } else { s[5]=R(-1,1); s[6]=R(-1,1); s[7]=R(-1,1); s[8]=R(-1,1); }
    SetShape(s);
}

// ---- stand-ins -------------------------------------------------------------------------------------------------------------------------
static U seenSelf, seenA1, seenA2, seenA3, originalCalls, cloneCalls; static bool seenInScope;
static void* curShape; static void* curPolygon; static B curAl; static bool runGate;
static U __fastcall FakeClone(U self,U,U a1,U a2,U a3) {   // PS_6A99E0 chain stand-in: ends in the Gate exactly like the PS_WALK 7F1E5A call
    seenSelf=self; seenA1=a1; seenA2=a2; seenA3=a3; ++cloneCalls; seenInScope=kntwr_record_test::InScope();
    if(runGate) curAl=kntwr_poly::Gate(curShape,nullptr,curPolygon);
    return 0xC0DE0000u|a3;
}
static U __fastcall FakeOriginal(U self,U,U a1,U a2,U a3) { seenSelf=self; seenA1=a1; seenA2=a2; seenA3=a3; ++originalCalls; seenInScope=kntwr_record_test::InScope(); return 0x0F1Fu; }
static U Addr(void* f) { return static_cast<U>(reinterpret_cast<uintptr_t>(f)); }

// One call of the modelled alt route: native reference, then Entry -> FakeClone -> Gate from the identical FP state.
static void AltCall(const char* what) {
    B n; ResetFp(); n=native(shape,nullptr,verts.data());
    curShape=shape; curPolygon=verts.data(); runGate=true; curAl=0xEE;
    ResetFp(); const U r=kntwr_record_test::Entry(0x13376ACu,0,0xA1A1A1A1u,0xB2B2B2B2u,0x000000C3u);
    Require(r==(0xC0DE0000u|0xC3u),what);
    Require(!kntwr_record_test::InScope(),"scope closed after Entry");
    Require(seenSelf==0x13376ACu && seenA1==0xA1A1A1A1u && seenA2==0xB2B2B2B2u && seenA3==0xC3u && seenInScope,"Entry forwards ECX and the three arguments inside the scope");
    Require(curAl==n,what);
}
static void PolyCall(const char* what) { // the default route / R2 sites: Gate outside the alt scope
    B n; ResetFp(); n=native(shape,nullptr,verts.data()); ResetFp(); const B g=kntwr_poly::Gate(shape,nullptr,verts.data()); Require(n==g,what);
}
static void Refusal(const char* what,kntwr_record_test::Word word,U csr=kCsr) {
    const volatile U* w=kntwr_record_test::words; const U before=w[word];
    ResetFp(csr); const B n=native(shape,nullptr,verts.data());
    curShape=shape; curPolygon=verts.data(); runGate=true; curAl=0xEE;
    ResetFp(csr); kntwr_record_test::Entry(1,0,2,3,4);
    Require(curAl==n,what); Require(w[word]==before+1,what);
}
static void Fill(void (*call)(const char*),U rounds) {
    const U classes[]={1,2,3,4,5,7,8,17,64,65,256,1000};
    for(U round=0;round<rounds;++round) for(U v:classes) {
        Star(v,R(-20,20),R(-20,20),10,60,round&1); RandomShape(R(-70,70),R(-70,70),!(round&2),round&1); call("random");
    }
}
int main(int argc,char** argv) {
    if(argc<2) { std::fprintf(stderr,"usage: native_record_test_oracle Napoleon.exe\n"); return 2; }
    Map(argv[1]); native=reinterpret_cast<Native>(At(0x80dcf0));
    namespace RT=kntwr_record_test;
    using volatile_row=const volatile U*;
    // 0. Disarmed (never configured / ModeOff): Entry calls the original, no scope, row zero.
    RT::Configure(RT::ModeOff,Addr(&FakeClone),Addr(&FakeOriginal),2000);
    { ResetFp(); const U r=RT::Entry(5,0,6,7,8); Require(r==0x0F1Fu && originalCalls==1 && seenSelf==5 && seenA1==6 && seenA2==7 && seenA3==8 && !seenInScope && !cloneCalls,"disarmed Entry runs the original");
      bool zero=true; for(U i=0;i<RT::kWords;++i) zero=zero && !RT::words[i]; Require(zero,"row zero when off"); }
    // 1. Shadow record-test next to a LIVE poly route: the alt route answers natively and compares every served call; the poly row is untouched by
    //    alt calls and keeps its live behaviour on direct Gate calls.
    kntwr_poly::Configure(native,kntwr_poly::ModeLive);
    RT::Configure(RT::ModeShadow,Addr(&FakeClone),Addr(&FakeOriginal),kntwr_poly::words[31]);
    Fill(AltCall,40);
    {
        volatile_row w=RT::words;
        Require(w[RT::WVersion]==1 && w[RT::WMode]==RT::ModeShadow && w[RT::WTscPerUs]==kntwr_poly::words[31] && w[RT::WTscPerUs]>=100,"record row: version, mode, tsc");
        Require(w[RT::WCalls]==40*12 && w[RT::WServed]>400 && w[RT::WCalls]==w[RT::WServed]+w[RT::WFallKind]+w[RT::WFallFp]+w[RT::WFallDomain]+w[RT::WFallWalkCap]+w[RT::WFallBusy],
                "record calls == served + fallbacks");
        Require(w[RT::WShadowCompares]==w[RT::WServed] && !w[RT::WMismatchAl] && !w[RT::WMismatchX87] && !w[RT::WMismatchMxcsr],"shadow compares every served call, 0 mismatches");
        Require(w[RT::WSampledCalls]==w[RT::WServed] && w[RT::WServedFastKc]==w[RT::WSampledFastKc] && w[RT::WSampledNativeKc]>0 && w[RT::WSampledFastKc]>0,"shadow samples every served call");
        Require(w[RT::WVerticesSum]>0 && w[RT::WVerticesMax]==1000 && w[RT::WVerticesOver256]>0 && w[RT::WTrue]>0 && w[RT::WTrue]<w[RT::WServed],"vertices, hit/miss mix");
        Require(w[RT::WEntryKc]>0,"entry timing accumulates");
        for(U i=2;i<=30;++i) Require(!kntwr_poly::words[i],"alt calls leave the poly row untouched");
    }
    Fill(PolyCall,6);
    {
        const volatile U* p=kntwr_poly::words;
        Require(p[0]==1 && p[1]==kntwr_poly::ModeLive && p[2]==6*12 && p[3]>50 && p[29]==p[3]/32 && p[8]==p[29] && !p[9] && !p[10] && !p[11],"direct Gate calls keep the live poly mode and row");
        Require(RT::words[RT::WCalls]==40*12,"direct Gate calls leave the record row untouched");
    }
    // 2. Live record-test next to a SHADOW poly route (independent modes), refusals by reason, 1-in-32 sample by count.
    kntwr_poly::Configure(native,kntwr_poly::ModeShadow);
    RT::Configure(RT::ModeLive,Addr(&FakeClone),Addr(&FakeOriginal),kntwr_poly::words[31]);
    Fill(AltCall,64);
    {
        volatile_row w=RT::words; const U served=w[RT::WServed];
        Require(w[RT::WMode]==RT::ModeLive && w[RT::WCalls]==64*12 && served>600,"live record row counts");
        Require(w[RT::WSampledCalls]==served/32 && w[RT::WShadowCompares]==w[RT::WSampledCalls] && !w[RT::WMismatchAl] && !w[RT::WMismatchX87] && !w[RT::WMismatchMxcsr],
                "live compares every 32nd served call (by count), 0 mismatches");
        Require(w[RT::WServedFastKc]>=w[RT::WSampledFastKc] && w[RT::WSampledNativeKc]>0,"live timing words");
        // Refusals: kind (not an OBB), FP precondition, domain (huge coordinate), walk cap -- each answered by native and counted by reason.
        { float s[9]={0,0,0,2,2,1,0,0,1}; SetShape(s,1); SetPolygon({{9,9},{10,9},{10,10}}); Refusal("kind refusal",RT::WFallKind); }
        { float s[9]={0,0,0,2,2,1,0,0,1}; SetShape(s); SetPolygon({{9,9},{10,9},{10,10}}); Refusal("FP-state refusal",RT::WFallFp,0x1f80u); }
        { float s[9]={0,0,0,2,2,1,0,0,1}; SetShape(s); SetPolygon({{1e9f,0},{2,2},{3,1}}); Refusal("domain refusal",RT::WFallDomain); }
        { Star(65537,0,0,10,20,false); float s[9]={100,100,0,2,2,1,0,0,1}; SetShape(s); Refusal("walk-cap refusal",RT::WFallWalkCap); }
        const volatile U* p=kntwr_poly::words;
        for(U i=2;i<=30;++i) Require(!p[i],"alt calls leave the (shadow) poly row untouched");
    }
    // 3. Slot routing counters and the row after a reconfigure (a second Configure resets it).
    RT::NoteSlot(true); RT::NoteSlot(true); RT::NoteSlot(false);
    Require(RT::words[RT::WSlotRouted]==2 && RT::words[RT::WSlotUnrouted]==1,"slot routing counters");
    RT::Configure(RT::ModeShadow,Addr(&FakeClone),Addr(&FakeOriginal),2000);
    { bool zero=true; for(U i=0;i<RT::kWords;++i) zero=zero && (i==RT::WVersion?RT::words[i]==1:i==RT::WMode?RT::words[i]==RT::ModeShadow:i==RT::WTscPerUs?RT::words[i]==2000:!RT::words[i]); Require(zero,"Configure resets the row"); }
    RT::Reset();
    { bool zero=true; for(U i=0;i<RT::kWords;++i) zero=zero && !RT::words[i]; Require(zero,"Reset zeroes the row"); }
    kntwr_poly::Configure(native,kntwr_poly::ModeOff);
    std::printf("record test oracle: %u checks, 0 mismatches\n",checks);
    return 0;
}

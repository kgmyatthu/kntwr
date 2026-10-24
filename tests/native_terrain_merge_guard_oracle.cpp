// Oracle for src/ai/kntwr_terrain_merge_guard.{h,cpp} (the always-on terrain-analyser merge predicate fast rejection) on a private relocated mapping of the owned image.
//  * PREDICATE: the ORIGINAL bytes of FUN_0063B470 (run in the private mapping, thiscall ECX = record i, stack record j, ret 4) against the guard (Entry(), reached directly AND
//    through the displacement actually written into the mapped call site 0x62CA2B) over hand-built geometry (shared full edge, corner-only touch, disjoint, containment, identity,
//    different types, rotations, degenerate lengths, signed zeros, NaN/infinity/extreme fields), rounding-sensitive boundaries (centres 0..4 ulps around exact touching) and
//    deterministic randomized records across an orientation x scale x type matrix.  The returned bool must be identical, EBX/ESI/EDI preserved, the callee pops its 4 bytes;
//    whenever Rejects() answers 1 the native predicate must answer false.  The sweeps are checked to contain native-true pairs, rejected pairs and non-rejected false pairs.
//  * MERGE ORDER: a greedy first-match merge with restart (a synthetic consumer of the predicate over lattice collections of unit squares) produces the identical ordered merge
//    log and final records whether it asks the native function or the hooked call site.
//  * REDIRECT: Install pins the call-site context, the native prologue/exit and the 0.5f constant (every mismatch is refused without a change), swaps exactly the displacement
//    dword (opcode and neighbours untouched, page protection restored), publishes the native address; Remove restores the stock displacement, is a no-op without install,
//    succeeds when the stock displacement is already back and refuses a foreign displacement.
// No running game or installed file is modified.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>
#include <xmmintrin.h>
#include "native_image_relocation.h"
#include "kntwr_runtime.h"
#include "ai/kntwr_terrain_merge_guard.h"
#pragma comment(lib,"bcrypt.lib")
using U=uint32_t;
using B=unsigned char;
namespace g=kntwr_terrain_merge_guard;
static_assert(sizeof(void*)==4,"owned x86 oracle");
static B* image;
static U delta, checks, imageSize;
static void Require(bool ok,const char* what) { ++checks; if(!ok) { std::fprintf(stderr,"FAIL %s\n",what); std::exit(1); } }
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static B* At(U va) { return reinterpret_cast<B*>(va+delta); }
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

// Deterministic generator (the oracle must be reproducible).
static U rngState=0x13579BDFu;
static U Rng() { rngState=rngState*1664525u+1013904223u; return rngState^(rngState>>15); }

// A terrain record as the predicate reads it: centre +0/+4, lengths +0xC/+0x10, axes +0x14/+0x18 and +0x1C/+0x20, type +0x24.  The unused dwords hold a pattern the
// predicate must not depend on.
struct Rec { U w[16]; };
static float F(U bits) { float f; std::memcpy(&f,&bits,4); return f; }
static U Bits(float f) { U b; std::memcpy(&b,&f,4); return b; }
enum Field { CX=0, CY=1, L0=3, L1=4, A1=5, A2=6, B1=7, B2=8, TYPE=9 };
static float Get(const Rec& r,Field f) { return F(r.w[f]); }
static void Set(Rec& r,Field f,float v) { r.w[f]=Bits(v); }
static Rec Make(U type,float cx,float cy,float l0,float l1,float a1,float a2,float b1,float b2) {
    Rec r; for(U i=0;i<16;++i) r.w[i]=0xCDCDCDCDu;
    Set(r,CX,cx); Set(r,CY,cy); Set(r,L0,l0); Set(r,L1,l1); Set(r,A1,a1); Set(r,A2,a2); Set(r,B1,b1); Set(r,B2,b2); r.w[TYPE]=type;
    return r;
}
static Rec Aligned(U type,float cx,float cy,float l0,float l1) { return Make(type,cx,cy,l0,l1,1.0f,0.0f,0.0f,1.0f); }

// thiscall(ECX = a, stack b, callee pops 4): EBX/ESI/EDI must survive and the stack must be balanced.  Returns AL.
static U CheckedCall(U fn,const void* a,const void* b,bool* preserved) {
    U result=0, ok=0, savedEsp=0;
    __asm {
        push ebx
        push esi
        push edi
        mov ebx, 0x11111111
        mov esi, 0x22222222
        mov edi, 0x33333333
        mov savedEsp, esp
        push b
        mov ecx, a
        call fn
        movzx eax, al
        mov result, eax
        xor eax, eax
        cmp esp, savedEsp
        jne bad
        cmp ebx, 0x11111111
        jne bad
        cmp esi, 0x22222222
        jne bad
        cmp edi, 0x33333333
        jne bad
        mov eax, 1
    bad:
        mov ok, eax
        pop edi
        pop esi
        pop ebx
    }
    *preserved=ok!=0;
    return result;
}
// cdecl(a, b) stub variant of the same check (the hooked-call-site stub is a cdecl function).
static U CheckedCdecl(U fn,const void* a,const void* b,bool* preserved) {
    U result=0, ok=0, savedEsp=0;
    __asm {
        push ebx
        push esi
        push edi
        mov ebx, 0x11111111
        mov esi, 0x22222222
        mov edi, 0x33333333
        mov savedEsp, esp
        push b
        push a
        call fn
        add esp, 8
        movzx eax, al
        mov result, eax
        xor eax, eax
        cmp esp, savedEsp
        jne bad
        cmp ebx, 0x11111111
        jne bad
        cmp esi, 0x22222222
        jne bad
        cmp edi, 0x33333333
        jne bad
        mov eax, 1
    bad:
        mov ok, eax
        pop edi
        pop esi
        pop ebx
    }
    *preserved=ok!=0;
    return result;
}

// The hooked call site: a stub that performs exactly what the engine does at 0x62CA20..0x62CA2F (ECX = record i, push record j, `call rel32`) with the displacement READ FROM THE
// MAPPED IMAGE (rebased to the stub), so the stub reaches whatever the install wrote there.
static B* stub;
static U stubTarget;
static void BuildStub() {
    if(!stub) { stub=static_cast<B*>(VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE)); Require(stub!=nullptr,"stub page"); }
    const B* site=At(g::kCallSite);
    U rel; std::memcpy(&rel,site+1,4);
    Require(site[0]==0xE8,"call site opcode is E8");
    stubTarget=A(site)+5+rel;
    static const B head[9]={0x8B,0x4C,0x24,0x04, 0x8B,0x44,0x24,0x08, 0x50};   // mov ecx,[esp+4]; mov eax,[esp+8]; push eax
    std::memcpy(stub,head,9); stub[9]=0xE8;
    const U rel2=stubTarget-(A(stub)+14); std::memcpy(stub+10,&rel2,4); stub[14]=0xC3;
    FlushInstructionCache(GetCurrentProcess(),stub,16);
}

static U gNative, gGuard;
static U Native(const Rec& a,const Rec& b) { bool p; const U r=CheckedCall(gNative,&a,&b,&p); Require(p,"native preserves ebx/esi/edi, pops 4"); return r; }
static U Guard(const Rec& a,const Rec& b) { bool p; const U r=CheckedCall(gGuard,&a,&b,&p); Require(p,"guard preserves ebx/esi/edi, pops 4"); return r; }
static U Hooked(const Rec& a,const Rec& b) { bool p; const U r=CheckedCdecl(A(stub),&a,&b,&p); Require(p,"hooked call preserves ebx/esi/edi"); return r; }

static U nativeTrue, rejected, guardedFalse, typeRejected, total;
// All three paths agree with the native result; a rejection implies native false.
static U Cmp(const Rec& a,const Rec& b) {
    const U n=Native(a,b);
    const U gd=Guard(a,b), h=Hooked(a,b);
    ++total;
    Require(n<=1,"native result is a bool");
    Require(gd==n,"guard result equals native");
    Require(h==n,"hooked call-site result equals native");
    const U rj=g::Rejects(a.w,b.w);
    Require(rj<=1,"Rejects is 0/1");
    if(rj) { Require(n==0,"a rejected pair is native false"); ++rejected; if(a.w[TYPE]!=b.w[TYPE]) ++typeRejected; }
    else if(!n) ++guardedFalse;
    if(n) { ++nativeTrue; Require(!rj,"a native-true pair is never rejected"); }
    return n;
}

static float Rf(float lo,float hi) { return lo+(hi-lo)*(static_cast<float>(Rng()>>8)/16777216.0f); }
static float Ulps(float v,int steps) {
    const float dir=steps>0 ? std::numeric_limits<float>::infinity() : -std::numeric_limits<float>::infinity();
    for(int i=0;i<std::abs(steps);++i) v=std::nextafterf(v,dir);
    return v;
}
struct Orient { float a1,a2,b1,b2; };
static const float kS=0.70710678118f;
static const Orient kOrient[]={{1,0,0,1},{0,1,-1,0},{-1,0,0,-1},{0,-1,1,0},{1,0,0,-1},{kS,kS,-kS,kS}};
static const float kScale[]={1.0f,0.001f,1.0e6f,3.0e18f,1.0e-20f};
static const U kTypes[]={0u,1u,2u,0x7FFFFFFFu,0xFFFFFFFFu};
static const float kLens[]={0.0f,0.5f,1.0f,2.0f,3.0f};

static void HandBuilt() {
    // adjacent along an edge / corner-only / overlapping: the predicate is true only when a whole segment (both endpoints) of one box equals a segment of the other
    Require(Cmp(Aligned(1,0,0,2,2),Aligned(1,2,0,2,2))==1,"edge-adjacent equal-extent squares share a full segment");
    Require(Cmp(Aligned(1,0,0,2,2),Aligned(1,2,2,2,2))==0,"corner-only touching squares share no full segment");
    Require(Cmp(Aligned(1,0,0,2,2),Aligned(1,0,0,2,2))==1,"identity");
    Require(Cmp(Aligned(1,0,0,2,2),Aligned(1,0,0,1,1))==0,"contained square has no shared corner");
    Require(Cmp(Aligned(1,0,0,2,2),Aligned(1,5,0,2,2))==0,"disjoint squares");
    Require(Cmp(Aligned(1,0,0,2,2),Aligned(1,1,0,2,2))==0,"partially overlapping squares share no corner");
    Cmp(Aligned(1,0,0,2,2),Aligned(1,2,0,2,1));   // half-edge adjacency: value compared against native
    Require(Cmp(Aligned(1,0,0,2,2),Aligned(2,0,0,2,2))==0,"identical geometry, different types");
    Require(Cmp(Aligned(1,0,0,2,2),Aligned(2,50,50,1,1))==0 && typeRejected>0,"different types are rejected as native");
    // rotations: 90 degrees swaps the corner roles; 45 degrees; mirrored axes
    const Orient& o90=kOrient[1]; const Orient& o45=kOrient[5];
    Cmp(Aligned(1,0,0,2,2),Make(1,0,0,2,2,o90.a1,o90.a2,o90.b1,o90.b2));
    Cmp(Aligned(1,0,0,2,2),Make(1,2,0,2,2,o90.a1,o90.a2,o90.b1,o90.b2));
    Cmp(Aligned(1,0,0,2,2),Make(1,0,0,2,2,o45.a1,o45.a2,o45.b1,o45.b2));
    Cmp(Make(1,0,0,2,2,o45.a1,o45.a2,o45.b1,o45.b2),Make(1,0,0,2,2,o45.a1,o45.a2,o45.b1,o45.b2));
    Cmp(Make(1,0,0,2,2,o45.a1,o45.a2,o45.b1,o45.b2),Make(1,1.41421356f,0,2,2,o45.a1,o45.a2,o45.b1,o45.b2));
    // degenerates: zero lengths (points/lines), both zero at the same point
    Require(Cmp(Aligned(1,3,3,0,0),Aligned(1,3,3,0,0))==1,"two identical points");
    Cmp(Aligned(1,3,3,0,0),Aligned(1,3,3,2,2));
    Cmp(Aligned(1,3,3,0,2),Aligned(1,3,3,2,0));
    Cmp(Aligned(1,0,0,2,0),Aligned(1,2,0,2,0));
    Cmp(Aligned(1,0,0,0,0),Aligned(1,1,1,0,0));
    // signed zeros: -0 and +0 compare equal in UCOMISS
    Require(Cmp(Aligned(1,0.0f,0.0f,2,2),Aligned(1,-0.0f,-0.0f,2,2))==1,"signed-zero centres are equal");
    Cmp(Aligned(1,0.0f,0.0f,0,0),Aligned(1,-0.0f,0.0f,0,0));
    Cmp(Aligned(1,-0.0f,-0.0f,0,0),Aligned(1,0.0f,0.0f,0,0));
    Cmp(Make(1,0,0,2,2,-0.0f,0.0f,0.0f,-0.0f),Make(1,0,0,2,2,1,0,0,1));
    // NaN in every field of either record (and both), infinities and extremes
    const float nan=std::numeric_limits<float>::quiet_NaN(), inf=std::numeric_limits<float>::infinity();
    const Field fields[8]={CX,CY,L0,L1,A1,A2,B1,B2};
    for(Field f : fields) {
        for(U which=0;which<3;++which) {
            Rec a=Aligned(1,0,0,2,2), b=Aligned(1,2,0,2,2);
            if(which!=1) Set(a,f,nan);
            if(which!=0) Set(b,f,nan);
            Cmp(a,b); Cmp(b,a);
            Rec c=a, d=Aligned(1,5,5,2,2); Cmp(c,d); Cmp(d,c);
        }
        for(float v : {inf,-inf,3.4e38f,-3.4e38f,1.0e-40f,-0.0f}) {
            Rec a=Aligned(1,0,0,2,2), b=Aligned(1,2,0,2,2);
            Set(a,f,v); Cmp(a,b); Cmp(b,a);
            Set(b,f,v); Cmp(a,b);
        }
    }
    Cmp(Aligned(1,inf,0,2,2),Aligned(1,inf,0,2,2));
    Cmp(Aligned(1,inf,0,0,0),Aligned(1,inf,0,0,0));
    Cmp(Aligned(1,-inf,0,0,0),Aligned(1,inf,0,0,0));
    Cmp(Aligned(1,0,0,inf,inf),Aligned(1,0,0,inf,inf));
    Cmp(Aligned(1,0,0,inf,2),Aligned(1,5,5,inf,2));
    Cmp(Aligned(1,3.4e38f,0,3.4e38f,2),Aligned(1,3.4e38f,0,3.4e38f,2));
}

// Exactly touching axis-aligned squares moved by -4..+4 ulps in x and y: the rounding-sensitive boundary of every strict comparison in Rejects().
static void Boundaries() {
    for(U iter=0;iter<60000;++iter) {
        const float scale=kScale[Rng()%5];
        const float ox=Rf(-4.0f,4.0f)*scale*(iter&1 ? 1000.0f : 1.0f), oy=Rf(-4.0f,4.0f)*scale;
        const float l0=Rf(0.25f,3.0f)*scale, l1=Rf(0.25f,3.0f)*scale, m0=Rf(0.25f,3.0f)*scale, m1=Rf(0.25f,3.0f)*scale;
        const Rec a=Aligned(1,ox,oy,l0,l1);
        const float touchX=ox+(l0+m0)*0.5f, touchY=oy+(l1+m1)*0.5f;
        const int kx=static_cast<int>(Rng()%9)-4, ky=static_cast<int>(Rng()%9)-4;
        const Rec b=Aligned(1,Ulps(touchX,kx),Ulps(touchY,(Rng()&1) ? ky : 0),m0,m1);
        Cmp(a,b); Cmp(b,a);
        const Rec c=Aligned(1,Ulps(touchX,kx),Ulps(oy,ky),m0,l1);   // same row: x boundary only
        Cmp(a,c);
        const Orient& o=kOrient[Rng()%6];
        const Rec d=Make(1,Ulps(touchX,kx),oy,m0,m1,o.a1,o.a2,o.b1,o.b2);
        Cmp(a,d); Cmp(d,a);
    }
}

// Lattice records (exact binary fractions, so shared corners/edges, containment and identity occur constantly) over the orientation x scale x type matrix.
static void Lattice() {
    for(U oa=0;oa<6;++oa) for(U ob=0;ob<6;++ob) for(U s=0;s<5;++s) {
        const float scale=kScale[s];
        for(U iter=0;iter<3000;++iter) {
            const U t=kTypes[Rng()%3], tb=(Rng()%8) ? t : kTypes[Rng()%5];
            const float cx=(static_cast<int>(Rng()%17)-8)*0.5f*scale, cy=(static_cast<int>(Rng()%17)-8)*0.5f*scale;
            const float dx=(static_cast<int>(Rng()%9)-4)*0.5f*scale, dy=(static_cast<int>(Rng()%9)-4)*0.5f*scale;
            const Rec a=Make(t,cx,cy,kLens[Rng()%5]*scale,kLens[Rng()%5]*scale,kOrient[oa].a1,kOrient[oa].a2,kOrient[oa].b1,kOrient[oa].b2);
            const Rec b=Make(tb,cx+dx,cy+dy,kLens[Rng()%5]*scale,kLens[Rng()%5]*scale,kOrient[ob].a1,kOrient[ob].a2,kOrient[ob].b1,kOrient[ob].b2);
            Cmp(a,b); Cmp(b,a); Cmp(a,a);
        }
    }
}

// Continuous random valid records, random angles (a, b orthonormal up to rounding), random scales; plus a pool of special values in every field.
static void Random() {
    for(U iter=0;iter<150000;++iter) {
        const float scale=kScale[Rng()%5];
        const float th=Rf(0.0f,6.2831853f), th2=Rf(0.0f,6.2831853f);
        const Rec a=Make(1,Rf(-10,10)*scale,Rf(-10,10)*scale,Rf(0,4)*scale,Rf(0,4)*scale,std::cos(th),std::sin(th),-std::sin(th),std::cos(th));
        const Rec b=Make(1,Rf(-10,10)*scale,Rf(-10,10)*scale,Rf(0,4)*scale,Rf(0,4)*scale,std::cos(th2),std::sin(th2),-std::sin(th2),std::cos(th2));
        Cmp(a,b);
        Cmp(b,a); Cmp(a,a);
    }
    const float nan=std::numeric_limits<float>::quiet_NaN(), inf=std::numeric_limits<float>::infinity();
    const float pool[]={0.0f,-0.0f,1.0f,-1.0f,0.5f,-0.5f,2.0f,inf,-inf,nan,1.0e-40f,3.4e38f,-3.4e38f,0.25f,-3.0f};
    const U n=sizeof pool/sizeof pool[0];
    for(U iter=0;iter<400000;++iter) {
        Rec a=Aligned(1,0,0,0,0), b=a;
        const Field fs[8]={CX,CY,L0,L1,A1,A2,B1,B2};
        for(Field f : fs) { Set(a,f,pool[Rng()%n]); Set(b,f,pool[Rng()%n]); }
        Cmp(a,b); Cmp(b,a);
    }
}

// Synthetic consumer: greedy first-match merge with a restart from the first pair after every merge (the structure of the native loop at 0x62C9F0..0x62CF54); the merge effect is
// the bounding rectangle of two axis-aligned records.  The ordered log of merged index pairs and the final records must not depend on which implementation answers.
typedef U (*Pred)(const Rec&,const Rec&);
static Rec Union(const Rec& a,const Rec& b) {
    const float lo0=std::min(Get(a,CX)-Get(a,L0)*0.5f,Get(b,CX)-Get(b,L0)*0.5f), hi0=std::max(Get(a,CX)+Get(a,L0)*0.5f,Get(b,CX)+Get(b,L0)*0.5f);
    const float lo1=std::min(Get(a,CY)-Get(a,L1)*0.5f,Get(b,CY)-Get(b,L1)*0.5f), hi1=std::max(Get(a,CY)+Get(a,L1)*0.5f,Get(b,CY)+Get(b,L1)*0.5f);
    return Aligned(a.w[TYPE],(lo0+hi0)*0.5f,(lo1+hi1)*0.5f,hi0-lo0,hi1-lo1);
}
static std::vector<Rec> MergeAll(std::vector<Rec> v,Pred pred,std::vector<std::pair<U,U>>& log) {
    for(bool again=true;again;) {
        again=false;
        for(U i=0;i<v.size() && !again;++i)
            for(U j=i+1;j<v.size();++j)
                if(pred(v[i],v[j])) { v[i]=Union(v[i],v[j]); v.erase(v.begin()+j); log.push_back({i,j}); again=true; break; }
    }
    return v;
}
// The guard performs the same SSE operations as the native predicate, so every MXCSR rounding mode and DAZ/FTZ must still give identical answers.  Bounded sweeps under each of
// the 16 modes (RN/RD/RU/RZ x DAZ x FTZ), including denormal-scale geometry; the original MXCSR is restored.
static void MxcsrModes() {
    const unsigned original=_mm_getcsr();
    const U savedTotal=total;
    for(unsigned mode=0;mode<16;++mode) {
        unsigned csr=(original&~0xE040u)|((mode&3u)<<13)|((mode&4u) ? 0x8000u : 0u)|((mode&8u) ? 0x0040u : 0u);
        _mm_setcsr(csr);
        for(U iter=0;iter<4000;++iter) {
            const float scale=kScale[Rng()%5];
            const Orient& oa=kOrient[Rng()%6]; const Orient& ob=kOrient[Rng()%6];
            const Rec a=Make(1,kLens[Rng()%5]*scale,kLens[Rng()%5]*scale,kLens[Rng()%5]*scale,kLens[Rng()%5]*scale,oa.a1,oa.a2,oa.b1,oa.b2);
            const Rec b=Make(1+(Rng()%16==0),kLens[Rng()%5]*scale,kLens[Rng()%5]*scale,kLens[Rng()%5]*scale,kLens[Rng()%5]*scale,ob.a1,ob.a2,ob.b1,ob.b2);
            Cmp(a,b); Cmp(b,a);
            const float th=Rf(0.0f,6.2831853f);
            const Rec c=Make(1,Rf(-10,10)*scale,Rf(-10,10)*scale,Rf(0,4)*scale,Rf(0,4)*scale,std::cos(th),std::sin(th),-std::sin(th),std::cos(th));
            Cmp(a,c); Cmp(c,a);
        }
        for(U iter=0;iter<500;++iter) {   // denormal-scale geometry: DAZ/FTZ change the comparisons
            const float tiny=1.0e-39f*static_cast<float>(1+Rng()%8);
            const Rec a=Aligned(1,tiny*static_cast<float>(Rng()%4),tiny*static_cast<float>(Rng()%4),tiny,tiny);
            const Rec b=Aligned(1,tiny*static_cast<float>(Rng()%4),tiny*static_cast<float>(Rng()%4),tiny*static_cast<float>(1+Rng()%2),tiny);
            Cmp(a,b); Cmp(b,a);
        }
        Cmp(Aligned(1,0,0,2,2),Aligned(1,2,0,2,2));
        Cmp(Aligned(1,0,0,0.1f,0.1f),Aligned(1,0.2f,0,0.1f,0.1f));
        Cmp(Aligned(1,0.1f,0.3f,0.7f,0.9f),Aligned(1,0.8f,0.3f,0.7f,0.9f));
    }
    // exception-unmasked state: the guard must hand every pair (even a plainly disjoint one) to native without doing float work.  Only exact, non-exceptional inputs are used.
    {
        const Rec a=Aligned(1,0,0,2,2), b=Aligned(1,50,0,2,2), t=Aligned(2,0,0,2,2);
        _mm_setcsr(original&~0x1F80u);
        const U farApart=g::Rejects(a.w,b.w), typeMismatch=g::Rejects(a.w,t.w);
        _mm_setcsr(original);
        Require(farApart==0,"disjoint pair is not rejected while SSE exceptions are unmasked");
        Require(typeMismatch==1,"integer type mismatch is still rejected (native returns false before any float work)");
        Require(g::Rejects(a.w,b.w)==1,"the same pair is rejected again with the original MXCSR");
    }
    _mm_setcsr(original);
    Require(total>savedTotal+16*8000,"MXCSR sweeps ran");
}
static void MergeOrder() {
    U merges=0, collections=0;
    for(U iter=0;iter<400;++iter) {
        std::vector<Rec> v;
        const U side=3+Rng()%6, types=1+Rng()%3;
        for(U y=0;y<side;++y) for(U x=0;x<side;++x)
            if(Rng()%10<7) v.push_back(Aligned(1+Rng()%types,static_cast<float>(x),static_cast<float>(y),1.0f,1.0f));
        for(U i=static_cast<U>(v.size());i>1;--i) std::swap(v[i-1],v[Rng()%i]);   // the visit order is part of the result
        std::vector<std::pair<U,U>> logN, logH;
        const std::vector<Rec> outN=MergeAll(v,[](const Rec& a,const Rec& b)->U { return Native(a,b); },logN);
        const std::vector<Rec> outH=MergeAll(v,[](const Rec& a,const Rec& b)->U { return Hooked(a,b); },logH);
        Require(logN==logH,"merge log identical");
        Require(outN.size()==outH.size() && (outN.empty() || !std::memcmp(outN.data(),outH.data(),outN.size()*sizeof(Rec))),"merged records identical");
        merges+=static_cast<U>(logN.size()); ++collections;
    }
    Require(merges>2000 && collections==400,"the lattice collections merge substantially");
}

// ---- redirect
static bool ReadOnlyPage(U va,DWORD protect) { DWORD old; return VirtualProtect(At(va),1,protect,&old)!=0; }
static DWORD Protection(U va) { MEMORY_BASIC_INFORMATION m; VirtualQuery(At(va),&m,sizeof m); return m.Protect; }
static U Rel(const B* site) { U r; std::memcpy(&r,site+1,4); return r; }

static void Redirect() {
    constexpr U kContext=g::kCallSite-11, kPrologue=g::kNative, kExit=g::kNative+0x19, kStock=g::kNative-(g::kCallSite+5);
    B* site=At(g::kCallSite);
    Require(Rel(site)==kStock && kStock==0xEA40u && site[0]==0xE8,"stock call site: E8 40 EA 00 00");
    Require((A(site+1)&3u)==0,"private mapping keeps the displacement dword aligned");
    Require(!g::fallback,"fallback is unpublished before the first install");
    B before[32]; std::memcpy(before,At(kContext),sizeof before);
    Require(g::RemoveRedirect(delta) && std::memcmp(At(kContext),before,sizeof before)==0,"remove without install is a no-op success");
    // every pinned item that differs is refused without a change
    struct Pin { U va; B mask; const char* what; };
    const Pin pins[]={{g::kCallSite,0x01,"call opcode"},{kContext,0x10,"context head first byte"},{g::kCallSite-1,0x01,"context head last operand"},{g::kCallSite+5,0x04,"context tail test"},
                      {g::kCallSite+8,0x20,"context tail jne displacement"},{kPrologue,0x02,"native prologue first byte"},{kPrologue+24,0x08,"native prologue last byte"},
                      {kExit,0x40,"native exit"},{kExit+12,0x01,"native exit ret imm"},{g::kHalf,0x01,"0.5f constant"},{g::kHalf+3,0x01,"0.5f constant top byte"}};
    for(const Pin& p : pins) {
        B* q=At(p.va); q[0]^=p.mask;
        B copy[32]; std::memcpy(copy,At(kContext),sizeof copy);
        Require(!g::InstallRedirect(delta) && std::memcmp(At(kContext),copy,sizeof copy)==0,p.what);
        q[0]^=p.mask;
    }
    for(U foreign : {0u,kStock+1u,kStock^0x100u}) {   // a foreign displacement is refused too
        const U stock=Rel(site); std::memcpy(site+1,&foreign,4);
        Require(!g::InstallRedirect(delta) && Rel(site)==foreign,"install refuses a foreign displacement");
        std::memcpy(site+1,&stock,4);
    }
    Require(g::fallback==0,"refused installs publish nothing");
    Require(std::memcmp(At(kContext),before,sizeof before)==0,"every pin test restored its byte");
    // unaligned delta can never be installed
    Require(!g::InstallRedirect(delta+1) && std::memcmp(At(kContext),before,sizeof before)==0,"misaligned image delta is refused");

    // real install under a read-execute page: the swap lifts and restores the protection
    Require(ReadOnlyPage(g::kCallSite,PAGE_EXECUTE_READ) && Protection(g::kCallSite)==PAGE_EXECUTE_READ,"page set read-execute");
    Require(g::InstallRedirect(delta),"install");
    Require(Protection(g::kCallSite)==PAGE_EXECUTE_READ,"protection restored after install");
    Require(g::fallback==A(At(g::kNative)),"native address published");
    const U target=g::Entry()-(A(site)+5);
    Require(site[0]==0xE8 && Rel(site)==target,"displacement now targets the guard, opcode kept");
    {   // every byte except the 4 displacement bytes is unchanged
        B now[32]; std::memcpy(now,At(kContext),sizeof now);
        for(U i=0;i<sizeof now;++i) { const U va=kContext+i; if(va>=g::kCallSite+1 && va<g::kCallSite+5) continue; Require(now[i]==before[i],"only the displacement changed"); }
    }
    Require(!g::InstallRedirect(delta),"second install refuses");
    BuildStub();
    Require(stubTarget==g::Entry(),"the hooked call reaches the guard entry");
    gGuard=g::Entry();
    HandBuilt();
    Boundaries();
    Lattice();
    Random();
    MergeOrder();
    MxcsrModes();
    // the sweeps are non-trivial: native true, rejected, and non-rejected false pairs all occur in volume
    Require(nativeTrue>5000,"native-true pairs occur");
    Require(rejected>100000,"rejections occur in volume");
    Require(guardedFalse>5000,"non-rejected native-false pairs occur");
    Require(typeRejected>1000,"type-mismatch rejections occur");

    // Remove: a foreign displacement is refused and left alone
    auto Poke=[&](U v) { DWORD old=0,ignored=0; Require(VirtualProtect(site+1,4,PAGE_EXECUTE_READWRITE,&old)!=0,"lift protection for the test write"); std::memcpy(site+1,&v,4); VirtualProtect(site+1,4,old,&ignored); };
    Poke(kStock+0x40u);
    Require(!g::RemoveRedirect(delta) && Rel(site)==kStock+0x40u,"remove refuses a foreign displacement and leaves it");
    Poke(target);
    // the stock displacement was put back by someone else: remove succeeds without a write and the module can install again
    Poke(kStock);
    Require(g::RemoveRedirect(delta) && Rel(site)==kStock,"remove succeeds when the stock displacement is already back");
    Require(g::InstallRedirect(delta) && Rel(site)==target,"reinstall after an external restore");
    Require(g::RemoveRedirect(delta) && Rel(site)==kStock && std::memcmp(At(kContext),before,sizeof before)==0 && Protection(g::kCallSite)==PAGE_EXECUTE_READ,"remove restores the stock bytes and the protection");
    Require(g::RemoveRedirect(delta),"remove is idempotent");
    BuildStub();
    Require(stubTarget==A(At(g::kNative)),"after remove the call site reaches the native predicate");
    Require(g::fallback==A(At(g::kNative)),"the fallback stays valid after remove (a thread still inside the guard finishes natively)");
    Cmp(Aligned(1,0,0,2,2),Aligned(1,2,0,2,2));
    Cmp(Aligned(1,0,0,2,2),Aligned(1,9,9,2,2));
}

int main(int argc,char** argv) {
    if(argc<2) { std::fprintf(stderr,"usage: native_terrain_merge_guard_oracle <Napoleon_patched.exe>\n"); return 2; }
    Map(argv[1]);
    gNative=A(At(g::kNative));
    Redirect();
    std::printf("native_terrain_merge_guard_oracle: %u checks passed (%u pairs, %u native-true, %u rejected, %u guarded-false)\n",checks,total,nativeTrue,rejected,guardedFalse);
    return 0;
}

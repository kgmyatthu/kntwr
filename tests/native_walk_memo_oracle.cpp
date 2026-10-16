// Executes the real gather/walk/polygon routines in a private relocated owned
// image against the production clones and value-key memo. No running game or
// installed file is modified. Only private loader/heap boundaries are supplied.
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
#include "ntw2_clones.h"
#include "ntw2_runtime.h"
#include "ntw2_walk_memo.h"
#pragma comment(lib,"bcrypt.lib")
#pragma fenv_access(on)
using U=uint32_t;
using B=unsigned char;
static_assert(sizeof(void*)==4,"owned x86 oracle");
extern "C" unsigned long _tls_index;
__declspec(thread) static volatile U tlsPad[32];
static B* image;
static U delta, checks;
static std::vector<U> heapEvents;
static void Require(bool ok,const char* what) { ++checks; if(!ok) { std::fprintf(stderr,"FAIL %s\n",what); std::exit(1); } }
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static B* At(U va) { return reinterpret_cast<B*>(va+delta); }
template<class T> static U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static void Put(void* p,U offset,U v) { std::memcpy(static_cast<B*>(p)+offset,&v,4); }
static U Bits(float f) { U u; std::memcpy(&u,&f,4); return u; }
static void Jump(U va,U target) { B* p=At(va); p[0]=0xb8; Put(p,1,target); p[5]=0xff; p[6]=0xe0; }
static void* __cdecl Allocate(size_t bytes,void*) {
    heapEvents.push_back(static_cast<U>(bytes));
    void* p=std::malloc(bytes ? bytes : 1); Require(p!=nullptr,"private heap allocation"); return p;
}
static void __cdecl Release(void* p) { heapEvents.push_back(0xffffffffu); std::free(p); }
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
    image=static_cast<B*>(VirtualAlloc(nullptr,nt->OptionalHeader.SizeOfImage,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE));
    Require(image!=nullptr,"private image mapping"); delta=A(image)-0x400000;
    std::memcpy(image,bytes.data(),nt->OptionalHeader.SizeOfHeaders);
    auto sections=IMAGE_FIRST_SECTION(nt);
    for(U i=0;i<nt->FileHeader.NumberOfSections;++i)
        std::memcpy(image+sections[i].VirtualAddress,bytes.data()+sections[i].PointerToRawData,
                    std::min(sections[i].SizeOfRawData,sections[i].Misc.VirtualSize));
    Require(RelocateNativeImage(image,nt->OptionalHeader.SizeOfImage,
        reinterpret_cast<IMAGE_NT_HEADERS32*>(image+dos->e_lfanew),delta),"relocation");
    Jump(0xff7f20,Fn(&Allocate)); Jump(0xff7ef0,Fn(&Release));
    Put(At(0x1841bb8),0,_tls_index); tlsPad[0]=0;
    // Bypass only static-guard registration, not the original gather/walk body.
    Put(At(0x15bbf5c),0,0x80000000u); Put(At(0x15afdb8),0,0x80000000u);
    Require(FlushInstructionCache(GetCurrentProcess(),image,nt->OptionalHeader.SizeOfImage)!=0,"flush image");
}
struct Vector { U tag,capacity,count,data; };
static void Clear(Vector& v) { std::free(reinterpret_cast<void*>(v.data)); v={}; }
static Vector& Scratch() { return *reinterpret_cast<Vector*>(At(0x15bbf4c)); }
static Vector& Interests() { return *reinterpret_cast<Vector*>(At(0x15afda8)); }
static std::vector<U> List(const Vector& v) {
    if(!v.count) return {};
    const U* p=reinterpret_cast<const U*>(v.data); return {p,p+v.count};
}
struct Node { U v[12]; };
struct Interest { U kind,unused1,unused2,owner,unused4,next; };
struct Owner { U v[9]; };
struct Vertex { U v[13]; };
static B root[0x28200],model[0x100],gatherOwner[0x40],tree[0x30],manager[0x30],path[4];
static Node nodes[5];
static Interest interests[12];
static Owner owners[12];
static Vertex polygon[65];
static U active[2];
static U shape[18];
static void Shape(float x,float y,float width,float height,U mode=1) {
    std::memset(shape,0,sizeof(shape)); shape[1]=Bits(x); shape[2]=Bits(y);
    shape[4]=Bits(width); shape[5]=Bits(height); shape[6]=Bits(1); shape[9]=Bits(1);
    shape[16]=mode; shape[17]=Bits(0);
}
static void Polygon(U n,float shift) {
    for(U i=0;i<n;++i) {
        polygon[i]={}; polygon[i].v[2]=A(&polygon[(i+1)%n]);
        // A rectangle with repeated edge vertices exercises ordering/duplicates.
        static const float xy[4][2]={{-2,-2},{2,-2},{2,2},{-2,2}};
        polygon[i].v[3]=Bits(xy[i%4][0]+shift); polygon[i].v[4]=Bits(xy[i%4][1]);
    }
}
static void Fixture() {
    Put(path,0,A(root)); Put(root,8,A(model)); Put(model,0xbc,A(gatherOwner));
    Put(gatherOwner,0x24,A(tree)); Put(tree,0x1c,A(nodes));
    Put(root,0x281ac,A(manager)); Put(manager,0x18,1);
    // Real image predicate tails supply active/inactive input objects; all
    // filtering and dispatch itself still runs through original 0x6DC9A0.
    active[0]=A(At(0x6dca08)); active[1]=A(At(0x6dca05));
    for(U i=0;i<5;++i) {
        nodes[i]={}; nodes[i].v[1]=Bits(-100); nodes[i].v[3]=Bits(-100);
        nodes[i].v[4]=Bits(100); nodes[i].v[6]=Bits(100);
        if(i) nodes[0].v[7+i]=A(&nodes[i]);
    }
    for(U i=0;i<12;++i) {
        owners[i]={}; owners[i].v[2]=A(polygon); owners[i].v[3]=A(active);
        owners[i].v[7]=1; owners[i].v[8]=Bits(1);
        interests[i]={0x10,0,0,A(&owners[i]),0,0};
        if(i%3) interests[i-1].next=A(&interests[i]);
        else nodes[1+i/3].v[7]=A(&interests[i]);
    }
}
using Gather=void(__fastcall*)(void*,void*,Vector*,const float*,U);
static Gather gatherUnderTest;
static void __fastcall GatherBound(void* owner,void*,Vector* out,const float* bounds,U mask) {
    gatherUnderTest(owner,nullptr,out,bounds,mask);
}
using Walk=B(__fastcall*)(void*,void*,U*);
struct __declspec(align(16)) Fx { B bytes[512]; };
static void ResetFp(U csr=0x1f80) { __asm { fninit } _mm_setcsr(csr); }
static void CheckKernel(ntw2_walk_memo::Kernel native,U csr) {
    Fx expected,actual;
    ResetFp(csr); const B a=native(shape,nullptr,polygon); _fxsave(expected.bytes);
    ResetFp(csr); const B b=ntw2_walk_memo::kernel(shape,nullptr,polygon); _fxsave(actual.bytes);
    Require(a==b,"kernel AL result");
    // Control, status (including TOP and sticky flags), tag and MXCSR are
    // computationally observable. Empty x87 payloads/FIP/FDP and volatile XMM
    // registers are not return values of this AL-returning x86 predicate.
    Require(!std::memcmp(expected.bytes,actual.bytes,5),"x87 controls/status/tags");
    Require(!std::memcmp(expected.bytes+24,actual.bytes+24,4),"MXCSR flags/control");
}
int main(int argc,char** argv) {
    if(argc!=2) { std::fprintf(stderr,"usage: native_walk_memo_oracle Napoleon.exe\n"); return 2; }
    Map(argv[1]);
    ntw2_clone_set clones={}; U bindings[NTW2_BIND_COUNT];
    // Unreached bindings are valid image addresses, never executed by these fixtures.
    for(U& binding:bindings) binding=A(At(0x6dca08));
    bindings[NTW2_BIND_SITE_CALL_42]=A(At(0x809110));
    bindings[NTW2_BIND_SITE_CALL_43]=A(At(0x6dc9a0));
    bindings[NTW2_BIND_SITE_CALL_44]=Fn(&ntw2_walk_memo::kernel);
    bindings[NTW2_BIND_SITE_CALL_45]=A(At(0x808f90));
    bindings[NTW2_BIND_SITE_CALL_41]=Fn(&GatherBound);
    U detail=0; Require(ntw2_build_clones(A(image),bindings,&clones,&detail)==0,"production clone source pins");
    auto nativeKernel=reinterpret_cast<ntw2_walk_memo::Kernel>(At(0x80dcf0));
    ntw2_walk_memo::configure(nativeKernel,reinterpret_cast<U*>(At(0x1318038)),reinterpret_cast<U*>(At(0x1318048)));
    auto gather=reinterpret_cast<Gather>(At(0x804dd0));
    auto gatherClone=reinterpret_cast<Gather>(clones.entries[NTW2_CLONE_AI_GATHER]);
    gatherUnderTest=gatherClone;
    auto walk=reinterpret_cast<Walk>(At(0x7f1d40));
    auto walkClone=reinterpret_cast<Walk>(clones.entries[NTW2_CLONE_AI_WALK]);
    Fixture(); ntw2_walk_memo::begin();
    for(U i=0;i<160;++i) {
        Polygon(4,static_cast<float>(i%7)); Shape(static_cast<float>(i%11)-5,0,1+static_cast<float>(i%5),3,1+i%2);
        owners[i%12].v[3]=A(active+(i%2)); // same pointers/counts, changed filter input
        interests[(i+1)%12].kind=(i%3) ? 0x10 : 0x20; // mask rejects before virtual lookup
        nodes[2].v[7]=(i%4==0) ? nodes[1].v[7] : A(&interests[3]); // repeated interest pointers retain duplicates/order
        const float boxes[3][4]={{-10,-10,10,10},{-200,-200,200,200},{200,200,300,300}};
        const float* bounds=boxes[i%3]; // partial subtree / contained subtree / no candidate
        Vector a={},b={}; Clear(Scratch()); heapEvents.clear();
        gather(gatherOwner,nullptr,&a,bounds,0x10); auto events=heapEvents; auto list=List(a);
        Require(Scratch().count==0,"native gather clears scratch count"); Clear(Scratch()); heapEvents.clear();
        gatherClone(gatherOwner,nullptr,&b,bounds,0x10);
        Require(List(b)==list,"bit-identical gather list and order");
        Require(a.capacity==b.capacity && heapEvents==events,"gather allocation sequence and capacity");
        Require(Scratch().count==0,"clone gather clears scratch count"); Clear(a); Clear(b);
        Clear(Scratch()); Clear(Interests()); heapEvents.clear(); ResetFp();
        const B wa=walk(path,nullptr,shape); events=heapEvents; const U capacity=Interests().capacity;
        Clear(Scratch()); Clear(Interests()); heapEvents.clear(); ResetFp();
        const B wb=walkClone(path,nullptr,shape);
        Require(wa==wb,"original walk vs memoized clone result");
        Require(Interests().count==0 && Interests().capacity==capacity && heapEvents==events,"walk allocation/reset effects");
        heapEvents.clear(); ResetFp(); const B warmA=walk(path,nullptr,shape); events=heapEvents;
        heapEvents.clear(); ResetFp(); const B warmB=walkClone(path,nullptr,shape);
        Require(warmA==warmB && heapEvents==events,"warm walk preserves allocation-visible effects");
        CheckKernel(nativeKernel,0x1f80); CheckKernel(nativeKernel,0x1f80); // guaranteed warm value-key lookup
        CheckKernel(nativeKernel,0x3f80); CheckKernel(nativeKernel,0x3f80); // changed rounding mode
        polygon[0].v[3]^=0x80000000u; CheckKernel(nativeKernel,0x1f80); // value mutation without generation change
    }
    Shape(0,0,2,2); Polygon(65,0); CheckKernel(nativeKernel,0x1f80); // bounded-key fallback
    ntw2_walk_memo::end(); CheckKernel(nativeKernel,0x1f80); // out-of-scope native path
    ntw2_walk_memo::begin(); Polygon(4,0); CheckKernel(nativeKernel,0x1f80); CheckKernel(nativeKernel,0x1f80);
    ntw2_walk_memo::end();
    Require(ntw2_walk_memo::counters[1]>0 && ntw2_walk_memo::counters[2]>0 && ntw2_walk_memo::counters[3]>0,"hit/miss/fallback coverage");
    Clear(Scratch()); Clear(Interests());
    std::printf("walk memo: %u checks; hits=%u misses=%u fallback=%u\n",checks,ntw2_walk_memo::counters[1],ntw2_walk_memo::counters[2],ntw2_walk_memo::counters[3]);
    return 0;
}

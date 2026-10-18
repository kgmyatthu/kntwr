// Owned-image differential oracle for the PRODUCT-generated ballistic clones, not the analysis clone blob.
// Usage: native_ballistics_runtime_integration.exe <Napoleon.exe> [worlds=N] [workers=N] [seed=N]
// No external DLL/kit is needed: the production nqc/nbc/pool/helper objects are linked directly. The six
// worker entries are exactly StartModules' image leaves + NTW2_CLONE_UNIT_HIT. All clones come from
// ntw2_build_clones; no generated code or native collision instruction is replaced with a mock.
//
// Queries compare native return, all defined result bytes, fixture writes, callback order/visited state,
// FP controls and static cleanup. Coverage includes cached positive/negative results, unsupported getters,
// consumed-input mutation, world identity rejection, replacement worlds, stopped hooks and restart.
// The actual 0x6F6BC0 manager and its generated clone compare three successive native ticks, including
// prefix commits, skipped items, expired-item swap removal/free lists and pending appends. Both modules
// use the SAME host-owned ntw_pool; manager work also runs while nqc is stopped. No sleep/yield ballast.
//
// Explicit boundary: manager fixtures take the original out-of-bounds tail exit (or the original +0x41
// skip exit). Query/wrapper results are exercised separately. Full manager -> query -> damage/effects
// needs a relocatable battle capture containing model+0x94 effect owner/vtables, +0x98 hit resolver,
// +0x9C terrain/heightfield, +0xA0 material grid, +0xB0 collision holder, +0xBC/+0xC0 scene managers,
// projectile definitions/owners and the reachable unit/effect/RNG state. No fake terrain/effects are used.
// Host TickGate/BallisticGate epoch and slot publication belong to ntw2_runtime.cpp and are not linked
// into this oracle. We verify the manager-to-query clone seams, not a live battle tick or its host gates.
//
// CMake (tests/CMakeLists.txt):
// ntw2_harness(native_ballistics_runtime_integration STD 20 FP strict
//   SOURCES native_ballistics_runtime_integration.cpp ../src/ntw2_clones.cpp
//   OBJECTS ntw2_ballistics_query_cache ntw2_ballistics_collision ntw2_worker_dispatch ntw2_ballistics_helpers
//   INCLUDES ../src LIBS bcrypt)
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <emmintrin.h>
#include <malloc.h>
#include <algorithm>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include "native_image_relocation.h"
#include "native_ballistics_query_cache.h"
#include "native_ballistics_abi.h"
#include "native_worker_dispatch.h"
#include "clones/ntw2_clones.h"
#pragma comment(lib, "bcrypt.lib")
#pragma fenv_access(on)
static_assert(sizeof(void*) == 4, "native x86 only");
using U = uint32_t;
using B = uint8_t;
extern "C" {
extern unsigned long _tls_index;
U __stdcall nqc_initialize(void*);
U __stdcall nqc_stop(void*);
U __fastcall nqc_query_hook(void*, void*, U, U, U, U, U, U, U, U, U);
U __fastcall nqc_unit_hook(void*, void*, const float*, U, float*, U, U);
void nqc_gather_hook();
extern volatile U nqc_state[NQC_STATE_WORDS];
ntw_u32 __stdcall ntw_pool_init(ntw_pool*, const ntw_pool_config*);
ntw_u32 __stdcall ntw_pool_shutdown(ntw_pool*);
ntw_u32 __stdcall ntw_pool_worker_start(void*);
void __stdcall ntw_pool_dispatch(ntw_u32, ntw_u32, ntw_u32, void*);
void __fastcall bal_stage(void*, bal_job*);
void __fastcall bal_step(void*, bal_job*);
void __fastcall bal_worker(bal_job*, bal_u32);
}
__declspec(thread) static volatile int tlsPad[32];
[[noreturn]] static void Fail(const char* fmt, ...) {
    std::fputs("FAIL: ", stderr);
    va_list ap; va_start(ap, fmt); std::vfprintf(stderr, fmt, ap); va_end(ap);
    std::fputc('\n', stderr); std::exit(1);
}
#define REQUIRE(c, ...) do { if (!(c)) Fail(__VA_ARGS__); } while (0)
template<class T> static T Get(const void* p, size_t off) { T x; std::memcpy(&x, static_cast<const B*>(p)+off, sizeof x); return x; }
template<class T> static void Put(void* p, size_t off, T x) { std::memcpy(static_cast<B*>(p)+off, &x, sizeof x); }
static U Addr(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> static U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static void* Ptr(U p) { return reinterpret_cast<void*>(static_cast<uintptr_t>(p)); }
static U delta;
static B* image;
static U Native(U va) { return va+delta; }
static B* Image(U va) { return static_cast<B*>(Ptr(Native(va))); }
static uint64_t Hash(const void* p, size_t n, uint64_t h=1469598103934665603ull) {
    auto b=static_cast<const B*>(p);
    for (size_t i=0;i<n;++i) h=(h^b[i])*1099511628211ull;
    return h;
}
static uint16_t Cw() { uint16_t w; __asm { fnstcw w } return w; }
static uint16_t Sw() { uint16_t w; __asm { fnstsw w } return w; }
static void SetFp(uint16_t cw=0x27f, U csr=0x1f80) { __asm { fldcw cw } _mm_setcsr(csr); }
static void* __cdecl Allocate(size_t n, void*) {
    void* p=_aligned_malloc(n ? n : 1,16);
    REQUIRE(p,"native heap allocation failed");
    return p;
}
static void __cdecl Deallocate(void* p) { _aligned_free(p); }
static void Jump(U va, U target) {
    B* p=Image(va); p[0]=0xb8; Put<U>(p,1,target); p[5]=0xff; p[6]=0xe0;
}
static void MapImage(const char* path) {
    FILE* f=std::fopen(path,"rb"); REQUIRE(f,"cannot open image: %s",path);
    REQUIRE(std::fseek(f,0,SEEK_END)==0,"seek image");
    long n=std::ftell(f); REQUIRE(n>0 && n<(256L<<20),"invalid image file size");
    REQUIRE(std::fseek(f,0,SEEK_SET)==0,"rewind image");
    std::vector<B> bytes(static_cast<size_t>(n));
    REQUIRE(std::fread(bytes.data(),1,bytes.size(),f)==bytes.size(),"read image"); std::fclose(f);
    BCRYPT_ALG_HANDLE alg=nullptr; B digest[32];
    REQUIRE(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)==0,"SHA provider");
    REQUIRE(BCryptHash(alg,nullptr,0,bytes.data(),static_cast<ULONG>(bytes.size()),digest,32)==0,"SHA image");
    BCryptCloseAlgorithmProvider(alg,0);
    char hex[65]; for (U i=0;i<32;++i) std::snprintf(hex+2*i,3,"%02x",digest[i]);
    REQUIRE(std::strcmp(hex,"13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4")==0,"unsupported image SHA-256: %s",hex);
    const auto* dos=reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
    const auto* nt=reinterpret_cast<const IMAGE_NT_HEADERS32*>(bytes.data()+dos->e_lfanew);
    REQUIRE(nt->OptionalHeader.ImageBase==0x400000,"preferred image base");
    image=static_cast<B*>(VirtualAlloc(nullptr,nt->OptionalHeader.SizeOfImage,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE));
    REQUIRE(image,"map private image"); delta=Addr(image)-0x400000;
    std::memcpy(image,bytes.data(),nt->OptionalHeader.SizeOfHeaders);
    const auto* s=IMAGE_FIRST_SECTION(nt);
    for (U i=0;i<nt->FileHeader.NumberOfSections;++i)
        std::memcpy(image+s[i].VirtualAddress,bytes.data()+s[i].PointerToRawData,std::min(s[i].SizeOfRawData,s[i].Misc.VirtualSize));
    REQUIRE(RelocateNativeImage(image,nt->OptionalHeader.SizeOfImage,reinterpret_cast<IMAGE_NT_HEADERS32*>(image+dos->e_lfanew),delta),"image relocation");
    // These are private loader/allocator seams only; no source span hashed by the clone/cache is changed.
    Jump(0xff7f20,Fn(&Allocate)); Jump(0xff7ef0,Fn(&Deallocate));
    Put<U>(Image(0x1841bb8),0,_tls_index);
    Put<U>(Image(0x1307178),0,Fn(&GetCurrentThreadId));
    tlsPad[0]=0;
    REQUIRE(FlushInstructionCache(GetCurrentProcess(),image,nt->OptionalHeader.SizeOfImage),"flush private image");
}
static const U bitsets[]={0x14d0a80,0x14d4ab0,0x14d8ae0};
static const U wrapperBitsets[]={0x15afec0,0x15b3ef0,0x15b7f20};
static void InitStatics() {
    using Ctor=void*(__thiscall*)(void*);
    auto bs=reinterpret_cast<Ctor>(Image(0x61a760));
    auto vec=reinterpret_cast<Ctor>(Image(0x4549f0));
    for (U b=0;b<2;++b) {
        for (U va:bitsets) bs(Image(va)+b*0x2014);
        for (U va:wrapperBitsets) bs(Image(va)+b*0x2014);
        vec(Image(0x14dcb0c)+b*16); vec(Image(0x15afe98)+b*16);
    }
    const U guards[]={0x14d4aa8,0x14d8ad8,0x14dcb08,0x14dcb2c,0x15afeb8,0x15b3ee8,0x15b7f18,0x15bbf48,0x15afe94};
    for (U va:guards) Put<U>(Image(va),0,0x80000000u);
}
static void CleanStatics() {
    for (U b=0;b<2;++b) {
        for (const U* bases:{bitsets,wrapperBitsets}) for (U i=0;i<3;++i) {
            const B* p=Image(bases[i])+b*0x2014;
            for (U j=0;j<0x2004;j+=4) REQUIRE(Get<U>(p,j)==0,"visited state leaked: %08X +%X",bases[i],j);
            REQUIRE(Get<U>(p,0x200c)==0,"dirty list leaked");
        }
        REQUIRE(Get<U>(Image(0x14dcb0c)+b*16,8)==0,"query cell vector leaked");
        REQUIRE(Get<U>(Image(0x15afe98)+b*16,8)==0,"wrapper cell vector leaked");
    }
}
static uint64_t VisitedHash() {
    const B* p=Image(bitsets[0]);
    uint64_t h=Hash(p,0x2004); U n=Get<U>(p,0x200c);
    h=Hash(&n,sizeof n,h); REQUIRE(n<=0x10000,"dirty-list count");
    if (n) h=Hash(Ptr(Get<U>(p,0x2010)),n*2,h);
    p=Image(0x14dcb0c); n=Get<U>(p,8); h=Hash(&n,sizeof n,h);
    REQUIRE(n<=0x10000,"gathered cells count");
    return n ? Hash(Ptr(Get<U>(p,12)),n*8,h) : h;
}
struct Arena {
    B* mem; size_t used=0; static constexpr size_t capacity=2u<<20;
    std::vector<B> saved;
    Arena() : mem(static_cast<B*>(VirtualAlloc(nullptr,capacity,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE))) { REQUIRE(mem,"fixture arena"); }
    ~Arena() { VirtualFree(mem,0,MEM_RELEASE); }
    Arena(const Arena&)=delete;
    Arena& operator=(const Arena&)=delete;
    B* Take(size_t n) {
        used=(used+15)&~size_t(15); REQUIRE(n<=capacity-used,"fixture arena full");
        B* p=mem+used; used+=n; return p;
    }
    void Reset() { std::memset(mem,0,used); used=0; saved.clear(); }
    void Save() { saved.assign(mem,mem+used); }
    void Restore() { std::memcpy(mem,saved.data(),saved.size()); }
};
struct Segment { U type; float p[6]; };
struct Entry { U kind; uint16_t id,pad; U aux,object,pad2,next; };
static_assert(sizeof(Entry)==0x18 && sizeof(Segment)==28,"native fixture layouts");
struct Output { U unused,capacity,count,data; };
static ntw2_clone_set clones{};
alignas(64) static ntw_pool pool{};
static bal_job job{};
static bal_record records[2048];
static U boundRoot,boundModel;
static U pureTable[16],opaqueTable[16];
static void __declspec(naked) UnexpectedBinding() { __asm { int 3 } }
static void BuildClones() {
    U bindings[NTW2_BIND_COUNT];
    for (U& b:bindings) b=Fn(&UnexpectedBinding); // unrelated emitted clones must never be invoked
    bindings[NTW2_BIND_BAL_STAGE]=Fn(&bal_stage);
    bindings[NTW2_BIND_BAL_STEP]=Fn(&bal_step);
    bindings[NTW2_BIND_BAL_JOB]=Addr(&job);
    bindings[NTW2_BIND_QUERY_GATHER]=Fn(&nqc_gather_hook);
    bindings[NTW2_BIND_QUERY_UNIT]=Fn(&nqc_unit_hook);
    bindings[NTW2_BIND_QUERY]=Fn(&nqc_query_hook);
    U detail=0; U e=ntw2_build_clones(Addr(image),bindings,&clones,&detail);
    REQUIRE(e==0,"ntw2_build_clones error %u detail %08X",e,detail);
    const auto call=[](U field,U target) {
        REQUIRE(Get<B>(Ptr(field-1),0)==0xe8 && field+4+Get<U>(Ptr(field),0)==target,"generated call seam %08X -> %08X",field,target);
    };
    call(clones.entries[NTW2_CLONE_QUERY]+0x639581-0x6392c0+1,Fn(&nqc_gather_hook));
    call(clones.entries[NTW2_CLONE_QUERY]+0x639699-0x6392c0+1,Fn(&nqc_unit_hook));
    call(clones.entries[NTW2_CLONE_QUERY_WRAPPER]+0x84,Fn(&nqc_query_hook));
    call(clones.entries[NTW2_CLONE_BAL_MANAGER]+0x48,Fn(&bal_stage));
    call(clones.entries[NTW2_CLONE_BAL_MANAGER]+0x61,clones.entries[NTW2_CLONE_BAL_STEP]);
    // BAL_STEP is a tail jmp, not a call.
    const U step=clones.entries[NTW2_CLONE_BAL_STEP];
    REQUIRE(Get<B>(Ptr(step),5)==0xe9 && step+10+Get<U>(Ptr(step),6)==Fn(&bal_step),"generated manager step tail seam");
    REQUIRE(Get<U>(Ptr(step),1)==Addr(&job),"generated manager job binding");
    call(clones.entries[NTW2_CLONE_BAL_ITEM]+0x659,clones.entries[NTW2_CLONE_QUERY_WRAPPER]);
    const U table=clones.entries[NTW2_CLONE_QUERY_TABLE];
    REQUIRE(Get<U>(Ptr(clones.entries[NTW2_CLONE_QUERY]),0x639661-0x6392c0+3)==table,"private query jump table reference");
    const U targets[]={0x639668,0x639670,0x639670,0x639668};
    for (U i=0;i<4;++i) REQUIRE(Get<U>(Ptr(table),i*4)==clones.entries[NTW2_CLONE_QUERY]+targets[i]-0x6392c0,"private query table target");
    job.abi=BAL_ABI_VERSION; job.capacity=2048; job.records=records;
    job.prefix_entry=clones.entries[NTW2_CLONE_BAL_PREFIX];
    job.orig_item=clones.entries[NTW2_CLONE_BAL_ITEM];
    job.tail_va=job.orig_item+NTW2_BAL_ITEM_TAIL_OFFSET; job.one_ptr=Native(0x1318048);
    job.dispatch=Fn(&ntw_pool_dispatch); job.dispatch_user=Addr(&pool);
    job.min_parallel=64; job.chunk_items=32; job.worker_entry=Fn(&bal_worker);
}
static void StartPool(U workers) {
    ntw_pool_config c{}; c.abi=NTW_POOL_ABI; c.workers=workers;
    c.api.create_event=Fn(&CreateEventW); c.api.close_handle=Fn(&CloseHandle);
    c.api.set_event=Fn(&SetEvent); c.api.wait_single=Fn(&WaitForSingleObject);
    c.api.create_thread=Fn(&CreateThread); c.api.worker_entry=Fn(&ntw_pool_worker_start);
    REQUIRE(ntw_pool_init(&pool,&c)==NTW_POOL_OK,"host pool initialization");
}
static void StartCache(U root,U model,U capacity=8192) {
    nqc_config c={NQC_ABI,sizeof(c),delta,root,model,capacity,32,Fn(&ntw_pool_dispatch),Addr(&pool),
        clones.entries[NTW2_CLONE_QUERY],Native(0x10e8500),Native(0x10e7030),Native(0x10e83e0),Native(0x5db450),
        clones.entries[NTW2_CLONE_UNIT_HIT],Native(0x809c00)};
    U e=nqc_initialize(&c); REQUIRE(e==0,"cache start class=%u detail=%X",NQC_ERR_CLASS(e),NQC_ERR_DETAIL(e));
    REQUIRE(nqc_state[NQC_S_ENABLED] && !nqc_state[NQC_S_BUSY] && !nqc_state[NQC_S_OWNER_THREAD],"cache start state");
    boundRoot=root; boundModel=model;
}
static void StopCache() {
    REQUIRE(nqc_stop(nullptr)==NQC_OK,"cache stop");
    REQUIRE(!nqc_state[NQC_S_ENABLED] && !nqc_state[NQC_S_BUSY] && !nqc_state[NQC_S_OWNER_THREAD],"cache stop state");
    REQUIRE(pool.state==NTW_POOL_S_READY,"cache stopped its host-owned pool");
}
enum Action { None, MutateUnit, StopInGetter };
struct World {
    Arena a;
    B *root=nullptr,*model=nullptr,*grid=nullptr,*holder=nullptr;
    Segment *segment=nullptr,*alt=nullptr;
    std::vector<B*> units;
    Action action=None;
    U stop=1,mode=0,mask=8;
    float extra=0;
};
static World* currentWorld;
static Output* currentOutput;
static U ownerThread;
static bool hooked;
static U stopResult;
static bool acted;
static std::vector<U> callbackLog;
static U __fastcall OpaqueGetter(B* unit,void*) {
    REQUIRE(GetCurrentThreadId()==ownerThread,"opaque native getter executed on worker");
    const uint64_t h=VisitedHash();
    callbackLog.push_back(Get<U>(unit,0x74)); callbackLog.push_back(currentOutput->count);
    callbackLog.push_back(static_cast<U>(h)); callbackLog.push_back(static_cast<U>(h>>32));
    Put<U>(unit,0x64,Get<U>(unit,0x64)+1);
    if (!acted && currentWorld->action!=None) {
        acted=true;
        if (currentWorld->action==MutateUnit) {
            // The first native getter changes a later already-snapshotted candidate from a hit into a miss.
            Put<float>(currentWorld->units.back(),0x48,50.0f);
        } else if (hooked) stopResult=nqc_stop(nullptr);
    }
    return 0;
}
static U randomState;
static U Random() { randomState^=randomState<<13; randomState^=randomState>>17; randomState^=randomState<<5; return randomState; }
static void MakeWorld(World& w,U n,U variant,bool missOnly=false) {
    w.a.Reset(); w.units.clear(); w.action=None; w.stop=1; w.mode=0; w.mask=8; w.extra=0;
    w.root=w.a.Take(0x40); w.model=w.a.Take(0x200); w.grid=w.a.Take(0x60); w.holder=w.a.Take(0x2900);
    B* thread=w.a.Take(0x20); B* heads=w.a.Take(16*16*4);
    B* mgr1=w.a.Take(0x40); B* mgr2=w.a.Take(0x40);
    Put<U>(w.root,8,Addr(w.model)); Put<U>(w.model,0,Addr(w.root)); Put<U>(w.model,0xa4,Addr(w.grid));
    Put<U>(w.model,0xbc,Addr(mgr1)); Put<U>(w.model,0xc0,Addr(mgr2)); Put<U>(mgr1,0,Addr(thread));
    Put<U>(w.holder,0,Addr(w.root)); Put<U>(w.model,0xb0,Addr(w.holder));
    Put<U>(thread,4,GetCurrentThreadId());
    Put<U>(w.grid,0,Addr(heads)); Put<U>(w.grid,8,4); Put<U>(w.grid,12,16); Put<U>(w.grid,20,15);
    Put<float>(w.grid,0x20,4.0f); Put<float>(w.grid,0x24,0.25f);
    Put<float>(w.grid,0x28,-1e5f); Put<float>(w.grid,0x2c,-1e5f);
    Put<float>(w.grid,0x30,1e5f); Put<float>(w.grid,0x34,1e5f); Put<U>(w.grid,0x38,Addr(thread));
    w.segment=reinterpret_cast<Segment*>(w.a.Take(sizeof(Segment)));
    *w.segment={2,{8.25f,1.0f,8.5f,11.75f,1.0f,8.5f}};
    w.alt=reinterpret_cast<Segment*>(w.a.Take(sizeof(Segment))); *w.alt=*w.segment;
    Entry* last=nullptr;
    for (U i=0;i<n;++i) {
        B* u=w.a.Take(0x80); w.units.push_back(u);
        Put<U>(u,0,Addr(pureTable)); Put<B>(u,0x30,1); Put<U>(u,0x34,0x18);
        Put<float>(u,0x48,9.0f+static_cast<float>(Random()%200)*0.01f);
        Put<float>(u,0x4c,0.0f); Put<float>(u,0x50,missOnly || (i%3==1) ? 11.0f : 8.5f);
        Put<float>(u,0x54,3.0f); Put<float>(u,0x58,0.25f+static_cast<float>(variant%3)*0.05f);
        Put<U>(u,0x74,i);
        auto* e=reinterpret_cast<Entry*>(w.a.Take(sizeof(Entry))); e->kind=8;
        e->id=static_cast<uint16_t>((i*31u+variant*17u)&0xffffu); e->object=Addr(u);
        if (last) last->next=Addr(e); else Put<U>(heads,((2u<<4)+2)*4,Addr(e));
        last=e;
        // Repeated entries use the same native visited id; no duplicate hit may leak through.
        if ((i%17)==0) {
            auto* duplicate=reinterpret_cast<Entry*>(w.a.Take(sizeof(Entry))); *duplicate=*e;
            last->next=Addr(duplicate); last=duplicate;
        }
    }
    // Last candidate is a guaranteed hit before the consumed-input mutation.
    if (!missOnly && n) Put<float>(w.units.back(),0x50,8.5f);
}
struct Result {
    B result=0;
    uint16_t cw=0,sw=0;
    U csr=0,stopCode=0xffffffffu;
    std::vector<B> outputs,arena;
    std::vector<U> log;
    U hits=0,fallbacks=0,changed=0,preparations=0;
};
enum Route { Original, Hook, WrapperOriginal, WrapperClone };
static Result RunQuery(World& w,Route route,uint16_t cw=0x27f,U csr=0x1f80) {
    w.a.Restore(); callbackLog.clear(); acted=false; stopResult=0xffffffffu;
    currentWorld=&w; ownerThread=GetCurrentThreadId(); hooked=route==Hook || route==WrapperClone;
    Output out{}; currentOutput=&out;
    U hits=nqc_state[NQC_S_CACHE_HITS],fall=nqc_state[NQC_S_FALLBACKS],changed=nqc_state[NQC_S_CHANGED],prep=nqc_state[NQC_S_PREPARATIONS];
    Result r; SetFp(cw,csr);
    if (route==WrapperOriginal || route==WrapperClone) {
        using Wrap=void(__thiscall*)(void*,void*,const Segment*,U,U,U,U);
        const U fn=route==WrapperOriginal ? Native(0x53c060) : clones.entries[NTW2_CLONE_QUERY_WRAPPER];
        reinterpret_cast<Wrap>(Ptr(fn))(w.holder,&out,w.segment,w.mode,w.stop,w.mask,0);
    } else if (route==Original) {
        using Query=B(__thiscall*)(void*,void*,const Segment*,U,U,const Segment*,U,void*,U,float);
        r.result=reinterpret_cast<Query>(Image(0x6392c0))(w.grid,&out,w.segment,w.stop,w.mask,w.alt,w.mode,nullptr,0,w.extra);
    } else {
        r.result=static_cast<B>(nqc_query_hook(w.grid,nullptr,Addr(&out),Addr(w.segment),w.stop,w.mask,Addr(w.alt),w.mode,0,0,Get<U>(&w.extra,0)));
    }
    r.cw=Cw(); r.sw=Sw(); r.csr=_mm_getcsr(); SetFp();
    REQUIRE(out.count<=8192,"query output capacity exceeded");
    r.outputs.resize(static_cast<size_t>(out.count)*0x19);
    for (U i=0;i<out.count;++i) std::memcpy(r.outputs.data()+i*0x19,static_cast<const B*>(Ptr(out.data))+i*0x1c,0x19);
    // Native appends leave +0x19..+0x1B padding undefined; all 25 defined bytes are compared, unnormalised.
    Deallocate(Ptr(out.data));
    r.arena.assign(w.a.mem,w.a.mem+w.a.used); r.log=callbackLog; r.stopCode=stopResult;
    r.hits=nqc_state[NQC_S_CACHE_HITS]-hits; r.fallbacks=nqc_state[NQC_S_FALLBACKS]-fall;
    r.changed=nqc_state[NQC_S_CHANGED]-changed; r.preparations=nqc_state[NQC_S_PREPARATIONS]-prep;
    CleanStatics();
    REQUIRE(!nqc_state[NQC_S_BUSY] && !nqc_state[NQC_S_OWNER_THREAD],"query scope leaked");
    REQUIRE(pool.state==NTW_POOL_S_READY,"query did not release shared pool");
    currentOutput=nullptr; currentWorld=nullptr;
    return r;
}
static void Equal(const Result& a,const Result& b,const char* label) {
    REQUIRE(a.result==b.result,"%s return differs",label);
    REQUIRE(a.outputs==b.outputs,"%s native result records differ (%zu/%zu)",label,a.outputs.size()/25,b.outputs.size()/25);
    REQUIRE(a.arena==b.arena,"%s fixture writes differ",label);
    REQUIRE(a.log==b.log,"%s original callback order/visited state differs",label);
    REQUIRE(a.cw==b.cw && ((a.csr^b.csr)&0xffc0u)==0,"%s FP control state differs",label);
    REQUIRE((a.sw&0x3800)==0 && (b.sw&0x3800)==0,"%s x87 stack leaked",label);
}
static Result Compare(World& w,const char* label,bool wrapper=false,uint16_t cw=0x27f,U csr=0x1f80) {
    w.a.Save();
    Result a=RunQuery(w,wrapper ? WrapperOriginal : Original,cw,csr);
    Result b=RunQuery(w,wrapper ? WrapperClone : Hook,cw,csr);
    Equal(a,b,label); return b;
}
// Actual native manager state, all backing addresses identical between reference and generated runs.
// Fixed spare vector capacity avoids comparing allocator addresses while still exercising pending appends.
struct ManagerWorld {
    Arena a;
    B* manager=nullptr;
};
static void MakeManager(ManagerWorld& m,U n,U variant) {
    m.a.Reset();
    B* root=m.a.Take(0x40); B* model=m.a.Take(0x200); m.manager=m.a.Take(0x40);
    B* array=m.a.Take((n+16)*4); B* pending=m.a.Take(8*4);
    Put<U>(root,8,Addr(model)); Put<U>(model,0,Addr(root)); Put<U>(model,0xe4,Addr(m.manager));
    Put<U>(m.manager,0,Addr(root)); Put<U>(m.manager,12,n+16); Put<U>(m.manager,16,n);
    Put<U>(m.manager,20,Addr(array)); Put<U>(m.manager,0x24,8); Put<U>(m.manager,0x28,Addr(pending));
    // Every moving projectile leaves these valid native model bounds, so no terrain/effect graph is needed.
    Put<float>(model,0x74,-2.0f); Put<float>(model,0x78,-2.0f);
    Put<float>(model,0x7c,2.0f); Put<float>(model,0x80,2.0f);
    for (U i=0;i<n+8;++i) {
        B* item=m.a.Take(BAL_SHADOW_BYTES); B* def=m.a.Take(0x100);
        Put<U>(item,0,Addr(root)); Put<U>(item,8,Addr(def));
        Put<float>(def,0x60,0.1f+static_cast<float>(i%7)*0.03f);
        Put<B>(def,0xe4,static_cast<B>(i%2)); Put<B>(def,0x91,static_cast<B>(i%3==0));
        Put<float>(item,0x64,100.0f+static_cast<float>(i%19)); Put<float>(item,0x68,30.0f); Put<float>(item,0x6c,120.0f);
        Put<float>(item,0x70,5.0f+static_cast<float>(i%17)); Put<float>(item,0x74,2.0f); Put<float>(item,0x78,4.0f);
        Put<float>(item,0x4c,100.0f); Put<float>(item,0x50,0.3f); Put<float>(item,0x54,0.5f);
        Put<float>(item,0x88,0.2f); Put<float>(item,0x8c,5.0f); Put<float>(item,0x90,0.1f); Put<float>(item,0x94,0.2f);
        Put<B>(item,0x40,static_cast<B>((i+variant)%2)); Put<B>(item,0x49,static_cast<B>((i+variant)%3==0));
        if (i%11==0) Put<B>(item,0x41,1); // original skip still updates previous position and age
        if (i<n && i%13==0) Put<B>(item,0xa4,1); // removed before staging
        if (i<n) Put<U>(array,i*4,Addr(item)); else Put<U>(pending,(i-n)*4,Addr(item));
    }
    m.a.Save();
}
static U managerComparisons;
static void CompareManager(ManagerWorld& w,const char* label,uint16_t cw=0x27f,U csr=0x1f80) {
    using Manager=void(__fastcall*)(void*);
    std::vector<B> reference; reference.reserve(w.a.used*3);
    uint16_t cws[3],sws[3]; U csrs[3];
    w.a.Restore();
    for (U tick=0;tick<3;++tick) {
        SetFp(cw,csr); reinterpret_cast<Manager>(Image(0x6f6bc0))(w.manager);
        cws[tick]=Cw(); sws[tick]=Sw(); csrs[tick]=_mm_getcsr(); SetFp();
        reference.insert(reference.end(),w.a.mem,w.a.mem+w.a.used);
    }
    w.a.Restore(); const U committed=job.st_committed;
    for (U tick=0;tick<3;++tick) {
        SetFp(cw,csr); reinterpret_cast<Manager>(Ptr(clones.entries[NTW2_CLONE_BAL_MANAGER]))(w.manager);
        const uint16_t gotCw=Cw(),gotSw=Sw(); const U gotCsr=_mm_getcsr(); SetFp();
        REQUIRE(std::memcmp(reference.data()+tick*w.a.used,w.a.mem,w.a.used)==0,"%s manager fixture differs at tick %u",label,tick);
        REQUIRE(cws[tick]==gotCw && ((csrs[tick]^gotCsr)&0xffc0u)==0,"%s manager FP control mismatch",label);
        REQUIRE((sws[tick]&0x3800)==0 && (gotSw&0x3800)==0,"%s manager x87 stack",label);
        REQUIRE(Get<U>(w.manager,0x24)==0,"%s pending list not consumed",label);
        REQUIRE(pool.state==NTW_POOL_S_READY,"manager left shared pool busy");
        ++managerComparisons;
    }
    REQUIRE(job.st_committed>committed,"%s never committed native worker prefixes",label);
}
static U Parse(const char* text,const char* key,U lo,U hi) {
    const size_t n=std::strlen(key); REQUIRE(std::strncmp(text,key,n)==0,"unexpected argument %s",text);
    char* end=nullptr; unsigned long x=std::strtoul(text+n,&end,10);
    REQUIRE(end!=text+n && *end==0 && x>=lo && x<=hi,"invalid %s (range %u..%u)",text,lo,hi);
    return static_cast<U>(x);
}
int main(int argc,char** argv) {
    REQUIRE(argc>=2,"usage: native_ballistics_runtime_integration.exe <Napoleon.exe> [worlds=64] [workers=3] [seed=6392]");
    U worlds=64,workers=3; randomState=6392;
    for (int i=2;i<argc;++i) {
        if (std::strncmp(argv[i],"worlds=",7)==0) worlds=Parse(argv[i],"worlds=",1,512);
        else if (std::strncmp(argv[i],"workers=",8)==0) workers=Parse(argv[i],"workers=",0,NTW_POOL_MAX_WORKERS);
        else randomState=Parse(argv[i],"seed=",1,0xffffffffu);
    }
    const U seed=randomState;
    MapImage(argv[1]); InitStatics(); BuildClones(); StartPool(workers);
    for (U& p:pureTable) p=Fn(&UnexpectedBinding);
    for (U& p:opaqueTable) p=Fn(&UnexpectedBinding);
    pureTable[6]=Native(0x461180); opaqueTable[6]=Fn(&OpaqueGetter);
    World a,b; ManagerWorld manager;
    MakeWorld(a,2048,0); StartCache(Addr(a.root),Addr(a.model));
    Result hit=Compare(a,"generated query positive/mixed");
    REQUIRE(!hit.outputs.empty() && hit.hits>0,"generated query never produced and consumed native hits");
    Result repeated=Compare(a,"repeat query"); REQUIRE(repeated.hits>0,"repeat cache consumption");
    Result wrap=Compare(a,"generated projectile wrapper",true);
    REQUIRE(wrap.hits>0 && !wrap.outputs.empty(),"generated wrapper never routed to the cache");
    // Rebuild at the same world addresses, preserving the bound root/model but changing every numeric input.
    MakeWorld(a,2048,1,true);
    Result miss=Compare(a,"negative cache results"); REQUIRE(miss.outputs.empty() && miss.hits>0,"native misses not served from cache");
    MakeWorld(a,1024,2); Put<U>(a.units[0],0,Addr(opaqueTable)); a.action=MutateUnit;
    Result changed=Compare(a,"consume-time world input mutation");
    REQUIRE(changed.changed>0 && changed.fallbacks>0 && !changed.log.empty(),"changed candidate did not run native fallback");
    MakeWorld(a,1024,3); Put<U>(a.units[0],0,Addr(opaqueTable));
    Result opaque=Compare(a,"unsupported native getter"); REQUIRE(opaque.fallbacks>0 && !opaque.log.empty(),"opaque getter fallback not reached");
    U queryComparisons=6;
    for (U i=0;i<worlds;++i) {
        MakeWorld(a,256+(Random()%1024),i+7,(i%7)==0);
        a.mode=i%4; a.stop=i%2; a.extra=(i%5)==0 ? 0.25f : 0.0f;
        if (i%6==0) a.alt=nullptr;
        if (i%6==1) a.alt->type=1;
        if (i%6==2) Put<U>(a.units[0],0,Addr(opaqueTable));
        const uint16_t cw=(i%9)==0 ? 0x37f : 0x27f;
        const U csr=(i%11)==0 ? 0x9fc0 : 0x1f80;
        Compare(a,"finite synthesized query matrix",false,cw,csr); ++queryComparisons;
        if (i%8==0) {
            MakeManager(manager,1024,i); CompareManager(manager,"shared-pool manager",cw,csr);
        }
    }
    // A different model/grid must fall back until stop/rebind, not reuse previous world's cache.
    MakeWorld(b,1024,51); Result wrong=Compare(b,"replacement world before rebind");
    REQUIRE(wrong.hits==0 && wrong.fallbacks>0,"foreign world used stale cache"); ++queryComparisons;
    MakeWorld(a,1024,52); Put<U>(a.model,0,Addr(b.root));
    Result rootChange=Compare(a,"bound model root changed");
    REQUIRE(rootChange.hits==0 && rootChange.fallbacks>0,"changed root used stale cache"); ++queryComparisons;
    StopCache();
    MakeManager(manager,1024,53); CompareManager(manager,"host pool survives cache stop");
    Result stopped=Compare(b,"stopped generated query hook");
    REQUIRE(stopped.hits==0 && stopped.fallbacks>0,"stopped hook did not use original"); ++queryComparisons;
    StartCache(Addr(b.root),Addr(b.model));
    Result rebound=Compare(b,"new-world cache restart"); REQUIRE(rebound.hits>0,"new-world restart not consumed"); ++queryComparisons;
    Put<U>(b.units[0],0,Addr(opaqueTable)); b.action=StopInGetter;
    Result busy=Compare(b,"stop inside native getter");
    REQUIRE(NQC_ERR_CLASS(busy.stopCode)==NQC_E_BUSY && !nqc_state[NQC_S_ENABLED],"in-scope stop did not disable then report busy"); ++queryComparisons;
    StopCache();
    MakeManager(manager,1024,54); CompareManager(manager,"host pool after busy cache stop");
    // Restart with a smaller capacity makes the unprepared tail remain original without changing outcomes.
    MakeWorld(b,1024,55); StartCache(Addr(b.root),Addr(b.model),32);
    Result limited=Compare(b,"restart with bounded cache capacity");
    REQUIRE(limited.hits>0 && limited.fallbacks>0,"bounded cache did not exercise hits and native misses"); ++queryComparisons;
    StopCache(); StartCache(boundRoot,boundModel);
    Result final=Compare(b,"full cache restart"); REQUIRE(final.hits>0,"full restart not consumed"); ++queryComparisons;
    U workerChunks=0; for (U i=0;i<pool.workers;++i) workerChunks+=pool.slots[i].chunks;
    const U teamDispatches=pool.st_team;
    StopCache(); REQUIRE(ntw_pool_shutdown(&pool)==NTW_POOL_OK && pool.state==NTW_POOL_S_UNINIT,"host pool shutdown");
    std::printf("PASS generated ballistics integration: seed=%u query_pairs=%u manager_ticks=%u pool_team_dispatches=%u worker_chunks=%u\n",
        seed,queryComparisons,managerComparisons,teamDispatches,workerChunks);
    std::puts("LIMIT: manager damage/effects and host epoch/slot publication require the battle graph/runtime host described in this source.");
    // Published clone/cache storage remains process-owned until exit, as required by the production ABI.
    return 0;
}

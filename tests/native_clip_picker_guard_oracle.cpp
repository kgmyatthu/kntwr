// Oracle for src/animation/kntwr_clip_picker_guard.{h,cpp} (the always-on clip picker crash guard) on a private relocated mapping of the owned image.
//  * HOT PATH: the ORIGINAL bytes of FUN_00e5f760 (0xE5F760, 53 bytes, run in the private mapping) against Picker over random tables whose requested category has a
//    non-zero count: the returned clip must be bit-identical, nothing may be counted, ESI/EDI/EBX are preserved and the callee pops its 8 argument bytes.
//  * COLD PATH, category 0 non-empty: requested category empty -> native result (rand % table[5]) is reproduced exactly; only calls_cold moves.
//  * GUARDED: requested category AND category 0 empty -> the original code raises #DE (EXCEPTION_INT_DIVIDE_BY_ZERO at 0xE5F77A, proven here); the guard returns the clip of
//    the first non-empty category 1..863 (rand % n_k + k*6), table[0] when all are empty, no fault; the counters/last-value words follow.
//  * REDIRECT: Install swaps exactly the 8 entry bytes (jmp rel32 + the three untouched original bytes 5..7), calling the image address then runs Picker (hot, cold and
//    guarded), Remove restores the original 8 bytes bit-exactly, Install refuses modified bytes, Remove without a prior install is a no-op success.
// No running game or installed file is modified.
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
#include "kntwr_runtime.h"
#include "animation/kntwr_clip_picker_guard.h"
#pragma comment(lib,"bcrypt.lib")
using U=uint32_t;
using B=unsigned char;
namespace g=kntwr_clip_picker_guard;
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
static U rngState=0x2468ACE1u;
static U Rng() { rngState=rngState*1664525u+1013904223u; return rngState^(rngState>>15); }

// Animation table object: [obj+0x2C] = table of 864 24-byte records.
struct Table {
    alignas(16) U slots[g::kCategories*6];
    alignas(16) B object[0x40];
    Table() { Clear(); }
    void Clear() { std::memset(slots,0,sizeof slots); std::memset(object,0,sizeof object); const U t=A(slots); std::memcpy(object+0x2C,&t,4); }
    void Set(U category,U count) {
        slots[category*6+5]=count;
        for(U s=0;s<5;++s) slots[category*6+s]=0xC1100000u+category*16+s;   // distinct non-null clip pointers
    }
    U Obj() const { return A(object); }
};

// Calls `fn` (ECX = table object, stack (category, random), callee pops 8) and checks that EBX/ESI/EDI survive and the stack is balanced.
static U CheckedCall(U fn,U object,U category,U random,bool* preserved) {
    U result=0, ok=0;
    __asm {
        push ebx
        push esi
        push edi
        mov ebx, 0x11111111
        mov esi, 0x22222222
        mov edi, 0x33333333
        push random
        push category
        mov ecx, object
        call fn
        mov result, eax
        xor eax, eax
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
// Same call, #DE reported instead of propagated.
static bool NativeFaults(U fn,U object,U category,U random,U* faultAddress) {
    __try { bool p; CheckedCall(fn,object,category,random,&p); return false; }
    __except (GetExceptionCode()==EXCEPTION_INT_DIVIDE_BY_ZERO ? (*faultAddress=A(GetExceptionInformation()->ExceptionRecord->ExceptionAddress),EXCEPTION_EXECUTE_HANDLER) : EXCEPTION_CONTINUE_SEARCH) {
        return true;
    }
}

static U Expect(const Table& t,U category,U random) { // reference model of the guarded function
    const U n=t.slots[category*6+5];
    if(n) return t.slots[random%n+category*6];
    if(t.slots[5]) return t.slots[random%t.slots[5]];
    for(U k=1;k<g::kCategories;++k) if(t.slots[k*6+5]) return t.slots[random%t.slots[k*6+5]+k*6];
    return t.slots[0];
}

static void Run() {
    const U original=A(At(g::kEntry));
    const U guard=g::Entry();
    static const B kOriginal[8]={0x8B,0x44,0x24,0x08,0x33,0xD2,0x56,0x8B};
    Require(std::memcmp(At(g::kEntry),kOriginal,8)==0,"entry bytes of the owned image");
    Require((original&15u)==0,"private mapping keeps the entry 16-byte aligned");
    g::ResetRow();
    Require(g::words[g::WVersion]==g::kVersion,"version word");
    static Table table;
    bool preserved;

    // ---- hot path: bit-identical, uncounted
    for(U iter=0;iter<200000;++iter) {
        table.Clear();
        const U requested=Rng()%g::kCategories;
        table.Set(requested,1+Rng()%5);
        for(U extra=Rng()%6;extra;--extra) table.Set(Rng()%g::kCategories,1+Rng()%5);
        const U random=Rng();
        const U a=CheckedCall(original,table.Obj(),requested,random,&preserved);
        Require(preserved,"native preserves ebx/esi/edi");
        const U b=CheckedCall(guard,table.Obj(),requested,random,&preserved);
        Require(preserved,"guard preserves ebx/esi/edi");
        Require(a==b,"hot path bit-identical");
        Require(b==Expect(table,requested,random),"hot path model");
    }
    for(U r : {0u,1u,4u,5u,0xFFFFFFFFu,0x80000000u}) {          // the divisor extremes
        table.Clear(); table.Set(863,5); table.Set(0,3);
        Require(CheckedCall(original,table.Obj(),863,r,&preserved)==CheckedCall(guard,table.Obj(),863,r,&preserved),"hot edge");
    }
    Require(g::words[g::WCallsCold]==0 && g::words[g::WGuarded]==0,"hot path counts nothing");

    // ---- cold path with a non-empty category 0: native result
    U cold=0;
    for(U iter=0;iter<100000;++iter) {
        table.Clear();
        table.Set(0,1+Rng()%5);
        const U requested=1+Rng()%(g::kCategories-1);
        for(U extra=Rng()%4;extra;--extra) { const U c=Rng()%g::kCategories; if(c!=requested) table.Set(c,1+Rng()%5); }
        const U random=Rng();
        Require(CheckedCall(original,table.Obj(),requested,random,&preserved)==CheckedCall(guard,table.Obj(),requested,random,&preserved) && preserved,"cold path with category 0");
        ++cold;
    }
    Require(g::words[g::WCallsCold]==cold && g::words[g::WGuarded]==0 && g::words[g::WEmptyTables]==0,"cold counters");

    // ---- guarded: the original faults, the guard answers
    U guarded=0, empty=0, maxScan=0;
    for(U iter=0;iter<20000;++iter) {
        table.Clear();
        const U requested=Rng()%g::kCategories;           // may be 0 itself
        const U first=1+Rng()%(g::kCategories-1);
        if(first!=requested) table.Set(first,1+Rng()%5);
        for(U extra=Rng()%3;extra;--extra) { const U c=1+Rng()%(g::kCategories-1); if(c!=requested && c>first) table.Set(c,1+Rng()%5); }
        const U random=Rng();
        U where=0;
        Require(NativeFaults(original,table.Obj(),requested,random,&where),"native picker faults on an all-empty fallback");
        Require(where==g::kEntry+delta+0x1A,"native fault address is the div at 0xE5F77A");
        const U got=CheckedCall(guard,table.Obj(),requested,random,&preserved);
        Require(preserved,"guard preserves registers on the guarded path");
        Require(got==Expect(table,requested,random),"guarded result");
        U hit=0;
        for(U k=1;k<g::kCategories && !hit;++k) if(table.slots[k*6+5]) hit=k;
        Require(hit ? got!=0 : got==table.slots[0],"guard returned a real clip when a category had one");
        ++guarded;
        if(hit) maxScan=std::max(maxScan,hit);
        else { ++empty; maxScan=std::max(maxScan,g::kCategories-1); }
    }
    // all-empty table: table[0] (the first dword), counted
    table.Clear(); table.slots[0]=0xDEAD0000u;
    for(U requested : {0u,106u,863u}) {
        Require(CheckedCall(guard,table.Obj(),requested,0x1234u,&preserved)==0xDEAD0000u && preserved,"all-empty table returns table[0]");
        ++guarded; ++empty;
    }
    maxScan=std::max(maxScan,g::kCategories-1);
    // category 863 is the last scanned one
    table.Clear(); table.Set(863,2);
    Require(CheckedCall(guard,table.Obj(),106,7,&preserved)==table.slots[863*6+1],"last category is scanned");
    ++guarded;
    Require(g::words[g::WGuarded]==guarded,"guarded counter");
    Require(g::words[g::WEmptyTables]==empty,"empty_tables counter");
    Require(g::words[g::WScannedMax]==maxScan,"scanned_max");
    Require(g::words[g::WTableLast]==A(table.slots) && g::words[g::WCatLast]==106u,"last-value words");
    Require(g::words[g::WCallsCold]==cold+guarded,"calls_cold covers guarded calls");
    U snapshot[g::kWords]; g::Snapshot(snapshot);
    for(U i=0;i<g::kWords;++i) Require(snapshot[i]==g::words[i],"snapshot");

    // ---- redirect
    g::ResetRow();
    B before[8]; std::memcpy(before,At(g::kEntry),8);
    {   // modified bytes are refused without a change
        B* p=At(g::kEntry); p[1]^=0x10;
        B modified[8]; std::memcpy(modified,p,8);
        Require(!g::InstallRedirect(delta) && std::memcmp(p,modified,8)==0 && !g::words[g::WPatchInstalled],"install refuses modified entry bytes");
        p[1]^=0x10;
        Require(std::memcmp(p,before,8)==0,"restored test byte");
    }
    Require(g::RemoveRedirect(delta) && std::memcmp(At(g::kEntry),before,8)==0,"remove without install is a no-op success");
    Require(g::InstallRedirect(delta) && g::words[g::WPatchInstalled]==1,"install");
    {
        B* p=At(g::kEntry);
        const U rel=g::Entry()-(A(p)+5);
        Require(p[0]==0xE9 && std::memcmp(p+1,&rel,4)==0 && std::memcmp(p+5,before+5,3)==0,"entry bytes are jmp rel32 + the untouched original bytes");
    }
    for(U iter=0;iter<20000;++iter) {   // through the image address: hot, cold, guarded
        table.Clear();
        const U requested=Rng()%g::kCategories;
        const U mode=iter%3;
        if(mode==0) table.Set(requested,1+Rng()%5);
        if(mode==1) { table.Set(0,1+Rng()%5); }
        if(mode==2) table.Set(1+Rng()%(g::kCategories-1),1+Rng()%5);
        const U random=Rng();
        const U got=CheckedCall(A(At(g::kEntry)),table.Obj(),requested,random,&preserved);
        Require(preserved && got==Expect(table,requested,random),"redirected picker");
    }
    Require(g::words[g::WGuarded]>0,"redirect reached the guarded path");
    Require(g::InstallRedirect(delta)==false,"second install refuses (entry is already patched)");
    Require(g::RemoveRedirect(delta) && std::memcmp(At(g::kEntry),before,8)==0 && !g::words[g::WPatchInstalled],"remove restores the original 8 bytes");
    Require(g::RemoveRedirect(delta),"remove is idempotent");
    {   // restored original again faults on the empty fallback (the guard is really gone)
        table.Clear(); table.Set(5,1);
        U where=0;
        Require(NativeFaults(A(At(g::kEntry)),table.Obj(),106,3,&where),"after remove the native picker is live again");
    }
}

int main(int argc,char** argv) {
    if(argc<2) { std::fprintf(stderr,"usage: native_clip_picker_guard_oracle <Napoleon_patched.exe>\n"); return 2; }
    Map(argv[1]);
    Run();
    std::printf("native_clip_picker_guard_oracle: %u checks passed\n",checks);
    return 0;
}

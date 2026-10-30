// --wounded hook (src/animation/kntwr_wounded_hook.cpp) against a private relocated copy of the supported Napoleon image.
//  * The stock 8 bytes of the state commit 0x653F1A are asserted; Install replaces them with E9 rel32 + 3 int3 and touches
//    no other image byte; Remove restores them bit-exactly; foreign bytes and bad percents are refused.
//  * EXECUTION: a ret scribbled after the state store 0x653F39 (our private copy only) lets the oracle call the site with
//    ECX=category / EBP=a fake man FSM. Pre-install the stock select answers; post-install the gate must agree with the
//    stock select for every non-flip case (knockdowns 0x4B, missing/untagged clips 0x2A) and flip exactly when the policy
//    (animation/kntwr_wounded.h) says so, leaving EAX=state, EDX=[0x14521C8], ECX untouched.
//  * xmm1..xmm7, ebx/esi/edi, the x87 stack depth and the state written through EBP are checked across the hooked call;
//    receipt words are checked against a tally. SEH: a poisoned clip-table pointer must count a fault and commit static.
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
#include <algorithm>
#include <vector>
#include "native_image_relocation.h"
#include "kntwr_runtime.h"
#include "animation/kntwr_wounded.h"
#include "animation/kntwr_wounded_hook.h"

#pragma comment(lib,"bcrypt.lib")
using U=uint32_t;
using B=unsigned char;
namespace h=kntwr_wounded_hook;
namespace w=kntwr_wounded;
static_assert(sizeof(void*)==4,"owned x86 oracle");
static B* image;
static U delta, checks, imageSize;
static void Require(bool ok,const char* what) { ++checks; if(!ok) { std::fprintf(stderr,"FAIL %s\n",what); std::exit(1); } }
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static B* At(U va) { return reinterpret_cast<B*>(va+delta); }
static U Rd(U va) { U v; std::memcpy(&v,At(va),4); return v; }
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

constexpr U kSite=0x653F1A, kStore=0x653F39, kRetScribble=0x653F3F, kRangeLo=0x14521C8;
constexpr B kStock[8]={0x8B,0x15,0xC8,0x21,0x45,0x01,0x3B,0xCA};
constexpr B kStore6[6]={0x89,0x85,0xB8,0x01,0x00,0x00};   // mov [ebp+0x1B8], eax

// ---- fake man FSM + clip world (layouts from the census: holder [M+0x218] -> table -> records [table+0x2C],
//      record cat*0x18 {clips[0..4], count +0x14}, clip {+0x54 FACE_UP int, +0x5C FACE_DOWN int, +0x60 FACE_DOWN byte},
//      rnd [M+0x1E0]) ----
constexpr U kCat=0x300;              // a DEATH_* category outside the knockdown range
alignas(16) static B M[0x600];
static B table[0x40];
static std::vector<B> records;       // 0x360 records * 0x18
static std::vector<U> remap;         // [table+0x3C] render pose-category remap, 0x360 entries (0x360 = "no pose")
alignas(16) static B clipUntagged[0x70], clipTagged[0x70], clipPresentOnly[0x70], clipFaceUp[0x70];
static U holderCell;                 // first dword = table ptr

static void Wr(void* p,U off,U v) { std::memcpy(static_cast<B*>(p)+off,&v,4); }
static void SetRnd(U rnd) { Wr(M,0x1E0,rnd); }
static void SetHolder(U v) { Wr(M,0x218,v); }
static U* RecordSlot(U cat,U idx) { return reinterpret_cast<U*>(records.data()+cat*0x18u+idx*4u); }
static U* RecordCount(U cat) { return reinterpret_cast<U*>(records.data()+cat*0x18u+0x14u); }
static void BuildWorld() {
    std::memset(M,0,sizeof M); std::memset(table,0,sizeof table);
    records.assign(0x360u*0x18u,0);
    std::memset(clipUntagged,0,sizeof clipUntagged);
    std::memset(clipTagged,0,sizeof clipTagged);
    std::memset(clipPresentOnly,0,sizeof clipPresentOnly);
    std::memset(clipFaceUp,0,sizeof clipFaceUp);
    Wr(clipTagged,0x5C,1); clipTagged[0x60]=1;          // FACE_DOWN int + presence
    clipPresentOnly[0x60]=1;                            // presence, both ints zero
    Wr(clipFaceUp,0x54,2); clipFaceUp[0x60]=1;          // FACE_UP int + presence
    *RecordSlot(kCat,0)=A(clipUntagged); *RecordSlot(kCat,1)=A(clipTagged);
    *RecordSlot(kCat,2)=A(clipPresentOnly); *RecordSlot(kCat,3)=A(clipFaceUp);
    *RecordCount(kCat)=4;
    Wr(table,0x2C,A(records.data()));
    remap.assign(0x360u,0x360u);
    Wr(table,0x3C,A(remap.data()));
    holderCell=A(table);
    SetHolder(A(&holderCell));
    SetRnd(1);
}

// ---- thunk: ECX=cat, EBP=M, sentinels in EAX/EDX/EBX/ESI/EDI, xmm1..7 from g_xin; site must leave EAX=state,
//      EDX=[0x14521C8], ECX=cat and preserve the rest. The scribbled ret right after the state store returns here. ----
static U g_state,g_edx,g_ecx,g_ebx,g_esi,g_edi,g_fsw;
alignas(16) static B g_xin[112],g_xout[112];
static __declspec(naked) void __stdcall CallSite(U /*site*/,U /*cat*/,U /*m*/) {
    __asm {
        push ebp
        push ebx
        push esi
        push edi
        mov eax, offset g_xin
        movups xmm1,[eax+0x00]
        movups xmm2,[eax+0x10]
        movups xmm3,[eax+0x20]
        movups xmm4,[eax+0x30]
        movups xmm5,[eax+0x40]
        movups xmm6,[eax+0x50]
        movups xmm7,[eax+0x60]
        mov ecx,[esp+24]
        mov ebp,[esp+28]
        mov ebx,0x13579BDF
        mov esi,0x2468ACE0
        mov edi,0x0F1E2D3C
        mov eax,0xDEADBEEF
        mov edx,0xCAFEF00D
        call dword ptr [esp+20]
        mov g_state,eax
        mov g_edx,edx
        mov g_ecx,ecx
        mov g_ebx,ebx
        mov g_esi,esi
        mov g_edi,edi
        fnstsw ax
        and eax,0x3800
        mov g_fsw,eax
        mov eax, offset g_xout
        movups [eax+0x00],xmm1
        movups [eax+0x10],xmm2
        movups [eax+0x20],xmm3
        movups [eax+0x30],xmm4
        movups [eax+0x40],xmm5
        movups [eax+0x50],xmm6
        movups [eax+0x60],xmm7
        pop edi
        pop esi
        pop ebx
        pop ebp
        ret 12
    }
}

// Run one commit through the (possibly hooked) site; verify register contract and return the committed state.
static U Commit(U cat) {
    for(U i=0;i<112;++i) g_xin[i]=static_cast<B>(0xA5^(i*37));
    std::memset(g_xout,0,sizeof g_xout);
    Wr(M,0x1B8,0xFFFFFFFFu);
    CallSite(kSite+delta,cat,A(M));
    U stored; std::memcpy(&stored,M+0x1B8,4);
    Require(stored==g_state,"state store through EBP == EAX at the store");
    Require(g_edx==0x32Au,"EDX == [0x14521C8] (range lo) at the resume point");
    Require(g_ecx==cat,"ECX (category) untouched");
    Require(g_ebx==0x13579BDFu && g_esi==0x2468ACE0u && g_edi==0x0F1E2D3Cu,"ebx/esi/edi preserved");
    Require(g_fsw==0u,"x87 stack balanced (TOP==0)");
    Require(!std::memcmp(g_xin,g_xout,112),"xmm1..xmm7 preserved");
    return g_state;
}

// ---- receipt tally ----
static U expReq,expApplied,expCalls,expNative,expStatic,expEligible,expFlipped,expDenied,expUntagged,expNoClip,expFaults,expLastCat,expRemap;
static void CheckRow(const char* what) {
    volatile U row[h::kWords]; h::Snapshot(row);
    char msg[96];
    std::snprintf(msg,sizeof msg,"%s: version",what);           Require(row[h::WVersion]==1u,msg);
    std::snprintf(msg,sizeof msg,"%s: requested",what);         Require(row[h::WRequested]==expReq,msg);
    std::snprintf(msg,sizeof msg,"%s: installed (applied)",what); Require(row[h::WInstalled]==expApplied,msg);
    std::snprintf(msg,sizeof msg,"%s: calls",what);             Require(row[h::WCalls]==expCalls,msg);
    std::snprintf(msg,sizeof msg,"%s: native knockdown",what);  Require(row[h::WNativeKnockdown]==expNative,msg);
    std::snprintf(msg,sizeof msg,"%s: static candidates",what); Require(row[h::WStaticCandidates]==expStatic,msg);
    std::snprintf(msg,sizeof msg,"%s: eligible",what);          Require(row[h::WEligible]==expEligible,msg);
    std::snprintf(msg,sizeof msg,"%s: flipped",what);           Require(row[h::WFlipped]==expFlipped,msg);
    std::snprintf(msg,sizeof msg,"%s: denied roll",what);       Require(row[h::WDeniedRoll]==expDenied,msg);
    std::snprintf(msg,sizeof msg,"%s: untagged",what);          Require(row[h::WUntagged]==expUntagged,msg);
    std::snprintf(msg,sizeof msg,"%s: no clip",what);           Require(row[h::WNoClip]==expNoClip,msg);
    std::snprintf(msg,sizeof msg,"%s: faults",what);            Require(row[h::WFaults]==expFaults,msg);
    std::snprintf(msg,sizeof msg,"%s: last cat",what);          Require(row[h::WLastCat]==expLastCat,msg);
    std::snprintf(msg,sizeof msg,"%s: remap fixes",what);       Require(row[h::WRemapFixes]==expRemap,msg);
    for(U i=h::WRemapFixes+1;i<h::kWords;++i) Require(row[i]==0u,"reserved words stay zero");
}

int main(int argc,char** argv) {
    if(argc!=2) { std::fprintf(stderr,"usage: native_wounded_hook_oracle <Napoleon.exe>\n"); return 2; }
    Map(argv[1]);
    const U base=A(image);

    // ---- stock image facts ----
    {
        B stock[8]; std::memcpy(stock,kStock,8);
        const U rangeRel=kRangeLo+delta; std::memcpy(stock+2,&rangeRel,4);   // disp32 carries a base relocation
        Require(!std::memcmp(At(kSite),stock,8),"stock commit bytes 8B 15 <&rangeLo> 3B CA at 0x653F1A");
    }
    Require(!std::memcmp(At(kStore),kStore6,6),"state store mov [ebp+1B8],eax at 0x653F39");
    Require(Rd(kRangeLo)==0x32Au && Rd(kRangeLo+4)==5u,"knockdown range {0x32A,5} in .data");
    *At(kRetScribble)=0xC3;                     // our private copy: return to the oracle right after the state store
    std::vector<B> pristine(image,image+imageSize);   // whole private image incl. the scribble

    // ---- pre-install: stock select answers ----
    BuildWorld();
    static const U kStockCases[][2]={{0x329,0x2A},{0x32A,0x4B},{0x32E,0x4B},{0x32F,0x2A},{0x293,0x2A},{kCat,0x2A}};
    for(const auto& c: kStockCases) Require(Commit(c[0])==c[1],"stock select state");

    // ---- refusals ----
    h::ResetRow(); CheckRow("after reset");
    Require(!h::Installed(),"not installed at start");
    Require(!h::Install(0,33),"null image base refused"); expReq=1;
    Require(!h::Install(base,0),"pct 0 refused");
    Require(!h::Install(base,101),"pct above 100 refused");
    {
        B* p=At(kSite); const B keep=p[3]; p[3]=0xF2;
        Require(!h::Install(base,33),"Install refuses modified entry bytes");
        Require(!h::Installed(),"refused Install leaves hook uninstalled");
        p[3]=keep;
        Require(!std::memcmp(image,pristine.data(),imageSize),"refused Install writes nothing");
    }
    CheckRow("after refusals");

    // ---- Install pct=100: every eligible death flips ----
    Require(h::Install(base,100),"Install on stock bytes"); expApplied=1;
    Require(h::Installed(),"Installed()");
    Require(!h::Install(base,100),"second Install refused while installed");
    Require(h::Installed(),"still installed after refused re-install");
    {
        const B* p=At(kSite);
        Require(p[0]==0xE9,"patch opcode E9");
        Require(p[5]==0xCC && p[6]==0xCC && p[7]==0xCC,"3 int3 pad");
        U rel; std::memcpy(&rel,p+1,4);
        const U target=A(p)+5+rel;
        Require(target<base || target>=base+imageSize,"detour target lives outside the image");
        for(U i=0;i<imageSize;++i) {
            const U va=i+0x400000; if(va>=kSite && va<kSite+8) continue;
            if(image[i]!=pristine[i]) Require(false,"install wrote outside the 8 entry bytes");
        }
    }
    auto native=[&](U cat) { Require(Commit(cat)==0x4Bu,"knockdown stays native 0x4B"); ++expCalls; ++expNative; expLastCat=cat; };
    auto noClip=[&](U cat) { Require(Commit(cat)==0x2Au,"missing clip commits static"); ++expCalls; ++expStatic; ++expNoClip; expLastCat=cat; };
    native(0x32A); native(0x32E);
    noClip(0x329); noClip(0x32F); noClip(0x293);        // zeroed records: count 0
    Require(remap[0x330]==0x330u,"first static-candidate commit repaired the render remap");
    for(U c=0x330u;c<=0x33Cu;++c) Require(remap[c]==c,"remap identity 0x330..0x33C");
    Require(remap[0x32F]==0x360u && remap[0x33D]==0x360u,"remap neighbors untouched");
    expRemap=1;
    SetRnd(4);  Require(Commit(kCat)==0x2Au,"untagged clip stays static"); ++expCalls; ++expStatic; ++expUntagged; expLastCat=kCat;
    SetRnd(6);  Require(Commit(kCat)==0x2Au,"present-but-unoriented clip stays static"); ++expCalls; ++expStatic; ++expUntagged;
    SetRnd(5);  Require(Commit(kCat)==0x4Bu,"FACE_DOWN clip flips at pct 100"); ++expCalls; ++expStatic; ++expEligible; ++expFlipped;
    SetRnd(7);  Require(Commit(kCat)==0x4Bu,"FACE_UP clip flips at pct 100"); ++expCalls; ++expStatic; ++expEligible; ++expFlipped;
    { Wr(table,0x3C,0); SetRnd(5); Require(Commit(kCat)==0x4Bu,"null remap pointer: flip still commits"); ++expCalls; ++expStatic; ++expEligible; ++expFlipped; Wr(table,0x3C,A(remap.data())); }
    { U keep=*RecordSlot(kCat,1); *RecordSlot(kCat,1)=0; SetRnd(5); noClip(kCat); *RecordSlot(kCat,1)=keep; }
    { Wr(table,0x2C,0); SetRnd(5); noClip(kCat); Wr(table,0x2C,A(records.data())); }
    { SetHolder(0); SetRnd(5); noClip(kCat); }
    { SetHolder(0x10u);                                  // unmapped: table deref faults under SEH
      SetRnd(5); Require(Commit(kCat)==0x2Au,"faulting walk commits static"); ++expCalls; ++expStatic; ++expFaults;
      SetHolder(A(&holderCell)); }
    CheckRow("after pct 100 battery");

    // ---- roll parity: host policy == gate at the pct boundary ----
    Require(h::Remove(),"Remove to change pct");
    Require(!std::memcmp(image,pristine.data(),imageSize),"Remove restores the whole image bit-exactly");
    U rollRnd=0,roll=0;
    for(U rnd=1;rnd<4096;++rnd)
        if(rnd%4u==1u) { const U r=w::Roll(rnd,A(M)); if(r>=10u && r<=99u) { rollRnd=rnd; roll=r; break; } }
    Require(rollRnd!=0,"found a tagged-clip random with roll in 10..99");
    Require(h::Install(base,roll),"Install pct == roll");
    SetRnd(rollRnd); Require(Commit(kCat)==0x2Au,"pct == roll denies"); ++expCalls; ++expStatic; ++expEligible; ++expDenied; expLastCat=kCat;
    Require(h::Remove(),"Remove between pct changes");
    Require(h::Install(base,roll+1),"Install pct == roll+1");
    SetRnd(rollRnd); Require(Commit(kCat)==0x4Bu,"pct == roll+1 flips"); ++expCalls; ++expStatic; ++expEligible; ++expFlipped;
    CheckRow("after roll boundary");

    // ---- Remove: foreign bytes refused, then bit-exact restore ----
    {
        B* p=At(kSite); const B keep=p[2]; p[2]^=0x5A;
        Require(!h::Remove(),"Remove refuses foreign bytes");
        Require(h::Installed(),"refused Remove leaves the hook installed");
        p[2]=keep;
        Require(h::Remove(),"Remove restores");
        Require(!h::Installed(),"not Installed after Remove");
        Require(!std::memcmp(image,pristine.data(),imageSize),"Remove restores the whole image bit-exactly");
        Require(h::Remove(),"Remove when not installed is a no-op success");
        CheckRow("after remove");   // applied-this-run word stays 1
    }
    // ---- stock answers return ----
    SetRnd(1);
    for(const auto& c: kStockCases) Require(Commit(c[0])==c[1],"after Remove: stock select state");

    // ---- lifecycle cycles ----
    for(U cycle=0;cycle<4;++cycle) {
        h::ResetRow();
        expReq=expApplied=expCalls=expNative=expStatic=expEligible=expFlipped=expDenied=expUntagged=expNoClip=expFaults=expLastCat=expRemap=0;
        std::fill(remap.begin(),remap.end(),0x360u);     // renderer remap broken again; first commit must re-repair it
        Require(h::Install(base,100),"cycle install"); expReq=1; expApplied=1;
        SetRnd(5); Require(Commit(kCat)==0x4Bu,"cycle: flip"); ++expCalls; ++expStatic; ++expEligible; ++expFlipped; expLastCat=kCat;
        expRemap=1;
        for(U c=0x330u;c<=0x33Cu;++c) Require(remap[c]==c,"cycle: remap identity restored");
        native(0x32C);
        CheckRow("cycle hooked");
        Require(h::Remove(),"cycle remove");
        CheckRow("cycle removed");
        Require(!std::memcmp(image,pristine.data(),imageSize),"cycle: image bit-exact");
        Require(Commit(kCat)==0x2Au,"cycle: stock static returns");
    }

    std::printf("native_wounded_hook_oracle: %u checks\n",checks);
    return 0;
}

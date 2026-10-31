// --wounded hooks (src/animation/kntwr_wounded_hook.cpp) against a private relocated copy of the supported Napoleon image.
//  * Two 8-byte entry patches: site A = state commit 0x653F1A (E9 rel32 + 3 int3 over the relocated stock mov/cmp), site
//    B = unique-clip builder entry 0xE61020 (E9 rel32 + 3 int3 over the 8-byte prologue). Install patches both or neither
//    and touches no other image byte; Remove restores both bit-exactly; foreign bytes at either site and bad percents are
//    refused.
//  * EXECUTION, site A: a ret scribbled after the state store 0x653F39 (our private copy only) lets the oracle call the
//    site with ECX=category / EBP=a fake man FSM. Pre-install the stock select answers; post-install the gate must agree
//    with the stock select for every non-flip case (knockdowns 0x4B, missing/untagged clips 0x2A) and flip exactly when
//    the policy (animation/kntwr_wounded.h) says so, leaving EAX=state, EDX=[0x14521C8], ECX untouched. Commits never
//    touch the render remap.
//  * EXECUTION, site B: pop esi/add esp,8/ret scribbled at 0xE61028 (right after the displaced prologue) bounds the call
//    to the detour + replayed prologue. Post-install one call must identity-write remap[0x330..0x33C] of the fake table
//    (neighbors untouched, idempotent on the second call) and preserve every register the prologue preserves; a null
//    remap pointer is skipped and a garbage table pointer must count a fault, never throw.
//  * xmm1..xmm7, ebx/esi/edi, the x87 stack depth and the memory each site writes are checked across every hooked call;
//    receipt words are checked against a tally. No running game or installed file is modified.
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
constexpr U kBuildSite=0xE61020, kBuildResume=0xE61028;
constexpr B kStock[8]={0x8B,0x15,0xC8,0x21,0x45,0x01,0x3B,0xCA};
constexpr B kStore6[6]={0x89,0x85,0xB8,0x01,0x00,0x00};   // mov [ebp+0x1B8], eax
constexpr B kBuildStock[8]={0x83,0xEC,0x08,0x56,0x8B,0xF1,0x33,0xC9};  // sub esp,8/push esi/mov esi,ecx/xor ecx,ecx
constexpr B kBuildScribble[5]={0x5E,0x83,0xC4,0x08,0xC3}; // pop esi/add esp,8/ret: unwind the replayed prologue

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

// ---- orientation-tag world (TagOrient, site B): death records 0x293..0x311 carry clips whose A-string name
//      {len +0x8, cap +0xC, wchar_t* +0x10} is looked up in kntwr_wounded_orient.h; tagging writes {+0x54,+0x58} FACE_UP
//      and {+0x5C,+0x60} FACE_DOWN (int param, presence byte) ----
enum { kOcDown,kOcUp,kOcUnknown,kOcPre,kOcNull,kOcUpperDown,kOcUpperUp,kOcNonDeath,kOcBelow,kOcAbove,kOcLast,kOcFirst,kOcPre2,kOcZeroLen,kOcTooLong,kOcN };
constexpr U kOcCatMain=0x294, kOcCatUpper=0x295, kOcCatEdge=0x296, kOcCatClamp=0x297, kOcCatNonDeath=0x200,
            kOcCatBelow=0x292, kOcCatFirst=0x293, kOcCatLast=0x311, kOcCatAbove=0x312;
struct OClip { B clip[0x70]; std::wstring name; U len, ptr; B pre; };   // pre: 1 = presence 0x60 preset, 2 = presence 0x58 preset
static OClip oc[kOcN];
static U RdC(const B* p,U off) { U v; std::memcpy(&v,p+off,4); return v; }
static std::wstring UpperAscii(std::wstring s) { for(auto& c: s) if(c>=L'a' && c<=L'z') c=static_cast<wchar_t>(c-L'a'+L'A'); return s; }
// Reset the tag fields (and everything else) of every orientation clip to its pristine, untagged state.
static void ResetOrient() {
    for(U i=0;i<kOcN;++i) {
        OClip& o=oc[i];
        std::memset(o.clip,0,sizeof o.clip);
        Wr(o.clip,0x8,o.len); Wr(o.clip,0xC,o.len); Wr(o.clip,0x10,o.ptr);
        if(o.pre==1) { o.clip[0x60]=1; Wr(o.clip,0x5C,7); }
        if(o.pre==2) { o.clip[0x58]=1; Wr(o.clip,0x54,3); }
    }
}
static void InitOrient() {
    const std::wstring down=KNTWR_WOUNDED_ORIENT_SAMPLE_DOWN_NAME, up=KNTWR_WOUNDED_ORIENT_SAMPLE_UP_NAME, unknown=L"animations/men/none/not_in_the_orient_table_001.anim";
    Require(w::OrientLookup(w::OrientHash(unknown.c_str(),static_cast<unsigned>(unknown.size())))==-1,"unknown clip name misses the table");
    for(U i=0;i<kOcN;++i) { oc[i].name.clear(); oc[i].len=0; oc[i].ptr=0; oc[i].pre=0; }
    auto named=[&](U i,const std::wstring& n) { oc[i].name=n; oc[i].len=static_cast<U>(n.size()); oc[i].ptr=A(oc[i].name.c_str()); };
    named(kOcDown,down); named(kOcUp,up); named(kOcUnknown,unknown);
    named(kOcPre,down); oc[kOcPre].pre=1;
    named(kOcPre2,up); oc[kOcPre2].pre=2;
    oc[kOcNull].len=5; oc[kOcNull].ptr=0;                                // null name pointer
    named(kOcUpperDown,UpperAscii(down)); named(kOcUpperUp,UpperAscii(up));
    named(kOcNonDeath,down); named(kOcBelow,up); named(kOcAbove,down); named(kOcLast,down); named(kOcFirst,up);
    oc[kOcZeroLen].len=0; oc[kOcZeroLen].ptr=0x10;                       // zero length: pointer never dereferenced
    oc[kOcTooLong].len=513; oc[kOcTooLong].ptr=0x10;                     // over the 512 cap: pointer never dereferenced
    ResetOrient();
    auto put=[&](U cat,U idx,U clipIdx) { *RecordSlot(cat,idx)=A(oc[clipIdx].clip); };
    put(kOcCatMain,0,kOcDown); put(kOcCatMain,1,kOcUp); put(kOcCatMain,2,kOcUnknown); put(kOcCatMain,3,kOcPre); put(kOcCatMain,4,kOcNull);
    *RecordCount(kOcCatMain)=5;
    put(kOcCatUpper,0,kOcUpperDown); *RecordSlot(kOcCatUpper,1)=0; put(kOcCatUpper,2,kOcUpperUp);
    *RecordCount(kOcCatUpper)=3;
    put(kOcCatEdge,0,kOcZeroLen); put(kOcCatEdge,1,kOcTooLong); put(kOcCatEdge,2,kOcPre2);
    *RecordCount(kOcCatEdge)=3;
    *RecordCount(kOcCatClamp)=9;                                         // slot 5 would read the count field itself as a clip pointer
    put(kOcCatNonDeath,0,kOcNonDeath); *RecordCount(kOcCatNonDeath)=1;
    put(kOcCatBelow,0,kOcBelow); *RecordCount(kOcCatBelow)=1;
    put(kOcCatAbove,0,kOcAbove); *RecordCount(kOcCatAbove)=1;
    put(kOcCatLast,0,kOcLast); *RecordCount(kOcCatLast)=1;
}
// Record 0x293 (first death category) is kept empty outside the build checks: the commit battery relies on it being clip-less.
static void ArmFirst(bool on) {
    if(on) *RecordSlot(kOcCatFirst,0)=A(oc[kOcFirst].clip); else *RecordSlot(kOcCatFirst,0)=0;
    *RecordCount(kOcCatFirst)=on?1u:0u;
}
static void ExpectTagged(U idx,bool faceDown,const char* what) {
    const B* c=oc[idx].clip;
    Require(RdC(c,0x5C)==(faceDown?1u:0u) && RdC(c,0x54)==(faceDown?0u:1u),what);
    Require(c[0x58]==1 && c[0x60]==1,what);
}
static void ExpectPristine(U idx,const char* what) {
    const B* c=oc[idx].clip;
    OClip ref; std::memset(ref.clip,0,sizeof ref.clip);
    Wr(ref.clip,0x8,oc[idx].len); Wr(ref.clip,0xC,oc[idx].len); Wr(ref.clip,0x10,oc[idx].ptr);
    if(oc[idx].pre==1) { ref.clip[0x60]=1; Wr(ref.clip,0x5C,7); }
    if(oc[idx].pre==2) { ref.clip[0x58]=1; Wr(ref.clip,0x54,3); }
    Require(!std::memcmp(c,ref.clip,sizeof ref.clip),what);
}
// Every orientation clip is in its pristine untagged state (fresh table or reset between cycles).
static void ExpectAllUntagged(const char* what) { for(U i=0;i<kOcN;++i) ExpectPristine(i,what); }
// State after one hooked build on the armed fake table: six clips tagged (down/up/upper x2/last/first), the rest untouched.
constexpr U kOcTaggedPerBuild=6;
static void ExpectBuilt(const char* what) {
    ExpectTagged(kOcDown,true,what);          // (a)
    ExpectTagged(kOcUp,false,what);           // (b)
    ExpectPristine(kOcUnknown,what);          // (c) unknown name
    ExpectPristine(kOcPre,what);              // (d) already tagged (presence 0x60): params untouched
    ExpectPristine(kOcPre2,what);             //     already tagged (presence 0x58 only): params untouched
    ExpectPristine(kOcNull,what);             // (e) null name pointer
    ExpectPristine(kOcNonDeath,what);         // (f) sample name under non-death cat 0x200
    ExpectTagged(kOcUpperDown,true,what);     // (h) uppercase ASCII folded
    ExpectTagged(kOcUpperUp,false,what);
    ExpectPristine(kOcBelow,what);            // cat 0x292, just below the death range
    ExpectPristine(kOcAbove,what);            // cat 0x312, just above
    ExpectTagged(kOcLast,true,what);          // cat 0x311, inclusive upper bound
    ExpectTagged(kOcFirst,false,what);        // cat 0x293, inclusive lower bound
    ExpectPristine(kOcZeroLen,what);          // zero length: skipped without dereferencing the pointer
    ExpectPristine(kOcTooLong,what);          // length > 512: skipped without dereferencing the pointer
}
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
    InitOrient();
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

// ---- thunk: ECX=table, sentinels everywhere else; the builder entry (gate + replayed prologue + scribble) must leave
//      ECX=0 (the displaced xor) and preserve EAX/EDX/EBX/ESI/EDI/EBP, the x87 depth and xmm1..7. ----
static U g_ebp;
static __declspec(naked) void __stdcall CallBuildSite(U /*site*/,U /*table*/) {
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
        mov ebx,0x13579BDF
        mov esi,0x2468ACE0
        mov edi,0x0F1E2D3C
        mov ebp,0x5A5A1234
        mov eax,0xDEADBEEF
        mov edx,0xCAFEF00D
        call dword ptr [esp+20]
        mov g_state,eax
        mov g_edx,edx
        mov g_ecx,ecx
        mov g_ebx,ebx
        mov g_esi,esi
        mov g_edi,edi
        mov g_ebp,ebp
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
        ret 8
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

// Run one table build through the (possibly hooked) builder entry; verify the register contract.
static void BuildCall(U tbl) {
    for(U i=0;i<112;++i) g_xin[i]=static_cast<B>(0x3C^(i*53));
    std::memset(g_xout,0,sizeof g_xout);
    CallBuildSite(kBuildSite+delta,tbl);
    Require(g_state==0xDEADBEEFu && g_edx==0xCAFEF00Du,"build: EAX/EDX preserved");
    Require(g_ecx==0u,"build: ECX zeroed by the replayed prologue");
    Require(g_ebx==0x13579BDFu && g_esi==0x2468ACE0u && g_edi==0x0F1E2D3Cu,"build: ebx/esi/edi preserved");
    Require(g_ebp==0x5A5A1234u,"build: EBP preserved");
    Require(g_fsw==0u,"build: x87 stack balanced");
    Require(!std::memcmp(g_xin,g_xout,112),"build: xmm1..xmm7 preserved");
}

// ---- receipt tally ----
static U expReq,expApplied,expCalls,expNative,expStatic,expEligible,expFlipped,expDenied,expUntagged,expNoClip,expFaults,expLastCat,expRemap,expOrient;
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
    std::snprintf(msg,sizeof msg,"%s: orient tagged",what);     Require(row[h::WOrientTagged]==expOrient,msg);
    for(U i=h::WOrientTagged+1;i<h::kWords;++i) Require(row[i]==0u,"reserved words stay zero");
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
    Require(!std::memcmp(At(kBuildSite),kBuildStock,8),"stock builder prologue at 0xE61020");
    Require(*At(kBuildResume)==0x57,"push edi at 0xE61028 (prologue displaces whole instructions)");
    *At(kRetScribble)=0xC3;                     // our private copy: return to the oracle right after the state store
    std::memcpy(At(kBuildResume),kBuildScribble,5);   // our private copy: unwind + return right after the prologue
    std::vector<B> pristine(image,image+imageSize);   // whole private image incl. the scribble

    // ---- pre-install: stock select answers, stock prologue replays ----
    BuildWorld();
    static const U kStockCases[][2]={{0x329,0x2A},{0x32A,0x4B},{0x32E,0x4B},{0x32F,0x2A},{0x293,0x2A},{kCat,0x2A}};
    for(const auto& c: kStockCases) Require(Commit(c[0])==c[1],"stock select state");
    BuildCall(A(table));
    ExpectAllUntagged("pre-install build never orient-tags");
    ArmFirst(true); BuildCall(A(table)); ArmFirst(false);
    ExpectAllUntagged("pre-install build never orient-tags (armed boundary)");
    for(U c=0x32Fu;c<=0x33Du;++c) Require(remap[c]==0x360u,"pre-install build leaves the remap stock");

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
    {
        B* p=At(kBuildSite); const B keep=p[1]; p[1]=0xF2;
        Require(!h::Install(base,33),"Install refuses modified builder entry bytes");
        Require(!h::Installed(),"refused Install leaves hooks uninstalled");
        p[1]=keep;
        Require(!std::memcmp(image,pristine.data(),imageSize),"refused Install rolled site A back bit-exactly");
    }
    CheckRow("after refusals");

    // ---- Install pct=100: every eligible death flips ----
    Require(h::Install(base,100),"Install on stock bytes"); expApplied=1;
    Require(h::Installed(),"Installed()");
    Require(!h::Install(base,100),"second Install refused while installed");
    Require(h::Installed(),"still installed after refused re-install");
    {
        for(const U site: {kSite,kBuildSite}) {
            const B* p=At(site);
            Require(p[0]==0xE9,"patch opcode E9");
            Require(p[5]==0xCC && p[6]==0xCC && p[7]==0xCC,"3 int3 pad");
            U rel; std::memcpy(&rel,p+1,4);
            const U target=A(p)+5+rel;
            Require(target<base || target>=base+imageSize,"detour target lives outside the image");
        }
        for(U i=0;i<imageSize;++i) {
            const U va=i+0x400000;
            if(va>=kSite && va<kSite+8) continue;
            if(va>=kBuildSite && va<kBuildSite+8) continue;
            if(image[i]!=pristine[i]) Require(false,"install wrote outside the two 8-byte entries");
        }
    }
    auto native=[&](U cat) { Require(Commit(cat)==0x4Bu,"knockdown stays native 0x4B"); ++expCalls; ++expNative; expLastCat=cat; };
    auto noClip=[&](U cat) { Require(Commit(cat)==0x2Au,"missing clip commits static"); ++expCalls; ++expStatic; ++expNoClip; expLastCat=cat; };
    native(0x32A); native(0x32E);
    noClip(0x329); noClip(0x32F); noClip(0x293);        // zeroed records: count 0
    SetRnd(4);  Require(Commit(kCat)==0x2Au,"untagged clip stays static"); ++expCalls; ++expStatic; ++expUntagged; expLastCat=kCat;
    SetRnd(6);  Require(Commit(kCat)==0x2Au,"present-but-unoriented clip stays static"); ++expCalls; ++expStatic; ++expUntagged;
    SetRnd(5);  Require(Commit(kCat)==0x4Bu,"FACE_DOWN clip flips at pct 100"); ++expCalls; ++expStatic; ++expEligible; ++expFlipped;
    SetRnd(7);  Require(Commit(kCat)==0x4Bu,"FACE_UP clip flips at pct 100"); ++expCalls; ++expStatic; ++expEligible; ++expFlipped;
    for(U c=0x32Fu;c<=0x33Du;++c) Require(remap[c]==0x360u,"commits never touch the render remap");
    { U keep=*RecordSlot(kCat,1); *RecordSlot(kCat,1)=0; SetRnd(5); noClip(kCat); *RecordSlot(kCat,1)=keep; }
    { Wr(table,0x2C,0); SetRnd(5); noClip(kCat); Wr(table,0x2C,A(records.data())); }
    { SetHolder(0); SetRnd(5); noClip(kCat); }
    { SetHolder(0x10u);                                  // unmapped: table deref faults under SEH
      SetRnd(5); Require(Commit(kCat)==0x2Au,"faulting walk commits static"); ++expCalls; ++expStatic; ++expFaults;
      SetHolder(A(&holderCell)); }
    CheckRow("after pct 100 battery");

    // ---- build gate battery: remap repaired at table build, idempotent, fault-safe ----
    ArmFirst(true);
    BuildCall(A(table));
    ArmFirst(false);
    for(U c=0x330u;c<=0x33Cu;++c) Require(remap[c]==c,"hooked build repairs remap identity 0x330..0x33C");
    Require(remap[0x32F]==0x360u && remap[0x33D]==0x360u,"remap neighbors untouched");
    ExpectBuilt("hooked build orient-tags untagged death clips");
    ++expRemap; expOrient+=kOcTaggedPerBuild; CheckRow("after first hooked build");
    ArmFirst(true);
    BuildCall(A(table));
    ArmFirst(false);
    ExpectBuilt("second build leaves the tags as they were");
    CheckRow("second build on a repaired, tagged table is a counted no-op");   // expRemap/expOrient unchanged: idempotent per table
    // (g) tag fields already set -> a hand-modified param survives (presence byte guards, params never rewritten)
    { oc[kOcDown].clip[0x5C]=9; ArmFirst(true); BuildCall(A(table)); ArmFirst(false);
      Require(RdC(oc[kOcDown].clip,0x5C)==9u,"tagged clip params never rewritten"); oc[kOcDown].clip[0x5C]=1; CheckRow("tagged clip survives a rebuild"); }
    std::fill(remap.begin(),remap.end(),0x360u);
    BuildCall(A(table));
    for(U c=0x330u;c<=0x33Cu;++c) Require(remap[c]==c,"re-broken remap repaired again");
    ++expRemap;
    { Wr(table,0x3C,0); BuildCall(A(table)); Wr(table,0x3C,A(remap.data())); }   // null remap: skipped, no fault
    { BuildCall(0x10u); ++expFaults; }                   // unmapped table: SEH fault counted, registers intact
    CheckRow("after build gate battery");

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
        B* p=At(kBuildSite); const B keepB=p[2]; p[2]^=0x5A;
        Require(!h::Remove(),"Remove refuses foreign bytes at the builder site");
        Require(h::Installed(),"refused Remove leaves the hooks installed");
        p[2]=keepB;
        B* q=At(kSite); const B keep=q[2]; q[2]^=0x5A;
        Require(!h::Remove(),"Remove refuses foreign bytes at the commit site");
        Require(h::Installed(),"refused Remove leaves the hooks installed (site B re-armed)");
        {
            const B* pb=At(kBuildSite);
            Require(pb[0]==0xE9 && pb[5]==0xCC,"builder site stays patched after the refused Remove");
        }
        q[2]=keep;
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
        expReq=expApplied=expCalls=expNative=expStatic=expEligible=expFlipped=expDenied=expUntagged=expNoClip=expFaults=expLastCat=expRemap=expOrient=0;
        std::fill(remap.begin(),remap.end(),0x360u);     // renderer remap broken again; the next build must repair it
        ResetOrient(); ArmFirst(false); ExpectAllUntagged("cycle: orientation clips reset to untagged");   // tag fields cleared between cycles
        Require(h::Install(base,100),"cycle install"); expReq=1; expApplied=1;
        SetRnd(5); Require(Commit(kCat)==0x4Bu,"cycle: flip"); ++expCalls; ++expStatic; ++expEligible; ++expFlipped; expLastCat=kCat;
        ArmFirst(true); BuildCall(A(table)); ArmFirst(false); expRemap=1; expOrient=kOcTaggedPerBuild;
        ExpectBuilt("cycle: death clips re-tagged exactly once");
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

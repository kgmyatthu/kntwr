// --drag-ladder v6 hook (src/formation/kntwr_drag_ladder_hook.cpp) against a private relocated copy of the supported Napoleon image.
//  * The stock 8 bytes of cdecl FilesPerRow 0x642C90 are asserted; Install replaces them with E9 rel32 + 3 int3 and touches no other image byte;
//    Remove restores them bit-exactly; foreign bytes are refused (Install: no write; Remove: no write, hook stays installed).
//  * PARITY: the relocated stock body is swept over a dense width grid for several layout (l8, l10) pairs plus the exact ladder-boundary
//    widths. Before install stock == port (ntw_formation_layout::FilesPerRow); after install hooked == LadderFiles(port), and hooked ==
//    stock exactly for every files <= 60.
//  * The layout vtable +0x10 body 0x642D00 (min(FilesPerRow, cap), thiscall ret 8) is called through the relocated image: cap < 60,
//    between ladder points, above files.
//  * xmm1..xmm7, ebx/esi/edi and the x87 stack depth are checked across the hooked call; receipt words are checked against a tally.
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
#include "formation/kntwr_drag_ladder.h"
#include "formation/kntwr_drag_ladder_hook.h"
#include "formation/native_formation_layout.h"

#pragma comment(lib,"bcrypt.lib")
using U=uint32_t;
using B=unsigned char;
namespace h=kntwr_drag_ladder_hook;
namespace q=kntwr_drag_ladder;
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

constexpr U kFiles=0x642C90, kCapWrap=0x642D00, kLayoutVt=0x1333AA8;
constexpr B kStock[8]={0x55,0x8B,0xEC,0xF3,0x0F,0x10,0x45,0x08};
typedef U(__cdecl* FilesFn)(float,float,float);
typedef U(__thiscall* CapFn)(void*,float,U);   // 0x642D00: ECX=layout, [esp+4]=width, [esp+8]=cap, ret 8

struct Layout { float l8,l10; };
static const Layout kLayouts[]={{0.7f,0.39f},{0.5f,0.5f},{1.2f,0.8f},{0.3f,0.25f},{0.0f,0.4f}};

// Receipt tally: every call through the hooked entry updates the expectation.
static U expCalls, expLad, expPass, lastBefore, lastAfter;
static U expApplied;   // sticky applied-this-run word: 1 after a successful Install, stays 1 across Remove, 0 only after ResetRow
static void Tally(U before) {
    const U after=q::LadderFiles(before);
    ++expCalls; if(after!=before) ++expLad; else ++expPass;
    lastBefore=before; lastAfter=after;
}
static void CheckRow(const char* what) {
    volatile U row[h::kWords]; h::Snapshot(row);
    char msg[96];
    std::snprintf(msg,sizeof msg,"%s: version",what);            Require(row[h::WVersion]==6u,msg);
    std::snprintf(msg,sizeof msg,"%s: requested",what);          Require(row[h::WRequested]==1u,msg);
    std::snprintf(msg,sizeof msg,"%s: installed (applied this run)",what); Require(row[h::WInstalled]==expApplied,msg);
    std::snprintf(msg,sizeof msg,"%s: calls",what);              Require(row[h::WCalls]==expCalls,msg);
    std::snprintf(msg,sizeof msg,"%s: laddered",what);           Require(row[h::WLaddered]==expLad,msg);
    std::snprintf(msg,sizeof msg,"%s: passthrough",what);        Require(row[h::WPassthrough]==expPass,msg);
    std::snprintf(msg,sizeof msg,"%s: faults",what);             Require(row[h::WFaults]==0u,msg);
    std::snprintf(msg,sizeof msg,"%s: last before",what);        Require(row[h::WLastFilesBefore]==lastBefore,msg);
    std::snprintf(msg,sizeof msg,"%s: last after",what);         Require(row[h::WLastFilesAfter]==lastAfter,msg);
    for(U i=h::WLastFilesAfter+1;i<h::kWords;++i) Require(row[i]==0u,"reserved words stay zero");
}
static void ResetTally() { h::ResetRow(); expCalls=expLad=expPass=lastBefore=lastAfter=0; expApplied=0; }

static FilesFn Files() { return reinterpret_cast<FilesFn>(At(kFiles)); }
static float MidWidth(U files,const Layout& l) { return l.l8-q::kFileSlack+(static_cast<float>(files)-0.5f)*l.l10; }
static float EdgeWidth(U files,const Layout& l,float frac) { return l.l8-q::kFileSlack+(static_cast<float>(files)-1.0f+frac)*l.l10; }

// Width sweep widths for one layout: dense grid plus ladder boundary neighbourhoods.
static std::vector<float> Widths(const Layout& l,bool dense) {
    std::vector<float> v;
    if(dense) for(U i=0;;++i) { const float w=0.1f+static_cast<float>(i)*0.0917f; if(w>400.0f) break; v.push_back(w); }
    static const U kBoundary[]={1,2,30,58,59,60,61,62,119,120,121,122,179,180,181,239,240,241,600,1000};
    for(U f: kBoundary) for(float fr: {0.0f,0.001f,0.25f,0.5f,0.75f,0.999f,1.0f}) v.push_back(EdgeWidth(f,l,fr));
    v.push_back(0.0f); v.push_back(-1.0f); v.push_back(l.l8); v.push_back(l.l8-q::kFileSlack);
    return v;
}

// Register-preservation probe: xmm1..xmm7 / ebx / esi / edi / x87 depth across a call of `fn`.
static __declspec(noinline) U Probe(FilesFn fn,float w,float l8,float l10,const B* xin,B* xout,U* g) {
    U result;
    __asm {
        mov eax, xin
        movups xmm1, [eax + 0x00]
        movups xmm2, [eax + 0x10]
        movups xmm3, [eax + 0x20]
        movups xmm4, [eax + 0x30]
        movups xmm5, [eax + 0x40]
        movups xmm6, [eax + 0x50]
        movups xmm7, [eax + 0x60]
        mov ebx, 0x13579BDF
        mov esi, 0x2468ACE0
        mov edi, 0x0F1E2D3C
        push dword ptr l10
        push dword ptr l8
        push dword ptr w
        mov edx, fn
        call edx
        add esp, 0xC
        mov result, eax
        fnstsw ax
        and eax, 0x3800
        mov ecx, g
        mov [ecx + 0x0], ebx
        mov [ecx + 0x4], esi
        mov [ecx + 0x8], edi
        mov [ecx + 0xC], eax
        mov eax, xout
        movups [eax + 0x00], xmm1
        movups [eax + 0x10], xmm2
        movups [eax + 0x20], xmm3
        movups [eax + 0x30], xmm4
        movups [eax + 0x40], xmm5
        movups [eax + 0x50], xmm6
        movups [eax + 0x60], xmm7
    }
    return result;
}

int main(int argc,char** argv) {
    if(argc!=2) { std::fprintf(stderr,"usage: native_drag_ladder_hook_oracle <Napoleon.exe>\n"); return 2; }
    Map(argv[1]);
    const U base=A(image);

    // ---- stock image facts ----
    Require(!std::memcmp(At(kFiles),kStock,8),"stock FilesPerRow entry bytes 55 8B EC F3 0F 10 45 08");
    Require(*At(kFiles-1)==0xCC,"int3 padding precedes 0x642C90");
    Require(*At(kCapWrap-1)==0xCC && *At(kCapWrap-2)==0xCC,"int3 padding precedes 0x642D00");
    Require(Rd(kLayoutVt+0x10)==kCapWrap+delta,"layout vt+0x10 = 0x642D00 (min(FilesPerRow,cap))");
    Require(Rd(kLayoutVt+0x14)==0x642B50u+delta,"layout vt+0x14 = WidthFromFiles 0x642B50 (stays stock)");
    Require(Rd(kLayoutVt+0x24)==0x62FD60u+delta,"layout vt+0x24 = slot generator 0x62FD60");
    std::vector<B> pristine(image,image+imageSize);   // whole private image before any patch

    // ---- pre-install PARITY: stock body == port ----
    U sweepSize=0;
    std::vector<std::vector<U>> stockFiles;
    for(size_t li=0;li<sizeof kLayouts/sizeof kLayouts[0];++li) {
        const Layout& l=kLayouts[li];
        const std::vector<float> ws=Widths(l,li==0);
        std::vector<U> out;
        for(float w: ws) {
            const U s=Files()(w,l.l8,l.l10);
            Require(s==ntw_formation_layout::FilesPerRow(w,l.l8,l.l10),"stock body == layout port");
            Require(s>=1u,"stock files >= 1");
            out.push_back(s); ++sweepSize;
        }
        stockFiles.push_back(out);
    }

    // ---- Install / Remove lifecycle, bit-exact ----
    h::ResetRow();
    Require(!h::Installed(),"not installed at start");
    Require(!h::Install(0),"null image base refused");
    // foreign stock bytes: no write, not installed
    {
        B* p=At(kFiles); const B keep=p[3]; p[3]=0xF2;
        Require(!h::Install(base),"Install refuses modified entry bytes");
        Require(!h::Installed(),"refused Install leaves hook uninstalled");
        p[3]=keep;
        Require(!std::memcmp(image,pristine.data(),imageSize),"refused Install writes nothing");
    }
    ResetTally();
    Require(h::Install(base),"Install on stock bytes"); expApplied=1;
    Require(h::Installed(),"Installed()");
    Require(h::Install(base),"second Install is idempotent");
    {
        const B* p=At(kFiles);
        Require(p[0]==0xE9,"patch opcode E9");
        Require(p[5]==0xCC && p[6]==0xCC && p[7]==0xCC,"3 int3 pad");
        U rel; std::memcpy(&rel,p+1,4);
        const U target=A(p)+5+rel;
        Require(target<base || target>=base+imageSize,"detour target lives outside the image");
        for(U i=0;i<imageSize;++i) {
            const U va=i+0x400000; if(va>=kFiles && va<kFiles+8) continue;
            if(image[i]!=pristine[i]) Require(false,"install wrote outside the 8 entry bytes");
        }
    }
    CheckRow("after install");

    // ---- hooked PARITY sweep ----
    U ladderedSeen=0, passSeen=0, stockEqual=0;
    for(size_t li=0;li<sizeof kLayouts/sizeof kLayouts[0];++li) {
        const Layout& l=kLayouts[li];
        const std::vector<float> ws=Widths(l,li==0);
        Require(ws.size()==stockFiles[li].size(),"sweep sizes agree");
        for(size_t i=0;i<ws.size();++i) {
            const float w=ws[i];
            const U port=ntw_formation_layout::FilesPerRow(w,l.l8,l.l10);
            const U got=Files()(w,l.l8,l.l10);
            Tally(port);
            Require(port==stockFiles[li][i],"port == stock (pre-install capture)");
            Require(got==q::LadderFiles(port),"hooked == LadderFiles(port)");
            Require(got<=port && got>=1u,"ladder only lowers, never below 1");
            if(port<=q::kLadderStep) { Require(got==stockFiles[li][i],"files<=60: hooked == stock exactly"); ++stockEqual; ++passSeen; }
            else { Require(got%q::kLadderStep==0u && got>port-q::kLadderStep,"files>60: largest 60-multiple <= files"); if(got!=port) ++ladderedSeen; else ++passSeen; }
        }
    }
    Require(ladderedSeen>0 && stockEqual>0,"sweep exercised both ladder and pass-through");
    CheckRow("after sweep");
    // exact boundary mid-step widths (kLayouts[0])
    {
        const Layout& l=kLayouts[0];
        static const U in[] ={1,59,60,61,119,120,121,179,180,181,300,301,599};
        static const U out[]={1,59,60,60,60,120,120,120,180,180,300,300,540};
        for(U i=0;i<sizeof in/sizeof in[0];++i) {
            const U got=Files()(MidWidth(in[i],l),l.l8,l.l10); Tally(in[i]);
            Require(got==out[i],"mid-step width of F files laddered to the table value");
            ++sweepSize;
        }
    }
    CheckRow("after boundary table");

    // ---- vt+0x10 body 0x642D00 through the relocated image: min(laddered files, cap) ----
    {
        alignas(16) B layout[0x40]; std::memset(layout,0,sizeof layout);
        const Layout& l=kLayouts[0];
        std::memcpy(layout+8,&l.l8,4); std::memcpy(layout+0x10,&l.l10,4);
        const CapFn cap=reinterpret_cast<CapFn>(At(kCapWrap));
        static const U kFilesList[]={1,30,59,60,61,119,120,121,130,180,500};
        static const U kCaps[]={1,30,59,60,61,100,119,120,121,1000};
        U capCases=0;
        for(U f: kFilesList) for(U c: kCaps) {
            const U before=expCalls;
            const U got=cap(layout,MidWidth(f,l),c);
            Tally(f);
            Require(expCalls==before+1,"model: one tally per cap call");
            Require(got==std::min(q::LadderFiles(f),c),"0x642D00 == min(laddered files, cap)");
            if(f<=q::kLadderStep) Require(got==std::min(f,c),"files<=60: cap body == stock min(files,cap)");
            ++capCases;
        }
        CheckRow("after cap wrapper");
        Require(capCases==110,"cap grid size");
        sweepSize+=capCases;
    }

    // ---- register / x87 preservation across the hooked call ----
    {
        alignas(16) B xin[112], xout[112]; U g[4];
        for(U i=0;i<112;++i) xin[i]=static_cast<B>(0xA5^(i*37));
        const Layout& l=kLayouts[0];
        for(float w: {MidWidth(30,l),MidWidth(61,l),MidWidth(500,l),-3.0f}) {
            std::memset(xout,0,sizeof xout); std::memset(g,0,sizeof g);
            const U port=ntw_formation_layout::FilesPerRow(w,l.l8,l.l10);
            const U got=Probe(Files(),w,l.l8,l.l10,xin,xout,g);
            Tally(port);
            Require(got==q::LadderFiles(port),"probe result");
            Require(!std::memcmp(xin,xout,112),"xmm1..xmm7 preserved across the hooked call");
            Require(g[0]==0x13579BDFu && g[1]==0x2468ACE0u && g[2]==0x0F1E2D3Cu,"ebx/esi/edi preserved");
            Require(g[3]==0u,"x87 stack balanced (TOP==0)");
        }
    }
    CheckRow("after probes");

    // ---- Remove: foreign bytes refused, then bit-exact restore ----
    {
        B* p=At(kFiles); const B keep=p[2]; p[2]^=0x5A;       // someone else rewrote the rel32
        const U fromRow=expCalls;
        Require(!h::Remove(),"Remove refuses foreign bytes");
        Require(h::Installed(),"refused Remove leaves the hook installed");
        Require(p[2]==static_cast<B>(keep^0x5A),"refused Remove writes nothing");
        p[2]=keep;
        Require(expCalls==fromRow,"model unchanged");
        Require(h::Remove(),"Remove restores");
        Require(!h::Installed(),"not Installed after Remove");
        Require(!std::memcmp(image,pristine.data(),imageSize),"Remove restores the whole image bit-exactly");
        Require(h::Remove(),"Remove when not installed is a no-op success");
        CheckRow("after remove");   // live hook gone, applied-this-run word stays 1
        {
            volatile U row[h::kWords]; h::Snapshot(row);
            Require(!h::Installed() && row[h::WInstalled]==1u,"final receipt keeps applied=1 after a clean Remove");
        }
    }
    // after Remove the stock body answers again
    for(size_t li=0;li<sizeof kLayouts/sizeof kLayouts[0];++li) {
        const Layout& l=kLayouts[li];
        const std::vector<float> ws=Widths(l,li==0);
        for(size_t i=0;i<ws.size();++i) Require(Files()(ws[i],l.l8,l.l10)==stockFiles[li][i],"after Remove: stock results return");
    }
    // lifecycle cycles: install -> hooked answers -> remove -> stock answers, bit-exact every time
    {
        const Layout& l=kLayouts[0];
        const float w=MidWidth(181,l);
        for(U cycle=0;cycle<8;++cycle) {
            Require(Files()(w,l.l8,l.l10)==181u,"cycle: stock 181");
            ResetTally();
            { volatile U row[h::kWords]; h::Snapshot(row); Require(row[h::WInstalled]==0u,"applied word clears only at ResetRow"); }
            Require(h::Install(base),"cycle install"); expApplied=1;
            Require(Files()(w,l.l8,l.l10)==180u,"cycle: hooked 180"); Tally(181);
            CheckRow("cycle hooked");
            Require(h::Remove(),"cycle remove");
            CheckRow("cycle removed");   // applied stays 1 after remove
            Require(!std::memcmp(image,pristine.data(),imageSize),"cycle: image bit-exact");
        }
    }
    std::printf("native_drag_ladder_hook_oracle: %u checks, parity sweep %u widths (%u layouts), cap grid 110, 8 lifecycle cycles\n",
                checks,sweepSize,static_cast<U>(sizeof kLayouts/sizeof kLayouts[0]));
    return 0;
}

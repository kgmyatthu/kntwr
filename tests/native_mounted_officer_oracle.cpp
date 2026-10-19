// Oracle for src/army/ntw2_mounted_officer.{h,cpp} (--mounted-officer) on a private relocated mapping of the owned image.
//  * The ORIGINAL bytes of the unit constructor's mount loop (0x51C22E..0x51C462: gate, loop body, both vector appends, radius MAXSS) run in the private mapping from a
//    hand-built frame, their engine callees (0x10D3140, 0xF548D0, 0x80B670, 0x531E30, 0x59EED0, 0x655B20, 0x444B40, 0xFF7EF0) redirected to scripted fakes.  They run on
//    a one-man unit copy with [unit+0x34] = 1 and [unit+0x30] = 1, the path the engine itself takes for a general's horse (one rider, one mount).  The host Gate runs
//    the same fakes on the real infantry-shaped unit ([unit+0x34] = 0, several men, resolved references) and must produce: the same call trace (callee and every
//    argument), the same entity serial, the same equipment and member vectors (capacity, count, data, growth allocation sequence) and, with the widen sub-switch,
//    the same radius; without it the radius is untouched.  Randomised over vector capacity/count states, radii and men counts.
//  * Predicates: mounts > 0, unresolved references (row / entity / animation key), officer not first, empty men: unit bytes and fakes untouched, counted by kind;
//    an unreadable unit is a counted fault, never an exception.
//  * Redirect: Install writes exactly the four displacement bytes of the call 0x531340, refuses modified bytes, Remove restores the original bytes bit-exactly.
// No running game or installed file is modified.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "native_image_relocation.h"
#include "ntw2_runtime.h"
#include "army/ntw2_mounted_officer.h"
#pragma comment(lib,"bcrypt.lib")
using U=uint32_t;
using B=unsigned char;
namespace mo=ntw2_mounted_officer;
static_assert(sizeof(void*)==4,"owned x86 oracle");
static B* image;
static U delta, checks, imageSize;
static void Require(bool ok,const char* what) { ++checks; if(!ok) { std::fprintf(stderr,"FAIL %s\n",what); std::exit(1); } }
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static B* At(U va) { return reinterpret_cast<B*>(va+delta); }
template<class T> static U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static void Put(void* p,U offset,U v) { std::memcpy(static_cast<B*>(p)+offset,&v,4); }
static U Get(const void* p,U offset) { U v; std::memcpy(&v,static_cast<const B*>(p)+offset,4); return v; }
static float GetF(const void* p,U offset) { float v; std::memcpy(&v,static_cast<const B*>(p)+offset,4); return v; }
static void PutF(void* p,U offset,float v) { std::memcpy(static_cast<B*>(p)+offset,&v,4); }
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

// ---------------------------------------------------------------------------------------------------------------------- fakes
using Event=std::array<U,12>;
static std::vector<Event> trace;
enum Kind : U { KAlloc=1, KVecAlloc, KVecFree, KModel, KAnim, KPose, KCtor, KAttach };
alignas(16) static B mountMem[2][0x800];
static U mountIndex;
alignas(16) static U vecPool[64][64];
static U vecIndex;
static U* VecBlock() { U* p=vecPool[vecIndex++]; std::memset(p,0xCD,sizeof vecPool[0]); return p; }
static U __cdecl FakeAlloc(U size) { trace.push_back({KAlloc,size}); B* m=mountMem[mountIndex++ & 1]; std::memset(m,0,sizeof mountMem[0]); return A(m); }
static U __cdecl FakeVecAlloc(U count,U flag) { trace.push_back({KVecAlloc,count,flag}); return count<=60 ? A(VecBlock()) : 0; }
static void __cdecl FakeVecFree(U p) { trace.push_back({KVecFree,p}); }
static U __fastcall FakeModel(U ecx,U) { trace.push_back({KModel,ecx}); return 0x11110000u; }
static U __fastcall FakeAnim(U ecx,U,U arg) { trace.push_back({KAnim,ecx,arg}); return 0x22220000u; }
static U __cdecl FakePose() { trace.push_back({KPose}); return 0x33330000u; }
static U __fastcall FakeCtor(U ecx,U,U a1,U a2,U a3,U a4,U a5,U a6,U a7,U a8) {
    trace.push_back({KCtor,ecx,a1,a2,a3,a4,a5,a6,a7,a8}); PutF(reinterpret_cast<void*>(static_cast<uintptr_t>(ecx)),0x58,1.25f); return ecx;
}
static void __fastcall FakeAttach(U ecx,U,U mount) { trace.push_back({KAttach,ecx,mount}); Put(reinterpret_cast<void*>(static_cast<uintptr_t>(mount)),mo::kMountRiders,1); }
static mo::Targets FakeTargets() { return {Fn(&FakeAlloc),Fn(&FakeVecAlloc),Fn(&FakeVecFree),Fn(&FakeModel),Fn(&FakeAnim),Fn(&FakePose),Fn(&FakeCtor),Fn(&FakeAttach)}; }

// ---------------------------------------------------------------------------------------------------------------------- original loop harness
static U gUnit, gArg1, gSerialIn, gSerialOut;
static B* stub;
static void PatchCalls() {
    struct Site { U site, fake; };
    // every `call rel32` of the loop body, keyed by its original target
    const U sites[]={0x51C255,0x51C283,0x51C28A,0x51C295,0x51C2B4,0x51C2E8,0x51C316,0x51C343,0x51C37B,0x51C3AF,0x51C3DC,0x51C41A};
    for(U site:sites) {
        B* p=At(site); Require(p[0]==0xE8,"loop call opcode");
        const U target=A(p)+5+Get(p,1)-delta; // preferred-base target of the original call
        U fake=0;
        switch(target) {
        case 0x10D3140: fake=Fn(&FakeAlloc); break;   case 0xF548D0: fake=Fn(&FakeAnim); break; case 0x80B670: fake=Fn(&FakePose); break;
        case 0x531E30: fake=Fn(&FakeModel); break;    case 0x59EED0: fake=Fn(&FakeCtor); break; case 0x655B20: fake=Fn(&FakeAttach); break;
        case 0x444B40: fake=Fn(&FakeVecAlloc); break; case 0xFF7EF0: fake=Fn(&FakeVecFree); break;
        default: Require(false,"unexpected loop callee");
        }
        Put(p,1,fake-(A(p)+5));
    }
    // Entry stub: frame of the constructor at 0x51C22E, jumps into the original loop; the loop exit 0x51C462 is redirected to the exit stub.
    stub=static_cast<B*>(VirtualAlloc(nullptr,0x1000,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE));
    B* c=stub; auto b=[&](std::initializer_list<int> v){ for(int x:v) *c++=static_cast<B>(x); }; auto d=[&](U v){ std::memcpy(c,&v,4); c+=4; };
    b({0x53,0x56,0x57,0x55});                           // push ebx esi edi ebp
    b({0x8B,0x2D}); d(A(&gUnit));                        // mov ebp,[gUnit]
    b({0x81,0xEC}); d(0x80);                             // sub esp,0x80
    b({0xA1}); d(A(&gArg1)); b({0x89,0x44,0x24,0x54});   // [esp+54] = arg1
    b({0xA1}); d(A(&gSerialIn)); b({0x89,0x44,0x24,0x5C}); // [esp+5C] = serial
    b({0xC7,0x44,0x24,0x10}); d(1);                      // [esp+10] = men per mount 1
    b({0xBF}); d(1); b({0xB9}); d(1);                    // edi = 1, ecx = [unit+0x34]
    b({0xE9}); d(At(0x51C22E)-(c+4));                    // jmp gate test
    B* exitStub=c;
    b({0x8B,0x44,0x24,0x5C}); b({0xA3}); d(A(&gSerialOut)); // mov eax,[esp+5C]; mov [gSerialOut],eax
    b({0x81,0xC4}); d(0x80); b({0x5D,0x5F,0x5E,0x5B,0xC3});
    B* exitSite=At(0x51C462); const B expect[]={0x8B,0x5C,0x24,0x18,0x85,0xDB};
    Require(!std::memcmp(exitSite,expect,sizeof expect),"loop exit is the pinned original");
    exitSite[0]=0xE9; Put(exitSite,1,A(exitStub)-(A(exitSite)+5));
}
static void RunOriginalLoop(U unit,U arg1,U serial) {
    gUnit=unit; gArg1=arg1; gSerialIn=serial; gSerialOut=0;
    reinterpret_cast<void(*)()>(stub)();
}

// ---------------------------------------------------------------------------------------------------------------------- unit fixture
constexpr U kUnitBytes=0x1000;
struct Rng { U s; U Next() { s=s*1664525u+1013904223u; return s>>8; } };
struct Fixture {
    alignas(16) B unit[kUnitBytes];
    alignas(16) B env[0x40], envInner[0x80], row[0x40], entity[0x40], men[8][0x40];
    U menArray[8], persArray[2];
    U equipBlock[16], memberBlock[16];
    wchar_t chars[8];
};
static Fixture fx;
struct Shape { U menCount, equipCap, equipCount, memberCap, memberCount; float radius; };
static void Build(const Shape& s,bool refs=true,bool officerFirst=true,U mounts=0) {
    B* u=fx.unit;
    std::memset(&fx,0,sizeof fx);
    Put(fx.env,8,A(fx.envInner));
    Put(u,mo::kUnitEnv,A(fx.env));
    Put(u,mo::kUnitMountRow,refs ? A(fx.row) : 0); Put(u,mo::kUnitMountEntity,refs ? A(fx.entity) : 0);
    Put(u,mo::kUnitMountStats,refs ? 3 : 0); Put(u,mo::kUnitMountStats+4,0); Put(u,mo::kUnitMountAnimPtr,refs ? A(fx.chars) : 0);
    Put(u,mo::kUnitMounts,mounts); Put(u,mo::kUnitMenPerMount,mounts ? s.menCount : 0);
    for(U i=0;i<8;++i) fx.menArray[i]=A(fx.men[i]);
    Put(u,mo::kUnitMenCap,8); Put(u,mo::kUnitMenCount,s.menCount); Put(u,mo::kUnitMenData,A(fx.menArray));
    fx.persArray[0]=officerFirst ? A(fx.men[0]) : A(fx.men[1]);
    Put(u,mo::kUnitPersCount,1); Put(u,mo::kUnitPersData,A(fx.persArray));
    for(U i=0;i<16;++i) { fx.equipBlock[i]=0xE0000000u+i; fx.memberBlock[i]=0xB0000000u+i; }
    Put(u,mo::kUnitEquipVec,s.equipCap); Put(u,mo::kUnitEquipVec+4,s.equipCount); Put(u,mo::kUnitEquipVec+8,s.equipCap ? A(fx.equipBlock) : 0);
    Put(u,mo::kUnitMemberVec,s.memberCap); Put(u,mo::kUnitMemberVec+4,s.memberCount); Put(u,mo::kUnitMemberVec+8,s.memberCap ? A(fx.memberBlock) : 0);
    PutF(u,mo::kUnitRadius,s.radius);
    Put(fx.men[0],0,0x13475E4u);
}
struct Snapshot { std::vector<B> unit; std::vector<U> equip, member; std::vector<Event> events; U serial; };
static Snapshot Capture(U serialOut) {
    Snapshot s; s.unit.assign(fx.unit,fx.unit+kUnitBytes); s.events=trace; s.serial=serialOut;
    auto dump=[&](U base,std::vector<U>& out) { const U count=Get(fx.unit,base+4), data=Get(fx.unit,base+8); for(U i=0;i<count;++i) out.push_back(*reinterpret_cast<const U*>(static_cast<uintptr_t>(data)+4*i)); };
    dump(mo::kUnitEquipVec,s.equip); dump(mo::kUnitMemberVec,s.member);
    return s;
}
static void Reset() { trace.clear(); mountIndex=0; vecIndex=0; }
static void CompareUnits(const Snapshot& a,const Snapshot& b,bool radius,const char* what) {
    Require(a.events==b.events,what);
    Require(a.serial==b.serial,"entity serial identical");
    Require(a.equip==b.equip && a.member==b.member,"equipment and member vector contents identical");
    // every unit byte except the men count (the stock copy holds one man), the radius (compared separately) and the vector data pointers (blocks differ per run)
    for(U off=0;off<kUnitBytes;off+=4) {
        if(off==mo::kUnitMenCount || off==mo::kUnitMenPerMount || off==mo::kUnitMounts) continue;
        if(off==mo::kUnitRadius && !radius) continue;
        if(off==mo::kUnitEquipVec+8 || off==mo::kUnitMemberVec+8) continue;
        U x,y; std::memcpy(&x,&a.unit[off],4); std::memcpy(&y,&b.unit[off],4);
        if(x!=y) { std::fprintf(stderr,"unit byte difference at +0x%X: %08X vs %08X (%s)\n",off,x,y,what); Require(false,"unit bytes identical"); }
    }
}

static void Equivalence() {
    Rng rng{12345u};
    mo::Configure(true,FakeTargets());
    for(U iter=0;iter<4000;++iter) {
        Shape s{1+rng.Next()%7,0,0,0,0,0.0f};
        const U caps[]={0,1,2,4,8}; s.equipCap=caps[rng.Next()%5]; s.equipCount=s.equipCap ? rng.Next()%(s.equipCap+1) : 0;
        s.memberCap=caps[rng.Next()%5]; s.memberCount=s.memberCap ? rng.Next()%(s.memberCap+1) : 0;
        s.radius=0.1f*(1+rng.Next()%30);
        if(s.equipCap==0) s.equipCount=0;
        const U serial=100+rng.Next()%1000, arg1=0xA0000000u+rng.Next();
        // stock: the original loop on a one-man copy with [unit+0x34] = 1 (the general's horse path)
        Shape one=s; one.menCount=1;
        Build(one); Put(fx.unit,mo::kUnitMounts,1); Put(fx.unit,mo::kUnitMenPerMount,1);
        Reset(); RunOriginalLoop(A(fx.unit),arg1,serial); const Snapshot stock=Capture(gSerialOut);
        // host: the real shape, [unit+0x34] = 0, widen
        Build(s); Reset(); U slot=serial; mo::Gate(A(fx.unit),arg1,&slot); const Snapshot host=Capture(slot);
        Require(stock.events.size()>=6,"stock loop ran the one-mount body");
        CompareUnits(stock,host,true,"host gate call trace equals the original loop body");
        // widen off: radius untouched, everything else identical
        mo::Configure(false,FakeTargets());
        Build(s); Reset(); slot=serial; mo::Gate(A(fx.unit),arg1,&slot); const Snapshot plain=Capture(slot);
        CompareUnits(stock,plain,false,"non-widening gate equals the original loop body");
        Require(GetF(fx.unit,mo::kUnitRadius)==s.radius,"default keeps the infantry spacing");
        mo::Configure(true,FakeTargets());
    }
}

static void Predicates() {
    const Shape s{5,4,2,4,3,0.4f};
    mo::Configure(true,FakeTargets());
    auto run=[&](const char* what,bool refs,bool officer,U mounts,U men,bool expectMount) {
        Shape t=s; t.menCount=men; Build(t,refs,officer,mounts);
        const std::vector<B> before(fx.unit,fx.unit+kUnitBytes); Reset(); U slot=7;
        const U created=mo::words[mo::WMountsCreated];
        mo::Gate(A(fx.unit),1,&slot);
        Require((mo::words[mo::WMountsCreated]!=created)==expectMount,what);
        if(!expectMount) { Require(trace.empty() && slot==7 && !std::memcmp(before.data(),fx.unit,kUnitBytes),what); }
    };
    run("resolved officer unit gets one mount",true,true,0,5,true);
    run("mounts > 0 stays stock",true,true,3,5,false);
    run("unresolved references skipped",false,true,0,5,false);
    run("officer not first skipped",true,false,0,5,false);
    { Build(s); Put(fx.unit,mo::kUnitGuns,2); const std::vector<B> before(fx.unit,fx.unit+kUnitBytes); Reset(); U slot=5; const U g=mo::words[mo::WSkippedHasGuns];
      mo::Gate(A(fx.unit),1,&slot);
      Require(mo::words[mo::WSkippedHasGuns]==g+1 && trace.empty() && !std::memcmp(before.data(),fx.unit,kUnitBytes),"artillery (guns > 0) keeps its horse-team mount columns native"); }
    run("empty men skipped",true,true,0,0,false);
    for(U which=0;which<4;++which) {
        Build(s); U off[4]={mo::kUnitMountRow,mo::kUnitMountEntity,mo::kUnitMountStats,mo::kUnitMountAnimPtr}; Put(fx.unit,off[which],0);
        const std::vector<B> before(fx.unit,fx.unit+kUnitBytes); Reset(); U slot=9; const U skipped=mo::words[mo::WSkippedNoRefs];
        mo::Gate(A(fx.unit),1,&slot);
        Require(mo::words[mo::WSkippedNoRefs]==skipped+1 && trace.empty() && !std::memcmp(before.data(),fx.unit,kUnitBytes),"each missing reference is counted and leaves the unit native");
    }
    const U faults=mo::words[mo::WFaults]; U slot=0;
    mo::Gate(0x10,1,&slot);
    Require(mo::words[mo::WFaults]==faults+1,"unreadable unit is a counted fault");
    Require(mo::words[mo::WUnitsSeen]>=10 && mo::words[mo::WSkippedHasMounts]==1 && mo::words[mo::WSkippedNoOfficer]==1 && mo::words[mo::WVersion]==mo::kVersion,"counters");
    U snap[mo::kWords]; mo::Snapshot(snap); Require(snap[mo::WMountsCreated]==mo::words[mo::WMountsCreated],"snapshot");
}

static void Redirect() {
    B* site=At(mo::kCallSite); B original[5]; std::memcpy(original,site,5);
    Require(original[0]==0xE8 && Get(site,1)==mo::kCtor+delta-(A(site)+5),"0x531340 is the single call of the unit constructor");
    mo::ResetRow();
    const U clone=A(stub);
    Require(mo::InstallRedirect(delta,clone),"install");
    Require(site[0]==0xE8 && Get(site,1)==clone-(A(site)+5) && mo::words[mo::WPatchInstalled]==1,"displacement points at the clone, opcode untouched");
    Require(mo::RemoveRedirect(delta) && !std::memcmp(original,site,5) && mo::words[mo::WPatchInstalled]==0,"remove restores the original bytes");
    Require(mo::RemoveRedirect(delta),"remove without install is a no-op");
    site[1]^=0x55; B modified[5]; std::memcpy(modified,site,5);
    Require(!mo::InstallRedirect(delta,clone) && !std::memcmp(modified,site,5),"install refuses a modified call and writes nothing");
    std::memcpy(site,original,5);
    Require(mo::InstallRedirect(delta,clone),"install again");
    site[1]^=0x55;
    Require(!mo::RemoveRedirect(delta),"remove refuses a foreign displacement");
    site[1]^=0x55;
    Require(mo::RemoveRedirect(delta) && !std::memcmp(original,site,5),"remove after the foreign change was undone");
}

int main(int argc,char** argv) {
    if(argc<2) { std::fprintf(stderr,"usage: native_mounted_officer_oracle <Napoleon.exe>\n"); return 2; }
    Map(argv[1]);
    { const B expect[]={0x85,0xC9,0x0F,0x8E,0x2C,0x02,0x00,0x00}; Require(!std::memcmp(At(0x51C22E),expect,sizeof expect),"mount-loop gate is the pinned original"); }
    { const B* p=At(0x51BFB9); Require(p[0]==0x8B && p[1]==0x4D && p[2]==0x34,"[unit+0x34] load"); }
    PatchCalls();
    Equivalence();
    Predicates();
    Redirect();
    std::printf("native_mounted_officer_oracle: OK (%u checks)\n",checks);
    return 0;
}

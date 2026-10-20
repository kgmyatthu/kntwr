// Oracle for src/ai/ntw2_group_standoff.{h,cpp} (--ai-standoff).
//  * call sites: in the owned image both `call 0x78B1C0` sites inside 0x7C7DC0 (0x7C7DD2, 0x7C82F6) are E8 rel32 to 0x78B1C0 and 0x7C7DC0's only callers are 0x7A6910 / 0x7A6960
//    (byte check); InstallRedirect / RemoveRedirect patch exactly the two displacements of a private relocated mapping, restore them bit for bit, refuse a mismatching site
//    without a partial write;
//  * off / excluded: a disabled gate, a foreign dump slot, a melee-only group and a group with no enemy in the corridor return the native point bit for bit;
//  * geometry on synthetic engine objects (the layout the gate reads): straight line, curved front, wide / deep lines, lateral corridor, own-side units in the region list,
//    radius-search fallback: the point lies at k x range short of the nearest enemy man along the heading, never behind the group front and never past the native centre;
//  * moving front: the cached point is reused inside the re-check window, kept while the front moved <= 15 m, re-issued once it moved more.
// Native callees 0x78B1C0 / 0x78B070 / 0x5646A0 are scripted host fakes; engine objects are zero-filled host memory carrying only the fields the gate reads.
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
#include <vector>
#include "native_image_relocation.h"
#include "ntw2_runtime.h"
#include "ai/ntw2_group_standoff.h"
#pragma comment(lib,"bcrypt.lib")
using U=uint32_t;
using B=unsigned char;
namespace so=ntw2_group_standoff;
static_assert(sizeof(void*)==4,"owned x86 oracle");
static B* image;
static U delta, checks, imageSize;
static void Require(bool ok,const char* what) { ++checks; if(!ok) { std::fprintf(stderr,"FAIL %s\n",what); std::exit(1); } }
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static B* At(U va) { return reinterpret_cast<B*>(va+delta); }
template<class T> static U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static void Put(void* p,U offset,U v) { std::memcpy(static_cast<B*>(p)+offset,&v,4); }
static void PutF(void* p,U offset,float v) { std::memcpy(static_cast<B*>(p)+offset,&v,4); }
static U Get(const void* p,U offset) { U v; std::memcpy(&v,static_cast<const B*>(p)+offset,4); return v; }
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

// ---------------------------------------------------------------------------------------------------------------------- call sites
static U RelOf(U site) { return Get(At(site)+1,0); }
static void TestSites() {
    Require(At(so::kSiteFirst)[0]==0xE8 && At(so::kSiteReset)[0]==0xE8,"both sites are E8 calls");
    Require(RelOf(so::kSiteFirst)==so::kRegionCentreOriginal-(so::kSiteFirst+5) && RelOf(so::kSiteReset)==so::kRegionCentreOriginal-(so::kSiteReset+5),"both sites call 0x78B1C0");
    // 0x7C7DC0 has exactly two callers (0x7A6910 = state-4 enter, 0x7A6960 = update): E8 rel32 to it at 0x7A691F and 0x7A6ADE; no other E8 in the image text targets it.
    Require(RelOf(0x7A691F)==0x7C7DC0u-(0x7A691F+5) && At(0x7A691F)[0]==0xE8 && RelOf(0x7A6ADE)==0x7C7DC0u-(0x7A6ADE+5) && At(0x7A6ADE)[0]==0xE8,"callers of 0x7C7DC0");
    // The tactic constructor 0x70B9A0 stores the vtable 0x13430C8 (C7 03 imm32 at 0x70B9BF) whose slot +0x20 is the ATTACK_BATTLEGROUP dump 0x765540.
    Require(At(0x70B9BF)[0]==0xC7 && At(0x70B9BF)[1]==0x03 && Get(At(0x70B9BF),2)==so::kVtable+delta,"tactic constructor stores the ATTACK_BATTLEGROUP vtable");
    Require(Get(At(so::kVtable+0x20),0)==0x765540u+delta,"vtable slot +0x20 is the dump 0x765540");
    const U saved0=RelOf(so::kSiteFirst), saved1=RelOf(so::kSiteReset);
    const U gate=Fn(&so::RegionGate);
    Require(so::InstallRedirect(delta,gate),"install");
    Require(RelOf(so::kSiteFirst)==gate-(so::kSiteFirst+delta+5) && RelOf(so::kSiteReset)==gate-(so::kSiteReset+delta+5),"both displacements point at the gate");
    Require(At(so::kSiteFirst)[0]==0xE8 && At(so::kSiteReset)[0]==0xE8 && At(so::kSiteFirst+5)[0]==At(so::kSiteFirst+5)[0],"opcodes kept");
    Require(!so::InstallRedirect(delta,gate),"a second install is refused (sites no longer the native call)");
    Require(so::RemoveRedirect(delta),"remove");
    Require(RelOf(so::kSiteFirst)==saved0 && RelOf(so::kSiteReset)==saved1,"displacements restored bit for bit");
    Require(so::RemoveRedirect(delta),"remove is idempotent");
    // A mismatching second site refuses the install and leaves the first one untouched.
    Put(At(so::kSiteReset),1,saved1+4);
    Require(!so::InstallRedirect(delta,gate),"install refused on a mismatching site");
    Require(RelOf(so::kSiteFirst)==saved0,"no partial write");
    Put(At(so::kSiteReset),1,saved1);
    std::printf("sites: ok\n");
}

// ---------------------------------------------------------------------------------------------------------------------- synthetic engine objects
constexpr U kUnits=64, kMen=300;
struct World {
    B tactic[0x900]; U vtable[0x40]; B planner[0x40]; B model[0x100]; B manager[0x100]; B sides[2][0x100]; B army[2][0x100];
    B box[0x40]; B region[0x80]; U groupList[8]; U regionList[64]; U sideArr[2]; U armyArr[2][1]; U unitArr[2][kUnits];
    B unit[2][kUnits][0xE00]; B formation[2][kUnits][0x700]; U memberArr[2][kUnits][kMen]; B man[2][kUnits][kMen][0x60];
    U sideUnits[2];
};
static World* w;
static void* noAccess;
static float rangeOf[2][kUnits];
static U weaponless;                 // group units with no weapon record
static float nativeX, nativeZ;       // 0x78B1C0's centre
static U vtableToken;
static U __fastcall FakeRegionOf(U,U) { return A(w->region); }
static float* __fastcall FakeCentre(U,U,float* out) { out[0]=nativeX; out[1]=nativeZ; return out; }
static float __fastcall FakeRange(U unit,U) {
    for(U s=0;s<2;++s) for(U i=0;i<kUnits;++i) if(unit==A(w->unit[s][i])) return rangeOf[s][i];
    return 0.0f;
}
static void Reset() {
    std::memset(w,0,sizeof(*w));
    std::memset(rangeOf,0,sizeof(rangeOf));
    vtableToken=A(w->vtable); Put(w->tactic,0,vtableToken);
    Put(w->tactic,4,A(w->planner)); Put(w->planner,8,A(w->model));
    Put(w->tactic,0x88+0x50,A(w->box));
    Put(w->tactic,0x88+0x20,0); Put(w->tactic,0x88+0x24,A(w->groupList));
    Put(w->model,0x58,1000); PutF(w->model,0x84,0); PutF(w->model,0x88,0); PutF(w->model,0x8C,4096); PutF(w->model,0x90,4096);
    Put(w->model,0xB0,A(w->manager));
    Put(w->manager,0x84,2); Put(w->manager,0x88,A(w->sideArr));
    for(U s=0;s<2;++s) {
        w->sideArr[s]=A(w->sides[s]); Put(w->sides[s],0x10,s); Put(w->sides[s],0x20,1); Put(w->sides[s],0x24,A(w->armyArr[s]));
        w->armyArr[s][0]=A(w->army[s]); Put(w->army[s],0xF4,A(w->unitArr[s]));
    }
    PutF(w->region,8,0); PutF(w->region,0xC,0); Put(w->region,0x5C,0); Put(w->region,0x60,A(w->regionList));
    nativeX=0; nativeZ=500;
    // group box: centre (0,0), width 40, depth 20, forward +z
    PutF(w->box,8,0); PutF(w->box,0xC,0); PutF(w->box,0x14,40); PutF(w->box,0x18,20); PutF(w->box,0x24,0); PutF(w->box,0x28,1);
}
// Adds a unit of side s with men at the given positions; returns its index.
static U AddUnit(U s,const std::vector<std::pair<float,float>>& men,float range,float radius) {
    const U i=w->sideUnits[s]++;
    B* u=w->unit[s][i]; B* f=w->formation[s][i];
    Put(u,0x2CC,static_cast<U>(men.size())); Put(u,0x2D0,A(w->memberArr[s][i])); Put(u,0xAA0,0); Put(u,0xADC,A(f));
    float cx=0,cz=0;
    for(U m=0;m<men.size();++m) { B* mm=w->man[s][i][m]; PutF(mm,0x48,men[m].first); PutF(mm,0x50,men[m].second); w->memberArr[s][i][m]=A(mm); cx+=men[m].first; cz+=men[m].second; }
    if(!men.empty()) { cx/=men.size(); cz/=men.size(); }
    PutF(f,0x644,cx); PutF(f,0x648,cz); PutF(f,0x670,radius);
    Put(u,0xDC4,range>0.0f ? 1u : 0u); rangeOf[s][i]=range;
    w->unitArr[s][i]=A(u); Put(w->army[s],0xF0,w->sideUnits[s]);
    return i;
}
static void AddToGroup(U unitIndex) { U n=Get(w->tactic,0x88+0x20); w->groupList[n]=A(w->unit[0][unitIndex]); Put(w->tactic,0x88+0x20,n+1); }
static void AddToRegion(U s,U i) { U n=Get(w->region,0x5C); w->regionList[n]=A(w->unit[s][i]); Put(w->region,0x5C,n+1); }
static std::vector<std::pair<float,float>> Line(float x0,float x1,float z,U ranks,float step=1.0f) {
    std::vector<std::pair<float,float>> v;
    for(U r=0;r<ranks;++r) for(float x=x0;x<=x1;x+=step) v.push_back({x,z+3.0f*r});
    return v;
}
static so::Targets Targets() { return so::Targets{Fn(&FakeCentre),Fn(&FakeRegionOf),Fn(&FakeRange),vtableToken}; }
static float out2[2];
static void Call() { out2[0]=0; out2[1]=0; so::RegionGate(A(w->tactic),0,out2); }
static U W(so::Word i) { return so::words[i]; }
static bool Near(float a,float b,float eps=0.01f) { return std::fabs(a-b)<=eps; }
static void SetTick(U t) { Put(w->model,0x58,t); }

static void TestOffAndExcluded() {
    Reset(); const U g=AddUnit(0,Line(-20,20,0,2),110,40); AddToGroup(g);
    const U e=AddUnit(1,Line(-50,50,300,2),110,60); AddToRegion(1,e);
    so::Configure(false,90,Targets()); Call();
    Require(out2[0]==nativeX && out2[1]==nativeZ && W(so::WCalls)==1 && W(so::WApplied)==0,"switch off: native centre bit for bit, only the call counted");
    so::Configure(true,90,Targets()); Call();
    Require(W(so::WApplied)==1 && out2[1]<nativeZ,"switch on: a stand-off point");
    // A foreign tactic class (another vtable) keeps the native point.
    Put(w->tactic,0,vtableToken+4); so::Configure(true,90,Targets()); Call();
    Require(out2[0]==nativeX && out2[1]==nativeZ && W(so::WFbTactic)==1 && W(so::WApplied)==0,"foreign tactic class: native");
    Put(w->tactic,0,vtableToken);
    // Melee-only group (no weapon record anywhere): native.
    Reset(); const U c=AddUnit(0,Line(-20,20,0,2),0,40); AddToGroup(c); const U e2=AddUnit(1,Line(-50,50,300,2),110,60); AddToRegion(1,e2);
    so::Configure(true,90,Targets()); Call();
    Require(out2[0]==nativeX && out2[1]==nativeZ && W(so::WFbNoRange)==1,"melee-only group: native");
    // One missile unit among melee units is enough.
    const U m=AddUnit(0,Line(-20,20,-30,2),110,40); AddToGroup(m); so::Configure(true,90,Targets()); Call();
    Require(W(so::WApplied)==1 && W(so::WLastRange)==110,"mixed group: stand-off from the missile member's range");
    // No enemy man inside the corridor (all beyond the lateral reach): native.
    Reset(); const U g3=AddUnit(0,Line(-20,20,0,2),110,40); AddToGroup(g3); const U e3=AddUnit(1,Line(300,340,300,2),110,60); AddToRegion(1,e3);
    so::Configure(true,90,Targets()); Call();
    Require(out2[0]==nativeX && out2[1]==nativeZ && W(so::WFbNoEnemy)==1,"no enemy in the corridor: native");
    std::printf("off/excluded: ok\n");
}
static void TestGeometry() {
    // straight line: 2 ranks at z = 300, 303; range 110, k 0.9 -> Pf.z = 300 - 99 = 201, x = 0 (on the approach line).
    Reset(); const U g=AddUnit(0,Line(-20,20,0,2),110,40); AddToGroup(g);
    const U e=AddUnit(1,Line(-50,50,300,2),110,60); AddToRegion(1,e);
    so::Configure(true,90,Targets()); Call();
    Require(Near(out2[0],0) && Near(out2[1],201.0f),"straight line: k x range short of the nearest enemy rank");
    Require(W(so::WRecomputes)==1 && W(so::WPoints)==1 && W(so::WGroups)==1 && W(so::WSrcGlobal)==0,"one evaluation, region-list source");
    Call(); Require(Near(out2[1],201.0f) && W(so::WRecomputes)==1 && W(so::WKept)==0,"cached inside the re-check window");
    // k scales it: 0.5 -> 300 - 55.
    so::Configure(true,50,Targets()); Call(); Require(Near(out2[1],245.0f),"k = 0.5");
    // Own-side units in the region list are ignored (nearer own unit must not become the front).
    Reset(); const U g2=AddUnit(0,Line(-20,20,0,2),110,40); AddToGroup(g2);
    const U own=AddUnit(0,Line(-10,10,150,1),110,30); AddToRegion(0,own);
    const U e2=AddUnit(1,Line(-50,50,300,2),110,60); AddToRegion(1,e2);
    so::Configure(true,90,Targets()); Call(); Require(Near(out2[1],201.0f),"own-side units in the target region are not the enemy edge");
    // Curved front: arc z = 400 - 0.002 x^2 around the line; the nearest man inside the corridor (|x| <= 20 + 110) sits at |x| = 130 -> z = 366.2.
    Reset(); const U g3=AddUnit(0,Line(-20,20,0,2),110,40); AddToGroup(g3);
    std::vector<std::pair<float,float>> arc; for(float x=-200;x<=200;x+=2) arc.push_back({x,400.0f-0.002f*x*x*1.0f});
    const U e3=AddUnit(1,arc,110,200); AddToRegion(1,e3);
    so::Configure(true,90,Targets()); Call();
    {   // nearest man in the corridor: smallest z among |x| <= 130 -> the corridor edge
        float best=1e9f; for(auto& m:arc) if(std::fabs(m.first)<=130.0f && m.second<best) best=m.second;
        Require(Near(out2[1],best-99.0f,0.05f) && Near(out2[0],0),"curved front: the point follows the nearest man in the corridor");
    }
    // Wide enemy, men outside the lateral corridor are ignored even when nearer: a skirmisher at x = 300, z = 100 must not pull the stand-off.
    Reset(); const U g4=AddUnit(0,Line(-20,20,0,2),110,40); AddToGroup(g4);
    const U e4=AddUnit(1,Line(-50,50,300,2),110,60); AddToRegion(1,e4);
    const U sk=AddUnit(1,Line(300,300,100,1),110,5); AddToRegion(1,sk);
    so::Configure(true,90,Targets()); Call(); Require(Near(out2[1],201.0f),"lateral corridor: far-flank skirmisher ignored");
    // Global fallback: the region list is empty, the enemy stands within kSearchM of the native centre.
    Reset(); const U g5=AddUnit(0,Line(-20,20,0,2),110,40); AddToGroup(g5); AddUnit(1,Line(-50,50,300,2),110,60);
    so::Configure(true,90,Targets()); Call(); Require(Near(out2[1],201.0f) && W(so::WSrcGlobal)==1,"radius-search fallback");
    // Enemy men behind the group (t < 0) are not an edge.
    Reset(); const U g6=AddUnit(0,Line(-20,20,0,2),110,40); AddToGroup(g6); const U back=AddUnit(1,Line(-10,10,-80,2),110,30); AddToRegion(1,back);
    so::Configure(true,90,Targets()); Call(); Require(out2[1]==nativeZ && W(so::WFbNoEnemy)==1,"enemy behind the group: native");
    // Heading is the direction group -> native centre (diagonal approach): enemy line square to it.
    Reset(); nativeX=300; nativeZ=300; const U g7=AddUnit(0,Line(-20,20,0,2),110,40); AddToGroup(g7);
    std::vector<std::pair<float,float>> diag; const float s=std::sqrt(0.5f); for(float u=-40;u<=40;u+=2) diag.push_back({300*s*1.0f+(-u)*s*0.0f+u*s*1.0f, 300*s-u*s}); // line square to h at t = 300
    const U e7=AddUnit(1,diag,110,60); AddToRegion(1,e7);
    so::Configure(true,90,Targets()); Call();
    {   const float t=(out2[0]*s+out2[1]*s); Require(Near(t,300.0f-99.0f,0.1f) && Near(out2[0],out2[1],0.05f),"diagonal approach: on the line group->centre at te - k x range"); }
    std::printf("geometry: ok\n");
}
static void TestHoldAndBounds() {
    // Enemy already inside k x range of the group front (front dot = 10 + 2 m lead): hold at the front, never behind the group.
    Reset(); const U g=AddUnit(0,Line(-20,20,0,2),110,40); AddToGroup(g);
    const U e=AddUnit(1,Line(-50,50,80,2),110,60); AddToRegion(1,e);
    so::Configure(true,90,Targets()); Call();
    Require(Near(out2[0],0) && Near(out2[1],12.0f) && W(so::WHolds)==1 && out2[1]>0,"enemy inside the stand-off: hold at the group front (D/2 + 2 m ahead of the centre)");
    // Region centre not past the group front: native.
    Reset(); nativeZ=8; const U g2=AddUnit(0,Line(-20,20,0,2),110,40); AddToGroup(g2); const U e2=AddUnit(1,Line(-5,5,200,1),110,10); AddToRegion(1,e2);
    so::Configure(true,90,Targets()); Call(); Require(out2[1]==nativeZ,"native centre at or behind the group front: native");
    // Point outside the play rect: native.
    Reset(); const U g3=AddUnit(0,Line(-20,20,0,2),110,40); AddToGroup(g3); const U e3=AddUnit(1,Line(-50,50,300,2),110,60); AddToRegion(1,e3);
    PutF(w->model,0x90,150.0f); so::Configure(true,90,Targets()); Call(); Require(out2[1]==nativeZ && W(so::WFbBounds)==1,"stand-off outside the play rect: native");
    // Unreadable group state: native + fault counted when a pointer is poisoned.
    Reset(); const U g4=AddUnit(0,Line(-20,20,0,2),110,40); AddToGroup(g4); const U e4=AddUnit(1,Line(-50,50,300,2),110,60); AddToRegion(1,e4);
    w->groupList[0]=A(noAccess); so::Configure(true,90,Targets()); Call();
    Require(out2[0]==nativeX && out2[1]==nativeZ && (W(so::WFaults)+W(so::WFbUnreadable)+W(so::WFbTactic))==1,"poisoned member pointer: native centre kept, counted");
    std::printf("hold/bounds: ok\n");
}
static void TestMoving() {
    Reset(); const U g=AddUnit(0,Line(-20,20,0,2),110,40); AddToGroup(g);
    std::vector<std::pair<float,float>> men=Line(-50,50,300,2); const U e=AddUnit(1,men,110,60); AddToRegion(1,e);
    so::Configure(true,90,Targets()); SetTick(1000); Call(); const float p0=out2[1];
    Require(Near(p0,201.0f),"initial point");
    // The enemy advances 10 m: inside the hysteresis, the issued point is kept after the re-check.
    auto Shift=[&](float dz) { for(U m=0;m<men.size();++m) PutF(w->man[1][e][m],0x50,men[m].second+dz); };
    Shift(-10.0f); SetTick(1005); Call(); Require(Near(out2[1],p0) && W(so::WRecomputes)==1,"inside the re-check window: cached");
    SetTick(1010); Call(); Require(Near(out2[1],p0) && W(so::WRecomputes)==2 && W(so::WKept)==1 && W(so::WPoints)==1,"front moved 10 m: evaluated, issued point kept");
    // 40 m more: re-issued at the new front.
    Shift(-40.0f); SetTick(1020); Call(); Require(Near(out2[1],p0-40.0f) && W(so::WPoints)==2,"front moved > 15 m: new point issued");
    // The native centre moving > 15 m forces an early re-check (fast window).
    Shift(-70.0f); nativeZ=450; SetTick(1022); Call(); Require(W(so::WRecomputes)==4 && Near(out2[1],p0-70.0f),"native centre moved: re-evaluated after the fast window");
    // Time going backwards (new battle) re-evaluates.
    SetTick(5); Call(); Require(W(so::WRecomputes)==5,"tick regression re-evaluates");
    // A vanished enemy (no men) falls back to the native centre and counts.
    for(U m=0;m<men.size();++m) PutF(w->man[1][e][m],0x50,-1000.0f);
    SetTick(100); Call(); Require(out2[1]==nativeZ && W(so::WFbNoEnemy)>=1,"no enemy left: native centre");
    std::printf("moving: ok\n");
}
int main(int argc,char** argv) {
    if(argc!=2) { std::fprintf(stderr,"usage: native_group_standoff_oracle Napoleon.exe\n"); return 2; }
    Map(argv[1]);
    w=static_cast<World*>(VirtualAlloc(nullptr,sizeof(World),MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    Require(w!=nullptr && A(w)>0x10000u && A(w)+sizeof(World)<0xFFFF0000u,"fixture allocation");
    noAccess=VirtualAlloc(nullptr,0x1000,MEM_RESERVE|MEM_COMMIT,PAGE_NOACCESS); Require(noAccess!=nullptr && A(noAccess)>0x10000u,"no-access page");
    TestSites(); TestOffAndExcluded(); TestGeometry(); TestHoldAndBounds(); TestMoving();
    std::printf("group standoff oracle: %u checks\n",checks);
    return 0;
}

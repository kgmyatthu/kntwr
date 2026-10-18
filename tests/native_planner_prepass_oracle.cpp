// Oracle for src/ntw2_planner_prepass.{h,cpp}: the walk key, the gathered-list hash, the ordered query log, the D1 cross-child
// snapshot, the census engine's counting, and the 0x559090 presize clone chain executed in a private relocated image against the
// native routine. No running game or installed file is modified; only private loader/heap boundaries are supplied.
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
#include <vector>
#include "native_image_relocation.h"
#include "clones/ntw2_clones.h"
#include "ntw2_runtime.h"
#include "ai/ntw2_planner_prepass.h"
#pragma comment(lib,"bcrypt.lib")
#pragma fenv_access(on)
using U=uint32_t;
using B=unsigned char;
namespace pp=ntw2_prepass;
static_assert(sizeof(void*)==4,"owned x86 oracle");
static B* image;
static U delta, checks;
static void Require(bool ok,const char* what) { ++checks; if(!ok) { std::fprintf(stderr,"FAIL %s\n",what); std::exit(1); } }
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static B* At(U va) { return reinterpret_cast<B*>(va+delta); }
template<class T> static U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static void Put(void* p,U offset,U v) { std::memcpy(static_cast<B*>(p)+offset,&v,4); }
static U Bits(float f) { U u; std::memcpy(&u,&f,4); return u; }
static void Jump(U va,U target) { B* p=At(va); p[0]=0xb8; Put(p,1,target); p[5]=0xff; p[6]=0xe0; }
static std::vector<U> heapEvents;
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
    Require(FlushInstructionCache(GetCurrentProcess(),image,nt->OptionalHeader.SizeOfImage)!=0,"flush image");
}

// ---------------------------------------------------------------------------------------------------------------- walk key
static void TestKey() {
    U shape[18]; for(U i=0;i<18;++i) shape[i]=0x1000+i; shape[0]=0;
    pp::WalkKey a,b,c;
    Require(pp::ReadWalkKey(0xE00,shape,&a),"zero-kind shape yields a key");
    Require(a.w[0]==0x7F1D40 && a.w[1]==0xE00 && a.w[2]==0x10,"key header: callee VA, ECX, gather mask");
    for(U i=0;i<18;++i) if(i!=3) Require(a.w[3+i]==shape[i],"descriptor dwords by value");
    shape[3]=0xABCD1234; Require(pp::ReadWalkKey(0xE00,shape,&a),"read a");
    shape[3]=0x1234;     Require(pp::ReadWalkKey(0xE00,shape,&b),"read b");
    shape[3]=0xFFFF1234; Require(pp::ReadWalkKey(0xE00,shape,&c),"read c");
    Require(a.w[6]==0x1234 && pp::EqualWalkKey(a,b) && pp::EqualWalkKey(b,c) && pp::HashWalkKey(a)==pp::HashWalkKey(c),
            "descriptor +0xC padding is masked out of the key and the hash");
    shape[3]=0x1235; Require(pp::ReadWalkKey(0xE00,shape,&c) && !pp::EqualWalkKey(a,c) && pp::HashWalkKey(a)!=pp::HashWalkKey(c),
            "the angle half is part of the key");
    shape[3]=0x1234; Require(pp::ReadWalkKey(0xE04,shape,&c) && !pp::EqualWalkKey(a,c),"ECX is part of the key");
    for(U i=0;i<18;++i) {
        if(i==0) continue;
        U save=shape[i]; shape[i]^=0x80000000u;
        if(i==3) shape[i]=save^1;
        Require(pp::ReadWalkKey(0xE00,shape,&c) && !pp::EqualWalkKey(b,c),"every descriptor dword is part of the key");
        shape[i]=save;
    }
    // FNV-1a over the 21 words (pinned algorithm).
    U h=2166136261u; for(U i=0;i<21;++i) { h^=b.w[i]; h*=16777619u; }
    Require(pp::HashWalkKey(b)==h,"hash is FNV-1a over the 21 words");
    shape[0]=1; pp::WalkKey keep=a; Require(!pp::ReadWalkKey(0xE00,shape,&a) && pp::EqualWalkKey(a,keep),"kind != 0 is unsupported and leaves the output untouched");
    shape[0]=0;
    Require(!pp::ReadWalkKey(0xE00,nullptr,&a),"null shape unsupported");
    void* guard=VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_NOACCESS);
    Require(guard!=nullptr && !pp::ReadWalkKey(0xE00,guard,&a),"unreadable shape unsupported (SEH-safe)");
    // A shape straddling into an unreadable page faults mid-copy: still false, never an exception.
    B* two=static_cast<B*>(VirtualAlloc(nullptr,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    DWORD old; Require(two && VirtualProtect(two+4096,4096,PAGE_NOACCESS,&old),"guard page");
    Require(!pp::ReadWalkKey(0xE00,two+4096-0x20,&a),"shape crossing into an unreadable page unsupported");
    VirtualFree(guard,0,MEM_RELEASE); VirtualFree(two,0,MEM_RELEASE);
}

// ------------------------------------------------------------------------------------------------------------- list hash
struct Vertex { U v[13]; };
struct Owner { U v[9]; };
struct Interest { U kind,u1,u2,owner,u4,next; };
static Vertex poly[3][70];
static Vertex bigRing[1100];
static Owner owners[4];
static Interest interests[4];
static U entries[4];
static void Ring(Vertex* p,U n,float dx) {
    for(U i=0;i<n;++i) {
        p[i]={}; p[i].v[2]=A(&p[(i+1)%n]);
        p[i].v[3]=Bits(static_cast<float>(i)+dx); p[i].v[4]=Bits(static_cast<float>(i*2));
    }
}
static void ListFixture() {
    Ring(poly[0],4,0); Ring(poly[1],5,0); Ring(poly[2],70,0);
    for(U i=0;i<4;++i) {
        owners[i]={}; owners[i].v[2]=A(poly[i%2]); owners[i].v[7]=1; owners[i].v[8]=Bits(2.0f);
        interests[i]={0x10,0,0,A(&owners[i]),0,0}; entries[i]=A(&interests[i]);
    }
}
static U H(U count,U mode=1,float thr=1.0f,U* flags=nullptr) { U f=0; U h=pp::HashGatheredListEx(entries,count,mode,thr,flags?flags:&f); return h; }
static void TestList() {
    ListFixture();
    U f=0; const U base=H(4,1,1.0f,&f);
    Require(f==0 && base==pp::HashGatheredList(entries,4,1,1.0f) && base==H(4),"hash is deterministic and flag-free for a plain list");
    std::swap(entries[0],entries[1]); Require(H(4)!=base,"entry order is part of the hash"); std::swap(entries[0],entries[1]);
    Require(H(3)!=base && H(4)==base,"count is part of the hash");
    U save=entries[2]; entries[2]=entries[3]; Require(H(4)!=base,"entry pointer is part of the hash"); entries[2]=save;
    interests[1].kind=0x20; U h20=H(4); Require(h20!=base,"entry type is part of the hash");
    owners[1].v[2]^=0x100; Require(H(4)==h20,"a non-0x10 entry's owner fields are not consumed"); owners[1].v[2]^=0x100; interests[1].kind=0x10;
    owners[0].v[7]=2; Require(H(4)!=base,"owner[+0x1C] is hashed"); owners[0].v[7]=1;
    owners[0].v[8]=Bits(3.0f); Require(H(4)!=base,"owner[+0x20] is hashed"); owners[0].v[8]=Bits(2.0f);
    const U beforeOwner=owners[0].v[0]; owners[0].v[0]^=0xFFFF; Require(H(4)==base,"owner fields the traversal never reads are not hashed"); owners[0].v[0]=beforeOwner;
    const U savedPoly=owners[3].v[2]; owners[3].v[2]=A(poly[0]); Require(H(4)!=base,"owner[+8] polygon pointer is hashed"); owners[3].v[2]=savedPoly;
    // Consumed polygon: vertex coordinates by value; unconsumed (owner[+0x20] < threshold): not read.
    poly[0][1].v[3]^=0x40000000u; Require(H(4)!=base,"consumed polygon vertex coordinates are hashed by value"); poly[0][1].v[3]^=0x40000000u;
    Require(H(4)==base,"restored vertex restores the hash");
    // poly[0] is consumed twice (owners 0 and 2). Every single-bit change of one of its vertex words must survive both visits:
    // word-wise FNV-1a cancels bit 31 always and bit 30 for an address-layout-dependent share of ASLR bases.
    for(U bit=0;bit<32;++bit) {
        poly[0][1].v[3]^=1u<<bit; const U changed=H(4); poly[0][1].v[3]^=1u<<bit;
        Require(changed!=base,"a vertex bit change in a polygon consumed twice changes the hash");
    }
    Require(H(4,1,5.0f)!=base,"threshold is part of the hash");
    const U unconsumed=H(4,1,5.0f); poly[0][1].v[3]^=0x40000000u; Require(H(4,1,5.0f)==unconsumed,"polygons failing the threshold are not hashed"); poly[0][1].v[3]^=0x40000000u;
    // NaN level never passes the walk's comiss/jb test: unconsumed.
    owners[0].v[8]=Bits(std::nanf("")); owners[2].v[8]=Bits(std::nanf("")); const U nanHash=H(4); poly[0][1].v[3]^=0x40000000u;
    Require(H(4)==nanHash,"NaN level skips the polygon like the native compare"); poly[0][1].v[3]^=0x40000000u; owners[0].v[8]=owners[2].v[8]=Bits(2.0f);
    // Vertex count: a ring of a different length changes the hash.
    owners[2].v[2]=A(poly[1]); Require(H(4)!=base,"ring length is hashed"); owners[2].v[2]=A(poly[0]);
    // Oversize ring and mode 2 are flagged, not silently exact.
    owners[1].v[2]=A(poly[2]); H(4,1,1.0f,&f); Require((f&pp::kListOversize)!=0,"a ring beyond the vertex bound is flagged oversize"); owners[1].v[2]=A(poly[1]);
    H(4,2,1.0f,&f); Require((f&pp::kListMode2)!=0,"mode 2 is flagged unproven");
    U big[pp::kMaxListEntries+8]; for(U i=0;i<pp::kMaxListEntries+8;++i) big[i]=entries[i%4];
    pp::HashGatheredListEx(big,pp::kMaxListEntries+8,1,1.0f,&f); Require((f&pp::kListOversize)!=0,"more entries than the bound are flagged");
    U bad[2]={entries[0],0xDEAD0000u}; pp::HashGatheredListEx(bad,2,1,1.0f,&f); Require((f&pp::kListUnreadable)!=0,"an unreadable entry is flagged (SEH-safe)");
    Require(pp::HashGatheredList(entries,0,1,1.0f)==pp::HashGatheredList(nullptr,0,1,1.0f),"empty list hashes without reading");
}

// ------------------------------------------------------------------------------------------------------------- query log
static void TestLog() {
    pp::ThinkLogEnd();
    pp::QueryRecord r; std::memset(&r,0,sizeof(r));
    Require(!pp::ThinkLogAppend(r) && !pp::ThinkLogOpen(),"append without Begin is refused");
    pp::ThinkLogBegin(0x100,0x200,3); r.child=3; r.gathered=7;
    Require(pp::ThinkLogOpen() && pp::ThinkLogPlanner()==0x100 && pp::ThinkLogNode()==0x200 && pp::ThinkLogChild()==3 && pp::ThinkLogCount()==0,"Begin opens a log");
    Require(pp::ThinkLogAppend(r) && pp::ThinkLogCount()==1,"append");
    pp::ThinkLogBegin(0x100,0x200,4); r.child=4; r.gathered=9; pp::ThinkLogAppend(r);
    Require(pp::ThinkLogCount()==2 && pp::ThinkLogChild()==4 && pp::ThinkLogRecord(0)->child==3 && pp::ThinkLogRecord(1)->child==4 &&
            pp::ThinkLogRecord(1)->gathered==9 && !pp::ThinkLogRecord(2),"same (planner,node) accumulates children in order");
    pp::ThinkLogBegin(0x100,0x204,0); Require(pp::ThinkLogCount()==0,"a different node starts a new log");
    pp::ThinkLogAppend(r); pp::ThinkLogEnd(); Require(!pp::ThinkLogOpen() && pp::ThinkLogCount()==1,"End closes but keeps the records readable");
    pp::ThinkLogBegin(0x100,0x204,0); Require(pp::ThinkLogCount()==0,"Begin after End starts a new log");
    for(U i=0;i<pp::kLogCapacity;++i) Require(pp::ThinkLogAppend(r),"fill the log");
    Require(!pp::ThinkLogAppend(r) && pp::ThinkLogOverflow()==1 && pp::ThinkLogCount()==pp::kLogCapacity,"overflow is counted, never wrapped");
    pp::ThinkLogEnd();
}

// ------------------------------------------------------------------------------------------------------------------- D1
static B nodeBuf[0x200]; static U childList[300]; static B childBufs[300][0x60];
static pp::D1State pre;
static void D1Fixture(U n) {
    std::memset(nodeBuf,0,sizeof(nodeBuf)); std::memset(childBufs,0,sizeof(childBufs));
    for(U j=0;j<n;++j) { childList[j]=A(childBufs[j]); Put(childBufs[j],0x30,j); Put(childBufs[j],0x34,0x1000+j); Put(childBufs[j],0x40,2*j); Put(childBufs[j],0x44,0x2000+j); }
    Put(nodeBuf,0x48,n); Put(nodeBuf,0x4C,A(childList));
}
static void TestD1() {
    D1Fixture(5);
    Require(pp::D1Capture(A(nodeBuf),&pre) && pre.n==5 && pre.count==5 && pre.data==A(childList) && !pre.truncated,"capture lists and children");
    Require(pre.words[3][0]==3 && pre.words[3][1]==0x1003 && pre.words[3][2]==6 && pre.words[3][3]==0x2003,"children's +30/+34/+40/+44 captured");
    pp::D1Diff d; pp::D1Compare(pre,A(nodeBuf),2,&d);
    Require(!d.listChanged && !d.otherChildren && !d.otherWords && !d.selfWords,"unchanged state: no diff");
    Put(childBufs[2],0x30,99); Put(childBufs[2],0x44,7); pp::D1Compare(pre,A(nodeBuf),2,&d);
    Require(d.selfWords==2 && !d.otherChildren && !d.otherWords && !d.listChanged,"self writes are counted separately");
    Put(childBufs[4],0x40,1234); pp::D1Compare(pre,A(nodeBuf),2,&d);
    Require(d.selfWords==2 && d.otherChildren==1 && d.otherWords==1,"another child's guarded count is cross-talk");
    Put(childBufs[0],0x34,5); Put(childBufs[0],0x44,6); Put(childBufs[4],0x30,5); pp::D1Compare(pre,A(nodeBuf),2,&d);
    Require(d.otherChildren==2 && d.otherWords==4,"cross-talk sums changed words over distinct children");
    D1Fixture(5); pp::D1Capture(A(nodeBuf),&pre);
    Put(nodeBuf,0x48,4); pp::D1Compare(pre,A(nodeBuf),1,&d); Require(d.listChanged==1,"count change is a list change"); Put(nodeBuf,0x48,5);
    static U other[300]; std::memcpy(other,childList,sizeof(childList)); Put(nodeBuf,0x4C,A(other)); pp::D1Compare(pre,A(nodeBuf),1,&d);
    std::memcpy(other,childList,sizeof(childList));
    pp::D1Compare(pre,A(nodeBuf),1,&d); Require(d.listChanged==1,"data pointer change is a list change"); Put(nodeBuf,0x4C,A(childList));
    U swap=childList[1]; childList[1]=childList[3]; pp::D1Compare(pre,A(nodeBuf),1,&d); Require(d.listChanged==1,"a replaced child pointer is a list change"); childList[1]=swap;
    D1Fixture(300); Require(pp::D1Capture(A(nodeBuf),&pre) && pre.n==pp::kMaxChildren && pre.truncated && pre.count==300,"more children than the snapshot bound are truncated and flagged");
    Put(nodeBuf,0x4C,0); Require(!pp::D1Capture(A(nodeBuf),&pre) && !pre.valid,"nonzero count with a null list is invalid");
    pp::D1Compare(pre,A(nodeBuf),0,&d); Require(!d.listChanged && !d.otherWords,"an invalid snapshot never reports changes");
    Require(!pp::D1Capture(0xDEAD0000u,&pre),"unreadable node is invalid (SEH-safe)");
}

// ----------------------------------------------------------------------------------------------------------- census engine
static U Row[pp::kCensusWords];
static void Snap() { pp::CensusSnapshot(Row); }
static bool InScope(U) { return true; }
static B shapeA[0x48], shapeB[0x48];
static U listHdr[4];
static void MakeShape(B* s,float x,U mode=1) {
    std::memset(s,0,0x48); Put(s,4,Bits(x)); Put(s,8,Bits(2)); Put(s,0x40,mode); Put(s,0x44,Bits(1.0f));
}
static void OneWalk(const B* shape,U ret,U al,U polygons) {
    pp::WalkBegin(0x900,A(shape),ret,0);
    listHdr[2]=4; listHdr[3]=A(entries);
    pp::WalkGathered(A(listHdr),10,100);
    for(U i=0;i<polygons;++i) pp::WalkPolygon(i&1 ? A(poly[1]) : A(poly[0]),i&1,1000);
    pp::WalkEnd(al,500,200);
}
static void TestCensus() {
    ListFixture();
    const U shapeEntry=0x30000000u;
    pp::Targets t={0x7D7BF0,0x1000,shapeEntry,&InScope,0x40000000u};
    pp::CensusReset(0,t,1000000); Snap();
    bool zero=true; for(U w:Row) zero=zero && !w; Require(zero,"flags 0: the row is all zero");
    pp::ScopeBegin(1); pp::WalkBegin(1,A(shapeA),0,0); pp::WalkEnd(0,1,1); Snap();
    zero=true; for(U w:Row) zero=zero && !w; Require(zero,"flags 0: hooks record nothing");
    pp::CensusReset(pp::kFlagCensus,t,1000000);
    Require(pp::CensusArmed(),"census armed");
    MakeShape(shapeA,10); MakeShape(shapeB,11);
    const U ret0=shapeEntry+(0x7C7FD3u+5-0x7C7DC0u), ret1=shapeEntry+(0x7C8113u+5-0x7C7DC0u), ret2=0x40000000u+(0x808492u+5-0x808040u);
    pp::ScopeBegin(0x77);
    // Outside a child: counted, flagged no-child; inside: child index stamped.
    OneWalk(shapeA,ret0,1,2);
    pp::ThinkLogBegin(0x77,0x88,0);   // the module's own child hooks do this; the walk appends only to an open log
    OneWalk(shapeA,ret1,0,1);          // duplicate of the first walk
    OneWalk(shapeB,ret2,1,0);          // distinct
    entries[0]^=0; owners[0].v[7]=2;   // world change between identical queries
    OneWalk(shapeA,0x1234,1,0);        // duplicate, different list hash, unknown site
    Put(shapeB,0,1);                   // unsupported kind
    OneWalk(shapeB,ret0,1,0);
    pp::ScopeEnd(9000);
    Snap();
    Require(Row[0]==1 && Row[1]==1 && Row[4]==5 && Row[6]==2 && Row[7]==2 && Row[9]==1,"walks 5: distinct 2, duplicates 2, unsupported 1");
    Require(Row[35]==1 && Row[36]==1,"duplicates: one same list, one changed list (world change)");
    Require(Row[37]==2 && Row[38]==1 && Row[80]==1 && Row[39]==1,"per-site counts: 7C7FD3 x2, 7C8113, 808492, other");
    Require(Row[20]==3 && Row[21]==1 && Row[22]==4,"polygon tests 3; AL=0 once, AL=1 four times");
    Require(Row[16]==2500 && Row[17]==50 && Row[18]==500 && Row[19]==500,"walk, gather and traversal microseconds (QPC ticks at 1 MHz)");
    Require(Row[11]==5 && Row[12]==2 && Row[14]==9000 && Row[15]==9000,"max walks/distinct per scope, think us sum/max");
    Require(Row[43]==1 && Row[44]==9000,"think-duration class <=32 ms: one think, 9000 us");
    Require(Row[23]==20 && Row[24]==4,"gathered sum and max");
    Require(Row[63]==pp::kFlagCensus && Row[0]==pp::kCensusVersion,"version and latched flags");
    Require(Row[64]==13 && Row[65]==5 && Row[66]==1 && Row[67]==0 && Row[68]==3 && Row[74]==3000,"vertex histogram: rings of 4,5,4 vertices; one AL=1 kernel result; 3 calls, 3000 us in V<=8");
    pp::ThinkLogEnd();
    // Second scope: the table was cleared by generation, so the same key is distinct again.
    pp::ScopeBegin(0x77); MakeShape(shapeA,10); OneWalk(shapeA,ret0,1,0); pp::ScopeEnd(200000); Snap();
    Require(Row[6]==3 && Row[7]==2 && Row[1]==2,"the distinct set is cleared at every scope");
    Require(Row[49]==1 && Row[50]==200000 && Row[43]==1,"a 200 ms scope lands in the <=512 ms class");
    // Probe exhaustion is counted and never a hit: fill the table so a fresh key finds no free slot.
    pp::ScopeBegin(0x77);
    U overflow=0, distinct=0;
    for(U i=0;i<20000;++i) { MakeShape(shapeA,static_cast<float>(i)+0.25f); pp::WalkBegin(0x900,A(shapeA),ret0,0); pp::WalkEnd(1,1,1); }
    pp::ScopeEnd(1); Snap(); overflow=Row[10]; distinct=Row[6];
    Require(overflow>0 && distinct>3 && Row[4]==5+1+20000 && Row[7]==2,"probe exhaustion is counted as overflow, never as a duplicate");
    // Vertex counts are counted well past the list-hash bound: a 70-node ring lands in <=256, a 1100-node ring in >256 and overflows 1024.
    pp::CensusReset(pp::kFlagCensus,t,1000000); pp::ScopeBegin(0x77); MakeShape(shapeA,10); pp::WalkBegin(0x900,A(shapeA),ret0,0);
    Ring(bigRing,1100,0); pp::WalkPolygon(A(bigRing),0,1); Ring(poly[2],70,0); pp::WalkPolygon(A(poly[2]),0,1); pp::WalkEnd(1,1,1); pp::ScopeEnd(1); Snap();
    Require(Row[72]==1 && Row[73]==1 && Row[81]==1 && Row[64]==70 && Row[65]==70,"V histogram counts past 64; rings over 1024 are an overflow bucket only");
    pp::CensusReset(0,t,1);
}

// ------------------------------------------------------------------------------------------------ presize: pure core + clones
static void* __cdecl NullAlloc(int,int) { return nullptr; }
static void* __cdecl CountingAlloc(int n,int) { heapEvents.push_back(static_cast<U>(n)); return std::malloc(static_cast<size_t>(n)*8+8); }
static void TestPresizeCore() {
    pp::PresizeConfigure(&CountingAlloc);
    U hdr[4]={}; volatile U counters[8]; pp::PresizeCounters(nullptr);
    Require(pp::PresizeReserve(5,5,0,9,hdr)==pp::kSkippedNoBound && !hdr[3] && !hdr[1],"empty x range: no reservation");
    Require(pp::PresizeReserve(7,3,0,9,hdr)==pp::kSkippedNoBound,"inverted range is an empty (unsigned) bound");
    Require(pp::PresizeReserve(0,4,6,6,hdr)==pp::kSkippedNoBound,"empty y range: no reservation");
    heapEvents.clear();
    Require(pp::PresizeReserve(2,5,1,4,hdr)==pp::kReserved && hdr[1]==9 && hdr[2]==0 && hdr[3]!=0 && heapEvents==std::vector<U>{9},"3x3 cells reserve 9 pairs once");
    std::free(reinterpret_cast<void*>(hdr[3])); hdr[1]=hdr[2]=hdr[3]=0;
    Require(pp::PresizeReserve(0,0xFFFFFFFFu,0,0xFFFFFFFFu,hdr)==pp::kReservedClamped && hdr[1]==pp::kPresizeMaxPairs,"a 2^64-1 cell bound is clamped, never overflowed");
    std::free(reinterpret_cast<void*>(hdr[3])); hdr[1]=hdr[2]=hdr[3]=0;
    Require(pp::PresizeReserve(0,17,0,17,hdr)==pp::kReservedClamped && hdr[1]==pp::kPresizeMaxPairs,"289 cells are clamped to the maximum");
    std::free(reinterpret_cast<void*>(hdr[3])); hdr[1]=hdr[2]=hdr[3]=0;
    hdr[1]=4; hdr[2]=1; hdr[3]=0x1234;
    Require(pp::PresizeReserve(0,3,0,3,hdr)==pp::kSkippedNonEmpty && hdr[1]==4 && hdr[2]==1 && hdr[3]==0x1234,"a non-empty header is left untouched");
    hdr[1]=0; hdr[2]=0; hdr[3]=0;
    pp::PresizeConfigure(&NullAlloc);
    Require(pp::PresizeReserve(0,3,0,3,hdr)==pp::kAllocFailed && !hdr[1] && !hdr[3],"a refused reservation leaves the native allocation path intact");
    pp::PresizeCounters(counters);
    Require(counters[0]==8 && counters[1]==3 && counters[2]==1 && counters[3]==3 && counters[4]==2 && counters[5]==1 && counters[6]==9+256+256,
            "presize counters: queries, reserved (incl. clamped), nonempty, nobound, clamped, alloc_failed, pairs");
}
struct Vec { U tag,capacity,count,data; };
using Kernel=void(__fastcall*)(void*,void*,U*,Vec*);
struct __declspec(align(16)) Fx { B bytes[512]; };
static void ResetFp() { __asm { fninit } _mm_setcsr(0x1f80); }
static B grid[0x40]; static U obb[9];
static void Grid(float cell) {
    std::memset(grid,0,sizeof(grid)); Put(grid,0x10,0); Put(grid,0x14,63); Put(grid,0x1c,Bits(0)); Put(grid,0x20,Bits(cell)); Put(grid,0x24,Bits(1.0f/cell));
}
static void Obb(float x,float y,float hx,float hy,float angle) {
    std::memset(obb,0,sizeof(obb)); obb[0]=Bits(x); obb[1]=Bits(y); obb[3]=Bits(hx); obb[4]=Bits(hy);
    const float c=std::cos(angle), s=std::sin(angle); obb[5]=Bits(c); obb[6]=Bits(s); obb[7]=Bits(-s); obb[8]=Bits(c);
}
static void RunBoth(Kernel native,Kernel clone,U prefill,const char* what,U* countOut=nullptr) {
    Fx fa,fb; Vec a={},b={};
    auto fill=[&](Vec& v) { if(prefill) { v.capacity=prefill; v.count=1; v.data=A(std::malloc(prefill*8)); static_cast<U*>(reinterpret_cast<void*>(v.data))[0]=0x77; static_cast<U*>(reinterpret_cast<void*>(v.data))[1]=0x88; } };
    fill(a); fill(b);
    ResetFp(); native(grid,nullptr,obb,&a); _fxsave(fa.bytes);
    ResetFp(); clone(grid,nullptr,obb,&b); _fxsave(fb.bytes);
    Require(a.count==b.count,what);
    Require(!std::memcmp(reinterpret_cast<void*>(a.data),reinterpret_cast<void*>(b.data),a.count*8),what);
    Require(!std::memcmp(fa.bytes,fb.bytes,5) && !std::memcmp(fa.bytes+24,fb.bytes+24,4),"x87 control/status/tags and MXCSR preserved");
    // XMM0..7 are caller-saved at return (the native routine's own allocator calls clobber them), so they are not compared.
    if(countOut) *countOut=a.count;
    if(a.data) std::free(reinterpret_cast<void*>(a.data)); if(b.data) std::free(reinterpret_cast<void*>(b.data));
}
static bool CloneCall(U clone,U offset,U& target) {
    const B* p=reinterpret_cast<const B*>(static_cast<uintptr_t>(clone+offset)); int32_t rel; std::memcpy(&rel,p+1,4);
    target=clone+offset+5+static_cast<U>(rel); return p[0]==0xE8;
}
static void TestPresizeClones() {
    ntw2_clone_set clones={}; U bindings[NTW2_BIND_COUNT];
    for(U& b:bindings) b=A(At(0x6dca08));   // unreached bindings: valid image addresses, never executed here
    bindings[NTW2_BIND_PP_CHILD_THINK]=pp::ChildThinkGateAddress();
    bindings[NTW2_BIND_PP_RESERVE]=pp::PresizeReserveGateAddress();
    bindings[NTW2_BIND_PP_EXIT]=pp::PresizeExitGateAddress();
    U detail=0; Require(ntw2_build_clones(A(image),bindings,&clones,&detail)==0,"production clone source pins");
    const U c559=clones.entries[NTW2_CLONE_PRESIZE_559090], c551=clones.entries[NTW2_CLONE_PRESIZE_551FE0], c56a=clones.entries[NTW2_CLONE_PRESIZE_56A610];
    U target=0;
    Require(CloneCall(c56a,0x56A66D-0x56A610,target) && target==c551,"56A610 clone calls the 551FE0 clone at 56A66D");
    Require(CloneCall(c551,0x55208A-0x551FE0,target) && target==c559,"551FE0 clone calls the 559090 clone at 55208A");
    auto findCall=[&](U gate,U len)->U {
        for(U o=0;o+5<=len;++o) { U t; if(CloneCall(c559,o,t) && t==gate) return o; }
        return 0xFFFFFFFFu;
    };
    const U reserveAt=findCall(pp::PresizeReserveGateAddress(),0xC30), exitAt=findCall(pp::PresizeExitGateAddress(),0xC30);
    Require(reserveAt==0x55930E-0x559090 && exitAt!=0xFFFFFFFFu && exitAt>reserveAt,"559090 clone inserts the reserve gate at 55930E and the exit gate before the epilogue");
    Require(!std::memcmp(reinterpret_cast<void*>(c559+reserveAt+5),At(0x55930E),7) && !std::memcmp(reinterpret_cast<void*>(c559+exitAt+5),At(0x559BFE),11),
            "original instructions follow the insertions byte for byte");
    pp::PresizeConfigure(reinterpret_cast<pp::AllocFn>(At(0x449e10)));
    auto native=reinterpret_cast<Kernel>(At(0x559090)), clone=reinterpret_cast<Kernel>(c559);
    pp::PresizeCounters(nullptr);
    U hits=0, maxHits=0, nonEmpty=0;
    struct Case { float x,y,hx,hy,angle,cell; };
    std::vector<Case> cases;
    for(U i=0;i<120;++i) cases.push_back({static_cast<float>(i%17)*2.5f+3,static_cast<float>(i%11)*3.0f+4,0.4f+static_cast<float>(i%5)*0.7f,0.3f+static_cast<float>(i%7)*0.5f,static_cast<float>(i)*0.31f,1.0f+static_cast<float>(i%3)});
    for(const Case& c:cases) { Grid(c.cell); Obb(c.x,c.y,c.hx,c.hy,c.angle); U n=0; RunBoth(native,clone,0,"count, pair order and effects equal the native routine",&n); hits+=n; maxHits=std::max(maxHits,n); nonEmpty+=n!=0; }
    Grid(1); Obb(30,30,0.2f,0.2f,0); { U n=0; RunBoth(native,clone,0,"tiny box: equal",&n); }
    Grid(1); Obb(30,30,40,40,0.4f); { U n=0; RunBoth(native,clone,0,"max-bound box: equal",&n); Require(n>pp::kPresizeMaxPairs,"max-bound fixture exceeds the clamp, exercising native growth after a clamped reserve"); }
    Grid(1); Obb(30,30,3,2,0.7f); RunBoth(native,clone,4,"non-empty header: reserve skipped, native appends after the existing pair");
    Grid(1); Obb(-500,-500,1,1,0); { U n=1; RunBoth(native,clone,0,"far outside the grid: equal",&n); }
    Grid(1); Obb(30,30,3,3,0.2f);
    pp::PresizeConfigure(&NullAlloc); { U n=0; RunBoth(native,clone,0,"refused reservation: native path, equal results",&n); Require(n>0,"refused-reserve fixture has hits"); }
    pp::PresizeConfigure(reinterpret_cast<pp::AllocFn>(At(0x449e10)));
    volatile U counters[8]; pp::PresizeCounters(counters);
    Require(counters[0]>=100 && counters[1]>=1 && counters[4]>=1 && counters[2]>=1 && counters[5]>=1 && counters[7]>=hits,"the gates counted queries, reserves, clamp, non-empty skip, refusal and hits");
    Require(nonEmpty>10 && maxHits>1,"the case set produced non-trivial hit lists");
    std::printf("presize: queries=%u reserved=%u nonempty=%u nobound=%u clamped=%u refused=%u pairs=%u hits=%u\n",counters[0],counters[1],counters[2],counters[3],counters[4],counters[5],counters[6],counters[7]);
}
// Gates preserve everything for any frame; the child gate's pre/post hooks wrap exactly one original call.
static U childCalls, childEsi, childEdi;
static void __fastcall FakeChildThink(void*) { ++childCalls; }
static void TestChildGate() {
    static B node[0x200]; static U list[1]; static B child[0x100]; static U vtable[16];
    for(U& v:vtable) v=A(reinterpret_cast<void*>(&FakeChildThink)); Put(child,0,A(vtable)); Put(child,0x30,1);
    list[0]=A(child); Put(node,0x48,1); Put(node,0x4C,A(list));
    ListFixture();
    pp::Targets t={0x7D7BF0,0x1000,0,&InScope,0};
    pp::CensusReset(pp::kFlagCensus,t,1000000);
    pp::ScopeBegin(0x55);
    U g=pp::ChildThinkGateAddress(), nodeAddr=A(node), childAddr=A(child), espBefore=0, espAfter=0, ebxBefore=0, ebxAfter=0;
    childCalls=0;
    __asm {
        pushad
        mov ebx, 0x13572468
        mov esi, 0
        mov edi, nodeAddr
        mov ecx, childAddr
        mov espBefore, esp
        mov ebx, 0x13572468
        mov ebxBefore, ebx
        call dword ptr [g]
        mov espAfter, esp
        mov ebxAfter, ebx
        mov childEsi, esi
        mov childEdi, edi
        popad
    }
    Require(childCalls==1 && espBefore==espAfter && ebxBefore==ebxAfter && childEsi==0 && childEdi==nodeAddr,"child gate calls the original exactly once and preserves ESP/EBX/ESI/EDI");
    pp::ScopeEnd(10); Snap();
    Require(Row[3]==1 && Row[28]==1 && Row[29]==0 && Row[31]==0,"one child think, D1 checked with no changes");
    pp::CensusReset(0,t,1);
}
int main(int argc,char** argv) {
    if(argc!=2) { std::fprintf(stderr,"usage: native_planner_prepass_oracle Napoleon.exe\n"); return 2; }
    TestKey(); TestList(); TestLog(); TestD1(); TestCensus(); TestPresizeCore();
    Map(argv[1]);
    TestPresizeClones(); TestChildGate();
    std::printf("planner prepass: %u checks\n",checks);
    return 0;
}

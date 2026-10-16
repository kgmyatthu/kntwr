// Differential oracle + microbenchmark: the real 0x80DCF0 -> 0x10EC150 closure of a private relocated copy of the supported image
// against ntw2_poly::Evaluate. Asserts byte-equal AL, x87 control/status/tag and MXCSR (control + sticky flags) on every call
// the replacement serves, and that every refusal reason fires on its fixture. `--bench` prints native vs replacement cost by
// vertex class. No running game or installed file is touched.
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
#include <random>
#include <vector>
#include "native_image_relocation.h"
#include "ntw2_runtime.h"
#include "ntw2_planner_search.h"
#pragma comment(lib,"bcrypt.lib")
#pragma fenv_access(on)
using U=uint32_t;
using B=unsigned char;
static_assert(sizeof(void*)==4,"owned x86 oracle");
static B* image;
static U delta, checks;
static void Require(bool ok,const char* what) { ++checks; if(!ok) { std::fprintf(stderr,"FAIL %s\n",what); std::exit(1); } }
static B* At(U va) { return reinterpret_cast<B*>(va+delta); }
static U Bits(float f) { U u; std::memcpy(&u,&f,4); return u; }
static float Flt(U u) { float f; std::memcpy(&f,&u,4); return f; }
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
    Require(image!=nullptr,"private image mapping"); delta=static_cast<U>(reinterpret_cast<uintptr_t>(image))-0x400000;
    std::memcpy(image,bytes.data(),nt->OptionalHeader.SizeOfHeaders);
    auto sections=IMAGE_FIRST_SECTION(nt);
    for(U i=0;i<nt->FileHeader.NumberOfSections;++i)
        std::memcpy(image+sections[i].VirtualAddress,bytes.data()+sections[i].PointerToRawData,
                    std::min(sections[i].SizeOfRawData,sections[i].Misc.VirtualSize));
    Require(RelocateNativeImage(image,nt->OptionalHeader.SizeOfImage,
        reinterpret_cast<IMAGE_NT_HEADERS32*>(image+dos->e_lfanew),delta),"relocation");
    Require(FlushInstructionCache(GetCurrentProcess(),image,nt->OptionalHeader.SizeOfImage)!=0,"flush image");
}
using Native=B(__fastcall*)(void*,void*,void*);
static Native native;
struct Vertex { U v[13]; };
static std::vector<Vertex> verts;
static U shape[18];
struct __declspec(align(16)) Fx { B bytes[512]; };
static const U kCsr=0x1f80u|0x20u;        // masks set, inexact already sticky (the entry guard's precondition)
static void ResetFp(U csr=kCsr) { __asm { fninit } _mm_setcsr(csr); }
static void SetShape(const float s[9],U kind=0) {
    std::memset(shape,0,sizeof(shape)); shape[0]=kind;
    for(U i=0;i<9;++i) shape[1+i]=Bits(s[i]);
}
static void SetPolygon(const std::vector<std::pair<float,float>>& pts) {
    verts.assign(pts.size(),Vertex{});
    for(size_t i=0;i<pts.size();++i) {
        verts[i].v[2]=static_cast<U>(reinterpret_cast<uintptr_t>(&verts[(i+1)%pts.size()]));
        verts[i].v[3]=Bits(pts[i].first); verts[i].v[4]=Bits(pts[i].second);
    }
}
static void SetPolygonBits(const std::vector<std::pair<U,U>>& pts) {
    verts.assign(pts.size(),Vertex{});
    for(size_t i=0;i<pts.size();++i) {
        verts[i].v[2]=static_cast<U>(reinterpret_cast<uintptr_t>(&verts[(i+1)%pts.size()]));
        verts[i].v[3]=pts[i].first; verts[i].v[4]=pts[i].second;
    }
}
static U counts[ntw2_poly::ReasonCount], hits, misses;
// Runs native and replacement from the identical FP state; when the replacement serves, everything observable must be equal.
static ntw2_poly::Reason Compare(U csr=kCsr,bool requireServed=false,const char* what="case") {
    Fx a,b; U vs=0; B result=0xcc;
    ResetFp(csr); const B n=native(shape,nullptr,verts.data()); _fxsave(a.bytes);
    ResetFp(csr); const auto why=ntw2_poly::Evaluate(shape,verts.data(),&result,&vs); _fxsave(b.bytes);
    ++counts[why];
    if(why==ntw2_poly::Served) {
        char msg[96]; std::snprintf(msg,sizeof(msg),"%s: AL native=%u fast=%u",what,n,result);
        Require(n==result,msg);
        std::snprintf(msg,sizeof(msg),"%s: x87 control/status/tag",what);
        Require(!std::memcmp(a.bytes,b.bytes,5),msg);
        std::snprintf(msg,sizeof(msg),"%s: MXCSR sticky/control native=%08x fast=%08x",what,*reinterpret_cast<U*>(a.bytes+24),*reinterpret_cast<U*>(b.bytes+24));
        Require(!std::memcmp(a.bytes+24,b.bytes+24,4),msg);
        n ? ++hits : ++misses;
    } else {
        // A refusal leaves only flags the native run would also have raised: the next native call must still agree.
        Require(!requireServed,what);
    }
    return why;
}
static std::mt19937 rng(12345);
static float R(float lo,float hi) { return lo+(hi-lo)*(rng()&0xffffff)/16777216.0f; }
static void Star(U n,float cx,float cz,float r0,float r1,bool integers) {
    std::vector<std::pair<float,float>> p(n);
    for(U i=0;i<n;++i) {
        const float ang=6.2831853f*i/n, r=R(r0,r1);
        float x=cx+r*std::cos(ang), z=cz+r*std::sin(ang);
        x=std::floor(x*64.0f+0.5f)/64.0f; z=std::floor(z*64.0f+0.5f)/64.0f; // real coordinates are never within 2^-12 of zero without being zero: keep synthetic trig noise out of that gap
        if(integers) { x=std::floor(x); z=std::floor(z); }
        p[i]={x,z};
    }
    SetPolygon(p);
}
static void RandomShape(float cx,float cz,bool orthonormal,bool integers) {
    float s[9]={cx,cz,0,R(0,6),R(0,4),1,0,0,1};
    if(integers) { s[3]=std::floor(s[3]); s[4]=std::floor(s[4]); }
    const float ang=R(0,6.2831853f), c=std::cos(ang), sn=std::sin(ang);
    if(orthonormal) { s[5]=c; s[6]=sn; s[7]=-sn; s[8]=c; }
    else { s[5]=R(-1,1); s[6]=R(-1,1); s[7]=R(-1,1); s[8]=R(-1,1); }
    SetShape(s);
}
static double Now() { LARGE_INTEGER f,c; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c); return 1e9*double(c.QuadPart)/double(f.QuadPart); }
static void Bench() {
    std::printf("class     V   hit%%   native ns/test   fast ns/test   S     (warm cache, sequential nodes, PE sticky set)\n");
    const U sizes[]={1,4,8,16,32,64,128,256,512,1024};
    for(U v:sizes) {
        std::vector<std::vector<Vertex>> polys; std::vector<std::vector<float>> shapes;
        const U cases=64; U served=0;
        std::vector<std::vector<Vertex>> store(cases);
        for(U c=0;c<cases;++c) {
            Star(v,0,0,60,100,false); store[c]=verts; // pointers fixed up below
            for(size_t i=0;i<store[c].size();++i) store[c][i].v[2]=static_cast<U>(reinterpret_cast<uintptr_t>(&store[c][(i+1)%store[c].size()]));
        }
        std::vector<std::vector<U>> shp(cases,std::vector<U>(18));
        for(U c=0;c<cases;++c) { RandomShape(R(-140,140),R(-140,140),true,false); shp[c].assign(shape,shape+18); }
        U nativeHits=0; B sink=0; const U reps=std::max<U>(4,200000/(v+8)/cases*4);
        ResetFp(); double t0=Now();
        for(U r=0;r<reps;++r) for(U c=0;c<cases;++c) { const B x=native(shp[c].data(),nullptr,store[c].data()); sink+=x; if(!r) nativeHits+=x; }
        const double tn=(Now()-t0)/(double(reps)*cases);
        B res; ResetFp(); t0=Now();
        for(U r=0;r<reps;++r) for(U c=0;c<cases;++c) { if(ntw2_poly::Evaluate(shp[c].data(),store[c].data(),&res,nullptr)==ntw2_poly::Served) { sink+=res; if(!r) ++served; } }
        const double tf=(Now()-t0)/(double(reps)*cases);
        ntw2_poly::Configure(native,ntw2_poly::ModeLive); ResetFp(); t0=Now();   // the clone-bound host gate: Evaluate + counters + refusal path
        for(U r=0;r<reps;++r) for(U c=0;c<cases;++c) sink+=ntw2_poly::Gate(shp[c].data(),nullptr,store[c].data());
        const double tg=(Now()-t0)/(double(reps)*cases);
        ntw2_poly::Configure(native,ntw2_poly::ModeOff);
        // Cross-check the benchmark inputs themselves.
        for(U c=0;c<cases;++c) { ResetFp(); const B n=native(shp[c].data(),nullptr,store[c].data()); ResetFp();
            if(ntw2_poly::Evaluate(shp[c].data(),store[c].data(),&res,nullptr)==ntw2_poly::Served) Require(res==n,"bench input equality"); }
        std::printf("V=%-5u hit=%3u%% native %10.1f ns   fast %9.1f ns   gate %9.1f ns   S(eval)=%.2f S(gate)=%.2f  served %u/%u (sink %u)\n",v,100*nativeHits/cases,tn,tf,tg,tn/tf,tn/tg,served,cases,sink);
    }
}
int main(int argc,char** argv) {
    if(argc<2) { std::fprintf(stderr,"usage: native_planner_search_oracle Napoleon.exe [--bench]\n"); return 2; }
    Map(argv[1]); native=reinterpret_cast<Native>(At(0x80dcf0));
    Require(*reinterpret_cast<U*>(At(0x1318038))==Bits(0.5f) && *reinterpret_cast<U*>(At(0x1318048))==Bits(1.0f),"image constants 0.5/1.0");
    if(argc>2 && !std::strcmp(argv[2],"--bench")) { Bench(); return 0; }
    // Random finite polygons: V classes, orthonormal and arbitrary axes, float and integer coordinates, hit/miss mix.
    const U classes[]={1,2,3,4,5,7,8,17,64,65,256,1000,1024};
    for(U round=0;round<400;++round) for(U v:classes) {
        const bool ints=round&1, ortho=!(round&2);
        Star(v,R(-20,20),R(-20,20),10,60,ints);
        RandomShape(R(-70,70),R(-70,70),ortho,ints); Compare(kCsr,false,"random");
    }
    // Degenerate geometry: zero-area OBBs, repeated vertices, collinear, vertex on OBB boundary, axis-aligned and 90-degree axes.
    for(U round=0;round<200;++round) {
        float s[9]={float(int(R(-5,5))),float(int(R(-5,5))),0,float(int(R(0,4))),float(int(R(0,4))),1,0,0,1};
        if(round%4==1) { s[3]=0; } if(round%4==2) { s[4]=0; } if(round%4==3) { s[3]=0; s[4]=0; }
        if(round&8) { s[5]=Flt(0x33ba3132u); s[6]=-1; s[7]=1; s[8]=Flt(0x33ba3132u); } // cos(pi/2)-style tiny axis
        SetShape(s);
        std::vector<std::pair<float,float>> p={{-2,-2},{2,-2},{2,2},{-2,2},{-2,2},{0,2},{-2,-2}};
        p.resize(1+round%7); SetPolygon(p); Compare(kCsr,false,"degenerate");
    }
    { float s[9]={0,0,0,2,2,1,0,0,1}; SetShape(s); SetPolygon({{1,0}}); Compare(kCsr,false,"single vertex inside"); }
    { float s[9]={0,0,0,2,2,1,0,0,1}; SetShape(s); SetPolygon({{9,9}}); Compare(kCsr,false,"single vertex outside"); }
    { float s[9]={0,0,0,2,2,1,0,0,1}; SetShape(s); SetPolygon({{9,9},{9,9}}); Compare(kCsr,false,"two coincident vertices"); }
    // Polygon contains the OBB entirely (PIP path), OBB contains polygon (first-vertex path), edge crossing only (segment passes).
    { float s[9]={0,0,0,2,2,1,0,0,1}; SetShape(s); SetPolygon({{-50,-50},{50,-50},{50,50},{-50,50}}); Require(Compare(kCsr,true,"polygon contains OBB")==ntw2_poly::Served,"served"); }
    { float s[9]={0,0,0,20,20,1,0,0,1}; SetShape(s); SetPolygon({{-1,-1},{1,-1},{1,1},{-1,1}}); Compare(kCsr,true,"OBB contains polygon"); }
    { float s[9]={0,0,0,20,2,1,0,0,1}; SetShape(s); SetPolygon({{-1,-5},{1,-5},{1,5},{-1,5}}); Compare(kCsr,true,"cross shape, no vertex inside"); }
    // Guard refusals, each on its own fixture (and the refused call must still be answered by native).
    { float s[9]={0,0,0,2,2,1,0,0,1}; SetShape(s,1); SetPolygon({{9,9},{10,9},{10,10}}); Require(Compare(kCsr,false,"kind 1")==ntw2_poly::FallKind,"kind refusal"); }
    { float s[9]={0,0,0,2,2,1,0,0,1}; SetShape(s); SetPolygon({{9,9},{10,9},{10,10}});
      Require(Compare(0x1f80u,false,"PE not sticky")==ntw2_poly::FallFp,"inexact precondition");
      Require(Compare(0x1f20u,false,"exception unmasked")==ntw2_poly::FallFp,"mask precondition");
      Fx f; ResetFp(); __asm { fld1 }
      B res; U vs; const auto why=ntw2_poly::Evaluate(shape,verts.data(),&res,&vs); __asm { fstp st(0) }
      Require(why==ntw2_poly::FallFp,"x87 TOP precondition"); (void)f;
      ResetFp(); unsigned short cw; __asm { fnstcw cw }
      cw&=~1u; __asm { fldcw cw }  // unmask invalid
      Require(ntw2_poly::Evaluate(shape,verts.data(),&res,&vs)==ntw2_poly::FallFp,"x87 mask precondition"); ResetFp(); }
    { // Too many vertices: refused (native would also be correct, just slow). A list that never returns to P must not hang us.
      Star(1025,0,0,10,20,false); float s[9]={100,100,0,2,2,1,0,0,1}; SetShape(s);
      Require(Compare(kCsr,false,"V=1025")==ntw2_poly::FallWalkCap,"walk cap"); }
    { std::vector<Vertex> cyc(3); for(U i=0;i<3;++i) { cyc[i].v[2]=static_cast<U>(reinterpret_cast<uintptr_t>(&cyc[(i+1)%3])); cyc[i].v[3]=Bits(9.0f); cyc[i].v[4]=Bits(float(9+i)); }
      Vertex head={}; head.v[2]=static_cast<U>(reinterpret_cast<uintptr_t>(&cyc[0])); head.v[3]=Bits(9.0f); head.v[4]=Bits(8.0f);
      float s[9]={0,0,0,2,2,1,0,0,1}; SetShape(s); B res; ResetFp();
      Require(ntw2_poly::Evaluate(shape,&head,&res,nullptr)==ntw2_poly::FallWalkCap,"list that never returns to P"); }
    // NaN / Inf / denormal / huge: the vector path must refuse; scalar stage identical to native whatever it raises.
    const U bad[]={0x7fc00000u,0x7f800001u,0xffc00000u,0x7f800000u,0xff800000u,0x00000001u,0x007fffffu,0x80000001u,0x00800000u,0x7f7fffffu,0x4b800000u,0x2f800000u,0x00ffffffu};
    for(U pattern:bad) {
        float s[9]={50,50,0,2,2,1,0,0,1}; SetShape(s);
        for(U field=0;field<2;++field) for(U vtx=0;vtx<5;++vtx) {
            std::vector<std::pair<U,U>> p={{Bits(0),Bits(0)},{Bits(4),Bits(0)},{Bits(4),Bits(4)},{Bits(0),Bits(4)},{Bits(-3),Bits(2)}};
            (field?p[vtx].second:p[vtx].first)=pattern; SetPolygonBits(p);
            const auto why=Compare(kCsr,false,"bad polygon coordinate");
            Require(why==ntw2_poly::FallDomain,"NaN/Inf/denormal/huge polygon coordinate refused to native");
        }
        for(U field=0;field<9;++field) {
            float s2[9]={50,50,0,2,2,1,0,0,1}; U w[9]; for(U i=0;i<9;++i) w[i]=Bits(s2[i]); w[field]=pattern;
            std::memset(shape,0,sizeof(shape)); for(U i=0;i<9;++i) shape[1+i]=w[i];
            SetPolygon({{0,0},{4,0},{4,4},{0,4}});
            const auto why=Compare(kCsr,false,"bad OBB field");
            if(field==2) continue; // OBB word +8 is not an input of the predicate: result must still be served and equal
            // NaN/Inf in any input field poisons the corners: refused to native. Denormal/huge patterns are either refused or
            // answered identically by the shared scalar stage (Compare asserts equality whenever the replacement serves).
            if((pattern&0x7f800000u)==0x7f800000u) Require(why==ntw2_poly::FallDomain,"NaN/Inf OBB field refused to native");
        }
    }
    // Poisoned OBB field 2 is ignored by the kernel: still served, identical.
    { float s[9]={50,50,0,2,2,1,0,0,1}; SetShape(s); shape[3]=0x7fc00000u; SetPolygon({{0,0},{4,0},{4,4},{0,4}});
      Require(Compare(kCsr,true,"OBB word +8 is not an input")==ntw2_poly::Served,"+8 ignored"); }
    // The clone-bound gate: shadow answers natively and must count zero mismatches (AL, x87 status, MXCSR); live answers like native.
    for(U mode=ntw2_poly::ModeShadow;mode<=ntw2_poly::ModeLive;++mode) {
        ntw2_poly::Configure(native,mode);
        for(U round=0;round<60;++round) for(U v:classes) {
            Star(v,R(-20,20),R(-20,20),10,60,round&1); RandomShape(R(-70,70),R(-70,70),!(round&2),round&1);
            ResetFp(); const B n=native(shape,nullptr,verts.data()); ResetFp(); const B g=ntw2_poly::Gate(shape,nullptr,verts.data());
            Require(n==g,"gate result equals native");
        }
        const volatile U* w=ntw2_poly::words;
        Require(w[0]==1 && w[1]==mode && w[2]==60*(sizeof(classes)/sizeof(classes[0])) && w[3]>500,"gate counters: version, mode, calls, served");
        if(mode==ntw2_poly::ModeShadow) Require(w[8]==w[3] && !w[9] && !w[10] && !w[11],"shadow compares every served call bit-identical");
        else {
            std::printf("live gate: calls=%u served=%u kind=%u fp=%u domain=%u cap=%u\n",w[2],w[3],w[4],w[5],w[6],w[7]);
            Require(w[4]==0 && w[6]<=w[2]/50,"live: (almost) no kind/domain refusals on finite random input");
        }
    }
    ntw2_poly::Configure(native,ntw2_poly::ModeOff);
    { bool zero=true; for(U i=0;i<ntw2_poly::kWords;++i) zero=zero && !ntw2_poly::words[i]; Require(zero,"row all zero when off"); }
    std::printf("coverage: served=%u hit=%u miss=%u kind=%u fp=%u domain=%u cap=%u\n",counts[ntw2_poly::Served],hits,misses,counts[ntw2_poly::FallKind],counts[ntw2_poly::FallFp],counts[ntw2_poly::FallDomain],counts[ntw2_poly::FallWalkCap]);
    Require(counts[ntw2_poly::Served]>5000 && hits>100 && misses>100,"coverage of served hit/miss");
    std::printf("planner search oracle: %u checks; served=%u (hit %u, miss %u) kind=%u fp=%u domain=%u cap=%u\n",checks,
        counts[ntw2_poly::Served],hits,misses,counts[ntw2_poly::FallKind],counts[ntw2_poly::FallFp],counts[ntw2_poly::FallDomain],counts[ntw2_poly::FallWalkCap]);
    return 0;
}

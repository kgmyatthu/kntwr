#include "native_collision_solver.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <xmmintrin.h>
#include <algorithm>
#include <string.h>
#include "loco/native_owned_grid.h"
#include "native_contact.h"

#pragma float_control(precise, on, push)
namespace ntw2_collide {
namespace {
using U = uint32_t;
using B = unsigned char;
constexpr U kChunks=32;
// Minimum contacts per plan chunk (~10 us of Predict) so per-chunk dispatch cost stays small.
constexpr U kPlanGrain=128;
constexpr U kPacketFlagMask=3u,kNoPacket=0x3fffffffu;
// Contact capacity is max(primary<=131072,ceil(pairs<=4194304 /16)), capped by pairs.
// Every valid index fits below the 30-bit link sentinel; low two bits remain native flags.
static_assert(131072u<kNoPacket && (4194304u+15)/16<kNoPacket,"contact link sentinel must be unreachable");
U kRecords,kPrimary,kCells,kMembers,kPairs,kHash,kContacts,kLanes,kHistogram;
struct Limits { U records,primary,cells,members,pairs,hash,contacts,lanes,histogram; };
struct Packet { U other, flags; float px,pz,nx,nz,dx,dz; };
struct Entry { U key,value; };
enum Phase : U { GatherPhase, MembershipPhase, HistogramPhase, AuditPhase, CachePhase,
    NativeClassifyPhase, PacketPhase, IncomingFillPhase, ReducePhase,
    CommitPhase, LabelCommitPhase, ContactPlanPhase };
struct Arena {
    B** rec;
    U *pointerHash,*order,*seen,*rank;
    B *done,*labelDirty;
    U *serial,*exclusion,*team,*shape,*flags,*heading,*active,*adjust,*fixed;
    // Read-only aliases: borrowed publication in owned mode, private audit snapshot otherwise.
    const float *x,*y,*z,*extent,*radius;
    const U *left,*right,*top,*bottom; // Inclusive bounds in both modes.
    float *mass,*inverse,*auditX,*auditY,*auditZ,*auditExtent,*auditRadius;
    U *auditLeft,*auditRight,*auditTop,*auditBottom;
    U *first,*span,*nativeRecord,*memberFirst;
    U *accepted,*acceptedFirst,*incomingFirst,*incomingCount,*incomingCursor,*shaped,*labels;
    float *sum70,*sum74,*sum78,*sum7c;
    // Shared cell-order geometry; owned mode never allocates the native-audit topology below.
    float *cellX,*cellZ,*cellRadius;
    Packet* packets;
    U *outgoing,*incoming,*stamps,*epochs;
    // Native-chain audit only: null in owned mode.
    U *counts,*starts,*cellDense,*csr,*cellTeam,*cellFlags;
    U *badCell,*firstRecord,*occupied,*badList;
    U occupiedCount;
    volatile LONG badCount;
    Entry* entries;
    U *histogram,*scratch;
    uint16_t* ids;
    // Contact-response plans (native_contact.h), one per accepted contact at acceptedFirst[i]+n;
    // reserved only when a contact mode is bound.
    ntw2_contact::Plan* plans;
};
Binding binding;
Arena storage;
B* allocation;
U storageBytes;
void* activationManager;
template<class T> void Reserve(T*& field,U count,B* base,size_t& bytes) {
    bytes=(bytes+alignof(T)-1)&~(alignof(T)-1);
    field=base?reinterpret_cast<T*>(base+bytes):nullptr;
    bytes+=static_cast<size_t>(count)*sizeof(T);
}
size_t Layout(Arena& a,B* base,const Limits& limits) {
    size_t bytes=0;
#define BUFFER(field,count) Reserve(a.field,count,base,bytes)
#define RECORD(field) BUFFER(field,limits.records)
    RECORD(rec); BUFFER(pointerHash,limits.hash); BUFFER(order,limits.primary);
    BUFFER(seen,(limits.records+31)/32); RECORD(rank); RECORD(done); RECORD(labelDirty);
    RECORD(serial); RECORD(exclusion); RECORD(team); RECORD(shape); RECORD(flags);
    RECORD(heading); RECORD(active); RECORD(adjust); RECORD(fixed);
    RECORD(mass); RECORD(inverse);
    BUFFER(first,limits.primary); BUFFER(span,limits.primary); BUFFER(accepted,limits.primary);
    BUFFER(acceptedFirst,limits.primary); BUFFER(shaped,limits.primary);
    BUFFER(nativeRecord,binding.read_grid?limits.primary:limits.records);
    RECORD(incomingFirst); RECORD(incomingCount); RECORD(incomingCursor); RECORD(labels);
    RECORD(sum70); RECORD(sum74); RECORD(sum78); RECORD(sum7c);
    BUFFER(cellX,limits.members); BUFFER(cellZ,limits.members); BUFFER(cellRadius,limits.members);
    BUFFER(packets,limits.contacts);
    BUFFER(outgoing,limits.contacts); BUFFER(incoming,limits.contacts);
    if (binding.contact_mode) BUFFER(plans,limits.contacts);
    if (!binding.read_grid) {
        RECORD(memberFirst);
        RECORD(auditX); RECORD(auditY); RECORD(auditZ); RECORD(auditExtent); RECORD(auditRadius);
        RECORD(auditLeft); RECORD(auditRight); RECORD(auditTop); RECORD(auditBottom);
        a.x=a.auditX; a.y=a.auditY; a.z=a.auditZ; a.extent=a.auditExtent; a.radius=a.auditRadius;
        a.left=a.auditLeft; a.right=a.auditRight; a.top=a.auditTop; a.bottom=a.auditBottom;
        BUFFER(stamps,limits.lanes*limits.records); BUFFER(epochs,limits.lanes);
        U dense=(std::min)(limits.cells,limits.members);
        BUFFER(counts,dense); BUFFER(starts,dense); BUFFER(firstRecord,dense);
        BUFFER(cellDense,limits.cells); BUFFER(csr,limits.members);
        BUFFER(cellTeam,limits.members); BUFFER(cellFlags,limits.members);
        BUFFER(badCell,limits.cells); BUFFER(occupied,limits.cells); BUFFER(badList,limits.cells);
        BUFFER(entries,limits.members); BUFFER(histogram,limits.histogram);
        BUFFER(scratch,0x2014/4); BUFFER(ids,65536);
    }
#undef RECORD
#undef BUFFER
    return bytes;
}
bool CapacityLimits(const ntw2_workload::Capacity& capacity,Limits& limits) {
    if (capacity.primary>131072 || capacity.records<capacity.primary || capacity.records>131072 ||
        !capacity.cells || capacity.cells>1048576 ||
        capacity.memberships>2097152 || capacity.pairs>4194304) return false;
    limits.primary=capacity.primary; limits.records=capacity.records; limits.cells=capacity.cells;
    limits.members=capacity.memberships; limits.pairs=capacity.pairs;
    limits.lanes=(std::min)(kChunks-1,binding.workers)+1;
    limits.hash=1; while (limits.hash<2*limits.records) limits.hash<<=1;
    // Pairs are a pure counter bound (no buffer is sized from them). Contacts are the buffered resource:
    // measured peak accepted contacts are 0.18 (open field, 48k primary) to 0.70 (dense borodino500, 56k primary) per primary,
    // so twice the primary slots cover the dense line with headroom. Dense worlds beyond this still refuse before the first game write.
    limits.contacts=2*limits.primary;
    limits.histogram=(((std::min)(limits.cells,limits.members)+15)&~15u)*limits.lanes;
    return true;
}
U ReservationBytes(const Limits& limits) {
    Arena descriptor{};
    size_t bytes=Layout(descriptor,nullptr,limits);
    // Bounds above keep layout arithmetic representable on x86; round the actual VA reservation.
    if (bytes>0xffffffffu-65535u) return 0xffffffffu;
    return static_cast<U>((bytes+65535)&~size_t(65535));
}
struct Job {
    U count, primaryCount, workCount, cells, shift, origin, maximum, chunkSize, chunks;
    U owner, mxcsr, phase, totalPairs;
    volatile LONG contactCount;
    U sortCount,sortKeys,sortStride,sortChunks;
    U auditCount,nativeQueries;
    volatile LONG auditVisits;
    ULONGLONG workerCpu,chunkCpu[kChunks];
    // Contact-plan dispatch: accepted contacts of the stage (dense plan rows), contact-range
    // chunk count, per-chunk QPC occupancy ticks (plan_thread_us; GetThreadTimes is 15.6 ms
    // quanta) and per-chunk Predict calls (oracle seam ContactPlans).
    U acceptedTotal,planChunks,chunkPlanned[kChunks];
    ULONGLONG chunkBusy[kChunks];
    unsigned short cw, headingBias;
    bool rebuild,owned;
    B* manager;
    // Borrowed owned-grid publication; null on the native-chain-audit path.
    const ntw2_loco::GridView* view;
    // Admitted contact-response stage of this Apply (null: every contact runs the original callback).
    const ntw2_contact::Stage* contact;
    U* work;
    U* nativeCells;
    float scale, bump, one, weightR, weightS, crossover, farScale;
    volatile LONG failure;
};
Arena* arena;
// The descriptor is fixed small state; all pointed-to storage belongs to one activation.
U words[WordCount];
U sourceWords[SourceWordCount];
volatile LONG diagnosticClaim;
// Most recent stage's plan rows and Predict calls (ContactPlans); reset at every stage entry.
U planRows,planPredicted;
bool faulted;
LARGE_INTEGER frequency;

template<class T> T& At(void* p,U offset) { return *reinterpret_cast<T*>(static_cast<B*>(p)+offset); }
U Address(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
U V(U p) { return p+binding.image_delta; }
__forceinline float Add(float a,float b) { return _mm_cvtss_f32(_mm_add_ss(_mm_set_ss(a),_mm_set_ss(b))); }
__forceinline float Sub(float a,float b) { return _mm_cvtss_f32(_mm_sub_ss(_mm_set_ss(a),_mm_set_ss(b))); }
__forceinline float Mul(float a,float b) { return _mm_cvtss_f32(_mm_mul_ss(_mm_set_ss(a),_mm_set_ss(b))); }
__forceinline float Div(float a,float b) { return _mm_cvtss_f32(_mm_div_ss(_mm_set_ss(a),_mm_set_ss(b))); }
float Abs(float value) {
    __asm { fld value }
    __asm { fabs }
    __asm { fstp value }
    return value;
}
// COMISS/JA is false for unordered inputs, exactly as the native rejection branches.
__forceinline bool Greater(float a,float b) {
    return _mm_comigt_ss(_mm_set_ss(a),_mm_set_ss(b))!=0;
}
U Cell(float value,Job& j) {
    float scaled=Mul(j.scale,value), half=-0.5f;
    int rounded;
    __asm { fld scaled }
    __asm { fadd st(0),st(0) }
    __asm { fadd half }
    __asm { fistp rounded }
    // Native SAR followed by unsigned ADD/CMOVAE: negative overflow clamps high.
    U coordinate=static_cast<U>(rounded>>1)+j.origin;
    return coordinate<j.maximum ? coordinate : j.maximum;
}
U Slot(B* rec) {
    U h=(Address(rec)>>4)*2654435761u & (kHash-1);
    while (arena->pointerHash[h]) {
        U slot=arena->pointerHash[h]-1;
        if (arena->rec[slot]==rec) return slot;
        h=(h+1)&(kHash-1);
    }
    return kRecords;
}
void Fail(Job& j,U reason) { _InterlockedCompareExchange(&j.failure,static_cast<LONG>(reason),0); }
int Fault(Job& j,U code) {
    _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&words[Faults]));
    _InterlockedExchange(reinterpret_cast<volatile LONG*>(&words[LastException]),static_cast<LONG>(code));
    Fail(j,StickyFallbacks);
    return EXCEPTION_EXECUTE_HANDLER;
}
ULONGLONG Clock() { LARGE_INTEGER value; QueryPerformanceCounter(&value); return value.QuadPart; }
U Micros(ULONGLONG start) { return static_cast<U>((Clock()-start)*1000000/frequency.QuadPart); }
ULONGLONG ThreadClock() {
    FILETIME created,exited,kernel,user;
    if (!GetThreadTimes(GetCurrentThread(),&created,&exited,&kernel,&user)) {
        _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&words[ThreadClockFailures]));
        return 0;
    }
    return (static_cast<ULONGLONG>(kernel.dwHighDateTime)<<32)+kernel.dwLowDateTime+
        (static_cast<ULONGLONG>(user.dwHighDateTime)<<32)+user.dwLowDateTime;
}
struct Timing { ULONGLONG wall,cpu,workers; };
Timing Begin(Job& j) { return {Clock(),ThreadClock(),j.workerCpu}; }
void End(Job& j,const Timing& t,U wall,U cpu) {
    words[wall]+=Micros(t.wall);
    ULONGLONG now=ThreadClock();
    if (now>=t.cpu) words[cpu]+=static_cast<U>((now-t.cpu+j.workerCpu-t.workers)/10);
}
void Diagnose(U reason,U record,B* node,U cell) {
    if (_InterlockedCompareExchange(&diagnosticClaim,1,0)) return;
    B* r=record<kRecords?arena->rec[record]:nullptr;
    words[DiagnosticRecord]=record;
    words[DiagnosticNode]=Address(node);
    words[DiagnosticType]=node?At<U>(node,0):0;
    words[DiagnosticVtable]=r?At<U>(r,0):0;
    words[DiagnosticOwner]=node?At<U>(node,12):0;
    words[DiagnosticPayload]=node?At<U>(node,8):0;
    words[DiagnosticId]=node?At<U>(node,4):0;
    words[DiagnosticCell]=cell;
    words[DiagnosticExpectedRecord]=Address(r);
    // Publish the first complete diagnostic; later ticks retain it until activation reset.
    _InterlockedExchange(reinterpret_cast<volatile LONG*>(&words[DiagnosticReason]),static_cast<LONG>(reason));
}
U NodeCell(Job& j,B* node) {
    U offset=At<U>(node,24)-Address(j.nativeCells);
    return !(offset&3) && offset/4<j.cells?offset/4:0xffffffffu;
}
void MarkCell(Job& j,U cell) {
    if (cell<j.cells && !_InterlockedExchange(reinterpret_cast<volatile LONG*>(&arena->badCell[cell]),1)) {
        U at=static_cast<U>(_InterlockedIncrement(&arena->badCount))-1;
        arena->badList[at]=cell;
    }
}
void Gather(Job& j,U i) {
    Arena& a=*arena; B* r=a.rec[i];
    if (!j.owned) {
        a.auditLeft[i]=a.auditTop[i]=1; a.auditRight[i]=a.auditBottom[i]=0; // Empty inclusive rectangle.
        a.nativeRecord[i]=0;
    }
    if (i<j.primaryCount) {
        a.first[i]=a.span[i]=a.nativeRecord[i]=a.accepted[i]=a.shaped[i]=0;
    }
    a.incomingCount[i]=0; a.rank[i]=0xffffffffu;
    // Owned CSR slots are positional: the merged registry slot must still hold the published record.
    if (j.owned && j.view->record[i]!=Address(r)) { Diagnose(OwnOwner,i,nullptr,0xffffffffu); Fail(j,LayoutFallbacks); return; }
    if (!r) { a.active[i]=0; return; }
    a.serial[i]=At<U>(r,0x2c); a.exclusion[i]=At<U>(r,0x3c);
    a.flags[i]=At<U>(r,0x38); a.active[i]=At<B>(r,0x30);
    a.done[i]=At<B>(r,0x40);
    a.labels[i]=At<U>(r,0x88); a.labelDirty[i]=0;
    U count=At<U>(r,0xac);
    // Identity/membership are validated; eligibility and numerics below are captured live.
    if (j.owned && (j.view->serial[i]!=a.serial[i] || j.view->inserted[i]!=count)) {
        Diagnose(j.view->serial[i]!=a.serial[i]?OwnId:OwnCoverage,i,nullptr,0xffffffffu);
        Fail(j,LayoutFallbacks); return;
    }
    if (!count) return; // No grid membership: no numeric fields can be consumed by a solver pair.
    a.team[i]=At<U>(r,0x44); a.shape[i]=At<U>(r,0x60);
    a.adjust[i]=At<B>(r,0x5c); a.fixed[i]=At<B>(r,0x66); a.heading[i]=At<uint16_t>(r,0x64);
    float x=At<float>(r,0x48), y=At<float>(r,0x4c), z=At<float>(r,0x50);
    float extent=At<float>(r,0x54), baseRadius=At<float>(r,0x58);
    a.mass[i]=At<float>(r,0x68); a.inverse[i]=At<float>(r,0x6c);
    if (count>kMembers) { Fail(j,CapacityFallbacks); return; }
    if (j.owned && j.view->node_type[i]!=8) { Diagnose(OwnType,i,nullptr,0xffffffffu); Fail(j,LayoutFallbacks); return; }
    // Published position/height/extent/radius are identity of the CSR geometry: any bitwise change is stale.
    if (j.owned) {
        const ntw2_loco::GridView& v=*j.view;
        if (memcmp(&x,&v.x[i],sizeof(float)) || memcmp(&y,&v.y[i],sizeof(float)) ||
            memcmp(&z,&v.z[i],sizeof(float)) || memcmp(&extent,&v.extent[i],sizeof(float)) ||
            memcmp(&baseRadius,&v.radius[i],sizeof(float))) {
            Diagnose(OwnCoverage,i,nullptr,0xffffffffu); Fail(j,LayoutFallbacks); return;
        }
    } else {
        a.auditX[i]=x; a.auditY[i]=y; a.auditZ[i]=z;
        a.auditExtent[i]=extent; a.auditRadius[i]=baseRadius;
    }
    float radius=a.adjust[i]==1 ? Add(a.radius[i],j.bump) : a.radius[i];
    U l=Cell(Sub(a.x[i],radius),j), rgt=Cell(Add(a.x[i],radius),j);
    U t=Cell(Sub(a.z[i],radius),j), b=Cell(Add(radius,a.z[i]),j);
    B* nodes=At<B*>(r,0xa8);
    if (l>rgt || t>b || count>At<U>(r,0xb0) ||
        static_cast<ULONGLONG>(rgt-l+1)*(b-t+1)!=count) {
        if (j.owned) { Diagnose(OwnCoverage,i,nodes,0xffffffffu); Fail(j,LayoutFallbacks); return; }
        a.nativeRecord[i]=1; Diagnose(OwnCoverage,i,nodes,NodeCell(j,nodes));
        // A lagging/mismatched geometry snapshot must not hide contacts in its actual native cells.
        for (U n=0;n<count;++n) MarkCell(j,NodeCell(j,nodes+n*0x1c));
        return;
    }
    // The published inclusive bounds must equal the live geometry, or the borrowed CSR is stale.
    if (j.owned && (j.view->left[i]!=l || j.view->right[i]!=rgt || j.view->top[i]!=t || j.view->bottom[i]!=b)) {
        Diagnose(OwnCoverage,i,nodes,0xffffffffu); Fail(j,LayoutFallbacks); return;
    }
    if (!j.owned) {
        a.auditLeft[i]=l; a.auditRight[i]=rgt; a.auditTop[i]=t; a.auditBottom[i]=b;
    }
    U n=0;
    for (U y=t;y<=b;++y) for (U x=l;x<=rgt;++x,++n) {
        U cell=(y<<j.shift)+x; B* node=nodes+n*0x1c; U reason=0;
        if (At<U>(node,0)!=8) reason=OwnType;
        else if (At<U>(node,4)!=a.serial[i]) reason=OwnId;
        else if (At<B*>(node,8)!=r+0x30) reason=OwnPayload;
        else if (At<B*>(node,12)!=r) reason=OwnOwner;
        else if (At<U*>(node,24)!=j.nativeCells+cell) reason=OwnCell;
        if (reason) {
            // Owned mode has no record-local native query: any inconsistent own node is stale topology.
            if (j.owned) { Diagnose(reason,i,node,cell); Fail(j,LayoutFallbacks); return; }
            a.nativeRecord[i]=1; Diagnose(reason,i,node,cell);
            MarkCell(j,cell); MarkCell(j,NodeCell(j,node));
        }
    }
}
// Phase B selection and packet numerics consume one immutable dispatch snapshot.
struct Input {
    U slot;
#define COLLIDE_INPUT(name, type, field, offset) \
    __forceinline type name() const { return static_cast<type>(arena->field[slot]); }
    COLLIDE_INPUT(active,B,active,0x30)
    COLLIDE_INPUT(exclusion,U,exclusion,0x3c)
    COLLIDE_INPUT(flags,U,flags,0x38)
    COLLIDE_INPUT(team,U,team,0x44)
    COLLIDE_INPUT(shape,U,shape,0x60)
    COLLIDE_INPUT(adjust,B,adjust,0x5c)
    COLLIDE_INPUT(fixed,B,fixed,0x66)
    COLLIDE_INPUT(heading,uint16_t,heading,0x64)
    COLLIDE_INPUT(x,float,x,0x48)
    COLLIDE_INPUT(y,float,y,0x4c)
    COLLIDE_INPUT(z,float,z,0x50)
    COLLIDE_INPUT(extent,float,extent,0x54)
    COLLIDE_INPUT(radius,float,radius,0x58)
    COLLIDE_INPUT(mass,float,mass,0x68)
    COLLIDE_INPUT(inverse,float,inverse,0x6c)
#undef COLLIDE_INPUT
};
__forceinline U MakePacket(Job& j,U i,U s,U cell,U querySerial) {
    Arena& a=*arena; Input r={i}, n={s};
    if ((n.active()!=1) | (r.exclusion()==a.serial[s]) | (n.exclusion()==querySerial)) return 0xffffffffu;
    U rt=r.team(),st=j.owned?n.team():a.cellTeam[cell];
    bool both=(rt!=0)&(st!=0),different=both&(rt!=st);
    U mask=both?(different?2u:1u):4u;
    if (!(r.flags()&(j.owned?n.flags():a.cellFlags[cell])&mask)) return 0xffffffffu;
    float dy=Sub(r.y(),n.y());
    if (!Greater(Greater(0,dy)?r.extent():n.extent(),Abs(dy))) return 0xffffffffu;
    float rr=r.radius(), rs=a.cellRadius[cell];
    if (different) { if (r.adjust()==1) rr=Add(rr,j.bump); if (n.adjust()==1) rs=Add(rs,j.bump); }
    float dx=Sub(a.cellX[cell],r.x()), dz=Sub(a.cellZ[cell],r.z());
    float sum=Add(rs,rr), threshold=Mul(sum,sum);
    // Squared-axis AABB rejection is conservative even for negative radii, overflow,
    // subnormals and unordered values. Keep the native MUL/ADD order for admitted pairs.
    float dx2=Mul(dx,dx),dz2=Mul(dz,dz);
    if (Greater(dx2,threshold) || Greater(dz2,threshold)) return 0xffffffffu;
    float distance=Add(dz2,dx2);
    if (!Greater(threshold,distance)) return 0xffffffffu;
    // With two null shapes the original leaf returns zero without touching the threshold.
    if (r.shape() | n.shape()) {
        ++a.shaped[i];
        using Radius = unsigned char (__cdecl*)(float*,U,U,float,float,float,float,U,U);
        if (reinterpret_cast<Radius>(V(0x81a670))(&threshold,r.shape(),n.shape(),dx,dz,rr,rs,r.heading(),n.heading()) &&
            !Greater(threshold,distance)) return 0xffffffffu;
    }
    U index=static_cast<U>(_InterlockedIncrement(&j.contactCount))-1;
    if (index>=kContacts) { Fail(j,CapacityFallbacks); return 0xffffffffu; }
    Packet& p=a.packets[index]; p.other=s;
    float weight=Mul(r.inverse(),n.mass());
    if (n.fixed()==1) weight=j.one;
    else if (different) {
        if (r.adjust()==1) weight=Mul(weight,j.weightR);
        if (n.adjust()==1) weight=Mul(weight,j.weightS);
    }
    float q=Sub(Greater(distance,j.crossover)?Div(threshold,distance):Mul(threshold,j.farScale),j.one);
    float minimum=_mm_cvtss_f32(_mm_min_ss(_mm_set_ss(weight),_mm_set_ss(j.one)));
    float maximum=_mm_cvtss_f32(_mm_max_ss(_mm_set_ss(weight),_mm_set_ss(j.one)));
    float owner=Mul(minimum,q), neighbor=Div(q,maximum);
    p.px=Mul(owner,dx); p.pz=Mul(owner,dz); p.nx=Mul(neighbor,dx); p.nz=Mul(neighbor,dz);
    p.dx=dx; p.dz=dz; p.flags=(kNoPacket<<2)|1|(different?2:0);
    return index;
}
bool Seen(U id) { return (arena->seen[id>>5]&(1u<<(id&31)))!=0; }
void See(U id) { arena->seen[id>>5]|=1u<<(id&31); }
bool Enqueue(Job& j,U id,U& queued) {
    if (id>=j.primaryCount || Seen(id)) return true;
    if (queued>=j.workCount || !arena->rec[id]) { Fail(j,LayoutFallbacks); return false; }
    See(id); arena->order[queued++]=id;
    return true;
}
bool AccountCandidates(Job& j,U count) {
    U previous=static_cast<U>(_InterlockedExchangeAdd(reinterpret_cast<volatile LONG*>(&j.totalPairs),static_cast<LONG>(count)));
    if (previous>kPairs || count>kPairs-previous) { Fail(j,CapacityFallbacks); return false; }
    return true;
}
// The rebuild instantiation runs on the owner, before ranks exist; the packet instantiation
// streams each query once in parallel. Compile-time selection adds no per-pair indirect call.
template<bool Rebuild> bool Enumerate(Job& j,U chunk,U i,U& queued) {
    Arena& a=*arena;
    if (!Rebuild) a.first[i]=kNoPacket;
    if (!a.rec[i] || !a.active[i] || !(a.flags[i]&3) || a.nativeRecord[i] ||
        (j.owned && !j.view->inserted[i])) { a.span[i]=0; return true; }
    U epoch=0;
    U* stamps=nullptr;
    if (!j.owned) {
        epoch=++a.epochs[chunk]; stamps=a.stamps+chunk*kRecords;
        if (!epoch) { memset(stamps,0,kRecords*sizeof(U)); epoch=++a.epochs[chunk]; }
    }
    U count=0,previous=kNoPacket;
    for (U y=a.top[i];y<=a.bottom[i];++y) for (U x=a.left[i];x<=a.right[i];++x) {
        const U cell=(y<<j.shift)+x;
        U first,last; const U* occupant;
        if (j.owned) {
            // Borrowed CSR, read-only: compact cell -> [offsets[k],offsets[k+1]) of view slot indices.
            const ntw2_loco::GridView& v=*j.view;
            const U dense=v.cell_dense[cell];
            if (!dense || dense>v.cells) { Fail(j,LayoutFallbacks); a.span[i]=0; return false; }
            first=v.offsets[dense-1]; last=v.offsets[dense]; occupant=v.occupants;
            if (last<first || last>v.memberships) { Fail(j,LayoutFallbacks); a.span[i]=0; return false; }
        } else {
            const U dense=a.cellDense[cell]-1;
            first=a.starts[dense]; last=first+a.counts[dense]; occupant=a.csr;
        }
        for (U n=first;n<last;++n) {
            U s=occupant[n];
            if (s>=j.count) { Fail(j,LayoutFallbacks); a.span[i]=0; return false; }
            if (s==i) continue;
            if (j.owned) {
                // Validated memberships are rectangles. Their first shared cell in row-major
                // query order is max(left),max(top): exactly the old first-seen dedup, without
                // a random epoch-table write for every visited neighbor.
                if (x!=(std::max)(a.left[i],a.left[s]) || y!=(std::max)(a.top[i],a.top[s])) continue;
            } else {
                if (stamps[s]==epoch) continue;
                stamps[s]=epoch;
            }
            if (++count>kPairs) { Fail(j,CapacityFallbacks); return false; }
            if (Rebuild) {
                if (!Enqueue(j,a.serial[s]&0xffff,queued)) return false;
            } else {
                // Count even ineligible/rejected candidates, but never allocate storage for them.
                if (a.rank[i]==0xffffffffu || a.done[s] || a.rank[s]<a.rank[i]) continue;
                U index=MakePacket(j,i,s,n,a.serial[i]);
                if (j.failure) return false;
                if (index==0xffffffffu) continue;
                if (previous==kNoPacket) a.first[i]=index;
                else a.packets[previous].flags=(a.packets[previous].flags&kPacketFlagMask)|(index<<2);
                previous=index;
                ++a.accepted[i];
            }
        }
    }
    a.span[i]=count;
    return Rebuild || AccountCandidates(j,count);
}
void Reduce(Job& j,U i) {
    Arena& a=*arena;
    U accepted=i<j.primaryCount?a.accepted[i]:0;
    if (!a.rec[i] || (!accepted && !a.incomingCount[i])) return;
    B* r=a.rec[i];
    float x=At<float>(r,0x70),z=At<float>(r,0x74),ax=At<float>(r,0x78),az=At<float>(r,0x7c);
    // Private per-record registers; deterministic outgoing-first, then incoming candidate order.
    for (U n=0;n<accepted;++n) {
        const Packet& p=a.packets[a.outgoing[a.acceptedFirst[i]+n]];
        x=Sub(x,p.px); z=Sub(z,p.pz); ax=Add(ax,Abs(p.px)); az=Add(az,Abs(p.pz));
    }
    for (U n=0;n<a.incomingCount[i];++n) {
        const Packet& p=a.packets[a.incoming[a.incomingFirst[i]+n]];
        x=Add(x,p.nx); z=Add(z,p.nz); ax=Add(ax,Abs(p.nx)); az=Add(az,Abs(p.nz));
    }
    a.sum70[i]=x; a.sum74[i]=z; a.sum78[i]=ax; a.sum7c[i]=az;
}
void AuditCell(Job& j,U cell);
void Commit(Job& j,U i,bool labels) {
    Arena& a=*arena; B* r=a.rec[i];
    if (!r) return;
    if (labels) {
        if (a.labelDirty[i]) At<U>(r,0x88)=a.labels[i];
        if (a.rank[i]!=0xffffffffu) At<B>(r,0x40)=1;
    }
    if ((i<j.primaryCount && a.accepted[i]) || a.incomingCount[i]) {
        At<float>(r,0x70)=a.sum70[i]; At<float>(r,0x74)=a.sum74[i];
        At<float>(r,0x78)=a.sum78[i]; At<float>(r,0x7c)=a.sum7c[i];
    }
}
void Body(Job& j,U chunk) {
    Arena& a=*arena;
    if (j.phase==CachePhase) {
        U size=(j.view->memberships+j.chunks-1)/j.chunks;
        U first=chunk*size,last=(std::min)(first+size,j.view->memberships);
        for (U n=first;n<last;++n) {
            U s=j.view->occupants[n];
            if (s>=j.count) { Fail(j,LayoutFallbacks); return; }
            a.cellX[n]=a.x[s]; a.cellZ[n]=a.z[s]; a.cellRadius[n]=a.radius[s];
        }
        return;
    }
    if (j.phase==HistogramPhase) {
        U size=(j.sortCount+j.sortChunks-1)/j.sortChunks,start=chunk*size,end=(std::min)(start+size,j.sortCount);
        U* histogram=a.histogram+chunk*j.sortStride;
        memset(histogram,0,j.sortKeys*sizeof(U));
        for (U n=start;n<end;++n) ++histogram[a.entries[n].key];
        return;
    }
    if (j.phase==AuditPhase) {
        U size=(j.auditCount+j.chunks-1)/j.chunks,start=chunk*size,end=(std::min)(start+size,j.auditCount);
        for (U n=start;n<end && !j.failure;++n) AuditCell(j,a.occupied[n]);
        return;
    }
    if (j.phase==ContactPlanPhase) {
        // Contact-balanced: plan rows are dense (acceptedFirst is the record-order prefix sum), and
        // contacts cluster in melee slot ranges, so split the contact index range, not the records.
        // Exactly the contacts ApplyRecord dispatches; read-only, from the state the callbacks see.
        U at=static_cast<U>(static_cast<ULONGLONG>(chunk)*j.acceptedTotal/j.planChunks);
        U end=static_cast<U>(static_cast<ULONGLONG>(chunk+1)*j.acceptedTotal/j.planChunks);
        j.chunkPlanned[chunk]=0;
        if (at>=end) return;
        // Owner of contact `at`: the last record whose first contact is <= at (acceptedFirst[0]==0).
        U i=static_cast<U>(std::upper_bound(a.acceptedFirst,a.acceptedFirst+j.primaryCount,at)-a.acceptedFirst)-1;
        for (;at<end && !j.failure;++i) {
            U last=(std::min)(a.acceptedFirst[i]+a.accepted[i],end);
            if (at>=last) continue;
            if (!a.nativeRecord[i] && a.active[i] && (a.flags[i]&3)) {
                B* r=a.rec[i];
                for (U n=at;n<last;++n)
                    ntw2_contact::Predict(*j.contact,a.plans[n],r,a.rec[a.packets[a.outgoing[n]].other]);
                j.chunkPlanned[chunk]+=last-at;
            }
            at=last;
        }
        return;
    }
    U start=chunk*j.chunkSize,end=(std::min)(start+j.chunkSize,j.count);
    for (U i=start;i<end && !j.failure;++i) {
        // Query metadata is primary-sized; secondary registry records are destinations only.
        if (i>=j.primaryCount && (j.phase==NativeClassifyPhase ||
            j.phase==PacketPhase || j.phase==IncomingFillPhase)) continue;
        if ((j.phase==GatherPhase || j.phase==CommitPhase || j.phase==LabelCommitPhase) && i+8<end && a.rec[i+8]) {
            _mm_prefetch(reinterpret_cast<const char*>(a.rec[i+8]+0x40),_MM_HINT_T0);
            _mm_prefetch(reinterpret_cast<const char*>(a.rec[i+8]+0x80),_MM_HINT_T0);
        }
        if (j.phase==GatherPhase) Gather(j,i);
        else if (j.phase==MembershipPhase) {
            U at=a.memberFirst[i];
            for (U y=a.top[i];y<=a.bottom[i];++y) for (U x=a.left[i];x<=a.right[i];++x)
                a.entries[at++]={(y<<j.shift)+x,i};
        } else if (j.phase==PacketPhase) {
            if (a.nativeRecord[i]) continue;
            U unused=0;
            Enumerate<false>(j,chunk,i,unused);
        }
        else if (j.phase==IncomingFillPhase) {
            if (a.nativeRecord[i] || !a.accepted[i]) continue;
            U at=a.acceptedFirst[i],index=a.first[i];
            for (U n=0;n<a.accepted[i];++n) {
                if (index>=kContacts) { Fail(j,LayoutFallbacks); return; }
                const Packet& packet=a.packets[index];
                a.outgoing[at++]=index;
                _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&a.incomingCount[packet.other]));
                index=packet.flags>>2;
            }
            if (index!=kNoPacket) { Fail(j,LayoutFallbacks); return; }
        } else if (j.phase==ReducePhase) Reduce(j,i);
        else if (j.phase==CommitPhase || j.phase==LabelCommitPhase) Commit(j,i,j.phase==LabelCommitPhase);
        else if (j.phase==NativeClassifyPhase) {
            for (U y=a.top[i];y<=a.bottom[i];++y) for (U x=a.left[i];x<=a.right[i];++x)
                if (a.badCell[(y<<j.shift)+x]) a.nativeRecord[i]=1;
        }
    }
}
void __fastcall Chunk(void* context,U chunk) {
    Job& j=*static_cast<Job*>(context);
    bool worker=GetCurrentThreadId()!=j.owner;
    ULONGLONG cpu=worker?ThreadClock():0;
    bool plan=j.phase==ContactPlanPhase;
    ULONGLONG busy=plan?Clock():0;
    U previous=_mm_getcsr(); unsigned short cw;
    __asm { fnstcw cw }
    _mm_setcsr(j.mxcsr);
    unsigned short ownerCw=j.cw;
    __asm { fldcw ownerCw }
    __try {
        __try { Body(j,chunk); }
        // Once game stores begin, an access violation cannot be rolled back into ORIGINAL.
        __except((j.phase==CommitPhase || j.phase==LabelCommitPhase)?EXCEPTION_CONTINUE_SEARCH:Fault(j,GetExceptionCode())) {}
    } __finally {
        _mm_setcsr(previous);
        __asm { fldcw cw }
    }
    if (plan) j.chunkBusy[chunk]=Clock()-busy;
    ULONGLONG end=worker?ThreadClock():0;
    j.chunkCpu[chunk]=end>=cpu?end-cpu:0;
    _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&words[worker?WorkerChunks:InlineChunks]));
}
void Dispatch(Job& j,U phase) {
    j.phase=phase;
    U chunks=phase==HistogramPhase?j.sortChunks:phase==ContactPlanPhase?j.planChunks:j.chunks;
    binding.dispatch(binding.pool,Address(reinterpret_cast<const void*>(&Chunk)),chunks,&j);
    for (U n=0;n<chunks;++n) j.workerCpu+=j.chunkCpu[n];
}
bool SortEntries(Job& j,U count,U keys) {
    j.sortCount=count; j.sortKeys=keys; j.sortStride=(keys+15)&~15u;
    if (!count) return true;
    if (!keys) return count==0;
    // Audit-only dense occupied keys: histogram once, then native-chain ordered scatter.
    j.sortChunks=(std::min)(j.chunks,kHistogram/j.sortStride);
    Dispatch(j,HistogramPhase); if (j.failure) return false;
    U next=0;
    for (U key=0;key<keys;++key) {
        U first=next;
        for (U chunk=0;chunk<j.sortChunks;++chunk) {
            U& bucket=arena->histogram[chunk*j.sortStride+key];
            U countInBucket=bucket; bucket=next; next+=countInBucket;
        }
        arena->starts[key]=first; arena->counts[key]=next-first;
    }
    // Native-chain auditing supplies the grid scatter in its exact original order.
    return !j.failure;
}
// Disjoint cells, read-only game accesses under the active epoch with AI parked.
// Any chunk fault is handled before the first game write; ORIGINAL can still run once.
void AuditCell(Job& j,U cell) {
    Arena& a=*arena;
    U dense=a.cellDense[cell],expected=dense?a.counts[dense-1]:0;
    U found=0,record=dense?a.firstRecord[dense-1]-1:kRecords;
    B* previous=nullptr;
    for (B* node=reinterpret_cast<B*>(j.nativeCells[cell]);node;node=At<B*>(node,20)) {
        if (++found>kMembers) { Fail(j,CapacityFallbacks); return; }
        U reason=0,slot=kRecords;
        if (At<U>(node,0)!=8) reason=ChainType;
        else if (At<B*>(node,16)!=previous) reason=ChainPrevious;
        else if (At<U*>(node,24)!=j.nativeCells+cell) reason=ChainCell;
        else {
            B* owner=At<B*>(node,12); U s=slot=Slot(owner);
            if (s==kRecords) reason=ChainOwner;
            else if (At<B*>(node,8)!=owner+0x30) reason=ChainPayload;
            else if (At<U>(node,4)!=a.serial[s]) reason=ChainId;
            else {
                U offset=Address(node)-At<U>(owner,0xa8);
                if (offset%0x1c || offset/0x1c>=At<U>(owner,0xac)) reason=ChainArray;
            }
        }
        if (reason) { Diagnose(reason,record,node,cell); MarkCell(j,cell); }
        else if (found<=expected) {
            U at=a.starts[dense-1]+found-1;
            a.csr[at]=slot;
            a.cellX[at]=a.x[slot]; a.cellZ[at]=a.z[slot]; a.cellRadius[at]=a.radius[slot];
            a.cellTeam[at]=a.team[slot]; a.cellFlags[at]=a.flags[slot];
        }
        previous=node;
    }
    LONG visits=_InterlockedExchangeAdd(&j.auditVisits,static_cast<LONG>(found));
    if (static_cast<U>(visits)>kMembers-found) Fail(j,CapacityFallbacks);
    if (found!=expected) {
        Diagnose(ChainCount,record,reinterpret_cast<B*>(j.nativeCells[cell]),cell); MarkCell(j,cell);
    }
    if (a.badCell[cell]) _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&words[UnsupportedCells]));
}
// Read-only original first-seen ID enumeration for native records on rebuild ticks.
// Native arithmetic/callbacks still execute only at their owner-ordered query position.
bool NativeNeighbors(Job& j,U i,U* queued) {
    Arena& a=*arena; B* r=a.rec[i]; a.span[i]=0;
    if (!j.rebuild || !r || !a.active[i] || !(a.flags[i]&3)) return true;
    memset(a.scratch,0,0x2004);
    U visits=0,count=0,nodes=At<U>(r,0xac); B* base=At<B*>(r,0xa8);
    for (U n=0;n<nodes;++n) {
        B* current=base+n*0x1c;
        for (B* node=*At<B**>(current,24);node;node=At<B*>(node,20)) {
            if (++visits>kPairs) { Fail(j,CapacityFallbacks); return false; }
            if (node==current) continue;
            U id=At<U>(node,4)&0xffff,mask=1u<<(id&31);
            if (a.scratch[id>>5]&mask) continue;
            a.scratch[id>>5]|=mask;
            // Unsupported native records enumerate original truncated IDs, never CSR slots.
            if (queued && !Enqueue(j,id,*queued)) return false;
            ++count;
        }
    }
    a.span[i]=count;
    return true;
}
bool BuildOrder(Job& j) {
    if (!j.rebuild) {
        for (U n=0;n<j.workCount;++n) {
            U slot=Slot(reinterpret_cast<B*>(j.work[n]));
            if (slot>=j.primaryCount) return false; // The worklist contains primary queries only.
            arena->order[n]=slot;
        }
        return true;
    }
    memset(arena->seen,0,((kRecords+31)/32)*sizeof(U));
    U seed=0,queued=0,next=0;
    while (seed<j.workCount) {
        U slot=kRecords;
        if (queued>next) slot=arena->order[next++];
        else {
            // Seed indices are full-width in the original; only neighbor IDs truncate.
            // Extend owned storage to 131072 bits rather than reproducing its stack overrun.
            if (!Seen(seed)) {
                if (seed>=j.primaryCount || !arena->rec[seed] || queued>=j.workCount) return false;
                See(seed); ++queued; slot=seed; arena->order[next++]=slot;
            }
            ++seed;
        }
        if (slot==kRecords) continue;
        if (arena->nativeRecord[slot]) {
            if (!NativeNeighbors(j,slot,&queued)) return false;
        } else if (!Enumerate<true>(j,0,slot,queued)) return false;
    }
    return next==j.workCount && queued==j.workCount;
}
// Entry identity of the borrowed publication against live manager/model/grid layout. Per-record
// serial/membership/geometry/node consistency is checked in Gather; no native chain is read.
bool ValidView(const Job& j,void* manager,B* model,B* grid) {
    const ntw2_loco::GridView& v=*j.view;
    float scale=v.inverse_scale; U published,live=At<U>(grid,0x24);
    memcpy(&published,&scale,sizeof(published));
    if (!v.record || !v.serial || !v.inserted || !v.left || !v.right || !v.top || !v.bottom ||
        !v.x || !v.y || !v.z || !v.extent || !v.radius ||
        !v.node_type || !v.cell_dense || !v.offsets || !v.occupants) return false;
    return v.manager==Address(manager) && v.model==Address(model) && v.grid==Address(grid) &&
        v.primary_count==j.primaryCount && v.primary_registry==At<U>(manager,0x250) &&
        v.secondary_count==At<U>(manager,0x278) && v.secondary_registry==At<U>(manager,0x27c) &&
        v.native_cells==Address(j.nativeCells) && v.row_shift==j.shift && v.origin==j.origin &&
        v.maximum==j.maximum && v.cell_count>=j.cells && published==live;
}
bool Prepare(Job& j,void* manager) {
    j.manager=static_cast<B*>(manager);
    // Owned mode is decided by the binding, never by view availability: a missing publication
    // refuses to the untouched original stage and is never audited or rebuilt here.
    if (binding.read_grid) {
        j.view=binding.read_grid(manager);
        if (!j.view) { Fail(j,LayoutFallbacks); return false; }
        j.owned=true;
    }
    j.count=j.primaryCount=At<U>(manager,0x24c); j.workCount=At<U>(manager,0x260);
    if (j.count>kPrimary || j.workCount>kPrimary) { Fail(j,CapacityFallbacks); return false; }
    j.work=At<U*>(manager,0x264);
    B* root=At<B*>(manager,0), *model=At<B*>(root,8), *grid=At<B*>(model,0xa4);
    j.rebuild=At<B>(manager,0x268)==1 || At<U>(model,0x58)%100==0;
    j.shift=At<U>(grid,8); j.origin=At<U>(grid,0x10); j.maximum=At<U>(grid,0x14);
    if (j.shift>20 || j.maximum>1023 || j.maximum>=(1u<<j.shift)) { Fail(j,LayoutFallbacks); return false; }
    ULONGLONG cells=(static_cast<ULONGLONG>(j.maximum)<<j.shift)+j.maximum+1;
    j.cells=static_cast<U>(cells); j.nativeCells=At<U*>(grid,0); j.scale=At<float>(grid,0x24);
    if (j.owned && !ValidView(j,manager,model,grid)) { Fail(j,LayoutFallbacks); return false; }
    if (cells>kCells) { Fail(j,CapacityFallbacks); return false; }
    if (j.owned && (j.view->count>kRecords || j.view->memberships>kMembers || j.view->cells>kCells)) {
        Fail(j,CapacityFallbacks); return false;
    }
    if (j.owned) {
        arena->x=j.view->x; arena->y=j.view->y; arena->z=j.view->z;
        arena->extent=j.view->extent; arena->radius=j.view->radius;
        arena->left=j.view->left; arena->right=j.view->right;
        arena->top=j.view->top; arena->bottom=j.view->bottom;
    }
    j.bump=*reinterpret_cast<float*>(V(0x1318038)); j.one=*reinterpret_cast<float*>(V(0x1318048));
    j.weightR=*reinterpret_cast<float*>(V(0x1325cb8)); j.weightS=*reinterpret_cast<float*>(V(0x1325d1c));
    j.crossover=*reinterpret_cast<float*>(V(0x1331b04)); j.farScale=*reinterpret_cast<float*>(V(0x1335a50));
    // Runtime .data/.bss, not a file-backed constant or a SOURCE pin.
    j.headingBias=*reinterpret_cast<volatile uint16_t*>(V(0x150fbc4));
    memset(arena->pointerHash,0,kHash*sizeof(U));
    B** registry=At<B**>(manager,0x250);
    for (U i=0;i<j.count;++i) {
        B* r=arena->rec[i]=registry[i]; if (!r) continue;
        U h=(Address(r)>>4)*2654435761u & (kHash-1);
        while (arena->pointerHash[h]) {
            if (arena->rec[arena->pointerHash[h]-1]==r) { Fail(j,LayoutFallbacks); return false; }
            h=(h+1)&(kHash-1);
        }
        arena->pointerHash[h]=i+1;
    }
    // 7EB935 registers the alternate population through manager+26C using the SAME
    // 483D40 wrapper as primary+240: count/data are wrapper+0C/+10 => +278/+27C.
    // These records are destinations, not additional queries or primary BFS ID entries.
    U secondaryCount=At<U>(manager,0x278);
    if (secondaryCount>kRecords) { Fail(j,CapacityFallbacks); return false; }
    B** secondary=At<B**>(manager,0x27c);
    for (U n=0;n<secondaryCount;++n) {
        B* r=secondary[n]; if (!r) continue;
        U h=(Address(r)>>4)*2654435761u & (kHash-1);
        while (arena->pointerHash[h] && arena->rec[arena->pointerHash[h]-1]!=r) h=(h+1)&(kHash-1);
        if (arena->pointerHash[h]) continue;
        if (j.count==kRecords) { Fail(j,CapacityFallbacks); return false; }
        arena->rec[j.count]=r; arena->pointerHash[h]=++j.count;
    }
    // Unique-secondary append must reproduce the publication's slot count and order.
    if (j.owned && j.count!=j.view->count) { Fail(j,LayoutFallbacks); return false; }
    j.owner=GetCurrentThreadId(); j.mxcsr=_mm_getcsr();
    unsigned short cw;
    __asm { fnstcw cw }
    j.cw=cw;
    U target=kLanes;
    j.chunkSize=(std::max)(64u,(j.count+target-1)/target);
    j.chunks=(std::max)(1u,(j.count+j.chunkSize-1)/j.chunkSize);
    if (!j.owned) {
        for (U n=0;n<arena->occupiedCount;++n) arena->cellDense[arena->occupied[n]]=0;
        for (U n=0;n<static_cast<U>(arena->badCount);++n) arena->badCell[arena->badList[n]]=0;
        arena->occupiedCount=0; arena->badCount=0;
    }
    Timing start=Begin(j); Dispatch(j,GatherPhase); End(j,start,GatherUs,GatherThreadUs);
    if (j.failure) return false;
    start=Begin(j);
    U members=0;
    for (U i=0;i<j.count;++i) {
        if (!j.owned) arena->memberFirst[i]=members;
        U count=j.owned?(arena->rec[i]?j.view->inserted[i]:0):
            (arena->right[i]-arena->left[i]+1)*(arena->bottom[i]-arena->top[i]+1);
        if (count>kMembers-members) { Fail(j,CapacityFallbacks); return false; }
        members+=count;
    }
    if (j.owned) {
        // Borrowed CSR: no binning, sort or chain audit. Every live membership must be published.
        if (members!=j.view->memberships) { Fail(j,LayoutFallbacks); return false; }
        Dispatch(j,CachePhase); if (j.failure) return false;
    } else {
        Dispatch(j,MembershipPhase); if (j.failure) return false;
        for (U n=0;n<members;++n) {
            Entry& entry=arena->entries[n];
            U cell=entry.key,dense=arena->cellDense[cell];
            if (!dense) {
                dense=arena->cellDense[cell]=++arena->occupiedCount;
                arena->occupied[dense-1]=cell; arena->firstRecord[dense-1]=entry.value+1;
            }
            entry.key=dense-1;
        }
        if (!SortEntries(j,members,arena->occupiedCount)) return false;
        // Bounded cell keys form a perfect direct-address hash; clear only occupied keys next stage.
        // Add bad-only cells once, keeping the compact occupied-cell IDs unchanged.
        j.auditCount=arena->occupiedCount;
        for (U n=0;n<static_cast<U>(arena->badCount);++n) {
            U cell=arena->badList[n];
            if (!arena->cellDense[cell]) arena->occupied[j.auditCount++]=cell;
        }
        Timing audit=Begin(j); Dispatch(j,AuditPhase); End(j,audit,AuditUs,AuditThreadUs);
        End(j,start,BinUs,BinThreadUs); if (j.failure) return false;
    }
    if (!j.owned) { Dispatch(j,NativeClassifyPhase); if (j.failure) return false; }
    start=Begin(j); bool valid=BuildOrder(j); End(j,start,RebuildUs,RebuildThreadUs);
    if (!valid) { Fail(j,LayoutFallbacks); return false; }
    memset(arena->seen,0,((kRecords+31)/32)*sizeof(U));
    for (U n=0;n<j.workCount;++n) {
        U slot=arena->order[n];
        if (Seen(slot)) { Fail(j,LayoutFallbacks); return false; }
        See(slot);
        if (arena->active[slot] && (arena->flags[slot]&3)) {
            arena->rank[slot]=n;
            if (arena->nativeRecord[slot]) ++j.nativeQueries;
        }
    }
    // Mixed native records have no streamed packets, but their rebuild candidate counts still
    // participate in the same fixed stage capacity. BFS already enumerated ranked queries.
    for (U i=0;i<j.primaryCount;++i) if (arena->nativeRecord[i]) {
        if (j.rebuild && arena->rank[i]==0xffffffffu && !NativeNeighbors(j,i,nullptr)) return false;
        if (!AccountCandidates(j,arena->span[i])) return false;
    }
    start=Begin(j); Dispatch(j,PacketPhase); End(j,start,PairsUs,PairsThreadUs); if (j.failure) return false;
    // This runtime word is not a SOURCE pin. Refuse a changed dispatch snapshot before any writes.
    if (*reinterpret_cast<volatile uint16_t*>(V(0x150fbc4))!=j.headingBias) { Fail(j,LayoutFallbacks); return false; }
    start=Begin(j);
    U contacts=0;
    for (U i=0;i<j.primaryCount;++i) {
        arena->acceptedFirst[i]=contacts;
        words[ShapedPairs]+=arena->shaped[i];
        if (arena->accepted[i]>kContacts-contacts) { Fail(j,CapacityFallbacks); return false; }
        contacts+=arena->accepted[i];
    }
    j.acceptedTotal=contacts;
    Dispatch(j,IncomingFillPhase); if (j.failure) return false;
    U incoming=0;
    for (U i=0;i<j.count;++i) {
        arena->incomingFirst[i]=arena->incomingCursor[i]=incoming;
        incoming+=arena->incomingCount[i];
    }
    // Stable record/candidate order, independent of packet allocation/worker completion.
    // The compact stream is small; no duplicated radix entries or per-lane record histogram.
    for (U n=0;n<contacts;++n) {
        U index=arena->outgoing[n],other=arena->packets[index].other;
        arena->incoming[arena->incomingCursor[other]++]=index;
    }
    Dispatch(j,ReducePhase);
    U previousWall=words[ReductionUs],previousCpu=words[ReductionThreadUs];
    End(j,start,ReductionUs,ReductionThreadUs);
    words[ApplyUs]+=words[ReductionUs]-previousWall;
    words[ApplyThreadUs]+=words[ReductionThreadUs]-previousCpu;
    return !j.failure;
}
void Redistribute(Job& j,U i,const Packet& p) {
    Arena& a=*arena; B* r=a.rec[i],*s=a.rec[p.other];
    if (At<B>(s,0x66) || (!(p.flags&2) && !(At<U>(r,0x38)&0x20))) return;
    float rz=At<float>(r,0x84), rx=At<float>(r,0x80);
    float rd=Add(Mul(rx,p.dx),Mul(rz,p.dz));
    if (!Greater(rd,0)) {
        // The neighbor dot has the reverse ADDSS operand order in the original.
        float sd=Add(Mul(At<float>(s,0x84),p.dz),Mul(At<float>(s,0x80),p.dx));
        if (!Greater(0,sd)) return;
    }
    float z=Add(At<float>(s,0x84),rz), x=Add(rx,At<float>(s,0x80));
    float rm=At<float>(r,0x68), sm=At<float>(s,0x68), inv=Div(j.one,Add(rm,sm));
    float wr=Mul(rm,inv);
    At<float>(r,0x84)=Mul(z,wr); At<float>(r,0x80)=Mul(x,wr);
    float ws=Mul(sm,inv);
    At<float>(s,0x80)=Mul(x,ws); At<float>(s,0x84)=Mul(z,ws);
    U rl=j.nativeQueries?At<U>(r,0x88):a.labels[i];
    U sl=j.nativeQueries?At<U>(s,0x88):a.labels[p.other];
    // Conditional sequential unsigned MAX is not an order-independent component reduction.
    U label=(std::max)(rl,sl);
    if (j.nativeQueries) { At<U>(r,0x88)=label; At<U>(s,0x88)=label; }
    else {
        a.labels[i]=a.labels[p.other]=label;
        a.labelDirty[i]=a.labelDirty[p.other]=1;
    }
    ++words[Redistributions]; if (rl!=sl) ++words[LabelChanges];
}
using Callback=void (__thiscall*)(void*,void*);
using Query=void (__thiscall*)(void*,void*);
// A callback fault has potentially committed side effects: never replay that callback or restart the stage.
bool CallbackGuard(Job& j,B* s,B* r) {
    __try { reinterpret_cast<Callback>(At<U>(At<void*>(s,0),0x44))(s,r); return true; }
    __except(Fault(j,GetExceptionCode())) { return false; }
}
bool ContactOriginal(void* context,void* s,void* r) {
    return CallbackGuard(*static_cast<Job*>(context),static_cast<B*>(s),static_cast<B*>(r));
}
// Model of the stage manager G: [[G+0]+8] (analysis/native-softcollision-spec.md, manager layout).
void* ContactModel(B* manager) {
    __try { B* root=At<B*>(manager,0); return root?At<void*>(root,8):nullptr; }
    __except(EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}
void NativeQuery(B* r) {
    ++words[NativeQueries];
    memset(arena->scratch,0,0x2004);
    arena->scratch[0x2008/4]=65536;
    arena->scratch[0x200c/4]=0;
    arena->scratch[0x2010/4]=Address(arena->ids);
    reinterpret_cast<Query>(V(0x81a790))(r,arena->scratch);
}
void ApplyRecord(Job& j,U i,bool& continuedAfterFault,U& contactIndex) {
    Arena& a=*arena; B* r=a.rec[i];
    ++words[Records];
    if (!a.active[i] || !(a.flags[i]&3)) return;
    ++words[EligibleQueries];
    if (a.nativeRecord[i]) { ++words[NodeFallbacks]; NativeQuery(r); return; }
    words[Pairs]+=a.span[i];
    for (U n=0;n<a.accepted[i];++n) {
        const Packet& p=a.packets[a.outgoing[a.acceptedFirst[i]+n]];
        if (n+4<a.accepted[i]) {
            const Packet* next=&a.packets[a.outgoing[a.acceptedFirst[i]+n+4]];
            _mm_prefetch(reinterpret_cast<const char*>(next),_MM_HINT_T0);
            _mm_prefetch(reinterpret_cast<const char*>(a.rec[next->other]),_MM_HINT_T0);
        }
        B* s=a.rec[p.other];
        // Native-local queries need their original +40 progression. Only this cold mixed
        // path interleaves redistribution and callbacks; supported stages time whole passes.
        if (j.nativeQueries) {
            Timing redistribution=Begin(j); Redistribute(j,i,p);
            End(j,redistribution,RedistributeUs,RedistributeThreadUs);
        }
        Timing callback={}; if (j.nativeQueries) callback=Begin(j);
        ++words[Contacts]; ++words[Callbacks];
        bool completed;
        if (j.contact) {
            // Planned contact: shadow runs the original and compares; workers mode replays the
            // same-team effects (or runs the original for every other plan kind).
            const ntw2_contact::Plan& plan=a.plans[a.acceptedFirst[i]+n];
            ntw2_contact::CountPlan(plan);
            completed=binding.contact_mode==ntw2_contact::ModeShadow ?
                ntw2_contact::Shadow(*j.contact,plan,contactIndex,r,s,&ContactOriginal,&j) :
                ntw2_contact::Replay(*j.contact,plan,r,s,&ContactOriginal,&j);
        } else completed=CallbackGuard(j,s,r);
        ++contactIndex;
        if (!completed) {
            faulted=true;
            if (!continuedAfterFault) {
                continuedAfterFault=true; ++words[OwnerContinuations]; ++words[FallbackTicks];
            }
        }
        if (j.nativeQueries) End(j,callback,CallbackUs,CallbackThreadUs);
    }
    if (j.nativeQueries) At<B>(r,0x40)=1;
}
void Apply(Job& j) {
    Arena& a=*arena;
    // All speculative phases were read-only. Parallel stores begin only after admission.
    // Store faults are not caught as restartable preparation faults.
    Timing stores={};
    if (j.nativeQueries) {
        stores=Begin(j); Dispatch(j,CommitPhase); End(j,stores,StoreUs,StoreThreadUs);
    }
    if (j.rebuild) {
        At<B>(j.manager,0x268)=0; ++words[Rebuilds];
        // The original seed/queue algorithm already produced this permutation from snapshot
        // first-seen IDs. Publishing it before callbacks keeps packet ranks and query order identical.
        for (U n=0;n<j.workCount;++n) j.work[n]=Address(a.rec[a.order[n]]);
    }
    if (!j.nativeQueries) {
        Timing redistribution=Begin(j);
        for (U n=0;n<j.workCount;++n) {
            U i=a.order[n];
            if (a.rank[i]==0xffffffffu) continue;
            for (U p=0;p<a.accepted[i];++p) {
                const Packet& packet=a.packets[a.outgoing[a.acceptedFirst[i]+p]];
                if (p+4<a.accepted[i]) {
                    const Packet* next=&a.packets[a.outgoing[a.acceptedFirst[i]+p+4]];
                    _mm_prefetch(reinterpret_cast<const char*>(next),_MM_HINT_T0);
                    _mm_prefetch(reinterpret_cast<const char*>(a.rec[next->other]+0x80),_MM_HINT_T0);
                }
                Redistribute(j,i,packet);
            }
        }
        End(j,redistribution,RedistributeUs,RedistributeThreadUs);
        stores=Begin(j); Dispatch(j,LabelCommitPhase); End(j,stores,StoreUs,StoreThreadUs);
    }
    // Contact responses: plans are decided on the pool from the state the callbacks see (every
    // effect a callback writes is outside the plan inputs, or revalidated at replay).
    ntw2_contact::Stage contactStage;
    bool contactStageOpen=false;
    j.contact=nullptr;
    if (binding.contact_mode && a.plans && ntw2_contact::BeginStage(contactStage,ContactModel(j.manager))) {
        contactStageOpen=true;
        ULONGLONG wall=Clock(); j.contact=&contactStage;
        // Each chunk >=kPlanGrain contacts (one owner-only chunk below 2*kPlanGrain, no wake),
        // at most kChunks; the pool's dynamic claim balances them.
        j.planChunks=(std::max)(1u,(std::min)(kChunks,j.acceptedTotal/kPlanGrain));
        Dispatch(j,ContactPlanPhase);
        ULONGLONG busy=0;
        for (U n=0;n<j.planChunks;++n) { busy+=j.chunkBusy[n]; planPredicted+=j.chunkPlanned[n]; }
        planRows=j.acceptedTotal;
        ntw2_contact::AddPlanTime(Micros(wall),static_cast<U>(busy*1000000/frequency.QuadPart));
        if (j.failure) j.contact=nullptr; // a solver-side chunk fault: no plan is trusted
    }
    // Approved split-pass visibility: supported callbacks see final sums, velocities,
    // conditional labels and processed bytes. Callback order itself is unchanged.
    bool continuedAfterFault=false; U contactIndex=0; Timing callbacks=Begin(j);
    for (U n=0;n<j.workCount;++n) ApplyRecord(j,a.order[n],continuedAfterFault,contactIndex);
    if (contactStageOpen) ntw2_contact::EndStage(contactStage,contactIndex);
    if (!j.nativeQueries) End(j,callbacks,CallbackUs,CallbackThreadUs);
    // After numeric commit, native-query fallback for a solver suffix would apply impulses twice.
    // Finish its precomputed owner work instead; sticky ORIGINAL-stage fallback begins next tick.
}
U Original(void* manager) {
    using StageFn=U (__thiscall*)(void*);
    return reinterpret_cast<StageFn>(V(0x57dc30))(manager);
}
}
bool Start(const Binding& value) {
    Stop(); binding=value; memset(words,0,sizeof(words)); memset(sourceWords,0,sizeof(sourceWords));
    faulted=false; diagnosticClaim=0;
    ntw2_contact::Start(binding.image_delta,binding.contact_mode);
    QueryPerformanceFrequency(&frequency);
    return true;
}
U EstimateActivationBytes(const ntw2_workload::Capacity& capacity) {
    Limits limits;
    return CapacityLimits(capacity,limits)?ReservationBytes(limits):0xffffffffu;
}
bool Activate(void* manager,const ntw2_workload::Capacity& capacity) {
    Stop();
    Limits limits;
    if (!manager || !CapacityLimits(capacity,limits)) return false;
    U bytes=ReservationBytes(limits);
    if (bytes==0xffffffffu) return false;
    kPrimary=limits.primary; kRecords=limits.records; kCells=limits.cells;
    kMembers=limits.members; kPairs=limits.pairs; kLanes=limits.lanes;
    kHash=limits.hash; kContacts=limits.contacts; kHistogram=limits.histogram;
    allocation=static_cast<B*>(VirtualAlloc(nullptr,bytes,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if (!allocation) return false;
    memset(allocation,0,bytes); // Activation-only prefault, no lazy tick-time growth.
    Layout(storage,allocation,limits);
    storageBytes=bytes; arena=&storage; activationManager=manager;
    return true;
}
U StorageBytes() { return storageBytes; }
void Stop() {
    if (allocation) VirtualFree(allocation,0,MEM_RELEASE);
    allocation=nullptr; arena=nullptr; activationManager=nullptr; storageBytes=0;
    storage=Arena{};
}
void Sample(U out[WordCount]) { memcpy(out,words,sizeof(words)); }
void SampleSource(U out[SourceWordCount]) { memcpy(out,sourceWords,sizeof(sourceWords)); }
const ntw2_contact::Plan* ContactPlans(U& rows,U& predicted) {
    rows=planRows; predicted=planPredicted;
    return arena?arena->plans:nullptr;
}
U __fastcall Stage(void* manager) {
    ++words[Calls]; ULONGLONG start=Clock(); Job job={};
    planRows=planPredicted=0;
    if (!arena) job.failure=ArenaFallbacks;
    else if (manager!=activationManager) job.failure=LayoutFallbacks;
    else if (faulted) job.failure=StickyFallbacks;
    else if (!binding.dispatch || !binding.workers) job.failure=PoolFallbacks;
    else {
        __try { if (!Prepare(job,manager) && !job.failure) Fail(job,LayoutFallbacks); }
        __except(Fault(job,GetExceptionCode())) {}
    }
    U result=0;
    if (job.failure) {
        if (job.failure==StickyFallbacks) faulted=true;
        ++words[FallbackTicks]; ++words[job.failure];
        // Owned mode requested: every original-stage fallback (missing/stale view included) is a refusal.
        if (binding.read_grid) ++sourceWords[OwnedRefusals];
        sourceWords[Source]=SourceNone;
        result=Original(manager);
    } else {
        Timing apply=Begin(job); Apply(job); End(job,apply,ApplyUs,ApplyThreadUs);
        ++words[SolverTicks]; words[Cells]+=job.owned?job.view->cells:arena->occupiedCount;
        sourceWords[Source]=job.owned?SourceOwned:SourceNativeAudit;
        ++sourceWords[job.owned?OwnedStages:NativeStages];
        words[MaxPairs]=(std::max)(words[MaxPairs],job.totalPairs);
        words[MaxRecords]=(std::max)(words[MaxRecords],job.workCount);
    }
    U elapsed=Micros(start); words[StageUs]+=elapsed; words[MaxUs]=(std::max)(words[MaxUs],elapsed);
    return result;
}
}
#pragma float_control(pop)

#include <windows.h>
#include <xmmintrin.h>
#include <cmath>
#include <cstring>
#include <new>
#include <algorithm>
#include <array>
#include <map>
#include <set>
#include <iterator>

#include "native_sweep.h"

static_assert(sizeof(void*) == 4, "sweep uses the native x86 identity ABI");
namespace ntw2_sweep {
namespace {
U words[WordCount];
struct TargetCount { U target, calls; };
enum PredicateKind : U { OwnerActivity, EdgePredicate, Payload20Activity, OtherOwnerActivity, PredicateKinds };
TargetCount targets[PredicateKinds][256];
U targetCount[PredicateKinds], skippedDepth;
Binding binding;
Scene scene;
Work* work;
LARGE_INTEGER frequency;
bool pending, evaluating;
AgentView input;
Aabb box;
U queryMode, headers[3], counts[3];
U inputMxcsr;
unsigned short inputControl;
U queryCall;
inline U D(U a) { return *reinterpret_cast<const U*>(a); }
inline float F(U a) { return *reinterpret_cast<const float*>(a); }
inline uint8_t B(U a) { return *reinterpret_cast<const uint8_t*>(a); }
inline U Address(const void* a) { return static_cast<U>(reinterpret_cast<uintptr_t>(a)); }
float Mul(float a,float b) { return _mm_cvtss_f32(_mm_mul_ss(_mm_set_ss(a),_mm_set_ss(b))); }
float Add(float a,float b) { return _mm_cvtss_f32(_mm_add_ss(_mm_set_ss(a),_mm_set_ss(b))); }
float Sub(float a,float b) { return _mm_cvtss_f32(_mm_sub_ss(_mm_set_ss(a),_mm_set_ss(b))); }
float Div(float a,float b) { return _mm_cvtss_f32(_mm_div_ss(_mm_set_ss(a),_mm_set_ss(b))); }
uint8_t Predicate(PredicateKind kind,U receiver,U slot=0) {
    // Load once: histogram and invocation consume the identical code pointer.
    // Only Sample normalizes it; never relocate the pointer used for dispatch.
    const U target=D(D(receiver)+slot);
    U& count=targetCount[kind];
    U i=0;
    for(;i<count;++i) if(targets[kind][i].target==target) break;
    if(i==count && count<256) targets[kind][count++]={target,0};
    if(i<256) ++targets[kind][i].calls;
    else ++words[8]; // A full histogram invalidates the capture rather than hiding targets.
    return reinterpret_cast<uint8_t(__thiscall*)(void*)>(target)(reinterpret_cast<void*>(receiver));
}
bool Eligible(U type,U owner) {
    switch(type) {
    case 0x40: case 0x80: return Predicate(OwnerActivity,owner+0x1C) != 0;
    case 0x20: return Predicate(Payload20Activity,D(owner+0x3C)+0xC) != 0;
    case 0x10: case 0x100: return Predicate(OtherOwnerActivity,owner+0xC) != 0;
    case 8: return B(owner+0x30) != 0;
    case 0x200: return B(owner+0x1C54) != 0;
    default: return true;
    }
}
bool Plane(U owner,const AgentView& a) {
    float sum = Add(Mul(F(owner+0x38),a.z),Mul(F(owner+0x30),a.x));
    float factor = Div(-1.0f,F(owner+0x34));
    sum = Add(sum,F(owner+0x3C));
    float delta = Sub(Mul(sum,factor),a.y);
    return a.extent > std::fabs(delta);
}
Aabb OwnerBounds(U owner) { return {F(owner+0x44),F(owner+0x4C),F(owner+0x50),F(owner+0x58)}; }
bool Overlap(const Aabb& a,const Aabb& b) {
    // JA rejects ordered greater only; NaNs do not reject.
    return !(a.minX>b.maxX || b.minX>a.maxX || a.minZ>b.maxZ || b.minZ>a.maxZ);
}
U Coordinate(float value,const Scene& s) {
    float scaled=Mul(value,s.scale),half=-0.5f;
    int rounded;
    __asm { fld scaled }
    __asm { fadd st(0), st(0) }
    __asm { fadd half }
    __asm { fistp rounded }
    U result=static_cast<U>(rounded>>1)+s.bias;
    return result<s.upper ? result:s.upper;
}
bool Mark(Work& w,U set,U owner,U offset) {
    uint16_t id=static_cast<uint16_t>(D(owner+offset));
    U bit=1u<<(id&31),&word=w.visited[set][id>>5];
    if(word&bit) return false;
    if(w.touchedCount[set]==w.touched[set].size()) RaiseException(WorkerRefusal,0,0,nullptr);
    word|=bit; w.touched[set][w.touchedCount[set]++]=id; return true;
}
void Clear(Work& w,U set) {
    for(U i=0;i<w.touchedCount[set];++i) w.visited[set][w.touched[set][i]>>5]=0;
    w.touchedCount[set]=0;
}
void Append(std::vector<U>& v,U value) {
    if(v.size()==v.capacity()) RaiseException(WorkerRefusal,0,0,nullptr);
    v.push_back(value);
}
template<class T> void Compact(std::vector<T>& v) {
    if(v.capacity()!=v.size()) std::vector<T>(std::make_move_iterator(v.begin()),std::make_move_iterator(v.end())).swap(v);
}
struct SceneCapture {
    Scene& s;
    WorkerScene* checks;
    std::map<std::array<U,3>,U> records;
    std::map<std::pair<U,U>,U> links;
    std::set<U> gridOwners, capsuleOwners;
    std::vector<U> chain;
    void Verify(U address,size_t bytes) {
        if(checks) VerifyOnBuild(*checks,0,address,bytes);
    }
    U Chain(U node,bool grid) {
        chain.clear();
        while(node) {
            const U type=D(node),nativeOwner=D(node+0xC);
            // These fields have no query meaning for other types. Keep their
            // native words in the activation tape, not in each interned record.
            const U payload=type==0x800 ? D(node+8):0;
            const bool usesOwner=type==0x40 || type==0x80 || type==0x20 || type==0x10 || type==0x100 || type==8 || type==0x200;
            const U owner=usesOwner ? nativeOwner:0;
            Verify(node,4); Verify(node+8,8); Verify(node+0x14,4);
            if(s.nativeNodes==UINT32_MAX) RaiseException(WorkerRefusal,0,0,nullptr);
            ++s.nativeNodes;
            if(grid) {
                if(type==0x40) gridOwners.insert(owner);
                else if(type==0x20) capsuleOwners.insert(owner);
                else if(type==0x800) ++s.wallCandidates;
            } else if(type==0x80) ++s.treeCandidates;
            const std::array<U,3> key{type,payload,owner};
            auto entry=records.try_emplace(key,static_cast<U>(s.type.size()));
            if(entry.second) {
                s.type.push_back(type); s.payload.push_back(payload); s.owner.push_back(owner);
            }
            chain.push_back(entry.first->second);
            node=D(node+0x14);
        }
        U head=UINT32_MAX;
        for(auto it=chain.rbegin();it!=chain.rend();++it) {
            auto entry=links.try_emplace(std::make_pair(*it,head),static_cast<U>(s.linkNode.size()));
            if(entry.second) { s.linkNode.push_back(*it); s.linkNext.push_back(head); }
            head=entry.first->second;
        }
        return head;
    }
    U Tree(U node) {
        const U index=static_cast<U>(s.treeIdentity.size());
        Verify(node+4,4); Verify(node+0xC,8); Verify(node+0x18,24);
        s.treeIdentity.push_back(node);
        s.treeBounds.push_back({F(node+4),F(node+0xC),F(node+0x10),F(node+0x18)});
        const U head=Chain(D(node+0x1C),false);
        s.treeHead.push_back(head);
        if(head!=UINT32_MAX) ++s.hitCapacity;
        for(U i=0;i<4;++i) s.child[i].push_back(UINT32_MAX);
        if(D(node+0x20)) for(U i=0;i<4;++i) {
            const U child=Tree(D(node+0x20+4*i)); s.child[i][index]=child;
        }
        return index;
    }
};
bool CaptureImpl(Scene& s,U model,U generation,WorkerScene* checks) {
    s=Scene{};
    const U grid=D(model+0xA8);
    memcpy(s.header,reinterpret_cast<void*>(grid),sizeof(s.header));
    s.shift=D(grid+8); s.bias=D(grid+0x10); s.upper=D(grid+0x14); s.scale=F(grid+0x24);
    if(s.shift>=31 || s.upper>=(1u<<s.shift)) return false;
    const uint64_t cells=(static_cast<uint64_t>(s.upper)<<s.shift)+s.upper+1;
    if(cells>UINT32_MAX/4) return false;
    s.cellCount=static_cast<U>(cells);
    SceneCapture capture{s,checks};
    const U heads=D(grid);
    capture.Verify(heads,s.cellCount*4);
    for(U cell=0;cell<s.cellCount;++cell) {
        const U head=capture.Chain(D(heads+4*cell),true);
        if(head==UINT32_MAX) continue;
        if(!s.cells.empty() && s.cells.back().last+1==cell && s.cells.back().head==head) s.cells.back().last=cell;
        else s.cells.push_back({cell,cell,head});
    }
    capture.Tree(D(D(model+0xC0)+0x4C)+0xC);
    s.gridOwners=static_cast<U>((std::min)(capture.gridOwners.size(),size_t(65536)));
    s.capsuleOwners=static_cast<U>((std::min)(capture.capsuleOwners.size(),size_t(65536)));
    Compact(s.cells); Compact(s.type); Compact(s.payload); Compact(s.owner);
    Compact(s.linkNode); Compact(s.linkNext); Compact(s.treeIdentity); Compact(s.treeHead); Compact(s.treeBounds);
    for(auto& child:s.child) Compact(child);
    s.model=model; s.generation=generation; return true;
}
template<class Visit> void Grid(const Scene& s,U x0,U x1,U z0,U z1,Visit visit) {
    for(U z=z0;z<z1;++z) {
        const U first=(z<<s.shift)+x0,end=(z<<s.shift)+x1;
        auto run=std::lower_bound(s.cells.begin(),s.cells.end(),first,
            [](const CellRun& r,U cell) { return r.last<cell; });
        for(;run!=s.cells.end() && run->first<end;++run)
            for(U cell=(std::max)(first,run->first);cell<end && cell<=run->last;++cell)
                for(U link=run->head;link!=UINT32_MAX;link=s.linkNext[link]) visit(s.linkNode[link]);
    }
}
void Hits(const Scene& s,U index,const Aabb& b,Work& w,bool contained) {
    const Aabb& n=s.treeBounds[index];
    if(!contained) {
        if(!Overlap(b,n)) return;
        contained=b.minX<=n.minX && b.minZ<=n.minZ && b.maxX>=n.maxX && b.maxZ>=n.maxZ;
    }
    if(s.treeHead[index]!=UINT32_MAX) Append(w.hits,index);
    if(s.child[0][index]!=UINT32_MAX)
        for(U i=0;i<4;++i) Hits(s,s.child[i][index],b,w,contained);
}
void BeforeImpl(Agent* agent,Scratch* scratch,const Aabb* bounds,U mode) {
    ++words[3];
    if(pending || evaluating) { ++words[8]; ++skippedDepth; return; }
    queryCall=words[3];
    U a=Address(agent),model=D(D(a+0x28)+8);
    Activate(model);
    if(!work || scene.model!=model) { ++words[8]; return; }
    input={a,D(a+0x10),F(a+0x48),F(a+0x4C),F(a+0x50),F(a+0x54)};
    box=*bounds; queryMode=mode;
    inputMxcsr=_mm_getcsr();
    __asm { fnstcw inputControl }
    for(U i=0;i<3;++i) {
        headers[i]=D(Address(scratch)+4*i);
        counts[i]=D(headers[i]+(i?8:12));
        work->output[i].clear();
    }
    pending=true;
}
void AfterImpl() {
    if(skippedDepth) { --skippedDepth; return; }
    if(!pending) return;
    pending=false; evaluating=true;
    _mm_setcsr(inputMxcsr);
    __asm { fldcw inputControl }
    Run(scene,input,box,queryMode,*work);
    for(U list=0;list<3;++list) {
        U after=D(headers[list]+(list?8:12));
        U data=D(headers[list]+(list?12:16));
        U actual=static_cast<U>(work->output[list].size());
        U expected=after>=counts[list] ? after-counts[list]:UINT32_MAX;
        U first=UINT32_MAX,ev=expected,av=actual;
        U common=(expected<actual ? expected:actual);
        for(U i=0;i<common;++i) if(D(data+4*(counts[list]+i))!=work->output[list][i]) {
            first=i; ev=D(data+4*(counts[list]+i)); av=work->output[list][i]; break;
        }
        if(first==UINT32_MAX && actual!=expected) first=common;
        if(first!=UINT32_MAX) {
            ++words[5+list];
            if(!words[10]) { words[9]=input.identity; words[10]=queryCall; words[11]=list;
                words[12]=first; words[13]=ev; words[14]=av; }
        }
    }
    ++words[4];
    if((queryMode&8) && input.owner) ++words[2];
    evaluating=false;
}
}
void CandidateCapacities(const Scene& s,size_t ownerCapacity,size_t output[3]) {
    // IDs are live, so count distinct owner addresses, not their activation-time
    // low-u16 values. Aliases may split later without increasing these bounds.
    output[0]=size_t(s.gridOwners)+s.treeCandidates+(std::min)(ownerCapacity,size_t(65536));
    output[1]=s.capsuleOwners;
    output[2]=s.wallCandidates;
}
void Work::Prepare(const Scene& s,size_t ownerCapacity,size_t prefixCapacity) {
    ownerCapacity=(std::min)(ownerCapacity,size_t(65536));
    // Exact fresh sizes also shed the previous generation's high-water capacity.
    // Value initialization prefaults every append slot during activation.
    std::vector<U>(s.hitCapacity).swap(hits); hits.clear();
    std::vector<uint16_t>(s.gridOwners).swap(touched[0]);
    std::vector<uint16_t>(s.capsuleOwners).swap(touched[1]);
    std::vector<uint16_t>(ownerCapacity).swap(touched[2]);
    std::vector<U>(ownerCapacity).swap(queue);
    size_t capacity[3]; CandidateCapacities(s,ownerCapacity,capacity);
    for(U i=0;i<3;++i) {
        std::vector<U>(capacity[i]+prefixCapacity).swap(output[i]); output[i].clear();
    }
    memset(visited,0,sizeof(visited)); memset(touchedCount,0,sizeof(touchedCount));
}
bool Capture(Scene& s,U model,U generation) { return CaptureImpl(s,model,generation,nullptr); }
void Run(const Scene& s,const AgentView& a,const Aabb& b,U mode,Work& w) {
    U z0=Coordinate(b.minZ,s),x0=Coordinate(b.minX,s);
    U z1=Coordinate(b.maxZ,s)+1,x1=Coordinate(b.maxX,s)+1;
    if(mode&0x15) Grid(s,x0,x1,z0,z1,[&](U n) {
            U type=s.type[n],owner=s.owner[n];
            if(!Eligible(type,owner)) return;
            if(type==0x40 && (mode&1)) {
                if(Mark(w,0,owner,0x2C) && Plane(owner,a)) Append(w.output[0],owner);
            } else if(type==0x20 && (mode&4)) {
                if(Mark(w,1,owner,0x34) && B(owner+0x48)==0) Append(w.output[1],owner);
            } else if(type==0x800 && (mode&0x10)) Append(w.output[2],s.payload[n]);
    });
    Clear(w,1); Clear(w,0);
    if((mode&2) && !s.treeIdentity.empty()) {
        Hits(s,0,b,w,false);
        for(U index:w.hits) for(U link=s.treeHead[index];link!=UINT32_MAX;link=s.linkNext[link]) {
            const U n=s.linkNode[link];
            if(s.type[n]==0x80 && Predicate(OwnerActivity,s.owner[n]+0x1C)==1 && Plane(s.owner[n],a))
                Append(w.output[0],s.owner[n]);
        }
        w.hits.clear();
    }
    if((mode&8) && a.owner) {
        U read=0,end=0; Mark(w,2,a.owner,0x2C); w.queue[end++]=a.owner;
        while(read<end) {
            U owner=w.queue[read++],head=D(owner+8),edge=head;
            bool anyFalse=false;
            do {
                U neighbor=0,records=D(edge+0x48);
                for(U i=0;i<D(edge+0x44);++i) {
                    U candidate=D(records+8*i);
                    if(Predicate(OwnerActivity,candidate+0x1C)==1) { neighbor=candidate; break; }
                }
                if(neighbor && Overlap(b,OwnerBounds(neighbor)) && Mark(w,2,neighbor,0x2C))
                    w.queue[end++]=neighbor;
                if(Predicate(EdgePredicate,edge,0x14)==0) anyFalse=true;
                edge=D(edge+8);
            } while(edge!=head);
            if(anyFalse && Predicate(OwnerActivity,owner+0x1C)==1 && Plane(owner,a)) Append(w.output[0],owner);
        }
        Clear(w,2);
    }
}
bool PureByteTarget(U target,U delta) {
    const U va=target-delta;
    return va==0x54E920 || va==0x462CB0 || va==0x447880;
}
bool PureAgentTarget(U agent,U target,U delta) {
    if(PureByteTarget(target,delta)) return true;
    const U va=target-delta;
    if(va!=0x62A620 && va!=0x5B77A0) return false;
    // Evidence: both read only agent vtable slots E8/EC/F0 (constant 462CB0/447880
    // or 5DB820's [A+67C]); 62A620 then reads the unit context read-only.
    // The receiver must be a participant copy of at least 0x680 bytes.
    for(U slot: {0xECu,0xF0u,0xE8u}) {
        const U nested=D(D(agent)+slot)-delta;
        if(nested!=0x462CB0 && nested!=0x447880 && nested!=0x5DB820) return false;
    }
    return true;
}
FpState CaptureFp() {
    FpState s{}; unsigned short control;
    s.mxcsr=_mm_getcsr();
    __asm { fnstcw control }
    s.control=control; return s;
}
void ApplyFp(const FpState& s) {
    unsigned short control=s.control;
    _mm_setcsr(s.mxcsr);
    __asm { fldcw control }
}
int RefusalFilter(unsigned long code) {
    return code==WorkerRefusal ? EXCEPTION_EXECUTE_HANDLER:EXCEPTION_CONTINUE_SEARCH;
}
uint8_t PureByte(U receiver,U target,U delta) {
    if(!PureAgentTarget(receiver,target,delta))
        RaiseException(WorkerRefusal,0,0,nullptr);
    return reinterpret_cast<uint8_t(__thiscall*)(void*)>(target)(reinterpret_cast<void*>(receiver));
}
void VerifyOnBuild(const WorkerScene& s,U group,U address,size_t bytes) {
    auto& checks=s.verification[group];
    for(size_t off=0;off<bytes;off+=4) checks.push_back({address+static_cast<U>(off),D(address+static_cast<U>(off))});
}
bool VerifyBuild(const WorkerScene& s,U firstGroup,U groupCount) {
    for(U group=firstGroup;group<firstGroup+groupCount;++group)
        for(const auto& check:s.verification[group]) {
            const U actual=D(check.address);
            if(actual!=check.value) {
                s.failure=SceneVerificationFailure; s.failureAddress=check.address; s.failureActual=actual;
                return false;
            }
        }
    return true;
}
void ReleaseBuildVerification(const WorkerScene& s) {
    for(auto& checks:s.verification) std::vector<VerificationWord>().swap(checks);
}
namespace {
U LivePredicate(U receiver,U slot,U delta) {
    const U target=D(D(receiver)+slot);
    switch(target-delta) {
    case 0x54E920: return B(receiver+4);
    case 0x462CB0: return 0;
    case 0x447880: return 1;
    default: RaiseException(WorkerRefusal,0,0,nullptr); return 0;
    }
}
const WorkerOwner* Owner(const WorkerScene& s,U identity) {
    auto it=std::lower_bound(s.owners.begin(),s.owners.end(),identity,
        [](const WorkerOwner& o,U p) { return o.identity<p; });
    return it!=s.owners.end() && it->identity==identity ? &*it:nullptr;
}
const WorkerEdge* Edge(const WorkerScene& s,U identity) {
    auto it=std::lower_bound(s.edges.begin(),s.edges.end(),identity,
        [](const WorkerEdge& e,U p) { return e.identity<p; });
    return it!=s.edges.end() && it->identity==identity ? &*it:nullptr;
}
bool FrozenPlane(const WorkerOwner& o,const AgentView& a) {
    float sum=Add(Mul(o.plane[2],a.z),Mul(o.plane[0],a.x));
    const float factor=Div(-1.0f,o.plane[1]);
    sum=Add(sum,o.plane[3]);
    return a.extent>std::fabs(Sub(Mul(sum,factor),a.y));
}
bool MarkId(Work& w,U set,U id) {
    id=static_cast<uint16_t>(id);
    U& word=w.visited[set][id>>5]; const U bit=1u<<(id&31);
    if(word&bit) return false;
    if(w.touchedCount[set]==w.touched[set].size()) RaiseException(WorkerRefusal,0,0,nullptr);
    word|=bit; w.touched[set][w.touchedCount[set]++]=static_cast<uint16_t>(id); return true;
}
U Eligibility(const WorkerScene& s,size_t i,U delta) {
    const U type=s.topology.type[i],p=s.topology.owner[i];
    switch(type) {
    case 0x40: case 0x80: return LivePredicate(p+0x1C,0,delta);
    case 0x20: return LivePredicate(D(p+0x3C)+0xC,0,delta);
    case 0x10: case 0x100: return LivePredicate(p+0xC,0,delta);
    case 8: return B(p+0x30)!=0;
    case 0x200: return B(p+0x1C54)!=0;
    default: return 1;
    }
}
void BuildScene(WorkerScene& s,U model,U delta,U generation) {
    s.built=false; s.image_delta=delta; s.failure=SceneCaptureFailure;
    s.failureAddress=s.failureActual=0;
    ReleaseBuildVerification(s);
    if(!CaptureImpl(s.topology,model,generation,&s)) RaiseException(WorkerRefusal,0,0,nullptr);
    s.failure=SceneOk;
    const size_t nodes=s.topology.type.size();
    s.grid=D(model+0xA8); s.tree=D(model+0xC0); s.root=D(s.tree+0x4C)+0xC;
    s.owners.clear(); s.edges.clear();
    std::vector<U> pending;
    auto addOwner=[&](U p) {
        if(!p) return;
        auto it=std::lower_bound(s.owners.begin(),s.owners.end(),p,[](const WorkerOwner& o,U key) { return o.identity<key; });
        if(it!=s.owners.end() && it->identity==p) return;
        WorkerOwner o{}; o.identity=p;
        o.firstEdge=D(p+8); memcpy(o.plane,reinterpret_cast<void*>(p+0x30),sizeof(o.plane)); o.bounds=OwnerBounds(p);
        VerifyOnBuild(s,1,p+8,4); VerifyOnBuild(s,1,p+0x30,16);
        VerifyOnBuild(s,1,p+0x44,4); VerifyOnBuild(s,1,p+0x4C,8); VerifyOnBuild(s,1,p+0x58,4);
        s.owners.insert(it,o); pending.push_back(p);
    };
    for(size_t i=0;i<nodes;++i) {
        const U type=s.topology.type[i];
        if(type==0x40 || type==0x80) addOwner(s.topology.owner[i]);
    }
    while(!pending.empty()) {
        const U owner=pending.back(); pending.pop_back();
        const U first=D(owner+8); U p=first;
        do {
            auto it=std::lower_bound(s.edges.begin(),s.edges.end(),p,[](const WorkerEdge& e,U key) { return e.identity<key; });
            if(it!=s.edges.end() && it->identity==p) break;
            WorkerEdge e{}; e.identity=p; e.next=D(p+8);
            e.point[0]=F(p+0xC); e.point[1]=F(p+0x10);
            e.nextPoint[0]=F(e.next+0xC); e.nextPoint[1]=F(e.next+0x10);
            const U count=D(p+0x44),data=D(p+0x48);
            e.neighbors.reserve(count); e.neighborEdges.reserve(count);
            VerifyOnBuild(s,2,p+8,12); VerifyOnBuild(s,2,e.next+0xC,8);
            VerifyOnBuild(s,2,p+0x44,8); VerifyOnBuild(s,2,data,count*8);
            for(U j=0;j<count;++j) {
                const U neighbor=D(data+8*j);
                e.neighbors.push_back(neighbor); e.neighborEdges.push_back(D(data+8*j+4));
                addOwner(neighbor);
            }
            p=e.next; s.edges.insert(it,std::move(e));
        } while(p!=first);
    }
    Compact(s.owners); Compact(s.edges);
    if(!VerifyBuild(s,0,3)) RaiseException(WorkerRefusal,0,0,nullptr);
    ++s.build; s.built=true;
}
void PrepareSceneImpl(WorkerScene& s,U model,U delta,U generation) {
    if(!s.attempted || s.generation!=generation) {
        s.attempted=true; s.model=model; s.generation=generation;
        BuildScene(s,model,delta,generation);
    }
    if(!s.built || s.model!=model || s.image_delta!=delta) {
        s.failure=SceneIdentityFailure;
        RaiseException(WorkerRefusal,0,0,nullptr);
    }
    // Native construction topology is immutable for this generation. Keep only
    // constant-cost publication/header guards after activation's complete check.
    bool same=D(model+0xA8)==s.grid && D(model+0xC0)==s.tree && D(s.tree+0x4C)+0xC==s.root;
    if(same) for(U word: {0u,2u,4u,5u,9u}) if(D(s.grid+4*word)!=s.topology.header[word]) same=false;
    if(!same) {
        s.failure=SceneIdentityFailure; s.failureAddress=s.grid;
        RaiseException(WorkerRefusal,0,0,nullptr);
    }
}
bool WorkerSweepImpl(WorkerContext& c,const void* agent,U identity,void* scratch,const Aabb& b,U mode) {
    if(!c.scene || !c.scene->built || c.build!=c.scene->build) return false;
    const WorkerScene& s=*c.scene; const Scene& t=s.topology; Work& w=c.work; const U p=Address(agent);
    const AgentView a{identity,D(p+0x10),F(p+0x48),F(p+0x4C),F(p+0x50),F(p+0x54)};
    for(auto& out:w.output) out.clear();
    const U z0=Coordinate(b.minZ,t),x0=Coordinate(b.minX,t),z1=Coordinate(b.maxZ,t)+1,x1=Coordinate(b.maxX,t)+1;
    if(mode&0x15) Grid(t,x0,x1,z0,z1,[&](U n) {
            if(!Eligibility(s,n,s.image_delta)) return;
            const U type=t.type[n],owner=t.owner[n];
            if(type==0x40 && (mode&1)) {
                const WorkerOwner* o=Owner(s,owner); if(!o) RaiseException(WorkerRefusal,0,0,nullptr);
                if(MarkId(w,0,D(owner+0x2C)) && FrozenPlane(*o,a)) Append(w.output[0],owner);
            } else if(type==0x20 && (mode&4)) {
                if(MarkId(w,1,D(owner+0x34)) && !B(owner+0x48)) Append(w.output[1],owner);
            } else if(type==0x800 && (mode&0x10)) Append(w.output[2],t.payload[n]);
    });
    Clear(w,1); Clear(w,0);
    if((mode&2) && !t.treeIdentity.empty()) {
        Hits(t,0,b,w,false);
        for(U index:w.hits) for(U link=t.treeHead[index];link!=UINT32_MAX;link=t.linkNext[link]) {
            const U n=t.linkNode[link]; if(t.type[n]!=0x80) continue;
            const WorkerOwner* o=Owner(s,t.owner[n]); if(!o) return false;
            if(LivePredicate(o->identity+0x1C,0,s.image_delta)==1 && FrozenPlane(*o,a)) Append(w.output[0],o->identity);
        }
        w.hits.clear();
    }
    if((mode&8) && a.owner) {
        const WorkerOwner* root=Owner(s,a.owner); if(!root) return false;
        U read=0,end=0; MarkId(w,2,D(root->identity+0x2C)); w.queue[end++]=root->identity;
        while(read<end) {
            const WorkerOwner* o=Owner(s,w.queue[read++]); if(!o) return false;
            U edge=o->firstEdge; bool anyFalse=false;
            do {
                const WorkerEdge* e=Edge(s,edge); if(!e) return false;
                const WorkerOwner* neighbor=nullptr;
                for(U p:e->neighbors) {
                    const WorkerOwner* n=Owner(s,p); if(!n) return false;
                    if(LivePredicate(p+0x1C,0,s.image_delta)==1) { neighbor=n; break; }
                }
                if(neighbor && Overlap(b,neighbor->bounds) && MarkId(w,2,D(neighbor->identity+0x2C))) w.queue[end++]=neighbor->identity;
                if(!LivePredicate(edge,0x14,s.image_delta)) anyFalse=true;
                edge=e->next;
            } while(edge!=o->firstEdge);
            if(anyFalse) {
                if(LivePredicate(o->identity+0x1C,0,s.image_delta)==1 && FrozenPlane(*o,a)) Append(w.output[0],o->identity);
            }
        }
        Clear(w,2);
    }
    if(w.output[0].empty() && w.output[1].empty() && w.output[2].empty()) return true;
    U header[3],count[3],data[3],mode3[3]={};
    for(U i=0;i<3;++i) {
        const U size=static_cast<U>(w.output[i].size());
        header[i]=D(Address(scratch)+4*i); count[i]=D(header[i]+(i?8:12)); data[i]=D(header[i]+(i?12:16));
        const U capacity=D(header[i]+(i?4:8));
        if(!size) continue;
        if(data[i] && count[i]<=capacity && size<=capacity-count[i]) mode3[i]=1;
        else if(!count[i]) mode3[i]=2; // clone headers own no storage: publish worker-owned output
        else return false;
    }
    for(U i=0;i<3;++i) {
        const U size=static_cast<U>(w.output[i].size());
        if(mode3[i]==1) {
            memcpy(reinterpret_cast<void*>(data[i]+4*count[i]),w.output[i].data(),size*4);
            *reinterpret_cast<U*>(header[i]+(i?8:12))=count[i]+size;
        } else if(mode3[i]==2) {
            *reinterpret_cast<U*>(header[i]+(i?12:16))=Address(w.output[i].data());
            *reinterpret_cast<U*>(header[i]+(i?4:8))=static_cast<U>(w.output[i].capacity());
            *reinterpret_cast<U*>(header[i]+(i?8:12))=size;
        }
    }
    return true;
}
}
bool PrepareScene(WorkerScene& s,U model,U delta,U generation) {
    // Only the adapter's own refusal code is unsupported; real faults propagate.
    bool ok=false;
    __try { PrepareSceneImpl(s,model,delta,generation); ok=true; }
    __except(RefusalFilter(GetExceptionCode())) { s.built=false; }
    return ok;
}
bool PrepareWorker(WorkerContext& c,const WorkerScene& s) {
    c.fp=CaptureFp();
    if(!s.built) return false;
    if(c.scene==&s && c.build==s.build) return true;
    Work& w=c.work; w.Prepare(s.topology,s.owners.size());
    c.scene=&s; c.build=s.build; return true;
}
size_t HeapBytes(const WorkerScene& s) {
    const Scene& t=s.topology;
    size_t bytes=t.cells.capacity()*sizeof(CellRun)+
        (t.type.capacity()+t.payload.capacity()+t.owner.capacity()+t.linkNode.capacity()+t.linkNext.capacity()+
        t.treeIdentity.capacity()+t.treeHead.capacity())*sizeof(U)+t.treeBounds.capacity()*sizeof(Aabb);
    for(const auto& child:t.child) bytes+=child.capacity()*sizeof(U);
    bytes+=s.owners.capacity()*sizeof(WorkerOwner)+s.edges.capacity()*sizeof(WorkerEdge);
    for(const auto& edge:s.edges) bytes+=(edge.neighbors.capacity()+edge.neighborEdges.capacity())*sizeof(U);
    for(const auto& checks:s.verification) bytes+=checks.capacity()*sizeof(VerificationWord);
    return bytes;
}
size_t HeapBytes(const WorkerContext& c) {
    const Work& w=c.work;
    size_t bytes=(w.queue.capacity()+w.hits.capacity())*sizeof(U);
    for(const auto& touched:w.touched) bytes+=touched.capacity()*sizeof(uint16_t);
    for(const auto& output:w.output) bytes+=output.capacity()*sizeof(U);
    return bytes;
}
void SampleCounts(const WorkerScene& s,U out[3]) {
    out[0]=s.topology.nativeNodes; out[1]=static_cast<U>(s.owners.size());
    out[2]=static_cast<U>(s.topology.treeIdentity.size());
}
bool WorkerSweep(WorkerContext& c,const void* agent,U identity,void* scratch,const Aabb& b,U mode) {
    FpState saved{}; bool ok=false;
    if(!c.fp_managed) { saved=CaptureFp(); ApplyFp(c.fp); }
    __try {
        __try { ok=WorkerSweepImpl(c,agent,identity,scratch,b,mode); }
        __finally {
            if(!ok) {
                for(U i=0;i<3;++i) { Clear(c.work,i); c.work.output[i].clear(); }
                c.work.hits.clear();
            }
            if(!c.fp_managed) ApplyFp(saved);
        }
    }
    __except(RefusalFilter(GetExceptionCode())) { ok=false; }
    return ok;
}
bool Start(const Binding& b) {
    Stop(); binding=b; memset(words,0,sizeof(words));
    memset(targets,0,sizeof(targets)); memset(targetCount,0,sizeof(targetCount)); skippedDepth=0;
    if(!b.enabled) return true;
    words[0]=2; words[1]=1;
    if(!QueryPerformanceFrequency(&frequency)) return false;
    work=new(std::nothrow) Work;
    return work!=nullptr;
}
void Abandon() {
    if(pending || evaluating || skippedDepth) ++words[8];
    pending=evaluating=false; skippedDepth=0;
}
void Stop() { Abandon(); delete work; work=nullptr; scene=Scene{}; binding.enabled=false; }
void Sample(U* destination) {
    memcpy(destination,words,sizeof(words));
    // Two highest-frequency targets per kind. Stable first-observed ties.
    // Preferred-image VAs are raw loaded pointers minus the actual image delta.
    for(U kind=0;kind<PredicateKinds;++kind) for(U i=0;i<targetCount[kind];++i) {
        const U begin=16+4*kind,end=begin+4;
        U slot=begin;
        while(slot<end && destination[slot] && destination[slot+1]>=targets[kind][i].calls) slot+=2;
        if(slot==end) continue;
        if(slot==begin) { destination[begin+2]=destination[begin]; destination[begin+3]=destination[begin+1]; }
        destination[slot]=targets[kind][i].target-binding.image_delta;
        destination[slot+1]=targets[kind][i].calls;
    }
}
void Activate(U model) {
    if(!binding.enabled || !work || scene.model==model) return;
    LARGE_INTEGER started,end; QueryPerformanceCounter(&started);
    __try {
        if(Capture(scene,model,binding.generation)) work->Prepare(scene);
        else ++words[8];
    } __except(EXCEPTION_EXECUTE_HANDLER) { ++words[8]; scene.model=0; }
    QueryPerformanceCounter(&end);
    words[15]+=static_cast<U>((end.QuadPart-started.QuadPart)*1000000/frequency.QuadPart);
}
void ShadowBefore(Agent* a,Scratch* r,const Aabb* b,U mode) {
    if(!binding.enabled) return;
    const U priorUs=words[15];
    LARGE_INTEGER started; QueryPerformanceCounter(&started);
    __try { BeforeImpl(a,r,b,mode); }
    __except(EXCEPTION_EXECUTE_HANDLER) { ++words[8]; pending=false; }
    LARGE_INTEGER end; QueryPerformanceCounter(&end);
    words[15]=priorUs+static_cast<U>((end.QuadPart-started.QuadPart)*1000000/frequency.QuadPart);
}
void ShadowAfter() {
    if(!binding.enabled) return;
    const U priorUs=words[15];
    LARGE_INTEGER started; QueryPerformanceCounter(&started);
    __try { AfterImpl(); }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        ++words[8]; pending=evaluating=false; skippedDepth=0;
        if(work) { for(U i=0;i<3;++i) Clear(*work,i); work->hits.clear(); }
    }
    LARGE_INTEGER end; QueryPerformanceCounter(&end);
    words[15]=priorUs+static_cast<U>((end.QuadPart-started.QuadPart)*1000000/frequency.QuadPart);
}
}

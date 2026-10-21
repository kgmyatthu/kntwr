#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <limits>
#include <memory>
#include "native_sweep.h"
using namespace kntwr_sweep;
namespace {
U Addr(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
U predicateCalls;
U predicateKinds[8];
uint8_t __fastcall Active(void* self,void*) { ++predicateCalls; ++predicateKinds[0]; return static_cast<uint8_t>(static_cast<U*>(self)[1]); }
uint8_t __fastcall AlternateActive(void* self,void*) { ++predicateCalls; ++predicateKinds[1]; return static_cast<uint8_t>(static_cast<U*>(self)[1]); }
uint8_t __fastcall Blocking(void* self,void*) { ++predicateCalls; ++predicateKinds[2]; return static_cast<uint8_t>(static_cast<U*>(self)[1]); }
uint8_t __fastcall AlternateBlocking(void* self,void*) { ++predicateCalls; ++predicateKinds[3]; return static_cast<uint8_t>(static_cast<U*>(self)[1]); }
uint8_t __fastcall PayloadActive(void* self,void*) { ++predicateCalls; ++predicateKinds[4]; return static_cast<uint8_t>(static_cast<U*>(self)[1]); }
uint8_t __fastcall AlternatePayloadActive(void* self,void*) { ++predicateCalls; ++predicateKinds[5]; return static_cast<uint8_t>(static_cast<U*>(self)[1]); }
uint8_t __fastcall OtherActive(void* self,void*) { ++predicateCalls; ++predicateKinds[6]; return static_cast<uint8_t>(static_cast<U*>(self)[1]); }
uint8_t __fastcall AlternateOtherActive(void* self,void*) { ++predicateCalls; ++predicateKinds[7]; return static_cast<uint8_t>(static_cast<U*>(self)[1]); }
struct Owner {
    U words[24] = {};
    U address() const { return Addr(this); }
    void integer(U offset,U value) { words[offset/4]=value; }
    void real(U offset,float value) { memcpy(reinterpret_cast<char*>(words)+offset,&value,4); }
};
struct Node { U type,id,payload,owner,previous,next,head; };
static_assert(sizeof(Node)==0x1C && offsetof(Node,next)==0x14 && offsetof(Node,owner)==0xC,"native grid/content node");
struct TreeNode { U words[12] = {}; };
struct Edge { U words[20] = {}; U records[8] = {}; };
struct Fixture {
    U activeVtable[1],alternateActiveVtable[1],edgeVtable[6],alternateEdgeVtable[6];
    U payloadVtable[2][1],otherVtable[2][1];
    Owner gridOwners[5],treeOwners[5],graphOwners[7],type20[2];
    U payload20[2][5] = {};
    Node gridNodes[11] = {}, treeNodes[5] = {};
    TreeNode trees[5];
    Edge edges[9];
    U grid[10] = {},heads[4] = {},tree[20] = {},model[49] = {};
    Fixture() {
        activeVtable[0]=Addr(reinterpret_cast<void*>(&Active));
        for(U& entry:edgeVtable) entry=Addr(reinterpret_cast<void*>(&Blocking));
        alternateActiveVtable[0]=Addr(reinterpret_cast<void*>(&AlternateActive));
        for(U& entry:alternateEdgeVtable) entry=Addr(reinterpret_cast<void*>(&AlternateBlocking));
        payloadVtable[0][0]=Addr(reinterpret_cast<void*>(&PayloadActive));
        payloadVtable[1][0]=Addr(reinterpret_cast<void*>(&AlternatePayloadActive));
        otherVtable[0][0]=Addr(reinterpret_cast<void*>(&OtherActive));
        otherVtable[1][0]=Addr(reinterpret_cast<void*>(&AlternateOtherActive));
        U id=1;
        for(auto& o:gridOwners) Init(o,id++);
        for(auto& o:treeOwners) Init(o,id++);
        for(auto& o:graphOwners) Init(o,id++);
        // Grid rejection marks ID before plane acceptance; the next owner collides by low16.
        gridOwners[0].real(0x3C,1.0f);
        gridOwners[1].integer(0x2C,0x10001);
        gridOwners[2].integer(0x20,2); // grid nonzero normalizes to true
        gridOwners[4].integer(0x1C,Addr(alternateActiveVtable));
        for(U i=0;i<2;++i) {
            type20[i].integer(0x34,77+i); type20[i].integer(0x3C,Addr(payload20[i]));
            payload20[i][3]=Addr(payloadVtable[i]); payload20[i][4]=1;
            type20[i].integer(0xC,Addr(otherVtable[i])); type20[i].integer(0x10,1);
        }
        type20[1].integer(0x48,1);
        gridNodes[0]={0x40,0,0,gridOwners[0].address(),0,Addr(&gridNodes[1]),0};
        gridNodes[1]={0x40,0,0,gridOwners[1].address(),0,Addr(&gridNodes[2]),0};
        gridNodes[2]={0x40,0,0,gridOwners[2].address(),0,Addr(&gridNodes[3]),0};
        gridNodes[3]={0x800,0,0x12345678,0,0,Addr(&gridNodes[4]),0};
        gridNodes[4]={0x20,0,0,type20[0].address(),0,Addr(&gridNodes[5]),0};
        gridNodes[5]={0x20,0,0,type20[1].address(),0,0,0};
        gridNodes[6]={0x800,0,0x12345678,0,0,Addr(&gridNodes[7]),0};
        gridNodes[7]={0x40,0,0,gridOwners[3].address(),0,Addr(&gridNodes[8]),0};
        gridNodes[8]={0x10,0,0,type20[0].address(),0,Addr(&gridNodes[9]),0};
        gridNodes[9]={0x40,0,0,gridOwners[4].address(),0,Addr(&gridNodes[10]),0};
        gridNodes[10]={0x100,0,0,type20[1].address(),0,0,0};
        heads[0]=Addr(gridNodes); heads[1]=Addr(gridNodes); heads[2]=Addr(&gridNodes[6]);
        grid[0]=Addr(heads); grid[2]=1; grid[5]=1; float scale=1; memcpy(&grid[9],&scale,4);
        model[0xA8/4]=Addr(grid); model[0xC0/4]=Addr(tree);
        tree[0x4C/4]=Addr(&trees[0])-0xC;
        for(U i=0;i<5;++i) {
            treeNodes[i]={0x80,0,0,treeOwners[i].address(),0,0,0};
            trees[i].words[0x1C/4]=Addr(&treeNodes[i]);
            Bounds(trees[i],-0.5f,-0.5f,1.5f,1.5f);
        }
        for(U i=0;i<4;++i) trees[0].words[8+i]=Addr(&trees[i+1]);
        treeOwners[3].integer(0x20,2); // tree requires exactly one
        Bounds(trees[4],2,2,3,3); // disjoint in partial traversal
        for(U i=0;i<9;++i) {
            edges[i].words[0]=Addr(edgeVtable); edges[i].words[2]=Addr(&edges[i]);
            edges[i].words[0x48/4]=Addr(edges[i].records);
        }
        edges[1].words[0]=Addr(alternateEdgeVtable);
        // Seed outside query still enters. FIFO root -> 1,2 -> 3 -> 4.
        graphOwners[0].real(0x44,100); graphOwners[0].real(0x50,101);
        for(U i=0;i<7;++i) graphOwners[i].integer(8,Addr(&edges[i+2]));
        graphOwners[0].integer(8,Addr(&edges[0]));
        edges[0].words[2]=Addr(&edges[1]); edges[1].words[2]=Addr(&edges[0]);
        graphOwners[6].integer(0x20,0);
        Adj(0,{graphOwners[6].address(),graphOwners[1].address()});
        Adj(1,{graphOwners[2].address()});
        Adj(3,{graphOwners[3].address()});
        Adj(4,{graphOwners[4].address()}); edges[4].words[1]=1; // traverses, no output
        Adj(5,{graphOwners[1].address(),graphOwners[5].address()}); // first active visited: no second choice
    }
    void Init(Owner& o,U id) {
        o.integer(0x1C,Addr(activeVtable)); o.integer(0x20,1); o.integer(0x2C,id);
        o.real(0x34,1); o.real(0x44,-1); o.real(0x4C,-1); o.real(0x50,1); o.real(0x58,1);
    }
    void Adj(U edge,std::initializer_list<U> owners) {
        edges[edge].words[0x44/4]=static_cast<U>(owners.size());
        U index=0; for(U owner:owners) { edges[edge].records[2*index]=owner; ++index; }
    }
    static void Bounds(TreeNode& t,float a,float b,float c,float d) {
        memcpy(&t.words[1],&a,4); memcpy(&t.words[3],&b,4);
        memcpy(&t.words[4],&c,4); memcpy(&t.words[6],&d,4);
    }
};
U failures;
void Check(bool value,const char* message) { if(!value) { ++failures; printf("FAIL %s\n",message); } }
void Prefix(Work& w) { for(U i=0;i<3;++i) { w.output[i].clear(); w.output[i].push_back(0xA000+i); } }
void CheckClean(const Work& w) {
    for(U set=0;set<3;++set) {
        Check(w.touchedCount[set]==0,"touched list reset");
        for(U word:w.visited[set]) if(word) { Check(false,"bitmap reset"); break; }
    }
    Check(w.hits.empty(),"tree hit scratch reset");
}
void CheckSceneBudget() {
    // 1M native cells, 65 occupied cells, distinct native membership identities
    // with equal contents. Compression must retain every native occurrence.
    constexpr U side=1024,repeated=64;
    std::vector<U> heads(side*side);
    std::vector<Node> nodes((repeated+1)*6);
    Owner owners[2],capsules[2]; Edge edges[2]; TreeNode trees[5];
    Node treeNodes[5]{};
    U active[1]={0x54E920},edgeVtable[6]={},payload[2][5]={};
    U grid[10]{},tree[20]{},model[49]{};
    for(U& target:edgeVtable) target=0x462CB0;
    for(U i=0;i<2;++i) {
        owners[i].integer(0x1C,Addr(active)); owners[i].integer(0x20,1);
        owners[i].integer(0x2C,1+i*65536); owners[i].integer(8,Addr(&edges[i]));
        owners[i].real(0x34,1); owners[i].real(0x50,1024); owners[i].real(0x58,1024);
        edges[i].words[0]=Addr(edgeVtable); edges[i].words[2]=Addr(&edges[i]);
        edges[i].words[0x48/4]=Addr(edges[i].records);
        capsules[i].integer(0x34,7+i*65536); capsules[i].integer(0x3C,Addr(payload[i]));
        payload[i][3]=Addr(active); payload[i][4]=1;
    }
    edges[0].words[0x44/4]=1; edges[0].records[0]=owners[1].address();
    edges[0].records[1]=Addr(&edges[1]);
    for(U c=0;c<=repeated;++c) {
        Node* chain=nodes.data()+6*c;
        chain[0]={0x40,0,0,owners[0].address(),0,Addr(chain+1),0};
        chain[1]={0x40,0,0,owners[1].address(),0,Addr(chain+2),0};
        chain[2]={0x20,0,0,capsules[0].address(),0,Addr(chain+3),0};
        chain[3]={0x20,0,0,capsules[1].address(),0,Addr(chain+4),0};
        chain[4]={0x800,0,0x12345678,0,0,Addr(chain+5),0};
        chain[5]={0x800,0,0x12345678,0,0,0,0};
        heads[c<repeated ? 512+c:side*side-1]=Addr(chain);
    }
    for(U i=0;i<5;++i) {
        treeNodes[i]={0x80,0,0,owners[0].address(),0,0,0};
        trees[i].words[0x1C/4]=Addr(treeNodes+i); Fixture::Bounds(trees[i],0,0,1024,1024);
    }
    for(U i=0;i<4;++i) trees[0].words[8+i]=Addr(trees+i+1);
    grid[0]=Addr(heads.data()); grid[2]=10; grid[5]=side-1;
    const float scale=1; memcpy(grid+9,&scale,4);
    tree[0x4C/4]=Addr(trees)-0xC; model[0xA8/4]=Addr(grid); model[0xC0/4]=Addr(tree);
    WorkerScene scene;
    Check(PrepareScene(scene,Addr(model),0,100),"prepare repeated-membership sparse worker scene");
    Check(scene.topology.cells.size()==2 && scene.topology.cells.capacity()==2,"only two occupied cell runs retained");
    Check(scene.topology.type.size()==6 && scene.topology.linkNode.size()==7,"record and chain interning keeps duplicate wall links");
    Check(scene.topology.type.capacity()==6 && scene.topology.linkNode.capacity()==7,"compact topology has exact retained capacities");
    U counts[3]; SampleCounts(scene,counts);
    Check(counts[0]==395 && counts[1]==2 && counts[2]==5,"counts retain native occurrences rather than interned records");
    // Every original cell and node remains checked, including empty cells and
    // an interned-away membership's native successor.
    heads[0]=heads[512];
    Check(!VerifyBuild(scene,0,3),"verification covers empty native grid cells");
    heads[0]=0;
    const U next=nodes[6].next; nodes[6].next=0;
    Check(!VerifyBuild(scene,0,3),"verification covers every original repeated membership");
    nodes[6].next=next;
    owners[0].real(0x30,1);
    Check(!VerifyBuild(scene,0,3),"verification still covers owner geometry");
    owners[0].real(0x30,0);
    Check(VerifyBuild(scene,0,3),"complete static scene verification restored");
    ReleaseBuildVerification(scene);
    for(const auto& tape:scene.verification) Check(tape.capacity()==0,"activation verification storage released");
    Check(HeapBytes(scene)<4096,"large sparse repeated scene retains less than four KiB of heap");
    auto work=std::make_unique<WorkerContext>();
    Check(PrepareWorker(*work,scene),"prepare exact distinct-domain scratch");
    Check(work->work.output[0].capacity()==9 && work->work.output[1].capacity()==2 && work->work.output[2].capacity()==130,
        "per-type output capacities preserve tree and wall multiplicity");
    Check(work->work.touched[0].size()==2 && work->work.touched[1].size()==2 && work->work.queue.size()==2,
        "low-u16 scratch bounded by distinct owner domains, not memberships or current aliases");
    const size_t bytes=HeapBytes(*work);
    U agent[24]{},headers[3][5]{},scratch[3]={Addr(headers[0]),Addr(headers[1]),Addr(headers[2])};
    agent[0x10/4]=owners[0].address(); memcpy(agent+0x54/4,&scale,4);
    const Aabb bounds{0,0,1023,1023};
    Check(WorkerSweep(*work,agent,Addr(agent),scratch,bounds,31),"worker sweeps all sparse cells and owner closure");
    Check(headers[0][3]==7 && headers[1][2]==1 && headers[2][2]==130,"low-u16 aliases dedup only grid and graph, never tree or walls");
    owners[1].integer(0x2C,2); capsules[1].integer(0x34,8);
    memset(headers,0,sizeof(headers));
    Check(WorkerSweep(*work,agent,Addr(agent),scratch,bounds,31),"live ID aliases may split without a rebuild or growth");
    Check(headers[0][3]==9 && headers[1][2]==2 && headers[2][2]==130,"entire proven output bounds are usable");
    Check(HeapBytes(*work)==bytes,"full-bound sweep cannot grow worker storage");
    CheckClean(work->work);
    memset(headers,0,sizeof(headers)); headers[0][2]=1; headers[0][3]=1;
    U before[3][5]; memcpy(before,headers,sizeof(headers));
    Check(!WorkerSweep(*work,agent,Addr(agent),scratch,bounds,31),"insufficient nonempty caller buffers refuse safely");
    Check(!memcmp(before,headers,sizeof(headers)),"refusal publishes no partial scratch header");
    CheckClean(work->work);
    Work resize;
    resize.Prepare(scene.topology,65536); resize.Prepare(scene.topology,2);
    Check(resize.queue.capacity()==2 && resize.output[0].capacity()==9,"new preparation sheds prior high-water capacities");
}
}
int main() {
    Fixture f; Scene s;
    Check(Capture(s,Addr(f.model),71),"capture real native layouts");
    Check(s.generation==71 && s.model==Addr(f.model) && s.cellCount==4 && s.cells.size()==2,"generation and compact cell geometry");
    Check(s.type[0]==0x40 && s.owner[0]==f.gridOwners[0].address(),"captured owner identity retained without duplicate bounds");
    // Destroy the live indexing links after import: Run must traverse the owned columns.
    const U savedHead=f.heads[0],savedNext=f.gridNodes[0].next;
    f.heads[0]=0; f.gridNodes[0].next=0;
    Fixture::Bounds(f.trees[0],100,100,101,101);
    auto w=std::make_unique<Work>(); w->Prepare(s,65536,1);
    AgentView a={0x111,f.graphOwners[0].address(),0,0,0,1};
    Aabb box={0,0,1,1};
    for(U mode=0;mode<32;++mode) {
        Prefix(*w); predicateCalls=0; Run(s,a,box,mode,*w);
        std::vector<U> expected[3]={{0xA000},{0xA001},{0xA002}};
        if(mode&1) for(U i:{2u,3u,4u}) expected[0].push_back(f.gridOwners[i].address());
        if(mode&4) expected[1].push_back(f.type20[0].address());
        if(mode&0x10) for(U i=0;i<3;++i) expected[2].push_back(0x12345678);
        if(mode&2) for(U i=0;i<3;++i) expected[0].push_back(f.treeOwners[i].address());
        if(mode&8) for(U i:{0u,1u,3u,4u}) expected[0].push_back(f.graphOwners[i].address());
        for(U list=0;list<3;++list) Check(w->output[list]==expected[list],"all modes ordered outputs and nonempty prefix");
        if(mode&0x15) Check(predicateCalls>=14,"eligibility executes even for mode-ignored grid types");
        CheckClean(*w);
    }
    f.heads[0]=savedHead; f.gridNodes[0].next=savedNext;
    Fixture::Bounds(f.trees[0],-0.5f,-0.5f,1.5f,1.5f);
    // Full containment gathers children without retesting even deliberately inconsistent child bounds.
    Prefix(*w); Run(s,a,{-1,-1,2,2},2,*w);
    Check(w->output[0]==std::vector<U>({0xA000,f.treeOwners[0].address(),f.treeOwners[1].address(),f.treeOwners[2].address(),f.treeOwners[4].address()}),"tree full containment preorder");
    float nan=std::numeric_limits<float>::quiet_NaN();
    Prefix(*w); Run(s,a,{nan,nan,nan,nan},2,*w);
    Check(w->output[0].size()==5,"unordered AABB rejects do not reject and containment falls back");
    Prefix(*w); Run(s,a,{3,3,4,4},2,*w); Check(w->output[0].size()==1,"disjoint tree root rejected");
    Prefix(*w); Run(s,a,{1.5f,1.5f,1.5f,1.5f},2,*w); Check(w->output[0].size()==4,"touching bounds overlap");
    // NaN plane is rejected while NaN adjacency bounds pass JA tests.
    f.graphOwners[1].real(0x44,nan); f.graphOwners[1].real(0x3C,nan);
    Prefix(*w); Run(s,a,box,8,*w);
    Check(w->output[0]==std::vector<U>({0xA000,f.graphOwners[0].address(),f.graphOwners[3].address(),f.graphOwners[4].address()}),"graph unordered bounds and strict unordered plane");
    f.graphOwners[1].real(0x3C,0);
    a.extent=0; Prefix(*w); Run(s,a,box,3,*w); Check(w->output[0].size()==1,"strict plane equality rejected");
    a.extent=1;
    auto other=std::make_unique<Work>(); other->Prepare(s,65536,1); Prefix(*other); Prefix(*w);
    Run(s,a,box,31,*other); Run(s,a,box,31,*w);
    for(U i=0;i<3;++i) Check(w->output[i]==other->output[i],"private scratch independence");
    CheckClean(*w); CheckClean(*other);
    // Nonzero relocation delta ensures telemetry normalizes the loaded target,
    // never the vtable/slot/receiver address; the indirect call must remain raw.
    constexpr U histogramDelta=0x170000;
    memset(predicateKinds,0,sizeof(predicateKinds));
    Check(Start({histogramDelta,72,true}),"shadow activation");
    U agent[24]={},context[3]={0,0,Addr(f.model)},headers[3][5]={},outputs[3][16]={},scratch[3];
    agent[0x28/4]=Addr(context); float extent=1; memcpy(&agent[0x54/4],&extent,4);
    for(U i=0;i<3;++i) {
        scratch[i]=Addr(headers[i]); headers[i][i?2:3]=1; headers[i][i?3:4]=Addr(outputs[i]); outputs[i][0]=0xB000+i;
    }
    ShadowBefore(reinterpret_cast<Agent*>(agent),reinterpret_cast<Scratch*>(scratch),&box,0x10);
    for(U i=1;i<=3;++i) outputs[2][i]=0x12345678; headers[2][2]=4;
    ShadowAfter(); U status[32]; Sample(status);
    Check(status[3]==1 && status[4]==1 && !status[5] && !status[6] && !status[7] && !status[8],"shadow compares only appended ranges");
    ShadowBefore(reinterpret_cast<Agent*>(agent),reinterpret_cast<Scratch*>(scratch),&box,0x10);
    outputs[2][4]=0xDEADBEEF; outputs[2][5]=outputs[2][6]=0x12345678; headers[2][2]=7;
    ShadowAfter(); Sample(status);
    Check(status[7]==1 && status[9]==Addr(agent) && status[10]==2 && status[11]==2 && status[12]==0 && status[13]==0xDEADBEEF && status[14]==0x12345678,"first mismatch identity order and detail");
    Check(status[0]==2 && status[2]==0,"version two and no graph coverage for grid-only calls");
    agent[0x10/4]=f.graphOwners[0].address();
    ShadowBefore(reinterpret_cast<Agent*>(agent),reinterpret_cast<Scratch*>(scratch),&box,8);
    U out=1;
    for(U i:{0u,1u,3u,4u}) outputs[0][out++]=f.graphOwners[i].address();
    headers[0][3]=out;
    ShadowAfter(); Sample(status);
    Check(status[2]==1 && status[4]==3 && !status[5] && !status[8],"graph phase counted only after successful comparison");
    agent[0x10/4]=0;
    ShadowBefore(reinterpret_cast<Agent*>(agent),reinterpret_cast<Scratch*>(scratch),&box,8);
    ShadowAfter();
    agent[0x10/4]=f.graphOwners[0].address();
    ShadowBefore(reinterpret_cast<Agent*>(agent),reinterpret_cast<Scratch*>(scratch),&box,0);
    ShadowAfter(); Sample(status);
    Check(status[2]==1 && status[4]==5,"graph coverage requires both mode8 and nonnull current owner");
    const U expectedTargets[8]={
        Addr(reinterpret_cast<void*>(&Active)),Addr(reinterpret_cast<void*>(&AlternateActive)),
        Addr(reinterpret_cast<void*>(&Blocking)),Addr(reinterpret_cast<void*>(&AlternateBlocking)),
        Addr(reinterpret_cast<void*>(&PayloadActive)),Addr(reinterpret_cast<void*>(&AlternatePayloadActive)),
        Addr(reinterpret_cast<void*>(&OtherActive)),Addr(reinterpret_cast<void*>(&AlternateOtherActive))};
    for(U i=0;i<8;++i) {
        Check(status[16+2*i]==expectedTargets[i]-histogramDelta,"kind-specific histogram records the normalized code target loaded from the slot");
        Check(status[17+2*i]==predicateKinds[i] && predicateKinds[i]!=0,"kind-specific histogram count equals executed synthetic predicate calls");
    }
    Stop(); Start({0,73,false}); Sample(status);
    for(U value:status) Check(value==0,"disabled shadow telemetry zero");
    CheckSceneBudget();
    Stop(); printf("native sweep synthetic fixtures: %u failures\n",failures);
    return failures ? 1:0;
}

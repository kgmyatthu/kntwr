#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <xmmintrin.h>
#include <emmintrin.h>
#include <cstring>
#include <cfenv>
#include <mutex>
#include <algorithm>
#include <new>
#include "native_env.h"
#pragma fenv_access(on)
namespace ntw2_env {
namespace {
using U = uint32_t; using B = uint8_t;
static_assert(sizeof(void*) == 4, "environment adapter is x86");
Binding binding{}; U words[WordCount]{}, owner_thread, depth; bool pending;
Agent* original; AgentView saved{}; Scene scene; WorkerScratch scratch; Result predicted;
LARGE_INTEGER frequency{}; LONGLONG capture_ticks;
fenv_t input_fp;
struct TargetCount { U target, count; }; std::vector<TargetCount> targets[3];
std::mutex target_mutex;
U Address(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
void* Pointer(U p) { return reinterpret_cast<void*>(p); }
template<class T> T Load(U p, U off) { T v; std::memcpy(&v, static_cast<const B*>(Pointer(p)) + off, sizeof(v)); return v; }
U Target(U p, U slot) { return Load<U>(Load<U>(p, 0), slot); }
float Add(float a,float b) { return _mm_cvtss_f32(_mm_add_ss(_mm_set_ss(a),_mm_set_ss(b))); }
float Sub(float a,float b) { return _mm_cvtss_f32(_mm_sub_ss(_mm_set_ss(a),_mm_set_ss(b))); }
float Mul(float a,float b) { return _mm_cvtss_f32(_mm_mul_ss(_mm_set_ss(a),_mm_set_ss(b))); }
float Div(float a,float b) { return _mm_cvtss_f32(_mm_div_ss(_mm_set_ss(a),_mm_set_ss(b))); }
float Sqrt(float a) { return _mm_cvtss_f32(_mm_sqrt_ss(_mm_set_ss(a))); }
float Max(float a,float b) { return _mm_cvtss_f32(_mm_max_ss(_mm_set_ss(a),_mm_set_ss(b))); }
float Neg(float a) { U u; std::memcpy(&u,&a,4); u ^= 0x80000000u; std::memcpy(&a,&u,4); return a; }
float Abs(float a) { __asm { fld a
 fabs
 fstp a } return a; }
void Record(U kind, U target) {
 const std::lock_guard<std::mutex> lock(target_mutex);
 const U va = target >= binding.image_delta + 0x400000u && target < binding.image_delta + 0x1900000u ? target - binding.image_delta : target;
 for (auto& t : targets[kind]) if (t.target == va) { ++t.count; return; }
 targets[kind].push_back({va,1});
}
U Policy(Scene& s, U receiver, U target, bool pointer = false, U kind = ~0u) {
 if (s.capture_policies) {
  if (owner_thread != GetCurrentThreadId()) RaiseException(0xE0425301,0,0,nullptr);
  if (kind != ~0u) Record(kind,target);
  const U v = pointer ? reinterpret_cast<U(__thiscall*)(void*)>(target)(Pointer(receiver)) : reinterpret_cast<B(__thiscall*)(void*)>(target)(Pointer(receiver));
  PolicyRead read{receiver,target,v,{}};
  if(pointer && v) for(U i=0;i<3;++i) read.position[i]=Load<U>(v,0x48+i*4);
  s.policies.push_back(read); ++s.policy_cursor; ++words[PolicyCalls]; return v;
 }
 if (s.policy_cursor >= s.policies.size()) { ++words[PolicyReplayFaults]; RaiseException(0xE0425302,0,0,nullptr); }
 const auto& p = s.policies[s.policy_cursor++];
 if (p.receiver != receiver || p.target != target) { ++words[PolicyReplayFaults]; RaiseException(0xE0425302,0,0,nullptr); }
 return p.value;
}
struct Point { float x,z; };
Point ReadPoint(U edge) { return {Load<float>(edge,0xC),Load<float>(edge,0x10)}; }
bool SidePoints(Point a,Point b,Point p) {
 const bool swap = a.x > b.x || (a.x == b.x && a.z > b.z);
 if (swap) { const Point tmp=a; a=b; b=tmp; }
 const float px=Sub(p.x,a.x), pz=Sub(p.z,a.z), dx=Sub(b.x,a.x), dz=Sub(b.z,a.z);
 const float cross=Sub(Mul(dx,pz),Mul(dz,px));
 return swap ? 0.0f >= cross : cross > 0.0f;
}
bool Side(U edge,Point p) { return SidePoints(ReadPoint(edge),ReadPoint(Load<U>(edge,8)),p); }
bool Inside(U owner, Point p) {
 const U first=Load<U>(owner,8); U edge=first;
 do { if (Side(edge,p)) return false; edge=Load<U>(edge,8); } while(edge!=first);
 return true;
}
float Height(U owner, const AgentView& a) { return Neg(Div(Add(Add(Mul(Load<float>(owner,0x38),a.z),Mul(a.x,Load<float>(owner,0x30))),Load<float>(owner,0x3C)),Load<float>(owner,0x34))); }
float Speed(const AgentView& a) { return Sqrt(Add(Mul(a.dz,a.dz),Mul(a.dx,a.dx))); }
void EventAt(Result& r, const AgentView& a, EventKind kind, U receiver, U target) {
 Event& e=r.events[r.event_count++]; e={}; e.kind=kind; e.receiver=receiver; e.target=target; e.owner=a.owner; e.b4=a.b4; e.b5=a.b5;
}
U Index(float coord, float inverse, U bias, U maximum) {
 const float v=Mul(coord,inverse), half=-0.5f; int i;
 __asm { fld v
 fadd st(0),st(0)
 fadd half
 fistp i }
 const U index=static_cast<U>(i>>1)+bias; return index <= maximum ? index : maximum;
}
float UnsignedFloat(U value) {
 const __m128d n=_mm_cvtepi32_pd(_mm_cvtsi32_si128(static_cast<int>(value)));
 return _mm_cvtss_f32(_mm_cvtpd_ps(_mm_add_sd(n,_mm_set_sd(value>>31 ? 4294967296.0 : 0.0))));
}
void Enqueue(WorkerScratch& s,U owner) {
 const uint16_t id=Load<uint16_t>(owner,0x2C); const U mask=1u<<(id&31);
 if(s.visited[id>>5]&mask) return;
 if(s.count==s.fifo.size() || s.touched_count==s.touched.size())
  RaiseException(ntw2_sweep::WorkerRefusal,0,0,nullptr);
 s.visited[id>>5]|=mask; s.touched[s.touched_count++]=id; s.fifo[s.count++]=owner;
}
}
void WorkerScratch::Clear() { for(U i=0;i<touched_count;++i) visited[touched[i]>>5]=0; count=read=touched_count=0; }
void WorkerScratch::Prepare(size_t ownerCapacity) {
 Clear();
 ownerCapacity=(std::min)(ownerCapacity,size_t(65536));
 // Fresh exact storage sheds previous-generation peaks as well as prefaulting.
 std::vector<U>(ownerCapacity).swap(fifo); std::vector<uint16_t>(ownerCapacity).swap(touched);
 std::memset(visited,0,sizeof(visited));
}
float SampleTerrain(U terrain,float x,float z,bool secondary) {
 const U maximum=Load<U>(terrain,0x14), bias=Load<U>(terrain,0x10), shift=Load<U>(terrain,8)&31;
 const float inverse=Load<float>(terrain,0x24), scale=Load<float>(terrain,0x20), offset=Load<float>(terrain,0x1C);
 const U iz=Index(z,inverse,bias,maximum), ix=Index(x,inverse,bias,maximum);
 float fx=Mul(Sub(x,Sub(Mul(UnsignedFloat(ix),scale),offset)),inverse);
 float fz=Mul(Sub(z,Sub(Mul(UnsignedFloat(iz),scale),offset)),inverse);
 if(0.0f>fx) fx=0; else if(fx>1.0f) fx=1;
 if(0.0f>fz) fz=0; else if(fz>1.0f) fz=1;
 const U nx=ix+1<=maximum?ix+1:maximum, nz=iz+1<=maximum?iz+1:maximum, data=Load<U>(terrain,0), channel=secondary?4:0;
 const float rx=Sub(1.0f,fx), rz=Sub(1.0f,fz);
 const float a=Mul(secondary?Mul(fz,rx):Mul(rx,fz),Load<float>(data,((nz<<shift)+ix)*8+channel));
 const float b=Mul(Mul(fx,fz),Load<float>(data,((nz<<shift)+nx)*8+channel));
 const float c=Mul(Mul(rx,rz),Load<float>(data,((iz<<shift)+ix)*8+channel));
 const float d=Mul(Mul(fx,rz),Load<float>(data,((iz<<shift)+nx)*8+channel));
 return Add(Add(Add(a,b),c),d);
}
namespace {
// Shadow tape policy: owner-thread only, identical call order to the recorded path.
struct ShadowPolicy {
 Scene& s;
 U count() const { return static_cast<U>(s.candidates.size()); }
 U candidate(U i) const { return s.candidates[i]; }
 U First(U o) const { return Load<U>(o,8); }
 U Next(U e) const { return Load<U>(e,8); }
 Point EdgePoint(U e) const { return ReadPoint(e); }
 U Neighbors(U e) const { return Load<U>(e,0x44); }
 U NeighborRecords(U e) const { return Load<U>(e,0x48); }
 U Neighbor(U records,U i) const { return Load<U>(records,i*8); }
 U NeighborEdge(U records,U i) const { return Load<U>(records,i*8+4); }
 bool Outside(U e,Point p) const { return Side(e,p); }
 bool Contains(U o,Point p) const { return Inside(o,p); }
 float PlaneHeight(U o,const AgentView& a) const { return Height(o,a); }
 U Eligible(U o) { return Policy(s,o,Target(o,0x24),false,0); }
 U Active(U o) { return Policy(s,o+0x1C,Target(o+0x1C,0),false,1); }
 U Identity(const AgentView& a,U pos[3]) {
  const U identity=Policy(s,a.entity,a.identity_target,true);
  if(identity) for(U i=0;i<3;++i) pos[i]=s.policies[s.policy_cursor-1].position[i];
  return identity;
 }
 void Notified(const AgentView& a) { if(s.capture_policies) Record(2,a.notification_target); }
 U Capable(const AgentView& a) { return Policy(s,a.entity,a.policy_target); }
};
template<class Pol> void RunCore(AgentView& a,Pol& pol,WorkerScratch& work,Result& r) {
 r={}; a.candidate_index=~0u; const Point p{a.x,a.z};
 if(!a.b4) {
  if(!a.owner) {
   for(U i=0;i<pol.count();++i) {
    const U o=pol.candidate(i); a.candidate_index=i;
    const float speed=Speed(a), delta=Sub(pol.PlaneHeight(o,a),a.y), denominator=speed>0.1f?speed:0.1f;
    const U eligible=pol.Eligible(o);
    if((eligible==1 || 2.0f>=Div(delta,denominator) || 0.25f>delta) && pol.Contains(o,p)) { a.owner=o; return; }
   }
   return;
  }
  if(pol.Active(a.owner) && pol.Contains(a.owner,p)) return;
  work.Clear(); Enqueue(work,a.owner); U best=0,exact=0; float best_t=0;
  while(work.read<work.count && !exact) {
   const U o=work.fifo[work.read++], first=pol.First(o); U edge=first;
   do {
    U adjacent=~0u; const U n=pol.Neighbors(edge); const auto records=pol.NeighborRecords(edge);
    for(U j=0;j<n;++j) { const U v=pol.Neighbor(records,j); if(pol.Active(v)==1) { adjacent=j; break; } }
    if(adjacent!=~0u && pol.Outside(edge,p)) {
     const U v=pol.Neighbor(records,adjacent); Enqueue(work,v);
     if(pol.Outside(pol.NeighborEdge(records,adjacent),p)) {
      const Point u=pol.EdgePoint(edge), end=pol.EdgePoint(pol.Next(edge));
      const float dx=Sub(end.x,u.x),dz=Sub(end.z,u.z),wx=Sub(p.x,u.x),wz=Sub(p.z,u.z),len=Sqrt(Add(Mul(dx,dx),Mul(dz,dz)));
      float t=0; if(len>0) { const float inv=Div(1.0f,len); t=Add(Mul(Mul(inv,wx),Mul(inv,dx)),Mul(Mul(inv,wz),Mul(inv,dz))); }
      if(!best || Abs(Sub(0.5f,best_t))>Abs(Sub(0.5f,t))) { best=o; best_t=t; }
     } else if(pol.Contains(v,p)) { exact=v; break; }
    }
    edge=pol.Next(edge);
   } while(edge!=first);
  }
  U selected=exact?exact:best;
  if(!selected) for(U i=0;i<pol.count();++i) {
   const U o=pol.candidate(i); a.candidate_index=i; const float slope=Div(Sub(pol.PlaneHeight(o,a),a.y),Max(Speed(a),0.1f));
   if(2.0f>=slope && slope>=-0.5f && pol.Contains(o,p)) { selected=o; break; }
  }
  if(!selected) { EventAt(r,a,EventKind::Leave,a.entity,a.transition_targets[0]); a.b4=1; }
  a.owner=selected; work.Clear(); return;
 }
 if(a.b5) return;
 for(U i=0;i<pol.count();++i) {
  const U o=pol.candidate(i); a.candidate_index=i; const float h=pol.PlaneHeight(o,a);
  if(h>=a.y && Sub(a.y,a.dy)>=h && pol.Contains(o,p)) { a.owner=o; break; }
 }
 if(a.owner) { a.b4=0; EventAt(r,a,EventKind::Land,a.entity,a.transition_targets[1]); return; }
 const float ground=SampleTerrain(a.terrain,a.x,a.z,false), surface=SampleTerrain(a.terrain,a.x,a.z,true);
 bool crossed=false;
 if(surface>ground && surface>=a.y) {
  crossed=true;
  if(Sub(a.y,a.dy)>surface) {
   U position[3]{}; const U identity=pol.Identity(a,position);
   if(identity) {
    EventAt(r,a,EventKind::Notification,a.notification,a.notification_target);
    Event& e=r.events[r.event_count-1]; e.args[0]=identity;
    for(U i=0;i<3;++i) e.args[i+1]=position[i];
    pol.Notified(a);
   }
  }
 }
 const U capable=pol.Capable(a);
 if(capable==1 && surface>Add(Mul(a.scalar54,0.75f),ground) && crossed) {
  a.b5=1; EventAt(r,a,EventKind::Secondary,a.entity,a.transition_targets[2]); return;
 }
 if(ground>=a.y) { a.b4=0; EventAt(r,a,EventKind::Land,a.entity,a.transition_targets[1]); }
}
// Worker policy: only recovered closed byte getters execute, against the participant
// copy; any other target is refused before the caller can observe a result.
struct WorkerPolicy {
 U delta, copy, n, list;
 const ntw2_sweep::WorkerScene& scene;
 mutable const ntw2_sweep::WorkerOwner* cachedOwner = nullptr;
 mutable const ntw2_sweep::WorkerEdge* cachedEdge = nullptr;
 const ntw2_sweep::WorkerOwner& Owner(U identity) const {
  if(cachedOwner && cachedOwner->identity==identity) return *cachedOwner;
  const auto it=std::lower_bound(scene.owners.begin(),scene.owners.end(),identity,
   [](const ntw2_sweep::WorkerOwner& o,U p) { return o.identity<p; });
  if(it==scene.owners.end() || it->identity!=identity) RaiseException(ntw2_sweep::WorkerRefusal,0,0,nullptr);
  cachedOwner=&*it; return *cachedOwner;
 }
 const ntw2_sweep::WorkerEdge& Edge(U identity) const {
  if(cachedEdge && cachedEdge->identity==identity) return *cachedEdge;
  const auto it=std::lower_bound(scene.edges.begin(),scene.edges.end(),identity,
   [](const ntw2_sweep::WorkerEdge& e,U p) { return e.identity<p; });
  if(it==scene.edges.end() || it->identity!=identity) RaiseException(ntw2_sweep::WorkerRefusal,0,0,nullptr);
  cachedEdge=&*it; return *cachedEdge;
 }
 U First(U o) const { return Owner(o).firstEdge; }
 U Next(U e) const { return Edge(e).next; }
 Point EdgePoint(U e) const { const auto& v=Edge(e); return {v.point[0],v.point[1]}; }
 U Neighbors(U e) const { return static_cast<U>(Edge(e).neighbors.size()); }
 const ntw2_sweep::WorkerEdge* NeighborRecords(U e) const { return &Edge(e); }
 U Neighbor(const ntw2_sweep::WorkerEdge* e,U i) const { return e->neighbors[i]; }
 U NeighborEdge(const ntw2_sweep::WorkerEdge* e,U i) const { return e->neighborEdges[i]; }
 bool Outside(U e,Point p) const {
  const auto& v=Edge(e); return SidePoints({v.point[0],v.point[1]},{v.nextPoint[0],v.nextPoint[1]},p);
 }
 bool Contains(U o,Point p) const {
  const U first=First(o); U e=first;
  do { if(Outside(e,p)) return false; e=Next(e); } while(e!=first);
  return true;
 }
 float PlaneHeight(U o,const AgentView& a) const {
  const auto& v=Owner(o);
  return Neg(Div(Add(Add(Mul(v.plane[2],a.z),Mul(a.x,v.plane[0])),v.plane[3]),v.plane[1]));
 }
 U count() const { return n; }
 U candidate(U i) const { return Load<U>(list,i*4); }
 B Pure(U receiver,U target) const {
  switch(target-delta) {
  case 0x54E920: return Load<B>(receiver,4);
  case 0x462CB0: return 0;
  case 0x447880: return 1;
  default: RaiseException(ntw2_sweep::WorkerRefusal,0,0,nullptr); return 0;
  }
 }
 U Eligible(U o) const { return Pure(o,Target(o,0x24)); }
 U Active(U o) const { return Pure(o+0x1C,Target(o+0x1C,0)); }
 // 4470B0 is `mov eax,ecx; ret`: the identity is the original receiver and the
 // position words are the private copy's x/y/z (+0x48..+0x50).
 U Identity(const AgentView& a,U pos[3]) const {
  if(a.identity_target-delta!=0x4470B0) RaiseException(ntw2_sweep::WorkerRefusal,0,0,nullptr);
  for(U i=0;i<3;++i) pos[i]=Load<U>(copy,0x48+i*4);
  return a.entity;
 }
 void Notified(const AgentView&) const { RaiseException(ntw2_sweep::WorkerRefusal,0,0,nullptr); }
 U Capable(const AgentView& a) const {
  if(!ntw2_sweep::PureAgentTarget(copy,a.policy_target,delta)) RaiseException(ntw2_sweep::WorkerRefusal,0,0,nullptr);
  return reinterpret_cast<B(__thiscall*)(void*)>(a.policy_target)(Pointer(copy));
 }
};
void FillView(U p,U entity,AgentView& a) {
 a={}; a.entity=entity; a.owner=Load<U>(p,0x10);
 a.x=Load<float>(p,0x48); a.y=Load<float>(p,0x4C); a.z=Load<float>(p,0x50); a.scalar54=Load<float>(p,0x54);
 a.dx=Load<float>(p,0xD4); a.dy=Load<float>(p,0xD8); a.dz=Load<float>(p,0xDC); a.b4=Load<B>(p,0xB4); a.b5=Load<B>(p,0xB5);
 a.transition_targets[0]=Target(p,0x64); a.transition_targets[1]=Target(p,0x68); a.transition_targets[2]=Target(p,0x6C);
 a.policy_target=Target(p,0x50); a.identity_target=Target(p,0x14);
 if(a.b4 && !a.b5) { const U model=Load<U>(Load<U>(p,0x28),8); a.terrain=Load<U>(model,0x9C); a.notification=Load<U>(model,0x94)+0xFE0; a.notification_target=Target(a.notification,8); }
}
bool WorkerEnvImpl(WorkerContext& c,U p,U identity,U scratch,Result& out) {
 if(!c.scene || !c.scene->built || c.build!=c.scene->build) return false;
 const U delta=c.image_delta; AgentView& a=c.view;
 const U header=Load<U>(scratch,0); if(!header) return false;
 const U n=Load<U>(header,0xC), list=Load<U>(header,0x10); if(n && !list) return false;
 const U owner=Load<U>(p,0x10); const B b4=Load<B>(p,0xB4),b5=Load<B>(p,0xB5);
 // Both native branches return without geometry or policy queries.
 if(!owner && ((!b4 && !n) || (b4 && b5))) {
  a.owner=owner; a.b4=b4; a.b5=b5; out={}; return true;
 }
 FillView(p,identity,a);
 // No up-front target proof: the flat B4=0 path touches no unrecovered policy.
 WorkerPolicy pol{delta,p,n,list,*c.scene};
 RunCore(a,pol,c.scratch,out);
 // Only an emitted transition needs its recovered target; others never reach callbacks.
 for(U i=0;i<out.event_count;++i) {
  const Event& e=out.events[i];
  const U expected=e.kind==EventKind::Leave?0x66B0F0:e.kind==EventKind::Land?0x66B2F0:e.kind==EventKind::Secondary?0x66B200:0;
  if(!expected || e.target-delta!=expected) return false;
 }
 // A recovered owner is later queried (+0x24, +0xC) by the clone tail outside this port.
 if(a.owner && (!ntw2_sweep::PureByteTarget(Target(a.owner,0x24),delta) || !ntw2_sweep::PureByteTarget(Target(a.owner,0xC),delta))) return false;
 return true;
}
}
void Run(AgentView& a,Scene& s,WorkerScratch& work,Result& r) {
 s.policy_cursor=0; ShadowPolicy pol{s}; RunCore(a,pol,work,r);
}
void Capture(Agent* agent,Scratch* input,AgentView& a,Scene& s) {
 if(!depth) owner_thread=GetCurrentThreadId();
 const U p=Address(agent); FillView(p,p,a);
 const U list=Load<U>(Address(input),0), n=Load<U>(list,0xC), data=Load<U>(list,0x10);
 s.candidates.resize(n); if(n) std::memcpy(s.candidates.data(),Pointer(data),n*4);
 s.policies.clear(); s.capture_policies=true;
 AgentView probe=a; Result ignored; Run(probe,s,scratch,ignored); s.capture_policies=false;
}
bool PrepareWorker(WorkerContext& c,const ntw2_sweep::WorkerScene& s) {
 c.fp=ntw2_sweep::CaptureFp();
 if(!s.built) return false;
 if(c.scene==&s && c.build==s.build) return true;
 c.image_delta=s.image_delta;
 c.scratch.Prepare(s.owners.size()); c.view={};
 c.scene=&s; c.build=s.build; return true;
}
size_t HeapBytes(const WorkerContext& c) {
 return c.scratch.fifo.capacity()*sizeof(U)+c.scratch.touched.capacity()*sizeof(uint16_t);
}
bool WorkerEnv(WorkerContext& c,void* agent,U identity,void* scratch,Result& out) {
 ntw2_sweep::FpState saved{}; bool ok=false;
 if(!c.fp_managed) { saved=ntw2_sweep::CaptureFp(); ntw2_sweep::ApplyFp(c.fp); }
 __try {
  __try { ok=WorkerEnvImpl(c,Address(agent),identity,Address(scratch),out); }
  __finally { if(!ok) c.scratch.Clear(); if(!c.fp_managed) ntw2_sweep::ApplyFp(saved); }
 }
 __except(ntw2_sweep::RefusalFilter(GetExceptionCode())) { ok=false; }
 if(ok) {
  const AgentView& a=c.view;
  std::memcpy(static_cast<B*>(agent)+0x10,&a.owner,4); static_cast<B*>(agent)[0xB4]=a.b4; static_cast<B*>(agent)[0xB5]=a.b5;
 }
 return ok;
}
bool ReplayEvent(const Event& e,void* liveAgent) {
 const U p=Address(liveAgent);
 const bool transition=e.kind==EventKind::Leave||e.kind==EventKind::Land||e.kind==EventKind::Secondary;
 if(!e.target || (!transition && e.kind!=EventKind::Notification) || (transition && e.receiver!=p)) return false;
 std::memcpy(static_cast<B*>(liveAgent)+0x10,&e.owner,4); static_cast<B*>(liveAgent)[0xB4]=e.b4; static_cast<B*>(liveAgent)[0xB5]=e.b5;
 if(e.kind==EventKind::Notification) {
  U packet[4]={e.args[0],e.args[1],e.args[2],e.args[3]};
  reinterpret_cast<void(__thiscall*)(void*,void*)>(e.target)(Pointer(e.receiver),packet);
 } else reinterpret_cast<void(__thiscall*)(void*)>(e.target)(Pointer(e.receiver));
 if(e.kind==EventKind::Leave) { static_cast<B*>(liveAgent)[0xB4]=1; const U none=0; std::memcpy(static_cast<B*>(liveAgent)+0x10,&none,4); }
 return true;
}
namespace {
void Finish() {
 AgentView actual=saved; Run(actual,scene,scratch,predicted);
 const U p=Address(original), expected[3]={Load<U>(p,0x10),Load<B>(p,0xB4),Load<B>(p,0xB5)}, got[3]={actual.owner,actual.b4,actual.b5};
 ++words[Compared]; bool mismatch=false;
 for(U i=0;i<3;++i) if(expected[i]!=got[i]) {
  ++words[MismatchOwner+i]; mismatch=true;
  if(!words[FirstCall]) { words[FirstEntity]=p; words[FirstCall]=words[Calls]; words[FirstField]=i; words[FirstExpected]=expected[i]; words[FirstActual]=got[i]; words[FirstOwner]=saved.owner; words[FirstFlags]=saved.b4|(saved.b5<<8); words[FirstCandidate]=actual.candidate_index; }
 }
 if(mismatch) ++words[Mismatches];
 EventKind inferred{}; U inferred_count=0;
 if(!saved.b4 && expected[1]) { inferred=EventKind::Leave; inferred_count=1; }
 else if(saved.b4 && !saved.b5 && !expected[1]) { inferred=EventKind::Land; inferred_count=1; }
 else if(saved.b4 && !saved.b5 && expected[2]) { inferred=EventKind::Secondary; inferred_count=1; }
 U transition_count=0; EventKind transition{};
 for(U i=0;i<predicted.event_count;++i) {
  const auto kind=predicted.events[i].kind;
  if(kind==EventKind::Notification) { ++words[NotificationPredicted]; ++words[NotificationUnobserved]; }
  else { transition=kind; ++transition_count; ++words[kind==EventKind::Leave?LeavePredicted:kind==EventKind::Land?LandPredicted:SecondaryPredicted]; }
 }
 words[EventsPredicted]+=predicted.event_count; words[EventsInferred]+=inferred_count;
 if(transition_count!=inferred_count || (transition_count && transition!=inferred)) ++words[MismatchEvent];
 if(mismatch && (predicted.event_count || inferred_count)) ++words[CallbackImplied];
 if(predicted.event_count || !scene.policies.empty()) ++words[OwnerRequired];
}
}
bool Start(const Binding& b) {
 Stop();
 const std::lock_guard<std::mutex> lock(target_mutex);
 for(auto& t:targets) t.clear();
 binding=b; std::memset(words,0,sizeof(words));
 // The optional live shadow has no frozen graph bound; owned workers do and
 // never allocate this legacy maximum-sized scratch.
 if(b.shadow) {
  try { scratch.Prepare(65536); }
  catch(const std::bad_alloc&) { binding={}; return false; }
 }
 if(b.enabled) { words[Version]=1; words[Enabled]=1; words[Generation]=b.generation; }
 QueryPerformanceFrequency(&frequency); return true;
}
void Stop() {
 pending=false; owner_thread=depth=0; original=nullptr; binding={}; words[Enabled]=0;
 scratch=WorkerScratch{}; scene=Scene{};
}
void Sample(U out[WordCount],U histogram[64]) {
 if(out) std::memcpy(out,words,sizeof(words)); if(!histogram) return; std::memset(histogram,0,64*4);
 const std::lock_guard<std::mutex> lock(target_mutex);
 // Exact top eight from all distinct observed targets, stable ties by first observation.
 for(U kind=0;kind<3;++kind) { U selected[8]{}; U used=0;
  for(U rank=0;rank<8;++rank) { U best=~0u;
   for(U i=0;i<targets[kind].size();++i) { bool seen=false; for(U j=0;j<used;++j) if(selected[j]==i) seen=true;
    if(!seen && (best==~0u || targets[kind][i].count>targets[kind][best].count)) best=i;
   }
   if(best==~0u) break; selected[used++]=best; histogram[kind*16+rank*2]=targets[kind][best].target; histogram[kind*16+rank*2+1]=targets[kind][best].count;
  }
  histogram[48+kind]=static_cast<U>(targets[kind].size()); for(const auto& t:targets[kind]) histogram[51+kind]+=t.count;
 }
}
void ShadowBefore(Agent* agent,Scratch* input) {
 if(!binding.enabled || !binding.shadow) return;
 const U thread=GetCurrentThreadId(); if(!depth) owner_thread=thread;
 if(owner_thread!=thread) { ++words[Reentry]; return; } if(++depth!=1) { ++words[Reentry]; return; }
 ++words[Calls]; original=agent; LARGE_INTEGER begin{},end{}; QueryPerformanceCounter(&begin);
 fegetenv(&input_fp);
 __try { Capture(agent,input,saved,scene); pending=true; } __except(EXCEPTION_EXECUTE_HANDLER) { ++words[Faults]; pending=false; scratch.Clear(); }
 fesetenv(&input_fp);
 QueryPerformanceCounter(&end); capture_ticks=end.QuadPart-begin.QuadPart;
}
void ShadowAfter() {
 if(owner_thread!=GetCurrentThreadId() || !depth) return; if(depth>1) { --depth; return; }
 LARGE_INTEGER begin{},end{}; QueryPerformanceCounter(&begin);
 fenv_t post_fp; fegetenv(&post_fp); fesetenv(&input_fp);
 if(pending) { __try { Finish(); } __except(EXCEPTION_EXECUTE_HANDLER) { ++words[Faults]; scratch.Clear(); } }
 fesetenv(&post_fp);
 pending=false; depth=0; QueryPerformanceCounter(&end);
 if(frequency.QuadPart) words[ShadowUs]+=static_cast<U>((capture_ticks+end.QuadPart-begin.QuadPart)*1000000/frequency.QuadPart);
}
void Abandon() { if(pending || depth) ++words[Faults]; pending=false; depth=0; scratch.Clear(); }
}

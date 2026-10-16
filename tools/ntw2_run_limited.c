/* Development-only process containment. Never used inside Napoleon.
   ntw2_run_limited LIMIT_MIB RESERVE_MIB TIMEOUT_SECONDS -- PROGRAM [ARGS...]
   The child is assigned, while suspended, to a non-breakaway job with a hard
   aggregate committed-memory limit. The job is killed if this supervisor dies,
   the deadline expires, or available physical RAM falls below the reserve. */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#define COMMAND_CHARS 32768
#define MIB ((uint64_t)1024*1024)
static wchar_t command[COMMAND_CHARS];
static size_t used;
static int append(wchar_t c) {
    if (used+1>=COMMAND_CHARS) return 0;
    command[used++]=c; command[used]=0; return 1;
}
static int quoted(const wchar_t *arg) {
    const wchar_t *p=arg;
    if (used && !append(L' ')) return 0;
    if (!append(L'"')) return 0;
    for (;;) {
        size_t slashes=0, i;
        while (*p==L'\\') { ++slashes; ++p; }
        if (*p==L'"' || !*p) slashes*=2;
        for (i=0;i<slashes;++i) if (!append(L'\\')) return 0;
        if (!*p) break;
        if (*p==L'"' && !append(L'\\')) return 0;
        if (!append(*p++)) return 0;
    }
    return append(L'"');
}
static int number(const wchar_t *text, uint64_t *out) {
    wchar_t *end;
    unsigned long long n;
    if (!text[0] || text[0]==L'-') return 0;
    n=wcstoull(text,&end,10);
    if (*end) return 0;
    *out=n; return 1;
}
static int probe(const wchar_t *mode) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    SIZE_T bytes;
    void *p;
    ZeroMemory(&limits,sizeof(limits));
    if (!QueryInformationJobObject(NULL,JobObjectExtendedLimitInformation,&limits,sizeof(limits),NULL) ||
        !(limits.BasicLimitInformation.LimitFlags&JOB_OBJECT_LIMIT_JOB_MEMORY) ||
        limits.JobMemoryLimit!=32*MIB) return 71;
    bytes=wcscmp(mode,L"deny")==0 ? (SIZE_T)(64*MIB) : (SIZE_T)(4*MIB);
    p=VirtualAlloc(NULL,bytes,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if (bytes==64*MIB) {
        if (p) { VirtualFree(p,0,MEM_RELEASE); return 72; }
        fwprintf(stdout,L"PASS: 64 MiB commitment denied inside 32 MiB job (Win32 %lu)\n",GetLastError());
        return 0;
    }
    if (!p) return 73;
    ((volatile unsigned char*)p)[0]=17;
    ((volatile unsigned char*)p)[bytes-1]=29;
    VirtualFree(p,0,MEM_RELEASE);
    fwprintf(stdout,L"PASS: bounded 4 MiB child allocation succeeded\n");
    return 0;
}
int wmain(int argc,wchar_t **argv) {
    uint64_t limitMiB,reserveMiB,seconds;
    MEMORYSTATUSEX memory;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT portInfo;
    STARTUPINFOW startup;
    PROCESS_INFORMATION child;
    HANDLE job=NULL,port=NULL;
    ULONGLONG started;
    DWORD result=1,stopReason=0;
    int i, memoryReported=0;
    if (argc==3 && wcscmp(argv[1],L"--budget-probe")==0) return probe(argv[2]);
    if (argc<6 || wcscmp(argv[4],L"--") || !number(argv[1],&limitMiB) ||
        !number(argv[2],&reserveMiB) || !number(argv[3],&seconds) || limitMiB<16 ||
        limitMiB>2048 || reserveMiB<4096 || reserveMiB>1048576 || !seconds || seconds>3600 ||
        limitMiB*MIB>(uint64_t)(SIZE_T)-1) {
        fwprintf(stderr,L"Usage: ntw2_run_limited LIMIT_MIB(16..2048) RESERVE_MIB(>=4096) TIMEOUT_SECONDS(1..3600) -- PROGRAM [ARGS...]\n");
        return 2;
    }
    ZeroMemory(&memory,sizeof(memory)); memory.dwLength=sizeof(memory);
    if (!GlobalMemoryStatusEx(&memory) || memory.ullAvailPhys<(reserveMiB+limitMiB)*MIB) {
        fwprintf(stderr,L"Refusing launch: insufficient available physical RAM for budget plus reserve.\n");
        return 3;
    }
    for (i=5;i<argc;++i) if (!quoted(argv[i])) { fwprintf(stderr,L"Command line too long.\n"); return 2; }
    job=CreateJobObjectW(NULL,NULL);
    if (!job) goto failed;
    ZeroMemory(&limits,sizeof(limits));
    limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_JOB_MEMORY|JOB_OBJECT_LIMIT_PROCESS_MEMORY|JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    limits.JobMemoryLimit=(SIZE_T)(limitMiB*MIB);
    limits.ProcessMemoryLimit=limits.JobMemoryLimit;
    if (!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits))) goto failed;
    port=CreateIoCompletionPort(INVALID_HANDLE_VALUE,NULL,0,1);
    if (!port) goto failed;
    portInfo.CompletionKey=job; portInfo.CompletionPort=port;
    if (!SetInformationJobObject(job,JobObjectAssociateCompletionPortInformation,&portInfo,sizeof(portInfo))) goto failed;
    ZeroMemory(&startup,sizeof(startup)); startup.cb=sizeof(startup);
    ZeroMemory(&child,sizeof(child));
    if (!CreateProcessW(NULL,command,NULL,NULL,TRUE,CREATE_SUSPENDED,NULL,NULL,&startup,&child)) goto failed;
    if (!AssignProcessToJobObject(job,child.hProcess)) {
        DWORD error=GetLastError();
        TerminateProcess(child.hProcess,4); WaitForSingleObject(child.hProcess,5000);
        CloseHandle(child.hThread); CloseHandle(child.hProcess);
        SetLastError(error); goto failed;
    }
    started=GetTickCount64();
    if (ResumeThread(child.hThread)==(DWORD)-1) {
        TerminateJobObject(job,4); WaitForSingleObject(child.hProcess,5000);
        CloseHandle(child.hThread); CloseHandle(child.hProcess); goto failed;
    }
    CloseHandle(child.hThread);
    for (;;) {
        DWORD wait=WaitForSingleObject(child.hProcess,100);
        DWORD event;
        ULONG_PTR key;
        LPOVERLAPPED value;
        for (i=0;i<8 && GetQueuedCompletionStatus(port,&event,&key,&value,0);++i) {
            if (key==(ULONG_PTR)job && (event==JOB_OBJECT_MSG_JOB_MEMORY_LIMIT || event==JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT)) {
                /* A denied allocation may be handled correctly by the child.
                   The hard job limit stays in force; report the event. */
                if (!memoryReported) fwprintf(stderr,L"Memory limit enforced for owned child (event %lu).\n",event);
                memoryReported=1;
            }
        }
        if (wait==WAIT_OBJECT_0) {
            if (!GetExitCodeProcess(child.hProcess,&result)) result=4;
            break;
        }
        if (wait==WAIT_FAILED) { stopReason=4; break; }
        if (GetTickCount64()-started>=seconds*1000) { stopReason=124; break; }
        memory.dwLength=sizeof(memory);
        if (!GlobalMemoryStatusEx(&memory) || memory.ullAvailPhys<reserveMiB*MIB) { stopReason=125; break; }
    }
    if (stopReason) {
        fwprintf(stderr,L"Stopping owned job: %ls.\n",stopReason==124?L"deadline":stopReason==125?L"RAM reserve reached":L"wait failure");
        TerminateJobObject(job,stopReason); WaitForSingleObject(child.hProcess,5000); result=stopReason;
    }
    ZeroMemory(&limits,sizeof(limits));
    if (QueryInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits),NULL))
        fwprintf(stderr,L"Owned job peak commitment: %llu bytes; hard limit: %llu bytes; child exit: %lu.\n",
                 (unsigned long long)limits.PeakJobMemoryUsed,(unsigned long long)(limitMiB*MIB),result);
    CloseHandle(child.hProcess);
    CloseHandle(port);
    CloseHandle(job); /* terminates any descendants left behind by the child */
    return (int)result;
failed:
    fwprintf(stderr,L"Contained launch failed (Win32 %lu); no uncontained child was allowed to run.\n",GetLastError());
    if (port) CloseHandle(port);
    if (job) CloseHandle(job);
    return 4;
}

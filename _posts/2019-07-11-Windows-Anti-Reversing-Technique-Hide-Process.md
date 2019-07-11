---
title:  "Windows - Anti-Reversing Technique: Hide Process"
categories:
  - WINDOWS
tags:
  - DRIVER
  - PROCESS
  - ANTI-REVERSING
---
# Anti-Reversing Technique: Hide Process
## 0x00_Description
별도의 Driver를 로드하는 프로그램 분석을 진행하다 보면 프로세스가 TaskManager에서 탐색되지 않는 경우가 존재한다. 이 기법을 `Process Hiding`이라고도 하는데 정확한 원리 파악을 위해 간략하게 `Driver` 코드를 작성하여 적용한 내용과 함께 필요 지식을 정리하였다.  

## 0x01_EPROCESS Structure

윈도우 OS에서 커널 메모리에서 프로세스를 관리하기 위해 사용하는 구조체를 `EPROCESS`라 한다. 즉, 모든 프로세스는 EPROCESS 형태로 정보를 저장하게 된다. OS 기본 개념에서 `PCB(Process Control Block)`이라 불리는 것이 EPROCESS 구조체 내부에 `KPROCESS`라는 이름으로 존재하며 프로세스 관리에 필요한 모든 정보를 지니고 있다. 추가로 Thread 또한, `ETHREAD`라는 구조체로 커널 메모리 상에서 관리된다. 

User Mode에서는 PEB와 TEB와 유사하다고 생각할 수 있는데 Kernel Mode에 필요한 정보를 가지고 있다는 점에서 차이가 있다. Kernel Mode의 EPROCESS와 User Mode의 PEB가 존재하는 이유는 User Mode로 동작하는 윈도우에서 커널 메모리 영역에 Direct Access가 불가능하기 때문에 Indirect Access를 수행해야하는데 이 때문에 속도 문제가 발생한다. 이를 해결하기 위해 User Mode에서 이용할 수 있는 PEB 구조체에 정보를 저장하고 사용하는 것이다.

간단하게 윈도우 OS에서 프로세스 생성 과정을 살펴보면 다음과 같다.

1. 커널 영역에서 `EPROCESS Object`를 생성하고 KPROCESS, PEB를 초기화 및 생성 후, 가상 주소 공간에 할당한다.
2. 로더(ntdll.exe)가 `실행 파일 이미지`를 가상 메모리에 로드한다.
3. `메인 Thread를 생성`하고 KTHREAD와 TEB를 초기화 및 생성한다.
4. CSRSS.exe에 프로세스 생성 메시지를 전달하고 `CSRSS PROCESS/THREAD Block`을 생성한다.
5. 생성된 `Process Block을 List에 추가`하고 Kernel Mode 영역의 `Data Structure를 초기화`한다.
6. `프로그램을 실행`한다. (Main Thread 시작)



커널 디버깅 환경에서 메모장을 실행하고 직접 EPROCESS 구조를 살펴보자. 우선, 요약된 프로세스 정보를 확인한다.

```powershell
kd> !process 0 0 notepad.exe
PROCESS ffff950f718f0080
        SessionId: 1  Cid: 1ac0    Peb: 76846ee000  ParentCid: 0f0c
        DirBase: 15c80002  ObjectTable: ffffd6037b021cc0  HandleCount: 206.
        Image: notepad.exe
```

상세 정보를 확인한다.

```c++
kd> !process ffff950f718f0080 7
PROCESS ffff950f718f0080
        SessionId: 1  Cid: 1ac0    Peb: 76846ee000  ParentCid: 0f0c
        DirBase: 15c80002  ObjectTable: ffffd6037b021cc0  HandleCount: 206.
        Image: notepad.exe
        VadRoot ffff950f6ebd8af0 Vads 89 Clone 0 Private 509. Modified 19. Locked 0.
        DeviceMap ffffd60374cc22a0
        Token                             ffffd6037b76f5d0
        ElapsedTime                       00:23:31.048
        UserTime                          00:00:00.000
        KernelTime                        00:00:00.031
        QuotaPoolUsage[PagedPool]         259776
        QuotaPoolUsage[NonPagedPool]      12624
        Working Set Sizes (now,min,max)  (4128, 50, 345) (16512KB, 200KB, 1380KB)
        PeakWorkingSetSize                4259
        VirtualSize                       2101407 Mb
        PeakVirtualSize                   2101419 Mb
        PageFaultCount                    4442
        MemoryPriority                    BACKGROUND
        BasePriority                      8
        CommitCharge                      598

                THREAD ffff950f71a95680  Cid 1ac0.16e0  Teb: 00000076846ef000 Win32Thread: ffff950f6ea98b50 WAIT: (WrUserRequest) UserMode Non-Alertable
                        ffff950f7185e280  QueueObject
                Not impersonating
                DeviceMap                 ffffd60374cc22a0
                Owning Process            ffff950f718f0080       Image:         notepad.exe
                Attached Process          N/A            Image:         N/A
                Wait Start TickCount      377951         Ticks: 10298 (0:00:02:40.906)
                Context Switch Count      673            IdealProcessor: 5             
                UserTime                  00:00:00.000
                KernelTime                00:00:00.031
                Win32 Start Address 0x00007ff69c70ac50
                Stack Init fffff50028fb8c10 Current fffff50028fb7fc0
                Base fffff50028fb9000 Limit fffff50028fb2000 Call 0000000000000000
                Priority 10 BasePriority 8 PriorityDecrement 0 IoPriority 2 PagePriority 5
                Kernel stack not resident.

```

위에서 확인한 프로세스 정보 중 대부분은 EPROCESS 구조체에서도 확인이 가능하며 WinDBG의 `DT 명령`을 이용하여 해당 프로세스 주소의 정보를 확인할 수 있다. 참고로 이 구조체의 구조는 OS마다 차이점이 존재한다.

```powershell
kd> dt_eprocess ffff8a8fc01822c0
nt!_EPROCESS
      +0x000 Pcb              : _KPROCESS
      +0x2d8 ProcessLock      : _EX_PUSH_LOCK
      +0x2e0 UniqueProcessId  : 0x00000000`00001e34 Void
      +0x2e8 ActiveProcessLinks : _LIST_ENTRY [ 0xfffff807`646ae5f0 - 0xffff8a8f`b8fda628 ]
      +0x2f8 RundownProtect   : _EX_RUNDOWN_REF
      +0x300 Flags2           : 0xd000
      +0x300 JobNotReallyActive : 0y0
      +0x300 AccountingFolded : 0y0
      +0x300 NewProcessReported : 0y0
      +0x300 ExitProcessReported : 0y0
      +0x300 ReportCommitChanges : 0y0
      +0x300 LastReportMemory : 0y0
      +0x300 ForceWakeCharge  : 0y0
      +0x300 CrossSessionCreate : 0y0
      +0x300 NeedsHandleRundown : 0y0
      +0x300 RefTraceEnabled  : 0y0
      +0x300 PicoCreated      : 0y0
      +0x300 EmptyJobEvaluated : 0y0
      +0x300 DefaultPagePriority : 0y101
      +0x300 PrimaryTokenFrozen : 0y1
      +0x300 ProcessVerifierTarget : 0y0
      +0x300 RestrictSetThreadContext : 0y0
      +0x300 AffinityPermanent : 0y0
      +0x300 AffinityUpdateEnable : 0y0
      +0x300 PropagateNode    : 0y0
      +0x300 ExplicitAffinity : 0y0
      +0x300 ProcessExecutionState : 0y00
      +0x300 EnableReadVmLogging : 0y0
      +0x300 EnableWriteVmLogging : 0y0
      +0x300 FatalAccessTerminationRequested : 0y0
      +0x300 DisableSystemAllowedCpuSet : 0y0
      +0x300 ProcessStateChangeRequest : 0y00
      +0x300 ProcessStateChangeInProgress : 0y0
      +0x300 InPrivate        : 0y0
      +0x304 Flags            : 0x144d0c01
      +0x304 CreateReported   : 0y1
      +0x304 NoDebugInherit   : 0y0
      +0x304 ProcessExiting   : 0y0
      +0x304 ProcessDelete    : 0y0
      +0x304 ManageExecutableMemoryWrites : 0y0
      +0x304 VmDeleted        : 0y0
      +0x304 OutswapEnabled   : 0y0
      +0x304 Outswapped       : 0y0
      +0x304 FailFastOnCommitFail : 0y0
      +0x304 Wow64VaSpace4Gb  : 0y0
      +0x304 AddressSpaceInitialized : 0y11
      +0x304 SetTimerResolution : 0y0
      +0x304 BreakOnTermination : 0y0
      +0x304 DeprioritizeViews : 0y0
      +0x304 WriteWatch       : 0y0
      +0x304 ProcessInSession : 0y1
      +0x304 OverrideAddressSpace : 0y0
      +0x304 HasAddressSpace  : 0y1
      +0x304 LaunchPrefetched : 0y1
      +0x304 Background       : 0y0
      +0x304 VmTopDown        : 0y0
      +0x304 ImageNotifyDone  : 0y1
      +0x304 PdeUpdateNeeded  : 0y0
      +0x304 VdmAllowed       : 0y0
      +0x304 ProcessRundown   : 0y0
      +0x304 ProcessInserted  : 0y1
      +0x304 DefaultIoPriority : 0y010
      +0x304 ProcessSelfDelete : 0y0
      +0x304 SetTimerResolutionLink : 0y0
      +0x308 CreateTime       : _LARGE_INTEGER 0x01d536f9`9b1b4902
      +0x310 ProcessQuotaUsage : [2] 0x3838
      +0x320 ProcessQuotaPeak : [2] 0x3838
      +0x330 PeakVirtualSize  : 0x00000201`0b3ad000
      +0x338 VirtualSize      : 0x00000201`0b3ad000
      +0x340 SessionProcessLinks : _LIST_ENTRY [ 0xffffc501`1da73010 - 0xffff8a8f`bfd71640 ]
      +0x350 ExceptionPortData : 0xffff8a8f`bc53ccd0 Void
      +0x350 ExceptionPortValue : 0xffff8a8f`bc53ccd0
      +0x350 ExceptionPortState : 0y000
      +0x358 Token            : _EX_FAST_REF
      +0x360 MmReserved       : 0
      +0x368 AddressCreationLock : _EX_PUSH_LOCK
      +0x370 PageTableCommitmentLock : _EX_PUSH_LOCK
      +0x378 RotateInProgress : (null) 
      +0x380 ForkInProgress   : (null) 
      +0x388 CommitChargeJob  : (null) 
      +0x390 CloneRoot        : _RTL_AVL_TREE
      +0x398 NumberOfPrivatePages : 0x24b
      +0x3a0 NumberOfLockedPages : 0
      +0x3a8 Win32Process     : 0xffff9b58`44f13ae0 Void
      +0x3b0 Job              : (null) 
      +0x3b8 SectionObject    : 0xffff9c83`c4f6a6e0 Void
      +0x3c0 SectionBaseAddress : 0x00007ff7`fc5c0000 Void
      +0x3c8 Cookie           : 0xac419005
      +0x3d0 WorkingSetWatch  : (null) 
      +0x3d8 Win32WindowStation : 0x00000000`000000a8 Void
      +0x3e0 InheritedFromUniqueProcessId : 0x00000000`00000300 Void
      +0x3e8 Spare0           : (null) 
      +0x3f0 OwnerProcessId   : 0x302
      +0x3f8 Peb              : 0x00000064`3b114000 _PEB
      +0x400 Session          : 0xffffc501`1da73000 _MM_SESSION_SPACE
      +0x408 Spare1           : (null) 
      +0x410 QuotaBlock       : 0xffff8a8f`be426c80 _EPROCESS_QUOTA_BLOCK
      +0x418 ObjectTable      : 0xffff9c83`c482ad80 _HANDLE_TABLE
      +0x420 DebugPort        : (null) 
      +0x428 WoW64Process     : (null) 
      +0x430 DeviceMap        : 0xffff9c83`c42280c0 Void
      +0x438 EtwDataSource    : 0xffff8a8f`bf88f220 Void
      +0x440 PageDirectoryPte : 0
      +0x448 ImageFilePointer : 0xffff8a8f`bf2e6570 _FILE_OBJECT
      +0x450 ImageFileName    : [15]  "notepad.exe"
      +0x45f PriorityClass    : 0x2 ''
      +0x460 SecurityPort     : (null) 
      +0x468 SeAuditProcessCreationInfo : _SE_AUDIT_PROCESS_CREATION_INFO
      +0x470 JobLinks         : _LIST_ENTRY [ 0x00000000`00000000 - 0x00000000`00000000 ]
      +0x480 HighestUserAddress : 0x00007fff`ffff0000 Void
      +0x488 ThreadListHead   : _LIST_ENTRY [ 0xffff8a8f`be6b8728 - 0xffff8a8f`b8f83728 ]
      +0x498 ActiveThreads    : 7
      +0x49c ImagePathHash    : 0xc5670914
      +0x4a0 DefaultHardErrorProcessing : 1
      +0x4a4 LastThreadExitStatus : 0n0
      +0x4a8 PrefetchTrace    : _EX_FAST_REF
      +0x4b0 LockedPagesList  : (null) 
      +0x4b8 ReadOperationCount : _LARGE_INTEGER 0x0
      +0x4c0 WriteOperationCount : _LARGE_INTEGER 0x0
      +0x4c8 OtherOperationCount : _LARGE_INTEGER 0x0
      +0x4d0 ReadTransferCount : _LARGE_INTEGER 0x0
      +0x4d8 WriteTransferCount : _LARGE_INTEGER 0x0
      +0x4e0 OtherTransferCount : _LARGE_INTEGER 0x0
      +0x4e8 CommitChargeLimit : 0
      +0x4f0 CommitCharge     : 0x30d
      +0x4f8 CommitChargePeak : 0x30d
      +0x500 Vm               : _MMSUPPORT_FULL
      +0x610 MmProcessLinks   : _LIST_ENTRY [ 0xfffff807`646da020 - 0xffff8a8f`b8fda950 ]
      +0x620 ModifiedPageCount : 6
      +0x624 ExitStatus       : 0n259
      +0x628 VadRoot          : _RTL_AVL_TREE
      +0x630 VadHint          : 0xffff8a8f`c10ff190 Void
      +0x638 VadCount         : 0x66
      +0x640 VadPhysicalPages : 0
      +0x648 VadPhysicalPagesLimit : 0
      +0x650 AlpcContext      : _ALPC_PROCESS_CONTEXT
      +0x670 TimerResolutionLink : _LIST_ENTRY [ 0x00000000`00000000 - 0x00000000`00000000 ]
      +0x680 TimerResolutionStackRecord : (null) 
      +0x688 RequestedTimerResolution : 0
      +0x68c SmallestTimerResolution : 0
      +0x690 ExitTime         : _LARGE_INTEGER 0x0
      +0x698 InvertedFunctionTable : (null) 
      +0x6a0 InvertedFunctionTableLock : _EX_PUSH_LOCK
      +0x6a8 ActiveThreadsHighWatermark : 7
      +0x6ac LargePrivateVadCount : 0
      +0x6b0 ThreadListLock   : _EX_PUSH_LOCK
      +0x6b8 WnfContext       : 0xffff9c83`c6030870 Void
      +0x6c0 ServerSilo       : (null) 
      +0x6c8 SignatureLevel   : 0 ''
      +0x6c9 SectionSignatureLevel : 0 ''
      +0x6ca Protection       : _PS_PROTECTION
      +0x6cb HangCount        : 0y000
      +0x6cb GhostCount       : 0y000
      +0x6cb PrefilterException : 0y0
      +0x6cc Flags3           : 0x41c000
      +0x6cc Minimal          : 0y0
      +0x6cc ReplacingPageRoot : 0y0
      +0x6cc Crashed          : 0y0
      +0x6cc JobVadsAreTracked : 0y0
      +0x6cc VadTrackingDisabled : 0y0
      +0x6cc AuxiliaryProcess : 0y0
      +0x6cc SubsystemProcess : 0y0
      +0x6cc IndirectCpuSets  : 0y0
      +0x6cc RelinquishedCommit : 0y0
      +0x6cc HighGraphicsPriority : 0y0
      +0x6cc CommitFailLogged : 0y0
      +0x6cc ReserveFailLogged : 0y0
      +0x6cc SystemProcess    : 0y0
      +0x6cc HideImageBaseAddresses : 0y0
      +0x6cc AddressPolicyFrozen : 0y1
      +0x6cc ProcessFirstResume : 0y1
      +0x6cc ForegroundExternal : 0y1
      +0x6cc ForegroundSystem : 0y0
      +0x6cc HighMemoryPriority : 0y0
      +0x6cc EnableProcessSuspendResumeLogging : 0y0
      +0x6cc EnableThreadSuspendResumeLogging : 0y0
      +0x6cc SecurityDomainChanged : 0y0
      +0x6cc SecurityFreezeComplete : 0y1
      +0x6cc VmProcessorHost  : 0y0
      +0x6d0 DeviceAsid       : 0n0
      +0x6d8 SvmData          : (null) 
      +0x6e0 SvmProcessLock   : _EX_PUSH_LOCK
      +0x6e8 SvmLock          : 0
      +0x6f0 SvmProcessDeviceListHead : _LIST_ENTRY [ 0xffff8a8f`c01829b0 - 0xffff8a8f`c01829b0 ]
      +0x700 LastFreezeInterruptTime : 0
      +0x708 DiskCounters     : 0xffff8a8f`c0182b10 _PROCESS_DISK_COUNTERS
      +0x710 PicoContext      : (null) 
      +0x718 EnclaveTable     : (null) 
      +0x720 EnclaveNumber    : 0
      +0x728 EnclaveLock      : _EX_PUSH_LOCK
      +0x730 HighPriorityFaultsAllowed : 0
      +0x738 EnergyContext    : 0xffff8a8f`c0182b38 _PO_PROCESS_ENERGY_CONTEXT
      +0x740 VmContext        : (null) 
      +0x748 SequenceNumber   : 0x95
      +0x750 CreateInterruptTime : 0x387142bb
      +0x758 CreateUnbiasedInterruptTime : 0x387142bb
      +0x760 TotalUnbiasedFrozenTime : 0
      +0x768 LastAppStateUpdateTime : 0x387142bb
      +0x770 LastAppStateUptime : 0y0000000000000000000000000000000000000000000000000000000000000 (0)
      +0x770 LastAppState     : 0y000
      +0x778 SharedCommitCharge : 0xb34
      +0x780 SharedCommitLock : _EX_PUSH_LOCK
      +0x788 SharedCommitLinks : _LIST_ENTRY [ 0xffff9c83`c6ec5fd8 - 0xffff9c83`c6ebf218 ]
      +0x798 AllowedCpuSets   : 0
      +0x7a0 DefaultCpuSets   : 0
      +0x798 AllowedCpuSetsIndirect : (null) 
      +0x7a0 DefaultCpuSetsIndirect : (null) 
      +0x7a8 DiskIoAttribution : (null) 
      +0x7b0 DxgProcess       : 0xffff9c83`c9ae2d70 Void
      +0x7b8 Win32KFilterSet  : 0
      +0x7c0 ProcessTimerDelay : _PS_INTERLOCKED_TIMER_DELAY_VALUES
      +0x7c8 KTimerSets       : 0
      +0x7cc KTimer2Sets      : 0
      +0x7d0 ThreadTimerSets  : 5
      +0x7d8 VirtualTimerListLock : 0
      +0x7e0 VirtualTimerListHead : _LIST_ENTRY [ 0xffff8a8f`c0182aa0 - 0xffff8a8f`c0182aa0 ]
      +0x7f0 WakeChannel      : _WNF_STATE_NAME
      +0x7f0 WakeInfo         : _PS_PROCESS_WAKE_INFORMATION
      +0x820 MitigationFlags  : 0x21
      +0x820 MitigationFlagsValues : <unnamed-tag>
      +0x824 MitigationFlags2 : 0
      +0x824 MitigationFlags2Values : <unnamed-tag>
      +0x828 PartitionObject  : 0xffff8a8f`b8295180 Void
      +0x830 SecurityDomain   : 0x00000001`0000002c
      +0x838 ParentSecurityDomain : 0x00000001`0000002c
      +0x840 CoverageSamplerContext : (null) 
      +0x848 MmHotPatchContext : (null) 
```

간략하게 프로세스 이름만 출력하여 확인하는 것도 가능하다.

```powershell
kd> dt_eprocess ffff950f718f0080 ImageFileName
ntdll!_EPROCESS
      +0x450 ImageFileName : [15]  "notepad.exe"
```

여기서 Process Hiding을 위해 필요한 것은 프로세스 이름을 저장하는 `ImageFileName`, 모든 프로세스를 Linked List 형태로 관리하는 `ActiveProcessLinks`, PID를 저장하고 있는 `UniqueProcessID`이다. 사실 PID 정보는 없어도 무관하며 핵심은 LIST_ENTRY 정보이다.

## 0x02_Hide Process

WDK를 설치 후에 Visual Studio에서 Driver Project를 생성하고 헤더를 수정하여 `Ntifs.h`로 수정한다. 이는 WDK Vista 이 후, 버전부터는 중복 Include를 하지 않도록 하기위해 계층적으로 구성되었으며 `Wdm.h > Ntddk.h > Ntifs.h` 순으로 상위 계층이다. 즉, `Ntifs.h`를 선언하면 함수와 구조체 정보를 포함한다. 

다음으로 위 과정에서 확인한 `ActiveProcessLinks와 ImageFileName의 Offset을 정의`한다. 이는 윈도우 OS 버전 별로 다를 수 있으므로 확인이 필요하다.

```c++
#include <ntifs.h>

#define ACTIVE_PROCESS_LINKS_OFFSET 0x2e8
#define IMAGE_FILE_NAME 0x450
```

이제, `PsGetCurrentProcess()` 함수를 이용하여 EPROCESS 포인터를 획득하고 모든 프로세스 정보를 가리키고 있는 LIST_ENTRY Pointer를 획득하기 위해 ActiveProcessLink의 Pointer 주소를 가져온다.

```c++
PEPROCESS pEPROC;
unsigned char* pCurrentProcess;
PLIST_ENTRY pHeadListEntryNode, pCurrentListEntryNode, pTempListEntryNode;
    
pEPROC = (PEPROCESS)PsGetCurrentProcess();
DbgPrint("[+] t0rchwo0d");
DbgPrint("\t[-] PsGetCurrentProcess() : %p\n", pEPROC);

pCurrentListEntryNode = (PLIST_ENTRY)((unsigned char*)pEPROC + ACTIVE_PROCESS_LINKS_OFFSET);
pHeadListEntryNode = pCurrentListEntryNode;
```

참고로 LIST_ETNRY 구조체 정보는 `ntdef.h` 헤더 파일 내에 다음과 같이 정의되어 있다.

```c++
typedef struct _LIST_ENTRY {
      struct _LIST_ENTRY *Flink;
      struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;
```

이 후, LIST_ENTRY에 저장된 각 EPROCESS 정보를 순회하면서 ImageFileName을 확인하여 Target 프로세스인지 탐색하고 동일할 경우 기존에 Linked List에서 삭제가 일어났을 경우 처리하는 로직과 유사하게 작성하되 Target 프로세스의 FLINK와 BLINK를 자신의 값을 가르키도록 한다. 즉, LIST_ENTRY에서 링크만 제거한다.

```c++
do {
    // 반복 후, pCurrentProcess 즉 EPROCESS 구조체 Offest의 시작 주소를 구하기 위해 ActiveProcessLinks의 Offset을 빼준다.
    pCurrentProcess = (unsigned char*)((unsigned char*)pCurrentListEntryNode - ACTIVE_PROCESS_LINKS_OFFSET);
    char* pImageFileName = ((unsigned char*)pCurrentProcess + IMAGE_FILE_NAME);
    
    DbgPrint("\t\t[-] Eprocess Pointer : %p\n", pCurrentProcess);
    DbgPrint("\t\t[-] Frist PLIST Link : %p\n", pCurrentListEntryNode);
    DbgPrint("\t\t\t[-] ImageFileName : %s\n", pImageFileName);
    
    if (strcmp("notepad.exe", pImageFileName) == 0) {
        DbgPrint("\t\t\t\t[!] FIND TARGET PROCESS\n");
        
        // 아래 연산은 자료 구조에서 Linked List에 저장된 자료가 Delete 되었을 때 일어나는 로직과 유사하다.
        pTempListEntryNode = pCurrentListEntryNode->Blink;
        pTempListEntryNode->Flink = pCurrentListEntryNode->Flink;
        pCurrentListEntryNode->Flink->Blink = pTempListEntryNode;

        pCurrentListEntryNode->Flink = pCurrentListEntryNode;
        pCurrentListEntryNode->Blink = pCurrentListEntryNode;

        break;
    }
        
    pCurrentListEntryNode = pCurrentListEntryNode->Flink;
} while (pCurrentListEntryNode->Flink 
```

이제 Target 프로세스와 `DbgView`를 실행 후, 직접 만든 Loader나 [`OSRLoader`](https://www.osronline.com/article.cfm^article=157.htm)를 이용하여 드라이버를 로드하면 TaskManager 상에서 해당 프로세스가 노출되지 않는 것을 확인할 수 있다. 그러나 이 구조체는 그대로 메모리 상에 존재하고 있으므로 메모리를 덤프하여 `Volatility`를 이용하면 분석이 가능하다.

## 0x03_PoC (YouTube)
[![Windows Process Injection Technique - Reflective DLL Injection](http://img.youtube.com/vi/-QHp4HFuj3U/0.jpg)](https://youtu.be/-QHp4HFuj3U?t=0s) 


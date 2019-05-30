---
title:  "Windows - PEB(Process Environment Block)"
categories:
  - WINDOWS
tags:
  - PEB
  - ANTI-DEBUGGING
  - REVERSE
---
# PEB(Process Environment Block)
## 0x00_Description
윈도우 OS의 Data Structure인 PEB는 운영체제 내부에서 사용하는 Opague Data Structure로 단순하게 생각하면 프로세스에 대한 정보를 가지고 있는 구조체이다. 이 구조체와 함께 몇몇 주요 필드에 대해서 정리하였다. 부족한 내용이 많아 이 후, 같은 주제로 계속해서 포스팅할 예정이다.

## 0x01_PEB(Process Environment Block)
기본적으로 TEB.ProcessEnvironmentBlock에서 PEB의 주소 값을 가지고 있다. 각 아키텍쳐(Architecture) 별로 Offset 위치를 살펴보면 아래와 같다.

**x86 Architecture**
```powershell
0:022> dt_TEB
ntdll!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x01c EnvironmentPointer : Ptr32 Void
   +0x020 ClientId         : _CLIENT_ID
   +0x028 ActiveRpcHandle  : Ptr32 Void
   +0x02c ThreadLocalStoragePointer : Ptr32 Void
   # +0x030 ProcessEnvironmentBlock : Ptr32 _PEB
   +0x034 LastErrorValue   : Uint4B
   /* … 생략 … */

0:022> dt_PEB @$peb
ntdll!_PEB
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0x1 ''
   /* … 생략 … */
```

**x64 Architecture**
```powershell
0:005> dt_TEB
ntdll!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x038 EnvironmentPointer : Ptr64 Void
   +0x040 ClientId         : _CLIENT_ID
   +0x050 ActiveRpcHandle  : Ptr64 Void
   +0x058 ThreadLocalStoragePointer : Ptr64 Void
   # +0x060 ProcessEnvironmentBlock : Ptr64 _PEB
   +0x068 LastErrorValue   : Uint4B
   /* … 생략 … */

0:005> dt_PEB @$peb
ntdll!_PEB
   /* … 생략 … */   
   +0x003 IsPackagedProcess : 0y0
   +0x003 IsAppContainer   : 0y0
   +0x003 IsProtectedProcessLight : 0y0
   +0x003 IsLongPathAwareProcess : 0y0
   +0x004 Padding0         : [4]  ""
   +0x008 Mutant           : 0xffffffff`ffffffff Void
   /* … 생략 … */   
```



x86 Architecture에서는 FS Register가 TEB의 구조체 주소(x64에서는 GS Register)를 가지고 있으며 해당 위치에서 Offset을 더하여 원하는 구조체 필드의 값을 가져올 수 있다. 

**x86 Architecture**

```c++
FS:[0x00] // 현재 SEH 프레임 (예외 처리를 위한 SEH Handler의 시작 주소)
FS:[0x18] // TEB
FS:[0x20] // PID
FS:[0x24] // TID
FS:[0x30] // PEB
FS:[0x34] // Last Error Value
```

**x64 Architecture**

```c++
FS:[0x00] // 현재 SEH 프레임 (예외 처리를 위한 SEH Handler의 시작 주소)
FS:[0x18] // TEB
FS:[0x20] // PID
FS:[0x24] // TID
FS:[0x30] // PEB
FS:[0x34] // Last Error Value
```



다음은 IsDebuggerPresent() 로직의 ASM 코드이다. 이와 같이 FS Register를 사용하는 이유는 PEB를 직점 참조 할 수 없기 때문이다. 즉, FS에서 TEB의 주소를 획득하고 해당 주소에서 Offset 30에 PEB가 존재하는 값을 가져오는 것이다. 

x64에서는 GS Register 기준으로 GS:[30]에 TEB가 존재하며 Offset 60에 PEB가 있다.
```c++
// x86, FS:[30] == PEBBaseAddress == TEB.ProcessEnvironmentBlock
mov eax, DWORD PTR FS:[18]
mov eax, DWORD PTR DS:[EAX+30]
// or
mov eax, DWORD PTR FS:[30]

// x64, GS:[60] == PEBBaseAddress == TEB.ProcessEnvironmentBlock
mov rax, QWORD PTR GS:[30]
mov rax, QWORD PTR DS:[RAX+60]
// or
mov rax, DWORD PTR GS:[60]


// x86, IsDebuggerPresent()
mov eax, DWORD PTR FS:[18h]
mov eax, DWORD PTR [EAX+30h]
movzx eax, byte PTR [EAX+2]
ret
```



자주 사용되는 PEB 구조체 멤버 변수는 아래와 같다. (다음은 x64이므로 8 Byte 씩 증가)

```powershell
0:005> dt_PEB @$peb
ntdll!_PEB
+0x002 BeingDebugged    : 0x1 ''
+0x010 ImageBaseAddress : 0x00000000`00400000 Void
# +0x018 Ldr              : 0x00007ffc`602553c0 _PEB_LDR_DATA
# +0x030 ProcessHeap      : 0x00000000`00bf0000 Void
+0x0b8 NumberOfProcessors : 0xc
+0x0bc NtGlobalFlag     : 0
```



## 0x02_PEB.Ldr->_PEB_LDR_DATA (x86 기준)
다른 변수들의 경우 이름으로 사용되는 역할을 파악할 수 있으나 Ldr (Loader)의 경우 명확하게 파악이되지 않으니 좀 더 살펴보았다. Ldr은 PEB_LDR_DATA 구조체(Structure)의 주소 값을 가지고 있으며 이 구조체는 로드된 Module에 대한 정보를 제공한다.

[이 곳](http://undocumented.ntinternals.net/index.html?page=UserMode%2FStructures%2FPEB_LDR_DATA.html)에서 PEB_LDR_DATA 구조체를 확인 할 수 있으며 다음과 같다.

```c++
typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

디버깅을 통해 다음과 같이 추가된 필드(Filed)가 존재하는 것을 확인할 수 있다.

```powershell
0:022> dt_PEB @$peb ldr
ntdll!_PEB
   # +0x00c Ldr : 0x774a0c40 _PEB_LDR_DATA

0:022> dx -r1 ((ntdll!_PEB_LDR_DATA *)0x774a0c40)
((ntdll!_PEB_LDR_DATA *)0x774a0c40)                 : 0x774a0c40 [Type: _PEB_LDR_DATA *]
    [+0x000] Length           : 0x30 [Type: unsigned long]
    [+0x004] Initialized      : 0x1 [Type: unsigned char]
    [+0x008] SsHandle         : 0x0 [Type: void *]
    [+0x00c] InLoadOrderModuleList [Type: _LIST_ENTRY]
    [+0x014] InMemoryOrderModuleList [Type: _LIST_ENTRY]
    # [+0x01c] InInitializationOrderModuleList [Type: _LIST_ENTRY]
    [+0x024] EntryInProgress  : 0x0 [Type: void *]
    [+0x028] ShutdownInProgress : 0x0 [Type: unsigned char]
    [+0x02c] ShutdownThreadId : 0x0 [Type: void *]
```



위에서 확인한 값 중, InInitializationOrderModuleList [Type: _LIST_ENTRY]는 초기화된 모듈을 순서대로 가지고 있는 연결 리스트(.Flink)의 시작 주소 값을 가지고 있다.

마찬가지로 [이 곳](http://undocumented.ntinternals.net/index.html?page=UserMode%2FStructures%2FPEB_LDR_DATA.html)에서 _LDR_MODULE 구조체를 확인 할 수 있으며 다음과 같다.

```c++
typedef struct _LDR_MODULE {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID BaseAddress;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;
```

```powershell
0:022> dx -r1 (*((ntdll!_LIST_ENTRY *)0x774a0c5c))
(*((ntdll!_LIST_ENTRY *)0x774a0c5c))                 [Type: _LIST_ENTRY]
    # [+0x000] Flink            : 0x1153940 [Type: _LIST_ENTRY *]
    [+0x004] Blink            : 0x42e6628 [Type: _LIST_ENTRY *]

0:022> dx -r1 ((ntdll!_LIST_ENTRY *)0x42e6628)
((ntdll!_LIST_ENTRY *)0x42e6628)                 : 0x42e6628 [Type: _LIST_ENTRY *]
    [+0x000] Flink            : 0x774a0c5c [Type: _LIST_ENTRY *]
    [+0x004] Blink            : 0x42e6368 [Type: _LIST_ENTRY *]

0:022> dx -r1 ((ntdll!_LIST_ENTRY *)0x42e6368)
((ntdll!_LIST_ENTRY *)0x42e6368)                 : 0x42e6368 [Type: _LIST_ENTRY *]
    [+0x000] Flink            : 0x42e6628 [Type: _LIST_ENTRY *]
    [+0x004] Blink            : 0x42e7c28 [Type: _LIST_ENTRY *]

```

다음과 같이 노드의 메모리 값을 확인하면 DLL이 존재하는 것을 확인할 수 있다.

```powershell
0:022> db 0x1154128 L?120
01154128  c8 3d 15 01 40 39 15 01-00 00 73 76 90 83 83 76  .=..@9....sv...v
01154138  00 a0 1f 00 44 00 46 00-00 42 15 01 1c 00 1e 00  ....D.F..B......
01154148  28 42 15 01 cc a2 08 00-ff ff 00 00 6c db 1b 01  (B..........l...
01154158  40 0a 4a 77 8b ee 77 98-00 00 00 00 00 00 00 00  @.Jw..w.........
01154168  c8 41 15 01 c8 41 15 01-c8 41 15 01 00 00 00 00  .A...A...A......
01154178  00 00 b5 76 b4 11 38 77-00 00 00 00 00 00 00 00  ...v..8w........
01154188  98 99 15 01 9c f6 15 01-cc fc 15 01 2c 3e 15 01  ............,>..
01154198  00 00 73 76 00 00 00 00-7d 52 6c cd 8f 16 d5 01  ..sv....}Rl.....
011541a8  c4 be 35 02 00 00 00 00-00 40 00 00 01 00 00 00  ..5......@......
011541b8  00 08 00 00 00 00 00 00-3d 4c da 3b 2b cc 00 0c  ........=L.;+...
011541c8  6c 41 15 01 6c 41 15 01-00 00 00 00 ff ff ff ff  lA..lA..........
011541d8  00 00 00 00 02 00 00 00-00 00 00 00 70 40 15 01  ............p@..
011541e8  09 00 00 00 00 00 00 00-02 00 00 00 00 00 00 00  ................
011541f8  30 4c da 36 3a cc 00 0a-43 00 3a 00 5c 00 57 00  0L.6:...C.:.\.W.
01154208  49 00 4e 00 44 00 4f 00-57 00 53 00 5c 00 53 00  I.N.D.O.W.S.\.S.
01154218  79 00 73 00 74 00 65 00-6d 00 33 00 32 00 5c 00  y.s.t.e.m.3.2.\.
01154228  4b 00 45 00 52 00 4e 00-45 00 4c 00 42 00 41 00  K.E.R.N.E.L.B.A.
01154238  53 00 45 00 2e 00 64 00-6c 00 6c 00 00 00 00 00  S.E...d.l.l.....
```

다음과 같이 노드의 메모리 값을 확인하면 DLL이 존재하는 것을 확인할 수 있다.

```powershell
0:022> u 0x76838390
KERNELBASE!KernelBaseDllInitialize:
76838390 8bff            mov     edi,edi
76838392 55              push    ebp
76838393 8bec            mov     ebp,esp
76838395 8b550c          mov     edx,dword ptr [ebp+0Ch]
76838398 8b4d08          mov     ecx,dword ptr [ebp+8]
7683839b 53              push    ebx
7683839c ff7510          push    dword ptr [ebp+10h]
7683839f e8ea000000      call    KERNELBASE!KernelBaseBaseDllInitialize (7683848e)
```

이 과정을 알고 있다면 리버싱 과정에서 DLL과 호출되는 API 함수들의 주소를 획득할 수 있을 것이다. 이 부분은 좀 더 공부 후 직접 코드를 작성 후에 포스팅할 예정이다.



## 0x03_PEB.ProcessHeap을 이용한 Anti-Debugging (x86 기준)
이 필드는 Heap의 구조체 주소를 가지고 있다. 이 곳을 보면 Ani-Debugging을 위해 이용되는 필드가 존재하는데 바로 DWORD 크기를 가지는 Flags(Offset 0x40)와 ForceFlags(Offset 0x44)이다. 오프셋의 경우 윈도우 7 이상부터 적용된 값이다. (x64의 경우 각각 Offset 0x70, Offset 0x74)

```c++
// Flags
HEAP_GROWABLE (2)
HEAP_TAIL_CHECKING_ENABLED (0x20)
HEAP_FREE_CHECKING_ENABLED (0x40)
HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000)
    
// ForceFlags
HEAP_TAIL_CHECKING_ENABLED (0x20)
HEAP_FREE_CHECKING_ENABLED (0x40)
HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000)
```

디버거를 통해 실행하여 확인한 값

```powershell
0:000> dt_PEB @$peb processheap
ntdll!_PEB
   +0x018 ProcessHeap : 0x00a20000 Void

0:000> dd 0x00a20000+0x40 L?1 # Flags
00a20040  40000062

0:000> dd 0x00a20000+0x44 L?1 # ForceFlags
00a20044  40000060
```

실행 후, 프로세스에 Attach하여 확인한 값

```powershell
0:005> dt_PEB @$peb processheap
ntdll!_PEB
   +0x018 ProcessHeap : 0x00ad0000 Void

0:005> dd 0x00ad0000+0x40 L?1 # Flags
00ad0040  00000002

0:005> dd 0x00ad0000+0x44 L?1 # ForceFlags
00ad0044  00000000
```

ForceFlags와 Flags에  값이 할당되는 점을 활용하여 안티 디버깅을 적용할 수 있을 것이다. 구현 시, 기본적으로 FS 또는 GS Register를 통해 접근해야 한다는 점을 잊지 말자. 참고로, GetProcessHeap() API로 동일하게 구현이 가능하다. 

다음은 ForceFlags의 값이 0이 아닌 경우 탐지를 수행하도록 한 ASM 코드이다.

```c++
mov eax, DWORD PTR FS:[30]
mov eax, DWORD PTR [eax+18]
cmp DWORD PTR ds:[eax+40], 0
jne Detected
```

이 방식을 알고 있다면 리버싱 과정에서 쉽게 우회가 가능할 것이다. (기본적으로 플러그인을 적용하면 자동으로 우회가 이루어진다.)
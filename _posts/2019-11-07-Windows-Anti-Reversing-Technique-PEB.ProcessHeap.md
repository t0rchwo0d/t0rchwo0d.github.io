---
title:  "Windows - Anti-Reversing Technique: PEB.ProcessHeap"
categories:
  - WINDOWS
tags:
  - ANTI
  - DEBUG
  - x64
  - MASM
---
# Anti-Reversing Technique: PEB.ProcessHeap

### 0x00_Description

이번에는 `PEB.Processheap`을 이용한 안티 디버깅에 대해서 정리하였다.



### 0x01_PEB.ProcessHeap

`Processheap`은 이름 그대로 프로세스 힙 구조체의 시작 주소를 지니고 있다.

```powershell
0:000> dt _peb @$peb ProcessHeap
ntdll!_PEB
   +0x030 ProcessHeap : 0x00000191`81810000 Void

0:000> !heap
    Heap Address      NT/Segment Heap
	19181810000              NT Heap
	191816c0000              NT Heap
```

이 중에서 디버깅 탐지 기법에는 `Flags`와 `ForceFlags`를 이용한다. 

```powershell
0:000> dt _heap F* 0x00000191`81810000
ntdll!_HEAP
   +0x040 FirstEntry : 0x00000191`81810740 _HEAP_ENTRY
   +0x070 Flags : 0x40000062
   +0x074 ForceFlags : 0x40000060
   +0x150 FreeLists : _LIST_ENTRY [ 0x00000191`81813d60 - 0x00000191`81817390 ]
   +0x198 FrontEndHeap : (null) 
   +0x1a0 FrontHeapLockCount : 0
   +0x1a2 FrontEndHeapType : 0 ''
   +0x1a8 FrontEndHeapUsageData : 0x00000191`81810750  ""
   +0x1b0 FrontEndHeapMaximumIndex : 0x80
   +0x1b2 FrontEndHeapStatusBitmap : [129]  ""

0:000> !heap
        Heap Address      NT/Segment Heap
	19181810000              NT Heap
	191816c0000              NT Heap

0:000> !heap -a 19181810000
Index   Address  Name      Debugging options enabled
  1:   19181810000 
    Segment at 0000019181810000 to 000001918190f000 (0000f000 bytes committed)
    Flags:                40000062
    ForceFlags:           40000060
# 생략
```

`Flags`와 `ForceFlags` 이 두 값은 `NtGlobalFlag`에 <u>Set</u>되는 `Flag` 정보를 참조하여 디버거에서 실행 시, 특정 `Flag`가 Set된다.
>
> HEAP_TAIL_CHECKING_ENABLED  (0x20) == FLG_HEAP_ENABLE_TAIL_CHECK
>
> HEAP_FREE_CHECKING_ENABLED  (0x40) == FLG_HEAP_ENABLE_FREE_CHECK
>
> HEAP_VALIDATE_PARAMETERS_ENABLED  (0x40000000) == FLG_HEAP_VALIDATE_PARAMETERS
>

"Windows Internals 5th"에서는 이 3개의 플래그는 디버거에서 프로세스를 실행 할 때, 로더로 인하여 자동으로 활성화 되는 값이며 이 디버깅 옵션 값들은 다음과 같은 기능을 수행한다고 명세되어 있다. (예전 책이라 윈도우 10은 다를 수 있다…)

| Flags                                         | Description                                                  |
| :-------------------------------------------- | :----------------------------------------------------------- |
| HEAP_TAIL_CHECKING_ENABLED (0x20)             | 활성화 블록이 해제될 때 해당 블록의 정상 유무를 검사하기 위해 각 블록의 끝에 시그니처 값을 포함한다. 버퍼오버런에 의해 시그니처 값이 손상되면 예외를 발생 |
| HEAP_FREE_CHECKING_ENABLED (0x40)             | 활성화 해제된 블록은 특정한 패턴으로 값이 채워져 힙 관리자가 해당 블록에 접근 할 필요가 있을 경우 검사를 수행한다. 이 때 해제된 블록에 쓰기가 수행된 경우 이를 감지하고 예외를 발생 |
| HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000) | 힙 함수로 전달되는 인자들에 대한 검사를 수행                 |

지금까지 데이터 구조 기준 탐지 기법을 정리하면서 빼먹은 부분이 있는데 탐지하는 로직을 구현할 때는 OS 버전 & 빌드 버전 별로 오프셋이 변경될 수 있어서 포괄적으로 구현할 때는 조심해야한다. (특히, 드라이버 단에서 구현할 때 주의해야 한다.)

예를 들면 아래와 같은 코드 형태가 된다.

```c
#ifdef _WIN64
    IsWindows7OrGreater() ? offsetHeapFlag=0x70 : offsetHeapFlag=0x14;
    IsWindows7OrGreater() ? offsetHeapForce=0x74 : offsetHeapForce=0x18;
    this->pPeb = (PVOID)__readgsqword(0x0C * sizeof(PVOID));
    offsetProcessHeap = 0x30;
#else
    IsWindows7OrGreater() ? offsetHeapFlag = 0x40 : offsetHeapFlag = 0x0C;
    IsWindows7OrGreater() ? offsetHeapForce = 0x44 : offsetHeapForce = 0x10;
    this->pPeb = (PVOID)__readfsdword(0x0C * sizeof(PVOID));
    offsetProcessHeap = 0x18;
#endif
```

이전에 얘기했던 `MASM`으로 이 기법을 이용한 탐지 로직을 구현해 보았다. (구현에만 초점을 맞춰 ASM 코드를 작성하다 보니 아래와 같이 `RAX` 레지스터만 주로 사용하는 코드가 되었다…) 참고로, `NtGlobalFlag`와 동일하게 디버깅 시에 세팅되는 값으로 탐지를 우회하고 디버깅을 하고 싶으면 실행하고 붙이는 방법도 있다.

```c
/* flag.asm */
.code
HeapFlagCheck proc
    sub rsp, 20h
    test rax, rax
    mov rax, gs:[60h]
    add rax, 30h
    mov rax, qword ptr [rax]
    add rax, 70h
    push rax
    mov eax, dword ptr[rax]
    xor eax, 40000060h
    cmp eax, 2h
    jne HeapFlagCheck+45h
    pop rax
    add rax, 4h
    mov eax, dword ptr[rax]
    xor eax, 40000060h
    cmp eax, 0
    jne HeapFlagCheck+45h
    add rsp, 20h
    mov rax, 1h
    ret
    pop rax
    mov rax, 0h
    add rsp, 20h
    ret
HeapFlagCheck endp
end
```

```c
/* main.cpp */
#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <winternl.h>

using namespace std;

extern "C" {
    bool HeapFlagCheck();
}

int main() {
    if (HeapFlagCheck()) {
        cout << "[+] T_T" << endl;
        return -1;
    }
    cout << "[+] ^_^" << endl;
    system("pause");
    return 0;
}
```

위 `MASM` 기반 탐지 코드를 실행하면 나름 잘 동작한다.

```powershell
0:000> r
rax=0000000000000001 rbx=00007ff9a2a2b570 rcx=0000000000000001
rdx=0000016406a96390 rsi=0000000000000000 rdi=0000016406a96390
rip=00007ff682741344 rsp=0000002fe8f4fb68 rbp=0000000000000000
 r8=0000016406a96620  r9=0000000000000470 r10=0000000000000000
r11=0000002fe8f4fb30 r12=0000000000000000 r13=0000000000000000
r14=0000000000000000 r15=0000000000000000
iopl=0         nv up ei pl nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
Test!HeapFlagCheck+0x44:
00007ff6`82741344 c3              ret

0:000> uf 00007ff6`82741300
Test!HeapFlagCheck [C:\Users\t0rchwo0d\Test\flag.asm @ 2]:
    2 00007ff6`82741300 4883ec20        sub     rsp,20h
    4 00007ff6`82741304 4885c0          test    rax,rax
    5 00007ff6`82741307 65488b042560000000 mov   rax,qword ptr gs:[60h]
    6 00007ff6`82741310 4883c030        add     rax,30h
    7 00007ff6`82741314 488b00          mov     rax,qword ptr [rax]
    8 00007ff6`82741317 4883c070        add     rax,70h
    9 00007ff6`8274131b 50              push    rax
   10 00007ff6`8274131c 8b00            mov     eax,dword ptr [rax]
   11 00007ff6`8274131e 3560000040      xor     eax,40000060h
   12 00007ff6`82741323 83f802          cmp     eax,2
   13 00007ff6`82741326 751d            jne     Test!HeapFlagCheck+0x45 (00007ff6`82741345)  Branch
Test!HeapFlagCheck+0x28 [C:\Users\t0rchwo0d\Test\flag.asm @ 14]:
   14 00007ff6`82741328 58              pop     rax
   15 00007ff6`82741329 4883c004        add     rax,4
   16 00007ff6`8274132d 8b00            mov     eax,dword ptr [rax]
   17 00007ff6`8274132f 3560000040      xor     eax,40000060h
   18 00007ff6`82741334 83f800          cmp     eax,0
   19 00007ff6`82741337 750c            jne     Test!HeapFlagCheck+0x45 (00007ff6`82741345)  Branch
Test!HeapFlagCheck+0x39 [C:\Users\t0rchwo0d\Test\flag.asm @ 20]:
   20 00007ff6`82741339 4883c420        add     rsp,20h
   21 00007ff6`8274133d 48c7c001000000  mov     rax,1
   22 00007ff6`82741344 c3              ret
Test!HeapFlagCheck+0x45 [C:\Users\t0rchwo0d\Test\flag.asm @ 23]:
   23 00007ff6`82741345 58              pop     rax
   24 00007ff6`82741346 48c7c000000000  mov     rax,0
   25 00007ff6`8274134d 4883c420        add     rsp,20h
   26 00007ff6`82741351 c3              ret
```

`Windbg`를 이용하여 실행 시, 다음과 같은 결과를 확인할 수 있다.

```powershell
[+] T_T
```



### 0x02_Bypass

 `WinDbg`를 사용하여 PEB에서 Heap의 주소를 가져와 메모리 내용을 조작하는 방식으로 우회가 쉽게 가능하다.



### 0x03_PoC (YouTube)

[![Windows Anti-Reversing Technique - PEB.ProcessHeap](http://img.youtube.com/vi/pG8uFx954Zs/0.jpg)](https://youtu.be/pG8uFx954Zs?t=0s) 

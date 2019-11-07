---
title:  "Windows - Anti-Reversing Technique: GetThreadContext()"
categories:
  - WINDOWS
tags:
  - ANTI-DEBUGGING
  - PROCESS
  - BYPASS
---
# Anti-Reversing Technique: GetThreadContext()
## 0x00_Description
Packing된 프로그램의 경우 디버깅을 방지하기 위해서 `CC Detection`과 같은 디버깅 방지 기법이 적용되어 있다. 때문에 리버서는 `Hardware Breakpoint`를 이용하여 IMAGE_SECTION_HEADER의 text 영역에 Write HWBP를 설치하고 진행을 하는 경우가 존재한다.  

HWBP가 설치되면 `Dr Register(Debug Register)`에 0이 아닌 값이 할당되는데 이 점을 이용하여 `GetThreadContext()` 함수로 Dr Register 값을 획득 후, 0이 아닌 경우 탐지를 수행할 수 있다.

## 0x01_GetThreadContext()

이 함수는 이름 그대로 Thread Context 정보를 가져오는 함수로 [MSDN](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-getthreadcontext)을 살펴보면 다음과 같은 형태를 지닌다.

```c++
BOOL GetThreadContext(
    HANDLE    hThread,
    LPCONTEXT lpContext
);
```

중요한 Parameter는 `LPCONTEXT(&CONTEXT)`로 해당 함수에 전달할 때 `ContextFlags` 값을 설정하고 전달해야 원하는 값을 획득할 수 있다. 이 ContextFlags는 Control Flags 중 하나로 `winnt.h`에 다음과 같이 정의되어 있다.

```c++
typedef struct DECLSPEC_ALIGN(16) DECLSPEC_NOINITALL _CONTEXT {

        //
        // Register parameter home addresses.
        //
        // N.B. These fields are for convience - they could be used to extend the
        //      context record in the future.
        //

        DWORD64 P1Home;
        DWORD64 P2Home;
        DWORD64 P3Home;
        DWORD64 P4Home;
        DWORD64 P5Home;
        DWORD64 P6Home;

        //
        // Control flags.
        //

        DWORD ContextFlags;
        DWORD MxCsr;

        //
        // Segment Registers and processor flags.
        //

        WORD   SegCs;
        WORD   SegDs;
        WORD   SegEs;
        WORD   SegFs;
        WORD   SegGs;
        WORD   SegSs;
        DWORD EFlags;

        //
        // Debug registers
        //

        DWORD64 Dr0;
        DWORD64 Dr1;
        DWORD64 Dr2;
        DWORD64 Dr3;
        DWORD64 Dr6;
        DWORD64 Dr7;
    
    /* ... 생략 ... */
}
```

보통 `CONTEXT_DEBUG_REGISTER` 값을 넘겨 Dr의 값을 획득한다. 다음은 `winnt.h`에 정의되어 있는 Flags 값들의 정의다. 이 것을 보면 알겠지만 `CONTEXT_ALL`을 통해 모든 정보를 획득하여 검증을 수행할 수 있다.

```c++
#define CONTEXT_CONTROL         (CONTEXT_AMD64 | 0x00000001L)
#define CONTEXT_INTEGER         (CONTEXT_AMD64 | 0x00000002L)
#define CONTEXT_SEGMENTS        (CONTEXT_AMD64 | 0x00000004L)
#define CONTEXT_FLOATING_POINT  (CONTEXT_AMD64 | 0x00000008L)
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_AMD64 | 0x00000010L)

#define CONTEXT_FULL            (CONTEXT_CONTROL | CONTEXT_INTEGER | \
CONTEXT_FLOATING_POINT)

#define CONTEXT_ALL             (CONTEXT_CONTROL | CONTEXT_INTEGER | \
CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | \
CONTEXT_DEBUG_REGISTERS)

#define CONTEXT_XSTATE          (CONTEXT_AMD64 | 0x00000040L)
```

## 0x02_Bypass

이 검증 로직에 대한 우회 방안에 대해서 참조 정보 없이 나름 생각해보았다. `GetContextThread()` 함수는 내부적으로 `ZwGetContextThread()`를 호출하는데 ZwGetContextThread() 내부적으로 Define된 플래그를 참조할 것이므로 이 값을 찾아 0으로 변조하는 `x64dbg Script`를 작성하여 우회가 가능하였다.

이 값은 x64 환경에서는 ZwGetContextThread()에 BP가 걸린 시점에서 `rdx` 기준으로 30 Bytes 떨어진 곳에 저장되어 있었다.

## 0x03_PoC (YouTube)
[![Windows Process Injection Technique - Reflective DLL Injection](http://img.youtube.com/vi/VATsQVuymXo/0.jpg)](https://youtu.be/VATsQVuymXo?t=0s) 


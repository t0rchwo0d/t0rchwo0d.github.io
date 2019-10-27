---
title:  "Windows - User Mode Debugging Mechanism"
categories:
  - WINDOWS
tags:
  - DEBUG
---
# User Mode Debugging Mechanism
## 1. Description
이번 문서에서는 Only 이론적인 부분으로 개인적인 호기심으로 유저 모드 디버깅이 윈도우 OS에서 어떤 구성을 가지는지 궁금해서 정리하였다. 그런데 이 부분은 이해가 어려워 보고 또 보고 다시 정리해봐야 할 듯...

윈도우에서는 유저모드 디버깅을 지원하기 위해 3가지 요소가 있는데 각각 Executive(커널), Ntdll.dll(네이티브), Kernel32.dll(서브 시스템)이다. 지금부터 각각 요소에 대해서 Araboza.



## 2. 커널 지원 (Executive)
`Executive`는 윈도우 커널 영역의 관리 시스템으로 설명보다 다음 그림을 보는 것이 이해가 더 쉽다. 이 Executive 내부에 dbgk(디버깅 프레임워크)가 존재하는데 디버그 이벤트 등록, 리스닝, 객체 관리, 유저 모드와 통신하기 위한 디버깅 정보 정리 등의 역할을 수행한다. 그러니까 심플하게 OS 관리 영역이다. (이 부분은 커널 드라이버를 이용한 안티 디버깅 영역에서 다시 한번 만날 것 같은 느낌적인 느낌이다…)

![2019-10-27-Windows-User-Mode-Debugging-Mechanism_001](https://t0rchwo0d.github.io//assets/images/2019-10-27-Windows-User-Mode-Debugging-Mechanism_001.png)



윈도우 커널은 디버그 객체를 통해서 유저 모드 디버깅을 지원하며 일반적으로 먼저 `DbgUi 계층`을 통해 접근하는 대부분 디버깅 API와 맵핑된 `System Call`을 수행한다. 

디버그 객체는 상태 플래그와 디버거 이벤트 알림, 처리를 기다리는 디버그 이벤트 리스트, 객체를 락하는 데 사용되는 <u>패스트 뮤텍스</u>로 구성된 Construct로 모든 정보가 커널이 디버거 이벤트를 처리하는데 필요하다.

> FAST_MUTEX (for Device Driver Development)
>
> - 한 시점에 단 하나의 스레드만 뮤텍스 오브젝트를 획득할 수 있도록 한다.
> - 데드락 방지 기법이 없다.
> - 반복적으로 획득할 수 없다. 이는 뮤텍스 획득&해제 과정에서 뮤텍스 오브젝트를 얻기 위해 대기중인 스레드가 없는 상황을 최적화 하였기 때문이다.
> - ExAcquireFastMutex(), ExReleaseFastMutex() : IRQL을 APC_LEVEL로 상승시키며 자동으로 APC를 차단한다.
> - 커널이 제공하지 않으며, Windows 서브 시스템이 제공한다. (HAL.DLL에 구현되어 있다.) 
>
> | **Kernel Mutex Object**              | **Fast Mutex Object**                                |
> | ------------------------------------ | ---------------------------------------------------- |
> | Slow                                 | Fast                                                 |
> | 하나의 스레드가 반복적으로 요청 가능 | 반복적으로 획득 불가능                               |
> | 특별한 형식의 APC 수신 가능          | XXXUnSafe()를 사용하지 않으면 어떤 APC도 수신 불가능 |



디버깅되는 각 프로세스는 자신의 구조체에 디버그 객체를 가리키는 디버그 포트 멤버를 가지고 있다. 이 포트를 통해서 발생되는 디버그 이벤트가 이벤트 리스트에 삽입된다.

```c++
// 디버그 이벤트 구조체
typedef struct _DEBUG_EVENT {
    LIST_ENTRY EventList;
    KEVENT ContinueEvent;
    CLIENT_ID ClientId;
    PEPROCESS Process;
    PETHREAD Thread;
    NTSTATUS Status;
    ULONG Flags;
    PETHREAD BackoutThread;
    DBGKM_MSG ApiMsg;
} DEBUG_EVENT, *PDEBUG_EVENT;

// 디버그 메시지 구조체
typedef struct _DBGKM_MSG {
    PORT_MESSAGE h;
    DBGKM_APINUMBER ApiNumber;
    ULONG ReturnedStatus;
    union {
        DBGKM_EXCEPTION Exception;
        DBGKM_CREATE_THREAD CreateThread;
        DBGKM_CREATE_PROCESS CreateProcess;
        DBGKM_EXIT_THREAD ExitThread;
        DBGKM_EXIT_PROCESS ExitProcess;
        DBGKM_LOAD_DLL LoadDll;
        DBGKM_UNLOAD_DLL UnloadDll;
    };
}
```



다음은 디버깅 이벤트를 정리한 내용이며 이 이벤트 외에도 특별한 디버거 트리거 조건들이 다수 있다. (현재 윈도우 OS에서는 내용이 상이할 수 있다.)

| 이벤트 유형           | 의미                              | 트리거 조건                                                  |
| --------------------- | --------------------------------- | :----------------------------------------------------------- |
| DbgKmExceptionApi     | 예외 발생                         | 유저모드에서 예외가 발생하여   KiDispatchException 호출      |
| DbgKmCreateThreadApi  | 스레드 생성                       | 유저모드 스레드 시작                                         |
| DbgKmCreateProcessApi | 프로세스 생성                     | 프로세스 내의 첫 번째 유저모드 스레드 시작                   |
| DbgKmExitThreadApi    | 스레드 종료                       | 유저모드 스레드 종료                                         |
| DbgKmExitProcessApi   | 프로세스 종료                     | 프로세스 내의 마지막 유저모드 스레드 종료                    |
| DbgKmLoadDllApi       | DLL 로드                          | EXE 또는 DLL이 로드 과정에서 섹션 이미지 파일을 처리를 위해 NtMapViewOfSection 호출 |
| DbgKmUnloadDllApi     | DLL 언로드                        | EXE 또는 DLL이 언로드 과정에서 섹션 이미지 파일을 처리를 위해 NtUnmapViewOfSection 호출 |
| DbgKmErrorReportApi   | 윈도우 오류 보고(WER)로 전송 필요 | 유저모드에서 예외가 발생하여   KiDispatchException 호출된 상황에서 디버가 예외를 처리할 수 없는 경우 |



디버거가 Attach 될 때 일어나는 과정은 다음과 같다.

> - Create Process와 주 스레드에 대한 Create Thread 메시지 전송
> - 프로세스 내의 기타 다른 모든 스레드에 대한      Create thread 메시지 전송
> - 디버깅되는 실행      파일(Ntdll.dll)에 대한 Load DLL 이벤트 전송
> - 디버깅되는 프로세스 내에 로드된 현재      DLL에 대한 이벤트 전송

디버거 객체가 다른 프로세스와 연관됐다면 프로세스 내의 모든 스레드는 서스펜드된다. 이 시점에서 디버거 이벤트에 대한 전송 요청 시작은 디버거가 수행한다. 

디버거는 디버그 객체에 대한 Wait를 수행하여 디버그 이벤트가 유저모드로 전환되도록 요청한다. 이 요청은 디버그 이벤트의 리스트를 순차적으로 순회하면서 각 요청이 리스트에서 제거되는 과정에서 디버그 이벤트의 내용이 내부 dbgk 구조체에서 바로 상위 계층이 이해하는 Navite 구조체로 변경된다. 이 구조체는 Win32 구조체와 다르며 다른 계층에 대한 변환도 일어난다. 

디버거가 펜딩된 모든 메시지를 처리한 이후에도 커널은 자동으로 프로세스를 재개하지 않는다. 실행 재개를 위해 `ContinueDebugEvent` 함수를 호출하는 것은 디버거가 담당한다.

결론적으로 디버그 프레임워크의 기본 모델은 디버그 이벤트를 생성하는 커널 내의 `Producers`와 디버그 이벤트에 대한 대기와 송신을 수행하는 디버거인 `Consumers` 간에 일어나는 활동이다.



## 3. 네이티브 지원 (Ntdll.dll)
유저모드 디버깅 기본 프로토콜은 단순하지만 애플리케이션단에서는 직접 사용할 수 없다. 이 프로토콜은 `Ntdll.dll` 내의 `DbgUi 함수`로 래핑되어 있다. Ntdll.dll 내부의 코드는 의존성이 없기 때문에 다른 서브 시스템과 네이티브 애플리케이션이 이들 루틴을 사용하기 위해 이런 추상화(랩퍼 함수)가 필요하다. DbgUi라는 이름으로 시작하는 API를 이용하여 Executive 내의 dpgk(디버그 프레임워크)와 대화를 수행한다. 이 API들은 디버그 객체 구현의 포장(?)을 담당하는데 이 디버그 객체 구현과 관련된 부분은 `Undocumented`다. 

결론적으로 이 Ntdll.dll 내부의 DbgUi라는 API를 통해 서브 시스템 애플리케이션(디버거)들이 공개된 API(사용할 수 있는 API)를 통해 디버깅을 수행할 수 있도록 한다. 이 DbgUi로 시작하는 API는 다음과 같이 WinDbg에서 확인할 수 있다. 참고로 서브 시스템은 말그대로 윈도우 OS를 보조하는 시스템들인데 이 구성 요소들은 항상 실행 중이여야 윈도우가 동작한다.

```powershell
2:008> x /D /f ntdll!dbgui*
  A B C D E F G H I J K L M N O P Q R S T U V W X Y Z

00007ffb`ef719500 ntdll!DbgUiStopDebugging (DbgUiStopDebugging)
00007ffb`ef7190e0 ntdll!DbgUiConvertStateChangeStructureEx (DbgUiConvertStateChangeStructureEx)
00007ffb`ef719030 ntdll!DbgUiConnectToDbg (DbgUiConnectToDbg)
00007ffb`ef719520 ntdll!DbgUiWaitStateChange (DbgUiWaitStateChange)
00007ffb`ef719410 ntdll!DbgUiIssueRemoteBreakin (DbgUiIssueRemoteBreakin)
00007ffb`ef719380 ntdll!DbgUiDebugActiveProcess (DbgUiDebugActiveProcess)
00007ffb`ef7190e8 ntdll!DbgUiConvertStateChangeStructureWorker (DbgUiConvertStateChangeStructureWorker)
00007ffb`ef7194e0 ntdll!DbgUiSetThreadDebugObject (DbgUiSetThreadDebugObject)
00007ffb`ef7190d0 ntdll!DbgUiConvertStateChangeStructure (DbgUiConvertStateChangeStructure)
00007ffb`ef719480 ntdll!DbgUiRemoteBreakin (DbgUiRemoteBreakin)
00007ffb`ef7190a0 ntdll!DbgUiContinue (DbgUiContinue)
00007ffb`ef7193f0 ntdll!DbgUiGetThreadDebugObject (DbgUiGetThreadDebugObject)
```

이 래핑을 통해 제공하는 함수는 윈도우 API 함수와 거의 유사하며 시스템 호출(System Call)과 관련된다. 래퍼 함수 내부 코드 또한 스레드와 연관된 다버그 객체를 생성하는데 필요한 기능을 제공한다. 생성된 디버그 객체에 대한 핸들은 노출되지 않으며 연결을 수행하는 디버거 스레드의 `TEB 구조체의 DbgSsReserved[1]`에 저장된다.

디버거가 프로세스에 연결되고 프로세스로 인젝션되는 스레드에 의해 발생하는 `int 3` 동작이 이뤄져야 한다. 그렇지 않다면 디버거는 프로세스 제어권을 획득할 수 없다. Ntdll.dll은 이 인젝션되는 스레드를 생성해 대상 프로세스 내로 인젝션한다.



## 3. 윈도우 서브 시스템 지원 (Kernel32.dll)
서브 시스템이 이용할 수 있는 DLL인 `Kernel32.dll` 내부에는 디버그 처리를 위한 API들이 존재한다. 이 `API`들을 활용하여 각 서브 시스템들이 다른 애플리케이션에 대한 <u>디버깅 수행과 개발자들이 활용할 수 있도록 문서화</u>되어 있다. 이 뿐만 아니라 중요한 관리 작업이 하나 더 있다. `복사된 파일(이미지)과 스레드 핸들을 관리`하는 것이다. 

Create Process 이벤트 동안 <u>프로세스 핸들에 Load DLL 이벤트가 보내질 때</u>마다 이미지 파일에 대한 핸들이 커널에 의해 복사되어 이벤트 구조체에 전달된다. 이 과정에서 `Kernel32. dll`은 각 대기(Wait) 상태인 대상에 대한 이벤트가 커널로부터 복사된 새로운 프로세스와 스레드 핸들이 생성되는 <u>이벤트(두 개의 Create 이벤트)인지를 검사</u>한다.  <u>해당 이벤트에 해당</u>한다면 `Kernel32. dll`은 구조체를 할당해 이곳에 프로세스 ID와 스레드 ID, 이벤트와 연관된 스레드와 프로세스 <u>핸들을 저장</u>한다. 

이 할당된 구조체는 `TEB` 내의 `DbgSsReserved`의 첫 번째 인덱스에 연결된다. `TEB`는 위 네이티브 지원 부분에서 언급한 바와 같이 디버그 객체 핸들이 저장되는 곳이기도 하다. 추가로 `Kernel32.dll`은 종료(Exit) 이벤트 또한 검사하며 이런 이벤트를 탐지할 때, 데이터 구조체 내에 해당 핸들을 표시(설정)한다. 

디버거가 핸들 사용을 마치고 `Continue 호출`을 수행하면 `Kernel32.dll`은 이 이벤트 구조체를 파싱해 종료된 스레드의 핸들이 있는지 찾아서 디버거를 위해 해당 핸들을 닫는다. 이렇게 하지 않는다면 디버거가 실행한 스레드와 프로세스의 오픈된 핸들이 항상 존재하여 종료하지 않는다.

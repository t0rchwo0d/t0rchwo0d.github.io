---
title:  "Windows - Kernel Memory Dump"
categories:
  - WINDOWS
tags:
  - DRIVER
  - KERNEL
  - DEBUG
---
# Kernel Memory Dump
## 0x00_Description
Debugger로 부터 Driver Module(*.sys)를 Hiding하는 Driver가 존재하는 경우가 있다. 필자가 본 프로그램의 경우 VM Detection이 포함된 Packer가 함께 적용되어 있어 있었다. 이 프로그램이 정상적으로 실행이 되지 않은 상태에서는 Dump를 떠도 Disassembler를 통해 일부 코드만 확인이 가능하였다. 

때문에 두 가지 선택지가 있었는데 하나는 VM Detection을 우회하여 정상적으로 실행하는 방법 또는 Host에서 정상 실행 후, 강제로 Kernel Crash를 발생시켜 커널 메모리를 덤프뜨는 방법이다.

본 문서는  Manual Kernel Crash를 발생시켜 자동으로 Memory Dump를 수행하고 WinDBG를 이용하여 Kernel Memory 내에서 Driver Module을 덤프뜨는 방법에 대하여 정리하였다. 이 방법은 정적 분석을 함께 진행하기 위해서이며 결국 제대로 분석을 위해서는 VM Detection을 우회하여 동적 분석을 함께 진행해야 한다.

## 0x01_Windows Registry Setup

윈도우에서는 Crash가 발생한 시점에 Kernel Memory Dump 생성을 위한 옵션을 제공한다. 이 옵션은 `시스템 속성 > 고급 > 시작 및 복구 > 설정` 메뉴에 접근하여 `디버깅 정보 쓰기` 항목에서 설정과 Dump 파일의 경로를 확인할 수 있다. 또한, [Registry](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/reg-query)의 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl`에서도 현재 상태를 확인 할 수 있다.

```powershell
C:\Users\t0rchwo0dλ reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl /s
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl                         
        AutoReboot    REG_DWORD    0x1
        CrashDumpEnabled    REG_DWORD    0x7
        DumpFile    REG_EXPAND_SZ    %SystemRoot%\MEMORY.DMP
        DumpFilters    REG_MULTI_SZ    dumpfve.sys
        LogEvent    REG_DWORD    0x1
        MinidumpDir    REG_EXPAND_SZ    %SystemRoot%\Minidump
        MinidumpsCount    REG_DWORD    0x5
        Overwrite    REG_DWORD    0x1
                                                                                      
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\FullLiveKernelReports
        LastFullLiveReport    REG_QWORD    0x1d51a713093363f
        
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\FullLiveKernelReports\win32k.sys         
        LastFullLiveReport    REG_QWORD    0x1d51a713093363f
        
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\LiveKernelReports                                    
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\LiveKernelReports\win32k.sys

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\StorageTelemetry     
        DeviceDumpEnabled    REG_DWORD    0x1
        StorageTCCode_0    REG_DWORD    0x77
        StorageTCCode_1    REG_DWORD    0x7a
        StorageTCCode_2    REG_DWORD    0x7b
        StorageTCCode_3    REG_DWORD    0x69696969  
```

여기서 중요한 값은 `CrashDumpEnabled`인데 [MSDN](https://support.microsoft.com/en-us/help/254649/overview-of-memory-dump-file-options-for-windows)을 참조하면 각 세팅 값은 다음과 같다. 이 값이 설정된 상태에 따라 GUI에 설정된 값이 출력된다.

```powershell
CrashDumpEnabled REG_DWORD 0x0 = None
CrashDumpEnabled REG_DWORD 0x1 = Complete memory dump
CrashDumpEnabled REG_DWORD 0x2 = Kernel memory dump
CrashDumpEnabled REG_DWORD 0x3 = Small memory dump (64KB)
CrashDumpEnabled REG_DWORD 0x7 = Automatic memory dump
```

사용자의 Key 입력으로 원하는 시점에 Dump를 수행하기 위해서는 Keyboard 설정을 수행해야한다. 설정을 위한 Registry 값 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\kbhid\Parameters`와 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\i8042prt\Parameters`로 kbhid는 USB로 연결된 keyboard, i8042prt는 일반 keyboard이다.

관리자 권한으로 다음과 같이 registry 편집 수행 후, 재부팅을 하고 `[Right Ctrl]+([Scroll Lock] * 2)`를 통해 강제로 Crash를 발생시켜 메모리 지정된 위치에 Dump 생성이 가능하다.

```powershell
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl" /v "CrashDumpEnabled" /t "REG_DWORD" /d "0x01"
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\kbhid\Parameters" /v "CrashOnCtrlScroll" /t "REG_DWORD" /d "0x01"
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\i8042prt\Parameters" /v "CrashOnCtrlScroll" /t "REG_DWORD" /d "0x01"

C:\Users\t0rchwo0d
λ reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl /s

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl
        AutoReboot    REG_DWORD    0x1
        CrashDumpEnabled    REG_DWORD    0x2
```

## 0x02_WinDBG
지정된 경로에서 Dump 파일 생성을 확인하고 WinDBG를 관리자 권한으로 실행하여 해당 파일을 불러온다. [lm ](https://docs.microsoft.com/ko-kr/windows-hardware/drivers/debugger/lm--list-loaded-modules-)명령을 통해 원하는 Module의 주소를 확인한다. 이 때, 해당 모듈이 존재하지 않는다면 ProcessHacker와 같은 툴을 이용하여 SYSTEM Process나 Target Process에서 해당 sys 파일의 주소를 확인하여 해당 주소를 살펴보고 Dump를 진행해야 한다. (이 방법은 Kernel Debugging 상황에서도 동일)

우선 Target Module의 정보를 확인한다.

```powershell
0: kd> lmDvmhvsocketcontrol
Browse full module list
start             end                 module name
fffff802`71740000 fffff802`7174d000   hvsocketcontrol   (pdb symbols)          C:\ProgramData\Dbg\sym\HvSocketControl.pdb\45E71B2278AF2E8CC0B4BFDB18803D241\HvSocketControl.pdb
        Loaded symbol image file: hvsocketcontrol.sys
        Image path: \SystemRoot\system32\drivers\hvsocketcontrol.sys
        Image name: hvsocketcontrol.sys
        Browse all global symbols  functions  data
        Image was built with /Brepro flag.
        Timestamp:        080BABF1 (This is a reproducible build file hash, not a timestamp)
        CheckSum:         00011AA1
        ImageSize:        0000D000
```

sys 파일 또한 PE 구조와 유사하기 때문에 0x1000 Offset 위치에서 코드를 확인할 수 있다.

```powershell
: kd> uf fffff802`71741000
hvsocketcontrol!WPP_SF_+0xffffffff`fffffff8:
fffff802`71741000 cc              int     3
fffff802`71741001 cc              int     3
fffff802`71741002 cc              int     3
fffff802`71741003 cc              int     3
fffff802`71741004 cc              int     3
fffff802`71741005 cc              int     3
fffff802`71741006 cc              int     3
fffff802`71741007 cc              int     3
fffff802`71741008 4883ec38        sub     rsp,38h
fffff802`7174100c 488b0595220000  mov     rax,qword ptr [hvsocketcontrol!pfnWppTraceMessage (fffff802`717432a8)]
fffff802`71741013 4c8d057e140000  lea     r8,[hvsocketcontrol!WPP_54b6d39bdcde3e0047e5b67313e97012_Traceguids (fffff802`71742498)]
fffff802`7174101a 488364242000    and     qword ptr [rsp+20h],0
fffff802`71741020 ba10000000      mov     edx,10h
fffff802`71741025 440fb7ca        movzx   r9d,dx
fffff802`71741029 ba2b000000      mov     edx,2Bh
fffff802`7174102e ff158c410000    call    qword ptr [hvsocketcontrol!_guard_dispatch_icall_fptr (fffff802`717451c0)]
fffff802`71741034 4883c438        add     rsp,38h
fffff802`71741038 c3              ret
```

이제 원하는 위치에 위에서 확인한 ImageSize 크기만큼 Dump를 진행하고 Disasembler에서 분석을 진행하면된다.

```powershell
0: kd> .writemem d:\t0rchwo0d.sys fffff802`71740000 L?0000D000
Writing D000 bytes...................
```




---
title:  "Windows - WinDbg Extensions"
categories:
  - WINDOWS
tags:
  - WINDBG
  - PLUGIN
  - EXTENSION
  - REVERSE
---
# WinDbg Extensions
## 0x00_Description
윈도우 Debugger인 WinDbg의 확장 모듈들에 대한 정리로 [여기를 참조](https://github.com/bruce30262/TWindbg)하여 쓸만한 모듈들에 대한 설정 및 기본 활용 방법을 명세하였다.

## 0x01_WinDbg Preview
윈도우 10에서 사용가능한 WinDbg Preview 버전의 경우 32, 64 Binary에 따라 자동으로 실행되는 바이너리가 변경되므로 32, 64를 동시에 사용하기 위해서는 확장 모듈의 이름을 32, 64로 구분을 지어서 적용해야 한다. 이를 위한 [환경 변수](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/loading-debugger-extension-dlls)가 존재하며 **_NT_DEBUGGER_EXTENSION_PATH** 환경 변수에 원하는 모듈의 경로를 설정하여 WinDbg 커맨드에서 다음 명령을 통해 로드할 수 있다.

```powershell
# 환경 변수 확인
> .extpath

# 모듈 적용
> .load [MODULE_NAME]

# 모듈 사용 예시
!py -g "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\winext\TWindbg\TWindbg.py"
```



## 0x02_List Up

- [pykd](https://githomelab.ru/pykd/pykd) - *Python extension for WinDbg*
  
  - Link에 접근하여 원하는 버전의 pykd 다운로드
  
  - 참고로 "pykd-0.3.4.6-cp27-none-win32.whl"에서 cp는 Python 버전
  
  - whl 파일을 pip로 설치
  
    - windbg_x86 또는 windbg_64에 따라 다른 버전으로 빌드해야하며 python 버전 또한 아키텍쳐에 맞게 되어야한다.
    
  - [WIN]+[X]를 통해 관리자 권한으로 파워쉘 실행 후 진행
  
    ```powershell
    # Python27amd64
    pip install pykd-0.3.4.6-cp27-none-win_amd64.whl
    
    cd C:\Python27amd64\Lib\site-packages\pykd
    cp *.dll "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\winext\"
    cp *.pyd "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\winext\"
    ```
    
  - WinDbg 실행 후, 실행 파일 열기
  
  - Command 창에서 ".load pykd.pyd"를 로드
  
  - "!py"을 통해 Python 이용 가능
  
    
  
- [TWinDbg](https://github.com/bruce30262/TWindbg) - *PEDA-like debugger UI for WinDbg*

  - pykd가 설치된 상태에서 압축 해제된 "TWindbg"폴더를 "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\winext\\" 복사

  - 실행 파일 오픈 후, Command 창 에서 아래 명령을 통해 적용

    ```powershell
    .load pykd.pyd
    !py -g "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\winext\TWindbg\TWindbg.py"
    ```
  - "TWindbg"를 입력하면 추가된 2가지 명령의 설명을 확인할 수 있다.
    

---
title:  "Windows - Kernel Debugging In Hyper-V"
categories:
  - WINDOWS
tags:
  - SYS
  - DRIVER
  - DEBUG
  - REVERSE
---
# Kernel Debugging In Hyper-V

## 0x00_Description
윈도우 상에서 프로그램을 리버싱하는 과정에서 드라이버(.SYS) 모듈이 로드되어 동작하는 경우가 존재한다. 특히 해당 모듈이 중요한 로직을 동작하거나 실행하는 경우 분석이 필요한데 Windows Pro 버전 이상에서 제공하는 Hyper-V 기능을 이용하여 디버깅이 가능하다.



## 0x01_Hyper-V Setup

- 관리자 권한으로 "PowerShell"을 실행하여 Hyper-V 사용하도록 설정 후, 재부팅
  ```powershell
  Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
  ```

- 윈도우 키를 눌러 Hyper-V 관리자를 검색하여 실행하고 "새로 만들기 > 가상 컴퓨터" 메뉴에 접근하여 진행
  - 윈도우7 제품군을 설치하는 경우 UEFI를 지원하지 않으므로 1세대로 진행
  - 2세대로 설치하는 경우 COM  포트를 지원하지 않으므로 네트워크 디버깅으로 진행
    - 윈도우 8 이상부터는 bcdedit 에서 dbgsetting 명령에서 net을 제공
    - 이하 버전에서는 WinDbg 폴더 내에 kdnet.exe 프로그램을 이용

- Host 설정 메뉴 접근
  - "가상 스위치 관리자 > 새 가상 네트워크 스위치 > 외부" 메뉴에서 가상 스위치 생성
  - "Hyper-V 설정 > 실제 GPU > GPU 선택 > RemoteFX 설정"
    - 3D GPU 장치를 가상화 OS에서 동작하도록 설정
    - 현재 윈도우에서 더 이상 RemoteFX를 지원하지 않아 추가되지 않는 경우 관리자 권한으로 아래의 명령을 통해 강제로 RemoteFX를 추가 할 수 있다.
    ```powershell
    Add-VMRemoteFx3dVideoAdapter -VMName [MyVM]
    ```
  - USB  외장 하드 인식
    - 윈도우 제어판의 "관리 도구 > 컴퓨터 관리 > 저장소 > 디스크 관리"에 접근
    - 해당 USB 외장 하드의 상태를 "온라인 > 오프라인"으로 변경

- Guest 설정 메뉴 접근
  - "하드웨어 > 네트워크 어탭터"에 접근하여 생성된 외부 가상 스위치 선택
  - "하드웨어 > 하드웨어 추가 > RemoteFX 3D 비디오 어댑터 > 추가" 및 설정
    - Windows 7 Enterprise 또는 Ultimate 이상에서 가능 (Windows 10 Pro 추천)
    - RemoteFX를 설정할 경우 RDP를 이용하여 접근해야 하므로 Guest IP를 확인
  - 메모리 및 프로세서 설정
  - USB 외장 하드 추가
    - "하드웨어 > SCSI 컨트롤러 > 실제 하드 디스크(Y)"에서 해당 메뉴 선택
    - 운영체제 실행 중에 가능

- 가상 머신을 실행 후, 설치 완료

- 사운드의 경우 RDP를 통해 출력하도록 설정하므로 PRO 이상의 윈도우 OS가 필요
  - [WIN]+[R]에서 mstsc 실행 후, "로컬 리소스 > 설정 > 이 컴퓨터에서 재생(P) > 확인"
  - RDP 접근 후, 아래의 사운드 아이콘을 클릭하면 "원격 오디오"로 활성화 된 것을 확인

- 타 PC에서 Guest OS RDP 접근 시, RDP 지원 프로토콜로 인하여 Hyper-V가 설치되있어야 한다. 



## 0x02_Windows Setup

- Host 설정
  - Power Shell에서 "이더넷 어댑터 vEthernet (기본 스위치)"와 인터넷과 연결된 NIC IP를 확인
    ```powershell
    ipconfig /all
    ```

  - "제어판 > 시스템 및 보안 > Windows Defender 방화벽 > 허용되는 앱 > 다른 앱 허용(R)"에 접근하여 WinDbg 허용
  
  - WinDbg 설정 ([MS Home](<https://docs.microsoft.com/ko-kr/windows-hardware/drivers/devtest/bcdedit--dbgsettings>))
    - [Ctrl]+[S] 또는 "File > Symbol File Path"에 접근하여 아래 내용을 입력
      ```powershell
      SRV*c:\symbols*http://msdl.microsoft.com/download/symbols
      ```

- Guest 설정
  - 관리자 권한의 CMD에서 다음 과정 진행
    ```powershell
    # 디버깅 활성화
    C:\Windows\system32>bcdedit /debug on
    작업을 완료했습니다.
    
    # 호스트 PC의 IP로 설정
    C:\Windows\system32>bcdedit /dbgsettings net hostip:192.168.0.13 port:50037
    key=????
    작업을 완료했습니다.
    
    # 설정 확인
    C:\Windows\system32>bcdedit /dbgsettings
    key                     ????
    debugtype               NET
    hostip                  192.168.0.13
    port                    50037
    dhcp                    Yes
    작업을 완료했습니다.
    
    # 재부팅
    C:\Windows\system32>shutdown -r -t 0
    ```

- 커널 디버깅 진행
  - Host에서 WinDbg를 실행하여 "File > Ketnel Debugging > Net"에 대상 PC의 포트 번호와 KEY 값을 삽입하고 확인또는 아래와  또는, Host에서 다음 커맨드와 함께 WinDbg 실행
    ```powershell
    C:\Windows\system32>cd C:\Program Files (x86)\Windows Kits\10\Debuggers\x64
    WinDbg –k net:port=50010,key=????
    ```
    
  - Host PC에서 디버깅 대기 상태에서 Hyper-V 관리자에서 Guest 실행
    ```powershell
    Using NET for debugging
    Opened WinSock 2.0
    Waiting to reconnect...
    ```
  
  - 이 후, 로그인을 진행하여 RDP를 통해 Guest의 상태를 확인하며 디버깅 진행
  
  - NET 설정을 통한 디버깅 대기 상태에서는 Guest OS가 테스트 모드로 진행되므로 정상적으로 이용하기 위해 디버그 모드를 해제해야한다.
  
    ```powershell
    # 디버깅 해제
    C:\Windows\system32>bcdedit /debug off
    ```



## 0x03_Debugging

- SYS 드라이버 관련 명령어
  ```powershell
  # 로드된 모듈 확인
  lm
  
  # [DIRVER_NAME] 로드 시 예외 발생 ("*" 이용 가능)
  sxe ld [DRIVER_NAME]
  sxe ld [DRIVER_NAME]_*
  
  # Disassembly 창에서 [DIRVER_NAME]으로 이용 가능
  [DIRVER_NAME]+offset
  
  # Driver Header Info
  !dh [DRIVER_NAME] -f
  
  # IAT Analysis 
  dps [DRIVER_NAME]+offset
  ```
  
  특정 드라이버의 경우 서명 문제로 testsigning 설정을 변경해야 한다.
  ```powershell
  bcdedit -set testsigning off
  ```

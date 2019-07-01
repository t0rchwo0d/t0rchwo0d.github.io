---
title:  "Windows - x64dbg Script"
categories:
  - WINDOWS
tags:
  - DEBUGGER
  - SCRIPT
---
# x64dbg Script
## 0x00_Description
안티 디버깅, 패킹 등을 자동으로 우회하기 위한 x64dbg 스크립트 예제로 x64dbg에서 `[Favourites] > [Script] > [Add]`에서 작성한 스크립트 추가 및 단축키 설정 후, 단축키를 통해 로드하여 "Script" 탭에서 실행이 가능하다. 
이 때, `[Space]`를 통한 run, `[tap]`을 통한 step 등의 기능을 제공하며 우클릭 항목을 통해 확인이 가능하다.



## 0x01_Example
### Bypassing PEB.begindebuged 
##### PEB 조작을 통한 방법
```php
msg "[*] t0rchwo0d x64dbg Script"

main:
$peb = peb()
log "[+] PEB Address == {0}", $peb

$Peb.begindebuged = 1:[$peb+0x2]
cmp $Peb.BeginDebuged, 0
jne BeginDebuged
log "[+] Peb.begindebuged == {0}", $Peb.begindebuged
ret

BeginDebuged:
1:[$peb+0x2] = 0
log "[+] Modifed Peb.begindebuged == {0}", $Peb.begindebuged
jmp main
```

##### Return Value 조작을 통한 방법
```php
msg "[*] t0rchwo0d x64dbg Script"

main:
bp IsDebuggerPresent
erun
bp [rsp]
bc IsDebuggerPresent
erun
rax = 0
erun
ret
```
---
title:  "Windows - x64dbg: Script"
categories:
  - WINDOWS
tags:
  - DEBUGGER
  - SCRIPT
---
# x64dbg: Script
## 0x00_Description
안티 디버깅, 패킹 등을 자동으로 우회하기 위한 x64dbg 스크립트 예제이다. (계속 작성 예정)



## 0x01_Exasmple

### Bypassing PEB.begindebuged 

```php
// Author : t0rchwo0d
// Contact : https://t0rchwo0d.github.io
// Data : 20190611
// Comment : First x64Dbg Script
// Reference : https://x64dbg.readthedocs.io/en/latest/

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

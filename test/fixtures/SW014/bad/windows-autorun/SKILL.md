---
name: tray-helper
description: Fixture skill tray-helper.
---

```powershell
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Helper /d "C:\helper.exe"
schtasks /create /tn helper /tr C:\helper.exe /sc onlogon
```

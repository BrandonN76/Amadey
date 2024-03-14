## Malware Analysis
### Amadey Family

**Description:**  
In this analysis, I'll be examining “Utsysc.exe” a member of the Amadey malware family. Through both static and dynamic analyses, I aim to uncover the key characteristics, functionalities, and potential impact of this malware on compromised systems.

**VirusTotal Report:**
<img src="https://i.imgur.com/A5LNpRd.png">
**Hashes:**  
- MD5: ef63c97f703ba796c336fcf6824b2400  
- SHA-1: 69b63ef20df1f2243a2a5c6eba2663d3eb4773bb  
- SHA-256: 6d3cd39358c91c56b4798b64c73f03e3877a80dffe01d07e2ad13e979e845ed0

**Original File Name:** Utsysc.exe  
**Presented File Name:** 6d3cd39358c91c56b4798b64c73f03e3877a80dffe01d07e2ad13e979e845ed0.exe  
**File Size:** 363008 bytes  
**File Type:** PE32  
**DLL:**  
- KERNEL32.dll  
- USER32.dll  
- GDI32.dll  
- ADVAPI32.dll

**Notable Strings:**  
- GetCurrentProcessId  
- SetSystemPowerState  
- VirtualProtect  
- ReplaceFileA  
- RemoveDirectoryW  
- WriteFile  
- TerminateProcess  
- SetProcessShutdownParameters  
- GetCurrentProcess  
- RaiseException  
- ClearEventLogW  
- GetConsoleProcessList  
- SetTimeZoneInformation  
- GetProcessWindowStation  
- GetUserObjectInformation  
- GetLastActivePopup  
- GetActiveWindow  
- Sleep  
- TlsFree

**Dynamic Analysis**

**Files Created:**  
- C:\Users\vboxuser\AppData\Local\Temp\d4dd819322\Utsysc.exe

**Files Opened:**  
- C:\Windows\SysWOW64\WerFault.exe  
- C:\Windows\apppatch\sysmain.sdb  
- C:\Users\vboxuser\AppData\Local\Microsoft\Windows\Caches\cversions.1.db  
- C:\Users\vboxuser\AppData\Local\Microsoft\Windows\Caches\{AFBF9F1A-8EE8-4C77-AF34-C647E37CA0D9}.1.ver0x0000000000000004.db  
- C:\Users\vboxuser\AppData\Local\Microsoft\Windows\INetCache\Content.IE5  
- C:\Users\vboxuser\AppData\Local\Microsoft\Windows\INetCache\IE  
- C:\Users\vboxuser\AppData\Local\Microsoft\Windows\INetCookies\ESE  
- C:\Users\vboxuser\AppData\Local\Microsoft\Windows\History\History.IE5  
- C:\Windows\SysWOW64\schtasks.exe  
- C:\Windows\SysWOW64\en-US\schtasks.exe.mui  
- C:\Windows\System32\config\SOFTWARE

**Files Attempted to Access:**  
- C:\ProgramData\AVAST Software  
- C:\ProgramData\Avira  
- C:\ProgramData\Kaspersky Lab  
- C:\ProgramData\ESET  
- C:\ProgramData\Panda Security  
- C:\ProgramData\Doctor Web  
- C:\ProgramData\AVG  
- C:\ProgramData\360TotalSecurity  
- C:\ProgramData\Bitdefender  
- C:\ProgramData\Sophos  
- C:\ProgramData\Comodo  
- C:\ProgramData\Norton

**Scheduled Task:**  
- Name: Utsysc.exe  
- Trigger: every 1 min  
- Action: Start a program C:\Users\vboxuser\AppData\Local\Temp\d4dd819322\Utsysc.exe

**Notable Registry Keys added:**  
- HKLM\System\CurrentControlSet\Control\FileSystem  
- HKLM\System\CurrentControlSet\Control\FileSystem\LongPathsEnabled  
- HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Cache

**Network Analysis:**  
- DNS:  
  - sibcomputer.ru  
  - Tve-mail.com  
  - Shohetrc.com  
- URL:  
  - hxxp://shohetrc.com/forum/index.php  
  - hxxp://tve-mail.com/forum/index.php  
  - hxxp://sibcomputer.ru/forum/index.php  
  - hxxp://shohetrc.com/forum/Plugins/cred64.dll  
  - hxxp://shohetrc.com/forum/Plugins/clip64.dll  
  - hxxp://shohetrc.com/forum/index.php?scr=1  
  - hxxp://sibcomputer.ru/forum/index.php?scr=1  
  - hxxp://tve-mail.com/forum/index.php?scr=1  
- IP Address:  
  - 91.189.114.25:80

**Tools used:**  
- PEStudio: Used for static analysis of the executable.
- RegShot: Monitored changes to the system's registry.
- Capa: Assisted in identifying capabilities and characteristics of the malware.
- Procmon: Monitored system activity in real-time.
- Wireshark: Captured and analyzed network traffic.

**Overview:**  
The malware "Blamer.exe" contains functions that are related to system manipulation, file operations, and network communication. It creates and opens several files, attempts to access directories associated with antivirus and security software, and establishes a scheduled task that runs every minute. The malware adds and modifies registry keys related to file systems and Explorer settings. Additionally, it communicates with specific domains and URLs, this could be an attempt to connect to a remote server for command and control for a payload delivery.

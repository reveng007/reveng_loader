# reveng_loader
CSharp based 2-in-1 Loader capable of running stage-1 payloads, with args passing.

### Capability:
1. Can run dotnet in-memory:\
  i. from remote url (`/dotnet:<ip/url>`)\
  (accepts both http as well as https)\
  ii. from local path (`/dotnet:<folder_path/fileshare_path>`)
2. Can run PE (C/C++/ASM based executable) in-memory:\
  i. from remote url (`/pe:<ip/url>`)\
  (accepts both http as well as https)\
  ii. from local path (`/pe:<folder_path/fileshare_path>`)
3. Can run more than one executable in-memory, one after another:\
  i. `/dotnet:<ip/url/folder_path/fileshare_path> /dotnet:<ip/folder_path/fileshare_path> ...`\
  ii. `/dotnet:<ip/url/folder_path/fileshare_path> /pe:<ip/folder_path/fileshare_path> ...`\
  iii. And all other Combinations
4. Ability to recognise target by checking username in the form of xor key (Explanation is present in my previous project repo: [ability-to-recognise-target-by-checking-5username-in-the-form-of-xor-key](https://github.com/reveng007/DareDevil/#ability-to-recognise-target-by-checking-username-in-the-form-of-xor-key))
5. Ability to Detect and Detach from debugger by using, `NtQueryInformationProcess()` and `NtRemoveProcessDebug()` respectively.

![image](https://github.com/reveng007/reveng_loader/blob/main/img/helpMenu.PNG?raw=true)

### Usage:
1. To obfuscate sensitive string (using Environmental Keying TTP ID: [T1480.00](https://attack.mitre.org/techniques/T1480/001/)). Using my `Obfuscator/encrypt.cs` code from my [DareDevil project](https://github.com/reveng007/DareDevil/).
2. Just run the _compile.bat_ file to create the executable and run it!

![image](https://github.com/reveng007/reveng_loader/blob/main/img/demo1.PNG?raw=true)
![image](https://github.com/reveng007/reveng_loader/blob/main/img/demo2.PNG?raw=true)
![image](https://github.com/reveng007/reveng_loader/blob/main/img/demo3.PNG?raw=true)

#### NOTE:
When we got access to mimikatz.exe in-memory, we can see those 3 arguments got feed to this binary, but that doesn't matter much as mimkatz.exe is well versed to deal with wrong out-of-scope options.

### Internal Noticing:

1. Using [@matterpreter's](https://twitter.com/matterpreter) [DefenderCheck](https://github.com/matterpreter/DefenderCheck).

![image](https://github.com/reveng007/reveng_loader/blob/main/img/DefenderCheck.png?raw=true)

2. According to [antiscan.me](https://antiscan.me/):

![image](https://github.com/reveng007/reveng_loader/blob/main/img/AntiScan.png?raw=true)

3. Empty Import Table according to [PEBear](https://github.com/hasherezade/pe-bear-releases):

![image](https://github.com/reveng007/reveng_loader/blob/main/img/No_imports.png?raw=true)

4. I haven't added the ApiMonitor SnapShot as all Api Calls are being noticed by ApiMonitor and thereby would surely be noticed by EDRs.

### To-Do list 👨‍🔧:
1. Try using DInvoke to Obfuscate `LoadLibrary()` and `GetProcAddress()` WinApi, taking reference from [SharpSploit](https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/Execution/DynamicInvoke/Native.cs), to hide them from getting detected by **EDRs**.
2. OR, Direct Upgradation to Direct/ Indirect Sycall to fully avoid ***UserLand Hooking*** done by **EDRs**. Currently used WinApis are:
```
1. VirtualAlloc() (NtAllocateVirtualMemory)
2. CreateThread() (NtCreateThread)
3. VirtualProtect() (or, granting RWX permission directly by NtAllocateVirtualMemory)
4. WaitForSingleObject() (NtWaitForSingleObject)
5. GetLastError() (didn't find anything in https://j00ru.vexillium.org/syscalls/nt/64/)
6. NtQueryInformationProcess()
7. NtRemoveProcessDebug()
Leaving "LoadLibrary()" and "GetProcAddress()" WinApi, as use of it will be nullified as soon as I apply DInvoke.
```
3. Link: 
  i. Applying [HellsGate](https://github.com/sbasu7241/HellsGate) to wash away WinApi function calls and thereby avoiding ***UserLand Hooking*** done by **EDRs**.
  ii. https://github.com/susMdT/HellsGate-with-no-gate-and-dinvoking-deez
  iii. https://github.com/jackullrich/syscall-detect

### Resources and Credits:
1. Sektor7 Malware Dev Intermediate YT: [Manually parsing PE files with PE-bear](https://www.youtube.com/watch?v=ZLAYdGxN0IQ&t=1137s).
2. [Corkami Project](https://raw.githubusercontent.com/corkami/pics/master/binary/pe101/pe101-64.png) by [@corkami](https://twitter.com/corkami).
3. Blog Article: https://0xrick.github.io/win-internals by [@Ahm3d_H3sham](https://twitter.com/ahm3d_h3sham)
4. [Youtube](https://www.youtube.com/c/Tech69YT) by [@Ox4d5a](https://twitter.com/Ox4d5a)
5. Guidance from [Creds](https://github.com/S3cur3Th1sSh1t/Creds) by [@ShitSecure](https://twitter.com/ShitSecure).
5. Also thanks to [@SoumyadeepBas12](https://twitter.com/SoumyadeepBas12) for assistance related to C# implementation.
6. Took assistance from projects by [@_winterknife_](https://twitter.com/_winterknife_).

### Author: @reveng007 (Soumyanil Biswas)
---
[![](https://img.shields.io/badge/Twitter-@reveng007-1DA1F2?style=flat-square&logo=twitter&logoColor=white)](https://twitter.com/reveng007)
[![](https://img.shields.io/badge/LinkedIn-@SoumyanilBiswas-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/soumyanil-biswas/)
[![](https://img.shields.io/badge/Github-@reveng007-0077B5?style=flat-square&logo=github&logoColor=black)](https://github.com/reveng007/)

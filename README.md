# Infosec Useful Stuff

This repository is my own list of tools / useful stuff for pentest, defensive activities, programming, lockpicking and physical security (all resources are in English only)

If you want to add something you can ask a pull request or send me the link on [@Sh0ckFR](https://twitter.com/Sh0ckFR) ;)

# Menu

- [Reverse Engineering / Pown](#reverse-engineering--pown---back-to-menu)
- [Open Source Intelligence](#open-source-intelligence---back-to-menu)
- [Pentesting](#pentesting---back-to-menu)
- [Social Engineering / Phishing / Vishing](#social-engineering--phishing--vishing---back-to-menu)
- [Forensics / Incident Response](#forensics--incident-response---back-to-menu)
- [Cryptography](#cryptography---back-to-menu)
- [802.11, Wifi, Bluetooth, BLE, ZigBee / IoT / LoraWan / GSM / RF](#80211-wifi-bluetooth-ble-zigbee--iot--lorawan--gsm--rf---back-to-menu)
- [Vehicle Security / Cars Hacking](#vehicle-security--cars-hacking---back-to-menu)
- [Hardware / Firmware Security](#hardware--firmware-security---back-to-menu)
- [Windows Offensive Resources / Red-Teaming](#windows-offensive-resources--red-teaming---back-to-menu)
- [Defensive Resources / Blue-Teaming](#defensive-resources--blue-teaming---back-to-menu)
- [Mobile Hacking](#mobile-hacking---back-to-menu)
- [Threat Intelligence / Malwares Analysis](#threat-intelligence--malwares-analysis---back-to-menu)
- [Lockpicking - Physical Security](#lockpicking--physical-security---back-to-menu)
- [Programming](#programming---back-to-menu)

## Reverse Engineering / Pown - [Back To Menu](#menu)

### x86 architecture

- [https://www.begin.re/](https://www.begin.re/)
- [https://malwareunicorn.org/#/workshops](https://malwareunicorn.org/#/workshops)

### x64 architecture

- [https://github.com/0xdidu/Reverse-Engineering-Intel-x64-101](https://github.com/0xdidu/Reverse-Engineering-Intel-x64-101)

### ARM architecture

- [https://azeria-labs.com/writing-arm-assembly-part-1/](https://azeria-labs.com/writing-arm-assembly-part-1/)

### Generic stuff

- [https://github.com/wtsxDev/reverse-engineering](https://github.com/wtsxDev/reverse-engineering) - Awesome resources about Reverse Engineering
- [https://github.com/DarthTon/Blackbone](https://github.com/DarthTon/Blackbone) - Windows memory hacking library (x86 and x64 support)
- [https://github.com/longld/peda](https://github.com/longld/peda) - PEDA - Python Exploit Development Assistance for GDB
- [https://github.com/JonathanSalwan/ROPgadget](https://github.com/JonathanSalwan/ROPgadget) - This tool lets you search your gadgets on your binaries to facilitate your ROP exploitation. ROPgadget supports ELF, PE and Mach-O format on x86, x64, ARM, ARM64, PowerPC, SPARC and MIPS architectures.
- [https://wiremask.eu/articles/hooking-firefox-with-frida/](https://wiremask.eu/articles/hooking-firefox-with-frida/) - Hooking Firefox with Frida
- [https://github.com/namazso/physmem_drivers](https://github.com/namazso/physmem_drivers) - This repo is a collection of various vulnerable (mostly physical memory exposing) drivers. No more deeper analysis was done on them, so some might not work. Also, there is no PoC available. So for short, if you want to use any of these, reverse them yourself to figure out how to use.

### DLL Injections Tricks

- [https://codingvision.net/tips-and-tricks/calling-a-c-method-from-c-c-native-process](https://codingvision.net/tips-and-tricks/calling-a-c-method-from-c-c-native-process) - Call a C# Method from C/C++ (native process)
- [https://github.com/erfg12/memory.dll/wiki/Make-a-Named-Pipe-DLL-(Cplusplus)](https://github.com/erfg12/memory.dll/wiki/Make-a-Named-Pipe-DLL-(Cplusplus)) - Make a Named Pipe DLL (Cplusplus)
- [https://github.com/erfg12/memory.dll/wiki/Using-Named-Pipes](https://github.com/erfg12/memory.dll/wiki/Using-Named-Pipes) - Using Named Pipes (C# communication with your C++ Named Pipe)
- [https://silentbreaksecurity.com/srdi-shellcode-reflective-dll-injection/](https://silentbreaksecurity.com/srdi-shellcode-reflective-dll-injection/) - sRDI – Shellcode Reflective DLL Injection
- [https://github.com/danielkrupinski/MemJect](https://github.com/danielkrupinski/MemJect) - Simple Dll injector loading from memory. Supports PE header and entry point erasure. Written in C99.

### Hooking Libraries / Resources

- [https://github.com/TsudaKageyu/minhook](https://github.com/TsudaKageyu/minhook) - The Minimalistic x86/x64 API Hooking Library for Windows
- [https://github.com/stevemk14ebr/PolyHook](https://github.com/stevemk14ebr/PolyHook) - x86/x64 C++ Hooking Library
- [https://www.unknowncheats.me/forum/general-programming-and-reversing/154643-different-ways-hooking.html](https://www.unknowncheats.me/forum/general-programming-and-reversing/154643-different-ways-hooking.html) - The different ways of hooking

### DirectX / OpenGL / Vulkan Hooks

- [https://github.com/Sh0ckFR/Universal-Dear-ImGui-Hook](https://github.com/Sh0ckFR/Universal-Dear-ImGui-Hook) - An universal Dear ImGui Hook for Directx12 D3D12 (D3D11, D3D10 and maybe Vulkan will be added later)
- [https://github.com/Sh0ckFR/Universal-ImGui-D3D11-Hook](https://github.com/Sh0ckFR/Universal-ImGui-D3D11-Hook) - Universal Directx11 D3D11 Hook Project for all directx11 - 10 applications with ImGui and InputHook included, fullscreen supported
- [https://github.com/Rebzzel/kiero](https://github.com/Rebzzel/kiero) - Universal graphical hook for a D3D9-D3D12, OpenGL and Vulcan based games.

## Open Source Intelligence - [Back To Menu](#menu)

- [https://github.com/jivoi/awesome-osint](https://github.com/jivoi/awesome-osint) - Awesome resources about OSINT
- [https://darksearch.io/](https://darksearch.io/) - Dark Web search engine (Tor not needed)
- [https://www.bellingcat.com/](https://www.bellingcat.com/) - Investigative journalism website
- [https://github.com/eth0izzle/shhgit](https://github.com/eth0izzle/shhgit) - Find GitHub secrets in real time
- [https://github.com/twintproject/twint](https://github.com/twintproject/twint) - An advanced Twitter scraping & OSINT tool written in Python that doesn't use Twitter's API, allowing you to scrape a user's followers, following, Tweets and more while evading most API limitations.
- [https://github.com/sherlock-project/sherlock](https://github.com/sherlock-project/sherlock) - Hunt down social media accounts by username across social networks

## Pentesting - [Back To Menu](#menu)

### Web Security

- [https://github.com/qazbnm456/awesome-web-security](https://github.com/qazbnm456/awesome-web-security) - Awesome resources about web security
- [https://github.com/infoslack/awesome-web-hacking](https://github.com/infoslack/awesome-web-hacking) - Awesome resources about web security
- [https://github.com/snoopysecurity/awesome-burp-extensions](https://github.com/snoopysecurity/awesome-burp-extensions) - A curated list of amazingly awesome Burp Extensions.
- [https://github.com/alphaSeclab/awesome-burp-suite](https://github.com/alphaSeclab/awesome-burp-suite) - Awesome Burp Suite Resources. 400+ open source Burp plugins, 500+ posts and videos.
- [https://github.com/wireghoul/graudit](https://github.com/wireghoul/graudit) - grep rough audit - source code auditing tool
- [https://github.com/OJ/gobuster](https://github.com/OJ/gobuster) - Directory/File, DNS and VHost busting tool written in Go
- [https://github.com/OWASP/Amass](https://github.com/OWASP/Amass) - In-depth Attack Surface Mapping and Asset Discovery https://owasp.org/www-project-amass/
- [https://github.com/projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) - subfinder is a subdomain discovery tool that discovers valid subdomains for websites by using passive online sources.
- [https://pentester.land/tutorials/2018/10/25/source-code-disclosure-via-exposed-git-folder.html](https://pentester.land/tutorials/2018/10/25/source-code-disclosure-via-exposed-git-folder.html) - Source code disclosure via exposed .git folder

### Generic stuff

- [https://github.com/enaqx/awesome-pentest](https://github.com/enaqx/awesome-pentest) - Awesome resources (generic)
- [https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - A list of useful payloads and bypass for Web Application Security and Pentest/CTF

## Social Engineering / Phishing / Vishing - [Back To Menu](#menu)

- [https://github.com/v2-dev/awesome-social-engineering](https://github.com/v2-dev/awesome-social-engineering) - Awesome resources about Social Engineering
- [https://github.com/gophish/gophish](https://github.com/gophish/gophish) - Open-Source Phishing Toolkit in GoLang

## Forensics / Incident Response - [Back To Menu](#menu)

- [https://github.com/cugu/awesome-forensics](https://github.com/cugu/awesome-forensics) - Awesome resources about forensics
- [https://github.com/meirwah/awesome-incident-response](https://github.com/meirwah/awesome-incident-response) - Awesome resources about Incident Response
- [https://medium.com/maverislabs/virustotal-is-not-an-incident-responder-80a6bb687eb9](https://medium.com/maverislabs/virustotal-is-not-an-incident-responder-80a6bb687eb9) - VirusTotal is not an Incident Responder (How attackers can manipulate VirusTotal’s URL link scanning to provide clean response)
- [https://www.comae.com/dumpit/](https://www.comae.com/dumpit/) - DumpIt provides a convenient way of obtaining a memory image of a Windows system even if the analyst is not physically sitting in front of the target computer.
- [https://github.com/orlikoski/CyLR](https://github.com/orlikoski/CyLR) - CyLR - Live Response Collection Tool
- [https://github.com/log2timeline/plaso/tree/master/tools](https://github.com/log2timeline/plaso/tree/master/tools) - Super timeline all the things Tools (psteal)
- [https://github.com/google/timesketch](https://github.com/google/timesketch) - Collaborative forensic timeline analysis

## Cryptography - [Back To Menu](#menu)

- [https://github.com/sobolevn/awesome-cryptography](https://github.com/sobolevn/awesome-cryptography) - Awesome resources about cryptography

## 802.11, Wifi, Bluetooth, BLE, ZigBee / IoT / LoraWan / GSM / RF - [Back To Menu](#menu)

- [https://github.com/nebgnahz/awesome-iot-hacks/](https://github.com/nebgnahz/awesome-iot-hacks/) - Awesome resources about IoT hacks
- [https://blog.attify.com/the-practical-guide-to-hacking-bluetooth-low-energy/](https://blog.attify.com/the-practical-guide-to-hacking-bluetooth-low-energy/) - Practical Guide to Bluetooth Low Energy Hacking
- [https://github.com/cn0xroot/RFSec-ToolKit](https://github.com/cn0xroot/RFSec-ToolKit) - RFSec-ToolKit is a collection of Radio Frequency Communication Protocol Hacktools

## Vehicle Security / Cars Hacking - [Back To Menu](#menu)

- [https://github.com/jaredthecoder/awesome-vehicle-security/](https://github.com/jaredthecoder/awesome-vehicle-security/) - A curated list of resources for learning about vehicle security and car hacking

## Hardware / Firmware Security - [Back To Menu](#menu)

- [https://github.com/PreOS-Security/awesome-firmware-security/](https://github.com/PreOS-Security/awesome-firmware-security/) - Awesome resources about firmware security
- [https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-630.pdf](https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-630.pdf) - Semi-invasive attacks, a new approach to hardware security analysis
- [https://www.kth.se/social/files/59102ef5f276540f03507109/hardware_security__2017_05_08.pdf](https://www.kth.se/social/files/59102ef5f276540f03507109/hardware_security__2017_05_08.pdf) - A complete whitepaper about the hardware security analysis

## Windows Offensive Resources / Red-Teaming - [Back To Menu](#menu)

- [https://github.com/yeyintminthuhtut/Awesome-Red-Teaming](https://github.com/yeyintminthuhtut/Awesome-Red-Teaming) - Awesome resources about Red-Teaming
- [https://github.com/infosecn1nja/Red-Teaming-Toolkit](https://github.com/infosecn1nja/Red-Teaming-Toolkit) - Red-Teaming Toolkit
- [https://github.com/marcosValle/awesome-windows-red-team](https://github.com/marcosValle/awesome-windows-red-team) - Awesome resources about Red-Teaming
- [https://github.com/specterops/at-ps](https://github.com/specterops/at-ps) - Adversary Tactics - PowerShell Training
- [https://github.com/BloodHoundAD/SharpHound](https://github.com/BloodHoundAD/SharpHound) - The BloodHound C# Ingestor
- [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound) - BloodHound uses graph theory to reveal hidden relationships and attack paths in an Active Directory environment
- [https://github.com/SpiderLabs/Responder](https://github.com/SpiderLabs/Responder) - Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication.
- [https://azeria-labs.com/advanced-persistent-threat/](https://azeria-labs.com/advanced-persistent-threat/) - Introduction of APT attacks with the different stages (Reconnaissance, Initial Compromise, Persistence, Command and Control, Privilege Escalation, Lateral Movement, Asset Discovery and Data Exfiltration)
- [https://github.com/hfiref0x/UACME](https://github.com/hfiref0x/UACME) - Defeating Windows User Account Control
- [https://en.hackndo.com/pass-the-hash/](https://en.hackndo.com/pass-the-hash/) - Pass The Hash Technique
- [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/) - Extract credentials from lsass remotely
- [https://github.com/Hackndo/lsassy](https://github.com/Hackndo/lsassy) - lsassy (Tool to extract credentials from lsass remotely)
- [https://en.hackndo.com/bloodhound/](https://en.hackndo.com/bloodhound/) - Introduction to BloodHound
- [https://en.hackndo.com/kerberos/](https://en.hackndo.com/kerberos/) - Introduction to Kerberos
- [https://malicious.link/post/2016/kerberoast-pt1/](https://malicious.link/post/2016/kerberoast-pt1/) - Kerberoasting (Part1)
- [https://malicious.link/post/2016/kerberoast-pt2/](https://malicious.link/post/2016/kerberoast-pt2/) - Kerberoasting (Part2)
- [https://malicious.link/post/2016/kerberoast-pt3/](https://malicious.link/post/2016/kerberoast-pt3/) - Kerberoasting (Part3)
- [https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/) - Red Team Tactics: Combining Direct System Calls and sRDI to bypass AV/EDR (LSASS dump with dumpert)
- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) - This tool compares a targets patch levels against the Microsoft vulnerability database in order to detect potential missing patches on the target. It also notifies the user if there are public exploits and Metasploit modules available for the missing bulletins.
- [https://oddvar.moe/2018/09/06/persistence-using-universal-windows-platform-apps-appx/](https://oddvar.moe/2018/09/06/persistence-using-universal-windows-platform-apps-appx/) - Persistence can be achieved with Appx/UWP apps using the debugger options (Cortana/People App)
- [https://github.com/ollypwn/BlueGate](https://github.com/ollypwn/BlueGate) - BlueGate - Proof of Concept (Denial of Service) for CVE-2020-0609 and CVE-2020-0610. These vulnerabilities allows an unauthenticated attacker to gain remote code execution with highest privileges via RD Gateway for RDP.
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md) - Active Directory Common Attacks
- [https://github.com/BankSecurity/Red_Team](https://github.com/BankSecurity/Red_Team) - Some scripts useful for red team activities
- [https://adsecurity.org/?page_id=4031](https://adsecurity.org/?page_id=4031) - Active Directory Attack Defense & Detection
- [https://github.com/samratashok/nishang](https://github.com/samratashok/nishang) - Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security, penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
- [https://github.com/api0cradle/UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList) - The goal of this repository is to document the most common and known techniques to bypass AppLocker.
- [https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) - The Sysinternals Troubleshooting Utilities have been rolled up into a single Suite of tools.
- [https://github.com/matterpreter/DefenderCheck](https://github.com/matterpreter/DefenderCheck) - Identifies the bytes that Microsoft Defender flags on.
- [https://github.com/jfmaes/LazySign](https://github.com/jfmaes/LazySign) - Create fake certs for binaries using windows binaries and the power of bat files.
- [https://github.com/mindcollapse/MalwareMultiScan](https://github.com/mindcollapse/MalwareMultiScan) - Self-hosted VirusTotal / MetaDefender wannabe with API, demo UI and Scanners running in Docker.
- [https://github.com/Mr-Un1k0d3r/EDRs](https://github.com/Mr-Un1k0d3r/EDRs) - This repo contains information about EDRs that can be useful during red team exercise.
- [https://github.com/FourCoreLabs/EDRHunt](https://github.com/FourCoreLabs/EDRHunt) - EDRHunt scans Windows services, drivers, processes, registry for installed EDRs (Endpoint Detection And Response).
- [https://github.com/codewhitesec/HandleKatz](https://github.com/codewhitesec/HandleKatz) - PIC lsass dumper using cloned handles.
- [https://github.com/aaaddress1/Skrull](https://github.com/aaaddress1/Skrull) - Skrull is a malware DRM, that prevents Automatic Sample Submission by AV/EDR and Signature Scanning from Kernel. It generates launchers that can run malware on the victim using the Process Ghosting technique. Also, launchers are totally anti-copy and naturally broken when got submitted. It's a proof-of-concept of the talk of ROOTCON & HITCON 2021, check out Skrull Like A King: From File Unlink to Persistence
- [https://github.com/optiv/ScareCrow](https://github.com/optiv/ScareCrow) - ScareCrow is a payload creation framework for side loading (not injecting) into a legitimate Windows process (bypassing Application Whitelisting controls). Once the DLL loader is loaded into memory, it utilizes a technique to flush an EDR’s hook out of the system DLLs running in the process's memory.
- [https://github.com/phra/PEzor](https://github.com/phra/PEzor) - PEzor, an Open-Source PE Packer, Red teamers often have the necessity of bypassing AV solutions and I recently needed a more powerful tool than x0rro in order to perform some tasks and bypass a solution that I was targeting.
- [https://github.com/klezVirus/inceptor](https://github.com/klezVirus/inceptor) - Inceptor is a template-based PE packer for Windows, designed to help penetration testers and red teamers to bypass common AV and EDR solutions. Inceptor has been designed with a focus on usability, and to allow extensive user customisation.
- [https://github.com/cribdragg3r/Alaris](https://github.com/cribdragg3r/Alaris) - A protective and Low Level Shellcode Loader that defeats modern EDR systems.
- [https://br-sn.github.io/Implementing-Syscalls-In-The-CobaltStrike-Artifact-Kit/](https://br-sn.github.io/Implementing-Syscalls-In-The-CobaltStrike-Artifact-Kit/) - Implementing Syscalls In The Cobaltstrike Artifact Kit.
- [https://github.com/boku7/SPAWN](https://github.com/boku7/SPAWN) - Cobalt Strike Beacon Object File (BOF) that takes the name of of a PE file as an argument and spawns the process in a suspended state.
- [https://github.com/boku7/azureOutlookC2](https://github.com/boku7/azureOutlookC2) - Azure Outlook Command &amp; Control. Threat Emulation Tool for North Korean APT InkySquid / ScarCruft / APT37. TTP = Abuse Microsoft Graph API for C2 Operations.
- [https://github.com/bats3c/shad0w](https://github.com/bats3c/shad0w) - A post exploitation framework designed to operate covertly on heavily monitored environments.
- [https://github.com/EspressoCake/Self_Deletion_BOF](https://github.com/EspressoCake/Self_Deletion_BOF) - Having an obfuscated artifact from Cobalt Strike is nice in that you've successfully evaded detection, but wouldn't it be nice to have it deleted and still running? All credits included in the repository, as they should!
- [https://github.com/blackarrowsec/pivotnacci](A tool to make socks connections through HTTP agents)
- [https://github.com/epinna/weevely3](Weevely - Weaponized web shell - socks connections through PHP)

## Defensive Resources / Blue-Teaming - [Back To Menu](#menu)

- [https://medium.com/bugbountywriteup/building-a-siem-combining-elk-wazuh-hids-and-elastalert-for-optimal-performance-f1706c2b73c6](https://medium.com/bugbountywriteup/building-a-siem-combining-elk-wazuh-hids-and-elastalert-for-optimal-performance-f1706c2b73c6) - Building an open-source SIEM: combining ELK, Wazuh HIDS and Elastalert for optimal performance

## Mobile Hacking - [Back To Menu](#menu)

### Android

- [http://ilkinulas.github.io/android/2016/06/13/reverse-engineering-apk-files.html](http://ilkinulas.github.io/android/2016/06/13/reverse-engineering-apk-files.html) - Reverse Engineering Apk Files
- [https://github.com/randorisec/MobileHackingCheatSheet](https://github.com/randorisec/MobileHackingCheatSheet) - The Mobile Hacking CheatSheet is an attempt to summarise a few interesting basics info regarding tools and commands needed to assess the security of Android and iOS mobile applications.
- [https://medium.com/@mantissts/hacking-with-frida-fridalab-1-a2b4d227c1e8](https://medium.com/@mantissts/hacking-with-frida-fridalab-1-a2b4d227c1e8) - Hacking With Frida — FridaLab #1

## Threat Intelligence / Malwares Analysis - [Back To Menu](#menu)

- [https://github.com/hslatman/awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence) - A curated list of awesome Threat Intelligence resources
- [https://otx.alienvault.com/](https://otx.alienvault.com/) - The World’s First Truly Open Threat Intelligence Community
- [https://www.threatcrowd.org/](https://www.threatcrowd.org/) - A Search Engine for Threats
- [https://www.virustotal.com/gui/home/search](https://www.virustotal.com/gui/home/search) - Analyze suspicious files and URLs to detect types of malware, automatically share them with the security community
- [https://community.riskiq.com/](https://community.riskiq.com/) - RiskIQ Community brings petabytes of internet intelligence directly to your fingertips. Investigate threats by pivoting through attacker infrastructure data.
- [https://attack.mitre.org/](https://attack.mitre.org/) - MITRE ATT&CK™ is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.

## Lockpicking / Physical Security - [Back To Menu](#menu)

- [https://github.com/meitar/awesome-lockpicking](https://github.com/meitar/awesome-lockpicking) - A curated list of awesome guides, tools, and other resources related to the security and compromise of locks, safes, and keys.
- [https://tihk.co/blogs/news/getting-started-lockpicking-with-these-resources](https://tihk.co/blogs/news/getting-started-lockpicking-with-these-resources) - 20 Awesome Lockpicking Resources for Beginners
- [https://www.youtube.com/watch?v=P4HIDJ-5lJo](https://www.youtube.com/watch?v=P4HIDJ-5lJo) - Physical Penetration Testing (SHA2017)

## Programming - [Back To Menu](#menu)

### Virtual Reality (VR)

- [https://developer.oculus.com/documentation/unity/unity-tutorial/](https://developer.oculus.com/documentation/unity/unity-tutorial/) - Build Your First VR App
- [https://github.com/mnrmja007/awesome-virtual-reality](https://github.com/mnrmja007/awesome-virtual-reality) - A curated list of VR resources

## License

This repository is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

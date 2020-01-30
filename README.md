# Infosec Useful Stuff

This repository is my own list of tools / useful stuff for pentest and defensive activities (all resources are in English only)

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

## Pentesting - [Back To Menu](#menu)

### Web Security

- [https://github.com/qazbnm456/awesome-web-security](https://github.com/qazbnm456/awesome-web-security) - Awesome resources about web security
- [https://github.com/infoslack/awesome-web-hacking](https://github.com/infoslack/awesome-web-hacking) - Awesome resources about web security
- [https://github.com/snoopysecurity/awesome-burp-extensions](https://github.com/snoopysecurity/awesome-burp-extensions) - A curated list of amazingly awesome Burp Extensions.
- [https://github.com/alphaSeclab/awesome-burp-suite](https://github.com/alphaSeclab/awesome-burp-suite) - Awesome Burp Suite Resources. 400+ open source Burp plugins, 500+ posts and videos.

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

## License

This repository is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

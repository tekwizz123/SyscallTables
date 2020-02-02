
# Syscall tables
## Combined Windows x64 syscall tables

## Ntoskrnl service tables

+ Windows 2003 SP2 build 3790 also Windows XP 64;
+ Windows Vista RTM build 6000;
+ Windows Vista SP2 build 6002;
+ Windows 7 SP1 build 7601;
+ Windows 8 RTM build 9200;
+ Windows 8.1 build 9600;
+ Windows 10 TP build 10061;
+ Windows 10 TH1 build 10240;
+ Windows 10 TH2 build 10586;
+ Windows 10 RS1 build 14393;
+ Windows 10 RS2 build 15063;
+ Windows 10 RS3 build 16299;
+ Windows 10 RS4 build 17134;
+ Windows 10 RS5 build 17763;
+ Windows 10 19H1 build 18362;
+ Windows 10 19H2 build 18363;
+ Windows 10 20H1 build 19037;
+ Windows 10 20H2 build 19536;
+ Windows 10 20H2 build 19541;
+ Windows 10 20H2 build 19546;
+ Windows 10 20H2 build 19555.

** located in Tables\ntos

**View online** https://hfiref0x.github.io/syscalls.html

## Win32k service tables

+ Windows Vista RTM build 6000;
+ Windows 7 SP1 build 7601;
+ Windows 8 RTM build 9200;
+ Windows 8.1 build 9600;
+ Windows 10 TH1 build 10240;
+ Windows 10 TH2 build 10586;
+ Windows 10 RS1 build 14393;
+ Windows 10 RS2 build 15063;
+ Windows 10 RS3 build 16299;
+ Windows 10 RS4 build 17134;
+ Windows 10 RS5 build 17763;
+ Windows 10 19H1 build 18362;
+ Windows 10 19H2 build 18363;
+ Windows 10 20H1 build 19037;
+ Windows 10 20H2 build 19536;
+ Windows 10 20H2 build 19541;
+ Windows 10 20H2 build 19546;
+ Windows 10 20H2 build 19555.

** located in Tables\win32k

**View online** https://hfiref0x.github.io/w32ksyscalls.html

# Usage

1) Dump syscall table list (using scg for ntoskrnl or wscg64 for win32k), see run examples for more info.  
2) [Tables] <- put syscall list text file named as build number inside directory (ntos subdirectory for ntoskrnl.exe tables, win32k subdirectory for win32k.sys tables);

3) sstc.exe <- run composer with key -m (generate markdown table output file) or -h (generate html output file), it will read files from Tables directory and compose output table. Specify -w as second param if you want to generate win32k combined syscall table.

Run Examples:
* scg64.exe c:\wfiles\ntdll\ntdll_7600.dll > table7600.txt 
* wscg64.exe c:\wfiles\win32k\10240\win32k.sys > wtable10240.txt
* sstc -m -w
* sstc -h

# Build

Composer source code written in C#. In order to build from source you need Microsoft Visual Studio version 2017 and higher and .NET Framework version 4.5 and higher. Both scg and wscg source code written in C. In order to build from source you need Microsoft Visual Studio version 2017 with SDK 17763 installed and higher.

# Authors

+ scg (c) 2018 - 2020 SyscallTables Project
+ sstComposer (c) 2016 - 2020 SyscallTables Project
+ wscg64 (c) 2016 - 2020 SyscallTables Project, portions (c) 2010 deroko of ARTeam

Original scg (c) 2011 gr8

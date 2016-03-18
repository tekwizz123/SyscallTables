
# Syscall tables
## Combined Windows x64 syscall tables

+ Windows 2003 SP2 build 3790 also Windows XP 64;
+ Windows Vista RTM build 6000;
+ Windows Vista SP2 build 6002;
+ Windows 7 SP1 build 7601;
+ Windows 8 RTM build 9200;
+ Windows 8.1 build 9600;
+ Windows 10 TP build 10061;
+ Windows 10 TH1 build 10240;
+ Windows 10 TH2 build 10586;
+ Windows 10 RS1 build 14279.

# Usage

1) Dump syscall table list (using scg);

2) [Tables] <- put syscall list text file named as build number inside directory;

3) sstc.exe <- run composer with key -t (generate text output file) or -h (generate html output file), it will read files from Tables directory and compose output table.


P.S.
Can be used to generate x86 syscall list too. You will need to use scg over x86 ntdll then.


# Build

Composer source code written in C#. In order to build from source you need Microsoft Visual Studio version 2013 and higher and .NET Framework version 4.5 and higher. SyscallGenerator source code written in C++ by gr8. In order to build from source you need Microsoft Visual Studio version 2010 and higher. It is using VC runtime. Included as tribute to author.

# Authors

+ sstComposer (c) 2016 SyscallTables Project
+ scg (c) 2011 gr8

Put in this directory

dbghelp.dll
symsrv.dll

both from Debugging Tools for Windows (NOT from Windows itself).

Ref:
https://msdn.microsoft.com/en-us/library/windows/hardware/ff551063(v=vs.85).aspx
http://www.microsoft.com/whdc/DevTools/WDK/WDKpkg.mspx

Without those dlls wscg64 will not work correctly.

wscg64 expect directory located Symdll in the process current directory. So before running it, copy Symdll folder to the same folder where wscg64.exe located

e.g. if wscg64.exe located in C:\sgen, then move to it Symdll directory, so it will be subdirectory of C:\sgen -> C:\sgen\Symdll.

/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.00
*
*  DATE:        01 June 2016
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "main.h"

#define PRINT_FMT  L"%s\t%u"

HANDLE g_ConOut;
BOOL g_ConsoleOutput = FALSE;

SYMBOL_ENTRY g_SymbolsHead;
SERVICE_ENTRY g_ServicesHead;

pfnSymSetOptions pSymSetOptions;
pfnSymInitializeW pSymInitializeW;
pfnSymLoadModuleExW pSymLoadModuleExW;
pfnSymEnumSymbolsW pSymEnumSymbolsW;
pfnSymUnloadModule64 pSymUnloadModule64;
pfnSymFromAddrW pSymFromAddrW;
pfnSymCleanup pSymCleanup;

/*
* InitDbgHelp
*
* Purpose:
*
* This function loads dbghelp.dll, symsrv.dll from symdll directory and
* initialize function pointers from dbghelp.dll.
*
*/
BOOL InitDbgHelp(
    VOID
    )
{
    BOOL bCond = FALSE, bResult = FALSE;
    HANDLE hDbgHelp = NULL;
    SIZE_T length;
    WCHAR szBuffer[MAX_PATH * 2];

    do {
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        if (GetModuleFileNameW(NULL, szBuffer, MAX_PATH) == 0)
            break;

        _filepath_w(szBuffer, szBuffer);

        _strcat_w(szBuffer, L"symdll\\");
        length = _strlen_w(szBuffer);
        _strcat_w(szBuffer, L"dbghelp.dll");

        hDbgHelp = LoadLibrary(szBuffer);
        if (hDbgHelp == NULL)
            break;
        szBuffer[length] = 0;
        _strcat_w(szBuffer, L"symsrv.dll");
        LoadLibrary(szBuffer);

        pSymSetOptions = (pfnSymSetOptions)GetProcAddress(hDbgHelp, "SymSetOptions");
        if (pSymSetOptions == NULL)
            break;

        pSymInitializeW = (pfnSymInitializeW)GetProcAddress(hDbgHelp, "SymInitializeW");
        if (pSymInitializeW == NULL)
            break;

        pSymLoadModuleExW = (pfnSymLoadModuleExW)GetProcAddress(hDbgHelp, "SymLoadModuleExW");
        if (pSymLoadModuleExW == NULL)
            break;

        pSymEnumSymbolsW = (pfnSymEnumSymbolsW)GetProcAddress(hDbgHelp, "SymEnumSymbolsW");
        if (pSymEnumSymbolsW == NULL)
            break;

        pSymUnloadModule64 = (pfnSymUnloadModule64)GetProcAddress(hDbgHelp, "SymUnloadModule64");
        if (pSymUnloadModule64 == NULL)
            break;

        pSymFromAddrW = (pfnSymFromAddrW)GetProcAddress(hDbgHelp, "SymFromAddrW");
        if (pSymFromAddrW == NULL)
            break;

        pSymCleanup = (pfnSymCleanup)GetProcAddress(hDbgHelp, "SymCleanup");
        if (pSymCleanup == NULL)
            break;

        bResult = TRUE;

    } while (bCond);

    return bResult;
}

/*
* ServiceListAdd
*
* Purpose:
*
* This function add new entry to the service list.
*
*/
BOOL ServiceListAdd(
    LPWSTR ServiceName,
    DWORD ServiceId
    )
{
    PSERVICE_ENTRY Entry;
    Entry = &g_ServicesHead;

    while (Entry->Next != NULL)
        Entry = Entry->Next;

    Entry->Next = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SERVICE_ENTRY));
    if (Entry->Next == NULL)
        return FALSE;

    Entry = Entry->Next;
    Entry->Next = NULL;

    Entry->Name = ServiceName;
    Entry->Index = ServiceId;

    return TRUE;
}

/*
* ServiceListEntryExist
*
* Purpose:
*
* This function check if given service already inserted in list.
*
*/
BOOL ServiceListEntryExist(
    LPWSTR ServiceName
    )
{
    PSERVICE_ENTRY Entry;
    Entry = &g_ServicesHead;

    while (Entry) {
        if (_strcmp(Entry->Name, ServiceName) == 0) {
            return TRUE;
        }
        Entry = Entry->Next;
    }
    return FALSE;
}

/*
* SymbolNameFromAddress
*
* Purpose:
*
* This function query Nt symbol name by given symbol address.
* If duplicate known name found then it looks for another name alias.
*
*/
BOOL SymbolNameFromAddress(
    DWORD64 lpAddress,
    LPWSTR SymbolName,
    DWORD ServiceId
)
{
    PSYMBOL_ENTRY Entry;

    Entry = g_SymbolsHead.Next;

    while (Entry) {
        if (Entry->Address == lpAddress) {
            if (_strncmp_w(Entry->Name, L"Nt", 2) == 0) {
                //
                // Some services share same symbol as they point to same routine under different names
                //
                if (ServiceListEntryExist(Entry->Name) != TRUE) {
                    _strncpy(SymbolName, MAX_PATH, Entry->Name, MAX_PATH);
                    return ServiceListAdd(Entry->Name, ServiceId);
                }
            }
        }
        Entry = Entry->Next;
    }
    return FALSE;
}


/*
* SymbolNameFromAddress2
*
* Purpose:
*
* SymFromAddrW variant of SymbolNameFromAddress
*
*/
BOOL SymbolNameFromAddress2(
    DWORD64 dwAddress,
    WCHAR *SymbolName,
    DWORD ServiceId
)
{
    SIZE_T sz;
    LPWSTR lpszSymbolName;
    DWORD64 dwDisplacement = 0;
    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(WCHAR)];
    PSYMBOL_INFOW pSymbol = (PSYMBOL_INFOW)buffer;

    RtlSecureZeroMemory(buffer, sizeof(buffer));
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;

    if (pSymFromAddrW(GetCurrentProcess(), dwAddress, &dwDisplacement, pSymbol)) {
        _strncpy_w(SymbolName, MAX_PATH, pSymbol->Name, MAX_PATH);
        sz = _strlen_w(SymbolName) * sizeof(WCHAR);

        lpszSymbolName = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
        if (lpszSymbolName) {
            _strncpy_w(lpszSymbolName, sz / sizeof(WCHAR), pSymbol->Name, sz / sizeof(WCHAR));
            return ServiceListAdd(lpszSymbolName, ServiceId);
        }
    }
    return FALSE;
}

/*
* SymbolsAddToList
*
* Purpose:
*
* This function add symbol to the list.
*
*/
VOID SymbolAddToList(
    LPWSTR SymbolName,
    DWORD64 lpAddress
    )
{
    PSYMBOL_ENTRY Entry;
    SIZE_T        sz;

    Entry = &g_SymbolsHead;

    while (Entry->Next != NULL)
        Entry = Entry->Next;

    sz = _strlen_w(SymbolName) * sizeof(WCHAR);
    sz += sizeof(WCHAR);

    Entry->Next = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SYMBOL_ENTRY));
    if (Entry->Next == NULL)
        return;

    Entry = Entry->Next;
    Entry->Next = NULL;

    Entry->Name = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
    if (Entry->Name == NULL) {
        HeapFree(GetProcessHeap(), 0, Entry->Next);
        return;
    }

    _strncpy_w(Entry->Name, sz / sizeof(WCHAR), SymbolName, sz / sizeof(WCHAR));
    Entry->Address = lpAddress;
}

/*
* SymbolAddressFromName
*
* Purpose:
*
* This function query address from the given symbol name.
*
*/
DWORD64 SymbolAddressFromName(
    LPWSTR lpszName
    )
{
    PSYMBOL_ENTRY Entry;

    Entry = g_SymbolsHead.Next;

    while (Entry) {
        if (!_strcmp_w(lpszName, Entry->Name))
            return Entry->Address;
        Entry = Entry->Next;
    }
    return 0;
}

/*
* SymEnumSymbolsProc
*
* Purpose:
*
* Callback of SymEnumSymbolsW.
*
*/
BOOL CALLBACK SymEnumSymbolsProc(
    _In_ PSYMBOL_INFOW pSymInfo,
    _In_ ULONG SymbolSize,
    _In_opt_ PVOID UserContext
)
{
#ifdef _DEBUG
    WCHAR szBuffer[MAX_PATH * 5];
#endif
    UNREFERENCED_PARAMETER(SymbolSize);
    UNREFERENCED_PARAMETER(UserContext);
#ifdef _DEBUG   
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    wsprintf(szBuffer, L"%08X %4u %s, %08X\n",
        pSymInfo->Address, SymbolSize, pSymInfo->Name, pSymInfo->Value);
    OutputDebugStringW(szBuffer);
#endif
    SymbolAddToList(pSymInfo->Name, pSymInfo->Address);
    return TRUE;
}

/*
* GetWin32kBuildVersion
*
* Purpose:
*
* Query Win32k build from VERSION_INFO.
*
*/
BOOL GetWin32kBuildVersion(
    LPWSTR szImagePath,
    ULONG *BuildNumber
    )
{
    BOOL bCond = FALSE, bResult = FALSE;
    DWORD dwHandle, dwSize;
    PVOID vinfo = NULL;
    UINT Length;
    VS_FIXEDFILEINFO *pFileInfo;

    do {

        if (BuildNumber == NULL)
            break;

        dwHandle = 0;
        dwSize = GetFileVersionInfoSizeW(szImagePath, &dwHandle);
        if (dwSize == 0) {
            break;
        }

        // allocate memory for version_info structure
        vinfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
        if (vinfo == NULL) {
            break;
        }
        // query it from file
        if (!GetFileVersionInfo(szImagePath, 0, dwSize, vinfo)) {
            break;
        }

        bResult = VerQueryValueW(vinfo, L"\\", (LPVOID *)&pFileInfo, (PUINT)&Length);
        if (bResult) {
            *BuildNumber = HIWORD(pFileInfo->dwFileVersionLS);
        }

    } while (bCond);

    if (vinfo) {
        HeapFree(GetProcessHeap(), 0, vinfo);
    }

    return bResult;
}


/*
* wscg10
*
* Purpose:
*
* In case of Windows 10+ we can build table directly from win32k.sys without using symbols.
*
*/
void wscg10(
    LPWSTR lpszWin32kImage,
    ULONG Win32kBuild
)
{
    BOOL        bCond = FALSE;
    ULONG       i, c, k;
    HMODULE     MappedImageBase = NULL;
    ULONG_PTR   Address;
    
    PCHAR       pfn;
    DWORD      *Table = NULL;
    PULONG      ServiceLimit;
    ULONG_PTR  *ServiceTable;

    PIMAGE_NT_HEADERS     NtHeaders;
    IMAGE_IMPORT_BY_NAME *ImportEntry = NULL;
    LPWSTR lpBuffer = NULL;
    WCHAR szBuffer[MAX_PATH * 4];

    __try {
        do {
            MappedImageBase = LoadLibraryExW(lpszWin32kImage, NULL, DONT_RESOLVE_DLL_REFERENCES);
            if (MappedImageBase == 0) {
                cuiPrintText(g_ConOut, L"wscg: Cannot load input file: ", g_ConsoleOutput, TRUE);
                cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
                break;
            }

            NtHeaders = RtlImageNtHeader((PVOID)MappedImageBase);
            if (NtHeaders == NULL) {
                cuiPrintText(g_ConOut, L"wscg: invalid input file.", g_ConsoleOutput, TRUE);
                break;
            }

            ServiceLimit = (ULONG*)GetProcAddress(MappedImageBase, "W32pServiceLimit");
            if (ServiceLimit == NULL) {
                cuiPrintText(g_ConOut, L"wscg: W32pServiceLimit not found.", g_ConsoleOutput, TRUE);
                break;
            }

            c = *ServiceLimit;

            ServiceTable = (ULONG_PTR *)GetProcAddress(MappedImageBase, "W32pServiceTable");
            if (ServiceTable == NULL) {
                cuiPrintText(g_ConOut, L"wscg: W32pServiceTable not found.", g_ConsoleOutput, TRUE);
                break;
            }

            for (i = 0; i < c; i++) {
                Address = 0;
                pfn = NULL;
                RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
                if (Win32kBuild > 10586) {
                    Table = (DWORD *)ServiceTable;
                    pfn = (PCHAR)(Table[i] + (ULONG_PTR)MappedImageBase);
                }
                else {
                    pfn = (PCHAR)(ServiceTable[i] - NtHeaders->OptionalHeader.ImageBase + (ULONG_PTR)MappedImageBase);
                }
                if (pfn) {
                    Address = (ULONG_PTR)MappedImageBase + *(ULONG_PTR*)(pfn + 6 + *(DWORD*)(pfn + 2));
                    ImportEntry = (IMAGE_IMPORT_BY_NAME *)Address;
                    if (ImportEntry) {
                        k = (ULONG)_strlen_a(ImportEntry->Name) * sizeof(WCHAR) + sizeof(UNICODE_NULL);
                        lpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, k + 100);
                        if (lpBuffer) {
                            MultiByteToWideChar(CP_ACP, 0, (LPCSTR)&ImportEntry->Name, -1, lpBuffer, k / sizeof(WCHAR));
                            _strcat_w(lpBuffer, L"\t");
                            ultostr_w(i + W32SYSCALLSTART, _strend_w(lpBuffer));
                            cuiPrintText(g_ConOut, lpBuffer, g_ConsoleOutput, TRUE);
                            HeapFree(GetProcessHeap(), 0, lpBuffer);
                        }
                    }
                }
            }

        } while (bCond);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return;
    }
}

/*
* wscg
*
* Purpose:
*
* Load symbols, enum them and output shadow service table.
*
*/
void wscg(
    LPWSTR lpszWin32kImage
    )
{
    BOOL       bCond = FALSE, bRet = FALSE;
    HANDLE     hSym = GetCurrentProcess();
    DWORD64   *pW32pServiceTable = NULL;
//    DWORD     *Table = NULL;
    ULONG     *pW32pServiceLimit = NULL;
    DWORD64    Win32kImage = 0;
    WCHAR      szSymbolName[MAX_PATH];
    WCHAR      szFullSymbolInfo[MAX_PATH * 2];
    ULONG      ServiceLimit, i, Win32kBuild = 0;

    IMAGE_NT_HEADERS *NtHeaders;

    if (lpszWin32kImage == NULL)
        return;

    if (!GetWin32kBuildVersion(lpszWin32kImage, &Win32kBuild)) {
        cuiPrintText(g_ConOut, L"wscg: Cannot query build information from input file.", g_ConsoleOutput, TRUE);
        return;
    }

    if (Win32kBuild > 9600) {
        wscg10(lpszWin32kImage, Win32kBuild);
    }
    else {

        SetLastError(0);

        if (!InitDbgHelp()) {
            _strcpy_w(szSymbolName, L"wscg: InitDbgHelp failed, make sure required dlls are in %wscg%\\Symdll folder.");
            cuiPrintText(g_ConOut, szSymbolName, g_ConsoleOutput, TRUE);
            return;
        }

        do {

            pSymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);

            RtlSecureZeroMemory(&g_SymbolsHead, sizeof(g_SymbolsHead));

            RtlSecureZeroMemory(szSymbolName, sizeof(szSymbolName));
            if (GetModuleFileNameW(NULL, szSymbolName, MAX_PATH) == 0)
                break;

            _strcpy_w(szFullSymbolInfo, L"SRV*");
            _filepath_w(szSymbolName, _strend_w(szFullSymbolInfo));
            _strcat_w(szFullSymbolInfo, L"Symbols");
            if (!CreateDirectoryW(&szFullSymbolInfo[4], NULL)) {
                if (GetLastError() != ERROR_ALREADY_EXISTS) {
                    cuiPrintText(g_ConOut, L"wscg: Cannot create symbols directory: ", g_ConsoleOutput, TRUE);
                    cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
                    break;
                }
            }
            _strcat_w(szFullSymbolInfo, L"*https://msdl.microsoft.com/download/symbols");
            if (!pSymInitializeW(hSym, szFullSymbolInfo, FALSE)) {
                cuiPrintText(g_ConOut, L"wscg: SymInitialize failed.", g_ConsoleOutput, TRUE);
                break;
            }

            Win32kImage = (DWORD64)(PVOID)LoadLibraryExW(lpszWin32kImage, NULL, DONT_RESOLVE_DLL_REFERENCES);
            if (Win32kImage == 0) {
                cuiPrintText(g_ConOut, L"wscg: Cannot load input file: ", g_ConsoleOutput, TRUE);
                cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
                break;
            }

            NtHeaders = RtlImageNtHeader((PVOID)Win32kImage);
            if (!pSymLoadModuleExW(hSym, NULL, lpszWin32kImage, NULL, (DWORD64)Win32kImage, 0, NULL, 0)) {
                cuiPrintText(g_ConOut, L"wscg: SymLoadModuleEx failed for input file with message: ", g_ConsoleOutput, TRUE);
                cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
                break;
            }

            if (!pSymEnumSymbolsW(hSym, (DWORD64)Win32kImage, NULL, SymEnumSymbolsProc, NULL)) {
                cuiPrintText(g_ConOut, L"wscg: SymEnumSymbols failed.", g_ConsoleOutput, TRUE);
                break;
            }

            pW32pServiceLimit = (ULONG *)SymbolAddressFromName(L"W32pServiceLimit");
            if (pW32pServiceLimit == NULL) {
                cuiPrintText(g_ConOut, L"wscg: W32pServiceLimit symbol not found.", g_ConsoleOutput, TRUE);
                break;
            }

            ServiceLimit = *pW32pServiceLimit;

            pW32pServiceTable = (DWORD64 *)SymbolAddressFromName(L"W32pServiceTable");
            if (pW32pServiceTable == NULL) {
                cuiPrintText(g_ConOut, L"wscg: W32pServiceTable symbol not found.", g_ConsoleOutput, TRUE);
                break;
            }

            for (i = 0; i < ServiceLimit; i++) {
                RtlSecureZeroMemory(szSymbolName, sizeof(szSymbolName));
               // if (Win32kBuild > 10586) {
               //     Table = (DWORD *)pW32pServiceTable;
               //     bRet = SymbolNameFromAddress(Table[i] + Win32kImage, szSymbolName, W32SYSCALLSTART + i);
               // }
               // else {
                    bRet = SymbolNameFromAddress(pW32pServiceTable[i] - NtHeaders->OptionalHeader.ImageBase + Win32kImage, szSymbolName, W32SYSCALLSTART + i);
                //}

                   /* RtlSecureZeroMemory(szFullSymbolInfo, sizeof(szFullSymbolInfo));
                    if (!bRet) {
                        _strcpy_w(szSymbolName, L"UnknownSyscall");
                    }
                    wsprintfW(szFullSymbolInfo, L"\"%s\",", szSymbolName, W32SYSCALLSTART + i);
                    cuiPrintText(g_ConOut, szFullSymbolInfo, g_ConsoleOutput, TRUE);*/

                    RtlSecureZeroMemory(szFullSymbolInfo, sizeof(szFullSymbolInfo));
                    if (!bRet) {
                        _strcpy_w(szSymbolName, L"UnknownSyscall");                      
                    }
                    wsprintfW(szFullSymbolInfo, PRINT_FMT, szSymbolName, W32SYSCALLSTART + i);
                    cuiPrintText(g_ConOut, szFullSymbolInfo, g_ConsoleOutput, TRUE);
            }

        } while (bCond);

        if (Win32kImage) {
            pSymUnloadModule64(hSym, (DWORD64)Win32kImage);
            FreeLibrary((HMODULE)Win32kImage);
        }
        pSymCleanup(hSym);
        //list cleanup done at process exit
    }
}

/*
* main
*
* Purpose:
*
* Program entry point.
*
*/
void main()
{
    LPWSTR *szArglist;
    INT nArgs = 0;
    DWORD dwTemp;
    WCHAR BE = 0xFEFF; 

    __security_init_cookie();

    g_ConOut = GetStdHandle(STD_OUTPUT_HANDLE);

    szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (szArglist) {
        if (nArgs > 1) {
            g_ConsoleOutput = TRUE;
            if (!GetConsoleMode(g_ConOut, &dwTemp)) {
                g_ConsoleOutput = FALSE;
            }
            SetConsoleMode(g_ConOut, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_OUTPUT);
            if (g_ConsoleOutput == FALSE) {
                WriteFile(g_ConOut, &BE, sizeof(WCHAR), &dwTemp, NULL);
            }

            if (PathFileExists(szArglist[1])) {
                wscg(szArglist[1]);
            }
            else {
                cuiPrintText(g_ConOut, L"wscg: Input File not found.", g_ConsoleOutput, TRUE);
            }
        }
        LocalFree(szArglist);
    }
    ExitProcess(0);
}

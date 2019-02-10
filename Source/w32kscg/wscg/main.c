/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2019
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.14
*
*  DATE:        20 Jan 2019
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
    HANDLE hDbgHelp = NULL, hSymSrv = NULL;
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
        hSymSrv = LoadLibrary(szBuffer);
        if (hSymSrv == NULL)
            break;

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
    _In_ LPWSTR ServiceName,
    _In_ DWORD ServiceId
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
    _In_ LPWSTR ServiceName
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
    _In_ DWORD64 lpAddress,
    _In_ LPWSTR SymbolName,
    _In_ DWORD ServiceId
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
                if (!ServiceListEntryExist(Entry->Name)) {
                    _strncpy(SymbolName, MAX_PATH, Entry->Name, Entry->NameLen);
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
    _In_ DWORD64 dwAddress,
    _In_ WCHAR *SymbolName,
    _In_ DWORD ServiceId
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
    _In_ LPWSTR SymbolName,
    _In_ DWORD64 lpAddress
)
{
    PSYMBOL_ENTRY Entry;
    SIZE_T        sz;

    Entry = &g_SymbolsHead;

    while (Entry->Next != NULL)
        Entry = Entry->Next;

    sz = (1 + _strlen(SymbolName)) * sizeof(WCHAR);

    Entry->Next = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SYMBOL_ENTRY));
    if (Entry->Next) {

        Entry = Entry->Next;
        Entry->Next = NULL;

        Entry->Name = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
        if (Entry->Name) {

            _strncpy(Entry->Name, sz / sizeof(WCHAR),
                SymbolName, sz / sizeof(WCHAR));

            Entry->Address = lpAddress;
            Entry->NameLen = sz / sizeof(WCHAR);
        }
        else {
            HeapFree(GetProcessHeap(), 0, Entry);
        }
    }
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
    _In_ LPWSTR lpszName
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

    if (pSymInfo->NameLen > 3) {
        if ((pSymInfo->Name[0] == L'W') &&
            (pSymInfo->Name[1] == L'3') &&
            (pSymInfo->Name[2] == L'2'))
        {
#ifdef _DEBUG   
            szBuffer[0] = 0;
            wsprintf(szBuffer, L"%I64X %4u %ws, %I64X\n",
                pSymInfo->Address, SymbolSize, pSymInfo->Name, pSymInfo->Value);
            OutputDebugStringW(szBuffer);
#endif
            SymbolAddToList(pSymInfo->Name, pSymInfo->Address);
        }
        else
            if ((pSymInfo->Name[0] == L'N') &&
                (pSymInfo->Name[1] == L't'))
            {
#ifdef _DEBUG   
                szBuffer[0] = 0;
                wsprintf(szBuffer, L"%I64X %4u %ws, %I64X\n",
                    pSymInfo->Address, SymbolSize, pSymInfo->Name, pSymInfo->Value);
                OutputDebugStringW(szBuffer);
#endif
                SymbolAddToList(pSymInfo->Name, pSymInfo->Address);
            }

    }
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
    _In_ LPWSTR szImagePath,
    _Out_ ULONG *BuildNumber
)
{
    BOOL bResult = FALSE;
    DWORD dwHandle, dwSize;
    PVOID vinfo = NULL;
    UINT Length;
    VS_FIXEDFILEINFO *pFileInfo;

    *BuildNumber = 0;

    dwHandle = 0;
    dwSize = GetFileVersionInfoSizeW(szImagePath, &dwHandle);
    if (dwSize) {
        vinfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
        if (vinfo) {
            if (GetFileVersionInfo(szImagePath, 0, dwSize, vinfo)) {
                bResult = VerQueryValueW(vinfo, L"\\", (LPVOID *)&pFileInfo, (PUINT)&Length);
                if (bResult)
                    *BuildNumber = HIWORD(pFileInfo->dwFileVersionLS);
            }
            HeapFree(GetProcessHeap(), 0, vinfo);
        }
    }

    return bResult;
}

#define MAX_DOS_HEADER (256 * (1024 * 1024))

/*
* LdrImageNtHeader
*
* Purpose:
*
* Query address of NT Header.
*
*/
PIMAGE_NT_HEADERS LdrImageNtHeader(
    _In_ PVOID Base)
{
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    if (Base != NULL && Base != (PVOID)-1) {
        __try {
            if ((((PIMAGE_DOS_HEADER)Base)->e_magic == IMAGE_DOS_SIGNATURE) &&
                (((ULONG)((PIMAGE_DOS_HEADER)Base)->e_lfanew) < MAX_DOS_HEADER)) {
                NtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
                if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
                    NtHeaders = NULL;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            NtHeaders = NULL;
        }
    }
    return NtHeaders;
}

/*
* LdrGetProcAddress
*
* Purpose:
*
* GetProcAddress for manually loaded file.
*
*/
LPVOID LdrGetProcAddress(
    _In_ PCHAR ImageBase,
    _In_ PCHAR RoutineName
)
{
    USHORT OrdinalNumber;
    PULONG NameTableBase;
    PUSHORT NameOrdinalTableBase;
    PULONG Addr;
    LONG Result, High, Low = 0, Middle = 0;
    LPVOID FunctionAddress = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;

    PIMAGE_FILE_HEADER			fh1 = NULL;
    PIMAGE_OPTIONAL_HEADER32	oh32 = NULL;
    PIMAGE_OPTIONAL_HEADER64	oh64 = NULL;

    __try {

        fh1 = (PIMAGE_FILE_HEADER)((ULONG_PTR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew + sizeof(DWORD));
        oh32 = (PIMAGE_OPTIONAL_HEADER32)((ULONG_PTR)fh1 + sizeof(IMAGE_FILE_HEADER));
        oh64 = (PIMAGE_OPTIONAL_HEADER64)oh32;

        if (fh1->Machine == IMAGE_FILE_MACHINE_AMD64) {

            ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ImageBase +
                oh64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        }
        else {

            ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ImageBase +
                oh32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        }

        NameTableBase = (PULONG)(ImageBase + (ULONG)ExportDirectory->AddressOfNames);
        NameOrdinalTableBase = (PUSHORT)(ImageBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);
        High = ExportDirectory->NumberOfNames - 1;
        while (High >= Low) {

            Middle = (Low + High) >> 1;

            Result = _strcmp_a(
                RoutineName,
                (PCHAR)(ImageBase + NameTableBase[Middle])
            );

            if (Result < 0)
                High = Middle - 1;
            else
                if (Result > 0)
                    Low = Middle + 1;
                else
                    break;
        } //while
        if (High < Low)
            return NULL;

        OrdinalNumber = NameOrdinalTableBase[Middle];
        if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions)
            return NULL;

        Addr = (PDWORD)((DWORD_PTR)ImageBase + ExportDirectory->AddressOfFunctions);
        FunctionAddress = (LPVOID)((DWORD_PTR)ImageBase + Addr[OrdinalNumber]);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FunctionAddress = NULL;
    }
    return FunctionAddress;
    }

/*
* LdrMapInputFile
*
* Purpose:
*
* Create mapped section from input file.
*
*/
PVOID LdrMapInputFile(
    _In_ LPWSTR lpszWin32kImage
)
{
    HANDLE hFile = INVALID_HANDLE_VALUE, hMapping = NULL;
    PVOID  pvImageBase = NULL;

    hFile = CreateFile(lpszWin32kImage,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        hMapping = CreateFileMapping(hFile,
            NULL,
            PAGE_READONLY | SEC_IMAGE,
            0,
            0,
            NULL);

        if (hMapping != NULL) {

            pvImageBase = MapViewOfFile(hMapping,
                FILE_MAP_READ, 0, 0, 0);

            CloseHandle(hMapping);
        }
        CloseHandle(hFile);
    }
    return pvImageBase;
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
    _In_ LPWSTR lpszWin32kImage,
    _In_ ULONG Win32kBuild
)
{
    BOOL        bCond = FALSE;
    ULONG       i, c;
    PVOID       pvImageBase = NULL;
    ULONG_PTR   Address;

    SIZE_T      Length;

    PCHAR       pfn;
    DWORD      *Table = NULL;
    PULONG      ServiceLimit;
    ULONG_PTR  *ServiceTable;

    HANDLE      ProcessHeap = GetProcessHeap();

    PIMAGE_NT_HEADERS     NtHeaders;
    IMAGE_IMPORT_BY_NAME *ImportEntry = NULL;
    LPWSTR lpBuffer = NULL;

    hde64s hs;

    do {

        pvImageBase = LdrMapInputFile(lpszWin32kImage);
        if (pvImageBase == NULL) {
            cuiPrintText(g_ConOut, L"wscg: Cannot load input file: ", g_ConsoleOutput, TRUE);
            cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
            break;
        }

        NtHeaders = LdrImageNtHeader(pvImageBase);
        if (NtHeaders == NULL) {
            cuiPrintText(g_ConOut, L"wscg: invalid input file.", g_ConsoleOutput, TRUE);
            break;
        }

        ServiceLimit = (ULONG*)LdrGetProcAddress(pvImageBase, "W32pServiceLimit");
        if (ServiceLimit == NULL) {
            cuiPrintText(g_ConOut, L"wscg: W32pServiceLimit not found.", g_ConsoleOutput, TRUE);
            break;
        }

        c = *ServiceLimit;

        ServiceTable = (ULONG_PTR *)LdrGetProcAddress(pvImageBase, "W32pServiceTable");
        if (ServiceTable == NULL) {
            cuiPrintText(g_ConOut, L"wscg: W32pServiceTable not found.", g_ConsoleOutput, TRUE);
            break;
        }

        __try {

            for (i = 0; i < c; i++) {
                Address = 0;
                pfn = NULL;
                if (Win32kBuild > 10586) {
                    Table = (DWORD *)ServiceTable; //-V114
                    pfn = (PCHAR)(Table[i] + (ULONG_PTR)pvImageBase);
                }
                else {
                    pfn = (PCHAR)(ServiceTable[i] - NtHeaders->OptionalHeader.ImageBase + (ULONG_PTR)pvImageBase);
                }
                if (pfn) {

                    hde64_disasm((void*)pfn, &hs);
                    if (hs.flags & F_ERROR) {
#ifdef _DEBUG
                        OutputDebugString(L"HDE error");
#endif
                        break;
                    }
                    Address = (ULONG_PTR)pvImageBase + *(ULONG_PTR*)(pfn + hs.len + *(DWORD*)(pfn + (hs.len - 4)));
                    ImportEntry = (IMAGE_IMPORT_BY_NAME *)Address;
                    if (ImportEntry) {
                        Length = 1 + _strlen_a(ImportEntry->Name);
                        lpBuffer = HeapAlloc(ProcessHeap, HEAP_ZERO_MEMORY, (Length * sizeof(WCHAR)) + 100);
                        if (lpBuffer) {

                            MultiByteToWideChar(CP_ACP,
                                0,
                                (LPCSTR)&ImportEntry->Name,
                                -1,
                                lpBuffer,
                                (INT)Length);

                            _strcat_w(lpBuffer, L"\t");
                            ultostr_w(i + W32SYSCALLSTART, _strend_w(lpBuffer));
                            cuiPrintText(g_ConOut, lpBuffer, g_ConsoleOutput, TRUE);
                            HeapFree(ProcessHeap, 0, lpBuffer);
                        }
                    }
                }
            }

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
#ifdef _DEBUG
            OutputDebugString(L"wscg: exception during parsing win32k.sys");
#else
			;
#endif
        }

    } while (bCond); 
    
    if (pvImageBase != NULL)
        UnmapViewOfFile(pvImageBase);
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
    _In_ LPWSTR lpszWin32kImage
)
{
    BOOL       bRet = FALSE;
    ULONG      ServiceLimit, i, Win32kBuild = 0;
    ULONG     *pW32pServiceLimit = NULL;
    HANDLE     hSym = GetCurrentProcess();
    DWORD64   *pW32pServiceTable = NULL;
    PVOID      pvImageBase = NULL;
    WCHAR      szSymbolName[MAX_PATH + 1];
    WCHAR      szFullSymbolInfo[MAX_PATH * 2];

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

        __try {

            pSymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);

            RtlSecureZeroMemory(&g_SymbolsHead, sizeof(g_SymbolsHead));

            RtlSecureZeroMemory(szSymbolName, sizeof(szSymbolName));
            if (GetModuleFileNameW(NULL, szSymbolName, MAX_PATH) == 0)
                __leave;

            _strcpy_w(szFullSymbolInfo, L"SRV*");
            _filepath_w(szSymbolName, _strend_w(szFullSymbolInfo));
            _strcat_w(szFullSymbolInfo, L"Symbols");
            if (!CreateDirectoryW(&szFullSymbolInfo[4], NULL)) {
                if (GetLastError() != ERROR_ALREADY_EXISTS) {
                    cuiPrintText(g_ConOut, L"wscg: Cannot create symbols directory: ", g_ConsoleOutput, TRUE);
                    cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
                    __leave;
                }
            }
            _strcat_w(szFullSymbolInfo, L"*https://msdl.microsoft.com/download/symbols");
            if (!pSymInitializeW(hSym, szFullSymbolInfo, FALSE)) {
                cuiPrintText(g_ConOut, L"wscg: SymInitialize failed.", g_ConsoleOutput, TRUE);
                __leave;
            }

            pvImageBase = LdrMapInputFile(lpszWin32kImage);
            if (pvImageBase == NULL) {
                cuiPrintText(g_ConOut, L"wscg: Cannot load input file: ", g_ConsoleOutput, TRUE);
                cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
                __leave;
            }

            NtHeaders = LdrImageNtHeader(pvImageBase);
            if (NtHeaders == NULL) {
                cuiPrintText(g_ConOut, L"wscg: invalid input file.", g_ConsoleOutput, TRUE);
                __leave;
            }

            if (!pSymLoadModuleExW(hSym, NULL, lpszWin32kImage, NULL, (DWORD64)pvImageBase, 0, NULL, 0)) {
                cuiPrintText(g_ConOut, L"wscg: SymLoadModuleEx failed for input file with message: ", g_ConsoleOutput, TRUE);
                cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
                __leave;
            }

            if (!pSymEnumSymbolsW(hSym, (DWORD64)pvImageBase, NULL, SymEnumSymbolsProc, NULL)) {
                cuiPrintText(g_ConOut, L"wscg: SymEnumSymbols failed.", g_ConsoleOutput, TRUE);
                __leave;
            }

            pW32pServiceLimit = (ULONG *)SymbolAddressFromName(L"W32pServiceLimit");
            if (pW32pServiceLimit == NULL) {
                cuiPrintText(g_ConOut, L"wscg: W32pServiceLimit symbol not found.", g_ConsoleOutput, TRUE);
                __leave;
            }

            ServiceLimit = *pW32pServiceLimit;

            pW32pServiceTable = (DWORD64 *)SymbolAddressFromName(L"W32pServiceTable");
            if (pW32pServiceTable == NULL) {
                cuiPrintText(g_ConOut, L"wscg: W32pServiceTable symbol not found.", g_ConsoleOutput, TRUE);
                __leave;
            }

            for (i = 0; i < ServiceLimit; i++) {
                RtlSecureZeroMemory(szSymbolName, sizeof(szSymbolName));

                bRet = SymbolNameFromAddress(pW32pServiceTable[i] - NtHeaders->OptionalHeader.ImageBase + (DWORD64)pvImageBase,
                    szSymbolName,
                    W32SYSCALLSTART + i);

                RtlSecureZeroMemory(szFullSymbolInfo, sizeof(szFullSymbolInfo));
                if (!bRet)
                    _strcpy_w(szSymbolName, L"UnknownSyscall");
                wsprintfW(szFullSymbolInfo, PRINT_FMT, szSymbolName, W32SYSCALLSTART + i);
                cuiPrintText(g_ConOut, szFullSymbolInfo, g_ConsoleOutput, TRUE);
            }
        }
        __finally {
            if (pvImageBase) {
                pSymUnloadModule64(hSym, (DWORD64)pvImageBase);
                UnmapViewOfFile(pvImageBase);
            }
            pSymCleanup(hSym);
        }
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

    g_ConsoleOutput = TRUE;
    if (!GetConsoleMode(g_ConOut, &dwTemp)) {
        g_ConsoleOutput = FALSE;
    }
    SetConsoleMode(g_ConOut, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_OUTPUT);
    if (g_ConsoleOutput == FALSE) {
        WriteFile(g_ConOut, &BE, sizeof(WCHAR), &dwTemp, NULL);
    }

    szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (szArglist) {
        if (nArgs > 1) {
            if (PathFileExists(szArglist[1])) {
                wscg(szArglist[1]);
            }
            else {
                cuiPrintText(g_ConOut, L"wscg: Input File not found.", g_ConsoleOutput, TRUE);
            }
        }
        else {
            cuiPrintText(g_ConOut, L"Usage: wscg64 win32kfilename", g_ConsoleOutput, TRUE);
        }
        LocalFree(szArglist);
    }
    ExitProcess(0);
}

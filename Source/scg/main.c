/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2019
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.01
*
*  DATE:        20 Jan 2019
*
*  Ntdll/Win32u Syscall dumper
*  Based on gr8 scg project
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#if !defined UNICODE
#error ANSI build is not supported
#endif

#if defined (_MSC_VER)
#if (_MSC_VER >= 1900)
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libucrt.lib")
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif
#endif

#pragma warning(disable: 4091) //'typedef ': ignored on left of '' when no variable is declared

#include <Windows.h>
#include "minirtl\cmdline.h"
#include "minirtl\minirtl.h"

HANDLE     g_ConOut = NULL;
BOOL       g_ConsoleOutput = FALSE;
WCHAR      g_BE = 0xFEFF;

/*
* cuiPrintTextA
*
* Purpose:
*
* Output text to the console or file.
* ANSI version.
*
*/
VOID cuiPrintTextA(
    _In_ HANDLE hOutConsole,
    _In_ LPSTR lpText,
    _In_ BOOL ConsoleOutputEnabled,
    _In_ BOOL UseReturn
)
{
    SIZE_T consoleIO;
    DWORD bytesIO;
    LPSTR Buffer;

    if (lpText == NULL)
        return;

    consoleIO = _strlen_a(lpText);
    if ((consoleIO == 0) || (consoleIO > MAX_PATH * 4))
        return;

    consoleIO = 5 + consoleIO;
    Buffer = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, consoleIO);
    if (Buffer) {

        _strcpy_a(Buffer, lpText);
        if (UseReturn) _strcat_a(Buffer, "\r\n");

        consoleIO = _strlen_a(Buffer);

        if (ConsoleOutputEnabled != FALSE) {
            WriteConsoleA(hOutConsole, Buffer, (DWORD)consoleIO, &bytesIO, NULL);
        }
        else {
            WriteFile(hOutConsole, Buffer, (DWORD)consoleIO, &bytesIO, NULL);
        }
        HeapFree(GetProcessHeap(), 0, Buffer);
    }
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
    _In_ LPWSTR lpFileName
)
{
    HANDLE hFile, hMapping;
    PVOID  pvImageBase = NULL;

    hFile = CreateFile(lpFileName,
        GENERIC_READ,
        FILE_SHARE_READ |
        FILE_SHARE_WRITE |
        FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        0,
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
* scg
*
* Purpose:
*
* Generate syscall list from given dll.
*
*/
VOID scg(
    _In_ LPWSTR lpFileName)
{
    BOOL                     Is64 = FALSE;
    PIMAGE_FILE_HEADER       fHeader;
    PIMAGE_OPTIONAL_HEADER32 oh32 = NULL;
    PIMAGE_OPTIONAL_HEADER64 oh64 = NULL;
    PIMAGE_EXPORT_DIRECTORY  ExportDirectory = NULL;

    PULONG NameTableBase;
    PULONG FunctionsTableBase;
    PUSHORT NameOrdinalTableBase;

    PCHAR pvImageBase, FunctionName, FunctionAddress;
    SIZE_T FunctionNameLength;

    ULONG i, sid;

    CHAR outBuf[MAX_PATH * 2];

    pvImageBase = LdrMapInputFile(lpFileName);
    if (pvImageBase == NULL) {

        cuiPrintTextA(g_ConOut,
            "scg: cannot load input file\n",
            g_ConsoleOutput, FALSE);

        return;
    }

    __try {

        fHeader = (PIMAGE_FILE_HEADER)((ULONG_PTR)pvImageBase +
            ((PIMAGE_DOS_HEADER)pvImageBase)->e_lfanew + sizeof(DWORD));

        switch (fHeader->Machine) {

        case IMAGE_FILE_MACHINE_I386:
            oh32 = (PIMAGE_OPTIONAL_HEADER32)((ULONG_PTR)fHeader +
                sizeof(IMAGE_FILE_HEADER));

            ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pvImageBase +
                oh32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

            break;

        case  IMAGE_FILE_MACHINE_AMD64:
            oh64 = (PIMAGE_OPTIONAL_HEADER64)((ULONG_PTR)fHeader +
                sizeof(IMAGE_FILE_HEADER));

            ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pvImageBase +
                oh64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

            Is64 = TRUE;

            break;

        default:

            cuiPrintTextA(g_ConOut,
                "scg: unexpected image machine type\n",
                g_ConsoleOutput, FALSE);

            break;
        }

        if (ExportDirectory == NULL)
            __leave;

        if ((oh32 == NULL) && (oh64 == NULL))
            __leave;

        NameTableBase = (PULONG)(pvImageBase + (ULONG)ExportDirectory->AddressOfNames);
        NameOrdinalTableBase = (PUSHORT)(pvImageBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);
        FunctionsTableBase = (PULONG)((PCHAR)pvImageBase + (ULONG)ExportDirectory->AddressOfFunctions);

        for (i = 0; i < ExportDirectory->NumberOfNames; i++) {

            FunctionName = (PCHAR)((PCHAR)pvImageBase + NameTableBase[i]);
            if (*(USHORT*)FunctionName == 'tN') {

                FunctionNameLength = _strlen_a(FunctionName);
                if (FunctionNameLength <= MAX_PATH) {
                    sid = (DWORD)-1;
                    FunctionAddress = (CHAR *)((CHAR *)pvImageBase + FunctionsTableBase[NameOrdinalTableBase[i]]);

                    if (Is64) {
                        if (*(UCHAR*)((UCHAR*)FunctionAddress + 3) == 0xB8) {
                            sid = *(ULONG*)((UCHAR*)FunctionAddress + 4);
                        }
                    }
                    else {
                        if (*(UCHAR*)FunctionAddress == 0xB8) {
                            sid = *(ULONG*)((UCHAR*)FunctionAddress + 1);
                        }
                    }
                    if (sid != (DWORD)-1) {
                        _strncpy_a(outBuf, MAX_PATH, FunctionName, FunctionNameLength);
                        _strcat_a(outBuf, "\t");
                        ultostr_a(sid, _strend_a(outBuf));
                        cuiPrintTextA(g_ConOut, outBuf, g_ConsoleOutput, TRUE);
                    }
                    else {
                        OutputDebugStringA(FunctionName);
                        OutputDebugStringA("\r\nscg: syscall value not found\r\n");
                    }
                }
                else {
                    OutputDebugStringA("\r\nscg: Unexpected function name length\r\n");
                    break;
                }
            }
        }

    }
    __finally {
        UnmapViewOfFile(pvImageBase);
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
    ULONG ParamLen = 0, l;
    WCHAR szInputFile[MAX_PATH + 1];

    __security_init_cookie();

    g_ConOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_ConOut) {

        g_ConsoleOutput = TRUE;
        if (!GetConsoleMode(g_ConOut, &l)) {
            g_ConsoleOutput = FALSE;
        }
        SetConsoleMode(g_ConOut, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_OUTPUT);

        RtlSecureZeroMemory(szInputFile, sizeof(szInputFile));
        GetCommandLineParamW(GetCommandLineW(), 1, szInputFile, MAX_PATH, &ParamLen);
        if (ParamLen > 0) {
            scg(szInputFile);
        }
        else {
            cuiPrintTextA(g_ConOut, "Syscall Generator\r\nUsage: scg filename", g_ConsoleOutput, FALSE);
        }
    }
    ExitProcess(0);
}

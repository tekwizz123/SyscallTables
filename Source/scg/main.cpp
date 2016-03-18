#include <Windows.h>
#include <stdio.h>

#define PRINT_FMT  "%s\t%u\n"

//i don't think that someday ssdt will rise to 4097 entries =)
char *SdtFunctions[0x1000] = { 0 };

void scg(
	LPWSTR lpNtdllName
	)
{
	PIMAGE_DOS_HEADER mz;
	PIMAGE_FILE_HEADER pfh;
	PIMAGE_OPTIONAL_HEADER poh;
	PIMAGE_EXPORT_DIRECTORY pexd;
	PULONG AddressOfFunctions;
	PULONG AddressOfNames;
	PWORD AddressOfNameOrdinals;

	void *base;
	char *name;
	unsigned int number = 0;
	unsigned int count = 0;
	unsigned int i;
	void *addr;

	base = LoadLibraryW(lpNtdllName);
	if (!base) {

		printf_s("ntdll base not found");
		return;
	}

	__try {

		*(PBYTE *)&mz = (PBYTE)base;
		*(PBYTE *)&pfh = (PBYTE)base + mz->e_lfanew + sizeof(IMAGE_NT_SIGNATURE);
		*(PIMAGE_FILE_HEADER *)&poh = pfh + 1;
		*(PBYTE *)&pexd = (PBYTE)base + poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		*(PBYTE *)&AddressOfFunctions = (PBYTE)base + pexd->AddressOfFunctions;
		*(PBYTE *)&AddressOfNames = (PBYTE)base + pexd->AddressOfNames;
		*(PBYTE *)&AddressOfNameOrdinals = (PBYTE)base + pexd->AddressOfNameOrdinals;

		for(i = 0; i < pexd->NumberOfNames; i++)	{

			name = ((CHAR *) base + AddressOfNames[i]);
			addr = (PVOID *)((CHAR *)base + AddressOfFunctions[AddressOfNameOrdinals[i]]);

			if ( *(USHORT*)name == 'tN' ) {

#ifdef _WIN64
				//this is simple check for "mov eax, index"
				if ( *(UCHAR*)((UCHAR*)addr + 3) == 0xB8 ) {

					number = *(ULONG*)((UCHAR*)addr + 4 );
					printf_s(PRINT_FMT, name, number);
					SdtFunctions[count++] = name;
				}
#else
				if ( *(UCHAR*)addr == 0xB8 ) {

					number = *(ULONG*)((UCHAR*)addr + 1 );
					printf_s(PRINT_FMT, name, number);
					SdtFunctions[count++] = name;
				}
#endif
			}
		}

        FreeLibrary((HMODULE)base);

	} __except (EXCEPTION_EXECUTE_HANDLER) {

		printf_s("\n\nexception: %x", GetExceptionCode());
	}
}

int main(
	VOID
	) 
{
    LPWSTR *szArglist;
    INT nArgs = 0;

    szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (szArglist) {
        if (nArgs > 1) {
            scg(szArglist[1]);
        }
        LocalFree(szArglist);
    }
	return 0;
}
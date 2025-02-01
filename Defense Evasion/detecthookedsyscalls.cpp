#include <iostream>
#include <Windows.h>
#include <psapi.h>

//code from here - > https://github.com/tlsbollei/HookDetector
bool isSyscall(const char* funcName) {
    return (funcName[0] == 'N' && funcName[1] == 't') || (funcName[0] == 'Z' && funcName[1] == 'w');
}

void checkFunctionHook(void* funcAddress, const char* funcName) {
    BYTE originalBytes[] = { 0x4C, 0x8B, 0xD1, 0xB8 };
    BYTE firstBytes[sizeof(originalBytes)];
    SIZE_T bytesRead;

    if (ReadProcessMemory(GetCurrentProcess(), funcAddress, firstBytes, sizeof(originalBytes), &bytesRead) && bytesRead == sizeof(originalBytes)) {
        if (isSyscall(funcName)) {
            if (memcmp(firstBytes, originalBytes, sizeof(originalBytes)) == 0) {
                printf("Function %s is unhooked (Nt/Zw syscall).\n", funcName);
            }
            else if (firstBytes[0] == 0xE9 || firstBytes[0] == 0xFF) {
                printf("Function %s is hooked (detected JMP or CALL in syscall)!!!\n", funcName);
            }
            else {
                printf("Function %s might be modified (unexpected bytes in syscall).\n", funcName);
            }
        }
        else {
            if (firstBytes[0] == 0xE9 || firstBytes[0] == 0xFF) {
                printf("Function %s is hooked (detected JMP or CALL).\n", funcName);
            }
            else {
                printf("Function %s is unhooked (regular function).\n", funcName);
            }
        }
    }
    else {
        printf("Failed to read function %s\n", funcName);
    }
}


int main() {
    HMODULE libraryBase = LoadLibraryA("ntdll");
    if (libraryBase == NULL) {
        printf("Failed to load NTDLL.dll. Error: %lu\n", GetLastError());
        return -1;
    }


    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(libraryBase);
    PIMAGE_NT_HEADERS imageNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

    if (imageNTHeaders == NULL) {
        printf("Failed to load NT Headers of the Portable Executable file structure\n");
        return -1;
    }

    DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((DWORD_PTR)libraryBase + exportDirectoryRVA);

    PDWORD addresOfFunctionsRVA = reinterpret_cast<PDWORD>((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
    PDWORD addressOfNamesRVA = reinterpret_cast<PDWORD>((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinalsRVA = reinterpret_cast<PWORD>((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < imageExportDirectory->NumberOfNames; i++) {
        const char* funcName = reinterpret_cast<const char*>((DWORD_PTR)libraryBase + addressOfNamesRVA[i]);
        void* funcAddress = reinterpret_cast<void*>((DWORD_PTR)libraryBase + addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]]);

        checkFunctionHook(funcAddress, funcName);
    }

    return 0;
}

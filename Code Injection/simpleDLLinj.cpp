#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("usage: %s <PID> <DLL Path>\n", argv[0]);
        return 1;
    }

    HANDLE processHandle;
    PVOID remoteBuffer;
    DWORD pid = atoi(argv[1]);
    if (pid == 0) {
        printf("Invalid PID provided.\n");
        return 1;
    }

    wchar_t dllPath[MAX_PATH];
    size_t convertedChars = 0;
    if (mbstowcs_s(&convertedChars, dllPath, MAX_PATH, argv[2], _TRUNCATE) != 0) { //mbstowcs_s requires size parameters, prevents buffer overflows
        printf("Failed to convert DLL path to wide string.\n");
        return 1;
    }

    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);  // retrieve process handle
    if (processHandle == NULL) {
        printf("Failed to open process. Error: %lu\n", GetLastError());
        return 1;
    }

    remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof(dllPath), MEM_COMMIT, PAGE_READWRITE);  // allocate memory inside of target process
    if (remoteBuffer == NULL) {
        printf("Failed to allocate memory in the target process. Error: %lu\n", GetLastError());
        CloseHandle(processHandle);
        return 1;
    }

    if (!WriteProcessMemory(processHandle, remoteBuffer, (LPVOID)dllPath, sizeof(dllPath), NULL)) { // write payload to allocated memory
        printf("Failed to write to target process memory. Error: %lu\n", GetLastError());
        VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return 1;
    }

    HMODULE hKernel32 = GetModuleHandle(TEXT("Kernel32"));  // retrieve kernel32 handle
    if (hKernel32 == NULL) {
        printf("failed to get handle of kernel32. Error: %lu\n", GetLastError());
        VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return 1;
    }

    PTHREAD_START_ROUTINE loadLibraryAddress = (PTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW"); //find loadlibraryW, needed to load dll
    if (loadLibraryAddress == NULL) {
        printf("failed to get address of LoadLibraryW. Error: %lu\n", GetLastError());
        VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return 1;
    }

    if (loadLibraryAddress == NULL) {
        printf("failed to get address of LoadLibraryW. Error: %lu\n", GetLastError());
        VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return 1;
    }

    HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, loadLibraryAddress, remoteBuffer, 0, NULL); // execute payload
    if (remoteThread == NULL) {
        printf("failed to create remote thread. Error: %lu\n", GetLastError());
        VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return 1;
    }

    WaitForSingleObject(remoteThread, INFINITE);

    VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(remoteThread);
    CloseHandle(processHandle);

    printf("dll injected successfully\n");
    printf("dll injected successfully\n");
    return 0;
}

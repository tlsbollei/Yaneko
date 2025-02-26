#include <windows.h>
#include <stdio.h>
#include <wchar.h>

typedef struct {
    const wchar_t* name;
    const wchar_t* msg;
} EDR;

EDR edrList[] = {
    {L"atrsdfw.sys", L"Altiris Symantec detected."},
    {L"avgtpx86.sys", L"AVG Technologies detected."},
    {L"avgtpx64.sys", L"AVG Technologies detected."},
    {L"naswSP.sys", L"Avast detected."},
    {L"edrsensor.sys", L"BitDefender detected."},
    {L"CarbonBlackK.sys", L"Carbon Black detected."},
    {L"csacentr.sys", L"Cisco detected."},
    {L"csaenh.sys", L"Cisco detected."},
    {L"csareg.sys", L"Cisco detected."},
    {L"csascr.sys", L"Cisco detected."},
    {L"im.sys", L"CrowdStrike detected."},
    {L"cmdguard.sys", L"Comodo Security detected."},
    {L"CyOptics.sys", L"Cylance detected."},
    {L"fsatp.sys", L"F-Secure detected."},
    {L"klifks.sys", L"Kaspersky detected."},
    {L"mbamwatchdog.sys", L"Malwarebytes detected."},
    {L"mfeaskm.sys", L"McAfee detected."},
    {L"PSINPROC.SYS", L"Panda Security detected."},
    {L"SentinelMonitor.sys", L"SentinelOne detected."},
    {L"SAVOnAccess.sys", L"Sophos detected."},
    {L"pgpwdefs.sys", L"Symantec detected."},
    {L"one.txt", L"test detected."} // prototype for checking
};

#define NUM_EDRS (sizeof(edrList) / sizeof(edrList[0]))

int wmain(void) {

    wchar_t searchPath[] = L"C:\\Windows\\System32\\drivers\\*";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"Error opening drivers directory: %ld\n", GetLastError());
        return 1;
    }
    BOOL edr_present = false;
    do {
        const wchar_t* fileName = findData.cFileName;
        for (size_t i = 0; i < NUM_EDRS; i++) {
            if (_wcsicmp(fileName, edrList[i].name) == 0) {
                wprintf(L"[+] %s\n", edrList[i].msg);
                edr_present = true;
                break;
            }
        }
        if (wcsncmp(fileName, L"EcatService", 11) == 0) {
            wprintf(L"[+] RSA NetWitness Endpoint detected.\n");
        }
    } while (FindNextFileW(hFind, &findData));
    if (!edr_present) {
        wprintf(L"[i] No EDR detected.\n\n");
    }
    FindClose(hFind);
    return 0;
}


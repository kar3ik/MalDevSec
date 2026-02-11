#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

// Maximum function name length
#define MAX_NAME_LEN 64

// Convert to lowercase for case-insensitive comparison
void ToLower(char *str)
{
    for (int i = 0; str[i]; i++)
    {
        str[i] = tolower(str[i]);
    }
}

// Extract syscall number from ntdll function stub
BYTE ExtractSyscallNumber(FARPROC pFunc)
{
    if (pFunc == NULL)
        return 0;

    PBYTE pBytes = (PBYTE)pFunc;

    // Common syscall stub patterns in x64 Windows:
    // Pattern 1: mov r10, rcx (4C 8B D1) + mov eax, SS (B8 SS 00 00 00) + syscall (0F 05)
    // Pattern 2: mov eax, SS (B8 SS 00 00 00) + syscall (0F 05)
    // Pattern 3: jmp to another stub (E9) - follow it

    // Handle jmp stubs (some functions jump to a common implementation)
    if (pBytes[0] == 0xE9)
    {
        // Calculate jump target
        DWORD offset = *(DWORD *)(pBytes + 1);
        pBytes = pBytes + 5 + offset;
    }

    // Search for mov eax, imm32 pattern (B8 xx xx xx xx)
    for (int i = 0; i < 32; i++)
    {
        if (pBytes[i] == 0xB8)
        {                         // mov eax, opcode
            return pBytes[i + 1]; // Syscall number is the first byte of the immediate
        }
    }

    return 0;
}

// Get syscall number for a given function name
BYTE GetSyscallNumber(const char *funcName)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
    {
        printf("[-] Failed to get ntdll handle\n");
        return 0;
    }

    // Try with "Nt" prefix
    char fullName[MAX_NAME_LEN];
    snprintf(fullName, sizeof(fullName), "Nt%s", funcName);

    FARPROC pFunc = GetProcAddress(hNtdll, fullName);

    // If not found, try with "Zw" prefix
    if (!pFunc)
    {
        snprintf(fullName, sizeof(fullName), "Zw%s", funcName);
        pFunc = GetProcAddress(hNtdll, fullName);
    }

    // If still not found, try the original name
    if (!pFunc)
    {
        pFunc = GetProcAddress(hNtdll, funcName);
    }

    if (!pFunc)
    {
        return 0;
    }

    return ExtractSyscallNumber(pFunc);
}

// List common NT functions (for suggestions)
void ListCommonFunctions()
{
    const char *commonFuncs[] = {
        "AllocateVirtualMemory",
        "ProtectVirtualMemory",
        "CreateThreadEx",
        "QueueApcThreadEx",
        "DelayExecution",
        "FreeVirtualMemory",
        "WriteVirtualMemory",
        "ReadVirtualMemory",
        "QueryInformationProcess",
        "OpenProcess",
        "Close",
        "CreateFile",
        "ReadFile",
        "WriteFile",
        "DeviceIoControlFile",
        "CreateSection",
        "MapViewOfSection",
        "UnmapViewOfSection",
        "SignalAndWaitForSingleObject",
        "WaitForSingleObject",
        "WaitForMultipleObjects",
        "ResumeThread",
        "SuspendThread",
        "GetContextThread",
        "SetContextThread",
        "QuerySystemInformation",
        "SetInformationFile",
        "QueryDirectoryFile",
        "CreateKey",
        "OpenKey",
        "QueryValueKey",
        "SetValueKey",
        NULL};

    printf("\nCommon function names (add 'Nt' or 'Zw' prefix):\n");
    for (int i = 0; commonFuncs[i] != NULL; i++)
    {
        if (i % 3 == 0)
            printf("    ");
        printf("%-28s", commonFuncs[i]);
        if (i % 3 == 2)
            printf("\n");
    }
    printf("\n");
}

// Dump function bytes for debugging
void DumpFunctionBytes(const char *funcName, FARPROC pFunc)
{
    printf("\n[*] Raw bytes for %s at 0x%p:\n    ", funcName, pFunc);
    PBYTE pBytes = (PBYTE)pFunc;
    for (int i = 0; i < 20; i++)
    {
        printf("%02X ", pBytes[i]);
        if (i == 9)
            printf("\n    ");
    }
    printf("\n");
}

int main()
{
    printf("========================================\n");
    printf("    Windows Syscall Number Finder\n");
    printf("========================================\n\n");

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
    {
        printf("[-] Failed to get ntdll.dll handle\n");
        return 1;
    }

    printf("[*] ntdll.dll base: 0x%p\n", hNtdll);
    printf("[*] Windows version: ");

    // Get Windows version
    typedef NTSTATUS(NTAPI * pRtlGetVersion)(PRTL_OSVERSIONINFOW);
    pRtlGetVersion RtlGetVersion = (pRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");

    if (RtlGetVersion)
    {
        RTL_OSVERSIONINFOW osInfo = {0};
        osInfo.dwOSVersionInfoSize = sizeof(osInfo);
        RtlGetVersion(&osInfo);
        printf("%d.%d.%d\n", osInfo.dwMajorVersion, osInfo.dwMinorVersion, osInfo.dwBuildNumber);
    }
    else
    {
        printf("(unknown)\n");
    }

    ListCommonFunctions();

    char input[MAX_NAME_LEN];

    while (1)
    {
        printf("\n----------------------------------------\n");
        printf("Enter function name (or 'quit' to exit, 'list' for suggestions):\n");
        printf("> ");

        if (!fgets(input, sizeof(input), stdin))
            break;

        // Remove newline
        input[strcspn(input, "\n")] = 0;

        // Check for empty input
        if (strlen(input) == 0)
            continue;

        // Convert to lowercase for comparison
        char lowerInput[MAX_NAME_LEN];
        strcpy(lowerInput, input);
        ToLower(lowerInput);

        // Check for quit
        if (strcmp(lowerInput, "quit") == 0 || strcmp(lowerInput, "exit") == 0)
        {
            printf("[*] Exiting...\n");
            break;
        }

        // Check for list
        if (strcmp(lowerInput, "list") == 0)
        {
            ListCommonFunctions();
            continue;
        }

        // Check for help
        if (strcmp(lowerInput, "help") == 0 || strcmp(lowerInput, "?") == 0)
        {
            printf("\n[*] Usage: Enter a function name like 'CreateThreadEx'\n");
            printf("    The program will automatically try 'Nt' and 'Zw' prefixes\n");
            printf("    Examples: AllocateVirtualMemory, CreateThreadEx, OpenProcess\n");
            continue;
        }

        printf("\n[+] Searching for: %s\n", input);

        // Get the syscall number
        BYTE ssn = GetSyscallNumber(input);

        if (ssn != 0)
        {
            printf("[✓] FOUND!\n");

            // Try to get both Nt and Zw variants
            char ntName[MAX_NAME_LEN];
            char zwName[MAX_NAME_LEN];
            snprintf(ntName, sizeof(ntName), "Nt%s", input);
            snprintf(zwName, sizeof(zwName), "Zw%s", input);

            FARPROC pNt = GetProcAddress(hNtdll, ntName);
            FARPROC pZw = GetProcAddress(hNtdll, zwName);

            printf("    Syscall Number: 0x%02X (%d)\n", ssn, ssn);

            if (pNt)
            {
                printf("    Nt%s address: 0x%p\n", input, pNt);
            }
            if (pZw)
            {
                printf("    Zw%s address: 0x%p\n", input, pZw);
            }

            // Show define format
            char defineName[MAX_NAME_LEN];
            for (int i = 0; input[i]; i++)
            {
                defineName[i] = toupper(input[i]);
            }
            defineName[strlen(input)] = 0;

            printf("\n    #define SYSCALL_NT_%s 0x%02X\n", defineName, ssn);

            // Ask if user wants to see raw bytes
            printf("\n    Show raw function bytes? (y/n): ");
            char choice = getchar();
            while (getchar() != '\n')
                ; // Clear buffer

            if (choice == 'y' || choice == 'Y')
            {
                if (pNt)
                    DumpFunctionBytes(ntName, pNt);
                else if (pZw)
                    DumpFunctionBytes(zwName, pZw);
            }
        }
        else
        {
            printf("[✗] NOT FOUND\n");
            printf("    Could not find function '%s' in ntdll.dll\n", input);
            printf("    Try using 'list' to see common function names\n");
            printf("    Make sure to omit the 'Nt'/'Zw' prefix\n");
        }
    }

    return 0;
}

// x86_64-w64-mingw32-gcc -o syscall_finder.exe syscall_finder.c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define MAX_FUNCS 4096
#define MAX_NAME 256

typedef struct
{
    char name[MAX_NAME];
    FARPROC address;
    BYTE syscall_number;
    char prefix[8];
} SYSCALL_ENTRY;

SYSCALL_ENTRY entries[MAX_FUNCS];
int entry_count = 0;

// Statistics counters
typedef struct
{
    int nt_count;
    int zw_count;
    int rtl_count;
    int ldr_count;
    int csr_count;
    int dbg_count;
    int ki_count;
    int etw_count;
    int tp_count;
    int alpc_count;
    int other_count;
    int with_syscall;
    int without_syscall;
    int total_exports;
} STATISTICS;

STATISTICS stats = {0};

// Extract syscall number from function stub
BYTE extract_syscall_number(FARPROC pFunc)
{
    if (!pFunc)
        return 0;

    PBYTE pBytes = (PBYTE)pFunc;

    // Windows 10/11 syscall stub pattern
    for (int i = 0; i < 64; i++)
    {
        // Look for mov eax, imm32 (B8 xx xx xx xx)
        if (pBytes[i] == 0xB8)
        {
            return pBytes[i + 1];
        }
    }
    return 0;
}

// Extract prefix from function name
void get_prefix(const char *name, char *prefix)
{
    prefix[0] = '\0';
    if (!name)
        return;

    int i = 0;
    while (name[i] && i < 7)
    {
        if (name[i] >= 'A' && name[i] <= 'Z')
        {
            prefix[i] = name[i];
        }
        else if (name[i] >= 'a' && name[i] <= 'z')
        {
            prefix[i] = name[i] - 32;
        }
        else
        {
            break;
        }
        i++;
    }
    prefix[i] = '\0';
}

// Update statistics based on function prefix
void update_stats(const char *name, BYTE has_syscall)
{
    char prefix[8] = {0};
    get_prefix(name, prefix);

    if (strcmp(prefix, "NT") == 0)
        stats.nt_count++;
    else if (strcmp(prefix, "ZW") == 0)
        stats.zw_count++;
    else if (strcmp(prefix, "RTL") == 0)
        stats.rtl_count++;
    else if (strcmp(prefix, "LDR") == 0)
        stats.ldr_count++;
    else if (strcmp(prefix, "CSR") == 0)
        stats.csr_count++;
    else if (strcmp(prefix, "DBG") == 0)
        stats.dbg_count++;
    else if (strcmp(prefix, "KI") == 0)
        stats.ki_count++;
    else if (strcmp(prefix, "ETW") == 0)
        stats.etw_count++;
    else if (strcmp(prefix, "TP") == 0)
        stats.tp_count++;
    else if (strcmp(prefix, "ALPC") == 0)
        stats.alpc_count++;
    else
        stats.other_count++;

    if (has_syscall)
        stats.with_syscall++;
    else
        stats.without_syscall++;
}

int compare_names(const void *a, const void *b)
{
    return _stricmp(((SYSCALL_ENTRY *)a)->name, ((SYSCALL_ENTRY *)b)->name);
}

int compare_prefix(const void *a, const void *b)
{
    int prefix_cmp = _stricmp(((SYSCALL_ENTRY *)a)->prefix, ((SYSCALL_ENTRY *)b)->prefix);
    if (prefix_cmp == 0)
    {
        return _stricmp(((SYSCALL_ENTRY *)a)->name, ((SYSCALL_ENTRY *)b)->name);
    }
    return prefix_cmp;
}

void get_windows_version()
{
    typedef LONG(NTAPI * pRtlGetVersion)(PRTL_OSVERSIONINFOW);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    if (hNtdll)
    {
        pRtlGetVersion RtlGetVersion = (pRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
        if (RtlGetVersion)
        {
            RTL_OSVERSIONINFOW osver = {0};
            osver.dwOSVersionInfoSize = sizeof(osver);
            if (RtlGetVersion(&osver) == 0)
            {
                printf("[*] Windows Version: %lu.%lu (Build %lu)\n",
                       osver.dwMajorVersion, osver.dwMinorVersion, osver.dwBuildNumber);
            }
        }
    }
}

// Safe memory access without SEH (GCC-compatible)
BYTE *SafePtr(PBYTE base, DWORD offset, DWORD size)
{
    if (!base || offset == 0)
        return NULL;

    // Simple bounds checking
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)(base + offset), &mbi, sizeof(mbi)) == 0)
    {
        return NULL;
    }

    // Check if memory is readable
    if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
    {
        return NULL;
    }

    return base + offset;
}

void enumerate_all_ntdll_exports()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
    {
        hNtdll = LoadLibraryA("ntdll.dll");
        if (!hNtdll)
        {
            printf("[-] Failed to load ntdll.dll\n");
            return;
        }
    }

    printf("[*] Enumerating ALL exports from ntdll.dll at %p...\n", hNtdll);

    BYTE *base = (BYTE *)hNtdll;

    // Verify DOS header
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)base;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("[-] Invalid DOS signature\n");
        return;
    }

    // Get NT headers
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(base + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("[-] Invalid NT signature\n");
        return;
    }

    // Get export directory
    DWORD exportRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRVA)
    {
        printf("[-] No export directory found\n");
        return;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(base + exportRVA);

    // Safely get pointers using VirtualQuery
    DWORD *pNames = (DWORD *)SafePtr(base, pExportDir->AddressOfNames, sizeof(DWORD));
    WORD *pOrdinals = (WORD *)SafePtr(base, pExportDir->AddressOfNameOrdinals, sizeof(WORD));
    DWORD *pFunctions = (DWORD *)SafePtr(base, pExportDir->AddressOfFunctions, sizeof(DWORD));

    if (!pNames || !pOrdinals || !pFunctions)
    {
        printf("[-] Failed to access export directory\n");

        // Fallback: Use GetProcAddress for common functions
        printf("[*] Using fallback method (GetProcAddress)...\n");

        const char *fallback_funcs[] = {
            "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx",
            "NtQueueApcThreadEx", "NtDelayExecution", "NtOpenProcess",
            "RtlAllocateHeap", "RtlFreeHeap", "RtlInitUnicodeString",
            "LdrLoadDll", "LdrGetProcedureAddress", "DbgPrint",
            NULL};

        for (int i = 0; fallback_funcs[i] != NULL && entry_count < MAX_FUNCS; i++)
        {
            FARPROC pFunc = GetProcAddress(hNtdll, fallback_funcs[i]);
            if (pFunc)
            {
                strcpy(entries[entry_count].name, fallback_funcs[i]);
                entries[entry_count].address = pFunc;
                entries[entry_count].syscall_number = extract_syscall_number(pFunc);
                get_prefix(fallback_funcs[i], entries[entry_count].prefix);
                update_stats(fallback_funcs[i], entries[entry_count].syscall_number != 0);
                entry_count++;
            }
        }

        stats.total_exports = entry_count;
        return;
    }

    stats.total_exports = pExportDir->NumberOfNames;
    printf("[*] Total exports in ntdll.dll: %lu\n", stats.total_exports);
    printf("[*] Reading ALL function names (this may take a moment)...\n");

    // Read all export names with careful bounds checking
    for (DWORD i = 0; i < pExportDir->NumberOfNames && entry_count < MAX_FUNCS; i++)
    {

        // Check if pNames[i] is accessible
        if ((PBYTE)pNames + (i * sizeof(DWORD)) > (PBYTE)hNtdll + 0x200000)
        {
            continue;
        }

        DWORD nameRVA = pNames[i];
        if (!nameRVA || nameRVA > 0x200000)
            continue;

        char *funcName = (char *)SafePtr(base, nameRVA, 1);
        if (!funcName)
            continue;

        // Check if pOrdinals[i] is accessible
        if ((PBYTE)pOrdinals + (i * sizeof(WORD)) > (PBYTE)hNtdll + 0x200000)
        {
            continue;
        }

        WORD ordinal = pOrdinals[i];

        // Check if pFunctions[ordinal] is accessible
        if ((PBYTE)pFunctions + (ordinal * sizeof(DWORD)) > (PBYTE)hNtdll + 0x200000)
        {
            continue;
        }

        DWORD funcRVA = pFunctions[ordinal];
        if (!funcRVA || funcRVA > 0x200000)
            continue;

        FARPROC pFunc = (FARPROC)(base + funcRVA);

        // Check for duplicates
        int already_exists = 0;
        for (int j = 0; j < entry_count; j++)
        {
            if (strcmp(entries[j].name, funcName) == 0)
            {
                already_exists = 1;
                break;
            }
        }

        if (!already_exists)
        {
            strncpy(entries[entry_count].name, funcName, MAX_NAME - 1);
            entries[entry_count].name[MAX_NAME - 1] = '\0';
            entries[entry_count].address = pFunc;
            entries[entry_count].syscall_number = extract_syscall_number(pFunc);
            get_prefix(funcName, entries[entry_count].prefix);

            update_stats(funcName, entries[entry_count].syscall_number != 0);
            entry_count++;

            // Show progress
            if (entry_count % 100 == 0)
            {
                printf("[*] Loaded %d functions...\n", entry_count);
            }
        }
    }

    // Sort alphabetically
    if (entry_count > 0)
    {
        qsort(entries, entry_count, sizeof(SYSCALL_ENTRY), compare_names);
    }

    printf("[*] TOTAL functions loaded: %d/%lu\n", entry_count, stats.total_exports);
}

void show_detailed_statistics()
{
    printf("\n========================================\n");
    printf("       COMPLETE ntdll.dll STATISTICS\n");
    printf("========================================\n");
    printf("  Total Exports in DLL : %d\n", stats.total_exports);
    printf("  Functions Loaded     : %d\n", entry_count);
    printf("  Coverage            : %.1f%%\n",
           entry_count > 0 ? (float)entry_count / stats.total_exports * 100 : 0);
    printf("----------------------------------------\n");
    printf("  BY PREFIX:\n");
    printf("  Nt  (Native API)     : %d\n", stats.nt_count);
    printf("  Zw  (Native API)     : %d\n", stats.zw_count);
    printf("  Rtl (Runtime Library): %d\n", stats.rtl_count);
    printf("  Ldr (Loader)         : %d\n", stats.ldr_count);
    printf("  Csr (Client Server)  : %d\n", stats.csr_count);
    printf("  Dbg (Debugger)       : %d\n", stats.dbg_count);
    printf("  Ki  (Kernel)         : %d\n", stats.ki_count);
    printf("  Etw (Event Tracing)  : %d\n", stats.etw_count);
    printf("  Tp  (Thread Pool)    : %d\n", stats.tp_count);
    printf("  Alpc (ALPC)          : %d\n", stats.alpc_count);
    printf("  Other Prefixes       : %d\n", stats.other_count);
    printf("----------------------------------------\n");
    printf("  SYSCALLS:\n");
    printf("  With syscall number  : %d (%.1f%% of loaded)\n",
           stats.with_syscall, (float)stats.with_syscall / entry_count * 100);
    printf("  Without syscall      : %d (%.1f%% of loaded)\n",
           stats.without_syscall, (float)stats.without_syscall / entry_count * 100);
    printf("========================================\n\n");
}

void list_by_prefix(char *prefix)
{
    printf("\n=== Functions with prefix '%s' ===\n", prefix);
    int count = 0;
    char upper_prefix[8];
    strcpy(upper_prefix, prefix);
    for (char *p = upper_prefix; *p; p++)
        *p = toupper(*p);

    for (int i = 0; i < entry_count; i++)
    {
        if (_strnicmp(entries[i].name, upper_prefix, strlen(upper_prefix)) == 0)
        {
            printf("%-40s | 0x%02X | %s\n",
                   entries[i].name,
                   entries[i].syscall_number,
                   entries[i].syscall_number ? "SYSCALL" : "        ");
            count++;
        }
    }
    printf("=== End (%d functions) ===\n\n", count);
}

void show_all_prefixes()
{
    printf("\n=== Available Prefixes ===\n");
    printf("  %-6s - %d functions\n", "Nt", stats.nt_count);
    printf("  %-6s - %d functions\n", "Zw", stats.zw_count);
    printf("  %-6s - %d functions\n", "Rtl", stats.rtl_count);
    printf("  %-6s - %d functions\n", "Ldr", stats.ldr_count);
    printf("  %-6s - %d functions\n", "Csr", stats.csr_count);
    printf("  %-6s - %d functions\n", "Dbg", stats.dbg_count);
    printf("  %-6s - %d functions\n", "Ki", stats.ki_count);
    printf("  %-6s - %d functions\n", "Etw", stats.etw_count);
    printf("  %-6s - %d functions\n", "Tp", stats.tp_count);
    printf("  %-6s - %d functions\n", "Alpc", stats.alpc_count);
    printf("  %-6s - %d functions\n", "Other", stats.other_count);
    printf("\n  Use: list Nt, list Rtl, list Zw, etc.\n");
    printf("================================\n\n");
}

void search_function(char *input)
{
    if (entry_count == 0)
    {
        printf("[-] No functions loaded. Cannot search.\n");
        return;
    }

    printf("\n[+] Searching for: '%s'\n", input);
    printf("----------------------------------------\n");

    // Try exact match
    for (int i = 0; i < entry_count; i++)
    {
        if (_stricmp(entries[i].name, input) == 0)
        {
            printf("\n✓ FOUND!\n");
            printf("   Function : %s\n", entries[i].name);
            printf("   Prefix   : %s\n", entries[i].prefix);
            printf("   Address  : %p\n", entries[i].address);
            printf("   Syscall  : 0x%02X (%d)\n",
                   entries[i].syscall_number,
                   entries[i].syscall_number);

            if (entries[i].syscall_number != 0)
            {
                char define_name[MAX_NAME];
                strcpy(define_name, entries[i].name);
                if (strncmp(define_name, "Nt", 2) == 0 || strncmp(define_name, "Zw", 2) == 0)
                {
                    char *define_part = define_name + 2;
                    for (char *p = define_part; *p; p++)
                        *p = toupper(*p);
                    printf("\n   #define SYSCALL_%s 0x%02X\n", define_part, entries[i].syscall_number);
                }
            }
            printf("\n");
            return;
        }
    }

    // Show partial matches
    printf("\n[?] No exact match. Similar functions:\n");
    int count = 0;
    for (int i = 0; i < entry_count && count < 20; i++)
    {
        if (strstr(entries[i].name, input) != NULL)
        {
            printf("   %-40s | 0x%02X | %s\n",
                   entries[i].name,
                   entries[i].syscall_number,
                   entries[i].prefix);
            count++;
        }
    }

    if (count == 0)
    {
        printf("   No matches found.\n");
    }
    printf("\n");
}

void show_help()
{
    printf("\n========================================\n");
    printf("              COMMANDS\n");
    printf("========================================\n");
    printf("  SEARCH:\n");
    printf("    function name    - Search for any function\n");
    printf("\n  LIST:\n");
    printf("    list            - Show ALL functions (WARNING: very long!)\n");
    printf("    list Nt         - Show only Nt functions\n");
    printf("    list Zw         - Show only Zw functions\n");
    printf("    list Rtl        - Show only Rtl functions\n");
    printf("    list [prefix]   - Show functions with specific prefix\n");
    printf("\n  STATISTICS:\n");
    printf("    stats           - Show detailed statistics\n");
    printf("    prefixes        - Show all available prefixes\n");
    printf("\n  SYSCALLS:\n");
    printf("    syscalls        - Show only functions with syscall numbers (Nt/Zw)\n");
    printf("\n  OTHER:\n");
    printf("    help            - Show this help\n");
    printf("    quit            - Exit program\n");
    printf("\n  Examples:\n");
    printf("    > AllocateVirtualMemory\n");
    printf("    > RtlAllocateHeap\n");
    printf("    > list Nt\n");
    printf("    > stats\n");
    printf("========================================\n\n");
}

int main()
{
    printf("\n========================================\n");
    printf("    Complete ntdll.dll Export Analyzer\n");
    printf("========================================\n");

    get_windows_version();
    enumerate_all_ntdll_exports();

    if (entry_count == 0)
    {
        printf("\n[-] CRITICAL: No functions loaded!\n");
        printf("[-] Press Enter to exit...");
        getchar();
        return 1;
    }

    show_detailed_statistics();
    printf("[*] System ready. Type 'help' for commands.\n\n");

    char input[MAX_NAME];

    while (1)
    {
        printf("----------------------------------------\n");
        printf("> ");

        if (!fgets(input, sizeof(input), stdin))
            break;

        // Remove newline
        size_t len = strlen(input);
        if (len > 0 && input[len - 1] == '\n')
        {
            input[len - 1] = 0;
        }

        if (strlen(input) == 0)
            continue;

        // Exit commands
        if (_stricmp(input, "quit") == 0 || _stricmp(input, "exit") == 0)
        {
            printf("[*] Goodbye!\n");
            break;
        }

        // Help
        if (_stricmp(input, "help") == 0 || _stricmp(input, "?") == 0)
        {
            show_help();
            continue;
        }

        // Statistics
        if (_stricmp(input, "stats") == 0)
        {
            show_detailed_statistics();
            continue;
        }

        // Show all prefixes
        if (_stricmp(input, "prefixes") == 0)
        {
            show_all_prefixes();
            continue;
        }

        // List commands
        if (_strnicmp(input, "list", 4) == 0)
        {
            char *prefix = input + 4;
            while (*prefix == ' ')
                prefix++;

            if (*prefix == '\0')
            {
                // Show ALL functions
                printf("\n=== ALL %d ntdll.dll FUNCTIONS ===\n", entry_count);
                printf("WARNING: Very long list! Press Ctrl+C to break.\n\n");
                for (int i = 0; i < entry_count; i++)
                {
                    printf("%-40s | 0x%02X | %-6s | %p\n",
                           entries[i].name,
                           entries[i].syscall_number,
                           entries[i].prefix,
                           entries[i].address);
                }
                printf("=== End (%d functions) ===\n\n", entry_count);
            }
            else
            {
                list_by_prefix(prefix);
            }
            continue;
        }

        // Show syscall functions only
        if (_stricmp(input, "syscalls") == 0)
        {
            printf("\n=== Functions with Syscall Numbers (Nt/Zw) ===\n");
            int count = 0;
            for (int i = 0; i < entry_count; i++)
            {
                if (entries[i].syscall_number != 0)
                {
                    printf("%-40s | 0x%02X\n", entries[i].name, entries[i].syscall_number);
                    count++;
                }
            }
            printf("=== End (%d functions) ===\n\n", count);
            continue;
        }

        // Search function
        search_function(input);
    }

    return 0;
}

// gcc -o ntdll_analyzer.exe ntdll_analyzer.c -O2 -s
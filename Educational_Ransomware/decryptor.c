/*
 * Decryptor for the ransomware output files.
 * Reads the AES-256 key (32 bytes, hex encoded) from "keyfile.c" (as per original challenge context).
 * Expects encrypted files to start with 16-byte IV, then ciphertext.
 * Decrypts files in-place.
 * Usage: decryptor.exe DIR_TO_DECRYPT/
 */

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// You may want to set this to the same as in encryption code
#define TARGET_DIR "fake_important_files\\"
// change to "." to run elsewhere or add argv[1] support

#define KEYFILE_NAME "keyfile.txt"
#define AES_KEY_SIZE 32

// Read the 32-byte (64 char) hex key string from keyfile.c
int read_key_from_keyfile(const char *filename, BYTE *key_out)
{
    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf("Could not open keyfile: %s\n", filename);
        return 0;
    }
    char line[128];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        printf("Could not read from keyfile\n");
        return 0;
    }
    fclose(f);
    // Remove whitespace/newline
    // This line finds the position of the first newline character in the 'line' buffer, if present.
    char *newline = strchr(line, '\n');
    if (newline) *newline = 0;
    size_t hexlen = strlen(line);
    if (hexlen < 64) {
        printf("Keyfile contents too short (got len %zu)\n", hexlen);
        return 0;
    }
    // decode hex
    for (int i = 0; i < 32; ++i) {
        unsigned int v;
        if (sscanf(&line[i*2], "%2x", &v) != 1) {
            printf("Malformed keyfile at pos %d\n", i*2); return 0;
        }
        key_out[i] = (BYTE)v;
    }
    return 1;
}

int decrypt_file(const char *filepath, HCRYPTKEY hKey)
{
    HANDLE hFile = CreateFileA(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Could not open %s\n", filepath);
        return 0;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize < 16) {
        printf("File too small or unreadable: %s\n", filepath);
        CloseHandle(hFile);
        return 0;
    }
    if (fileSize < 16) {
        printf("File %s is too small for IV + data.\n", filepath);
        CloseHandle(hFile);
        return 0;
    }

    BYTE *filebuf = (BYTE*)malloc(fileSize);
    if (!filebuf) {
        printf("Could not allocate memory for %s\n", filepath);
        CloseHandle(hFile);
        return 0;
    }
    DWORD bytesRead = 0;
    BOOL ok = ReadFile(hFile, filebuf, fileSize, &bytesRead, NULL);
    if (!ok || bytesRead != fileSize) {
        printf("Failed to read %s\n", filepath);
        free(filebuf);
        CloseHandle(hFile);
        return 0;
    }

    // IV is first 16 bytes
    BYTE iv[16];
    memcpy(iv, filebuf, 16);
    // Ciphertext is filebuf+16, length = fileSize-16
    DWORD encLen = fileSize - 16;
    BYTE *encbuf = filebuf + 16;

    // Set IV for decryption
    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
        printf("Could not set IV for %s\n", filepath);
        free(filebuf);
        CloseHandle(hFile);
        return 0;
    }

    // Decrypt in-place
    DWORD decLen = encLen;
    ok = CryptDecrypt(hKey, 0, TRUE, 0, encbuf, &decLen);
    if (!ok) {
        printf("Decryption failed for %s\n", filepath);
        free(filebuf);
        CloseHandle(hFile);
        return 0;
    }

    // Write back only the plaintext
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    DWORD written;
    ok = WriteFile(hFile, encbuf, decLen, &written, NULL);
    if (!ok || written != decLen) {
        printf("Could not write plaintext for %s (wrote %lu)\n", filepath, written);
        free(filebuf);
        CloseHandle(hFile);
        return 0;
    }
    // Truncate file to decLen
    SetFilePointer(hFile, decLen, NULL, FILE_BEGIN);
    SetEndOfFile(hFile);

    printf("Decrypted: %s (output %lu bytes)\n", filepath, decLen);

    free(filebuf);
    CloseHandle(hFile);
    return 1;
}

int main(int argc, char **argv)
{
    char dirToDecrypt[MAX_PATH];
    // This block sets the directory to decrypt.
    // If a directory path is provided as a command-line argument, use it (ensure null-termination).
    // Otherwise, use the predefined TARGET_DIR.
    if (argc > 1) {
        strncpy(dirToDecrypt, argv[1], MAX_PATH-1);
        dirToDecrypt[MAX_PATH-1] = 0;
    } else {
        strcpy(dirToDecrypt, TARGET_DIR);
    }

    BYTE key[AES_KEY_SIZE];
    if (!read_key_from_keyfile(KEYFILE_NAME, key)) {
        printf("Cannot get decryption key.\n");
        return 1;
    }

    // Setup CryptoAPI
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Crypt context failed\n");
        return 1;
    }

    struct {
        BLOBHEADER hdr;
        DWORD keyLen;
        BYTE key[32];
    } keyBlob;
    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.reserved = 0;
    keyBlob.hdr.aiKeyAlg = CALG_AES_256;
    keyBlob.keyLen = 32;
    memcpy(keyBlob.key, key, 32);

    if (!CryptImportKey(hProv, (BYTE *)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
        printf("Couldn't import key\n");
        CryptReleaseContext(hProv, 0);
        return 1;
    }

    // Begin traverse directory and decrypt files
    char searchPattern[MAX_PATH];
    snprintf(searchPattern, MAX_PATH, "%s*.*", dirToDecrypt);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Could not open directory: %s\n", dirToDecrypt);
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return 1;
    }

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        char fullPath[MAX_PATH];
        snprintf(fullPath, MAX_PATH, "%s%s", dirToDecrypt, fd.cFileName);
        decrypt_file(fullPath, hKey);
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);

    printf("All files decrypted.\n");

    return 0;
}


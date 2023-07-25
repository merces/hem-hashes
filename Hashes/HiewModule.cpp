#include <windows.h>
#include <bcrypt.h>
#include <strsafe.h>

#include "hem.h"

// Global defs

#define BUFFER_SIZE 1024 * 1024 * 4 

// Hash definitions

#define HASH_MD5_LEN 16
#define HASH_MD5_STR_LEN HASH_MD5_LEN * 2
#define HASH_SHA1_LEN 20
#define HASH_SHA1_STR_LEN HASH_SHA1_LEN * 2
#define HASH_SHA256_LEN 32
#define HASH_SHA256_STR_LEN HASH_SHA256_LEN * 2

// HEM definitions

#define HEM_MODULE_VERSION_MAJOR 1
#define HEM_MODULE_VERSION_MINOR 1
#define HEM_MODULE_NAME "Hashes"
#define HEM_MODULE_FULL_NAME "Hashes: MD5, SHA-1, SHA-256"
#define HEM_MODULE_DESCRIPTION "Calculate common hashes for a file or block"
#define HEM_MODULE_AUTHOR "Fernando Merces - github.com/merces"

int HEM_API Hem_EntryPoint(HEMCALL_TAG* hemCall);
int HEM_API Hem_Unload(VOID);

HEMINFO_TAG hemMod = {
    sizeof(HEMINFO_TAG),
    sizeof(int),
    0,
    HEM_SDK_VERSION_MAJOR,
    HEM_SDK_VERSION_MINOR,
    HEM_MODULE_VERSION_MAJOR,
    HEM_MODULE_VERSION_MINOR,
    HEM_FLAG_MODEMASK | HEM_FLAG_FILEMASK,
    0,
    Hem_EntryPoint,
    Hem_Unload,
    NULL,
    0,
    0,
    0,
    0,
    HEM_MODULE_NAME,
    HEM_MODULE_FULL_NAME,
    "========================================",
    HEM_MODULE_DESCRIPTION,
    HEM_MODULE_AUTHOR
};

// Module support functions

static int ShowHelp(VOID) {
    static PCHAR HelpText[] = {
        "This module calculates the MD5, SHA-1, and SHA-256 hashes",
        "for a given file or block.",
        "",
        "Author: "HEM_MODULE_AUTHOR,
        "",
        "Options:",
        "",
        "   F1 - Show this Help text.",
        "   F5 - Copy selected hash value to clipboard.",
        "",
        "To hash a block of data, first mark a block, then",
        "press F11 and load this module.",
    };

    static CHAR title[100] = HEM_MODULE_NAME; // In case StringCchPrintfA() fails, we still have a title :)
    StringCchPrintfA(title, _countof(title), "%s %d.%d", HEM_MODULE_NAME, HEM_MODULE_VERSION_MAJOR, HEM_MODULE_VERSION_MINOR);

    return HiewGate_Window(title, HelpText, _countof(HelpText), 60, NULL, NULL);
}

static BOOL SendTextToClipboard(const PCHAR text) {

    if (!text)
        return FALSE;

    size_t len;

    if (FAILED(StringCchLengthA(text, STRSAFE_MAX_CCH, &len)))
        return FALSE;

    if (len < 1)
        return FALSE;

    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len + 1);

    if (!hMem)
        return FALSE;

    LPVOID p = GlobalLock(hMem);

    if (!p)
        return FALSE;

    CopyMemory(p, text, len);

    if (!GlobalUnlock(hMem) && GetLastError() != NO_ERROR)
        return FALSE;

    OpenClipboard(NULL);

    if (!EmptyClipboard())
        return FALSE;

    if (!SetClipboardData(CF_TEXT, hMem)) {
        GlobalFree(hMem);
        return FALSE;
    }

    if (!CloseClipboard())
        return FALSE;

    return TRUE;
}

// printf-like error display function using HiewGate_Message
// max 256 characters
static void ShowErrorF(STRSAFE_LPCSTR format, ...) {
    STRSAFE_LPSTR s[256];

    va_list argptr;
    va_start(argptr, format);

    if (FAILED(StringCchPrintfA(s, sizeof(s), format, va_arg(argptr, char*)))) {
        HiewGate_Message("Error", "ShowErrorF(): StringCchPrintfA() failed");
        return;
    }

    HiewGate_Message("Error", (HEM_BYTE*)s);
}

int HEM_EXPORT Hem_Load(HIEWINFO_TAG* HiewInfo) {
    HiewGate_Set(HiewInfo);
    HiewInfo->hemInfo = &hemMod;
    return HEM_OK;
}

int HEM_API Hem_Unload(VOID) {
    return HEM_OK;
}

int HEM_API Hem_EntryPoint(HEMCALL_TAG* HemCall) {
    HEM_QWORD BaseAddr;
    HEM_UINT BufferSize;
    HEM_QWORD BufferEnd;
    HIEWGATE_GETDATA HiewData;
    PVOID Buffer;

    if (HemCall->cbSize < sizeof(HEMCALL_TAG))
        return HEM_ERROR;

    if (HiewGate_GetData(&HiewData) != HEM_OK)
        return HEM_ERROR;

    // Check if there is an active block, if not use the whole file.
    if (HiewData.sizeMark) {
        BaseAddr = HiewData.offsetMark1;
        BufferEnd = HiewData.sizeMark;
        // Use the smallest buffer if marked block size is smaller than BUFFER_SIZE
        BufferSize = BufferEnd < BUFFER_SIZE ? BufferEnd : BUFFER_SIZE;
    } else {
        BaseAddr = 0;
        BufferEnd = HiewData.filelength;
        // Use a buffer to read the file contents using BUFFER_SIZE byte chunks
        BufferSize = BUFFER_SIZE;
    }

    Buffer = HiewGate_GetMemory(BufferSize);
    
    if (!Buffer) {
        HiewGate_Message("Error", "Memory allocation error");
        return HEM_OK;
    }

    HiewGate_MessageWaitOpen("Calculating hashes...");

    // MD5
    UCHAR md5Hash[HASH_MD5_LEN] = { 0 };
    UCHAR md5String[HASH_MD5_STR_LEN + 1] = { 0 };
    ULONG md5HashSize = sizeof(md5Hash);

    // SHA-1
    UCHAR sha1Hash[HASH_SHA1_LEN] = { 0 };
    UCHAR sha1String[HASH_SHA1_STR_LEN + 1] = { 0 };
    ULONG sha1HashSize = HASH_SHA1_LEN;

    // SHA-256
    UCHAR sha256Hash[HASH_SHA256_LEN] = { 0 };
    UCHAR sha256String[HASH_SHA256_STR_LEN + 1] = { 0 };
    ULONG sha256HashSize = HASH_SHA256_LEN;

    BCRYPT_ALG_HANDLE hMd5Alg, hSha1Alg, hSha256Alg;
    BCRYPT_HASH_HANDLE hMd5Hash, hSha1Hash, hSha256Hash;
    NTSTATUS status;

    // MD5
    status = BCryptOpenAlgorithmProvider(&hMd5Alg, BCRYPT_MD5_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HiewGate_Message("Error", "BCryptOpenAlgorithmProvider() failed for MD5");
        return HEM_OK;
    }
    
    status = BCryptCreateHash(hMd5Alg, &hMd5Hash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hMd5Alg, 0);
        HiewGate_Message("Error", "BCryptCreateHash() failed for MD5");
        return HEM_OK;
    }

    // SHA-1
    status = BCryptOpenAlgorithmProvider(&hSha1Alg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HiewGate_Message("Error", "BCryptOpenAlgorithmProvider() failed for SHA-1");
        return HEM_OK;
    }

    status = BCryptCreateHash(hSha1Alg, &hSha1Hash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hSha1Alg, 0);
        HiewGate_Message("Error", "BCryptCreateHash() failed for SHA-1");
        return HEM_OK;
    }

    // SHA-256
    status = BCryptOpenAlgorithmProvider(&hSha256Alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HiewGate_Message("Error", "BCryptOpenAlgorithmProvider() for SHA-256");
        return HEM_OK;
    }

    status = BCryptCreateHash(hSha256Alg, &hSha256Hash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HiewGate_Message("Error", "BCryptCreateHash() failed for SHA-256");
        return HEM_OK;
    }
    
    // Calculate MD5, SHA-1, and SHA-256 using a single loop

    HEM_QWORD totalRead = 0;

    while (totalRead < BufferEnd) {
        int read = HiewGate_FileRead(BaseAddr + totalRead, BufferSize, Buffer);

        if (read == 0) {
              break;
        } else if (read == HEM_ERROR || read == HEM_ERR_POINTER_IS_NULL) {
            HiewGate_Message("Error", "Error reading the file");
            return HEM_OK;
        }

        // MD5
        status = BCryptHashData(hMd5Hash, Buffer, read, 0);
        if (!BCRYPT_SUCCESS(status)) {
            goto cleanupHash;
        }

        // SHA-1
        status = BCryptHashData(hSha1Hash, Buffer, read, 0);
        if (!BCRYPT_SUCCESS(status)) {
            goto cleanupHash;
        }

        // SHA-256
        status = BCryptHashData(hSha256Hash, Buffer, read, 0);
        if (!BCRYPT_SUCCESS(status)) {
            goto cleanupHash;
        }

        totalRead += read;
    }

    // MD5
    status = BCryptFinishHash(hMd5Hash, md5Hash, md5HashSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HiewGate_Message("Error", "BCryptFinishHash() for MD5");
        goto cleanupHash;
    }

    // SHA-1
    status = BCryptFinishHash(hSha1Hash, sha1Hash, sha1HashSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HiewGate_Message("Error", "BCryptFinishHash() for SHA-1");
        goto cleanupHash;
    }

    // SHA-256
    status = BCryptFinishHash(hSha256Hash, sha256Hash, sha256HashSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HiewGate_Message("Error", "BCryptFinishHash() for SHA-256");
        goto cleanupHash;
    }

cleanupHash:
    // MD5
    BCryptDestroyHash(hMd5Hash);
    BCryptCloseAlgorithmProvider(hMd5Alg, 0);
    // SHA-1
    BCryptDestroyHash(hSha1Hash);
    BCryptCloseAlgorithmProvider(hSha1Hash, 0);
    // SHA-256
    BCryptDestroyHash(hSha256Hash);
    BCryptCloseAlgorithmProvider(hSha256Hash, 0);

    // Build hash strings

    // MD5
    for (ULONG i = 0; i < md5HashSize; ++i) {
        if (FAILED(StringCchPrintfA(md5String + i * 2, sizeof(md5String) - i * 2, "%02x", md5Hash[i]))) {
            HiewGate_Message("Error", "StringCchPrintfA() failed for MD5");
            goto cleanup;
        }
    }

    // SHA-1
    for (ULONG i = 0; i < sha1HashSize; ++i) {
        if (FAILED(StringCchPrintfA(sha1String + i * 2, sizeof(sha1String) - i * 2, "%02x", sha1Hash[i]))) {
            HiewGate_Message("Error", "StringCchPrintfA() failed for SHA-1");
            goto cleanup;
        }
    }

    // SHA-256
    for (ULONG i = 0; i < sha256HashSize; ++i) {
        if (FAILED(StringCchPrintfA(sha256String + i * 2, sizeof(sha256String) - i * 2, "%02x", sha256Hash[i]))) {
            HiewGate_Message("Error", "StringCchPrintfA() failed for SHA-256");
            goto cleanup;
        }
    }

    HiewGate_MessageWaitClose();

    // Menu code

    // Keys setup
    //                    "123456789ABC|F1____F2____F3____F4____F5____F6____F7____F8____F9____F10___F11___F12___"
    HEM_FNKEYS fnKeys = { "100010000000|Help                    Copy                                            ",   // main Fn
                  "",   // no Alt-Fn
                  "",   // no Ctrl-Fn
                  ""};  // no ShiftFn

    // Menu entries
    UCHAR* lines[] = {
        md5String,
        sha1String,
        sha256String,
    };

    // Menu loop

    HEM_UINT pressedFnKey;

    int item = 1; // Just a reminder menu items start at 1 (not 0)
    while (item = HiewGate_Menu(HEM_MODULE_FULL_NAME, lines, _countof(lines), HASH_SHA256_STR_LEN, item, &fnKeys, &pressedFnKey, NULL, NULL)) {
        if (!pressedFnKey)
            continue;

        switch (pressedFnKey) {
        case HEM_FNKEY_F1:
            ShowHelp();
            break;
        case HEM_FNKEY_F5:
                if (!SendTextToClipboard(lines[item - 1])) {
                    HiewGate_Message("Error", "Could not send the text to clipboard");
                    goto cleanup;
                }
            break; 
        default:
            break;
        }
    }

    cleanup:
    HiewGate_FreeMemory(Buffer);
    
    return HEM_OK;
}

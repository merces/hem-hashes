#include <windows.h>
#include <bcrypt.h>
#include <strsafe.h>

#include "hem.h"

// Hashes definitions

#define HASHES_MD5_LEN 16
#define HASHES_MD5_STR_LEN HASHES_MD5_LEN * 2
#define HASHES_SHA1_LEN 20
#define HASHES_SHA1_STR_LEN HASHES_SHA1_LEN * 2
#define HASHES_SHA256_LEN 32
#define HASHES_SHA256_STR_LEN HASHES_SHA256_LEN * 2

// HEM definitions

#define HEM_MODULE_VERSION_MAJOR 1
#define HEM_MODULE_VERSION_MINOR 0
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

// Module supporting functions

int ShowHelp(VOID) {
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
        "press F11 and load this module",
    };

    CHAR title[100] = HEM_MODULE_NAME; // In case StringCchPrintfA() fails, we still have a title :)
    StringCchPrintfA(title, _countof(title), "%s %d.%d", HEM_MODULE_NAME, HEM_MODULE_VERSION_MAJOR, HEM_MODULE_VERSION_MINOR);

    return HiewGate_Window(title, HelpText, _countof(HelpText), 60, NULL, NULL);
}

BOOL SendTextToClipboard(const PCHAR text) {

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

BOOL CalculateMd5Hash(PVOID buffer, ULONG bufferLen, PUCHAR md5Hash, ULONG* md5HashSize) {
    BOOL result = FALSE;

    BCRYPT_ALG_HANDLE hMd5Alg;
    NTSTATUS status;
    status = BCryptOpenAlgorithmProvider(&hMd5Alg, BCRYPT_MD5_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return FALSE;
    }

    BCRYPT_HASH_HANDLE hMd5Hash;
    status = BCryptCreateHash(hMd5Alg, &hMd5Hash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hMd5Alg, 0);
        return FALSE;
    }

    status = BCryptHashData(hMd5Hash, buffer, bufferLen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }


    status = BCryptFinishHash(hMd5Hash, md5Hash, *md5HashSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

cleanup:
    BCryptDestroyHash(hMd5Hash);
    BCryptCloseAlgorithmProvider(hMd5Alg, 0);

    return TRUE;
}

BOOL CalculateSha1Hash(PVOID buffer, ULONG bufferLen, PUCHAR sha1Hash, ULONG* sha1HashSize) {
    BOOL result = FALSE;

    BCRYPT_ALG_HANDLE hSha1Alg;
    NTSTATUS status;
    status = BCryptOpenAlgorithmProvider(&hSha1Alg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return FALSE;
    }

    BCRYPT_HASH_HANDLE hSha1Hash;
    status = BCryptCreateHash(hSha1Alg, &hSha1Hash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hSha1Alg, 0);
        return FALSE;
    }

    status = BCryptHashData(hSha1Hash, buffer, bufferLen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }


    status = BCryptFinishHash(hSha1Hash, sha1Hash, *sha1HashSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

cleanup:
    BCryptDestroyHash(hSha1Hash);
    BCryptCloseAlgorithmProvider(hSha1Alg, 0);

    return TRUE;
}

BOOL CalculateSha256Hash(PVOID buffer, ULONG bufferLen, PUCHAR sha256Hash, ULONG* sha256HashSize) {
    BOOL result = FALSE;

    BCRYPT_ALG_HANDLE hSha256Alg;
    NTSTATUS status;
    status = BCryptOpenAlgorithmProvider(&hSha256Alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return FALSE;
    }

    BCRYPT_HASH_HANDLE hSha256Hash;
    status = BCryptCreateHash(hSha256Alg, &hSha256Hash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hSha256Alg, 0);
        return FALSE;
    }

    status = BCryptHashData(hSha256Hash, buffer, bufferLen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }


    status = BCryptFinishHash(hSha256Hash, sha256Hash, *sha256HashSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

cleanup:
    BCryptDestroyHash(hSha256Hash);
    BCryptCloseAlgorithmProvider(hSha256Alg, 0);

    return TRUE;
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
    HEM_QWORD BufferSize;
    HIEWGATE_GETDATA HiewData;
    PVOID Buffer;

    if (HemCall->cbSize < sizeof(HEMCALL_TAG))
        return HEM_ERROR;

    if (HiewGate_GetData(&HiewData) != HEM_OK)
        return HEM_ERROR;

    // Check if there is an active block, if not use the whole file.
    if (HiewData.sizeMark) {
        BaseAddr = HiewData.offsetMark1;
        BufferSize = HiewData.sizeMark;
    } else {
        BaseAddr = 0;
        BufferSize = HiewData.filelength;
    }

    Buffer = HiewGate_GetMemory((HEM_UINT)BufferSize);
    
    if (!Buffer) {
        HiewGate_Message("Error", "Memory allocation error");
        return HEM_OK;
    }

    if (HiewGate_FileRead(BaseAddr, (HEM_UINT)BufferSize, Buffer) != BufferSize) {
        HiewGate_Message("Error", "File read error");
        goto cleanup;
    }

    HiewGate_MessageWaitOpen("Calculating hashes...");

    // MD5
    UCHAR md5Hash[HASHES_MD5_LEN];
    UCHAR md5String[HASHES_MD5_STR_LEN + 1] = { 0 };
    ULONG md5HashSize = sizeof(md5Hash);

    if (!CalculateMd5Hash(Buffer, (ULONG)BufferSize, md5Hash, &md5HashSize)) {
        HiewGate_Message("Error", "Hash calculation failed");
        goto cleanup;
    }

    for (ULONG i = 0; i < md5HashSize; ++i) {
        if (FAILED(StringCchPrintfA(md5String + i * 2, sizeof(md5String) - i * 2, "%02x", md5Hash[i]))) {
            HiewGate_Message("Error", "StringCchPrintfA() failed for MD5");
            goto cleanup;
        }
    }

    // SHA-1
    UCHAR sha1Hash[HASHES_SHA1_LEN];
    UCHAR sha1String[HASHES_SHA1_STR_LEN + 1] = { 0 };
    ULONG sha1HashSize = HASHES_SHA1_LEN;

    if (!CalculateSha1Hash(Buffer, (ULONG)BufferSize, sha1Hash, &sha1HashSize)) {
        HiewGate_Message("Error", "Hash calculation failed");
        goto cleanup;
    }

    for (ULONG i = 0; i < sha1HashSize; ++i) {
        if (FAILED(StringCchPrintfA(sha1String + i * 2, sizeof(sha1String) - i * 2, "%02x", sha1Hash[i]))) {
            HiewGate_Message("Error", "StringCchPrintfA() failed for SHA-1");
            goto cleanup;
        }
    }

    // SHA-256
    UCHAR sha256Hash[HASHES_SHA256_LEN];
    UCHAR sha256String[HASHES_SHA256_STR_LEN + 1] = { 0 };
    ULONG sha256HashSize = HASHES_SHA256_LEN;

    if (!CalculateSha256Hash(Buffer, (ULONG)BufferSize, sha256Hash, &sha256HashSize)) {
        HiewGate_Message("Error", "Hash calculation failed");
        goto cleanup;
    }

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
    UCHAR *lines[] = {
        md5String,
        sha1String,
        sha256String
    };

    // Menu loop

    HEM_UINT pressedFnKey;

    int item = 1; // Just a reminder menu items start at 1 (not 0)
    while (item = HiewGate_Menu(HEM_MODULE_FULL_NAME, lines, _countof(lines), HASHES_SHA256_STR_LEN, item, &fnKeys, &pressedFnKey, NULL, NULL)) {
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
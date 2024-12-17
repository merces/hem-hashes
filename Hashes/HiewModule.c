#include <windows.h>
#include <bcrypt.h>
#include <strsafe.h>

#include "hem.h"

// Module defs

#define BUFFER_SIZE 1024 * 1024 * 4

#define HASH_CRC32_LEN 4
#define HASH_CRC32_STR_LEN HASH_CRC32_LEN * 2
#define HASH_MD5_LEN 16
#define HASH_MD5_STR_LEN HASH_MD5_LEN * 2
#define HASH_SHA1_LEN 20
#define HASH_SHA1_STR_LEN HASH_SHA1_LEN * 2
#define HASH_SHA256_LEN 32
#define HASH_SHA256_STR_LEN HASH_SHA256_LEN * 2

// HEM SDK required defs

#define HEM_MODULE_VERSION_MAJOR 1
#define HEM_MODULE_VERSION_MINOR 3
#define HEM_MODULE_NAME "Hashes"
#define HEM_MODULE_FULL_NAME "Hashes: CRC-32, MD5, SHA-1, SHA-256"
#define HEM_MODULE_DESCRIPTION "Calculate common hashes of files and blocks"
#define HEM_MODULE_AUTHOR "Fernando Merces - github.com/merces"

enum opMode { HASHES_FILE, HASHES_BLOCK };

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

// Module functions

static int ShowHelp(VOID) {
    static PCHAR HelpText[] = {
        "This module calculates CRC-32, MD5, SHA-1,",
        "and SHA-256 hashes for a given file/block.",
        "",
        "Author: "HEM_MODULE_AUTHOR,
        "",
        "Options:",
        "",
        "   F1 - Show this Help text.",
        "   F5 - Copy selected hash value to clipboard.",
		"   F6    - Copy all hashes to clipboard.",
        "",
        "To hash a block of data, first mark a block, then",
        "press F11 and load this module.",
    };

    static CHAR title[64] = HEM_MODULE_NAME; // In case StringCchPrintfA() fails, we still have a title :)
    StringCchPrintfA(title, _countof(title), "%s %d.%0.2d", HEM_MODULE_NAME, HEM_MODULE_VERSION_MAJOR, HEM_MODULE_VERSION_MINOR);

    return HiewGate_Window(title, HelpText, _countof(HelpText), 60, NULL, NULL);
}

static bool sendTextToClipboard(const char** lines, const size_t numberOfLines) {
	if (!lines)
		return false;

	size_t totalLen = 0;
	
	for (size_t i = 0; i < numberOfLines; i++) {
    size_t len;

		if (FAILED(StringCchLengthA(lines[i], STRSAFE_MAX_CCH, &len)))
			return false;

		totalLen += len + 1; // +1 for nullbyte or newline
	}

	if (totalLen < 1)
		return false;

	HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, totalLen);

    if (!hMem)
		return false;

	LPSTR dest = (LPSTR) GlobalLock(hMem);

	if (!dest)
		return false;

	for (size_t i = 0; i < numberOfLines; i++) {
		size_t len;

		if (FAILED(StringCchLengthA(lines[i], STRSAFE_MAX_CCH, &len))) {
			GlobalFree(hMem);
			return false;
		}

		CopyMemory(dest, lines[i], len);
		dest += len;
		*dest++ = '\n';
	}
	*(dest - 1) = '\0'; // replace last newline by nullbyte

	if (!GlobalUnlock(hMem) && GetLastError() != NO_ERROR) {
		GlobalFree(hMem);
		return false;
	}

	if (!OpenClipboard(NULL))
		return false;

	if (!EmptyClipboard()) {
		CloseClipboard();
		return false;
	}

    if (!SetClipboardData(CF_TEXT, hMem)) {
        GlobalFree(hMem);
		CloseClipboard();
		return false;
    }

    if (!CloseClipboard())
		return false;

	return true;
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

    enum opMode mode;

    // Check if there is an active block, if not use the whole file.
    if (HiewData.sizeMark) {
        mode = HASHES_BLOCK;
        BaseAddr = HiewData.offsetMark1;
        BufferEnd = HiewData.sizeMark;
        // Use the smallest buffer if marked block size is smaller than BUFFER_SIZE
        // Notice a marked block cannot exceed UINT_MAX
        BufferSize = BufferEnd < BUFFER_SIZE ? (HEM_UINT)BufferEnd : BUFFER_SIZE;
    } else {
        mode = HASHES_FILE;
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

    // CRC-32
    UINT32 crc32Hash = 0;
    UCHAR crc32String[HASH_CRC32_STR_LEN + 1] = { 0 };

    // MD5
    UCHAR md5Hash[HASH_MD5_LEN] = { 0 };
    UCHAR md5String[HASH_MD5_STR_LEN + 1] = { 0 };

    // SHA-1
    UCHAR sha1Hash[HASH_SHA1_LEN] = { 0 };
    UCHAR sha1String[HASH_SHA1_STR_LEN + 1] = { 0 };

    // SHA-256
    UCHAR sha256Hash[HASH_SHA256_LEN] = { 0 };
    UCHAR sha256String[HASH_SHA256_STR_LEN + 1] = { 0 };

    BCRYPT_ALG_HANDLE hMd5Alg, hSha1Alg, hSha256Alg;
    hMd5Alg = hSha1Alg = hSha256Alg = NULL;
    BCRYPT_HASH_HANDLE hMd5Hash, hSha1Hash, hSha256Hash;
    hMd5Hash = hSha1Hash = hSha256Hash = NULL;
    NTSTATUS status;

    // Initialize MD5
    status = BCryptOpenAlgorithmProvider(&hMd5Alg, BCRYPT_MD5_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HiewGate_Message("Error", "BCryptOpenAlgorithmProvider() failed for MD5");
        goto cleanup;
    }
    
    status = BCryptCreateHash(hMd5Alg, &hMd5Hash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HiewGate_Message("Error", "BCryptCreateHash() failed for MD5");
        goto cleanup;
    }

    // Initialize SHA-1
    status = BCryptOpenAlgorithmProvider(&hSha1Alg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HiewGate_Message("Error", "BCryptOpenAlgorithmProvider() failed for SHA-1");
        goto cleanup;
    }

    status = BCryptCreateHash(hSha1Alg, &hSha1Hash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HiewGate_Message("Error", "BCryptCreateHash() failed for SHA-1");
        goto cleanup;
    }

    // Initialize SHA-256
    status = BCryptOpenAlgorithmProvider(&hSha256Alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HiewGate_Message("Error", "BCryptOpenAlgorithmProvider() for SHA-256");
        goto cleanup;
    }

    status = BCryptCreateHash(hSha256Alg, &hSha256Hash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HiewGate_Message("Error", "BCryptCreateHash() failed for SHA-256");
        goto cleanup;
    }

    // Load ntdll.dll to use RtlComputeCrc32() for CRC-32

    typedef DWORD (WINAPI* pRtlComputeCrc32)(DWORD dwInitial, const BYTE* pData, INT iLen);
    pRtlComputeCrc32 gRtlComputeCrc32;

    HMODULE ntdll = LoadLibrary(TEXT("ntdll.dll"));

    if (!ntdll) {
        HiewGate_Message("Error", "Could not load ntdll for CRC-32 calculation");
        status = STATUS_INVALID_HANDLE;
        goto cleanup;
    }

    gRtlComputeCrc32 = (pRtlComputeCrc32)GetProcAddress(ntdll, "RtlComputeCrc32");

    if (!gRtlComputeCrc32) {
        HiewGate_Message("Error", "Could not find the address for RtlComputeCrc32() in ntdll.dll");
        status = STATUS_INVALID_HANDLE;
        goto cleanup;
    }

    // Calculate all hashes using a single loop

    HEM_QWORD totalRead = 0;

    while (totalRead < BufferEnd) {

        if (mode == HASHES_BLOCK) {
            BufferSize = BufferEnd - totalRead;
            if (BufferSize > BUFFER_SIZE) {
                BufferSize = BUFFER_SIZE;
            }
        }

        int read = HiewGate_FileRead(BaseAddr + totalRead, BufferSize, Buffer);

        if (read == 0) {
              break;
        } else if (read == HEM_ERROR || read == HEM_ERR_POINTER_IS_NULL) {
            HiewGate_Message("Error", "HiewGate_FileRead(): Error reading the file");
            goto cleanup;
        }

        // Hash the buffer using all algorithms

        // CRC-32
        crc32Hash = gRtlComputeCrc32(crc32Hash, Buffer, read);

        // MD5
        status = BCryptHashData(hMd5Hash, Buffer, read, 0);
        if (!BCRYPT_SUCCESS(status)) {
            goto cleanup;
        }

        // SHA-1
        status = BCryptHashData(hSha1Hash, Buffer, read, 0);
        if (!BCRYPT_SUCCESS(status)) {
            goto cleanup;
        }

        // SHA-256
	UCHAR sha256Hash[HASHES_SHA256_LEN] = { 0 };
	UCHAR sha256String[HASHES_SHA256_STR_LEN + 1] = { 0 };

	// Calculate all hashes using a single loop
	hashObj.buffer = buffer;

	PVOID hashingFunctions[] = {
		calcCrc32,
		calcMd5,
		calcSha1,
		calcSha256
	};
	HANDLE threadHandles[_countof(hashingFunctions)];
	HEM_UINT bytesToRead = bufferSize;

	while (totalRead < bufferEnd) {
		// Update BytesToRead on every iteration.
		// If the remaining data size is lower than
		// the buffer size, read the remaining bytes only
		if (bufferEnd - totalRead < HASHES_BUFFER_SIZE)
			bytesToRead = (HEM_UINT)(bufferEnd - totalRead);

		int read = HiewGate_FileRead(baseAddr + totalRead, bytesToRead, buffer);

		if (read == 0) {
			break;
		} else if (read == HEM_ERROR || read == HEM_ERR_POINTER_IS_NULL) {
			HiewGate_MessageWaitClose();
			HiewGate_FreeMemory(buffer);
			hashesDestroy(&hashObj);
			HiewGate_SetErrorMsg("HiewGate_FileRead(): Error reading the file");
			return HEM_ERROR;
        }

        totalRead += read;
    }

    // Finalize hashing

    // MD5
    status = BCryptFinishHash(hMd5Hash, md5Hash, HASH_MD5_LEN, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HiewGate_Message("Error", "BCryptFinishHash() for MD5");
        goto cleanup;
    }

    // SHA-1
    status = BCryptFinishHash(hSha1Hash, sha1Hash, HASH_SHA1_LEN, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HiewGate_Message("Error", "BCryptFinishHash() for SHA-1");
        goto cleanup;
    }

    // SHA-256
    status = BCryptFinishHash(hSha256Hash, sha256Hash, HASH_SHA256_LEN, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HiewGate_Message("Error", "BCryptFinishHash() for SHA-256");
        goto cleanup;
    }

cleanup:
    HiewGate_FreeMemory(Buffer);
    // MD5
    BCryptDestroyHash(hMd5Hash);
    BCryptCloseAlgorithmProvider(hMd5Alg, 0);
    // SHA-1
    BCryptDestroyHash(hSha1Hash);
    BCryptCloseAlgorithmProvider(hSha1Hash, 0);
    // SHA-256
    BCryptDestroyHash(hSha256Hash);
    BCryptCloseAlgorithmProvider(hSha256Hash, 0);

    if (!BCRYPT_SUCCESS(status)) {
        HiewGate_Message("Error", "Error calculating hashes");
        return HEM_OK;
    }

    // Build hash strings

    //  CRC-32
    if (FAILED(StringCchPrintfA(crc32String, sizeof(crc32String), "%08X", crc32Hash))) {
        HiewGate_Message("Error", "StringCchPrintfA() failed for CRC-32");
    }

    // MD5
    for (ULONG i = 0; i < HASH_MD5_LEN; ++i) {
        if (FAILED(StringCchPrintfA(md5String + i * 2, sizeof(md5String) - i * 2, "%02x", md5Hash[i]))) {
            HiewGate_Message("Error", "StringCchPrintfA() failed for MD5");
            break;
        }
    }

    // SHA-1
    for (ULONG i = 0; i < HASH_SHA1_LEN; ++i) {
        if (FAILED(StringCchPrintfA(sha1String + i * 2, sizeof(sha1String) - i * 2, "%02x", sha1Hash[i]))) {
            HiewGate_Message("Error", "StringCchPrintfA() failed for SHA-1");
            break;
        }
    }

    // SHA-256
    for (ULONG i = 0; i < HASH_SHA256_LEN; ++i) {
        if (FAILED(StringCchPrintfA(sha256String + i * 2, sizeof(sha256String) - i * 2, "%02x", sha256Hash[i]))) {
            HiewGate_Message("Error", "StringCchPrintfA() failed for SHA-256");
            break;
        }
    }

    HiewGate_MessageWaitClose();

    // Menu code

    // Keys setup
    //                    "123456789ABC|F1____F2____F3____F4____F5____F6____F7____F8____F9____F10___F11___F12___"
	HEM_FNKEYS fnKeys = { "100011000000|Help                    Copy  CpyAll                                    ",   // main Fn
                  "",   // no Alt-Fn
                  "",   // no Ctrl-Fn
				  "" };  // no ShiftFn

    // Menu entries
    UCHAR* lines[] = {
        crc32String,
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
			if (!sendTextToClipboard(&lines[item - 1], 1))
				HiewGate_Message("Error", "SendTextToClipboard() failed");
			break;
		case HEM_FNKEY_F6:
			if (!sendTextToClipboard(lines, _countof(lines)))
                HiewGate_Message("Error", "SendTextToClipboard() failed");
            break; 
        default:
            break;
        }
    }

    return HEM_OK;
}

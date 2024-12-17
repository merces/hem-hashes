#include <windows.h>
#include <bcrypt.h>
#include <strsafe.h>
#include <stdbool.h>

#include "hem.h"
#include "hashes.h"

int HEM_API Hem_EntryPoint(HEMCALL_TAG* hemCall);
int HEM_API Hem_Unload(void);

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
bool gThreadError = false;

static int showHelp(void) {
	static PCHAR helpText[] = {
		"This module calculates CRC-32, MD5, SHA-1,",
		"and SHA-256 hashes for a given file/block.",
		"",
		"Author: "HEM_MODULE_AUTHOR,
		"",
		"Options:",
		"",
		"   F1    - Show this help text.",
		"   F5    - Copy selected hash value to clipboard.",
		"   ENTER - Same as F5, but closes the window afterwards.",
		"   F6    - Copy all hashes to clipboard.",
		"",
		"To hash a block of data, first mark a block, then",
		"press F11 and load this module.",
	};

	static CHAR title[64] = { 0 };
	StringCchPrintfA(title,
		_countof(title),
		"%s %d.%0.2d",
		HEM_MODULE_NAME,
		HEM_MODULE_VERSION_MAJOR,
		HEM_MODULE_VERSION_MINOR);

	return HiewGate_Window(title, helpText, _countof(helpText), 60, NULL, NULL);
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

int HEM_API Hem_Unload(void) {
	return HEM_OK;
}

static DWORD WINAPI calcCrc32(LPVOID data) {
	hashObject* obj = (hashObject*)data;

	typedef DWORD(WINAPI* pRtlComputeCrc32)(DWORD dwInitial, const BYTE* pData, INT iLen);

	pRtlComputeCrc32 gRtlComputeCrc32;

	HMODULE ntdll = LoadLibrary(TEXT("ntdll.dll"));

	if (!ntdll) {
		gThreadError = true;
		return 0;
	}

	gRtlComputeCrc32 = (pRtlComputeCrc32)GetProcAddress(ntdll, "RtlComputeCrc32");

	if (!gRtlComputeCrc32) {
		gThreadError = true;
		return 0;
	}

	obj->crc32 = gRtlComputeCrc32(obj->crc32, obj->buffer, obj->buffer_len);

	if (obj->crc32 == 0)
	{
		gThreadError = true;
		return 0;
	}

	return 1;
}

static DWORD WINAPI calcMd5(LPVOID data) {
	hashObject* obj = (hashObject*)data;

	if (!BCRYPT_SUCCESS(BCryptHashData(obj->hashMd5, obj->buffer, obj->buffer_len, 0)))
		gThreadError = TRUE;

	return 0;
}

static DWORD WINAPI calcSha1(LPVOID data) {
	hashObject* obj = (hashObject*)data;

	if (!BCRYPT_SUCCESS(BCryptHashData(obj->hashSha1, obj->buffer, obj->buffer_len, 0)))
		gThreadError = TRUE;

	return 0;
}

static DWORD WINAPI calcSha256(LPVOID data) {
	hashObject* obj = (hashObject*)data;

	if (!BCRYPT_SUCCESS(BCryptHashData(obj->hashSha256, obj->buffer, obj->buffer_len, 0)))
		gThreadError = TRUE;
	return 0;
}

static BOOL hashesInit(hashObject* obj) {
	if (obj == NULL)
		return FALSE;

	obj->crc32 = 0;

	if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&obj->algMd5, BCRYPT_MD5_ALGORITHM, NULL, 0)))
		return FALSE;

	if (!BCRYPT_SUCCESS(BCryptCreateHash(obj->algMd5, &obj->hashMd5, NULL, 0, NULL, 0, 0)))
		return FALSE;

	if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&obj->algSha1, BCRYPT_SHA1_ALGORITHM, NULL, 0)))
		return FALSE;

	if (!BCRYPT_SUCCESS(BCryptCreateHash(obj->algSha1, &obj->hashSha1, NULL, 0, NULL, 0, 0)))
		return FALSE;

	if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&obj->algSha256, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
		return FALSE;

	if (!BCRYPT_SUCCESS(BCryptCreateHash(obj->algSha256, &obj->hashSha256, NULL, 0, NULL, 0, 0)))
		return FALSE;

	return TRUE;
}

static VOID hashesDestroy(hashObject* obj) {
	if (obj == NULL)
		return;

	if (obj->hashMd5)
		BCryptDestroyHash(obj->hashMd5);

	if (obj->algMd5)
		BCryptCloseAlgorithmProvider(obj->algMd5, 0);

	if (obj->hashSha1)
		BCryptDestroyHash(obj->hashSha1);

	if (obj->algSha1)
		BCryptCloseAlgorithmProvider(obj->algSha1, 0);

	if (obj->hashSha256)
		BCryptDestroyHash(obj->hashSha256);

	if (obj->algSha256)
		BCryptCloseAlgorithmProvider(obj->algSha256, 0);
}

int HEM_API Hem_EntryPoint(HEMCALL_TAG* HemCall) {
	HIEWGATE_GETDATA HiewData;
	HEM_QWORD baseAddr;
	HEM_QWORD bufferEnd;
	PVOID buffer;
	HEM_UINT bufferSize;
	HEM_QWORD totalRead = 0;
	hashObject hashObj;

#ifdef _DEBUG
	DWORD tickStart = GetTickCount();
	static_assert(HASHES_BUFFER_SIZE <= UINT_MAX, "Buffer is too big");
#endif

	// Prepare hashing algorithms
	if (!hashesInit(&hashObj)) {
		HiewGate_SetErrorMsg("Error initializing hashes");
		return HEM_ERROR;
	}

	if (HemCall->cbSize < sizeof(HEMCALL_TAG))
		return HEM_ERROR; // Causes "Hem error: General error" message

	if (HiewGate_GetData(&HiewData) != HEM_OK)
		return HEM_ERROR;

	// Check if there is an active block. If not, use the whole file.
	if (HiewData.sizeMark) {
		baseAddr = HiewData.offsetMark1;
		bufferEnd = HiewData.sizeMark;
	} else {
		baseAddr = 0;
		bufferEnd = HiewData.filelength;
	}

	// Use the smallest buffer if the data size is smaller than HASHES_BUFFER_SIZE
	bufferSize = bufferEnd < HASHES_BUFFER_SIZE ? (HEM_UINT)bufferEnd : HASHES_BUFFER_SIZE;

	// Allocate buffer memory (HASHES_BUFFER_SIZE or less)
	buffer = HiewGate_GetMemory(bufferSize);

	if (!buffer) {
		HiewGate_SetErrorMsg("Memory allocation error");
		hashesDestroy(&hashObj);
		return HEM_ERROR;
	}

	HiewGate_MessageWaitOpen("Calculating hashes...");

	// CRC-32
	UCHAR crc32String[HASHES_CRC32_STR_LEN + 1] = { 0 };

	// MD5
	UCHAR md5Hash[HASHES_MD5_LEN] = { 0 };
	UCHAR md5String[HASHES_MD5_STR_LEN + 1] = { 0 };

	// SHA-1
	UCHAR sha1Hash[HASHES_SHA1_LEN] = { 0 };
	UCHAR sha1String[HASHES_SHA1_STR_LEN + 1] = { 0 };

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

		// Spawn one thread for each algorithm
		hashObj.buffer_len = read;
		for (int i = 0; i < _countof(hashingFunctions); i++) {
			threadHandles[i] = CreateThread(NULL, 0, hashingFunctions[i], &hashObj, 0, NULL);
			// Clean up and abort if any thread fails
			if (!threadHandles[i]) {
				for (int j = 0; j < i; j++) {
					WaitForSingleObject(threadHandles[i], INFINITE);
					CloseHandle(threadHandles[i]);
				}
				HiewGate_MessageWaitClose();
				HiewGate_FreeMemory(buffer);
				hashesDestroy(&hashObj);
				HiewGate_SetErrorMsg("Thread creation failed");
				return HEM_ERROR;
			}
		}
		totalRead += read;

		// Wait for the threads to finish and close their handles
		WaitForMultipleObjects(_countof(threadHandles), threadHandles, TRUE, INFINITE);
		for (int i = 0; i < _countof(threadHandles); i++) {
			// Handles should be valid at this point, but this prevents a compiler warning
			if (threadHandles[i] != INVALID_HANDLE_VALUE)
				CloseHandle(threadHandles[i]);
		}

		// Abort if any thread reported an error
		if (gThreadError) {
			HiewGate_MessageWaitClose();
			HiewGate_FreeMemory(buffer);
			hashesDestroy(&hashObj);
			HiewGate_SetErrorMsg("Error hashing data");
			return HEM_ERROR;
		}

		// Abort if user press ESC
		if (HiewGate_IsKeyBreak()) {
			HiewGate_MessageWaitClose();
			HiewGate_FreeMemory(buffer);
			hashesDestroy(&hashObj);
			return HEM_OK;
		}

	}

	// Things went well, clean up as much as we can
	HiewGate_MessageWaitClose();
	HiewGate_FreeMemory(buffer);

	// Finalize hashing
	if (!BCRYPT_SUCCESS(BCryptFinishHash(hashObj.hashMd5, md5Hash, HASHES_MD5_LEN, 0))) {
		HiewGate_SetErrorMsg("BCryptFinishHash() for MD5");
		hashesDestroy(&hashObj);
		return HEM_ERROR;
	}

	if (!BCRYPT_SUCCESS(BCryptFinishHash(hashObj.hashSha1, sha1Hash, HASHES_SHA1_LEN, 0))) {
		HiewGate_SetErrorMsg("BCryptFinishHash() for SHA-1");
		hashesDestroy(&hashObj);
		return HEM_ERROR;
	}

	if (!BCRYPT_SUCCESS(BCryptFinishHash(hashObj.hashSha256, sha256Hash, HASHES_SHA256_LEN, 0))) {
		HiewGate_SetErrorMsg("BCryptFinishHash() for SHA-256");
		hashesDestroy(&hashObj);
		return HEM_ERROR;
	}

	// All good, release the hash objects
	hashesDestroy(&hashObj);

	// Build hash strings

	if (FAILED(StringCchPrintfA(crc32String, sizeof(crc32String), "%08X", hashObj.crc32)))
		HiewGate_Message("Error", "StringCchPrintfA() failed for CRC-32");

	for (ULONG i = 0; i < HASHES_MD5_LEN; i++) {
		if (FAILED(StringCchPrintfA(md5String + i * 2, sizeof(md5String) - i * 2, "%02x", md5Hash[i]))) {
			HiewGate_Message("Error", "StringCchPrintfA() failed for MD5");
			break;
		}
	}

	for (ULONG i = 0; i < HASHES_SHA1_LEN; i++) {
		if (FAILED(StringCchPrintfA(sha1String + i * 2, sizeof(sha1String) - i * 2, "%02x", sha1Hash[i]))) {
			HiewGate_Message("Error", "StringCchPrintfA() failed for SHA-1");
			break;
		}
	}

	for (ULONG i = 0; i < HASHES_SHA256_LEN; i++) {
		if (FAILED(StringCchPrintfA(sha256String + i * 2, sizeof(sha256String) - i * 2, "%02x", sha256Hash[i]))) {
			HiewGate_Message("Error", "StringCchPrintfA() failed for SHA-256");
			break;
		}
	}

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
	
	UCHAR windowTitle[64] = { 0 };

#ifdef _DEBUG
	DWORD tickEnd = GetTickCount();

	// Cast tick_end to signed int in case GetTickCount() wraps around
	DWORD tickDiff = tickEnd - (tickEnd > tickStart ? tickStart : (int)tickStart);

	double elapsedSeconds = tickDiff / 1000.0;
	if (FAILED(StringCchPrintfA(windowTitle, sizeof(windowTitle), "Hashes (completed in %.2f seconds)", elapsedSeconds))) {
		HiewGate_Message("Error", "Failed to build title string, but hashes are fine");
	}
#else
	if (FAILED(StringCchPrintfA(windowTitle, sizeof(windowTitle), HEM_MODULE_FULL_NAME))) {
		HiewGate_Message("Error", "Failed to build time string, but hashes are fine");
	}
#endif // _DEBUG

	int item = 1; // Just a reminder menu items start at 1, not 0
	while (item = HiewGate_Menu(windowTitle, lines, _countof(lines), HASHES_SHA256_STR_LEN, item, &fnKeys, &pressedFnKey, NULL, NULL)) {
		if (item == HEM_INPUT_ESC)
			break;

		if (pressedFnKey == 0)
			break;

		switch (pressedFnKey) {
		case HEM_FNKEY_F1:
			showHelp();
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

	// Handle ENTER key press
	if (item > 0) {
		if (!sendTextToClipboard(&lines[item - 1], 1))
			HiewGate_Message("Error", "SendTextToClipboard() failed");
	}

	return HEM_OK;
}

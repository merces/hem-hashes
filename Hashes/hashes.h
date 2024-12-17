#pragma once

// Module defs

#define HASHES_BUFFER_SIZE 1024 * 1024 * 4

#define HASHES_CRC32_LEN 4
#define HASHES_CRC32_STR_LEN HASHES_CRC32_LEN * 2
#define HASHES_MD5_LEN 16
#define HASHES_MD5_STR_LEN HASHES_MD5_LEN * 2
#define HASHES_SHA1_LEN 20
#define HASHES_SHA1_STR_LEN HASHES_SHA1_LEN * 2
#define HASHES_SHA256_LEN 32
#define HASHES_SHA256_STR_LEN HASHES_SHA256_LEN * 2

// HEM SDK required defs

#define HEM_MODULE_VERSION_MAJOR 2
#define HEM_MODULE_VERSION_MINOR 0
#define HEM_MODULE_NAME "Hashes"
#define HEM_MODULE_FULL_NAME "Hashes 2.00: CRC-32|MD5|SHA-1|SHA-256"
#define HEM_MODULE_DESCRIPTION "Calculate common hashes of files and blocks"
#define HEM_MODULE_AUTHOR "Fernando Merces - github.com/merces"

// Object to be passed to threads
typedef struct {
    PVOID buffer;
    HEM_UINT buffer_len;
    UINT32 crc32;
    BCRYPT_ALG_HANDLE algMd5, algSha1, algSha256;
    BCRYPT_HASH_HANDLE hashMd5, hashSha1, hashSha256;
} hashObject;

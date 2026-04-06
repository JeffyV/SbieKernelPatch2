//
// Created by YuHuanTin on 2026/4/6.
//

module;

#include <ntstatus.h>
#include <windows.h>
#include <winternl.h>

export module CertGenerator;

import std;
import std.compat;
import Logger;


using bytes = std::vector<uint8_t>;

#define SystemFirmwareTableInformation 76

typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION {
    ULONG ProviderSignature;
    ULONG Action;
    ULONG TableID;
    ULONG TableBufferLength;
    UCHAR TableBuffer[ANYSIZE_ARRAY];
} SYSTEM_FIRMWARE_TABLE_INFORMATION, *PSYSTEM_FIRMWARE_TABLE_INFORMATION;

typedef enum _SYSTEM_FIRMWARE_TABLE_ACTION {
    SystemFirmwareTable_Enumerate,
    SystemFirmwareTable_Get
} SYSTEM_FIRMWARE_TABLE_ACTION;

typedef struct _RawSMBIOSData {
    UCHAR Used20CallingMethod;
    UCHAR SMBIOSMajorVersion;
    UCHAR SMBIOSMinorVersion;
    UCHAR DmiRevision;
    DWORD Length;
    UCHAR SMBIOSTableData[1];
} RawSMBIOSData;

typedef struct _dmi_header {
    UCHAR  type;
    UCHAR  length;
    USHORT handle;
    UCHAR  data[1];
} dmi_header;

bool GetFwUuid(unsigned char *uuid) {
    bool result = false;

    SYSTEM_FIRMWARE_TABLE_INFORMATION sfti;
    sfti.Action            = SystemFirmwareTable_Get;
    sfti.ProviderSignature = 'RSMB';
    sfti.TableID           = 0;
    sfti.TableBufferLength = 0;

    ULONG    Length = sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION);
    NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemFirmwareTableInformation), &sfti, Length, &Length);
    if (status != STATUS_BUFFER_TOO_SMALL)
        return result;

    ULONG BufferSize = sfti.TableBufferLength;

    Length                                   = BufferSize + sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION);
    SYSTEM_FIRMWARE_TABLE_INFORMATION *pSfti = reinterpret_cast<SYSTEM_FIRMWARE_TABLE_INFORMATION *>(new std::uint8_t[Length]);
    if (!pSfti)
        return result;
    *pSfti                   = sfti;
    pSfti->TableBufferLength = BufferSize;

    status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemFirmwareTableInformation), pSfti, Length, &Length);
    if (NT_SUCCESS(status)) {
        RawSMBIOSData *smb = (RawSMBIOSData *)pSfti->TableBuffer;

        for (UCHAR *data = smb->SMBIOSTableData; data < smb->SMBIOSTableData + smb->Length;) {
            dmi_header *h = (dmi_header *)data;
            if (h->length < 4)
                break;

            // Search for System Information structure with type 0x01 (see para 7.2)
            if (h->type == 0x01 && h->length >= 0x19) {
                data += 0x08; // UUID is at offset 0x08

                // check if there is a valid UUID (not all 0x00 or all 0xff)
                bool all_zero = true, all_one = true;
                for (int i = 0; i < 16 && (all_zero || all_one); i++) {
                    if (data[i] != 0x00) all_zero = false;
                    if (data[i] != 0xFF) all_one = false;
                }

                if (!all_zero && !all_one) {
                    // As off version 2.6 of the SMBIOS specification, the first 3 fields
                    // of the UUID are supposed to be encoded on little-endian. (para 7.2.1)
                    *uuid++ = data[3];
                    *uuid++ = data[2];
                    *uuid++ = data[1];
                    *uuid++ = data[0];
                    *uuid++ = data[5];
                    *uuid++ = data[4];
                    *uuid++ = data[7];
                    *uuid++ = data[6];
                    for (int i = 8; i < 16; i++)
                        *uuid++ = data[i];

                    result = true;
                }

                break;
            }

            // skip over formatted area
            UCHAR *next = data + h->length;

            // skip over unformatted area of the structure (marker is 0000h)
            while (next < smb->SMBIOSTableData + smb->Length && (next[0] != 0 || next[1] != 0))
                next++;

            next += 2;

            data = next;
        }
    }

    delete pSfti;
    return result;
}

char *hexbyte(UCHAR b, char *ptr) {
    std::string_view table = "0123456789ABCDEF";
    *ptr++                 = table[b >> 4];
    *ptr++                 = table[b & 0x0f];
    return ptr;
}

std::string InitFwUuid() {
    UCHAR uuid[16];
    char  uuid_local[40] = "00000000-0000-0000-0000-000000000000";

    if (GetFwUuid(uuid)) {
        auto *ptr = uuid_local;
        int   i;
        for (i = 0; i < 4; i++)
            ptr = hexbyte(uuid[i], ptr);
        *ptr++ = '-';
        for (; i < 6; i++)
            ptr = hexbyte(uuid[i], ptr);
        *ptr++ = '-';
        for (; i < 8; i++)
            ptr = hexbyte(uuid[i], ptr);
        *ptr++ = '-';
        for (; i < 10; i++)
            ptr = hexbyte(uuid[i], ptr);
        *ptr++ = '-';
        for (; i < 16; i++)
            ptr = hexbyte(uuid[i], ptr);
        *ptr++ = 0;
    }

    Logger::Info("sbie FW-UUID: {}", uuid_local);
    return uuid_local;
}

std::string Base64Encode(const bytes &data) {
    if (data.empty()) return {};

    DWORD base64Length = 0;
    if (!CryptBinaryToStringA(data.data(), data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &base64Length)) {
        return {};
    }

    std::string base64String(base64Length, '\0');
    if (!CryptBinaryToStringA(data.data(), data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64String.data(), &base64Length)) {
        return {};
    }

    // 去掉结尾的 '\0'
    if (!base64String.empty() && base64String.back() == '\0') {
        base64String.pop_back();
    }
    return base64String;
}

std::string Sha256(const std::string &input) {
    BCRYPT_ALG_HANDLE  hAlg   = nullptr;
    BCRYPT_HASH_HANDLE hHash  = nullptr;
    NTSTATUS           status = 0;
    DWORD              cbData = 0, cbHash = 0, cbHashObject = 0;
    PBYTE              pbHashObject = nullptr;
    PBYTE              pbHash       = nullptr;

    std::string result;

    // 1. 打开 SHA256 算法提供者
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) { return {}; }

    // 2. 获取哈希对象的大小（用于内部分配内存）
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status)) { goto cleanup; }

    // 3. 获取哈希输出结果的大小 (SHA256 应该是 32 字节)
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    // 分配缓冲区
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    pbHash       = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (NULL == pbHashObject || NULL == pbHash) goto cleanup;

    // 4. 创建哈希对象
    status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    // 5. 计算哈希
    status = BCryptHashData(hHash, (PBYTE)input.c_str(), (ULONG)input.length(), 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    // 6. 完成哈希，获取原始字节
    status = BCryptFinishHash(hHash, pbHash, cbHash, 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    result = std::string { pbHash, pbHash + cbHash };
cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
    if (pbHash) HeapFree(GetProcessHeap(), 0, pbHash);

    return result;
}

export namespace CertGenerator
{
    class ECDSA {
        struct Keys {
            bytes privateKey;
            bytes publicKey;
        };

        BCRYPT_ALG_HANDLE alg_handle_;
        NTSTATUS          status_;

        constexpr static auto CryptAlgorithm           = BCRYPT_ECDSA_P256_ALGORITHM;
        constexpr static auto CryptKeySize             = 256;
        constexpr static auto CryptExportFormatPublic  = BCRYPT_ECCPUBLIC_BLOB;
        constexpr static auto CryptExportFormatPrivate = BCRYPT_ECCPRIVATE_BLOB;

    public:
        ECDSA() {
            // https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider
            // https://learn.microsoft.com/en-us/windows/win32/SecCNG/cng-algorithm-identifiers
            status_ = BCryptOpenAlgorithmProvider(&alg_handle_, CryptAlgorithm, nullptr, 0);
            if (!NT_SUCCESS(status_)) {
                Logger::Err("BCryptOpenAlgorithmProvider failed with status: 0x{:#x}", status_);
                throw std::runtime_error("Failed to open algorithm provider");
            }
        }

        ~ECDSA() {
            status_ = BCryptCloseAlgorithmProvider(alg_handle_, 0);
            if (!NT_SUCCESS(status_)) {
                Logger::Err("BCryptCloseAlgorithmProvider failed with status: 0x{:#x}", status_);
            }
        }

        /**
         * windows bcrypt 生成 ECDSA 密钥对
         * @return
         */
        std::optional<Keys> GenerateKeyPair() {
            BCRYPT_KEY_HANDLE key_handle;

            // generate key pair
            status_ = BCryptGenerateKeyPair(
                alg_handle_,
                &key_handle,
                CryptKeySize,
                0);
            if (!NT_SUCCESS(status_)) {
                Logger::Err("BCryptGenerateKeyPair failed with status: 0x{:#x}", status_);
                return std::nullopt;
            }

            // finish key pair generation
            status_ = BCryptFinalizeKeyPair(key_handle, 0);
            if (!NT_SUCCESS(status_)) {
                Logger::Err("BCryptFinalizeKeyPair failed with status: 0x{:#x}", status_);
                BCryptDestroyKey(key_handle);
                return std::nullopt;
            }


            Keys  keys;
            ULONG sizeOfPubKey  = 0;
            ULONG sizeOfPrivKey = 0;

            // export public keys
            status_ = BCryptExportKey(key_handle, nullptr, CryptExportFormatPublic, nullptr, 0, &sizeOfPubKey, 0);
            if (!NT_SUCCESS(status_) || sizeOfPubKey == 0) {
                Logger::Err("BCryptExportKey (public key size query) failed with status: 0x{:#x}", status_);
                goto CleanUpExit;
            }


            keys.publicKey.resize(sizeOfPubKey);

            status_ = BCryptExportKey(key_handle, nullptr, CryptExportFormatPublic, keys.publicKey.data(), keys.publicKey.size(), &sizeOfPubKey, 0);
            if (!NT_SUCCESS(status_) || sizeOfPubKey == 0) {
                Logger::Err("BCryptExportKey (public key export) failed with status: 0x{:#x}", status_);
                goto CleanUpExit;
            }

            // export private keys

            status_ = BCryptExportKey(key_handle, nullptr, CryptExportFormatPrivate, nullptr, 0, &sizeOfPrivKey, 0);
            if (!NT_SUCCESS(status_) || sizeOfPrivKey == 0) {
                Logger::Err("BCryptExportKey (private key size query) failed with status: 0x{:#x}", status_);
                goto CleanUpExit;
            }

            keys.privateKey.resize(sizeOfPrivKey);

            status_ = BCryptExportKey(key_handle, nullptr, CryptExportFormatPrivate, keys.privateKey.data(), keys.privateKey.size(), &sizeOfPrivKey, 0);
            if (!NT_SUCCESS(status_) || sizeOfPrivKey == 0) {
                Logger::Err("BCryptExportKey (private key export) failed with status: 0x{:#x}", status_);
                goto CleanUpExit;
            }

            BCryptDestroyKey(key_handle);
            return keys;
CleanUpExit:
            BCryptDestroyKey(key_handle);
            return std::nullopt;
        }

        bytes Sign(const bytes &data, const bytes &privateKey) {
            BCRYPT_KEY_HANDLE key_handle;

            // import private key
            status_ = BCryptImportKeyPair(
                alg_handle_,
                nullptr,
                CryptExportFormatPrivate,
                &key_handle,
                (PUCHAR)privateKey.data(),
                privateKey.size(),
                0);
            if (!NT_SUCCESS(status_)) {
                Logger::Err("BCryptImportKeyPair failed with status: 0x{:#x}", status_);
                return {};
            }

            // sign data
            ULONG signatureSize = 0;
            status_             = BCryptSignHash(
                key_handle,
                nullptr,
                (PUCHAR)data.data(),
                data.size(),
                nullptr,
                0,
                &signatureSize,
                0);
            if (!NT_SUCCESS(status_) || signatureSize == 0) {
                Logger::Err("BCryptSignHash (signature size query) failed with status: 0x{:#x}", status_);
                BCryptDestroyKey(key_handle);
                return {};
            }

            bytes signature(signatureSize);

            status_ = BCryptSignHash(
                key_handle,
                nullptr,
                (PUCHAR)data.data(),
                data.size(),
                signature.data(),
                signature.size(),
                &signatureSize,
                0);
            if (!NT_SUCCESS(status_) || signatureSize == 0) {
                Logger::Err("BCryptSignHash (signing) failed with status: 0x{:#x}", status_);
                BCryptDestroyKey(key_handle);
                return {};
            }

            BCryptDestroyKey(key_handle);

            return { signature.begin(), signature.end() };
        }
    };

    std::string GetSignature(const std::string &certContent, const bytes &privKey) {
        using namespace std::ranges::views;

        auto kvs = certContent
                   | split('\n')
                   | transform([](auto line) {
                         return line | split(':');
                     })
                   | join;

        std::string full;
        for (auto &&part: kvs) {
            full.insert(full.end(), part.begin(), part.end());
        }

        Logger::Info("Certificate content for hashing:\n{}", full);
        auto hash = Sha256(full);

        ECDSA      ecdsa;
        const auto sign = ecdsa.Sign({ hash.begin(), hash.end() }, privKey);
        return Base64Encode(sign);
    }

    std::string GenerateNewCert(const bytes &privKey, std::string_view uuid = InitFwUuid()) {
        std::string content = std::format("TYPE:{}\n"
                                          "OPTIONS:{}\n"
                                          "HWID:{}",
            "ETERNAL", "NoSR,SBOX,EBOX,NETI,DESK,NoCR", uuid);

        content += "\nSIGNATURE: " + GetSignature(content, privKey);

        Logger::Info("Certificate content:\n{}", content);
        return content;
    }
}

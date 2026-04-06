//
// Created by YuHuanTin on 2026/3/30.
//

module;

#include <windows.h>
#include <winternl.h>

export module HostUtils;

import std;
import std.compat;
import Logger;

#define MAXIMUM_FILENAME_LENGTH 255

namespace Detail
{
    struct VirtualFreeDeleter {
        void operator()(void *ptr) const { VirtualFree(ptr, 0, MEM_RELEASE); }
    };

    // https://github.com/sam-b/windows_kernel_address_leaks/blob/master/NtQuerySysInfo_SystemModuleInformation/NtQuerySysInfo_SystemModuleInformation/NtQuerySysInfo_SystemModuleInformation.cpp
    typedef struct SYSTEM_MODULE {
        ULONG Reserved1;
        ULONG Reserved2;
#ifdef _WIN64
        ULONG Reserved3;
#endif
        PVOID ImageBaseAddress;
        ULONG ImageSize;
        ULONG Flags;
        WORD  Id;
        WORD  Rank;
        WORD  w018;
        WORD  NameOffset;
        CHAR  Name[MAXIMUM_FILENAME_LENGTH];
    } SYSTEM_MODULE, *PSYSTEM_MODULE;

    typedef struct _SYSTEM_MODULE_INFORMATION {
        ULONG         ModulesCount;
        SYSTEM_MODULE Modules[0];
    } SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;
} // namespace Detail

export namespace HostUtils
{
    std::unique_ptr<void, Detail::VirtualFreeDeleter> AllocSystemMem(size_t size) {
        std::unique_ptr<void, Detail::VirtualFreeDeleter> ptr(VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        return ptr;
    }

    std::optional<size_t> QuerySysModuleBase(std::string_view module) {
        // 11 = SystemModuleInformation
        ULONG sizeNeeded = 0;
        NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, nullptr, 0, &sizeNeeded);

        auto  mem     = AllocSystemMem(sizeNeeded);
        ULONG writeIn = 0;
        auto  status  = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, mem.get(), sizeNeeded, &writeIn);

        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
        if (!NT_SUCCESS(status) || writeIn != sizeNeeded) {
            Logger::Err("NtQuerySystemInformation failed with status: 0x{:#x} or writeIn != sizeNeeded, {} != {}", status, writeIn, sizeNeeded);
            return std::nullopt;
        }

        auto sysModuleInfo = reinterpret_cast<Detail::PSYSTEM_MODULE_INFORMATION>(mem.get());
        for (ULONG i = 0; i < sysModuleInfo->ModulesCount; ++i) {
            auto            &mod = sysModuleInfo->Modules[i];
            std::string_view modPath(mod.Name);
            std::string_view modName(mod.Name + mod.NameOffset);

            Logger::Debug("Module: {}\t[{}], Base Address: {:p}, Size: 0x{:#x}, Flags: {:#x}, Id: {}, Rank: {}, w018: {}", modPath, modName, mod.ImageBaseAddress, mod.ImageSize,
                mod.Flags, mod.Id, mod.Rank, mod.w018);

            if (modName == module) {
                Logger::Info("Found module: {}, Base Address: {:p}, Size: {:#x}", modName, mod.ImageBaseAddress, mod.ImageSize);
                return reinterpret_cast<size_t>(mod.ImageBaseAddress);
            }
        }
        return std::nullopt;
    }
} // namespace HostUtils

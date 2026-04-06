//
// Created by YuHuanTin on 2026/4/5.
//

module;

#include <windows.h>

#include <dbghelp.h>

export module PdbUtils;

import std;

export namespace PdbUtils
{

    // copy from https://github.com/EEEEhex/SbieKernelPatch.git
    /**
     * @brief 从模块文件 + PDB 中获取符号的模块内偏移.
     *
     * @param searchPath 包含 文件 和 pdb 的目录
     * @param execNameWithExt 文件名（需要包含后缀）
     * @param symbolName 符号名
     * @param baseAddress 基址
     * @return
     */
    std::optional<size_t> GetSymbolOffset(
        std::string_view searchPath,
        std::string_view execNameWithExt,
        std::string_view symbolName,
        DWORD64          baseAddress = 0x10000000) {

        HANDLE hProcess = GetCurrentProcess();
        if (!SymInitialize(hProcess, NULL, FALSE)) {
            return std::nullopt;
        }

        // 设置符号搜索路径
        if (!SymSetSearchPath(hProcess, searchPath.data())) {
            SymCleanup(hProcess);
            return std::nullopt;
        }

        // 加载模块
        DWORD64 moduleBase = SymLoadModuleEx(
            hProcess,
            NULL,
            execNameWithExt.data(),
            NULL,
            baseAddress,
            0,
            NULL,
            0);

        if (!moduleBase) {
            SymCleanup(hProcess);
            return std::nullopt;
        }


        // 查找符号
        BYTE         buffer[sizeof(SYMBOL_INFO) + 512];
        PSYMBOL_INFO symbol = reinterpret_cast<PSYMBOL_INFO>(buffer);
        ZeroMemory(symbol, sizeof(buffer));
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen   = 512;

        if (!SymFromName(hProcess, symbolName.data(), symbol)) {
            SymUnloadModule64(hProcess, moduleBase);
            SymCleanup(hProcess);
            return std::nullopt;
        }

        DWORD64 address = symbol->Address;
        size_t  offset  = address - moduleBase;

        // 卸载模块 & 清理
        SymUnloadModule64(hProcess, moduleBase);
        SymCleanup(hProcess);

        return offset;
    }
}

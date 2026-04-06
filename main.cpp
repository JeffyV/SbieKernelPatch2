
#include <windows.h>

import FileUtils;
import CertGenerator;
import DriverController;
import DriverManager;
import HostUtils;
import PdbUtils;
import Logger;
import std;
import std.compat;


using bytes = std::vector<std::uint8_t>;

constexpr std::string_view module        = "SbieDrv.sys";
constexpr std::string_view driverName    = "EchoDrv";
constexpr std::string_view pubSymbolName = "KphpTrustedPublicKey";
constexpr std::string      certFileName  = "Certificate.dat";
constexpr std::size_t      pubKeySize    = 4 + 4 + 32 + 32;

constexpr std::string_view defaultSysPath    = "Echo.sys";
constexpr std::string_view defaultSandboxDir = "./Sandboxie-Plus";


std::string FormatBytes(std::span<const std::uint8_t> bytes) {
    std::string dump;
    dump.reserve(bytes.size() * 5);

    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0) {
            dump += ' ';
        }
        dump += std::format("0x{:02X}", bytes[i]);
    }

    return dump;
}

bool DriverFunc(std::uintptr_t baseAddress, std::size_t keyOffset, const bytes &pubKey) {
    const auto keyAddress = baseAddress + keyOffset;
    Logger::Info("KphpTrustedPublicKey address: {:#x}", keyAddress);

    DriverInterface driver;
    if (driver.hDevice == INVALID_HANDLE_VALUE) {
        Logger::Err("Failed to open driver device");
        return false;
    }

    HANDLE processHandle = driver.get_handle_for_pid(GetCurrentProcessId());
    if (!processHandle || processHandle == INVALID_HANDLE_VALUE) {
        Logger::Err("Failed to obtain process handle for pid {}", GetCurrentProcessId());
        return false;
    }

    std::uint8_t originalKey[pubKeySize] { 0 };
    if (!driver.MmMove(reinterpret_cast<void *>(keyAddress), originalKey, sizeof(originalKey), processHandle)) {
        Logger::Err("Failed to read KphpTrustedPublicKey");
        Logger::Err("Error code: {}", GetLastError());
        return false;
    }

    Logger::Info("Current KphpTrustedPublicKey: [{}]", FormatBytes(originalKey));

    if (!driver.MmMove((void *)pubKey.data(), reinterpret_cast<void *>(keyAddress), pubKey.size(), processHandle)) {
        Logger::Err("Failed to patch KphpTrustedPublicKey");
        Logger::Err("Error code: {}", GetLastError());
        return false;
    }

    std::uint8_t patchedKey[pubKeySize] { 0 };
    if (!driver.MmMove(reinterpret_cast<void *>(keyAddress), patchedKey, sizeof(patchedKey), processHandle)) {
        Logger::Err("Failed to re-read KphpTrustedPublicKey after patch");
        Logger::Err("Error code: {}", GetLastError());
        return false;
    }

    Logger::Info("Patched KphpTrustedPublicKey: [{}]", FormatBytes(patchedKey));


    if (memcmp(patchedKey, pubKey.data(), pubKey.size()) != 0) {
        Logger::Err("Patched KphpTrustedPublicKey does not match the expected public key");
        return false;
    }

    Logger::Info("Patch SbieDrv.sys public key over.");
    return true;
}

int main(int argc, char *argv[]) {
    struct _OPT {
        bool help    = false;
        bool autoRun = false;
    } OPT;

    for (int i = 1; i < argc; ++i) {
        auto arg = std::string(argv[i]);
        if (arg.starts_with("--")) {
            arg = arg.substr(1);
        }
        if (arg.starts_with("-h") || arg.starts_with("-help")) {
            OPT.help = true;
        } else if (arg.starts_with("-a")) {
            OPT.autoRun = true;
        }
    }

    if (OPT.help || argc == 1) {
        Logger::Info("Usage: {} [--help|-h] <BYOVD-sys_FullPath, default = cur_path + {}> <sbieDrv_Dir, default = {}>", argv[0], defaultSysPath, defaultSandboxDir);
        return 0;
    }

    auto curPath = std::filesystem::current_path();

    auto byovdSysPath = OPT.autoRun ? (curPath / defaultSysPath).string() : argv[argc - 2];
    auto sbieDrvDir   = OPT.autoRun ? defaultSandboxDir : argv[argc - 1];
    
    Logger::Info("BYOVD sys path: {}", byovdSysPath);
    Logger::Info("SbieDrv directory: {}", sbieDrvDir);


    // generate key pair if not exist
    bytes privKey, pubKey;

    if (std::filesystem::exists("priv.blob") && std::filesystem::exists("pub.blob")) {
        Logger::Info("Existing key pair found, skipping generation.");

        auto e = FileUtils::readFile<bytes>("priv.blob");
        if (!e) {
            Logger::Err("Failed to read private key from 'priv.blob': {}", e.error());
            return -1;
        }
        privKey = e.value();

        e = FileUtils::readFile<bytes>("pub.blob");
        if (!e) {
            Logger::Err("Failed to read public key from 'pub.blob': {}", e.error());
            return -1;
        }
        pubKey = e.value();
    } else {
        Logger::Info("No existing key pair found, generating new ECDSA key pair...");

        CertGenerator::ECDSA ecdsa;
        auto                 keys = ecdsa.GenerateKeyPair();
        if (!keys) {
            Logger::Err("Failed to generate ECDSA key pair");
            return -1;
        }

        FileUtils::writeFile("priv.blob", keys->privateKey);
        FileUtils::writeFile("pub.blob", keys->publicKey);

        privKey = std::move(keys->privateKey);
        pubKey  = std::move(keys->publicKey);
    }

    // generate new cert
    if (std::filesystem::exists(certFileName)) {
        Logger::Info("Existing certificate file '{}' found, skipping generation.", certFileName);
    } else {
        auto cert = CertGenerator::GenerateNewCert(privKey);
        if (cert.empty()) {
            Logger::Err("Failed to generate certificate");
            return -1;
        }
        FileUtils::writeFile(certFileName, cert);
    }

    // search driver base address
    auto base = HostUtils::QuerySysModuleBase(module);
    if (!base) {
        Logger::Err("Failed to find base address of {}", module);
        return -1;
    }

    auto offset = PdbUtils::GetSymbolOffset(sbieDrvDir, module, pubSymbolName);
    if (!offset) {
        Logger::Err("Could't find symbol offset");
        return -1;
    }
    Logger::Info("Find symbol at: {:#x}", offset.value());


    auto bRet = DriverManager::InstallDriver(driverName, byovdSysPath);
    if (!bRet) {
        Logger::Err("failed to install driver '{}'", driverName);
        return -1;
    }

    bRet = DriverManager::StartDriver(driverName);
    if (!bRet) {
        Logger::Err("failed to start driver '{}'", driverName);
        return -1;
    }

    const auto patchOk = DriverFunc(base.value(), offset.value(), pubKey);
    if (!patchOk) {
        Logger::Err("failed to patch '{}'", module);
    }

    bRet = DriverManager::StopDriver(driverName);
    if (!bRet) {
        Logger::Err("failed to stop driver '{}'", driverName);
        return -1;
    }

    bRet = DriverManager::DeleteDriver(driverName);
    if (!bRet) {
        Logger::Err("failed to uninstall driver '{}'", driverName);
        return -1;
    }

    return patchOk ? 0 : -1;
}

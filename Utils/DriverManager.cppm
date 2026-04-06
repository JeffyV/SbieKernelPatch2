//
// Created by YuHuanTin on 2026/3/30.
//

module;

#include <windows.h>

export module DriverManager;

import std;
import Logger;

export namespace DriverManager
{
    bool InstallDriver(std::string_view driverName, std::string_view driverPath) {
        SC_HANDLE hSCManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!hSCManager) {
            Logger::Err("OpenSCManager failed: {}", GetLastError());
            return false;
        }

        SC_HANDLE hService = CreateServiceA(
            hSCManager,
            driverName.data(),
            driverName.data(),
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            driverPath.data(),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr);

        if (!hService) {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_EXISTS) {
                Logger::Info("Service '{}' already exists.", driverName);
            } else {
                Logger::Err("CreateService '{}' failed: {}", driverName, err);
                CloseServiceHandle(hSCManager);
                return false;
            }
        } else {
            Logger::Info("Service '{}' created successfully.", driverName);
            CloseServiceHandle(hService);
        }

        CloseServiceHandle(hSCManager);
        return true;
    }

    bool StartDriver(std::string_view driverName) {
        SC_HANDLE hSCManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hSCManager) {
            Logger::Err("OpenSCManager failed: {}", GetLastError());
            return false;
        }

        SC_HANDLE hService = OpenServiceA(hSCManager, driverName.data(), SERVICE_START);
        if (!hService) {
            Logger::Err("OpenService '{}' failed: {}", driverName, GetLastError());
            CloseServiceHandle(hSCManager);
            return false;
        }

        if (!StartServiceA(hService, 0, nullptr)) {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_ALREADY_RUNNING) {
                Logger::Info("Service '{}' is already running.", driverName);
            } else {
                Logger::Err("StartService '{}' failed: {}", driverName, err);
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                return false;
            }
        } else {
            Logger::Info("Service '{}' started successfully.", driverName);
        }

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return true;
    }

    bool StopDriver(std::string_view driverName) {
        SC_HANDLE hSCManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hSCManager) {
            Logger::Err("OpenSCManager failed: {}", GetLastError());
            return false;
        }

        SC_HANDLE hService = OpenServiceA(hSCManager, driverName.data(), SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (!hService) {
            Logger::Err("OpenService '{}' failed: {}", driverName, GetLastError());
            CloseServiceHandle(hSCManager);
            return false;
        }

        SERVICE_STATUS status = {};
        if (!ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_NOT_ACTIVE) {
                Logger::Info("Service '{}' is not running.", driverName);
            } else {
                Logger::Err("ControlService (STOP) failed: {}", err);
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                return false;
            }
        } else {
            Logger::Info("Service '{}' stopped successfully.", driverName);
        }

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return true;
    }

    bool DeleteDriver(std::string_view driverName) {
        SC_HANDLE hSCManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hSCManager) {
            Logger::Err("OpenSCManager failed: {}", GetLastError());
            return false;
        }

        SC_HANDLE hService = OpenServiceA(hSCManager, driverName.data(), DELETE);
        if (!hService) {
            Logger::Err("OpenService '{}' failed: {}", driverName, GetLastError());
            CloseServiceHandle(hSCManager);
            return false;
        }

        if (!DeleteService(hService)) {
            Logger::Err("DeleteService '{}' failed: {}", driverName, GetLastError());
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return false;
        }

        Logger::Info("Service '{}' deleted successfully.", driverName);
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return true;
    }
};

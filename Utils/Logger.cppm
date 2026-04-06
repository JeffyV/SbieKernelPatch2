//
// Created by YuHuanTin on 2026/3/31.
//

module;

export module Logger;

import std;
import std.compat;



export {
    namespace Logger
    {
        template<typename... Args>
        void Debug(std::format_string<Args...> format, Args &&...args) {
            std::println("[DEBUG] {}", std::format(format, std::forward<Args>(args)...));
        }

        template<typename... Args>
        void Info(std::format_string<Args...> format, Args &&...args) {
            std::println("[+] {}", std::format(format, std::forward<Args>(args)...));
        }
        
        template<typename... Args>
        void Err(std::format_string<Args...> format, Args &&...args) {
            std::println("[Error] {}", std::format(format, std::forward<Args>(args)...));
        }
    }
}

//
// Created by YuHuanTin on 2026/4/6.
//

module;

export module FileUtils;

import std;
import std.compat;

export namespace FileUtils
{
    template<typename ReturnType>
        requires requires {
            sizeof(typename ReturnType::value_type) == 1;
        }
    std::expected<ReturnType, std::string> readFile(const std::string &FilePath, const bool CreateIfNotExist = true) {
        std::fstream fs(FilePath, std::ios_base::in | std::ios_base::binary);

        // 不存在则创建
        if (!fs.is_open() && CreateIfNotExist)
            fs.open(FilePath, std::ios_base::out | std::ios_base::binary);

        // 还读取不了则返回空
        if (!fs.is_open())
            return std::unexpected("can't open file, maybe not exist or permission denied");

        // 获取文件大小
        const auto begin = fs.tellg();
        fs.seekg(0, std::ios_base::end);
        const auto end = fs.tellg();
        fs.seekg(0, std::ios_base::beg);

        // 读取
        ReturnType content;
        content.resize(static_cast<size_t>(end - begin));
        fs.read(reinterpret_cast<char *>(content.data()), static_cast<std::streamsize>(content.size()));
        return content;
    }

    template<typename InputType>
        requires requires(InputType content) {
            content.data();
            content.size();
        }
    bool writeFile(const std::string &FilePath, InputType &&content) {
        std::fstream fs(FilePath, std::ios_base::out | std::ios_base::binary);
        if (!fs.is_open())
            return false;

        fs.write(std::bit_cast<const char *>(content.data()), content.size());
        fs.close();
        return true;
    }
}

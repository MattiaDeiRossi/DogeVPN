#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <map>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iterator>
#include <optional>

namespace file_utils {

    std::map<std::string, std::string> parse_key_value_lines(const char *path);

    std::vector<std::map<std::string, std::string>> parse_multi_key_value_lines(const char *path);

    std::optional<std::map<std::string, std::string>> find_in_multi_key_value_lines(const char *path, const char *key, const char *value);
}

#endif
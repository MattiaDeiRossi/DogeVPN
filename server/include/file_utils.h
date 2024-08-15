#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <map>
#include <string>
#include <fstream>
#include <sstream>
#include <iterator>

namespace file_utils {

    std::map<std::string, std::string> parse_key_value_lines(const char *path, char delimiter);
}

#endif
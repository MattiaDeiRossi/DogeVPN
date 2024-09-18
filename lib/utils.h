#ifndef UTILS_H
#define UTILS_H

#include <cstdlib>
#include <cstring>
#include <string>

namespace utils
{
    unsigned char hex_char_to_byte(char ch);

	void hex_string_to_bytes(const std::string& hex, unsigned char* byte_array, size_t byte_array_size);

    void reverse_string(char *str, size_t length);

    int read_reverse(
        unsigned char *dst,
        const unsigned char *src,
        ssize_t dst_size,
        ssize_t src_size,
        ssize_t *current_index,
        bool strict_size);

    bool start_with(const char *raw_message, size_t n, std::string start);

    std::string string_from_bytes(unsigned const char *bytes, size_t n);

    void log_hex(const void *buffer, size_t n);

    void push_back(std::string &str, const void *buffer, size_t buffer_size);
}

#endif
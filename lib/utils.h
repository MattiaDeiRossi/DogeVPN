#ifndef UTILS_H
#define UTILS_H

#include <cstdlib>
#include <cstring>

namespace utils
{
    void reverse_string(char *str, size_t length);

    int read_reverse(
        unsigned char *dst,
        const unsigned char *src,
        ssize_t dst_size,
        ssize_t src_size,
        ssize_t *current_index,
        bool strict_size);
}

#endif
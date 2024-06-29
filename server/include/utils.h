#ifndef UTILS_H
#define UTILS_H

#include "standards.h"

namespace utils
{
    void reverse_string(char *str, size_t length);

    int read_reverse(
        unsigned char *dst, 
        const unsigned char *src, 
        size_t dst_size, 
        size_t src_size, 
        int *current_index,
        bool strict_size
    );
}

#endif
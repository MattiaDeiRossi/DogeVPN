#ifndef RANDOM_UTILS_H
#define RANDOM_UTILS_H

#include <cstddef>

namespace random_utils
{
    struct random
    {
        int generate_secure(unsigned char *buffer, size_t num);

        int generate(unsigned char *buffer, size_t num);

        int generate_16(unsigned char *buffer, bool secure);

        int generate_32(unsigned char *buffer, bool secure);
    };
}

#endif
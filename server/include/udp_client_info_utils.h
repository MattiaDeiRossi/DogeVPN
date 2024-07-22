#ifndef UDP_CLIENT_INFO_UTILS_H
#define UDP_CLIENT_INFO_UTILS_H

#include "standards.h"

namespace udp_client_info_utils {

    const int KEY_SIZE = 32;

    struct udp_client_info{
        unsigned char key[KEY_SIZE];
    };

    int init(const char *key, udp_client_info *info);
}

#endif
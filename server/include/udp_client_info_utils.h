#ifndef UDP_CLIENT_INFO_UTILS_H
#define UDP_CLIENT_INFO_UTILS_H

#include "standards.h"
#include "data_structures.h"

namespace udp_client_info_utils
{

    int init(const char *key, size_t num, udp_client_info **info);
}

#endif
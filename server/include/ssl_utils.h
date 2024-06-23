#ifndef SSL_UTILS_H
#define SSL_UTILS_H

#include "standards.h"
#include "defines.h"

namespace ssl_utils
{

    int init_ssl(
        SSL_CTX **ctx_pointer,
        bool is_server,
        const char *pub_cert_path,
        const char *pri_cert_path
    );
}

#endif
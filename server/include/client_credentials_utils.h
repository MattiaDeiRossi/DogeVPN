#ifndef CLIENT_CREDENTIALS_UTILS_H
#define CLIENT_CREDENTIALS_UTILS_H

#include "standards.h"
#include "data_structures.h"
#include "defines.h"

namespace client_credentials_utils
{
    int initialize(const char* data, size_t num, client_credentials *result);
    
    void log_client_credentials(const client_credentials *credentials);
}

#endif
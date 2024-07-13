#ifndef CLIENT_CREDENTIALS_UTILS_H
#define CLIENT_CREDENTIALS_UTILS_H

#include <stdio.h>
#include <string.h>

namespace client_credentials_utils
{
    const int MIN_PASSWORD_SIZE = 16;
    const int MAX_CREDENTIALS_SIZE = 256;
    const char USER_PASSWORD_SEPARATOR = '.';

    struct client_credentials {
        char username[256];
        char password[256];
    };

    typedef struct client_credentials client_credentials;

    int initialize(const char* data, size_t num, client_credentials *result);
    
    void log_client_credentials(const client_credentials *credentials);
}

#endif
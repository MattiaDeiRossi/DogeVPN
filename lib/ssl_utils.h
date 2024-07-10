#ifndef SSL_UTILS_H
#define SSL_UTILS_H

#include "socket_utils.h"
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

namespace ssl_utils
{

    int init_ssl(
        SSL_CTX **ctx_pointer,
        bool is_server,
        const char *pub_cert_path,
        const char *pri_cert_path
    );

    void free_ssl(SSL *ssl, int *with_error);

    int bind_ssl(SSL_CTX *ctx, socket_utils::socket_t socket, SSL **ssl_p, const char *server_name);

    void log_ssl_cipher(SSL *ssl, struct sockaddr_storage storage, socklen_t length);

    int read(SSL *ssl, char *buffer, size_t num);

    int write(SSL *ssl, char *buffer, size_t num);

    int generate_rand_32(unsigned char *buffer);
}

#endif
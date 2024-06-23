#include "ssl_utils.h"

namespace ssl_utils
{

    /* Function to call whenever a SSL contect is needed. 
    *  It can be resued for all the connections.
    */
    int init_ssl(
        SSL_CTX **ctx_pointer,
        bool is_server,
        const char *pub_cert_path,
        const char *pri_cert_path
    ) {

        // This is required to initialize the OpenSSL.
        SSL_library_init();

        /* This cause OpenSSL to load all available algorithms. 
        *  A better alternative is loading only the needed ones.
        */
        OpenSSL_add_all_algorithms();

        /* This cause OpenSSL to load error strings: 
        *   - it is used just to see readable error messages when something goes wrong
        */
        SSL_load_error_strings();

        SSL_CTX *ctx = SSL_CTX_new(is_server ? TLS_server_method(): TLS_client_method());
        if (!ctx) return INIT_SSL_ERROR;

        if (is_server) {

            int load_certificate = SSL_CTX_use_certificate_file(ctx, pub_cert_path , SSL_FILETYPE_PEM);
            int load_private_key = SSL_CTX_use_PrivateKey_file(ctx, pri_cert_path, SSL_FILETYPE_PEM);

            if (!load_certificate || !load_private_key) {
                ERR_print_errors_fp(stderr);
                SSL_CTX_free(ctx);
                return SSL_CERTIFICATE_ERROR;
            }
        }

        *ctx_pointer = ctx;
        return 0;
    }
}
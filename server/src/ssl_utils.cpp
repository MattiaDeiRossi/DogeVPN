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
        if (!ctx) return -1;

        if (is_server) {

            int load_certificate = SSL_CTX_use_certificate_file(ctx, pub_cert_path , SSL_FILETYPE_PEM);
            int load_private_key = SSL_CTX_use_PrivateKey_file(ctx, pri_cert_path, SSL_FILETYPE_PEM);

            if (!load_certificate || !load_private_key) {
                ERR_print_errors_fp(stderr);
                SSL_CTX_free(ctx);
                return -1;
            }
        }

        *ctx_pointer = ctx;
        return 0;
    }

    void free_ssl(SSL *ssl) {

        // Nothing can be done.
        if (ssl == NULL) return;

        // Review this piece of code.
        SSL_shutdown(ssl);
        SSL_free(ssl);

        int socket = SSL_get_fd(ssl);
        if (socket != -1) {
            socket_utils::close_socket(socket);
        }
    }

    int bind_ssl(SSL_CTX *ctx, socket_t socket, SSL **ssl_p) {
    
        // Creating an SSL object.
        SSL *ssl = SSL_new(ctx);
        if (ssl == NULL) {
            free_ssl(ssl);
            return -1;
        }

        /* Associating the ssl object with the client socket.
        *  Now the ssl object is bound to a socket that can be used to communicate over TLS.
        */
        SSL_set_fd(ssl, socket);

        /* A call to SSL_accept() can fail for many reasons. 
        *  For example if the connected client does not trust our certificate.
        *  Or the client and the server cannot agree on a cipher suite. 
        *  This must be taking into account a the server should continue listening to incoming connections.
        */
        if (SSL_accept(ssl) != 1) {
            ERR_print_errors_fp(stderr);
            free_ssl(ssl);
            return -1;
        }

        // Saving the SSL object just created.
        *ssl_p = ssl;

        return 0;
    }

    void log_ssl_cipher(SSL *ssl, struct sockaddr_storage storage, socklen_t length) {

        char buffer[512];
        struct sockaddr *address = (struct sockaddr*) &storage;
        getnameinfo(address, length, buffer, sizeof(buffer), 0, 0, NI_NUMERICHOST);

        /* Logging client IP address.
        *  Logging the established cipher.
        */
        printf("New connection from %s wth cipher %s\n", buffer, SSL_get_cipher(ssl));
    }

    int read(SSL *ssl, char *buffer, size_t num) {

        /* The assumption here is that all the data comes from a single read.
        *  This is not the ideal solution sunce there's no guarantees that a single read can suffice.
        *  A better approach would be agreeing on maximum size and a final line indicating the end of the message.
        */
        int bytes = SSL_read(ssl, buffer, num);
        if (bytes < 1) {
            ssl_utils::free_ssl(ssl);
            return -1;
        }

        return bytes;
    }

    int write(SSL *ssl, char *buffer, size_t num) {

        /* Errors can be different.
        *  A more resilient approach would be call SSL_get_error() to find out if it's retryable.
        */
        int bytes = SSL_write(ssl, buffer, num);
        if (bytes < 1) {
            ssl_utils::free_ssl(ssl);
            return -1;
        }

        return bytes;
    }

    int generate_rand_32(unsigned char *buffer) {

        /* Generating a key by using the OpenSSL library.
        *  It will be 32 bytes long.
        */
        memset(buffer, 0, 32);
        int rand_value = RAND_bytes(buffer, 32);
        if (rand_value != 1) return -1;
        else return 0;
    }

}
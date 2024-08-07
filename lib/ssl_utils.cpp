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

    SSL_CTX *create_ssl_context_or_abort(
        bool is_server,
        const char *pub_cert_path,
        const char *pri_cert_path
    ) {

        SSL_CTX *ctx = NULL;
        if (ssl_utils::init_ssl(&ctx, is_server, pub_cert_path, pri_cert_path) == -1) {
            fprintf(stderr, "create_ssl_context_or_abort: ssl context cannot be created\n");
            exit(EXIT_FAILURE);
        }

        return ctx;
    }

    int ssl_fd_or_throw(const SSL* ssl) {

        int socket = SSL_get_fd(ssl);

        if (socket == -1) {
            throw std::invalid_argument("SSL is not bound to any socket");
        }

        return socket;
    }

    void free_ssl(SSL *ssl, int *with_error) {

        // Nothing can be done.
        if (ssl == NULL) return;

        /* SSL_shutdown() should not be called if a previous fatal error has occurred on a connection.
        *  That is when SSL_get_error(3) has returned SSL_ERROR_SYSCALL or SSL_ERROR_SSL.
        */
        bool should_shutdown = true;
        if (with_error != NULL) {
            int error = SSL_get_error(ssl, *with_error);
            should_shutdown = !(error == SSL_ERROR_SYSCALL || error == SSL_ERROR_SSL);
        }

        if (should_shutdown) {
            /* The fast shutdown approach can only be used if there is no intention to reuse the underlying connection. */
            SSL_shutdown(ssl);
        }

        SSL_free(ssl);

        int socket = SSL_get_fd(ssl);
        if (socket != -1) {
            socket_utils::close_socket(socket);
        }
    }

    void ssl_context_free(SSL_CTX *ctx) {
        if (ctx != NULL) SSL_CTX_free(ctx);
    }

    int bind_ssl(SSL_CTX *ctx, socket_utils::socket_t socket, SSL **ssl_p, bool is_server) {
    
        // Creating an SSL object.
        SSL *ssl = SSL_new(ctx);
        if (ssl == NULL) {
            utils::print_error("bind_ssl: a new SSL object cannot be created\n");
            free_ssl(ssl, NULL);
            return -1;
        }

        /* Associating the ssl object with the client socket.
        *  Now the ssl object is bound to a socket that can be used to communicate over TLS.
        */
        SSL_set_fd(ssl, socket);

        /* Client is trying to communicate with the server.
        *  In the end a connect must be called.
        */
        if (!is_server) {

            int connect_result = SSL_connect(ssl);
            if (SSL_connect(ssl) != 1) {
                utils::print_error("bind_ssl: client cannot connect to server\n");
                free_ssl(ssl, &connect_result);
                return -1;
            }
        }

        // The server must accept an incoming client.
        if (is_server) {

            /* A call to SSL_accept() can fail for many reasons. 
            *  For example if the connected client does not trust our certificate.
            *  Or the client and the server cannot agree on a cipher suite. 
            *  This must be taking into account a the server should continue listening to incoming connections.
            */
            int accept_result = SSL_accept(ssl);
            if (accept_result != 1) {
                utils::print_error("bind_ssl: server cannot accept connections\n");
                ERR_print_errors_fp(stderr);
                free_ssl(ssl, &accept_result);
                return -1;
            }
        }

        // Saving the SSL object just created.
        *ssl_p = ssl;

        return 0;
    }

    SSL *bind_client_ssl_or_abort(SSL_CTX *ctx, socket_utils::socket_t socket) {

        SSL *ssl_pointer;
        if (bind_ssl(ctx, socket, &ssl_pointer, false) == -1) {
            fprintf(stderr, "bind_client_ssl_or_abort: client socket cannot be bound to ssl object\n");
            exit(EXIT_FAILURE);
        }

        return ssl_pointer;
    }

    void log_ssl_cipher(SSL *ssl, struct sockaddr_storage storage, socklen_t length) {

        char buffer[512];
        struct sockaddr *address = (struct sockaddr*) &storage;
        getnameinfo(address, length, buffer, sizeof(buffer), 0, 0, NI_NUMERICHOST);

        /* Logging client IP address.
        *  Logging the established cipher.
        */
        utils::print("Connection established:\n", 0);
        utils::print("From:", 3);
        utils::print(" ", 0);
        utils::print(buffer, 0);
        utils::print("\n", 0);
        utils::print("Cipher:", 3);
        utils::print(" ", 0);
        utils::print(SSL_get_cipher(ssl), 0);
        utils::print("\n", 0);
    }

    int read(SSL *ssl, char *buffer, size_t num) {

        /* The assumption here is that all the data comes from a single read.
        *  This is not the ideal solution sunce there's no guarantees that a single read can suffice.
        *  A better approach would be agreeing on maximum size and a final line indicating the end of the message.
        */
        int bytes = SSL_read(ssl, buffer, num);
        if (bytes < 1) {
            ssl_utils::free_ssl(ssl, &bytes);
            return -1;
        }

        return bytes;
    }

    int read_or_throw(SSL *ssl, char *buffer, size_t num) {

        int bytes = read(ssl, buffer, num);
        if (bytes == -1) {
            throw std::invalid_argument("SSL report read failure");
        }

        return bytes;
    }

    int write(SSL *ssl, char *buffer, size_t num) {

        /* Errors can be different.
        *  A more resilient approach would be call SSL_get_error() to find out if it's retryable.
        */
        int bytes = SSL_write(ssl, buffer, num);
        if (bytes < 1) {
            ssl_utils::free_ssl(ssl, &bytes);
            return -1;
        }

        return bytes;
    }

    int write_or_throw(SSL *ssl, char *buffer, size_t num) {

        int bytes = write(ssl, buffer, num);
        if (bytes == -1) {
            throw std::invalid_argument("SSL report write failure");
        }

        return bytes;
    }

    int generate_rand(unsigned char *buffer, size_t num) {

        /* Generating a key by using the OpenSSL library.
        *  It will be num bytes long.
        */
        memset(buffer, 0, num);
        int rand_value = RAND_bytes(buffer, num);
        if (rand_value != 1) return -1;
        else return 0;
    }

    int generate_rand_32(unsigned char *buffer) {
        return generate_rand(buffer, 32);
    }

    int generate_rand_16(unsigned char *buffer) {
        return generate_rand(buffer, 16);
    }

}
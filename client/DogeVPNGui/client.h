#ifndef CLIENT_H
#define CLIENT_H

#include <openssl/ssl.h>
#include <netinet/in.h>
#include <socket_utils.h>
#include <utils.h>
#include <ssl_utils.h>
#include <socket_utils.h>
#include <client_credentials_utils.h>
#include "defines.h"
#include "standards.h"
#include <iostream>
#include <encryption.h>

// Macros
#define IS_VALID_SOCKET(s) ((s) >= 0)
#define CLOSE_SOCKET(s) close(s)
#define GET_SOCKET_ERRNO() (errno)
#define PANIC_EXIT() exit(GET_SOCKET_ERRNO())

// Constants
#define TRUE 1
#define AUTH_FAILED "AuthFailed"
#define SA struct sockaddr

// Typedefs
typedef int SOCKET;

// Global variables
extern bool stop_flag;

// Function declarations
void set_stop_flag(bool status);
int create_tcp_socket(SOCKET *tcp_socket);
void free_tcp_ssl(SSL_CTX* ctx, SOCKET tcp_socket, SSL* ssl_session);
int bind_socket_to_SSL(SSL_CTX* ctx, SOCKET tcp_socket, SSL** ssl_session);
int send_credential(SSL* ssl_session, char const* user, char const* pwd, char* secret_key);
int udp_exchange_data(socket_utils::socket_t *udp_socket, unsigned char* secret_key);
int tun_alloc(socket_utils::socket_t *tun_fd);
void ifconfig();
void setup_route_table();
void cleanup_route_table();
static void run(char *cmd);
static int max(int a, int b);
int start_doge_vpn(char const* domain, char const* port, char const* user, char const* pwd);
#endif // CLIENT_H

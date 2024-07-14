#ifndef CLIENT_H
#define CLIENT_H

#include <openssl/ssl.h>
#include <netinet/in.h>
#include "standards.h"
#include "encryption.h"
#include "defines.h"
#include "utils.h"
#include "ssl_utils.h"
#include <iostream>

// Macro e costanti
#define IS_VALID_SOCKET(s) ((s) >= 0)
#define CLOSE_SOCKET(s) close(s)
#define GET_SOCKET_ERRNO() (errno)
#define PANIC_EXIT() exit(GET_SOCKET_ERRNO())
#define TRUE 1
#define AUTH_FAILED "AuthFailed"
#define SA struct sockaddr

typedef int SOCKET;

// Dichiarazioni delle funzioni
void set_stop_flag(bool status);
int create_tcp_socket(SOCKET *tcp_socket);
void free_tcp_ssl(SSL_CTX* ctx, SOCKET tcp_socket, SSL* ssl_session);
int bind_socket_to_SSL(SSL_CTX* ctx, SOCKET tcp_socket, SSL** ssl_session);
int send_credential(SSL* ssl_session, char const* user, char const* pwd, char* secret_key);
int create_udp_socket(SOCKET *udp_socket);
int udp_exchange_data(SOCKET *udp_socket, unsigned char* secret_key);
int tun_alloc(SOCKET *tun_fd);
void ifconfig();
void setup_route_table();
void cleanup_route_table();
int start_doge_vpn(char const* user, char const* pwd);

#endif // CLIENT_H

#ifndef DATA_STRUCTURE_H
#define DATA_STRUCTURE_H

#include "defines.h"
#include "standards.h"

typedef int socket_t;
typedef int user_id;

typedef enum {
  TCP_SERVER_SOCKET,
  TCP_CLIENT_SOCKET,
  UDP_SERVER_SOCKET
} socket_type;

typedef struct {
    socket_t socket;
    socklen_t client_len;
    struct sockaddr_storage client_address;
    SSL *ssl;    
} tcp_client_socket;

typedef struct {
    socket_t socket;
} tcp_server_socket;

typedef struct {
    socket_t socket;
} udp_server_socket;

typedef union {
    tcp_client_socket *tcs;
    tcp_server_socket *tss;
    udp_server_socket *uss;
} socket_data;

typedef struct {
    socket_data data;
    socket_type type;
} socket_holder;

typedef struct {
    char data[256];
    char username[256];
    char password[256];
} client_credentials;

typedef struct {
    char key[KEY_LEN];
} udp_client_info;

typedef struct {
    unsigned char message[UDP_THEORETICAL_LIMIT];
    size_t length;
} packet;

typedef struct {
    unsigned char key[KEY_LEN];
    unsigned char iv[IV_LEN];
} encryption_data;

typedef struct {
    unsigned char user_id[ID_LEN];
    unsigned char iv[IV_LEN];
    unsigned char hash[SHA_256_BYTES];
    unsigned char message[MAX_MESSAGE_BYTES];
} vpn_client_packet_data;

#endif#ifndef DATA_STRUCTURE_H
#define DATA_STRUCTURE_H

#include "defines.h"
#include "standards.h"

typedef int socket_t;
typedef int user_id;

typedef enum {
  TCP_SERVER_SOCKET,
  TCP_CLIENT_SOCKET,
  UDP_SERVER_SOCKET
} socket_type;

typedef struct {
    socket_t socket;
    socklen_t client_len;
    struct sockaddr_storage client_address;
    SSL *ssl;    
} tcp_client_socket;

typedef struct {
    socket_t socket;
} tcp_server_socket;

typedef struct {
    socket_t socket;
} udp_server_socket;

typedef union {
    tcp_client_socket *tcs;
    tcp_server_socket *tss;
    udp_server_socket *uss;
} socket_data;

typedef struct {
    socket_data data;
    socket_type type;
} socket_holder;

typedef struct {
    char data[256];
    char username[256];
    char password[256];
} client_credentials;

typedef struct {
    char key[KEY_LEN];
} udp_client_info;

typedef struct {
    unsigned char message[UDP_THEORETICAL_LIMIT];
    size_t length;
} packet;

typedef struct {
    unsigned char key[KEY_LEN];
    unsigned char iv[IV_LEN];
} encryption_data;

typedef struct {
    unsigned char user_id[ID_LEN];
    unsigned char iv[IV_LEN];
    unsigned char hash[SHA_256_BYTES];
    unsigned char message[MAX_MESSAGE_BYTES];
} vpn_client_packet_data;

#endif
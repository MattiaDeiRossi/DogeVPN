#ifndef DATA_STRUCTURE_H
#define DATA_STRUCTURE_H

#include "defines.h"
#include "standards.h"
#include "encryption.h"
#include "socket_utils.h"

typedef int user_id;

typedef enum {
  TCP_SERVER_SOCKET,
  TCP_CLIENT_SOCKET,
  UDP_SERVER_SOCKET, 
  TUN_SERVER_SOCKET,
} socket_type;

typedef struct {
    socket_utils::socket_t socket;
    socklen_t client_len;
    struct sockaddr_storage client_address;
    SSL *ssl;    
} tcp_client_socket;

typedef struct {
    socket_utils::socket_t socket;
} tcp_server_socket;

typedef struct {
    socket_utils::socket_t socket;
} udp_server_socket;

typedef struct {
    socket_utils::socket_t socket;
} tun_server_socket;

typedef union {
    tcp_client_socket *tcs;
    tcp_server_socket *tss;
    udp_server_socket *uss;
    tun_server_socket *tun_ss;
} socket_data;

typedef struct {
    socket_data data;
    socket_type type;
} socket_holder;

typedef struct {
    char key[32];
} udp_client_info;

typedef struct {
    unsigned char user_id[ID_LEN];
    unsigned char iv[encryption::MAX_IV_SIZE];
    unsigned char hash[encryption::SHA_256_SIZE];
    encryption::packet encrypted_packet;
} vpn_client_packet_data;

#endif
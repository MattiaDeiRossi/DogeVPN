#ifndef DATA_STRUCTURE_H
#define DATA_STRUCTURE_H

#include "defines.h"
#include "socket.h"

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
} client_udp_connection_info;

struct packet{
    unsigned char* msg;
    size_t len;
    packet(unsigned char* msg_, size_t len_):
        msg(msg_), len(len_){}
};
typedef struct packet packet;

struct encryption_data{
    unsigned char key[KEY_LEN];
    unsigned char iv[IV_LEN];
    encryption_data(unsigned char* key_, unsigned char* iv_)
    {
        memset(key, 0, KEY_LEN);
        memcpy(key, key_, KEY_LEN);

        memset(iv, 0, IV_LEN);
        memcpy(iv, iv_, IV_LEN);
    };
};
typedef struct encryption_data encryption_data;


#endif
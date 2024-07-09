#ifndef DEFINES_H
#define DEFINES_H

// Error definitions
#define SSL_INIT_ERROR 1000
#define SSL_NEW_ERROR 1001
#define SSL_TLSEXT_HOST_NAME_ERROR 1002
#define SSL_SET_FD_ERROR 1003
#define TCP_SSL_CONNECT_ERROR 1004
#define TCP_SOCKET_ERROR 2000
#define TCP_CONNECT_ERROR 2001
#define TCP_SEND_ERROR 2002
#define TCP_READ_ERROR 2003
#define UDP_SOCKET_ERROR 3000
#define UDP_CONNECT_ERROR 3001
#define UDP_SEND_ERROR 3002
#define UDP_READ_ERROR 3003
#define TUN_OPEN_DEV 4000
#define TUN_TUNSETIFF 4001
#define TUN_SEND_ERROR 4002
#define TUN_READ_ERROR 4003
#define MAX_FD_ERROR 5000
#define WRONG_CREDENTIAL 7000

// TCP constant definitions
#define TCP_HOST "0.0.0.0"
#define TCP_PORT 8080

// UDP constant definitions
#define UDP_HOST "127.0.0.1"
#define UDP_PORT 19090

// TUN constant definitions
#define SERVER_HOST "10.5.0.6"
#define MTU 1400

#endif
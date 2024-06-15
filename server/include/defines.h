#ifndef DEFINES_H
#define DEFINES_H

// ***  Start error definitions ***
#define INIT_SSL_ERROR 10
#define TCP_SOCKET_ERROR 11
#define TCP_BIND_ERROR 12
#define TCP_LISTEN_ERROR 13
#define TCP_ACCEPT_ERROR 14
#define SSL_CREATION_ERROR 15
#define SSL_ACCEPT_ERROR 16
#define SSL_CERTIFICATE_ERROR 17
#define OUT_OF_MEMORY 18
#define UDP_SOCKET_ERROR 19
#define UDP_BIND_ERROR 20
#define ILLEGAL_STATE 21
#define SELECT_ERROR 22
#define UNEXPECTED_DISCONNECT 23
#define UNEXPECTED_SOCKET_TO_DELETE 24
#define PWD_TOO_SHORT 25
#define RAND_NOT_SUPPORTED 26
#define RAND_FAILURE 27
// ***  End error definitions ***

// *** Start TCP constant definitions ***
#define MAX_TCP_CONNECTIONS 10
#define TCP_HOST 0
#define TCP_PORT "8080"
// *** End TCP constant definitions ***

// *** Start UDP constant definitions ***
#define UDP_HOST 0
#define UDP_PORT "9090"
// *** Start UDP constant definitions ***

// *** Start constants ***
#define TRUE 1
#define USR_PWD_SEPARATOR '.'
#define MESSAGE_SEPARATOR '.'
#define MINIMUM_PWD_LEN 16
#define KEY_LEN 16
#define ID_LEN 24
#define MAX_KEY_MESSAGE_LEN 64
// *** End constants ***

// *** Salt ***
#define SALT "slt123safe" // should not be present here but in .env file

#endif
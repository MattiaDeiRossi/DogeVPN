// Compile with gcc client.c -lssl -lcrypto -o client

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <ctype.h>
#include "aes.h"

// *** Start SSL headers ***
// In order to generate a self signed certificate:
//  - openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout key.pem -out cert.pem -days 365
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
// *** End SSL headers ***

// ***  Start error definitions ***
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
#define WRONG_CREDENTIAL 4000


// ***  End error definitions ***

// *** Start TCP constant definitions ***
#define TCP_HOST "0.0.0.0"
#define TCP_PORT 8080
// *** End TCP constant definitions ***

// *** Start UDP constant definitions ***
#define UDP_HOST "127.0.0.1"
#define UDP_PORT 19090
// *** End UDP constant definitions ***

// *** Start Tun constant definitions ***
#define SERVER_HOST "10.5.0.6"
// *** End Tun constant definitions ***


// *** Start macros ***
#define IS_VALID_SOCKET(s) ((s) >= 0)
#define CLOSE_SOCKET(s) close(s)
#define GET_SOCKET_ERRNO() (errno)
#define PANIC_EXIT() exit(GET_SOCKET_ERRNO())
// *** End macros ***

// *** Start constants ***
#define TRUE 1
#define AUTH_FAILED "AuthFailed"
// *** End constants ***

#define SA struct sockaddr

typedef int SOCKET;

void log_vpn_client_error(int error_number) {

    switch (error_number) {
        case SSL_INIT_ERROR:
            fprintf(
                stderr, 
                "Client cannot start since a valid SSL context cannot be created. Call to SSL_CTX_new() failed.\n"
            );
            break;
        case SSL_NEW_ERROR:
            fprintf(
                stderr, 
                "Call to SSL_new() failed.\n"
            );
            break;
        case SSL_TLSEXT_HOST_NAME_ERROR:
            fprintf(
                stderr, 
                "Call to SSL_set_tlsext_host_name() failed.\n"
            );
            break;
        case SSL_SET_FD_ERROR:
            fprintf(
                stderr, 
                "Call to SSL_set_fd() failed.\n"
            );
            break;
        case TCP_SSL_CONNECT_ERROR:
            fprintf(
                stderr, 
                "Call to SSL_connect() failed.\n"
            );
            break;
        case TCP_SOCKET_ERROR:
            fprintf(
                stderr, 
                "TCP server cannot be created. Call to socket() failed with error=%d.\n", 
                GET_SOCKET_ERRNO()
            );
            break;
        case TCP_CONNECT_ERROR:
            fprintf(
                stderr, 
                "TCP server cannot connect. Call to connect() failed with error=%d.\n", 
                GET_SOCKET_ERRNO()
            );        
            break;
        case TCP_SEND_ERROR:
            fprintf(
                stderr, 
                "TCP cannot send. Call to send() failed with error=%d.\n", 
                GET_SOCKET_ERRNO()
            );
            break;
        case TCP_READ_ERROR:
            fprintf(
                stderr, 
                "TCP cannot send. Call to read() failed with error=%d.\n", 
                GET_SOCKET_ERRNO()
            );
            break;
        case UDP_SOCKET_ERROR:
            fprintf(
                stderr, 
                "TCP server cannot be created. Call to socket() failed with error=%d.\n", 
                GET_SOCKET_ERRNO()
            );
            break;
        case UDP_CONNECT_ERROR:
            fprintf(
                stderr, 
                "TCP server cannot connect. Call to connect() failed with error=%d.\n", 
                GET_SOCKET_ERRNO()
            );        
            break;
        case UDP_SEND_ERROR:
            fprintf(
                stderr, 
                "TCP cannot send. Call to send() failed with error=%d.\n", 
                GET_SOCKET_ERRNO()
            );
            break;
        case UDP_READ_ERROR:
            fprintf(
                stderr, 
                "TCP cannot send. Call to read() failed with error=%d.\n", 
                GET_SOCKET_ERRNO()
            );
            break;
        case WRONG_CREDENTIAL:
            fprintf(
                stderr, 
                "Wrong credentials. Authentication failed\n"
            );
            break;
        
        
        default:
            fprintf(stderr, "Some error occured.\n");
    }
}

// Function to call whenever a SSL contect is needed. 
// It can be resued for all the connections.
int init_ssl(SSL_CTX **ctx_pointer) {

    // This is required to initialize the OpenSSL.
    SSL_library_init();

    // This cause OpenSSL to load all available algorithms. A better alternative
    // is loading only the needed ones.
    OpenSSL_add_all_algorithms();

    // This cause OpenSSL to load error strings: it is used just to see
    // readable error messages when something goes wrong.
    SSL_load_error_strings();


    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        log_vpn_client_error(SSL_INIT_ERROR);
        return SSL_INIT_ERROR;
    }

    *ctx_pointer = ctx;
    return 0;
}

int create_tcp_socket(SOCKET *tcp_socket) {
    int sockfd;
    struct sockaddr_in servaddr;
    int ret_val = 0;
    
    printf("*** Setting up TCP address info ***\n");
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (!IS_VALID_SOCKET(sockfd)) {
        log_vpn_client_error(TCP_SOCKET_ERROR);
        return TCP_SOCKET_ERROR;
    }

    printf("*** Creating TCP socket ***\n");
    bzero(&servaddr, sizeof(servaddr));
 
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(TCP_HOST);
    servaddr.sin_port = htons(TCP_PORT);
    
    printf("*** Connecting TCP socket ***\n");

    // connect the client socket to server socket
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr))) {
        log_vpn_client_error(TCP_CONNECT_ERROR);
        return TCP_CONNECT_ERROR;
    }   

    *tcp_socket = sockfd;
 
    return ret_val;
}

void free_tcp_ssl(SSL_CTX* ctx, SOCKET tcp_socket, SSL* ssl_session) {
    printf("*** SSL shutdown ***\n");
    SSL_shutdown(ssl_session);
    printf("*** SSL free ***\n");
    SSL_free(ssl_session);
    printf("*** SSL Context free ***\n");
    SSL_CTX_free(ctx);
    printf("*** Close socket ***\n");
    CLOSE_SOCKET(tcp_socket);
}

int bind_socket_to_SSL(SSL_CTX* ctx, SOCKET tcp_socket, SSL** ssl_session){
    int ret_val = 0;

    printf("*** Creating SSL ***\n");
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        log_vpn_client_error(SSL_NEW_ERROR);
        return SSL_NEW_ERROR;
    }

    printf("*** Setting tlsext hostname  ***\n");
    if (SSL_set_tlsext_host_name(ssl, TCP_HOST) == 0) {
        log_vpn_client_error(SSL_TLSEXT_HOST_NAME_ERROR);
        return SSL_TLSEXT_HOST_NAME_ERROR;
    }

    printf("*** Binding TCP socket with SSL session  ***\n");
    if (!SSL_set_fd(ssl, tcp_socket)) {
        log_vpn_client_error(SSL_SET_FD_ERROR);
        return SSL_SET_FD_ERROR;
    }

    printf("*** Conneting SSL  ***\n");
    if (SSL_connect(ssl) == -1) {
        log_vpn_client_error(TCP_SSL_CONNECT_ERROR);
        return TCP_SSL_CONNECT_ERROR;
    }

    *ssl_session = ssl;

    return ret_val;    
}

int send_credential(SSL* ssl_session, char const* user, char const* pwd, char* secret_key){
    int ret_val = 0;
    int size = strlen(user) + strlen(pwd) + 1;
    char *auth_credential = (char *)malloc(sizeof(char) * size);
    char symmetric_key[256];

    strcpy(auth_credential, user);
    strcat(auth_credential, ":");
    strcat(auth_credential, pwd);
    strcat(auth_credential, "\0");

    printf("*** Send authentication parameters ***\n");
    if (!SSL_write(ssl_session, auth_credential, strlen(auth_credential))) {
        log_vpn_client_error(TCP_SEND_ERROR);
        return TCP_SEND_ERROR;
    }

    bzero(symmetric_key, sizeof(symmetric_key));
    printf("*** Read authentication's response ***\n");
    if (!SSL_read(ssl_session, symmetric_key, sizeof(symmetric_key))) {
        log_vpn_client_error(TCP_READ_ERROR);
        return TCP_READ_ERROR;
    }
    
    if((strncmp(symmetric_key, AUTH_FAILED, strlen(AUTH_FAILED))) == 0) { 
        log_vpn_client_error(WRONG_CREDENTIAL);
        return WRONG_CREDENTIAL;
    }    
    
    strcpy(secret_key, symmetric_key);

    return ret_val;
}

int create_udp_socket(SOCKET *udp_socket) {
    int sockfd;
    struct sockaddr_in servaddr;
    int ret_val = 0;
    
    printf("*** Setting up UDP address info ***\n");
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (!IS_VALID_SOCKET(sockfd)) {
        log_vpn_client_error(UDP_SOCKET_ERROR);
        return UDP_SOCKET_ERROR;
    }

    printf("*** Creating UDP socket ***\n");
    bzero(&servaddr, sizeof(servaddr));
 
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(UDP_HOST);
    servaddr.sin_port = htons(UDP_PORT);
    
    printf("*** Connecting UDP socket ***\n");

    // connect the client socket to server socket
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr))) {
        log_vpn_client_error(UDP_CONNECT_ERROR);
        return UDP_CONNECT_ERROR;
    }   

    *udp_socket = sockfd;
 
    return ret_val;
}

int udp_exchange_data(SOCKET *udp_socket, unsigned char* secret_key) {
    int ret_val = 0;

    unsigned char* crypted_message = (unsigned char *)malloc(sizeof(char) * 1500);
    unsigned char* decrypted_message = (unsigned char *)malloc(sizeof(char) * 1500);
    bzero(crypted_message, sizeof(crypted_message));
    bzero(decrypted_message, sizeof(decrypted_message));
    unsigned char* send_message = "CIAO";

    int len_e = encrypt(send_message, strlen(send_message), secret_key, crypted_message);
    crypted_message[len_e] = 0;

    printf("*** Send UDP message ***\n");
    if (!send(*udp_socket, crypted_message, strlen(crypted_message), 0)) {
        log_vpn_client_error(UDP_SEND_ERROR);
        return UDP_SEND_ERROR;
    }

    unsigned char* read_message = (unsigned char *)malloc(sizeof(char) * 1500);

    bzero(read_message, sizeof(read_message));
    printf("*** Read udp message ***\n");
    if (!read(*udp_socket, read_message, sizeof(read_message))) {
        log_vpn_client_error(UDP_READ_ERROR);
        return UDP_READ_ERROR;
    }

    int len_d = decrypt(read_message, strlen(read_message), secret_key, decrypted_message);
    decrypted_message[len_d] = 0;
    printf("Data received decrypted: %s\n", decrypted_message);

    return ret_val;
}

/*int tun_alloc() {
  struct ifreq ifr;
  int fd, e;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    perror("Cannot open /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);

  if ((e = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
    perror("ioctl[TUNSETIFF]");
    close(fd);
    return e;
  }

  return fd;
}*/

void setup_route_table() {
    run("iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE");
    run("iptables -I FORWARD 1 -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT");
    run("iptables -I FORWARD 1 -o tun0 -j ACCEPT");
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ip route add %s via $(ip route show 0/0 | sed -e 's/.* via \([^ ]*\).*/\1/')", SERVER_HOST);
    run(cmd);
    run("ip route add 0/1 dev tun0");
    run("ip route add 128/1 dev tun0");
}

void cleanup_route_table() {    
    run("iptables -t nat -D POSTROUTING -o tun0 -j MASQUERADE");
    run("iptables -D FORWARD -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT");
    run("iptables -D FORWARD -o tun0 -j ACCEPT");
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ip route del %s", SERVER_HOST);
    run(cmd);
    run("ip route del 0/1");
    run("ip route del 128/1");
}

/*void tun_read_write(SOCKET *udp_socket, unsigned char* secret_key) {
    char tun_buf[MTU], udp_buf[MTU];
    bzero(tun_buf, MTU);
    bzero(udp_buf, MTU);

    while (TRUE) {
        fd_set readset;
        FD_ZERO(&readset);
        FD_SET(tun_fd, &readset);
        FD_SET(udp_fd, &readset);
        int max_fd = max(tun_fd, udp_fd) + 1;

        if (-1 == select(max_fd, &readset, NULL, NULL, NULL)) {
            perror("select error");
            break;
        }

        int r;
        if (FD_ISSET(tun_fd, &readset)) {
            r = read(tun_fd, tun_buf, MTU);
            if (r < 0) {
                perror("read from tun_fd error");
                break;
            }

            encrypt(tun_buf, udp_buf, r);

            r = sendto(udp_socket, udp_buf, r, 0, (const struct sockaddr *)&client_addr, client_addrlen);
            if (r < 0) {
                perror("sendto udp_fd error");
                break;
            }
        }

        if (FD_ISSET(udp_fd, &readset)) {
            r = recvfrom(udp_fd, udp_buf, MTU, 0, (struct sockaddr *)&client_addr, &client_addrlen);
            if (r < 0) {
                perror("recvfrom udp_fd error");
                break;
            }

            decrypt(udp_buf, tun_buf, r);

            r = write(tun_fd, tun_buf, r);
            if (r < 0) {
                perror("write tun_fd error");
                break;
            }
        }
    
}*/

int start_doge_vpn(char const* user, char const* pwd) {
    int ret_val = 0;
    unsigned char* secret_key = (unsigned char *)malloc(sizeof(char) * 256);  

    // SSL initialization.
    SSL_CTX *ctx = NULL;
    ret_val = init_ssl(&ctx);
    if (ret_val) return ret_val;

    SOCKET tcp_socket;
    ret_val = create_tcp_socket(&tcp_socket);
    if (ret_val) return ret_val;

    SSL* ssl_session;
    ret_val = bind_socket_to_SSL(ctx, tcp_socket, &ssl_session);
    if (ret_val) return ret_val;

    
    ret_val = send_credential(ssl_session, user, pwd, secret_key);
    if (ret_val) return ret_val;

    printf("Key received: %s\n", secret_key);

    free_tcp_ssl(ctx, tcp_socket, ssl_session);

    SOCKET udp_socket;
    ret_val = create_udp_socket(&udp_socket);
    if (ret_val) return ret_val;

    udp_exchange_data(&udp_socket, secret_key);

    return ret_val;
}



int main(int argc, char const *argv[]) {  
    return start_doge_vpn(argv[1], argv[2]);    
}

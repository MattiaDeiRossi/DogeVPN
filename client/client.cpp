// Compile with gcc aes.c client.c -lssl -lcrypto -o client
//https://github.com/davlxd/simple-vpn-demo/blob/master/vpn.c#L29
#include "standards.h"
#include "aes.h"
#include "defines.h"
#include "../lib/utils.h"
#include "../lib/ssl_utils.h"

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

int create_tcp_socket(SOCKET *tcp_socket) {
    int sockfd;
    struct sockaddr_in servaddr;
    int ret_val = 0;
    
    printf("*** Setting up TCP address info ***\n");
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (!IS_VALID_SOCKET(sockfd)) {
        utils::print_error("TCP_SOCKET_ERROR");
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
        utils::print_error("TCP_CONNECT_ERROR");
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
        utils::print_error("SSL_NEW_ERROR");
        return SSL_NEW_ERROR;
    }

    printf("*** Setting tlsext hostname  ***\n");
    if (SSL_set_tlsext_host_name(ssl, TCP_HOST) == 0) {
        utils::print_error("SSL_TLSEXT_HOST_NAME_ERROR");
        return SSL_TLSEXT_HOST_NAME_ERROR;
    }

    printf("*** Binding TCP socket with SSL session  ***\n");
    if (!SSL_set_fd(ssl, tcp_socket)) {
        utils::print_error("SSL_SET_FD_ERROR");
        return SSL_SET_FD_ERROR;
    }

    printf("*** Conneting SSL  ***\n");
    if (SSL_connect(ssl) == -1) {
        utils::print_error("TCP_SSL_CONNECT_ERROR");
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
        utils::print_error("TCP_SEND_ERROR");
        return TCP_SEND_ERROR;
    }

    bzero(symmetric_key, sizeof(symmetric_key));
    printf("*** Read authentication's response ***\n");
    if (!SSL_read(ssl_session, symmetric_key, sizeof(symmetric_key))) {
        utils::print_error("TCP_READ_ERROR");
        return TCP_READ_ERROR;
    }
    
    if((strncmp(symmetric_key, AUTH_FAILED, strlen(AUTH_FAILED))) == 0) { 
        utils::print_error("WRONG_CREDENTIAL");
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
        utils::print_error("UDP_SOCKET_ERROR");
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
        utils::print_error("UDP_CONNECT_ERROR");
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
    unsigned char* send_message = (unsigned char *) "CIAO";

    int len_e = encrypt(send_message, strlen((const char *) send_message), secret_key, crypted_message);
    crypted_message[len_e] = 0;

    printf("*** Send UDP message ***\n");
    if (!send(*udp_socket, crypted_message, strlen((const char *) crypted_message), 0)) {
        utils::print_error("UDP_SEND_ERROR");
        return UDP_SEND_ERROR;
    }

    unsigned char* read_message = (unsigned char *)malloc(sizeof(char) * 1500);

    bzero(read_message, sizeof(read_message));
    printf("*** Read udp message ***\n");
    if (!read(*udp_socket, read_message, sizeof(read_message))) {
        utils::print_error("UDP_READ_ERROR");
        return UDP_READ_ERROR;
    }

    int len_d = decrypt(read_message, strlen((const char *) read_message), secret_key, decrypted_message);
    decrypted_message[len_d] = 0;
    printf("Data received decrypted: %s\n", decrypted_message);

    return ret_val;
}

int tun_alloc(SOCKET *tun_fd) {
    int ret_val = 0;
    struct ifreq ifr;
    int fd, e;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        utils::print_error("TUN_OPEN_DEV");
        return TUN_OPEN_DEV;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);

    if ((e = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        utils::print_error("TUN_TUNSETIFF");
        return TUN_TUNSETIFF;
    }

    *tun_fd = fd;

    return ret_val;
}

static void run(char *cmd) {
  printf("Execute `%s`\n", cmd);
  if (system(cmd)) {
    perror(cmd);
    exit(1);
  }
}

void ifconfig() {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ifconfig tun0 10.8.0.2/16 mtu %d up", MTU);
    run(cmd);
}

void setup_route_table() {
    
    run("iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE");
    run("iptables -I FORWARD 1 -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT");
    run("iptables -I FORWARD 1 -o tun0 -j ACCEPT");
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ip route add %s via $(ip route show 0/0 | sed -e 's/.* via \\([^ ]*\\).*/\\1/')", SERVER_HOST);
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

static int max(int a, int b) {
  return a > b ? a : b;
}

int start_doge_vpn(char const* user, char const* pwd) {
    int ret_val = 0;
    unsigned char* secret_key = (unsigned char *)malloc(sizeof(char) * 256);  

    // SSL initialization.
    SSL_CTX *ctx = NULL;
    ret_val = ssl_utils::init_ssl(&ctx, false, NULL, NULL);
    if (ret_val) return ret_val;

    SOCKET tcp_socket;
    ret_val = create_tcp_socket(&tcp_socket);
    if (ret_val) return ret_val;

    SSL* ssl_session;
    ret_val = bind_socket_to_SSL(ctx, tcp_socket, &ssl_session);
    if (ret_val) return ret_val;

    
    ret_val = send_credential(ssl_session, user, pwd, (char *) secret_key);
    if (ret_val) return ret_val;

    printf("Key received: %s\n", secret_key);

    free_tcp_ssl(ctx, tcp_socket, ssl_session);

    SOCKET udp_socket;
    ret_val = create_udp_socket(&udp_socket);
    if (ret_val) return ret_val;

    SOCKET tun_fd;
    ret_val = tun_alloc(&tun_fd);
    if (ret_val) return ret_val;
    ifconfig();
    setup_route_table();

    char tun_buf[MTU], udp_buf[MTU];
    bzero(tun_buf, MTU);
    bzero(udp_buf, MTU);

    while (TRUE) {
        fd_set readset;
        FD_ZERO(&readset);
        FD_SET(tun_fd, &readset);
        FD_SET(udp_socket, &readset);

        int max_fd = max(tun_fd, udp_socket) + 1;

        if (-1 == select(max_fd, &readset, NULL, NULL, NULL)) {
            utils::print_error("MAX_FD_ERROR");
            return MAX_FD_ERROR;
            break;
        }
        
        int r;
        if (FD_ISSET(tun_fd, &readset)) {
            printf("*** Read from tun interface ***\n");
            if(read(tun_fd, tun_buf, MTU) <0) {
                utils::print_error("TUN_SEND_ERROR");
                return TUN_SEND_ERROR;
                break;
            }

            int len_e = encrypt((unsigned char *) tun_buf, strlen(tun_buf), secret_key, (unsigned char *) udp_buf);
            udp_buf[len_e] = 0;

            printf("*** Send UDP message ***\n");
            if (!send(udp_socket, udp_buf, strlen(udp_buf), 0)) {
                utils::print_error("UDP_SEND_ERROR");
                return UDP_SEND_ERROR;
            }
        }

        if (FD_ISSET(udp_socket, &readset)) {
            printf("*** Read UDP message ***\n");
            if (!read(udp_socket, udp_buf, MTU)) {
                utils::print_error("UDP_READ_ERROR");
                return UDP_READ_ERROR;
            }

            int len_d = decrypt((unsigned char *) udp_buf, strlen(udp_buf), secret_key, (unsigned char *) tun_buf);
            tun_buf[len_d] = 0;

            printf("*** Send with tun interface ***\n");
            if (write(tun_fd, tun_buf, r) < 0) {
                utils::print_error("TUN_SEND_ERROR");
                return TUN_SEND_ERROR;                
                break;
            }
        }
    }

    cleanup_route_table();

    return ret_val;
}



int main(int argc, char const *argv[]) {  
    return start_doge_vpn("argv[1]", "argv[2]");    
}

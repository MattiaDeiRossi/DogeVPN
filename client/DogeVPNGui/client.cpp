#include "client.h"

bool stop_flag = false;

void set_stop_flag(bool status){
    stop_flag = status;
}

int create_tcp_socket(SOCKET *tcp_socket) {
    int sockfd;
    struct sockaddr_in servaddr;
    int ret_val = 0;
    
    std::cout<<"*** Setting up TCP address info ***"<<std::endl;
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (!IS_VALID_SOCKET(sockfd)) {
        utils::print_error("TCP_SOCKET_ERROR");
        return TCP_SOCKET_ERROR;
    }

    std::cout<<"*** Creating TCP socket ***"<<std::endl;
    bzero(&servaddr, sizeof(servaddr));
 
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(TCP_HOST);
    servaddr.sin_port = htons(TCP_PORT);
    
    std::cout<<"*** Connecting TCP socket ***"<<std::endl;

    // connect the client socket to server socket
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr))) {
        utils::print_error("TCP_CONNECT_ERROR");
        return TCP_CONNECT_ERROR;
    }   

    *tcp_socket = sockfd;
 
    return ret_val;
}

void free_tcp_ssl(SSL_CTX* ctx, SOCKET tcp_socket, SSL* ssl_session) {
    std::cout<<"*** SSL shutdown ***"<<std::endl;
    SSL_shutdown(ssl_session);
    std::cout<<"*** SSL free ***"<<std::endl;
    SSL_free(ssl_session);
    std::cout<<"*** SSL Context free ***"<<std::endl;
    SSL_CTX_free(ctx);
    std::cout<<"*** Close socket ***"<<std::endl;
    CLOSE_SOCKET(tcp_socket);
}

int bind_socket_to_SSL(SSL_CTX* ctx, SOCKET tcp_socket, SSL** ssl_session){
    int ret_val = 0;

    std::cout<<"*** Creating SSL ***"<<std::endl;
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        utils::print_error("SSL_NEW_ERROR");
        return SSL_NEW_ERROR;
    }

    std::cout<<"*** Setting tlsext hostname  ***"<<std::endl;
    if (SSL_set_tlsext_host_name(ssl, TCP_HOST) == 0) {
        utils::print_error("SSL_TLSEXT_HOST_NAME_ERROR");
        return SSL_TLSEXT_HOST_NAME_ERROR;
    }

    std::cout<<"*** Binding TCP socket with SSL session  ***"<<std::endl;
    if (!SSL_set_fd(ssl, tcp_socket)) {
        utils::print_error("SSL_SET_FD_ERROR");
        return SSL_SET_FD_ERROR;
    }

    std::cout<<"*** Conneting SSL  ***"<<std::endl;
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

    std::cout<<"*** Send authentication parameters ***"<<std::endl;
    if (!SSL_write(ssl_session, auth_credential, strlen(auth_credential))) {
        utils::print_error("TCP_SEND_ERROR");
        return TCP_SEND_ERROR;
    }

    bzero(symmetric_key, sizeof(symmetric_key));
    std::cout<<"*** Read authentication's response ***"<<std::endl;
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
    
    std::cout<<"*** Setting up UDP address info ***"<<std::endl;
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (!IS_VALID_SOCKET(sockfd)) {
        utils::print_error("UDP_SOCKET_ERROR");
        return UDP_SOCKET_ERROR;
    }

    std::cout<<"*** Creating UDP socket ***"<<std::endl;
    bzero(&servaddr, sizeof(servaddr));
 
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(UDP_HOST);
    servaddr.sin_port = htons(UDP_PORT);
    
    std::cout<<"*** Connecting UDP socket ***"<<std::endl;

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
    unsigned char iv[16];
    int len_e = encryption::encrypt(send_message, strlen((const char *) send_message), secret_key, iv, crypted_message);
    crypted_message[len_e] = 0;

    std::cout<<"*** Send UDP message ***"<<std::endl;
    if (!send(*udp_socket, crypted_message, strlen((const char *) crypted_message), 0)) {
        utils::print_error("UDP_SEND_ERROR");
        return UDP_SEND_ERROR;
    }

    unsigned char* read_message = (unsigned char *)malloc(sizeof(char) * 1500);

    bzero(read_message, sizeof(read_message));
    std::cout<<"*** Read udp message ***"<<std::endl;
    if (!read(*udp_socket, read_message, sizeof(read_message))) {
        utils::print_error("UDP_READ_ERROR");
        return UDP_READ_ERROR;
    }

    int len_d = encryption::decrypt(read_message, strlen((const char *) read_message), secret_key, iv, decrypted_message);
    decrypted_message[len_d] = 0;
    std::cout<<"Data received decrypted: "<< decrypted_message<<std::endl;

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
    std::cout<<"Execute: "<< cmd<<std::endl;
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

    std::cout<<"Key received: "<< secret_key<<std::endl;

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

    while (stop_flag == false) {
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
        unsigned char iv[16];
        int r;
        if (FD_ISSET(tun_fd, &readset)) {
            std::cout<<"*** Read from tun interface ***"<<std::endl;
            if(read(tun_fd, tun_buf, MTU) <0) {
                utils::print_error("TUN_SEND_ERROR");
                return TUN_SEND_ERROR;
                break;
            }

            int len_e = encryption::encrypt((unsigned char *) tun_buf, strlen(tun_buf), secret_key, iv, (unsigned char *) udp_buf);
            udp_buf[len_e] = 0;

            std::cout<<"*** Send UDP message ***"<<std::endl;
            if (!send(udp_socket, udp_buf, strlen(udp_buf), 0)) {
                utils::print_error("UDP_SEND_ERROR");
                return UDP_SEND_ERROR;
            }
        }

        if (FD_ISSET(udp_socket, &readset)) {
            std::cout<<"*** Read UDP message ***"<<std::endl;
            if (!read(udp_socket, udp_buf, MTU)) {
                utils::print_error("UDP_READ_ERROR");
                return UDP_READ_ERROR;
            }

            int len_d = encryption::decrypt((unsigned char *) udp_buf, strlen(udp_buf), secret_key,iv, (unsigned char *) tun_buf);
            tun_buf[len_d] = 0;

            std::cout<<"*** Send with tun interface ***"<<std::endl;
            if (write(tun_fd, tun_buf, r) < 0) {
                utils::print_error("TUN_SEND_ERROR");
                return TUN_SEND_ERROR;                
                break;
            }
        }
    }

    cleanup_route_table();
    std::cout<<"*** Closing TCP socket ***"<<std::endl;

    return ret_val;
}


// int main(int argc, char const *argv[]) {
//     return start_doge_vpn("argv[1]", "argv[2]");
// }

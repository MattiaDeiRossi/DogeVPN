// Compile with gcc aes.c client.c -lssl -lcrypto -o client
//https://github.com/davlxd/simple-vpn-demo/blob/master/vpn.c#L29
#include "client.h"

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

bool stop_flag = false;

void set_stop_flag(bool status){
    stop_flag = status;
}

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

int send_credential(SSL* ssl_session, char const* user, char const* pwd, char* secret_key) {

    char credentials[client_credentials_utils::MAX_CREDENTIALS_SIZE];
    int size = utils::concat_with_separator(
        user, strlen(user),
        pwd, strlen(pwd),
        credentials,
        client_credentials_utils::MAX_CREDENTIALS_SIZE,
        client_credentials_utils::USER_PASSWORD_SEPARATOR
        );

    if (size == -1) {
        utils::print_error("send_credential: cannot create credentials\n");
        return -1;
    }

    if (ssl_utils::write(ssl_session, credentials, size) == -1) {
        utils::print_error("send_credential: cannot send credentials\n");
        return -1;
    }

    char s_key[32];
    size_t s_key_size = sizeof(s_key);
    if (ssl_utils::read(ssl_session, s_key, s_key_size) != s_key_size) {
        utils::print_error("send_credential: cannot send credentials\n");
        return -1;
    }

    if(strncmp(
            s_key,
            client_credentials_utils::WRONG_CREDENTIALS,
            strlen(client_credentials_utils::WRONG_CREDENTIALS)) == 0
        ) {
        utils::print_error("send_credential: wrong credentials\n");
        return -1;
    }

    strcpy(secret_key, s_key);

    return 0;
}
int udp_exchange_data(socket_utils::socket_t *udp_socket, unsigned char* secret_key) {
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

int tun_alloc(socket_utils::socket_t *tun_fd) {
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

// void generate_test_string(char *secret_key, encryption::packet *result) {

//     const char *test = "TEST_STRING";

//     encryption::packet message;
//     encryption::append(&message, (unsigned char *) test, strlen(test));
//     vpn_data_utils::build_packet_to_send(message, secret_key, 42, result);
//     vpn_data_utils::log_vpn_client_packet_data(result);
// }

int start_doge_vpn(char const* user, char const* pwd) {

    int ret_val = 0;

    SSL_CTX *ctx = NULL;
    ret_val = ssl_utils::init_ssl(&ctx, false, NULL, NULL);
    if (ret_val) return ret_val;

    socket_utils::socket_t tcp_socket;
    ret_val = socket_utils::bind_tcp_client_socket("127.0.0.1", "8080", &tcp_socket);
    if (ret_val) return ret_val;

    SSL* ssl_session;
    ret_val = bind_socket_to_SSL(ctx, tcp_socket, &ssl_session);
    if (ret_val) return ret_val;

    char secret_key[128];
    memset(secret_key, 0, sizeof(secret_key));
    std::cout<< user <<", " << pwd << std::endl;
    ret_val = send_credential(ssl_session, user, pwd, secret_key);
    if (ret_val) return ret_val;

    utils::print_bytes("Received key from server", secret_key, 32, 4);

    ssl_utils::free_ssl(ssl_session, NULL);
    SSL_CTX_free(ctx);

    socket_utils::socket_t udp_socket;
    ret_val = socket_utils::bind_udp_client_socket("127.0.0.1", "8080", &udp_socket);
    if (ret_val) return ret_val;

    socket_utils::socket_t tun_fd;

    /*
    ret_val = tun_alloc(&tun_fd);
    if (ret_val) return ret_val;
    ifconfig();
    setup_route_table();
    */

    char tun_buf[MTU], udp_buf[MTU];
    bzero(tun_buf, MTU);
    bzero(udp_buf, MTU);

    // while (true) {
    //     encryption::packet result;
    //     generate_test_string(secret_key, &result);
        
    //     printf("*** Send UDP message ***\n");
    //     if (!send(udp_socket, result.message, result.length, 0)) {
    //         utils::print_error("UDP_SEND_ERROR");
    //         return UDP_SEND_ERROR;
    //     }

    //     sleep(3600);
    // }

    // while (true) {
    //     encryption::packet result;
    //     generate_test_string(secret_key, &result);
        
    //     printf("*** Send UDP message ***\n");
    //     if (!send(udp_socket, result.message, result.length, 0)) {
    //         utils::print_error("UDP_SEND_ERROR");
    //         return UDP_SEND_ERROR;
    //     }

    //     sleep(3600);
    // }

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

            int len_e = encryption::encrypt((unsigned char *) tun_buf, strlen(tun_buf), (unsigned char*) secret_key, iv, (unsigned char *) udp_buf);
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

            int len_d = encryption::decrypt((unsigned char *) udp_buf, strlen(udp_buf), (unsigned char*) secret_key,iv, (unsigned char *) tun_buf);
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



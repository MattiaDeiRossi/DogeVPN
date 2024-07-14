// Compile with gcc aes.c client.c -lssl -lcrypto -o client
//https://github.com/davlxd/simple-vpn-demo/blob/master/vpn.c#L29
#include "standards.h"
#include "aes.h"
#include "defines.h"
#include "../lib/utils.h"
#include "../lib/ssl_utils.h"
#include "../lib/socket_utils.h"
#include "../lib/client_credentials_utils.h"

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
 

int bind_socket_to_SSL(SSL_CTX* ctx, socket_utils::socket_t tcp_socket, SSL** ssl_session){
    if (ssl_utils::bind_ssl(ctx, tcp_socket, ssl_session, false) == -1) {
         utils::print_error("bind_socket_to_SSL: ssl warmup failed\n");
         return -1;
    }
    return 0;  
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
    ret_val = send_credential(ssl_session, user, pwd, secret_key);
    if (ret_val) return ret_val;

    utils::print_bytes("Received key from server", secret_key, 32, 8);

    ssl_utils::free_ssl(ssl_session, NULL);
    SSL_CTX_free(ctx);

    socket_utils::socket_t udp_socket;
    ret_val = socket_utils::bind_udp_client_socket("127.0.0.1", "8080", &udp_socket);
    if (ret_val) return ret_val;

    socket_utils::socket_t tun_fd;
    ret_val = tun_alloc(&tun_fd);
    if (ret_val) return ret_val;
    ifconfig();
    setup_route_table();

    char tun_buf[MTU], udp_buf[MTU];
    bzero(tun_buf, MTU);
    bzero(udp_buf, MTU);

    while (true) {
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

            int len_e = encrypt((unsigned char *) tun_buf, strlen(tun_buf), (unsigned char *) secret_key, (unsigned char *) udp_buf);
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

            int len_d = decrypt((unsigned char *) udp_buf, strlen(udp_buf), (unsigned char *) secret_key, (unsigned char *) tun_buf);
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
    return start_doge_vpn("user", "password_password_password");    
}

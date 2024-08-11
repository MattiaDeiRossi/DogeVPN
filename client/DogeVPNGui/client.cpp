#include "client.h"

bool stop_flag = false;

void set_stop_flag(bool status) {
    stop_flag = status;
}

void generate_test_string(char *secret_key, encryption::packet *result) {

     const char *test = "TEST_STRING";

     encryption::packet message;
     bzero(&message, sizeof(encryption::packet));

     message.append((unsigned char *) test, strlen(test));

     vpn_data_utils::udp_packet_data data = 
        vpn_data_utils::udp_packet_data(&message, secret_key, 42);

     data.log();

     *result = data.compose_udp_client_message();
}

void test(int udp_socket, char *key) {
    while (true) {
        encryption::packet result;
        generate_test_string(key, &result);

        printf("*** Send UDP message ***\n");
        if (!send(udp_socket, result.buffer, result.size, 0)) {
            utils::print_error("UDP_SEND_ERROR");
        }

        sleep(3600);
    }
}

void handle_tcp_packet(SSL *ssl_session) {}

void handle_udp_packet(
    socket_utils::socket_t udp_socket,
    tun_utils::tundev_t tun_device,
    vpn_data_utils::key_exchange_data key_exchange
) {

    encryption::packet e_packet;
    e_packet.size = socket_utils::recv_from_socket(udp_socket, e_packet.buffer, e_packet.max_capacity);

    vpn_data_utils::udp_packet_data data(&e_packet, true);
    data.log();

    std::optional<encryption::packet> d_packet_opt = data.decrypt(key_exchange.key);

    if (!d_packet_opt.has_value()) {

        std::cerr << "cannot decrypt packet from server" << std::endl;
        return;
    }

    encryption::packet d_packet = d_packet_opt.value();
    tun_device.write_data(d_packet.buffer, d_packet.size);
}

void handle_tun_packet(
    socket_utils::socket_t udp_socket,
    tun_utils::tundev_t tun_device,
    vpn_data_utils::key_exchange_data key_exchange,
    std::vector<tun_utils::ipv4_netmask_t> nets
) {

    tun_utils::tundev_frame_t frame = tun_device.read_data();
    tun_utils::ip_header header = frame.get_ip_header();

    bool can_forward = false;

    for (auto net : nets) {
        tun_utils::ipv4_t ipv4(header.destination_ip);
        can_forward = can_forward || net.same_network(&ipv4);
    }

    if (!can_forward) {

        std::cout 
            << header.destination_ip 
            << "is not among a valid route" 
            << std::endl;

        return;
    }

    /**/
    encryption::packet tun_pkt((unsigned char *) frame.data, frame.size);
    vpn_data_utils::udp_packet_data(&tun_pkt, (char *) key_exchange.key, key_exchange.id_to_i())
        .send_or_throw(udp_socket);
}

int start_doge_vpn(
    char const* domain,
    char const* port,
    char const* user,
    char const* pwd
) {

    /* Move */
    const char *dev_name = "DogeVpnTun";

    std::vector<tun_utils::ipv4_netmask_t> nets;
    nets.push_back(tun_utils::ipv4_netmask_t("192.168.53.0", 24));

    int ret_val = 0;

    /* No need to continue with computation if context cannot be created. */
    SSL_CTX *ctx = ssl_utils::create_ssl_context_or_abort(false, NULL, NULL);

    /* Two kinds of socket will be used:
    *   1. TCP: in order to keep up to date the connection and its paramaters; bound to the ssl object
    *   2. UDP: when data packets will be sent
    */
    SSL* ssl_session = ssl_utils::bind_client_ssl_or_abort(ctx, socket_utils::connect_tcp_client_socket_or_abort(domain, port));
    socket_utils::socket_t tcp_socket = ssl_utils::ssl_fd_or_throw(ssl_session);
    socket_utils::socket_t udp_socket = socket_utils::connect_udp_client_socket_or_abort(domain, port);

    /* First message to exchange between client and server inder a TLS sessions.
    *  After this exchange, the following data is available:
    *   - key:      the symmetric key with wich udp packets will be encrypted
    *   - id:       the id for this client
    *   - tun_ip:   the ip to assign to the TUN device
    */
    vpn_data_utils::raw_credentials(user, pwd).send(ssl_session);
    vpn_data_utils::key_exchange_data key_exchange(ssl_session);
    key_exchange.log();

    /* TODO: netmask should be send by server */
    tun_utils::tundev_t tun_device(dev_name, (const char *) key_exchange.tun_ip, 24);
    tun_device.persist();
    
    for (auto net : nets) {
        tun_device.add_route(net);
    }

    std::set<socket_utils::socket_t> client_sockets;
    client_sockets.insert(tun_device.fd);
    client_sockets.insert(udp_socket);
    client_sockets.insert(tcp_socket);

    // test(udp_socket, (char *) key_exchange.key);

    while (!stop_flag) {

        fd_set master = socket_utils::select_or_throw(client_sockets);

        for (auto socket : client_sockets) {

            if (FD_ISSET(socket, &master)) {

                printf("DC: %d\n", socket);
                if (socket == tcp_socket) handle_tcp_packet(ssl_session);
                else if (socket == udp_socket) handle_udp_packet(udp_socket, tun_device, key_exchange);
                else if (socket == tun_device.fd) handle_tun_packet(udp_socket, tun_device, key_exchange, nets);
            }
        }
    }

    ssl_utils::free_ssl(ssl_session, NULL);
    ssl_utils::ssl_context_free(ctx);

    return ret_val;
}


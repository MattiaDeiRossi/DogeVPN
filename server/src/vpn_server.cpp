#include "standards.h"
#include "defines.h"
#include "data_structures.h"
#include "encryption.h"
#include "utils.h"
#include "ssl_utils.h"
#include "socket_utils.h"
#include "client_credentials_utils.h"
#include "udp_client_info_utils.h"
#include "vpn_data_utils.h"
#include "tun_utils.h"
#include "holder.h"
#include "selector.h"

/* Probably a thread approach is be better approach since SSL_accept is I/O blocking.
*  When handling a new client there is no need to just create the client socket and return.
*  A dedicated process should handle the process of data exchange without relying on select in the main loop.
*  After a timeout or some error the client socket can be freed along with the thread.
*  This will simplify the whole logic.
*/
void handle_tcp_client_key_exchange(
    SSL_CTX *ctx,
    socket_utils::tcp_client_info *info,
    holder::client_register *c_register
) {

    if (c_register->register_client_holder(ctx, info)) {
        std::cerr << 
            "Handle tcp client key exchange: registration error" << 
            "\n";
    }
}

/* Errors should be notified to the client peer.
*  This should be done by using the initial TCP connection. 
*  This version does not include any error notification.
*/
std::optional<encryption::packet> handle_incoming_udp_packet(
    socket_utils::socket_t udp_socket, 
    holder::client_register *c_register
) {

    /* Using the theoretical limit of an UDP packet.
    *  Instead of setting the MSG_PEEK flag, a safe bet is made on how much data to allocate.
    */
    encryption::packet pkt;
    socket_utils::recvfrom_result recv_result = socket_utils::recvfrom(udp_socket, pkt.buffer, pkt.max_capacity);

    // TODO: Try delete with address.
    /* A negative value should never happen.
    *  In this case no actions are performed, just returning the error.
    */
    if (recv_result.bytes_read < 0) {
        utils::print_error("handle_incoming_udp_packet: invalid packet length\n");
        return std::nullopt;
    }

    pkt.size = recv_result.bytes_read;

    recv_result
        .udp_info
        .to_raw_info()
        .log();

    /* Now the main logic of must happen:
    *   1. Extract the the packet
    *   2. Check the presence of the id within the shared map
    *   3. Get the connection info to verify some UDP connection property
    *   4. Decrypt the packet
    *   5. Forward it to the TUN interface
    *  There can be different scenarios for which packets must be rejected.
    */
    vpn_data_utils::vpn_client_packet_data vpn_data;
    if (vpn_data_utils::parse_packet(&pkt, &vpn_data) == -1) {
        fprintf(stderr, "handle_incoming_udp_packet: vpn data cannot be extracted\n");
        return std::nullopt;
    }

    vpn_data_utils::log_vpn_client_packet_data(&vpn_data);

    int id_num;
    sscanf((const char *) vpn_data.user_id, "%d", &id_num);
    user_id user_id = id_num;

    std::optional<holder::client_holder> c_holder = c_register->get_client_holder(user_id);

    if (!c_holder.has_value()) {
        fprintf(stderr, "handle_incoming_udp_packet: failing during key extraction\n");
        return std::nullopt;
    }

    std::optional<encryption::packet> d_packet = 
        vpn_data
            .encrypted_packet
            .decrypt(encryption::encryption_data(c_holder.value().symmetric_key, vpn_data.iv));

    if (!d_packet.has_value()) {
        return std::nullopt;
    }

    bool valid_hash = 
        d_packet
            .value()
            .valid_hash(vpn_data.hash);

    // With the encrypted packet we must verify the hash.
    if (!valid_hash) {
        utils::print_error("handle_incoming_udp_packet: wrong hash detected\n");
        return std::nullopt;
    }

    return d_packet;
}

int start_doge_vpn() {

    SSL_CTX *ctx = ssl_utils::create_ssl_context_or_abort(true, "certs/cert.pem", "certs/key.pem");
    holder::socket_holder server_tcp_holder = holder::create_server_holder_or_abort("0.0.0.0", "8080", true);
    holder::socket_holder server_udp_holder = holder::create_server_holder_or_abort("0.0.0.0", "8080", false);
    holder::client_register c_register(11);


    /* After tcp and udp sockets are created:
    *   1. extract sockets from holder
    *   2. update selector_set
    */
    socket_utils::socket_t tcp_socket = holder::extract_socket(&server_tcp_holder);
    socket_utils::socket_t udp_socket = holder::extract_socket(&server_udp_holder);

    std::set<socket_utils::socket_t> server_socket_set;
    server_socket_set.insert(tcp_socket);
    server_socket_set.insert(udp_socket);

    while(true) {

        socket_utils::socket_t max_socket;
        fd_set master = c_register.fd_set_merge(server_socket_set, &max_socket);
        socket_utils::select_or_throw(max_socket + 1, &master);

        for (socket_utils::socket_t socket = 0; socket <= max_socket; ++socket) {

           if (FD_ISSET(socket, &master)) {

                if (socket == tcp_socket) {

                    /* Calling accept_client won't block the main thread since a call to select was made. */
                    socket_utils::tcp_client_info info = socket_utils::accept_client(socket);

                    if (socket_utils::invalid_info(&info)) {

                        /* This could fail when the connections reach the maximum allowed number. */
                        fprintf(stderr, "start_doge_vpn: cannot accept new client\n");
                    } else {

                        /* Why do we need to start a new thread when handling a new client?
                        *  SSL operations may block on a slow client.
                        *  Instead of blocking the entire server we may want to block only one therad.
                        *  This thread is in charge of establish a TLS connection and exchange a key for UDP.
                        */
                        std::thread th(handle_tcp_client_key_exchange, ctx, &info, &c_register);
                        th.detach();
                    }
                } else if (socket == udp_socket) {

                    encryption::packet received_packet;
                    if (!handle_incoming_udp_packet(socket, &c_register).has_value()) {
                        utils::print_error("start_doge_vpn: udp packet of client cannot be verified\n");
                    } else {

                    }
                } else {

                    //printf("client disconnected!!!\n");

                    // if (socket == extract_socket(tun_ss_holder))

                    /* This section should handle specific client packets by using the TCP connection.
                    *  The TCP connection should be kept in order to perform reliable actions.
                    */
                }
            }
        }
    }

    fprintf(stderr, "start_doge_vpn: something wrong occurred and server must be stopped\n");
    ssl_utils::ssl_context_free(ctx);

	return 0;
}

void test_tun() {

    char name[500];
    bzero(name, sizeof(name));
    snprintf(name, sizeof(name), "tun42");

    tun_utils::tundev_t meta = tun_utils::init_meta_no_pi(name);
    tun_utils::tun_alloc(&meta);
    tun_utils::enable_forwarding(true);
    tun_utils::configure_interface(&meta, true, "192.168.53.5/24");
    
    /* Note that "buffer" should be at least the MTU size of the interface, eg 1500 bytes */

    while (true) {

        tun_utils::tundev_frame_t frame;
        tun_utils::ip_header header;
        tun_utils::read_ip_header(tun_utils::tun_read(&meta, &frame), &header);
        tun_utils::log_ip_header(&header);

        /*if(nread < 0) {
            perror("Reading from interface");
            close(meta.fd);
            exit(1);
        }*/

        /* Do whatever with the data */
       // printf("Read %d bytes from device %s\n", nread, name);

    }
}

void test_pool() {

    tun_utils::ip_pool_t pool;
    tun_utils::configure_private_class_c_pool(11, &pool);

    char buffer[512];
    unsigned int nip;
    while (tun_utils::next(&pool, buffer, 512, &nip)) {
        std::cout << buffer << "--" << nip << std::endl;
    }
}

int main() {
    //test_pool();
    //test_tun();
	return start_doge_vpn();
}

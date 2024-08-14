#include <encryption.h>
#include <ssl_utils.h>
#include <socket_utils.h>
#include <vpn_data_utils.h>
#include <tun_utils.h>
#include <holder.h>
#include <thread>
#include "config.h"

/* Probably a thread approach is be better approach since SSL_accept is I/O blocking.
*  When handling a new client there is no need to just create the client socket and return.
*  A dedicated process should handle the process of data exchange without relying on select in the main loop.
*  After a timeout or some error the client socket can be freed along with the thread.
*  This will simplify the whole logic.
*/
void handle_tls_handshake(
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
void handle_udp_packet(socket_utils::socket_t udp_socket, tun_utils::tundev_t device, holder::client_register *c_register) {

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
        return;
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
    std::optional<vpn_data_utils::udp_packet_data> vpn_data_opt = 
        vpn_data_utils::udp_packet_data_or_empty(&pkt, false);

    if (!vpn_data_opt.has_value()) {
        fprintf(stderr, "handle_incoming_udp_packet: vpn data cannot be extracted\n");
        return;
    }

    vpn_data_utils::udp_packet_data vpn_data = vpn_data_opt.value();
    vpn_data.log();

    int id_num;
    sscanf((const char *) vpn_data.user_id, "%d", &id_num);

    std::optional<holder::client_holder> c_holder_opt = c_register->get_client_holder(id_num);

    if (!c_holder_opt.has_value()) {
        fprintf(stderr, "handle_incoming_udp_packet: failing during key extraction\n");
        return;
    }

    /* Since we received the udp info from client, we must save this
    *  information on order to properly send packets back.
    */
    holder::client_holder c_holder = c_holder_opt.value();
    c_holder.udp_info = recv_result.udp_info;
    c_register->update_client_holder(c_holder);

    c_holder.log();

    std::optional<encryption::packet> d_packet_opt = 
        vpn_data.decrypt(c_holder.symmetric_key);

    if (!d_packet_opt.has_value()) {
        std::cerr
            << "handle_incoming_udp_packet: packet cannot be decrypted\n"
            << std::endl;
        return;
    }

    encryption::packet d_packet = d_packet_opt.value();
    device.write_data(d_packet.buffer, d_packet.size);
 }

 void handle_tun_packet(
    socket_utils::socket_t socket,
    tun_utils::tundev_t device,
    holder::client_register *c_register
) {
    
    tun_utils::tundev_frame_t frame = device.read_data();
    tun_utils::ip_header header = frame.get_ip_header();

    std::optional<holder::client_holder> holder_opt = 
        c_register->get_client_holder(holder::tun_ip(header.destination_ip));

    if (holder_opt.has_value()) {

        holder::client_holder holder = holder_opt.value();

        encryption::packet tun_pkt((unsigned char *) frame.data, frame.size);
        vpn_data_utils::udp_packet_data(&tun_pkt, holder.symmetric_key)
            .send_or_throw(socket, holder.udp_info);
    }
 }

/* This section should handle specific client packets by using the TCP connection.
*  The TCP connection should be kept in order to perform reliable actions.
*/
void handle_tcp_packet() {}

void start_doge_vpn() {

    /* Server pool.
    *  By using a pool of ip, for each client a unique address gets selected.
    */
    tun_utils::ip_pool_t server_pool;
    server_pool.compose_class_c_pool(config::third_octet);

    /* TUN device.
    *  By configuring the TUN device, raw ip 
    */
    char server_tun_ip[holder::SIZE_32];
    tun_utils::tundev_t device(config::name, server_pool.next(server_tun_ip, sizeof(server_tun_ip), NULL), server_pool.netmask);
    device.persist();

    SSL_CTX *ctx = ssl_utils::create_ssl_context_or_abort(true, config::public_cert, config::private_key);
    holder::socket_holder server_tcp_holder = holder::create_server_holder_or_abort(config::address, config::port, true);
    holder::socket_holder server_udp_holder = holder::create_server_holder_or_abort(config::address, config::port, false);

    /* After tcp and udp sockets are created:
    *   1. extract sockets from holder
    *   2. update selector_set
    */
    socket_utils::socket_t tcp_socket = holder::extract_socket(&server_tcp_holder);
    socket_utils::socket_t udp_socket = holder::extract_socket(&server_udp_holder);

    std::set<socket_utils::socket_t> server_socket_set;
    server_socket_set.insert(tcp_socket);
    server_socket_set.insert(udp_socket);
    server_socket_set.insert(device.fd);

    /**/
    holder::client_register c_register(server_pool);

    while(true) {

        holder::select_result result = c_register.merge_select(server_socket_set);

        for (auto socket : result.sockets) {

           if (FD_ISSET(socket, &result.fdset)) {

                if (socket == tcp_socket) {

                    /* Calling accept_client won't block the main thread since a call to select was made. */
                    socket_utils::tcp_client_info info = socket_utils::accept_client(socket);

                    if (socket_utils::invalid_info(&info)) {

                        /* This could fail when the connections reach the maximum allowed number. */
                        std::cerr 
                            << "start_doge_vpn: cannot accept new client" 
                            << std::endl;
                    } else {

                        /* Why do we need to start a new thread when handling a new client?
                        *  SSL operations may block on a slow client.
                        *  Instead of blocking the entire server we may want to block only one therad.
                        *  This thread is in charge of establish a TLS connection and exchange a key for UDP.
                        */
                        std::thread(handle_tls_handshake, ctx, &info, &c_register)
                            .detach();
                    }
                } 
                else if (socket == udp_socket) handle_udp_packet(udp_socket, device, &c_register);
                else if (socket == device.fd) handle_tun_packet(udp_socket, device, &c_register);
                else handle_tcp_packet();
            }
        }
    }
}

int main() {

	start_doge_vpn();
    return 0;
}
